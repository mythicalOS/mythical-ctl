// NO BATS INVENTORY — see confirm_test.go's header. The failure modes exercised below (a verb
// blocked on a question nobody can answer, an interface that never starts, an interface that ends
// first) exist only because this package runs a synchronous verb on a goroutine; the reference has
// no such execution model and therefore no test of it to port.
package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/verbs"
)

// fakeProgram stands in for *tea.Program: it really drives the Root model, executing the commands
// it returns and stopping on tea.Quit, so the runner's coordination is exercised end to end without
// a terminal.
//
// Commands are executed SYNCHRONOUSLY here where bubbletea runs them on goroutines. That is a
// deliberate simplification and it is safe for what is under test: every command this package
// produces is either nil, a cancellation hook, or tea.Quit — none of them block.
type fakeProgram struct {
	msgs   chan tea.Msg
	ctx    context.Context
	cancel context.CancelFunc

	model Root

	// neverStart makes Run return without ever calling Init — the "the interface could not come
	// up" case.
	neverStart bool
	// startThenDie runs the start hook and returns immediately, leaving `started` and `uiDone`
	// closed at essentially the same instant. Bubble Tea can produce exactly this: it dispatches
	// the Init command to a goroutine and does not wait for it during shutdown.
	startThenDie bool
	runErr       error

	// onUpdate is called after every Update, with the current model. Tests use it to react to what
	// is on screen (answer a question, interrupt, kill the program).
	onUpdate func(m Root, p *fakeProgram)

	mu    sync.Mutex
	final Root
}

func newFakeProgram() *fakeProgram {
	ctx, cancel := context.WithCancel(context.Background())
	// Buffered so a test's onUpdate hook can post from inside the loop.
	return &fakeProgram{msgs: make(chan tea.Msg, 64), ctx: ctx, cancel: cancel}
}

// make is the runner's program constructor.
func (p *fakeProgram) make(root Root) program {
	p.model = root
	return p
}

// Send mirrors bubbletea's contract: it blocks until the loop takes the message, and returns
// immediately once the program has finished.
func (p *fakeProgram) Send(msg tea.Msg) {
	select {
	case <-p.ctx.Done():
	case p.msgs <- msg:
	}
}

// kill ends the program the way a torn-down terminal would: Run returns, nothing was quit.
func (p *fakeProgram) kill() { p.cancel() }

func (p *fakeProgram) Final() Root {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.final
}

func (p *fakeProgram) Run() (tea.Model, error) {
	defer p.cancel()
	m := p.model
	if p.neverStart {
		return m, p.runErr
	}
	if p.startThenDie {
		p.exec(m.Init())
		return m, p.runErr
	}
	if p.exec(m.Init()) {
		return m, p.runErr
	}
	for {
		select {
		case <-p.ctx.Done():
			return m, p.runErr
		case msg := <-p.msgs:
			next, cmd := m.Update(msg)
			m = next.(Root)
			p.mu.Lock()
			p.final = m
			p.mu.Unlock()
			if p.onUpdate != nil {
				p.onUpdate(m, p)
			}
			if p.exec(cmd) {
				return m, p.runErr
			}
		}
	}
}

// exec runs a command tree and reports whether it contained a quit.
func (p *fakeProgram) exec(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	switch msg := cmd().(type) {
	case nil:
		return false
	case tea.QuitMsg:
		return true
	case tea.BatchMsg:
		quit := false
		for _, c := range msg {
			if p.exec(c) {
				quit = true
			}
		}
		return quit
	default:
		p.Send(msg)
		return false
	}
}

func baseDeps() (verbs.Deps, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return verbs.Deps{Stdout: &out, Stderr: &errb, Env: nil}, &out, &errb
}

// TestRunReportsTheVerbsExitCode — the code comes from the verb, not from the model. A front-end
// that could report a different status than the operation produced can lie to a script.
func TestRunReportsTheVerbsExitCode(t *testing.T) {
	for _, want := range []int{0, 1, 2, 3} {
		p := newFakeProgram()
		d, _, _ := baseDeps()
		code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			return want
		}, p.make, time.Second)
		if err != nil {
			t.Fatalf("code %d: %v", want, err)
		}
		if code != want {
			t.Fatalf("run returned %d, verb returned %d", code, want)
		}
		if got := p.Final().Code(); got != want {
			t.Fatalf("the model recorded %d", got)
		}
	}
}

// TestRunAnswersAConfirmThroughTheOverlay is the whole execution model in one test: the verb blocks
// in a synchronous Confirm, the question becomes a modal, the operator types a line, and the answer
// travels back to the still-blocked verb.
func TestRunAnswersAConfirmThroughTheOverlay(t *testing.T) {
	for _, tc := range []struct {
		typed string
		want  bool
	}{{"yes", true}, {"y", true}, {"no", false}, {"yess", false}, {"", false}} {
		p := newFakeProgram()
		typedIn := false
		p.onUpdate = func(m Root, p *fakeProgram) {
			if typedIn || m.Overlay() == nil {
				return
			}
			typedIn = true
			for _, r := range tc.typed {
				p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			}
			p.Send(tea.KeyMsg{Type: tea.KeyEnter})
		}
		d, _, _ := baseDeps()
		var answered bool
		code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			// Named rather than left to panic: a nil seam means the verb falls back to the
			// plain-CLI default, which reads a stdin the renderer has taken over.
			if d.Confirm == nil {
				t.Error("the runner left Confirm nil")
				return 1
			}
			answered = d.Confirm("Remove every volume?")
			if answered {
				return 0
			}
			return 1
		}, p.make, time.Second)
		if err != nil {
			t.Fatalf("%q: %v", tc.typed, err)
		}
		if answered != tc.want {
			t.Fatalf("typed %q: the verb saw %v, want %v", tc.typed, answered, tc.want)
		}
		wantCode := 1
		if tc.want {
			wantCode = 0
		}
		if code != wantCode {
			t.Fatalf("typed %q: code %d", tc.typed, code)
		}
	}
}

// TestRunRefusesWhenTheInterfaceDiesMidQuestion is the deadlock guard. A program can end for
// reasons the model never sees — a torn-down terminal, a renderer error, a recovered panic — and a
// verb blocked on a question nobody can answer would otherwise hold the family lock forever.
func TestRunRefusesWhenTheInterfaceDiesMidQuestion(t *testing.T) {
	p := newFakeProgram()
	p.onUpdate = func(m Root, p *fakeProgram) {
		if m.Overlay() != nil {
			p.kill()
		}
	}
	d, _, _ := baseDeps()
	var answered bool
	var asked = make(chan struct{})
	done := make(chan struct{})
	var code int
	var err error
	go func() {
		defer close(done)
		code, err = run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			close(asked)
			answered = d.Confirm("Remove every volume?")
			return 9
		}, p.make, time.Second)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run never returned: a verb is blocked on a confirmation nobody can answer")
	}
	<-asked
	if answered {
		t.Fatal("a question the operator never saw was answered YES")
	}
	if code != 9 || err != nil {
		t.Fatalf("code %d err %v", code, err)
	}
}

// TestRunRefusesWhenTheContextIsCancelled — the caller's own cancellation must release the verb too.
func TestRunRefusesWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := newFakeProgram()
	p.onUpdate = func(m Root, p *fakeProgram) {
		if m.Overlay() != nil {
			cancel()
		}
	}
	d, _, _ := baseDeps()
	var answered bool
	var sawCtxDone bool
	code, err := run(ctx, d, func(vctx context.Context, d verbs.Deps) int {
		if d.Confirm == nil {
			t.Error("the runner left Confirm nil")
			return 4
		}
		answered = d.Confirm("Remove every volume?")
		sawCtxDone = vctx.Err() != nil
		return 4
	}, p.make, time.Second)
	cancel()
	if answered {
		t.Fatal("a cancelled confirmation was accepted")
	}
	if !sawCtxDone {
		t.Fatal("the verb's own context was not cancelled — only the confirmation was released")
	}
	if code != 4 || err != nil {
		t.Fatalf("code %d err %v", code, err)
	}
}

// TestRunCtrlCCancelsTheVerb — the keystroke reaches the model, which refuses the open question and
// cancels the verb's context.
func TestRunCtrlCCancelsTheVerb(t *testing.T) {
	p := newFakeProgram()
	sent := false
	p.onUpdate = func(m Root, p *fakeProgram) {
		if !sent && m.Overlay() != nil {
			sent = true
			p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
		}
	}
	d, _, _ := baseDeps()
	var answered, cancelled bool
	code, err := run(context.Background(), d, func(vctx context.Context, d verbs.Deps) int {
		answered = d.Confirm("Remove every volume?")
		<-vctx.Done()
		cancelled = true
		return 1
	}, p.make, time.Second)
	if answered {
		t.Fatal("ctrl+c accepted the open question")
	}
	if !cancelled {
		t.Fatal("ctrl+c did not cancel the verb's context")
	}
	if code != 1 || err != nil {
		t.Fatalf("code %d err %v", code, err)
	}
}

// TestRunDoesNotInvokeTheVerbIfTheInterfaceNeverStarts. Running it anyway would mean an operation
// executing with every confirmation refused because nobody could be asked — half-done work and an
// exit code that describes none of it. The caller is told to use the plain path instead.
func TestRunDoesNotInvokeTheVerbIfTheInterfaceNeverStarts(t *testing.T) {
	p := newFakeProgram()
	p.neverStart = true
	p.runErr = errors.New("could not open a terminal")
	d, _, _ := baseDeps()
	ran := false
	code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		ran = true
		return 0
	}, p.make, time.Second)
	if ran {
		t.Fatal("the verb ran inside an interface that never came up")
	}
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("err %v, want ErrNotStarted", err)
	}
	if !strings.Contains(err.Error(), "could not open a terminal") {
		t.Fatalf("the underlying reason was dropped: %v", err)
	}
	if code != 0 {
		t.Fatalf("code %d — a verb that never ran has no exit code", code)
	}
}

// TestRunNeverLaunchesAVerbIntoAnInterfaceThatHasGone.
//
// The runtime can end AFTER dispatching the start announcement but BEFORE the goroutine carrying it
// runs — Bubble Tea does not wait for that goroutine on the way out — so the verb goroutine can find
// `started` and `uiDone` both closed. A select over the two then picks at random, and half the time
// it launches a mutating verb into an interface nobody can answer. The decision must be a lock, not
// a race, and this drives the interleaving repeatedly to say so.
//
// The assertion is the INVARIANT, not a fixed outcome: exactly one of "the verb ran and its code
// came back" or "ErrNotStarted and the verb never ran" must hold, every time, and run must always
// return.
func TestRunNeverLaunchesAVerbIntoAnInterfaceThatHasGone(t *testing.T) {
	for i := 0; i < 300; i++ {
		p := newFakeProgram()
		p.startThenDie = true
		d, _, _ := baseDeps()
		var ran int32
		code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			atomic.AddInt32(&ran, 1)
			return 6
		}, p.make, time.Second)
		switch {
		case errors.Is(err, ErrNotStarted):
			if n := atomic.LoadInt32(&ran); n != 0 {
				t.Fatalf("iteration %d: ErrNotStarted, but the verb ran %d time(s)", i, n)
			}
			if code != 0 {
				t.Fatalf("iteration %d: a verb that never ran reported code %d", i, code)
			}
		case err == nil:
			if n := atomic.LoadInt32(&ran); n != 1 {
				t.Fatalf("iteration %d: no error, but the verb ran %d time(s)", i, n)
			}
			if code != 6 {
				t.Fatalf("iteration %d: code %d, want the verb's own", i, code)
			}
		default:
			t.Fatalf("iteration %d: unexpected error %v", i, err)
		}
	}
}

// TestRunWaitsForAVerbThatOutlivesTheInterface, and says out loud that it is waiting. Returning
// while the verb is still mutating would exit the process mid-operation; waiting in silence, after
// the frame is gone, looks like a hang.
func TestRunWaitsForAVerbThatOutlivesTheInterface(t *testing.T) {
	p := newFakeProgram()
	// The verb is released well after the grace period, so the "still waiting" path is the one
	// under test rather than a timing accident.
	release := make(chan struct{})
	time.AfterFunc(150*time.Millisecond, func() { close(release) })
	p.onUpdate = func(m Root, p *fakeProgram) {
		if m.Overlay() != nil {
			p.kill()
		}
	}
	d, _, errb := baseDeps()
	code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Confirm("?")
		// Deliberately ignores the cancelled context, the way a verb stuck in a long
		// uninterruptible call would.
		<-release
		return 5
	}, p.make, 20*time.Millisecond)
	if code != 5 || err != nil {
		t.Fatalf("code %d err %v", code, err)
	}
	if !strings.Contains(errb.String(), "waiting for the operation still in flight") {
		t.Fatalf("nothing said why the terminal had not come back:\n%s", errb.String())
	}
}

// TestRunReplaysTheRecordToTheRealStreams — what stays in the terminal must be the lines the plain
// path would have printed, in order, on the right stream. The renderer owns the terminal while the
// verb runs, so the writes are captured and replayed once the frame is gone.
func TestRunReplaysTheRecordToTheRealStreams(t *testing.T) {
	p := newFakeProgram()
	d, out, errb := baseDeps()
	code, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Progress(verbs.ProgressEvent{Stage: "preflight", Detail: "checking the runtime"})
		fmt.Fprintln(d.Stderr, "mythical-ctl: the network was already attached")
		d.Progress(verbs.ProgressEvent{Stage: "start", Detail: "started brokkr"})
		fmt.Fprint(d.Stdout, "a line with no newline")
		return 0
	}, p.make, time.Second)
	if code != 0 || err != nil {
		t.Fatalf("code %d err %v", code, err)
	}
	// BYTE-EXACT: the verb's last write had no newline, so the replay must not invent one.
	wantOut := "checking the runtime\nstarted brokkr\na line with no newline"
	if out.String() != wantOut {
		t.Fatalf("stdout replay:\n%q\nwant\n%q", out.String(), wantOut)
	}
	wantErr := "mythical-ctl: the network was already attached\n"
	if errb.String() != wantErr {
		t.Fatalf("stderr replay:\n%q\nwant\n%q", errb.String(), wantErr)
	}
	// And the same lines were on screen while it ran.
	lines := p.Final().Progress().Lines()
	if len(lines) != 4 {
		t.Fatalf("the pane saw %d lines: %q", len(lines), lines)
	}
}

// TestRunReplayPreservesOrderAcrossAPartialLine. A partial write is HELD back from the screen until
// its newline arrives — that is a drawing rule — and it must not become an ordering rule: a record
// of complete lines would replay the held fragment AFTER the step that was narrated while it waited,
// printing "p / ab" where the plain path printed "ap / b".
func TestRunReplayPreservesOrderAcrossAPartialLine(t *testing.T) {
	p := newFakeProgram()
	d, out, errb := baseDeps()
	_, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		fmt.Fprint(d.Stdout, "a")
		d.Progress(verbs.ProgressEvent{Stage: "s", Detail: "p"})
		fmt.Fprint(d.Stdout, "b\n")
		fmt.Fprint(d.Stderr, "e1")
		fmt.Fprint(d.Stderr, "e2\n")
		return 0
	}, p.make, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "ap\nb\n"; got != want {
		t.Fatalf("stdout replay %q, want %q — the plain path's order", got, want)
	}
	if got, want := errb.String(), "e1e2\n"; got != want {
		t.Fatalf("stderr replay %q, want %q", got, want)
	}
}

// TestRunKeepsTheVerbsStreamsOffTheRealTerminal — a bare Fprintln into a live frame corrupts the
// screen, so the verb must never be handed the real streams.
func TestRunKeepsTheVerbsStreamsOffTheRealTerminal(t *testing.T) {
	p := newFakeProgram()
	d, out, errb := baseDeps()
	var sawOut, sawErr bool
	_, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		sawOut = d.Stdout == out
		sawErr = d.Stderr == errb
		fmt.Fprintln(d.Stdout, "mid-flight")
		// Nothing may have reached the real stream yet.
		if out.Len() != 0 || errb.Len() != 0 {
			t.Error("a verb's write reached the real terminal while the renderer owned it")
		}
		return 0
	}, p.make, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sawOut || sawErr {
		t.Fatal("the verb was handed the real streams")
	}
}

// TestRunSuppliesBothSeams — a nil Confirm or Progress would silently fall back to the plain-CLI
// defaults, which read a stdin the renderer has taken over and print into the live frame.
func TestRunSuppliesBothSeams(t *testing.T) {
	p := newFakeProgram()
	d, _, _ := baseDeps()
	_, err := run(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		if d.Confirm == nil {
			t.Error("Confirm was left nil")
		}
		if d.Progress == nil {
			t.Error("Progress was left nil")
		}
		return 0
	}, p.make, time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

// --- the bridge on its own ---------------------------------------------------------------------

// blackHole accepts every message and does nothing with it — an interface that is not listening.
type blackHole struct{}

func (blackHole) Send(tea.Msg) {}

// recordingSender counts what was posted, so a message that must NEVER be posted can be asserted
// on rather than reasoned about.
type recordingSender struct {
	mu   sync.Mutex
	msgs []tea.Msg
}

func (r *recordingSender) Send(m tea.Msg) {
	r.mu.Lock()
	r.msgs = append(r.msgs, m)
	r.mu.Unlock()
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

// TestBridgePostsNothingToADeadInterface — a question asked after the interface is gone must refuse
// WITHOUT being posted. Posting it would race a torn-down program and, on a program that has not
// started, would block the verb inside Send with nothing able to take the message.
func TestBridgePostsNothingToADeadInterface(t *testing.T) {
	rec := &recordingSender{}
	b := NewBridge(context.Background(), rec)
	b.Close()
	if b.Confirm("?") {
		t.Fatal("a closed bridge accepted")
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("%d message(s) were posted to a dead interface", got)
	}
	b.Progress(verbs.ProgressEvent{Stage: "s", Detail: "d"})
	b.PullProgress("layer")
	w := b.Writer(false)
	fmt.Fprintln(w, "a line")
	_ = w.Close()
	if got := rec.count(); got != 0 {
		t.Fatalf("%d message(s) were posted to a dead interface", got)
	}
	// The narration is still RECORDED, so nothing the verb said is lost.
	if got := len(b.Record()); got != 2 {
		t.Fatalf("record holds %d lines, want the progress step and the stream line", got)
	}

	// And on a live bridge, the same calls do post.
	rec2 := &recordingSender{}
	b2 := NewBridge(context.Background(), rec2)
	b2.Progress(verbs.ProgressEvent{Stage: "s", Detail: "d"})
	b2.PullProgress("layer")
	w2 := b2.Writer(false)
	fmt.Fprintln(w2, "a line")
	if got := rec2.count(); got != 3 {
		t.Fatalf("a live bridge posted %d messages, want 3", got)
	}
}

// postedSender reports when a message has actually been posted, so a test can release an asker at a
// point where the asker is PROVABLY outstanding.
type postedSender struct{ posted chan tea.Msg }

func newPostedSender() *postedSender { return &postedSender{posted: make(chan tea.Msg, 8)} }

func (s *postedSender) Send(m tea.Msg) { s.posted <- m }

// TestBridgeConfirmRefusesWhenClosed covers both orderings: closed before the question, and closed
// while it is outstanding.
//
// THE SECOND ORDERING IS ESTABLISHED BY THE POST, NOT BY A SLEEP. A sleep is not a happens-before
// edge: the asking goroutine might not have started at all, take the preflight refusal instead, and
// pass a test whose whole claim is about the other path. Waiting for the request to appear proves
// the preflight is behind us and the asker is in its select.
func TestBridgeConfirmRefusesWhenClosed(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	b.Close()
	if b.Confirm("?") {
		t.Fatal("a closed bridge accepted")
	}
	// Idempotent: a second Close must not panic on an already-closed channel.
	b.Close()

	send := newPostedSender()
	b2 := NewBridge(context.Background(), send)
	answered := make(chan bool, 1)
	go func() { answered <- b2.Confirm("?") }()
	select {
	case msg := <-send.posted:
		if _, ok := msg.(ConfirmRequestMsg); !ok {
			t.Fatalf("posted %T", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the question was never posted")
	}
	// The question is outstanding — nothing will answer it.
	b2.Close()
	select {
	case ok := <-answered:
		if ok {
			t.Fatal("closing the bridge accepted an outstanding question")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the bridge did not release the asker")
	}
}

// TestBridgeConfirmRefusesWhenTheContextIsCancelled, with the same ordering discipline.
func TestBridgeConfirmRefusesWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	send := newPostedSender()
	b := NewBridge(ctx, send)
	answered := make(chan bool, 1)
	go func() { answered <- b.Confirm("?") }()
	select {
	case msg := <-send.posted:
		if _, ok := msg.(ConfirmRequestMsg); !ok {
			t.Fatalf("posted %T", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the question was never posted")
	}
	cancel()
	select {
	case ok := <-answered:
		if ok {
			t.Fatal("a cancelled question was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling did not release the asker")
	}
	// And a question asked after cancellation refuses without ever being posted.
	if b.Confirm("?") {
		t.Fatal("a question asked after cancellation was accepted")
	}
	select {
	case msg := <-send.posted:
		t.Fatalf("a question asked after cancellation was posted: %T", msg)
	default:
	}
}

// TestBridgeNilContextIsBackground — a Deps built without a context must not panic on the first
// select.
func TestBridgeNilContextIsBackground(t *testing.T) {
	b := NewBridge(nil, blackHole{})
	b.Close()
	if b.Confirm("?") {
		t.Fatal("accepted")
	}
}

// TestBridgeRecordsProgressEvenAfterTheInterfaceIsGone — a step that happens during teardown is
// still part of what the operation did.
func TestBridgeRecordsProgressEvenAfterTheInterfaceIsGone(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	b.Close()
	b.Progress(verbs.ProgressEvent{Stage: "s", Detail: "did the thing"})
	var out, errb bytes.Buffer
	b.Flush(&out, &errb)
	if out.String() != "did the thing\n" {
		t.Fatalf("record %q", out.String())
	}
	// Flush tolerates nil streams.
	b.Flush(nil, nil)
}

// TestBridgePullProgressIsNotRecorded — thousands of transient layer lines replayed into the
// terminal afterwards would bury the operation's actual narration.
func TestBridgePullProgressIsNotRecorded(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	for i := 0; i < 100; i++ {
		b.PullProgress("layer: Downloading")
	}
	if got := len(b.Record()); got != 0 {
		t.Fatalf("%d pull lines entered the record", got)
	}
}

// TestStreamWriterDrawsCompleteLinesOnly. A Fprintf that writes a prefix and then the rest must not
// be drawn as two lines; a final write with no newline must still be drawn.
func TestStreamWriterDrawsCompleteLinesOnly(t *testing.T) {
	rec := &recordingSender{}
	b := NewBridge(context.Background(), rec)
	w := b.Writer(true)
	fmt.Fprint(w, "mythical-ctl: ")
	if got := rec.count(); got != 0 {
		t.Fatalf("a partial line was drawn: %v", rec.msgs)
	}
	fmt.Fprint(w, "refused\nand another\ntrailing")
	if got := rec.count(); got != 2 {
		t.Fatalf("drew %d lines, want 2", got)
	}
	_ = w.Close()
	if got := rec.count(); got != 3 {
		t.Fatalf("Close did not draw the trailing partial line: %d", got)
	}
	first, ok := rec.msgs[0].(OutputMsg)
	if !ok || first.Line != "mythical-ctl: refused" || !first.Stderr {
		t.Fatalf("first drawn line %#v", rec.msgs[0])
	}
	// Closing twice must not re-draw.
	_ = w.Close()
	if got := rec.count(); got != 3 {
		t.Fatalf("a second Close re-drew: %d", got)
	}
	// Write reports the full length it was given, as io.Writer requires.
	n, err := w.Write([]byte("abc\n"))
	if n != 4 || err != nil {
		t.Fatalf("Write returned %d, %v", n, err)
	}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("an empty Write returned %d, %v", n, err)
	}
}

// TestStreamWriterRecordIsByteExact. The record is replayed to the real terminal, so it must be the
// bytes the verb wrote — not lines reassembled from them. A line-shaped record adds a newline the
// verb never wrote, and the added newline is invisible in a test that expects it.
func TestStreamWriterRecordIsByteExact(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	w := b.Writer(true)
	fmt.Fprint(w, "mythical-ctl: ")
	fmt.Fprint(w, "refused\nand another\ntrailing")
	_ = w.Close()
	var out, errb bytes.Buffer
	b.Flush(&out, &errb)
	want := "mythical-ctl: refused\nand another\ntrailing"
	if errb.String() != want {
		t.Fatalf("stderr %q, want %q", errb.String(), want)
	}
	if out.Len() != 0 {
		t.Fatalf("a stderr write landed on stdout: %q", out.String())
	}
	// Close adds nothing to the record: the bytes were already there.
	before := len(b.Record())
	_ = w.Close()
	if got := len(b.Record()); got != before {
		t.Fatalf("Close appended to the record: %d -> %d", before, got)
	}
}

// TestProgressRecordMatchesThePlainPathByte for byte: the plain default is
// fmt.Fprintln(d.out(), ev.Detail).
func TestProgressRecordMatchesThePlainPathByte(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	b.Progress(verbs.ProgressEvent{Stage: "s", Detail: "started brokkr"})
	b.Progress(verbs.ProgressEvent{Stage: "s", Detail: ""})
	var out, errb bytes.Buffer
	b.Flush(&out, &errb)

	var plain bytes.Buffer
	fmt.Fprintln(&plain, "started brokkr")
	fmt.Fprintln(&plain, "")
	if out.String() != plain.String() {
		t.Fatalf("record %q, plain path %q", out.String(), plain.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("narration reached stderr: %q", errb.String())
	}
}

// senderFunc adapts a function to Sender.
type senderFunc func(tea.Msg)

func (f senderFunc) Send(m tea.Msg) { f(m) }

// TestRecordAndScreenAgreeOnOrderAcrossStreams. The ordering lock has to span the whole bridge, not
// each writer: stdout can record its line and then pause inside the post while stderr records AND
// posts its own, and then the replayed record says stdout-first while the screen said stderr-first.
// One of the two is then lying about what happened when.
//
// The interleaving is PINNED rather than raced: the first post blocks until this test releases it,
// which is exactly the pause a per-writer lock leaves open.
func TestRecordAndScreenAgreeOnOrderAcrossStreams(t *testing.T) {
	var mu sync.Mutex
	var drawn []string
	firstPost := make(chan struct{})
	release := make(chan struct{})
	// A CAS rather than sync.Once: Once BLOCKS every concurrent caller until the first Do returns,
	// which would serialise the second writer inside the sender and hide the very interleaving this
	// test exists to produce. The first caller parks; every later one walks straight through.
	var parked int32

	b := NewBridge(context.Background(), senderFunc(func(m tea.Msg) {
		if atomic.CompareAndSwapInt32(&parked, 0, 1) {
			close(firstPost)
			<-release
		}
		if om, ok := m.(OutputMsg); ok {
			mu.Lock()
			drawn = append(drawn, om.Line)
			mu.Unlock()
		}
	}))

	out, errw := b.Writer(false), b.Writer(true)
	done := make(chan struct{}, 2)
	go func() { fmt.Fprint(out, "A\n"); done <- struct{}{} }()
	// Wait until the first writer is INSIDE the post and stuck there.
	<-firstPost
	go func() { fmt.Fprint(errw, "B\n"); done <- struct{}{} }()
	// Give the second writer every chance to overtake: with a per-writer lock it records and draws
	// B while A is still parked in its post.
	time.Sleep(20 * time.Millisecond)
	close(release)
	<-done
	<-done

	var recorded []string
	for _, c := range b.Record() {
		recorded = append(recorded, strings.TrimSuffix(c.text, "\n"))
	}
	mu.Lock()
	got := append([]string(nil), drawn...)
	mu.Unlock()
	if len(recorded) != 2 || len(got) != 2 {
		t.Fatalf("recorded %q drawn %q", recorded, got)
	}
	if recorded[0] != got[0] || recorded[1] != got[1] {
		t.Fatalf("the record says %q and the screen says %q — one of them is lying about the order", recorded, got)
	}
	if recorded[0] != "A" {
		t.Fatalf("the writer that got there first is %q", recorded[0])
	}
}

// TestBridgeIsRaceFreeUnderConcurrentUse. A goroutine-per-verb design plus a message loop is exactly
// where races live; this is the shape `go test -race` needs to see.
func TestBridgeIsRaceFreeUnderConcurrentUse(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := b.Writer(i%2 == 0)
			for j := 0; j < 50; j++ {
				b.Progress(verbs.ProgressEvent{Stage: "s", Detail: fmt.Sprintf("%d-%d", i, j)})
				fmt.Fprintf(w, "out %d-%d\n", i, j)
				b.PullProgress("layer")
			}
			_ = w.Close()
		}(i)
	}
	wg.Wait()
	if got := len(b.Record()); got != 8*50*2 {
		t.Fatalf("record holds %d lines", got)
	}
	b.Close()
}
