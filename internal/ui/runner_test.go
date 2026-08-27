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
	runErr     error

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
	wantOut := "checking the runtime\nstarted brokkr\na line with no newline\n"
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

// TestBridgeConfirmRefusesWhenClosed covers both orderings: closed before the question, and closed
// while it is outstanding.
func TestBridgeConfirmRefusesWhenClosed(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	b.Close()
	if b.Confirm("?") {
		t.Fatal("a closed bridge accepted")
	}
	// Idempotent: a second Close must not panic on an already-closed channel.
	b.Close()

	b2 := NewBridge(context.Background(), blackHole{})
	answered := make(chan bool, 1)
	go func() { answered <- b2.Confirm("?") }()
	// The question is outstanding — nothing is listening, so nothing can answer it.
	time.Sleep(10 * time.Millisecond)
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

// TestBridgeConfirmRefusesWhenTheContextIsCancelled.
func TestBridgeConfirmRefusesWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := NewBridge(ctx, blackHole{})
	answered := make(chan bool, 1)
	go func() { answered <- b.Confirm("?") }()
	time.Sleep(10 * time.Millisecond)
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

// TestStreamWriterEmitsCompleteLinesOnly — a Fprintf that writes a prefix and then the rest must not
// become two lines, and a final write with no newline must not be swallowed.
func TestStreamWriterEmitsCompleteLinesOnly(t *testing.T) {
	b := NewBridge(context.Background(), blackHole{})
	w := b.Writer(true)
	fmt.Fprint(w, "mythical-ctl: ")
	if got := len(b.Record()); got != 0 {
		t.Fatalf("a partial line was emitted: %v", b.Record())
	}
	fmt.Fprint(w, "refused\nand another\ntrailing")
	if got := len(b.Record()); got != 2 {
		t.Fatalf("record %v", b.Record())
	}
	_ = w.Close()
	rec := b.Record()
	if len(rec) != 3 {
		t.Fatalf("Close did not flush the trailing partial line: %v", rec)
	}
	var out, errb bytes.Buffer
	b.Flush(&out, &errb)
	want := "mythical-ctl: refused\nand another\ntrailing\n"
	if errb.String() != want {
		t.Fatalf("stderr %q, want %q", errb.String(), want)
	}
	if out.Len() != 0 {
		t.Fatalf("a stderr write landed on stdout: %q", out.String())
	}
	// Closing twice must not re-emit.
	_ = w.Close()
	if got := len(b.Record()); got != 3 {
		t.Fatalf("a second Close re-emitted: %v", b.Record())
	}
	// Write reports the full length it was given, as io.Writer requires.
	n, err := w.Write([]byte("abc\n"))
	if n != 4 || err != nil {
		t.Fatalf("Write returned %d, %v", n, err)
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
