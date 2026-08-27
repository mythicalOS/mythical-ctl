package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/verbs"
)

// ErrNotStarted reports that the interface never came up, so THE VERB WAS NEVER INVOKED and
// nothing was attempted. A caller that sees it must fall back to the plain path rather than treat
// the returned code as an outcome — the alternative is an operation that reports a failure it never
// tried, or, worse, one that ran with every confirmation refused because no one could be asked.
var ErrNotStarted = errors.New("ui: the terminal interface did not start")

// VerbFunc is one whole verb invocation. It is the verb layer's own shape — a context in, an exit
// code out — and this package never widens it.
type VerbFunc func(ctx context.Context, d verbs.Deps) int

// Sender is the subset of *tea.Program that the verb's goroutine uses: posting a message into the
// message loop. Narrowing it is what lets the bridge be tested without a terminal.
type Sender interface{ Send(tea.Msg) }

// program is the subset of *tea.Program the runner drives.
type program interface {
	Sender
	Run() (tea.Model, error)
}

// waitForVerbGrace is how long the runner lets a verb finish unwinding after the interface has
// gone, before it says out loud that it is still waiting. A verb that quits promptly (the normal
// case, and every cancelled case) never reaches it; a verb that ignores its context does, and then
// the operator is told why the prompt has not come back instead of watching a hung terminal.
const waitForVerbGrace = 2 * time.Second

// ---------------------------------------------------------------------------------------------
// Bridge — the verb-facing half of the execution model
// ---------------------------------------------------------------------------------------------

// Bridge implements verbs.Deps's two human-facing seams against a running Bubble Tea program.
//
// THE VERB STAYS SYNCHRONOUS. It is run on a goroutine; Confirm posts a request and BLOCKS on the
// answer; Progress posts a message. The verb never learns which world it is in, so the refusal
// semantics are the plain path's, unchanged.
//
// EVERY BLOCK HAS THREE RELEASES, and the two that are not "the operator answered" both mean
// REFUSE:
//
//  1. The operator answers — the only path that can return true.
//  2. The verb's context is cancelled (ctrl+c, or the caller's own context) — refuse.
//  3. The bridge is closed, which the runner does as soon as the program's Run returns for ANY
//     reason: quit, a torn-down terminal, a renderer error, a panic bubbletea recovered — refuse.
//
// Without (3), a program that dies while a verb is mid-question leaves that verb blocked forever on
// a channel nobody will write to, holding the family lock, with no screen to say so. Refusing is
// strictly better: it is the same answer an empty stdin gives the plain path.
type Bridge struct {
	ctx    context.Context
	send   Sender
	closed chan struct{}
	once   sync.Once

	// order serialises the RECORD-THEN-POST pair across EVERY producer — both stream writers and
	// the narration. A per-writer lock is not enough: stdout can record A and pause before posting
	// while stderr records and posts B, and then the replayed record says A-then-B while the screen
	// said B-then-A. The two must not be able to disagree about what happened first.
	//
	// It is held across the post, which can block until the message loop takes it. That is bounded
	// by the program's lifetime, and nothing the message loop runs writes back through a Bridge, so
	// there is no cycle. Lock order is ALWAYS order -> StreamWriter.mu -> mu, and nothing takes them
	// in any other order.
	order sync.Mutex

	mu     sync.Mutex
	record []recordChunk
}

// recordChunk is one WRITE of the operation's durable record — the exact bytes, tagged with the
// stream they belong on, in the order they were produced.
//
// CHUNKS, NOT LINES, and this is load-bearing. A record of lines cannot represent a write with no
// trailing newline (replaying it adds one the verb never wrote) and cannot preserve order across a
// partial line: hold "a" back waiting for its newline, narrate a step, then write "b\n", and a
// line-shaped record replays "p / ab" where the plain path printed "ap / b". The two streams share
// ONE ordered slice so that interleaving survives too.
type recordChunk struct {
	stderr bool
	text   string
}

// NewBridge builds the seams over a message sink. ctx is the context the verb is given.
func NewBridge(ctx context.Context, send Sender) *Bridge {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Bridge{ctx: ctx, send: send, closed: make(chan struct{})}
}

// Close releases every asker. It is idempotent and safe to call from any goroutine.
func (b *Bridge) Close() { b.once.Do(func() { close(b.closed) }) }

// gone reports that this bridge has been closed or its context cancelled — i.e. that posting to the
// interface can no longer accomplish anything.
func (b *Bridge) gone() bool {
	select {
	case <-b.closed:
		return true
	case <-b.ctx.Done():
		return true
	default:
		return false
	}
}

// Confirm is the verbs.ConfirmFunc seam. It asks the interface and blocks until it is answered or
// released.
//
// IT NEVER PARSES A REPLY. The overlay does that, through cliio.AcceptedReply — the same function
// the plain path calls — so there is exactly one definition of what an accepted reply is.
func (b *Bridge) Confirm(prompt string) bool {
	if b.gone() {
		// Asked after the interface is gone: refuse without posting. Fail-closed, and it keeps a
		// late question from racing a torn-down program.
		return false
	}
	reply := NewReply()
	// Send blocks only until the message loop takes the request, and returns immediately once the
	// program has finished — bubbletea cancels its own context on the way out. It is not a queue:
	// nothing is buffered here that could be delivered to a program that has already gone.
	b.send.Send(ConfirmRequestMsg{Prompt: prompt, Reply: reply})
	select {
	case ok := <-reply.C():
		return ok
	case <-b.closed:
		return false
	case <-b.ctx.Done():
		return false
	}
}

// Progress is the verbs.Deps progress seam.
//
// The detail is recorded FIRST and posted second. The record is what lands in the terminal when the
// interface comes down, so a step that happens during a teardown is still reported rather than lost
// with the frame it was drawn in.
func (b *Bridge) Progress(ev verbs.ProgressEvent) {
	b.order.Lock()
	defer b.order.Unlock()
	// EXACTLY what the plain path writes for the same event: fmt.Fprintln(d.out(), ev.Detail).
	b.appendRecord(false, ev.Detail+"\n")
	if b.gone() {
		return
	}
	b.send.Send(ProgressMsg{Event: ev})
}

// PullProgress is the engine's image-pull callback (engine.Mutator.PullProgress). It is NOT
// recorded: a pull emits a record per layer per tick, and replaying thousands of transient status
// lines into the terminal afterwards would bury the operation's actual narration.
func (b *Bridge) PullProgress(status string) {
	// Not recorded, but still ordered: a pull line drawn out of sequence with the step it belongs to
	// would tell the operator the wrong story about where the operation is.
	b.order.Lock()
	defer b.order.Unlock()
	if b.gone() {
		return
	}
	b.send.Send(PullProgressMsg{Status: status})
}

func (b *Bridge) appendRecord(stderr bool, text string) {
	b.mu.Lock()
	b.record = append(b.record, recordChunk{stderr: stderr, text: text})
	b.mu.Unlock()
}

// Record is the operation's durable output, in order. Exposed for tests; the runner replays it
// through Flush.
func (b *Bridge) Record() []recordChunk {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]recordChunk(nil), b.record...)
}

// Flush writes the record to the real streams, VERBATIM — every chunk, in order, on the stream it
// was written to, with nothing added.
//
// This is what makes the interface's output MATCH THE PLAIN PATH's rather than merely resemble it.
// Nothing is appended: a verb that wrote no trailing newline gets no trailing newline here either.
// The confirmation PROMPTS are deliberately not part of the record — they were asked and answered on
// screen, and reprinting a question after it has been answered would read as if it were still open.
func (b *Bridge) Flush(stdout, stderr io.Writer) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	for _, c := range b.Record() {
		w := stdout
		if c.stderr {
			w = stderr
		}
		_, _ = io.WriteString(w, c.text)
	}
}

// Writer returns an io.Writer that routes a stream's writes into the interface line by line, and
// into the record. It is what verbs.Deps's Stdout and Stderr are replaced with while the renderer
// owns the terminal.
func (b *Bridge) Writer(stderr bool) *StreamWriter { return &StreamWriter{b: b, stderr: stderr} }

// StreamWriter records a stream's writes VERBATIM and posts them to the interface as complete lines.
//
// The two are deliberately different shapes. The RECORD takes the raw bytes of every Write, in
// order, because it is replayed to the real terminal and must be byte-exact. The INTERFACE is given
// complete lines only — a Fprintf that writes a prefix and then the rest would otherwise be drawn as
// two lines — so a partial line is held until its newline arrives, and Close flushes whatever is
// left so a final write without a newline is still drawn.
type StreamWriter struct {
	b      *Bridge
	stderr bool

	mu  sync.Mutex
	buf []byte
}

var _ io.WriteCloser = (*StreamWriter)(nil)

func (w *StreamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// RECORDED FIRST, RAW, AND IN THE SAME CRITICAL SECTION as the line splitting: the record's
	// order is the order the verb wrote in, and a chunk appended after another goroutine's would
	// replay out of sequence.
	// RECORDED AND DRAWN UNDER THE BRIDGE'S ORDERING LOCK, so the replay and the screen agree —
	// across streams, not merely within one. See Bridge.order.
	w.b.order.Lock()
	defer w.b.order.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.appendRecord(w.stderr, string(p))
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		w.emit(line)
	}
	return len(p), nil
}

// Close drops whatever partial line is still held. It adds NOTHING to the record — the bytes are
// already there, exactly as written — and it DRAWS NOTHING.
//
// Drawing here was the last way the record and the screen could disagree about order: a partial
// line held while a later step was narrated would be drawn AFTER that step, though its bytes are
// recorded before it. And the draw bought nothing — Close runs when the verb has returned, so the
// frame is erased and the record replayed within microseconds. Every line the screen shows is now
// drawn at the position of the write that completed it, which is the same order the record has.
func (w *StreamWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = nil
	return nil
}

// emit draws one line. The interface only; the record is written by Write.
func (w *StreamWriter) emit(line string) {
	if w.b.gone() {
		return
	}
	w.b.send.Send(OutputMsg{Line: line, Stderr: w.stderr})
}

// ---------------------------------------------------------------------------------------------
// Run — the driver
// ---------------------------------------------------------------------------------------------

// Run drives one verb under the terminal interface and returns ITS exit code.
//
// The code is the value the verb returned, taken from the verb's own channel — never from the
// model. A front-end that could report a different exit status than the operation produced is a
// front-end that can lie to a script.
func Run(ctx context.Context, d verbs.Deps, fn VerbFunc) (int, error) {
	return run(ctx, d, fn, func(root Root) program {
		// The program reads and draws on the streams the process was handed, not on os.Stdin and
		// os.Stdout: those are what the caller proved were terminals, and reaching for the globals
		// instead would put the interface on a different pair.
		opts := []tea.ProgramOption{}
		if d.Stdin != nil {
			opts = append(opts, tea.WithInput(d.Stdin))
		}
		if d.Stdout != nil {
			opts = append(opts, tea.WithOutput(d.Stdout))
		}
		return tea.NewProgram(root, opts...)
	}, waitForVerbGrace)
}

// run is Run with the program construction and the grace period injected, so the failure modes —
// a program that never starts, one that ends while the verb is mid-question, a cancelled context,
// a verb that outlives the interface — are all reachable from a test with no terminal.
func run(ctx context.Context, base verbs.Deps, fn VerbFunc, mk func(Root) program, grace time.Duration) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// The VERB's context, cancelled by ctrl+c and by every return path out of here. It is NOT the
	// program's context: cancelling must let the verb unwind while the interface stays up to say
	// so, not tear the screen away and leave the process apparently hung.
	vctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := make(chan struct{})
	root := NewRoot(cancel).withStartHook(func() { close(started) })
	p := mk(root)
	b := NewBridge(vctx, p)
	defer b.Close()

	outW, errW := b.Writer(false), b.Writer(true)
	d := base
	d.Confirm = b.Confirm
	d.Progress = b.Progress
	// The verb's streams are redirected for as long as the renderer owns the terminal; the record
	// is replayed to the real ones below.
	d.Stdout, d.Stderr = outW, errW

	type outcome struct {
		code int
		ran  bool
	}
	done := make(chan outcome, 1)
	uiDone := make(chan struct{})
	// The launch gate. THE DECISION IS A LOCK, NOT A RACE BETWEEN TWO CHANNELS: with `started` and
	// `uiDone` both closed — which happens whenever the runtime ends after dispatching the start
	// command but before its goroutine ran, and Bubble Tea does not wait for that goroutine — a
	// select over the two picks at random, and half the time it launches a verb into an interface
	// that has already gone. `barred` is set BEFORE uiDone is closed, so the verb goroutine either
	// takes the lock first and runs, or takes it after and never starts. Exactly one of those
	// happens, and both publish an outcome.
	var gate sync.Mutex
	barred := false

	go func() {
		// THE VERB DOES NOT START UNTIL THE INTERFACE IS LIVE. Starting it first would mean that a
		// program which fails to come up (an unusable terminal, a renderer error) leaves a verb
		// running with a Confirm nobody can answer — every destructive step refused, an operation
		// that half-happened, and an exit code that describes none of it.
		select {
		case <-started:
		case <-uiDone:
		}
		gate.Lock()
		if barred {
			gate.Unlock()
			done <- outcome{}
			return
		}
		gate.Unlock()
		code := fn(vctx, d)
		// Trailing partial lines are flushed into the record BEFORE the code is published, so the
		// replay below sees the whole of what the verb wrote.
		_ = outW.Close()
		_ = errW.Close()
		done <- outcome{code: code, ran: true}
		// Told last: this is what ends the program, and the code must already be published when
		// it does.
		p.Send(VerbDoneMsg{Code: code})
	}()

	_, runErr := p.Run()
	// Barred BEFORE uiDone is closed: a verb that has not taken the gate by now never will.
	gate.Lock()
	barred = true
	gate.Unlock()
	close(uiDone)
	// The interface is gone. Release the verb from everything it can be blocked on BEFORE waiting
	// for it — this is the whole reason a blocking Confirm bridged over a channel is safe.
	cancel()
	b.Close()

	res, waited := waitOutcome(done, grace)
	if waited {
		// Said on the REAL stderr, after the frame is gone: an operator staring at a terminal that
		// has not come back deserves to know what it is waiting for.
		fmt.Fprintln(realErr(base), "mythical-ctl: the interface has closed; waiting for the operation still in flight to finish.")
		res = <-done
	}
	if !res.ran {
		return 0, fmt.Errorf("%w: %v", ErrNotStarted, runErr)
	}
	b.Flush(base.Stdout, base.Stderr)
	return res.code, runErr
}

// waitOutcome takes the verb's outcome if it is already there or arrives within the grace period.
// The bool reports that neither happened, which is the only case that warrants saying anything.
func waitOutcome[T any](ch <-chan T, grace time.Duration) (T, bool) {
	var zero T
	t := time.NewTimer(grace)
	defer t.Stop()
	select {
	case v := <-ch:
		return v, false
	case <-t.C:
		return zero, true
	}
}

func realErr(d verbs.Deps) io.Writer {
	if d.Stderr == nil {
		return io.Discard
	}
	return d.Stderr
}
