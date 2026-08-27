package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// VerbDoneMsg reports that the verb goroutine has returned. Code is its exit code, kept for the
// pane's benefit only — the AUTHORITATIVE exit code is the value the verb returned, which the
// runner reads from the verb's own channel. One number, one source; a model that had to be
// consulted for the process's exit status would be a second.
type VerbDoneMsg struct{ Code int }

// interruptMsg is emitted after the cancellation hook has been called. It carries nothing; it
// exists so the hook runs as a tea.Cmd (off the update path) rather than inside Update.
type interruptMsg struct{}

// Root is the top-level model: the progress pane, the modal overlay stack, and the interrupt.
//
// It is returned as a concrete type rather than as tea.Model — a documented widening of the plan's
// sketch. Root satisfies tea.Model, so tea.NewProgram(NewRoot(...)) is unaffected; the concrete
// type is what lets the runner and the tests reach the accessors without a dynamic type assertion
// on every call.
type Root struct {
	progress Progress
	overlays overlayStack

	width, height int
	// hasSize records that a WindowSizeMsg has ARRIVED, which is not the same as the size being
	// non-zero: a terminal can legitimately report 0x0, and testing the dimensions instead would
	// skip handing a newly pushed overlay its size.
	hasSize bool

	// onInterrupt cancels the running verb. nil means there is nothing to cancel, and then
	// ctrl+c quits outright rather than doing nothing — an interface with no escape is worse than
	// any operation it might be guarding.
	onInterrupt func()

	// onStart is called once, from Init, i.e. once the program's event loop is actually running.
	// The runner uses it as the gate that keeps a verb from being launched into an interface that
	// never came up.
	onStart func()

	interrupting bool
	quitting     bool
	done         bool
	code         int
}

var (
	_ tea.Model = Root{}
	_ tea.Model = Progress{}
)

// NewRoot builds the root model. cancel is called when the operator interrupts; it may be nil.
func NewRoot(cancel func()) Root {
	return Root{progress: NewProgress(), onInterrupt: cancel}
}

// withStartHook returns a copy that calls hook from Init. It is a copy-returning setter to match
// the value semantics of the rest of the package: a Root handed to tea.NewProgram is never mutated
// afterwards.
func (m Root) withStartHook(hook func()) Root {
	m.onStart = hook
	return m
}

// Progress is the narration pane.
func (m Root) Progress() Progress { return m.progress }

// Overlay is the topmost overlay, nil when none is installed.
func (m Root) Overlay() Overlay { return m.overlays.top() }

// Overlays is how deep the modal stack is.
func (m Root) Overlays() int { return len(m.overlays) }

// Interrupting reports that the operator has asked to cancel and the verb has not finished yet.
func (m Root) Interrupting() bool { return m.interrupting }

// Quitting reports whether the model has issued tea.Quit.
func (m Root) Quitting() bool { return m.quitting }

// Done reports whether the verb has returned, and Code is what it returned.
func (m Root) Done() bool { return m.done }
func (m Root) Code() int  { return m.code }

// Width and Height are the last window size the root was told about.
func (m Root) Width() int  { return m.width }
func (m Root) Height() int { return m.height }

// Init announces that the loop is running. Bubble Tea calls it only after the terminal has been
// put into the state the renderer needs, so it is the first moment at which a verb may safely be
// launched into this interface.
func (m Root) Init() tea.Cmd {
	if m.onStart == nil {
		return nil
	}
	hook := m.onStart
	return func() tea.Msg {
		hook()
		return nil
	}
}

// Update implements tea.Model.
func (m Root) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	return next, cmd
}

func (m Root) update(msg tea.Msg) (Root, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height, m.hasSize = msg.Width, msg.Height, true
		// A resize reaches EVERY layer, including ones currently behind a modal: propagating only
		// to the visible one leaves the rest laid out for the old terminal and drawn wrong the
		// moment they come back.
		return m.broadcast(msg)

	case ConfirmRequestMsg:
		// A question that arrives after the operator has asked to cancel, or after the verb has
		// been recorded as finished, is REFUSED WITHOUT BEING SHOWN. Putting it on screen would
		// ask the operator to authorise a step of an operation that is already being torn down.
		if m.interrupting || m.done {
			msg.Reply.Resolve(false)
			return m, nil
		}
		return m.push(Confirm(msg.Prompt, msg.Reply))

	case PushOverlayMsg:
		return m.push(msg.Overlay)

	case PopOverlayMsg:
		// AN OVERLAY THAT LEAVES THE STACK IS ANSWERED ON ITS WAY OUT. A pop that merely dropped a
		// confirmation would leave the verb blocked on a question that is no longer on screen, with
		// the program and the context both still live — the one deadlock the bridge's release paths
		// cannot reach, because neither of them has fired.
		dismiss(m.overlays.top())
		m.overlays = m.overlays.pop()
		return m, nil

	case VerbDoneMsg:
		m.done, m.code = true, msg.Code
		// Anything still asking is answered — the asker has already returned, so this only keeps
		// the screen and the model honest — and then the stack is cleared and the program ends.
		m = m.refuseAll()
		m.quitting = true
		var cmd tea.Cmd
		m.progress, cmd = m.progress.update(msg)
		return m, tea.Batch(cmd, tea.Quit)

	case interruptMsg:
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Everything else is data and reaches every layer regardless of what has focus. Withholding a
	// progress event because a confirmation happens to be open would freeze the narration for as
	// long as the question is up.
	return m.broadcast(msg)
}

// push installs an overlay on top of the stack and gives it the current size.
func (m Root) push(o Overlay) (Root, tea.Cmd) {
	// A TYPED nil — a (*ConfirmOverlay)(nil) from a constructor that declined to build one — is
	// not caught by a plain == nil on the interface, and every later call on it panics.
	if isNilSeam(o) {
		return m, nil
	}
	m.overlays = m.overlays.push(o)
	var cmds []tea.Cmd
	// The overlay is told the current size IMMEDIATELY: it was built by a caller that has no
	// window size of its own and would otherwise stay unsized until the next resize, which may
	// never come. Gated on a size having ARRIVED, not on the dimensions being non-zero.
	if m.hasSize {
		var sizeCmd tea.Cmd
		m, sizeCmd = m.routeToTop(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		cmds = append(cmds, sizeCmd)
	}
	// The step above can dissolve the overlay, so Init is only reached while one is still there.
	if top := m.overlays.top(); top != nil {
		cmds = append(cmds, top.Init())
	}
	return m, tea.Batch(cmds...)
}

// broadcast delivers a message to the pane and to the topmost overlay.
func (m Root) broadcast(msg tea.Msg) (Root, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd
	m.progress, cmd = m.progress.update(msg)
	cmds = append(cmds, cmd)
	if m.overlays.top() != nil {
		m, cmd = m.routeToTop(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

// routeToTop is the ONLY place an overlay is driven and the only place its result is stored.
//
// Funnelling every path through here is what makes the typed-nil normalisation complete: an
// overlay's own Update may hand back a typed-nil Overlay, which is non-nil as an interface and
// panics on the next call.
func (m Root) routeToTop(msg tea.Msg) (Root, tea.Cmd) {
	top := m.overlays.top()
	if top == nil {
		return m, nil
	}
	next, cmd := top.Update(msg)
	if isNilSeam(next) {
		// An overlay that dissolves itself is the same thing as a pop, and is answered like one.
		// A confirmation that dissolved BECAUSE it was answered has already resolved and this is a
		// no-op (Reply answers at most once); one that dissolved for any other reason is refused
		// rather than abandoned.
		dismiss(top)
		m.overlays = m.overlays.pop()
		return m, cmd
	}
	m.overlays = m.overlays.replaceTop(next)
	return m, cmd
}

// refuseAll answers every open question with a refusal and empties the stack.
//
// It is called when the operation is being cancelled or has ended. The bridge would release the
// asker anyway when the interface goes away, but doing it HERE means the screen and the verb stop
// disagreeing at the moment of the keystroke rather than at the moment of teardown.
func (m Root) refuseAll() Root {
	for _, o := range m.overlays {
		dismiss(o)
	}
	m.overlays = nil
	return m
}

// dismiss answers an overlay that is leaving the stack, if it has a question outstanding.
//
// It is the ONE place that knows an overlay may be holding somebody's blocked call, and every path
// that removes an overlay goes through it. Refusing is idempotent — an overlay that already
// answered is unaffected — so a caller never has to know which case it is in.
func dismiss(o Overlay) {
	if r, ok := o.(interface{ Refuse() }); ok {
		r.Refuse()
	}
}

// handleKey is the global keymap.
func (m Root) handleKey(msg tea.KeyMsg) (Root, tea.Cmd) {
	key := msg.String()

	// ctrl+c is answered FIRST, above the modal check: a confirmation that can trap the operator in
	// the program is a worse defect than any action it might be guarding.
	//
	// It CANCELS rather than quits while a verb is still running. Quitting here would restore the
	// terminal and leave the process blocked on a verb that is still holding the family lock and
	// still mutating — with nothing on screen to say so. Cancelling refuses every open question,
	// cancels the verb's context, and lets the verb unwind and report; the interface goes away when
	// it does. A verb that ignores its context can therefore keep the screen up, and that is the
	// verb's contract to keep, not this model's to paper over.
	if key == "ctrl+c" {
		if m.done || m.onInterrupt == nil {
			m.quitting = true
			return m, tea.Quit
		}
		m.interrupting = true
		m = m.refuseAll()
		hook := m.onInterrupt
		return m, func() tea.Msg {
			hook()
			return interruptMsg{}
		}
	}

	// An overlay is modal: it consumes every remaining key, and nothing underneath sees it.
	if m.overlays.top() != nil {
		return m.routeToTop(msg)
	}

	// There is no `q` here on purpose. A single keystroke that abandons a half-finished install is
	// not a convenience, and ctrl+c already expresses the intent with the right semantics.
	return m, nil
}

// View renders the current screen.
func (m Root) View() string {
	if m.quitting {
		// The frame is erased on the way out; the runner then writes the operation's record —
		// the same lines, in the same order, that the plain path would have printed — to the real
		// streams, so what stays in the terminal is not a truncated pane.
		return ""
	}
	var b strings.Builder
	b.WriteString(m.progress.View())
	if top := m.overlays.top(); top != nil {
		b.WriteString("\n\n")
		b.WriteString(top.View())
	}
	b.WriteString("\n")
	switch {
	case m.interrupting:
		b.WriteString("cancelling — waiting for the operation to unwind")
	default:
		b.WriteString("ctrl+c cancels")
	}
	return b.String()
}
