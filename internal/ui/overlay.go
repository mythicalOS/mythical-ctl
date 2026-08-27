// Package ui is the terminal front-end: a Bubble Tea root model, a stack of modal overlays, the
// confirmation overlay, and the progress pane — plus the bridge that lets a SYNCHRONOUS verb run
// under it without knowing it is there.
//
// THE EXECUTION MODEL IS THE VERB LAYER'S, NOT THIS PACKAGE'S. A verb takes a context and returns
// an exit code; it never learns which front-end is driving it. The two places it talks to a human
// are the two function seams the verb layer already declares — Confirm and Progress — and this
// package supplies implementations of exactly those. Nothing here widens verbs.Deps, and nothing
// here re-decides what an accepted reply is: the overlay collects a line and hands it to
// cliio.AcceptedReply, the SAME function the plain path uses, so the two worlds cannot drift into
// two answers for the same keystrokes.
//
// EVERY BLOCKING SEAM HAS A RELEASE. A confirmation that reaches an interface nobody is looking at
// any more must REFUSE, promptly, rather than park the verb forever: a verb blocked on a question
// no one can answer still holds the family lock, and the operator has no way to tell that from a
// slow pull. See Bridge for the three release paths and the tests that pin each of them.
package ui

import (
	"reflect"

	tea "github.com/charmbracelet/bubbletea"
)

// Overlay is a modal layer drawn over the current view — a confirmation, a picker, a form.
//
// It mirrors tea.Model but returns an Overlay, so the root can keep it without a type assertion on
// every keystroke. It is given tea.WindowSizeMsg as well as keys, because a modal that does not
// know the terminal width cannot lay itself out.
//
// Returning a nil Overlay from Update is how an overlay dismisses ITSELF; the root treats it
// exactly as a pop.
type Overlay interface {
	Init() tea.Cmd
	Update(tea.Msg) (Overlay, tea.Cmd)
	View() string
}

// PushOverlayMsg installs an overlay on top of the stack.
type PushOverlayMsg struct{ Overlay Overlay }

// PopOverlayMsg dismisses the TOPMOST overlay. It is safe when there is none.
type PopOverlayMsg struct{}

// PushOverlay is the tea.Cmd form of PushOverlayMsg.
func PushOverlay(o Overlay) tea.Cmd { return func() tea.Msg { return PushOverlayMsg{Overlay: o} } }

// PopOverlay is the tea.Cmd form of PopOverlayMsg.
func PopOverlay() tea.Cmd { return func() tea.Msg { return PopOverlayMsg{} } }

// overlayStack is the modal stack: last pushed is the one that has the keyboard and the one that
// is drawn.
//
// A STACK RATHER THAN A SLOT, deliberately. With a single slot, a second push while one is open
// SILENTLY REPLACES the first — and if that first overlay was a confirmation, the verb waiting on
// its answer is left blocked on a question that has been erased from the screen. Nothing in this
// task can produce a second concurrent confirmation (a verb is synchronous and asks one question at
// a time), so the stack is not load-bearing TODAY; it is what keeps the erase-a-pending-question
// failure unreachable when a later task adds a second overlay kind.
type overlayStack []Overlay

func (s overlayStack) top() Overlay {
	if len(s) == 0 {
		return nil
	}
	return s[len(s)-1]
}

// push appends, COPYING the backing array first. The models in this package are values passed by
// copy; appending in place can write into an array an earlier model value still points at, which
// would let one Root's push mutate another Root's view of the stack.
func (s overlayStack) push(o Overlay) overlayStack {
	next := make(overlayStack, len(s), len(s)+1)
	copy(next, s)
	return append(next, o)
}

// pop removes the topmost overlay. It re-slices rather than copying — the removed element is no
// longer reachable through the returned value, and the shared tail is never written to.
func (s overlayStack) pop() overlayStack {
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}

// replaceTop swaps the topmost overlay for the value its own Update returned.
func (s overlayStack) replaceTop(o Overlay) overlayStack {
	if len(s) == 0 {
		return s
	}
	next := make(overlayStack, len(s))
	copy(next, s)
	next[len(next)-1] = o
	return next
}

// isNilSeam reports whether an interface value is nil, INCLUDING the typed-nil case where the
// interface itself is non-nil but its dynamic value is a nil pointer.
//
// A constructor that declines to build an overlay and returns (*ConfirmOverlay)(nil) produces
// exactly that shape: `== nil` on the interface is false and the first method call panics. A TUI
// that dies on the operator mid-verb is the worst outcome available here, so every path that
// stores an Overlay normalises through this.
//
// It is reflection, and reflection is not free — which is why it is called only where an overlay is
// STORED, never per rendered line.
func isNilSeam(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}
