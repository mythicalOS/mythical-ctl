// NO BATS INVENTORY — see confirm_test.go's header. The reference CLI has no terminal interface,
// so no bats test in tests/ describes any of this and none is claimed here.
package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// stubOverlay is a minimal Overlay for the stack tests: it records what it was shown and can be
// told to dissolve itself.
type stubOverlay struct {
	name     string
	seen     []string
	dissolve bool
	inits    *int
}

func (s stubOverlay) Init() tea.Cmd {
	if s.inits != nil {
		*s.inits++
	}
	return nil
}

func (s stubOverlay) Update(msg tea.Msg) (Overlay, tea.Cmd) {
	switch m := msg.(type) {
	case tea.KeyMsg:
		if s.dissolve && m.String() == "esc" {
			return nil, nil
		}
		s.seen = append(append([]string(nil), s.seen...), m.String())
	case tea.WindowSizeMsg:
		s.seen = append(append([]string(nil), s.seen...), "size")
	}
	return s, nil
}

func (s stubOverlay) View() string { return "[" + s.name + "]" }

// typedNilOverlay is the shape that makes isNilSeam necessary: a nil pointer inside a non-nil
// interface. Every method on it would panic.
type typedNilOverlay struct{}

func (*typedNilOverlay) Init() tea.Cmd                     { panic("Init on a typed nil") }
func (*typedNilOverlay) Update(tea.Msg) (Overlay, tea.Cmd) { panic("Update on a typed nil") }
func (*typedNilOverlay) View() string                      { panic("View on a typed nil") }

// TestIsNilSeamCatchesTypedNil — a plain `== nil` on the interface does not.
func TestIsNilSeamCatchesTypedNil(t *testing.T) {
	var p *typedNilOverlay
	var o Overlay = p
	if o == nil {
		t.Fatal("the test's own premise is wrong: a typed nil compares non-nil as an interface")
	}
	if !isNilSeam(o) {
		t.Fatal("isNilSeam missed a typed nil — the next method call panics and takes the process with it")
	}
	if isNilSeam(stubOverlay{name: "a"}) {
		t.Fatal("isNilSeam rejected a real overlay")
	}
	if !isNilSeam(nil) {
		t.Fatal("isNilSeam missed an untyped nil")
	}
	// A non-pointer, non-nilable kind must not be mistaken for nil.
	if isNilSeam(0) || isNilSeam("") {
		t.Fatal("isNilSeam called a plain value nil")
	}
}

// TestOverlayStackIsLIFO covers push/pop/top and the empty cases.
func TestOverlayStackIsLIFO(t *testing.T) {
	var s overlayStack
	if s.top() != nil {
		t.Fatal("an empty stack has no top")
	}
	if s.pop() != nil {
		t.Fatal("popping an empty stack must not panic or invent one")
	}
	s = s.push(stubOverlay{name: "a"})
	s = s.push(stubOverlay{name: "b"})
	if got := s.top().(stubOverlay).name; got != "b" {
		t.Fatalf("top is %q, want the last pushed", got)
	}
	s = s.pop()
	if got := s.top().(stubOverlay).name; got != "a" {
		t.Fatalf("after pop, top is %q", got)
	}
	s = s.replaceTop(stubOverlay{name: "a2"})
	if got := s.top().(stubOverlay).name; got != "a2" {
		t.Fatalf("after replaceTop, top is %q", got)
	}
	if len(s) != 1 {
		t.Fatalf("replaceTop changed the depth: %d", len(s))
	}
	// replaceTop on an empty stack is a no-op, not a panic.
	var empty overlayStack
	if empty.replaceTop(stubOverlay{name: "x"}) != nil {
		t.Fatal("replaceTop on an empty stack invented an overlay")
	}
}

// TestOverlayStackPushDoesNotMutateAnEarlierValue is the value-semantics guard. Bubble Tea models
// are copied; a push that appended in place could write into the array an earlier copy of the model
// is still reading, so one Root's push would silently change another Root's view of the stack.
func TestOverlayStackPushDoesNotMutateAnEarlierValue(t *testing.T) {
	base := overlayStack(nil).push(stubOverlay{name: "a"})
	// Two independent pushes onto the SAME base, as two copies of a model would do.
	left := base.push(stubOverlay{name: "L"})
	right := base.push(stubOverlay{name: "R"})
	if got := left.top().(stubOverlay).name; got != "L" {
		t.Fatalf("the second push overwrote the first: left top is %q", got)
	}
	if got := right.top().(stubOverlay).name; got != "R" {
		t.Fatalf("right top is %q", got)
	}
	if len(base) != 1 {
		t.Fatalf("the base stack grew: %d", len(base))
	}

	// The case above only aliases if append happens to have left spare capacity, which is not
	// something a test may rely on. This is the shape that ALWAYS aliases without the copy.
	shared := make(overlayStack, 1, 8)
	shared[0] = stubOverlay{name: "a"}
	l2 := shared.push(stubOverlay{name: "L"})
	r2 := shared.push(stubOverlay{name: "R"})
	if got := l2.top().(stubOverlay).name; got != "L" {
		t.Fatalf("the second push wrote into the first's backing array: %q", got)
	}
	if got := r2.top().(stubOverlay).name; got != "R" {
		t.Fatalf("right top is %q", got)
	}
	if len(shared) != 1 {
		t.Fatalf("the shared stack grew: %d", len(shared))
	}
}

// TestPushPopCmdsCarryTheirMessages — the two Cmds are the seam an actions layer uses.
func TestPushPopCmdsCarryTheirMessages(t *testing.T) {
	o := stubOverlay{name: "a"}
	msg := PushOverlay(o)()
	push, ok := msg.(PushOverlayMsg)
	if !ok {
		t.Fatalf("PushOverlay produced %T", msg)
	}
	if push.Overlay.(stubOverlay).name != "a" {
		t.Fatal("PushOverlay lost its overlay")
	}
	if _, ok := PopOverlay()().(PopOverlayMsg); !ok {
		t.Fatal("PopOverlay produced the wrong message")
	}
}
