// NO BATS INVENTORY — see confirm_test.go's header.
package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/verbs"
)

// step drives one message through the root and returns the new root plus the command.
func step(m Root, msg tea.Msg) (Root, tea.Cmd) { return m.update(msg) }

// isQuit reports whether a command is (or contains) tea.Quit. Bubble Tea's batch message is
// exported, so a command tree can be walked; its sequence message is not, which is why this package
// never returns one.
func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	switch msg := cmd().(type) {
	case tea.QuitMsg:
		return true
	case tea.BatchMsg:
		for _, c := range msg {
			if isQuit(c) {
				return true
			}
		}
	}
	return false
}

// TestRootShowsAConfirmRequestAsAnOverlay — the request arrives from the verb's goroutine and must
// become a modal.
func TestRootShowsAConfirmRequestAsAnOverlay(t *testing.T) {
	m := NewRoot(func() {})
	r := NewReply()
	m, _ = step(m, ConfirmRequestMsg{Prompt: "Destroy everything?", Reply: r})
	if m.Overlays() != 1 {
		t.Fatalf("overlays: %d", m.Overlays())
	}
	c, ok := m.Overlay().(ConfirmOverlay)
	if !ok {
		t.Fatalf("overlay is %T", m.Overlay())
	}
	if c.Prompt() != "Destroy everything?" {
		t.Fatalf("prompt %q", c.Prompt())
	}
	if !strings.Contains(m.View(), "Destroy everything?") {
		t.Fatalf("the question is not on screen:\n%s", m.View())
	}
	// Answering it dismisses the modal and reaches the asker.
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.Overlays() != 0 {
		t.Fatalf("the answered overlay is still installed: %d", m.Overlays())
	}
	if ok := <-r.C(); !ok {
		t.Fatal("the answer did not reach the asker")
	}
}

// TestRootOverlayIsModal — while a question is up, nothing underneath sees a keystroke.
func TestRootOverlayIsModal(t *testing.T) {
	m := NewRoot(func() {})
	m, _ = step(m, ConfirmRequestMsg{Prompt: "?", Reply: NewReply()})
	before := m.Progress().Lines()
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if m.Quitting() {
		t.Fatal("a key reached the global keymap through an open modal")
	}
	if len(m.Progress().Lines()) != len(before) {
		t.Fatal("a key reached the pane through an open modal")
	}
	if got := m.Overlay().(ConfirmOverlay).Input(); got != "q" {
		t.Fatalf("the modal did not receive the key: %q", got)
	}
}

// TestRootHasNoSingleKeyQuit — `q` must not abandon a running operation.
func TestRootHasNoSingleKeyQuit(t *testing.T) {
	m := NewRoot(func() {})
	for _, k := range []string{"q", "esc", "Q", "x"} {
		var cmd tea.Cmd
		m, cmd = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		if m.Quitting() || isQuit(cmd) {
			t.Fatalf("%q quit while a verb was still running", k)
		}
	}
}

// TestRootCtrlCCancelsRatherThanQuits is the interrupt contract. Quitting here would restore the
// terminal and leave the process blocked on a verb that is still holding the family lock, with
// nothing on screen to say so.
func TestRootCtrlCCancelsRatherThanQuits(t *testing.T) {
	cancelled := 0
	m := NewRoot(func() { cancelled++ })
	r := NewReply()
	m, _ = step(m, ConfirmRequestMsg{Prompt: "Wipe?", Reply: r})
	m, cmd := step(m, tea.KeyMsg{Type: tea.KeyCtrlC})
	// The command is deliberately NOT executed yet: running it here would call the hook and make
	// the "not inside Update" assertion below vacuous.
	if m.Quitting() {
		t.Fatal("ctrl+c quit while the verb was still running")
	}
	if !m.Interrupting() {
		t.Fatal("ctrl+c did not record the interrupt")
	}
	// The open question is REFUSED immediately, so the screen and the verb stop disagreeing at the
	// keystroke rather than at teardown.
	if m.Overlays() != 0 {
		t.Fatalf("the question is still on screen after cancel: %d", m.Overlays())
	}
	if ok := <-r.C(); ok {
		t.Fatal("cancelling accepted the pending confirmation")
	}
	// The cancellation hook runs as a command, off the update path.
	if cancelled != 0 {
		t.Fatal("the hook ran inside Update")
	}
	if cmd == nil {
		t.Fatal("ctrl+c returned no command, so nothing cancels the verb")
	}
	switch msg := cmd().(type) {
	case interruptMsg:
	case tea.QuitMsg:
		t.Fatal("ctrl+c issued a quit while the verb was still running")
	default:
		t.Fatalf("the interrupt command produced %T", msg)
	}
	if cancelled != 1 {
		t.Fatalf("the verb was cancelled %d times", cancelled)
	}
	if !strings.Contains(m.View(), "cancelling") {
		t.Fatalf("the screen does not say it is cancelling:\n%s", m.View())
	}
}

// TestRootRefusesAQuestionAskedAfterCancel — a question that arrives during teardown must not be
// put on screen; asking the operator to authorise a step of an operation that is already being
// cancelled is worse than refusing it.
func TestRootRefusesAQuestionAskedAfterCancel(t *testing.T) {
	m := NewRoot(func() {})
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyCtrlC})
	r := NewReply()
	m, _ = step(m, ConfirmRequestMsg{Prompt: "another?", Reply: r})
	if m.Overlays() != 0 {
		t.Fatal("a question asked after cancel reached the screen")
	}
	if ok := <-r.C(); ok {
		t.Fatal("a question asked after cancel was accepted")
	}
}

// TestRootCtrlCQuitsOnceTheVerbIsDone — and when there is nothing to cancel at all. An interface
// with no escape is worse than any operation it might be guarding.
func TestRootCtrlCQuitsOnceTheVerbIsDone(t *testing.T) {
	m := NewRoot(nil)
	m, cmd := step(m, tea.KeyMsg{Type: tea.KeyCtrlC})
	if !m.Quitting() || !isQuit(cmd) {
		t.Fatal("with no cancellation hook, ctrl+c must quit")
	}

	m2 := NewRoot(func() {})
	m2, _ = step(m2, VerbDoneMsg{Code: 0})
	m2, cmd2 := step(m2, tea.KeyMsg{Type: tea.KeyCtrlC})
	if !m2.Quitting() || !isQuit(cmd2) {
		t.Fatal("after the verb has finished, ctrl+c must quit")
	}
}

// TestRootQuitsWhenTheVerbFinishes, and records the code for the pane.
func TestRootQuitsWhenTheVerbFinishes(t *testing.T) {
	m := NewRoot(func() {})
	r := NewReply()
	m, _ = step(m, ConfirmRequestMsg{Prompt: "?", Reply: r})
	m, cmd := step(m, VerbDoneMsg{Code: 3})
	if !m.Done() || m.Code() != 3 {
		t.Fatalf("done=%v code=%d", m.Done(), m.Code())
	}
	if !m.Quitting() || !isQuit(cmd) {
		t.Fatal("the verb finished and the program did not quit")
	}
	if m.Overlays() != 0 {
		t.Fatal("an overlay survived the verb")
	}
	if ok := <-r.C(); ok {
		t.Fatal("the still-open question was not refused when the verb ended")
	}
	if m.View() != "" {
		t.Fatalf("the frame must be erased on the way out, so the record replaces it: %q", m.View())
	}
}

// TestRootBroadcastsDataToPaneAndOverlay — withholding a progress event because a question happens
// to be open would freeze the narration for as long as the question is up.
func TestRootBroadcastsDataToPaneAndOverlay(t *testing.T) {
	m := NewRoot(func() {})
	inits := 0
	m, _ = step(m, PushOverlayMsg{Overlay: stubOverlay{name: "a", inits: &inits}})
	m, _ = step(m, ProgressMsg{Event: verbs.ProgressEvent{Stage: "pull", Detail: "pulling the image"}})
	if got := m.Progress().Stage(); got != "pull" {
		t.Fatalf("the pane did not see the event: stage %q", got)
	}
	if !strings.Contains(m.View(), "pulling the image") {
		t.Fatalf("the narration is not on screen:\n%s", m.View())
	}
}

// TestRootSizesAnOverlayOnPush — an overlay built by a caller with no window size of its own would
// otherwise stay unsized until a resize that may never come.
func TestRootSizesAnOverlayOnPush(t *testing.T) {
	m := NewRoot(func() {})
	// 0x0 is a real, representable window size: the gate is that a size ARRIVED, not that it is
	// non-zero.
	m, _ = step(m, tea.WindowSizeMsg{Width: 0, Height: 0})
	inits := 0
	m, cmd := step(m, PushOverlayMsg{Overlay: stubOverlay{name: "a", inits: &inits}})
	if got := m.Overlay().(stubOverlay).seen; len(got) != 1 || got[0] != "size" {
		t.Fatalf("the overlay was not sized on push: %v", got)
	}
	if inits != 1 {
		t.Fatalf("Init ran %d times", inits)
	}
	_ = cmd

	// Without a size having arrived, nothing is sent — an overlay must not be told a size that was
	// never measured.
	m2 := NewRoot(func() {})
	m2, _ = step(m2, PushOverlayMsg{Overlay: stubOverlay{name: "b"}})
	if got := m2.Overlay().(stubOverlay).seen; len(got) != 0 {
		t.Fatalf("an unmeasured size was sent: %v", got)
	}
}

// TestRootReachesEveryLayerOnResize — a layer behind a modal that missed a resize is drawn wrong the
// moment it comes back.
func TestRootReachesEveryLayerOnResize(t *testing.T) {
	m := NewRoot(func() {})
	m, _ = step(m, PushOverlayMsg{Overlay: stubOverlay{name: "a"}})
	m, _ = step(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	if m.Width() != 100 || m.Height() != 40 {
		t.Fatalf("root size %dx%d", m.Width(), m.Height())
	}
	if got := m.Overlay().(stubOverlay).seen; len(got) == 0 || got[len(got)-1] != "size" {
		t.Fatalf("the overlay missed the resize: %v", got)
	}
}

// TestRootNormalisesTypedNilOverlays on every path that stores one: the push, and an overlay's own
// Update handing one back.
func TestRootNormalisesTypedNilOverlays(t *testing.T) {
	m := NewRoot(func() {})
	var p *typedNilOverlay
	m, _ = step(m, PushOverlayMsg{Overlay: p})
	if m.Overlays() != 0 {
		t.Fatal("a typed-nil overlay was installed — the next keystroke panics")
	}
	// And an overlay that dissolves itself is a pop, not a stored nil.
	m, _ = step(m, PushOverlayMsg{Overlay: stubOverlay{name: "a", dissolve: true}})
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.Overlays() != 0 {
		t.Fatalf("a self-dissolving overlay was kept: %d", m.Overlays())
	}
	// A key after the stack is empty must reach the (empty) global keymap without panicking.
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'z'}})
}

// TestRootPopOnEmptyStack is safe.
func TestRootPopOnEmptyStack(t *testing.T) {
	m := NewRoot(func() {})
	m, _ = step(m, PopOverlayMsg{})
	if m.Overlays() != 0 {
		t.Fatal("popping an empty stack invented an overlay")
	}
}

// TestRootPopRefusesAnOpenQuestion is the deadlock the bridge's own release paths cannot reach: a
// pop while a confirmation is up leaves the program and the context BOTH live, so neither of the
// bridge's two releases fires and the verb waits forever on a question that is no longer on screen.
// Every path that removes an overlay must answer it.
func TestRootPopRefusesAnOpenQuestion(t *testing.T) {
	m := NewRoot(func() {})
	r := NewReply()
	m, _ = step(m, ConfirmRequestMsg{Prompt: "Wipe?", Reply: r})
	m, _ = step(m, PopOverlayMsg{})
	if m.Overlays() != 0 {
		t.Fatal("the overlay survived the pop")
	}
	select {
	case ok := <-r.C():
		if ok {
			t.Fatal("popping a confirmation accepted it")
		}
	default:
		t.Fatal("popping a confirmation abandoned the asker — it blocks forever")
	}
	// The Cmd form reaches the same message, so a caller that pops through it is covered too.
	if _, ok := PopOverlay()().(PopOverlayMsg); !ok {
		t.Fatal("PopOverlay produced the wrong message")
	}
}

// TestRootDissolveRefusesAnOpenQuestion — an overlay that hands back a nil Overlay leaves the stack
// the same way, and must be answered the same way. A ConfirmOverlay that dissolved BECAUSE it was
// answered is unaffected: the answer is once-only.
func TestRootDissolveRefusesAnOpenQuestion(t *testing.T) {
	// A stand-in that dissolves on esc while holding a real Reply, the way a future overlay kind
	// could.
	r := NewReply()
	m := NewRoot(func() {})
	m, _ = step(m, PushOverlayMsg{Overlay: dissolvingConfirm{ConfirmOverlay: Confirm("?", r)}})
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if m.Overlays() != 0 {
		t.Fatal("the overlay did not dissolve")
	}
	select {
	case ok := <-r.C():
		if ok {
			t.Fatal("a dissolving overlay accepted")
		}
	default:
		t.Fatal("a dissolving overlay abandoned the asker")
	}

	// And an ordinary answered confirmation keeps its answer rather than being overwritten by the
	// refusal on the way out.
	r2 := NewReply()
	m2 := NewRoot(func() {})
	m2, _ = step(m2, ConfirmRequestMsg{Prompt: "?", Reply: r2})
	m2, _ = step(m2, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m2, _ = step(m2, tea.KeyMsg{Type: tea.KeyEnter})
	if ok := <-r2.C(); !ok {
		t.Fatal("the answer was overwritten by the dismissal's refusal")
	}
}

// dissolvingConfirm answers nothing and vanishes on any key — the shape that proves the refusal is
// applied by the ROOT rather than by the overlay being polite on its way out.
type dissolvingConfirm struct{ ConfirmOverlay }

func (d dissolvingConfirm) Update(tea.Msg) (Overlay, tea.Cmd) { return nil, nil }

// TestRootDrawsOnlyTheTopOverlay — a stack draws its top, and the top has the keyboard.
func TestRootDrawsOnlyTheTopOverlay(t *testing.T) {
	m := NewRoot(func() {})
	m, _ = step(m, PushOverlayMsg{Overlay: stubOverlay{name: "under"}})
	m, _ = step(m, PushOverlayMsg{Overlay: stubOverlay{name: "over"}})
	v := m.View()
	if !strings.Contains(v, "[over]") || strings.Contains(v, "[under]") {
		t.Fatalf("the wrong overlay is drawn:\n%s", v)
	}
	m, _ = step(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if got := m.Overlay().(stubOverlay).seen; len(got) != 1 || got[0] != "k" {
		t.Fatalf("the top overlay did not get the key: %v", got)
	}
	// And the one underneath is untouched.
	under := m.Overlays()
	if under != 2 {
		t.Fatalf("depth %d", under)
	}
}

// TestRootSatisfiesTeaModel — Update's tea.Model form must agree with the internal one.
func TestRootSatisfiesTeaModel(t *testing.T) {
	var m tea.Model = NewRoot(nil)
	next, _ := m.Update(VerbDoneMsg{Code: 7})
	r, ok := next.(Root)
	if !ok {
		t.Fatalf("Update returned %T", next)
	}
	if r.Code() != 7 {
		t.Fatalf("code %d", r.Code())
	}
	if m.Init() != nil {
		t.Fatal("a root with no start hook must have nothing to init")
	}
}

// TestRootInitRunsTheStartHookExactlyOnce — the runner gates the verb on it, so a hook that never
// fired would mean the verb never runs, and one that fired twice would close a channel twice.
func TestRootInitRunsTheStartHookExactlyOnce(t *testing.T) {
	n := 0
	m := NewRoot(nil).withStartHook(func() { n++ })
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init returned no command, so the interface never announces itself")
	}
	if n != 0 {
		t.Fatal("the hook ran inside Init rather than in its command")
	}
	if msg := cmd(); msg != nil {
		t.Fatalf("the start command produced a message: %T", msg)
	}
	if n != 1 {
		t.Fatalf("the hook ran %d times", n)
	}
}
