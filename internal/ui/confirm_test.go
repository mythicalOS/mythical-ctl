// NO BATS INVENTORY. This package has no share of tests/unit/*.bats and claims none: the frozen
// reference is a shell CLI with no terminal interface at all — no root model, no overlay, no
// progress pane — so there is no bats test for any of it to port. What the reference DOES define is
// the confirmation CONTRACT (lib/verbs.sh's mi_confirm), and that is already ported, once, as
// cliio.Confirm/cliio.AcceptedReply with tests/unit/verbs.bats claimed by Task 22. The tests below
// do not re-port it; they prove this package REACHES it — that the same reply produces the same
// answer through the overlay as through the plain path, and that MI_CONFIRM never meets an overlay.
package ui

import (
	"io"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/cliio"
)

// typeRunes drives one keystroke per rune, the way a terminal delivers typing.
func typeRunes(t *testing.T, o Overlay, s string) Overlay {
	t.Helper()
	for _, r := range s {
		if o == nil {
			return nil
		}
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
		if r == ' ' {
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
		}
		o, _ = o.Update(msg)
	}
	return o
}

func press(t *testing.T, o Overlay, k tea.KeyType) Overlay {
	t.Helper()
	if o == nil {
		return nil
	}
	next, _ := o.Update(tea.KeyMsg{Type: k})
	return next
}

// answerThroughOverlay types a line, presses Enter, and returns the answer the asker receives.
func answerThroughOverlay(t *testing.T, line string) bool {
	t.Helper()
	r := NewReply()
	var o Overlay = Confirm("Proceed?", r)
	o = typeRunes(t, o, line)
	o = press(t, o, tea.KeyEnter)
	if o != nil {
		t.Fatalf("a submitted confirmation must dismiss itself; %q left one installed", line)
	}
	select {
	case ok := <-r.C():
		return ok
	default:
		t.Fatalf("no answer reached the asker for %q", line)
		return false
	}
}

// TestOverlayAndPlainPathAgreeOnEveryReply is the anti-drift assertion this package exists for: for
// the same reply, the overlay and cliio.Confirm return the SAME answer. A destructive verb must not
// be easier to confirm in one world than in the other.
func TestOverlayAndPlainPathAgreeOnEveryReply(t *testing.T) {
	// The five accepted forms, then everything nearby that must NOT be accepted.
	lines := []string{
		"y", "Y", "yes", "Yes", "YES",
		"n", "N", "no", "No", "NO",
		"", " ", "  y", "y ", " y ", "yess", "yy", "ye", "YEs", "yEs", "yes!",
		"ok", "1", "true", "Y\r", "yes\r", "\ry",
		"Y\u202e", "y\x00", "\u200by",
	}
	for _, line := range lines {
		plain := cliio.Confirm(nil, strings.NewReader(line+"\n"), io.Discard, "Proceed?")
		tui := answerThroughOverlay(t, line)
		if plain != tui {
			t.Errorf("reply %q: plain path %v, overlay %v — the two worlds disagree", line, plain, tui)
		}
		// And the accept-set is exactly the five forms, asserted directly so a change to BOTH
		// implementations at once still reddens.
		want := line == "y" || line == "Y" || line == "yes" || line == "Yes" || line == "YES"
		if tui != want {
			t.Errorf("reply %q: overlay accepted=%v, want %v", line, tui, want)
		}
	}
}

// TestConfirmSubmitsOnEnterOnly pins the shape of the prompt: a bare `y` keystroke is NOT an
// answer. The plain path reads a complete line, and a front-end that armed a purge on one keypress
// would be a materially easier trigger for the same operation.
func TestConfirmSubmitsOnEnterOnly(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "y")
	if o == nil {
		t.Fatal("typing y dismissed the overlay — it must wait for Enter")
	}
	select {
	case ok := <-r.C():
		t.Fatalf("typing y answered %v without Enter", ok)
	default:
	}
	if got := o.(ConfirmOverlay).Input(); got != "y" {
		t.Fatalf("buffer %q", got)
	}
	o = press(t, o, tea.KeyEnter)
	if o != nil {
		t.Fatal("Enter must dismiss")
	}
	if ok := <-r.C(); !ok {
		t.Fatal("y + Enter must accept")
	}
}

// TestConfirmEscRefuses — cancelling is an ANSWER, not a dismissal. An overlay that vanished without
// answering would leave the verb blocked until teardown.
func TestConfirmEscRefuses(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "yes")
	o = press(t, o, tea.KeyEsc)
	if o != nil {
		t.Fatal("esc must dismiss the overlay")
	}
	select {
	case ok := <-r.C():
		if ok {
			t.Fatal("esc accepted — cancel must refuse even with `yes` typed")
		}
	default:
		t.Fatal("esc gave no answer at all — the asker would block")
	}
}

// TestConfirmRefuseAnswersWithoutAKeystroke covers the root's cancel path.
func TestConfirmRefuseAnswersWithoutAKeystroke(t *testing.T) {
	r := NewReply()
	o := Confirm("Really?", r)
	o.Refuse()
	if ok := <-r.C(); ok {
		t.Fatal("Refuse accepted")
	}
}

// TestConfirmEditing covers backspace and ctrl+u, and — the part that matters — that neither can
// leave a buffer that reads as accepted when the typed text was not.
func TestConfirmEditing(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "yess")
	o = press(t, o, tea.KeyBackspace)
	if got := o.(ConfirmOverlay).Input(); got != "yes" {
		t.Fatalf("after backspace: %q", got)
	}
	o = press(t, o, tea.KeyCtrlU)
	if got := o.(ConfirmOverlay).Input(); got != "" {
		t.Fatalf("after ctrl+u: %q", got)
	}
	o = press(t, o, tea.KeyEnter)
	if ok := <-r.C(); ok {
		t.Fatal("an empty line accepted")
	}
	// Backspace on an empty buffer must not panic or underflow.
	r2 := NewReply()
	var o2 Overlay = Confirm("Really?", r2)
	o2 = press(t, o2, tea.KeyBackspace)
	if got := o2.(ConfirmOverlay).Input(); got != "" {
		t.Fatalf("backspace on empty: %q", got)
	}
}

// TestConfirmKeepsControlBytesInTheBuffer is the drift guard on the input filter. cliio.Confirm
// keeps every byte up to the newline, so "y\x00" REFUSES there; an overlay that stripped the NUL
// would hold "y" and ACCEPT. The bytes stay; only the rendering is made safe.
func TestConfirmKeepsControlBytesInTheBuffer(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o, _ = o.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y', '\x00'}})
	if got := o.(ConfirmOverlay).Input(); got != "y\x00" {
		t.Fatalf("buffer %q — the control rune must survive into the buffer", got)
	}
	if strings.ContainsRune(o.View(), '\x00') {
		t.Fatal("the control rune reached the rendered view")
	}
	o = press(t, o, tea.KeyEnter)
	if ok := <-r.C(); ok {
		t.Fatal("y+NUL accepted")
	}
}

// TestConfirmPastedNewlineSubmits — the plain path's reader stops at the first newline, so a pasted
// "y\n…" is an accepted answer there. Buffering the newline instead would refuse it here.
func TestConfirmPastedNewlineSubmits(t *testing.T) {
	for _, tc := range []struct {
		paste string
		want  bool
	}{
		{"y\n", true},
		{"yes\nrm -rf /\n", true},
		{"\ny", false},
		{"yess\ny", false},
	} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o, _ = o.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tc.paste), Paste: true})
		if o != nil {
			t.Fatalf("paste %q left the overlay open — the newline must submit", tc.paste)
		}
		got := <-r.C()
		if got != tc.want {
			t.Errorf("paste %q: %v, want %v", tc.paste, got, tc.want)
		}
		// And the plain path agrees, byte for byte, on the same input.
		plain := cliio.Confirm(nil, strings.NewReader(tc.paste), io.Discard, "Proceed?")
		if plain != tc.want {
			t.Errorf("paste %q: plain path %v, want %v", tc.paste, plain, tc.want)
		}
	}
}

// TestConfirmSwallowsUnclaimedKeys — a modal that let arrows through would move a selection the
// operator cannot see.
func TestConfirmSwallowsUnclaimedKeys(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	for _, k := range []tea.KeyType{tea.KeyUp, tea.KeyDown, tea.KeyTab, tea.KeyF1, tea.KeyCtrlA, tea.KeyHome} {
		o = press(t, o, k)
		if o == nil {
			t.Fatalf("key %v dismissed the overlay", k)
		}
		if got := o.(ConfirmOverlay).Input(); got != "" {
			t.Fatalf("key %v wrote %q into the buffer", k, got)
		}
	}
	select {
	case <-r.C():
		t.Fatal("an unclaimed key answered the question")
	default:
	}
}

// TestReplyAnswersAtMostOnce — Bubble Tea copies models on every Update, so a stale copy can try to
// answer again. A second send into a channel nobody is reading would block the message loop.
func TestReplyAnswersAtMostOnce(t *testing.T) {
	r := NewReply()
	r.Resolve(true)
	r.Resolve(false)
	r.Resolve(false)
	if ok := <-r.C(); !ok {
		t.Fatal("the first answer must win")
	}
	select {
	case extra := <-r.C():
		t.Fatalf("a second answer got through: %v", extra)
	default:
	}
	// A nil Reply is inert rather than a panic: an overlay built without one must not take the
	// program down.
	var none *Reply
	none.Resolve(true)
	if none.C() != nil {
		t.Fatal("a nil Reply must have no channel")
	}
}

// TestConfirmDoubleSubmitCannotAnswerTwice drives the stale-copy case directly.
func TestConfirmDoubleSubmitCannotAnswerTwice(t *testing.T) {
	r := NewReply()
	stale := Confirm("Really?", r)
	typed := typeRunes(t, stale, "y").(ConfirmOverlay)
	if next, _ := typed.Update(tea.KeyMsg{Type: tea.KeyEnter}); next != nil {
		t.Fatal("submit must dismiss")
	}
	// The stale, pre-Enter copy is still a valid value; submitting it again must change nothing.
	if next, _ := stale.Update(tea.KeyMsg{Type: tea.KeyEnter}); next != nil {
		t.Fatal("submit must dismiss")
	}
	if ok := <-r.C(); !ok {
		t.Fatal("the first answer must win")
	}
	select {
	case extra := <-r.C():
		t.Fatalf("the stale copy answered too: %v", extra)
	default:
	}
}

// TestConfirmViewSanitizes — a pasted bidi override must not be able to make a refusing line render
// as an accepting one.
func TestConfirmViewSanitizes(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Wipe \u202eeveryone\u202c?", r)
	o, _ = o.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y\u200fes")})
	v := o.View()
	for _, bad := range []rune{'\u202e', '\u202c', '\u200f', '\ufeff'} {
		if strings.ContainsRune(v, bad) {
			t.Errorf("%U reached the rendered view", bad)
		}
	}
	if !strings.Contains(v, "[y/N]") {
		t.Errorf("the view must say which way the default falls: %q", v)
	}
}

// TestConfirmDefaultPrompt — an empty prompt reads the same in both worlds.
func TestConfirmDefaultPrompt(t *testing.T) {
	if got := Confirm("", nil).Prompt(); got != "Proceed?" {
		t.Fatalf("default prompt %q", got)
	}
}
