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

// keyForRune is the key a terminal + Bubble Tea produce for one character of typed input.
//
// It exists because the parity table must drive the overlay the way the RUNTIME does, not the way
// that is convenient. Fabricating every character as KeyRunes was exactly that convenience, and it
// hid a real divergence: a tab is not a rune to Bubble Tea, it is KeyTab, and an overlay that
// dropped KeyTab accepted a line the plain path refuses. Control characters are reported as their
// own KeyType — whose value IS the ASCII code — and the space bar as KeySpace.
func keyForRune(r rune) tea.KeyMsg {
	switch {
	case r == ' ':
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case r < 0x20 || r == 0x7f:
		return tea.KeyMsg{Type: tea.KeyType(r)}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
	}
}

// typeRunes drives one keystroke per rune, the way a terminal delivers typing.
func typeRunes(t *testing.T, o Overlay, s string) Overlay {
	t.Helper()
	for _, r := range s {
		if o == nil {
			return nil
		}
		o, _ = o.Update(keyForRune(r))
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
		"ok", "1", "true",
		"Y\u202e", "y\x00", "\u200by",
		// The keys Bubble Tea reports as something other than a rune. Each of these bytes refuses
		// on the plain path — none appears in an accepted reply — and each must refuse here.
		"y\t", "\ty", "y\x01", "y\x1b", "\x1by", "y\x0b", "y\x1f", "y\x7f\x7f",
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

// TestConfirmUnclaimedKeysVetoTheReply. Dropping an unclaimed key was a real divergence and it fell
// the DANGEROUS way: `y<Tab><Enter>` submitted "y" and ACCEPTED here while the byte reader refuses
// "y\t". The rule is now structural — anything that is not typed text marks the line, and a marked
// line cannot be accepted however it reads.
func TestConfirmUnclaimedKeysVetoTheReply(t *testing.T) {
	unclaimed := []tea.KeyType{
		tea.KeyTab, tea.KeyCtrlA, tea.KeyNull, tea.KeyCtrlV, tea.KeyCtrlW, tea.KeyCtrlK,
		tea.KeyUp, tea.KeyDown, tea.KeyLeft, tea.KeyRight, tea.KeyF1, tea.KeyHome, tea.KeyEnd,
		tea.KeyPgUp, tea.KeyShiftTab, tea.KeyDelete, tea.KeyInsert,
	}
	for _, k := range unclaimed {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o = typeRunes(t, o, "y")
		o = press(t, o, k)
		if o == nil {
			t.Fatalf("key %v dismissed the overlay", k)
		}
		c := o.(ConfirmOverlay)
		if !c.Marked() {
			t.Fatalf("key %v did not mark the line", k)
		}
		// It reaches neither the buffer nor anything underneath the modal.
		if got := c.Input(); got != "y" {
			t.Fatalf("key %v wrote %q into the buffer", k, got)
		}
		o = press(t, o, tea.KeyEnter)
		if ok := <-r.C(); ok {
			t.Fatalf("key %v: `y` plus an unclaimed key was ACCEPTED", k)
		}
	}

	// The mark is STICKY: erasing back to a clean-looking line does not restore acceptance. This is
	// the interleaving that a per-key reconstructed BYTE would have got wrong — backspace would have
	// removed the byte and left an accepting "y".
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "y")
	o = press(t, o, tea.KeyCtrlW)
	o = press(t, o, tea.KeyBackspace)
	o = typeRunes(t, o, "y")
	if got := o.(ConfirmOverlay).Input(); got != "y" {
		t.Fatalf("buffer %q", got)
	}
	o = press(t, o, tea.KeyEnter)
	if ok := <-r.C(); ok {
		t.Fatal("erasing around an unclaimed key restored acceptance")
	}

	// An ALT modifier marks the line on ANY key, submit keys included: a terminal sends alt as an
	// ESC prefix, and no accepted reply contains one.
	for _, msg := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'x'}, Alt: true},
		{Type: tea.KeyEnter, Alt: true},
		{Type: tea.KeySpace, Runes: []rune{' '}, Alt: true},
	} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o = typeRunes(t, o, "y")
		o, _ = o.Update(msg)
		if o == nil {
			// alt+enter submits; it must have refused.
			if ok := <-r.C(); ok {
				t.Fatalf("%v was ACCEPTED", msg)
			}
			continue
		}
		if !o.(ConfirmOverlay).Marked() {
			t.Fatalf("%v did not mark the line", msg)
		}
		o = press(t, o, tea.KeyEnter)
		if ok := <-r.C(); ok {
			t.Fatalf("%v was ACCEPTED", msg)
		}
	}
}

// TestConfirmMarksOnInputItCannotName. Bubble Tea delivers more than KeyMsg: an unmapped CSI
// sequence (ctrl+delete on xterm, ESC [ 3 ; 5 ~) and a byte that is not valid UTF-8 each arrive as
// their own UNEXPORTED message type. Ignoring what cannot be named is how `y`, ctrl+delete, Enter
// came to ACCEPT while a pipe carrying "y\x1b[3;5~" refuses.
func TestConfirmMarksOnInputItCannotName(t *testing.T) {
	// Stand-ins for the unexported types: the test asserts the DEFAULT, which is what makes those
	// types safe without being nameable.
	type unnameableInput []byte
	for _, msg := range []tea.Msg{
		unnameableInput("\x1b[3;5~"),
		struct{ mouse int }{1},
		tea.Msg(nil),
	} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o = typeRunes(t, o, "y")
		o, _ = o.Update(msg)
		if o == nil {
			t.Fatalf("%T dismissed the overlay", msg)
		}
		if !o.(ConfirmOverlay).Marked() {
			t.Fatalf("%T did not mark the line", msg)
		}
		o = press(t, o, tea.KeyEnter)
		if ok := <-r.C(); ok {
			t.Fatalf("%T: `y` plus unnameable input was ACCEPTED", msg)
		}
	}

	// The package's own DATA messages are broadcast to every layer and must NOT mark: a narration
	// step arriving while a question is up would otherwise make the question unanswerable.
	for _, msg := range []tea.Msg{
		ProgressMsg{},
		OutputMsg{Line: "x"},
		PullProgressMsg{Status: "x"},
		VerbDoneMsg{},
		ConfirmRequestMsg{},
		PushOverlayMsg{},
		PopOverlayMsg{},
		tea.WindowSizeMsg{Width: 80, Height: 24},
	} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o = typeRunes(t, o, "y")
		o, _ = o.Update(msg)
		if o == nil {
			t.Fatalf("%T dismissed the overlay", msg)
		}
		if o.(ConfirmOverlay).Marked() {
			t.Fatalf("%T marked the line — a data message is not input", msg)
		}
		o = press(t, o, tea.KeyEnter)
		if ok := <-r.C(); !ok {
			t.Fatalf("%T made a typed `y` unacceptable", msg)
		}
	}
}

// TestConfirmKillClearsTheMark. ^U discards everything typed so far — that is the line discipline's
// own semantics, and it is the operator's way back from a stray keystroke without abandoning the
// operation. It cannot widen the accept-set: the reply must be typed again from nothing.
func TestConfirmKillClearsTheMark(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "y")
	o = press(t, o, tea.KeyTab)
	if !o.(ConfirmOverlay).Marked() {
		t.Fatal("the tab did not mark the line")
	}
	o = press(t, o, tea.KeyCtrlU)
	c := o.(ConfirmOverlay)
	if c.Marked() || c.Input() != "" {
		t.Fatalf("^U left marked=%v input=%q", c.Marked(), c.Input())
	}
	o = typeRunes(t, o, "yes")
	o = press(t, o, tea.KeyEnter)
	if ok := <-r.C(); !ok {
		t.Fatal("a line retyped after ^U was refused")
	}

	// AN ALT-MODIFIED KILL IS NOT A KILL. `y`, alt+^U, `y`, Enter must refuse: a terminal sends
	// alt+^U as ESC then 0x15, and the pipe bytes "y\x1b\x15y" refuse. Clearing the mark there let
	// the modifier's own mark be laundered away by the key that carried it.
	r3 := NewReply()
	var o3 Overlay = Confirm("Really?", r3)
	o3 = typeRunes(t, o3, "y")
	o3, _ = o3.Update(tea.KeyMsg{Type: tea.KeyCtrlU, Alt: true})
	if !o3.(ConfirmOverlay).Marked() {
		t.Fatal("alt+^U laundered the mark it had just set")
	}
	if got := o3.(ConfirmOverlay).Input(); got != "" {
		t.Fatalf("alt+^U left %q in the line", got)
	}
	o3 = typeRunes(t, o3, "y")
	o3 = press(t, o3, tea.KeyEnter)
	if ok := <-r3.C(); ok {
		t.Fatal("`y`, alt+^U, `y` was ACCEPTED")
	}
	if cliio.Confirm(nil, strings.NewReader("y\x1b\x15y\n"), io.Discard, "Proceed?") {
		t.Fatal("the plain path accepted the same bytes")
	}

	// And ^U alone does not make an empty line acceptable.
	r2 := NewReply()
	var o2 Overlay = Confirm("Really?", r2)
	o2 = press(t, o2, tea.KeyCtrlU)
	o2 = press(t, o2, tea.KeyEnter)
	if ok := <-r2.C(); ok {
		t.Fatal("an empty line after ^U was accepted")
	}
}

// TestConfirmMarkIsVisible — an operator whose reply cannot be accepted must be told why, or the
// prompt looks broken.
func TestConfirmMarkIsVisible(t *testing.T) {
	var o Overlay = Confirm("Really?", NewReply())
	if strings.Contains(o.View(), "only typed text") {
		t.Fatal("a clean prompt says the line is marked")
	}
	o = press(t, o, tea.KeyTab)
	if !strings.Contains(o.View(), "only typed text") {
		t.Fatalf("a marked prompt does not say so:\n%s", o.View())
	}
}

// TestConfirmCtrlDRefuses. ^D is end of transmission: on the plain path it makes the read fail —
// end of input on an empty line, a line without its terminator otherwise — and mi_confirm refuses on
// a failed read either way. Swallowing it here would leave the operator holding down the one key
// that means "no more input" against a modal that will not take it.
func TestConfirmCtrlDRefuses(t *testing.T) {
	for _, typed := range []string{"", "y", "yes"} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o = typeRunes(t, o, typed)
		o = press(t, o, tea.KeyCtrlD)
		if o != nil {
			t.Fatalf("typed %q: ^D left the question open", typed)
		}
		select {
		case ok := <-r.C():
			if ok {
				t.Fatalf("typed %q: ^D accepted", typed)
			}
		default:
			t.Fatalf("typed %q: ^D gave no answer — the asker would block", typed)
		}
		// The plain path answers the same, by both of its readings of "no more input": a stdin
		// that ends without a terminator, and the byte 0x04 sitting in a line.
		if cliio.Confirm(nil, strings.NewReader(typed), io.Discard, "Proceed?") {
			t.Fatalf("typed %q: the plain path accepted an unterminated line", typed)
		}
		if cliio.Confirm(nil, strings.NewReader(typed+"\x04\n"), io.Discard, "Proceed?") {
			t.Fatalf("typed %q: the plain path accepted a line containing 0x04", typed)
		}
	}
}

// TestConfirmCarriageReturnDependsOnHowItArrives, and both arrivals agree with the plain path.
//
// A bare CR is the one byte that is NOT the same input in the two worlds, and saying so is more
// useful than pretending it is. A pipe carrying "Y\r\n" gives the plain path the line "Y\r", which
// refuses. A TERMINAL never delivers a bare CR as data: the Enter key is the line terminator (the
// line discipline turns CR into NL), which is what KeyEnter means here — so pressing Y then Enter is
// the line "Y" and accepts, in both worlds. The only way a literal CR reaches the buffer is a PASTE,
// and there it stays in the line and refuses, exactly as the pipe does.
func TestConfirmCarriageReturnDependsOnHowItArrives(t *testing.T) {
	// Pasted: the CR is data, and the line refuses — as it does on the plain path.
	for _, paste := range []string{"Y\r", "yes\r", "\ry"} {
		r := NewReply()
		var o Overlay = Confirm("Really?", r)
		o, _ = o.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(paste), Paste: true})
		o = press(t, o, tea.KeyEnter)
		if o != nil {
			t.Fatalf("paste %q left the overlay open", paste)
		}
		if ok := <-r.C(); ok {
			t.Fatalf("paste %q was accepted", paste)
		}
		if cliio.Confirm(nil, strings.NewReader(paste+"\n"), io.Discard, "Proceed?") {
			t.Fatalf("paste %q: the plain path accepted it", paste)
		}
	}
	// Pressed: Enter is the terminator, so the line is what was typed before it.
	if !answerThroughOverlay(t, "Y") {
		t.Fatal("Y followed by Enter was refused")
	}
	if !cliio.Confirm(nil, strings.NewReader("Y\n"), io.Discard, "Proceed?") {
		t.Fatal("the plain path refused the line Y")
	}
}

// TestConfirmCtrlJSubmits — ^J is the line terminator a terminal delivers; the Enter key delivers CR
// and the line discipline turns it into the same thing.
func TestConfirmCtrlJSubmits(t *testing.T) {
	r := NewReply()
	var o Overlay = Confirm("Really?", r)
	o = typeRunes(t, o, "yes")
	o = press(t, o, tea.KeyCtrlJ)
	if o != nil {
		t.Fatal("^J did not submit")
	}
	if ok := <-r.C(); !ok {
		t.Fatal("`yes` submitted with ^J was refused")
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
