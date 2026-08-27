package ui

import (
	"strings"
	"sync"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/cliio"
)

// Reply is the one-shot answer channel a confirmation resolves into.
//
// It is a type rather than a bare `chan bool` so its two disciplines cannot be got wrong at a call
// site: the channel is BUFFERED (so answering never blocks the message loop) and it is answered
// AT MOST ONCE (so a stale copy of an overlay value — Bubble Tea models are copied on every
// Update — cannot send a second answer into a channel nobody will read again).
type Reply struct {
	once sync.Once
	ch   chan bool
}

// NewReply builds an unanswered Reply.
func NewReply() *Reply { return &Reply{ch: make(chan bool, 1)} }

// Resolve answers, exactly once; later calls are ignored. It never blocks: the channel has room
// for the single answer this type permits.
func (r *Reply) Resolve(ok bool) {
	if r == nil {
		return
	}
	r.once.Do(func() { r.ch <- ok })
}

// C is the receiving side — the asker waits here.
func (r *Reply) C() <-chan bool {
	if r == nil {
		return nil
	}
	return r.ch
}

// ConfirmRequestMsg is a verb asking its question. The bridge posts it from the verb's goroutine;
// the root turns it into an overlay. Reply is how the answer travels back.
type ConfirmRequestMsg struct {
	Prompt string
	Reply  *Reply
}

// ConfirmOverlay is the modal that asks a destructive-action question.
//
// IT IS NOT A KEY-PER-ANSWER PROMPT. It collects a COMPLETE LINE and submits on Enter, because the
// plain path reads a complete line too — `read -r` in the reference, cliio.Confirm here — and a
// front-end that accepted a bare `y` keystroke would make a purge one keypress away in one world
// and a typed word away in the other. The line is then handed, UNTRIMMED and UNMODIFIED, to
// cliio.AcceptedReply: the accept-set lives in exactly one function, so `yess`, ` y`, `y\r` and an
// empty line refuse in both worlds for the same reason.
//
// THE PARITY CLAIM, EXACTLY. The other world is NOT a terminal: the wiring rule sends every
// invocation whose stdin is a tty here, so cliio.Confirm always reads a pipe or a file — bytes up to
// a newline, no line discipline, no ERASE, no VEOF. Emulating a canonical terminal would therefore
// be emulating something nothing runs, and the attempt is a rabbit hole with a dangerous floor: the
// first version of this overlay SWALLOWED unclaimed keys, and `y<Tab><Enter>` accepted here while
// the byte reader refuses "y\t".
//
// So the rule is structural rather than imitative. The line is built ONLY from printable text the
// operator typed, edited with the two operations a line discipline offers (ERASE and KILL). ANY
// other input — a tab, a navigation key, an unclaimed control key, an alt modifier — marks the line
// as not-plainly-typed, and a marked line CANNOT be accepted no matter what it now reads as. The
// accept-set is then exactly the five strings, reachable only by typing them, which is a strict
// subset of what a pipe can express: this overlay can never be the EASIER of the two.
//
// KILL (^U) clears the mark along with the line. That is the line discipline's own semantics — ^U
// discards everything typed so far — and it is the operator's way back from a stray keystroke
// without abandoning the operation. It cannot widen the accept-set: after ^U the reply must be
// typed again from nothing.
//
// Esc refuses. So does ^D, which is the operator saying there is no more input. So does the
// interface going away without an answer — see Bridge.
//
// A PASTE IS NOT AN ANSWER — see the msg.Paste branch in handleKey for why, and for the one place
// this overlay is deliberately stricter than the pipe. The program also declines to turn bracketed
// paste ON (see programOptions), which is defence in depth rather than the fix: that option only
// skips ENABLING the terminal mode, and Bubble Tea's decoder runs regardless.
//
// STATED RESIDUAL, and it is a property of the transport rather than of this code: with bracketing
// off, a terminal gives no signal that distinguishes pasted bytes from typed ones. A CR among them
// is then the Enter key, because that is what a terminal means by CR — so pasting "y\r\n" without
// bracketing answers as typing y and pressing Enter does. The pipe, which has no Enter key, reads
// the same bytes as the line "y\r" and refuses. Nothing in a model can tell the two apart when the
// terminal does not.
//
// Signature note (a deliberate, documented widening of the plan's `Confirm(prompt string)
// Overlay`): the constructor takes the Reply as well. An overlay with nowhere to send its answer
// cannot resolve anything, and correlating answers back to askers through a package-level side
// table would be a second source of truth about which question is open.
type ConfirmOverlay struct {
	prompt string
	input  []rune
	reply  *Reply
	// marked records that something other than plainly typed text has reached this prompt. It is
	// STICKY (except through KILL, which discards the line) and it VETOES acceptance: the reply is
	// then refused whatever the buffer happens to read as.
	marked bool
	// answered records that this overlay has already resolved. Reply.Resolve is idempotent on its
	// own; this field is what keeps the VIEW and the key handling honest about it.
	answered bool
	width    int
}

var _ Overlay = ConfirmOverlay{}

// Confirm builds the confirmation overlay for one question.
func Confirm(prompt string, reply *Reply) ConfirmOverlay {
	if prompt == "" {
		// The same default the plain path applies, so the two prompts read alike.
		prompt = "Proceed?"
	}
	return ConfirmOverlay{prompt: prompt, reply: reply}
}

// Prompt is the question as asked.
func (o ConfirmOverlay) Prompt() string { return o.prompt }

// Input is the line typed so far, exactly as typed — no trimming, no folding. Tests compare
// against this to prove the buffer is what AcceptedReply will be shown.
func (o ConfirmOverlay) Input() string { return string(o.input) }

// Answered reports whether this overlay has resolved its question.
func (o ConfirmOverlay) Answered() bool { return o.answered }

// Marked reports that something other than plainly typed text has reached this prompt, so the reply
// cannot be accepted until the line is discarded with ^U and typed again.
func (o ConfirmOverlay) Marked() bool { return o.marked }

// accepted is the ONE place the answer is decided: the mark vetoes, and the line is judged by the
// same function the plain path uses.
func (o ConfirmOverlay) accepted() bool {
	return !o.marked && cliio.AcceptedReply(string(o.input))
}

// Init has nothing to start.
func (o ConfirmOverlay) Init() tea.Cmd { return nil }

// Update implements Overlay.
//
// THE DEFAULT BRANCH MARKS THE LINE, and that is the whole point of writing it this way.
//
// Bubble Tea does not deliver only KeyMsg. Input it cannot map — an unknown CSI sequence from a key
// this build has no name for (ctrl+delete on xterm, `ESC [ 3 ; 5 ~`), or a byte that is not valid
// UTF-8 — arrives as its OWN message type, and those types are UNEXPORTED, so they cannot be named
// here. Ignoring what cannot be named is how `y`, ctrl+delete, Enter came to ACCEPT while a pipe
// carrying "y\x1b[3;5~" refuses. A mouse click or a focus change is not typed text either.
//
// So everything this package did not itself send is treated as input that is not text. A DATA
// message added to this package later must be added to the list below; the failure if it is not is a
// confirmation that refuses and says so in its own footer — loud, safe, and visible.
func (o ConfirmOverlay) Update(msg tea.Msg) (Overlay, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		o.width = msg.Width
		return o, nil
	case tea.KeyMsg:
		return o.handleKey(msg)
	case ProgressMsg, OutputMsg, PullProgressMsg, VerbDoneMsg,
		ConfirmRequestMsg, PushOverlayMsg, PopOverlayMsg:
		// This package's own messages, broadcast to every layer. They say nothing about what the
		// operator typed.
		return o, nil
	}
	o.marked = true
	return o, nil
}

// handleKey is the whole editor: append, backspace, clear, submit, refuse.
//
// THE ANSWER IS SENT FROM HERE, INLINE, rather than from a returned tea.Cmd. That is a departure
// from the pure-state-machine shape of the rest of the model and it is deliberate: a Cmd is
// executed by the runtime, and a runtime that is shutting down may never execute it — which would
// leave the asking verb blocked on an answer that was given and then dropped. The send cannot
// block (Reply is buffered, cap one, and answered at most once), so nothing about the message loop
// depends on the asker being ready to receive.
func (o ConfirmOverlay) handleKey(msg tea.KeyMsg) (Overlay, tea.Cmd) {
	// An ALT MODIFIER is not typed text on any key — a terminal sends it as an ESC prefix, which no
	// accepted reply contains. It marks the line whatever key carries it.
	if msg.Alt {
		o.marked = true
	}
	// A PASTE IS NOT TYPED TEXT EITHER, and this is the one place the two worlds are deliberately
	// asymmetric. Bubble Tea's paste decoder is LOSSY: it silently drops every rune that decodes to
	// U+FFFD, so the runes handed over are not the bytes that were pasted, and a clipboard
	// containing the paste terminator ends the paste early so its tail is decoded separately.
	// Judging an accept on a lossy transform of the input is unsound whichever way it falls, and the
	// decoder runs whether or not the program enabled bracketed paste in the terminal
	// (WithoutBracketedPaste only skips ENABLING it — measured against v1.3.10). So a paste is
	// marked, and the reply must be typed.
	//
	// This is the direction that makes the confirmation HARDER than the pipe's, knowingly: pasting
	// "yes" no longer answers it. That is the safe half of the asymmetry, it is recoverable in one
	// keystroke (^U clears the line and the mark), and the prompt says so in its own footer.
	if msg.Paste {
		o.marked = true
	}
	switch msg.Type {
	case tea.KeyEsc:
		// Cancel is a REFUSAL, not a dismissal: the verb asked and must be told.
		return o.resolve(false)
	case tea.KeyCtrlD:
		// ^D is the operator saying there is no more input. On the plain path the equivalent — a
		// stdin that ends without an answer — REFUSES, and so does the byte 0x04 sitting in a line.
		// Swallowing it would leave the question open on the one keystroke that means "no".
		return o.resolve(false)
	case tea.KeyEnter, tea.KeyCtrlJ:
		// Both submit: a terminal's Enter delivers CR, ^J delivers NL, and the line discipline makes
		// them the same terminator.
		return o.resolve(o.accepted())
	case tea.KeyBackspace:
		// ERASE. It removes a character; it cannot remove an event that put no character there, so
		// it does not clear the mark.
		if n := len(o.input); n > 0 {
			o.input = append([]rune(nil), o.input[:n-1]...)
		}
		return o, nil
	case tea.KeyCtrlU:
		// KILL discards everything typed so far — the mark with it. See the type comment.
		//
		// AN ALT-MODIFIED KILL IS NOT A KILL. A terminal sends it as ESC then 0x15, two bytes that
		// sit in the line and that no accepted reply contains; treating it as a KILL let alt+^U
		// LAUNDER the mark the alt modifier had just set, and `y`, alt+^U, `y`, Enter accepted
		// where the pipe bytes refuse. The line still clears — that costs nothing — but the mark
		// stays.
		o.input = nil
		if !msg.Alt {
			o.marked = false
		}
		return o, nil
	case tea.KeyRunes, tea.KeySpace:
		// A NEWLINE INSIDE THE INPUT SUBMITS WHAT PRECEDES IT, and everything after it is
		// discarded. That is what the plain path does — its reader takes bytes up to the first
		// `\n` and stops — and it is reachable here through a bracketed paste. Inserting the
		// newline into the buffer instead would make a pasted "y\n" refuse in this world and
		// accept in the other, for the same keystrokes.
		if i := indexRune(msg.Runes, '\n'); i >= 0 {
			o = o.appendRunes(msg.Runes[:i])
			return o.resolve(o.accepted())
		}
		return o.insert(msg), nil
	}
	// EVERY OTHER KEY MARKS THE LINE: a tab, an arrow, a function key, ^W, ^K, anything this editor
	// does not claim. None of them is text the operator typed, none of them appears in an accepted
	// reply, and the first version of this overlay simply dropped them — which let `y<Tab><Enter>`
	// submit "y" and ACCEPT while the byte reader refuses "y\t". Marking is the fail-closed reading
	// and it needs no claim about what byte a terminal would have produced.
	//
	// Nothing reaches what is underneath the modal either way; that property is unchanged.
	o.marked = true
	return o, nil
}

// insert appends the message's runes to the buffer.
//
// NOTHING IS FILTERED OUT. A control or bidi rune in a paste stays in the buffer, because the
// buffer is what AcceptedReply is shown and the plain path keeps those bytes too (its reader takes
// raw bytes up to the newline). Dropping them here would make "y<NUL>" — which refuses in the plain
// path — become "y" and ACCEPT, which is precisely the drift between the two worlds this package
// exists to prevent. Such runes are made harmless at RENDER time instead; see sanitize.
func (o ConfirmOverlay) insert(msg tea.KeyMsg) ConfirmOverlay {
	if msg.Type == tea.KeySpace && len(msg.Runes) == 0 {
		// Bubble Tea reports the space bar as KeySpace with the rune in Runes; a build that ever
		// reports it empty must still insert a space rather than nothing.
		return o.appendRunes([]rune{' '})
	}
	if len(msg.Runes) == 0 {
		return o
	}
	return o.appendRunes(msg.Runes)
}

// appendRunes adds runes to the buffer.
//
// The buffer is COPIED before the first append: the receiver is a value, but its slice header points
// at shared backing memory, so appending in place can write into an array an earlier model value is
// still using.
func (o ConfirmOverlay) appendRunes(rs []rune) ConfirmOverlay {
	next := make([]rune, 0, len(o.input)+len(rs))
	next = append(next, o.input...)
	next = append(next, rs...)
	o.input = next
	return o
}

func indexRune(rs []rune, want rune) int {
	for i, r := range rs {
		if r == want {
			return i
		}
	}
	return -1
}

// resolve answers the question and dismisses the overlay.
func (o ConfirmOverlay) resolve(ok bool) (Overlay, tea.Cmd) {
	if o.answered {
		return o, nil
	}
	o.answered = true
	o.reply.Resolve(ok)
	// A nil Overlay is a pop; the root needs no separate command.
	return nil, nil
}

// Refuse answers false without a keystroke — what the root does to every open question when the
// operation is being cancelled, so the screen and the verb agree immediately instead of the verb
// finding out later through the bridge's release path.
func (o ConfirmOverlay) Refuse() {
	o.reply.Resolve(false)
}

// View renders the question, the line so far, and the two keys that end it.
func (o ConfirmOverlay) View() string {
	var b strings.Builder
	b.WriteString(sanitize(o.prompt))
	b.WriteString(" [y/N]\n")
	b.WriteString("> ")
	b.WriteString(sanitize(string(o.input)))
	b.WriteString("\n")
	if o.marked {
		b.WriteString("only typed text is accepted here — ctrl+u clears the line\n")
	}
	b.WriteString("enter submits · esc refuses")
	return b.String()
}

// sanitize replaces anything that must not reach a terminal with a visible placeholder.
//
// It is a RENDERING transform and nothing else — the buffer it is shown is never changed, so what
// the operator approves and what AcceptedReply judges are the same string. Escape sequences and
// bidi overrides are what it exists for: a pasted U+202E can otherwise make a refusing line render
// as an accepting one.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), isBidiControl(r), r == '\ufeff':
			b.WriteRune('\ufffd')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isBidiControl reports the Bidi_Control code points. unicode.IsControl does NOT cover them — they
// are Cf, not Cc — and they are the ones that reorder a rendered line.
func isBidiControl(r rune) bool {
	switch r {
	case '\u061c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	}
	return false
}
