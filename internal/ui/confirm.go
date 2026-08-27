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
// Esc refuses. So does the interface going away without an answer — see Bridge.
//
// Signature note (a deliberate, documented widening of the plan's `Confirm(prompt string)
// Overlay`): the constructor takes the Reply as well. An overlay with nowhere to send its answer
// cannot resolve anything, and correlating answers back to askers through a package-level side
// table would be a second source of truth about which question is open.
type ConfirmOverlay struct {
	prompt string
	input  []rune
	reply  *Reply
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

// Init has nothing to start.
func (o ConfirmOverlay) Init() tea.Cmd { return nil }

// Update implements Overlay.
func (o ConfirmOverlay) Update(msg tea.Msg) (Overlay, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		o.width = msg.Width
		return o, nil
	case tea.KeyMsg:
		return o.handleKey(msg)
	}
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
	switch msg.Type {
	case tea.KeyEsc:
		// Cancel is a REFUSAL, not a dismissal: the verb asked and must be told.
		return o.resolve(false)
	case tea.KeyCtrlD:
		// ^D is END OF TRANSMISSION. On the plain path it makes the read FAIL — end of input on an
		// empty line, and a line delivered without its terminator otherwise — and mi_confirm
		// refuses on a failed read either way. Swallowing it here would leave the question open on
		// a keystroke that means "no more input", which is the one divergence that makes the modal
		// impossible to get out of by the means the other world offers.
		return o.resolve(false)
	case tea.KeyCtrlJ:
		// ^J IS the line terminator a terminal delivers (NL); the Enter key delivers CR, which the
		// line discipline turns into the same thing. Both submit.
		return o.resolve(cliio.AcceptedReply(string(o.input)))
	case tea.KeyEnter:
		// The buffer is submitted AS TYPED. Trimming here would accept " y" in this world and
		// refuse it in the plain one.
		return o.resolve(cliio.AcceptedReply(string(o.input)))
	case tea.KeyBackspace:
		if n := len(o.input); n > 0 {
			o.input = append([]rune(nil), o.input[:n-1]...)
		}
		return o, nil
	case tea.KeyCtrlU:
		o.input = nil
		return o, nil
	case tea.KeyRunes, tea.KeySpace:
		// A NEWLINE INSIDE THE INPUT SUBMITS WHAT PRECEDES IT, and everything after it is
		// discarded. That is what the plain path does — its reader takes bytes up to the first
		// `\n` and stops — and it is reachable here through a bracketed paste. Inserting the
		// newline into the buffer instead would make a pasted "y\n" refuse in this world and
		// accept in the other, for the same keystrokes.
		if i := indexRune(msg.Runes, '\n'); i >= 0 {
			o = o.appendRunes(msg.Runes[:i])
			return o.resolve(cliio.AcceptedReply(string(o.input)))
		}
		return o.insert(msg), nil
	}
	// EVERY OTHER KEY CONTRIBUTES TO THE LINE, exactly as it would on the plain path.
	//
	// Swallowing them was a real divergence, and it fell the DANGEROUS way: a terminal reading a
	// line puts the tab byte into it, so `y<Tab><Enter>` gives the plain path "y\t" and REFUSES —
	// while an editor that dropped the tab would submit "y" and ACCEPT. The same for every
	// unclaimed control key and for an escape sequence from an arrow or function key. Reconstructing
	// the byte keeps the buffer equal to the line the other world would have read, which is the only
	// way the two can be held to one accept-set.
	//
	// Nothing reaches what is underneath the modal either way; that property is unchanged.
	return o.appendUnclaimed(msg), nil
}

// appendUnclaimed adds the bytes an unclaimed key would have put into a line.
//
// Bubble Tea's control-key KeyTypes ARE their ASCII codes (KeyTab == 9, KeyCtrlA == 1, KeyNull == 0,
// and so on up to DEL), so a control key reconstructs exactly. The navigation keys — arrows,
// function keys, page and home — have negative KeyTypes and arrive at a line-reading terminal as an
// ESCAPE SEQUENCE; the introducer alone is appended, which is enough to make the line refuse for the
// same reason the full sequence would, and is not a claim to reproduce the sequence byte for byte.
// An alt-modified key is ESC-prefixed, which is how a terminal sends it.
func (o ConfirmOverlay) appendUnclaimed(msg tea.KeyMsg) ConfirmOverlay {
	var rs []rune
	if msg.Alt {
		rs = append(rs, '\x1b')
	}
	if t := int(msg.Type); t >= 0 && t <= 127 {
		rs = append(rs, rune(t))
	} else {
		rs = append(rs, '\x1b')
	}
	return o.appendRunes(rs)
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
		if msg.Alt {
			return o.appendRunes([]rune{'\x1b', ' '})
		}
		return o.appendRunes([]rune{' '})
	}
	if len(msg.Runes) == 0 {
		return o
	}
	if msg.Alt {
		// A terminal sends alt+x as ESC then x, so the line the plain path reads carries the ESC.
		return o.appendRunes(append([]rune{'\x1b'}, msg.Runes...))
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
