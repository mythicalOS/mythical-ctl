package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/verbs"
)

// ProgressMsg is one narration step, posted from the verb's goroutine by the bridge. It carries the
// verb layer's own event type rather than a copy of its fields: a second shape here would be a
// second thing to keep in step, and the only thing it could ever add is drift.
type ProgressMsg struct{ Event verbs.ProgressEvent }

// OutputMsg is one COMPLETE line a verb wrote straight to a stream rather than through the progress
// seam — a warning, an error relay.
//
// It exists because those writes must not reach the real terminal while the renderer owns it: a
// bare Fprintln into a live Bubble Tea frame interleaves with the repaint and corrupts the screen,
// and suppressing the write instead would LOSE a diagnostic. Both are worse than routing it.
type OutputMsg struct {
	Line string
	// Stderr distinguishes a diagnostic from ordinary output. It survives into the transcript so
	// nothing has to guess which stream a line came from when it is flushed or replayed.
	Stderr bool
}

// PullProgressMsg is an image-pull status line from the engine's pull stream. The engine's pull
// path takes a callback for exactly this (Mutator.PullProgress); a front-end that shows a stalled
// screen through a 400MB pull is the reason it is there.
type PullProgressMsg struct{ Status string }

// maxTranscript bounds what the pane retains. A pull is thousands of status records and a batch
// over five products is hundreds of steps; an unbounded transcript is a memory leak whose size is
// chosen by the registry.
const maxTranscript = 200

// visibleTranscript is how many retained lines the pane draws. The rest stays in the terminal's own
// scrollback, where a verb's narration is written line by line as it happens.
const visibleTranscript = 8

// Progress is the pane that narrates a running verb: the step it is on, and the tail of what it has
// said so far.
type Progress struct {
	stage  string
	detail string
	// pull is the most recent image-pull status. It is kept SEPARATE from the transcript: a pull
	// emits a record per layer per tick, and folding those into the transcript would push every
	// verb step out of the visible tail within a second.
	pull  string
	lines []string

	width int
	// done marks the verb as finished; the pane then stops presenting a live step.
	done bool
}

var _ tea.Model = Progress{}

// NewProgress builds an empty pane.
func NewProgress() Progress { return Progress{} }

// Stage, Detail and Pull are the pane's projections, for the root and for tests.
func (p Progress) Stage() string  { return p.stage }
func (p Progress) Detail() string { return p.detail }
func (p Progress) Pull() string   { return p.pull }

// Lines is the retained transcript, oldest first.
func (p Progress) Lines() []string { return p.lines }

// Init has nothing to start: every event arrives from the outside.
func (p Progress) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (p Progress) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := p.update(msg)
	return next, cmd
}

func (p Progress) update(msg tea.Msg) (Progress, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		return p, nil

	case ProgressMsg:
		p.stage, p.detail = msg.Event.Stage, msg.Event.Detail
		// A step supersedes whatever the pull was reporting: the pull is over, or was never the
		// thing being waited on.
		p.pull = ""
		return p.append(msg.Event.Detail), nil

	case OutputMsg:
		return p.append(msg.Line), nil

	case PullProgressMsg:
		// Pull status REPLACES rather than accumulates — see the field comment.
		p.pull = msg.Status
		return p, nil

	case VerbDoneMsg:
		p.done = true
		return p, nil
	}
	return p, nil
}

// append adds one line to the bounded transcript.
func (p Progress) append(line string) Progress {
	// Copied before growing: the receiver is a value and its slice header is shared with every
	// earlier copy of this model.
	next := make([]string, 0, len(p.lines)+1)
	next = append(next, p.lines...)
	next = append(next, line)
	if len(next) > maxTranscript {
		next = next[len(next)-maxTranscript:]
	}
	p.lines = next
	return p
}

// View renders the tail of the transcript and, while a verb is still running, the live step.
func (p Progress) View() string {
	var b strings.Builder
	tail := p.lines
	if len(tail) > visibleTranscript {
		tail = tail[len(tail)-visibleTranscript:]
	}
	for _, l := range tail {
		b.WriteString(sanitize(l))
		b.WriteString("\n")
	}
	if p.done {
		return b.String()
	}
	switch {
	case p.pull != "":
		b.WriteString("… " + sanitize(p.pull))
	case p.stage != "":
		b.WriteString("… " + sanitize(p.stage))
	default:
		b.WriteString("… working")
	}
	return b.String()
}
