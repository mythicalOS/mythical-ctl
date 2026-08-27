// NO BATS INVENTORY — see confirm_test.go's header.
package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"mythicalos.ai/ctl/internal/verbs"
)

func progStep(p Progress, msg tea.Msg) Progress {
	next, _ := p.update(msg)
	return next
}

// TestProgressRecordsTheVerbsNarration — the pane's transcript is the verb's own lines, in order.
func TestProgressRecordsTheVerbsNarration(t *testing.T) {
	p := NewProgress()
	p = progStep(p, ProgressMsg{Event: verbs.ProgressEvent{Stage: "preflight", Detail: "checking the runtime"}})
	p = progStep(p, ProgressMsg{Event: verbs.ProgressEvent{Stage: "pull", Detail: "pulling brokkr"}})
	if got := p.Stage(); got != "pull" {
		t.Fatalf("stage %q", got)
	}
	if got := p.Detail(); got != "pulling brokkr" {
		t.Fatalf("detail %q", got)
	}
	want := []string{"checking the runtime", "pulling brokkr"}
	if got := p.Lines(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("transcript %q", got)
	}
	v := p.View()
	for _, w := range want {
		if !strings.Contains(v, w) {
			t.Fatalf("%q missing from the view:\n%s", w, v)
		}
	}
}

// TestProgressKeepsStreamWritesToo — a warning a verb writes straight to stderr must not vanish
// because the renderer owns the terminal.
func TestProgressKeepsStreamWritesToo(t *testing.T) {
	p := NewProgress()
	p = progStep(p, OutputMsg{Line: "mythical-ctl: the network is already attached", Stderr: true})
	if got := p.Lines(); len(got) != 1 || !strings.Contains(got[0], "already attached") {
		t.Fatalf("transcript %q", got)
	}
}

// TestProgressPullStatusReplacesRatherThanAccumulates. A pull emits a record per layer per tick;
// folding those into the transcript would push every actual step out of the visible tail within a
// second, and would grow without bound.
func TestProgressPullStatusReplacesRatherThanAccumulates(t *testing.T) {
	p := NewProgress()
	p = progStep(p, ProgressMsg{Event: verbs.ProgressEvent{Stage: "pull", Detail: "pulling brokkr"}})
	for i := 0; i < 500; i++ {
		p = progStep(p, PullProgressMsg{Status: fmt.Sprintf("layer%d: Downloading", i)})
	}
	if got := len(p.Lines()); got != 1 {
		t.Fatalf("the pull stream entered the transcript: %d lines", got)
	}
	if got := p.Pull(); got != "layer499: Downloading" {
		t.Fatalf("pull status %q", got)
	}
	if !strings.Contains(p.View(), "layer499: Downloading") {
		t.Fatalf("the live pull status is not on screen:\n%s", p.View())
	}
	// A new step supersedes the pull.
	p = progStep(p, ProgressMsg{Event: verbs.ProgressEvent{Stage: "create", Detail: "creating the container"}})
	if p.Pull() != "" {
		t.Fatalf("a finished pull is still being reported: %q", p.Pull())
	}
}

// TestProgressTranscriptIsBounded — an unbounded transcript is a memory leak whose size is chosen by
// the registry, not by this process.
func TestProgressTranscriptIsBounded(t *testing.T) {
	p := NewProgress()
	for i := 0; i < maxTranscript*3; i++ {
		p = progStep(p, OutputMsg{Line: fmt.Sprintf("line %d", i)})
	}
	if got := len(p.Lines()); got != maxTranscript {
		t.Fatalf("retained %d lines, want the cap %d", got, maxTranscript)
	}
	// The tail is what is kept — dropping the NEWEST lines would hide what just happened.
	last := p.Lines()[maxTranscript-1]
	if want := fmt.Sprintf("line %d", maxTranscript*3-1); last != want {
		t.Fatalf("last retained line %q, want %q", last, want)
	}
	if got := strings.Count(p.View(), "\n"); got > visibleTranscript+1 {
		t.Fatalf("the pane drew %d lines, more than the visible cap", got)
	}
}

// TestProgressAppendDoesNotMutateAnEarlierValue is the value-semantics guard: two updates from the
// same model value must not write into each other's transcript.
func TestProgressAppendDoesNotMutateAnEarlierValue(t *testing.T) {
	base := progStep(NewProgress(), OutputMsg{Line: "shared"})
	left := progStep(base, OutputMsg{Line: "left"})
	right := progStep(base, OutputMsg{Line: "right"})
	if got := left.Lines()[1]; got != "left" {
		t.Fatalf("the second append overwrote the first: %q", got)
	}
	if got := right.Lines()[1]; got != "right" {
		t.Fatalf("right: %q", got)
	}
	if got := len(base.Lines()); got != 1 {
		t.Fatalf("the base transcript grew: %d", got)
	}
}

// TestProgressAppendNeverWritesIntoSharedBacking is the same guard driven at the ONE shape that can
// actually alias: a transcript slice with spare capacity. Through the public API every transcript
// happens to be built at exactly len == cap, so a plain append would reallocate anyway and the
// black-box test above cannot tell the two implementations apart. Constructed directly here, it
// can: a plain append writes "right" into the array "left" is still reading.
func TestProgressAppendNeverWritesIntoSharedBacking(t *testing.T) {
	shared := make([]string, 1, 8)
	shared[0] = "shared"
	base := Progress{lines: shared}
	left := base.append("left")
	right := base.append("right")
	if got := left.Lines()[1]; got != "left" {
		t.Fatalf("the second append wrote into the first's backing array: %q", got)
	}
	if got := right.Lines()[1]; got != "right" {
		t.Fatalf("right: %q", got)
	}
	if got := len(base.Lines()); got != 1 {
		t.Fatalf("the base transcript grew: %d", got)
	}
}

// TestProgressStopsShowingALiveStepWhenDone — a spinner still turning after the verb has returned
// says the operation is still running when it is not.
func TestProgressStopsShowingALiveStepWhenDone(t *testing.T) {
	p := NewProgress()
	p = progStep(p, ProgressMsg{Event: verbs.ProgressEvent{Stage: "pull", Detail: "pulling"}})
	if !strings.Contains(p.View(), "pull") {
		t.Fatal("the live step is not shown while running")
	}
	p = progStep(p, VerbDoneMsg{Code: 0})
	if strings.Contains(p.View(), "… ") {
		t.Fatalf("a live step is still being drawn after the verb finished:\n%s", p.View())
	}
}

// TestProgressSanitizesWhatItDraws — a verb relays registry and daemon text verbatim, and that text
// is not this process's to trust with the terminal.
func TestProgressSanitizesWhatItDraws(t *testing.T) {
	p := NewProgress()
	p = progStep(p, OutputMsg{Line: "denied\x1b[2Jcleared"})
	p = progStep(p, PullProgressMsg{Status: "pulling\u202eevil"})
	v := p.View()
	if strings.ContainsRune(v, '\x1b') {
		t.Fatalf("an escape sequence reached the view:\n%q", v)
	}
	if strings.ContainsRune(v, '\u202e') {
		t.Fatalf("a bidi override reached the view:\n%q", v)
	}
}

// TestProgressSatisfiesTeaModel.
func TestProgressSatisfiesTeaModel(t *testing.T) {
	var m tea.Model = NewProgress()
	next, cmd := m.Update(OutputMsg{Line: "x"})
	if cmd != nil {
		t.Fatal("the pane issues no commands")
	}
	if got := next.(Progress).Lines(); len(got) != 1 {
		t.Fatalf("lines %q", got)
	}
	if m.Init() != nil {
		t.Fatal("the pane has nothing to start")
	}
}
