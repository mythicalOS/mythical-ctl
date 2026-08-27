// NO BATS INVENTORY. The pull-progress callback below has no counterpart in the frozen reference:
// lib/probe.sh states that the pull's progress output "is discarded", and no bats test in tests/
// asserts anything about it. Nothing is claimed here, and nothing already claimed by another task's
// inventory is re-asserted — TestImagePullOutcomes in client_test.go still owns the pull's
// failure-distinguishability behaviour.
package engine_test

import (
	"context"
	"strings"
	"testing"
)

// TestImagePullReportsProgressWhenAskedTo — the callback is the only way a front-end can show
// anything at all during the one step of an install that takes minutes.
func TestImagePullReportsProgressWhenAskedTo(t *testing.T) {
	f, c := newFake(t)
	m, _ := newMutator(t, c)
	var got []string
	m.PullProgress = func(status string) { got = append(got, status) }
	if err := m.ImagePull(context.Background(), "reg.example/probe:v1"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("progress lines: %q", got)
	}
	if !strings.Contains(got[0], "Pulling from reg.example/probe") {
		t.Fatalf("first line %q", got[0])
	}
	if !strings.Contains(got[1], "Downloaded newer image") {
		t.Fatalf("second line %q", got[1])
	}
	_ = f
}

// TestImagePullWithoutACallbackIsUnchanged — the field is additive and nil by default, so every
// existing caller and every non-interactive invocation behaves exactly as before.
func TestImagePullWithoutACallbackIsUnchanged(t *testing.T) {
	_, c := newFake(t)
	m, _ := newMutator(t, c)
	if m.PullProgress != nil {
		t.Fatal("a freshly constructed Mutator must have no progress callback")
	}
	if err := m.ImagePull(context.Background(), "reg.example/probe:v1"); err != nil {
		t.Fatal(err)
	}
}

// TestImagePullReportsTheFailureRatherThanTheProgress. A record can carry both; narrating the
// failure as if it were a step would put a reassuring line on screen for an operation that just
// failed, and the error must still be the one the caller sees.
func TestImagePullReportsTheFailureRatherThanTheProgress(t *testing.T) {
	f, c := newFake(t)
	m, _ := newMutator(t, c)
	var got []string
	m.PullProgress = func(status string) { got = append(got, status) }
	// A failure ARRIVING MID-STREAM after a 200: one status record, then the registry's refusal.
	f.PullOutcome = "streamerr"
	err := m.ImagePull(context.Background(), "img:v9")
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("err %v — the registry's own words must still ride the error", err)
	}
	if len(got) != 1 {
		t.Fatalf("progress lines %q — only the records before the failure are steps", got)
	}
	// A pull that never got a 200 narrates nothing at all.
	got = nil
	f.PullOutcome = "notfound"
	if err := m.ImagePull(context.Background(), "img:v9"); err == nil {
		t.Fatal("a 404 pull reported success")
	}
	if len(got) != 0 {
		t.Fatalf("a refused pull narrated %q", got)
	}
}
