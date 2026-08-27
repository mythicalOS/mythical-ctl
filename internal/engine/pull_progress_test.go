// NO BATS INVENTORY. The pull-progress callback below has no counterpart in the frozen reference:
// lib/probe.sh states that the pull's progress output "is discarded", and no bats test in tests/
// asserts anything about it. Nothing is claimed here, and nothing already claimed by another task's
// inventory is re-asserted — TestImagePullOutcomes in client_test.go still owns the pull's
// failure-distinguishability behaviour.
package engine_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
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

// TestImagePullOneRecordCarryingBoth is the case the sentence above actually claims and the shared
// fake cannot produce: ONE record with a status AND an error. Two separate records — a status, then
// an error — pass whichever order the two checks are in, so a regression that narrated first would
// have gone unnoticed. Served here from a socket this test owns, so the shared fake is untouched.
func TestImagePullOneRecordCarryingBoth(t *testing.T) {
	stream := []map[string]string{
		{"status": "Pulling from reg.example/img", "id": "abc"},
		{"status": "Downloading", "progress": "1/2", "error": "denied: requested access is denied"},
		{"status": "Downloaded newer image"},
	}
	c := pullServer(t, stream)
	m, _ := newMutator(t, c)
	var got []string
	m.PullProgress = func(s string) { got = append(got, s) }

	err := m.ImagePull(context.Background(), "reg.example/img:v1")
	if err == nil || !strings.Contains(err.Error(), "denied: requested access is denied") {
		t.Fatalf("err %v — the registry's own words must ride the error", err)
	}
	// The status on the FAILING record is not a step: narrating it would put a reassuring line on
	// screen for the moment the pull failed. And nothing after the failure is read at all.
	if len(got) != 1 {
		t.Fatalf("narrated %q, want only the records before the failure", got)
	}
	if !strings.Contains(got[0], "abc: Pulling from reg.example/img") {
		t.Fatalf("first line %q", got[0])
	}
}

// pullServer serves one canned image-create stream over a unix socket and returns a client for it.
func pullServer(t *testing.T, records []map[string]string) *engine.Client {
	t.Helper()
	// A unix socket path has a hard length limit (sun_path, ~104 bytes on darwin), so neither
	// t.TempDir — which bakes the test's name into the path — nor a long $TMPDIR will do. The
	// directory is created under whichever base keeps the path short, and its cleanup is registered
	// BEFORE anything can fail, so a refused listen does not leak it.
	dir, sock := "", ""
	for _, base := range []string{"", "/tmp"} {
		d, err := os.MkdirTemp(base, "pullprog")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		if s := filepath.Join(d, "d.sock"); len(s) < 100 {
			dir, sock = d, s
			break
		}
	}
	if sock == "" {
		t.Skip("no temp directory short enough for a unix socket path")
	}
	_ = dir
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/images/create") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		for _, rec := range records {
			_ = enc.Encode(rec)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return engine.Dial(sock)
}
