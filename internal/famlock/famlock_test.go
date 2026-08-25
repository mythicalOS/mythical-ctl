package famlock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Inventory — tests/unit/lock.bats. The ln/recovery-gate MECHANISM is replaced by flock(2)
// (plan Task 7); tests of the mechanism are N/A, tests of the CONTRACT port:
// PORTED: tests/unit/lock.bats: "acquire then release round-trips and sets the token" -> TestAcquireReleaseRoundTrip
// PORTED: tests/unit/lock.bats: "acquire creates its own .state directory on a fresh machine (never mis-reports a missing dir as contention)" -> TestAcquireCreatesStateDir
// PORTED: tests/unit/lock.bats: "a live holder blocks a second acquire and names the holder" -> TestLiveHolderBlocksAndIsNamed
// PORTED: tests/unit/lock.bats: "a dead holder's lock is broken and acquired" -> TestDeadHolderReleasesAutomatically (the kernel drops a dead holder's flock; no break protocol remains)
// N/A: tests/unit/lock.bats: "an unreadable-PID lock is treated as in-progress, not broken" -- the pid body is diagnostic only; liveness is the kernel's, no record read decides anything
// N/A: tests/unit/lock.bats: "a malformed lock record fails closed — unreadable, not parsed or broken" -- same: no record parsing grants or breaks anything
// N/A: tests/unit/lock.bats: "a multi-record lock file fails closed — refused, never broken (one record is LIVE)" -- same: the flock, not the file body, is the lock
// N/A: tests/unit/lock.bats: "a recovery gate left by a crash is NOT stolen — refuse and name it for manual clear" -- the recovery gate does not exist under flock; there is nothing to steal or clear
// N/A: tests/unit/lock.bats: "a LIVE recovery gate blocks the break — another operation is already recovering" -- same: no gate, no break
// PORTED: tests/unit/lock.bats: "release will NOT delete a lock it does not own" -> TestReleaseCannotAffectAnotherHolder
// PORTED: tests/unit/lock.bats: "release is a safe no-op when not held" -> TestReleaseNoOpWhenNotHeld

func TestAcquireReleaseRoundTrip(t *testing.T) {
	home := t.TempDir()
	h, err := Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := Assert(h, "test a write"); err != nil {
		t.Fatalf("live token failed assert: %v", err)
	}
	got, err := HomeOf(h)
	if err != nil || got != home {
		t.Fatalf("HomeOf = %q, %v", got, err)
	}
	if err := Release(h); err != nil {
		t.Fatal(err)
	}
	if err := Assert(h, "write after release"); err == nil {
		t.Fatal("released token still asserts")
	}
	if _, err := HomeOf(h); err == nil {
		t.Fatal("released token still resolves a home")
	}
	h2, err := Acquire(home)
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	_ = Release(h2)
}

func TestAcquireCreatesStateDir(t *testing.T) {
	home := filepath.Join(t.TempDir(), "fresh") // .state does not exist yet
	h, err := Acquire(home)
	if err != nil {
		t.Fatalf("fresh-machine acquire mis-reported: %v", err)
	}
	defer Release(h)
	if st, err := os.Stat(filepath.Join(home, ".state")); err != nil || !st.IsDir() {
		t.Fatal(".state not created")
	}
}

func TestLiveHolderBlocksAndIsNamed(t *testing.T) {
	home := t.TempDir()
	h, err := Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(h)
	_, err = Acquire(home) // a second open file description conflicts, same process or not
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("second acquire: %v", err)
	}
	if !strings.Contains(err.Error(), "pid ") {
		t.Fatalf("holder not named: %v", err)
	}
}

// The cross-process halves: a child that HOLDS blocks us; a child that DIES releases by
// kernel action, with no stale-break protocol. The child is this test binary re-exec'd.
func TestDeadHolderReleasesAutomatically(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run", "TestHelperHoldLock", "-test.v")
	cmd.Env = append(os.Environ(), "FAMLOCK_HELPER_HOME="+home)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait for the child to report it holds the lock.
	buf := make([]byte, 4096)
	deadline := time.Now().Add(10 * time.Second)
	held := false
	for !held && time.Now().Before(deadline) {
		n, _ := out.Read(buf)
		if strings.Contains(string(buf[:n]), "HELPER-HOLDS") {
			held = true
		}
	}
	if !held {
		_ = cmd.Process.Kill()
		t.Fatal("helper never reported holding the lock")
	}
	if _, err := Acquire(home); !errors.Is(err, ErrBusy) {
		_ = cmd.Process.Kill()
		t.Fatalf("live cross-process holder did not block: %v", err)
	}
	// Kill the holder mid-hold — the crash case. The kernel drops its flock with the fd.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	h, err := Acquire(home)
	if err != nil {
		t.Fatalf("dead holder's lock not released by the kernel: %v", err)
	}
	_ = Release(h)
}

// TestHelperHoldLock is the re-exec child: it acquires and holds until killed. Not a test of
// anything when run in the normal suite (no env marker => skip).
func TestHelperHoldLock(t *testing.T) {
	home := os.Getenv("FAMLOCK_HELPER_HOME")
	if home == "" {
		t.Skip("helper mode only")
	}
	h, err := Acquire(home)
	if err != nil {
		t.Fatalf("helper acquire: %v", err)
	}
	os.Stdout.WriteString("HELPER-HOLDS\n")
	_ = os.Stdout.Sync()
	time.Sleep(30 * time.Second) // killed long before this expires
	_ = Release(h)
}

func TestReleaseCannotAffectAnotherHolder(t *testing.T) {
	home := t.TempDir()
	a, err := Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(a)
	// A stranger's failed acquire yields no token; releasing what it got (nil) touches
	// nothing, and A still excludes the next comer.
	b, berr := Acquire(home)
	if !errors.Is(berr, ErrBusy) || b != nil {
		t.Fatalf("expected busy, got %v, %v", b, berr)
	}
	_ = Release(b)
	if _, err := Acquire(home); !errors.Is(err, ErrBusy) {
		t.Fatal("A's lock was destroyed by a non-owner's release")
	}
	if err := Assert(a, "write"); err != nil {
		t.Fatal("A's token damaged")
	}
}

func TestReleaseNoOpWhenNotHeld(t *testing.T) {
	if err := Release(nil); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	h, _ := Acquire(home)
	_ = Release(h)
	if err := Release(h); err != nil { // double release
		t.Fatal(err)
	}
}

// The sealed-type regression the plan requires: EVERY wrapper is refused — only the exact
// value Acquire returned is a token. (Round-2 wave gate: delegation through an embedding
// wrapper was arguably harmless, but a rule with no judgment calls beats one with a safe
// exception, and the exact-type check cannot panic on a nil-inner wrapper.)
type wrapper struct{ Held }

func TestEmbeddingWrapperCannotForgeAuthority(t *testing.T) {
	if err := Assert(wrapper{}, "write"); err == nil {
		t.Fatal("empty wrapper asserted")
	}
	if _, err := HomeOf(wrapper{}); err == nil {
		t.Fatal("empty wrapper resolved a home")
	}
	home := t.TempDir()
	h, err := Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(h)
	if err := Assert(wrapper{h}, "write"); err == nil {
		t.Fatal("a wrapper around a real token asserted — only Acquire's exact value is a token")
	}
	if _, err := HomeOf(wrapper{h}); err == nil {
		t.Fatal("a wrapper around a real token resolved a home")
	}
	// The real token is unharmed by the refusals.
	if err := Assert(h, "write"); err != nil {
		t.Fatal(err)
	}
}

// The malformed-record contract, ported to the flock world: the lock FILE's content grants
// nothing and breaks nothing — garbage scribbled into it leaves the holder's authority intact
// (the flock is the authority) and still refuses every other comer.
func TestLockFileContentGrantsNothing(t *testing.T) {
	home := t.TempDir()
	h, err := Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(h)
	lf := filepath.Join(home, ".state", "lock")
	if err := os.WriteFile(lf, []byte("pid=999999 pid=1\ngarbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Assert(h, "write"); err != nil {
		t.Fatal("garbage in the lock file broke the holder's authority")
	}
	if _, err := Acquire(home); !errors.Is(err, ErrBusy) {
		t.Fatalf("garbage in the lock file granted a second acquire: %v", err)
	}
}

func TestSymlinkAndHardlinkTargetsRefused(t *testing.T) {
	home := t.TempDir()
	ld := filepath.Join(home, ".state")
	if err := os.MkdirAll(ld, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink planted at the lock path must be refused (O_NOFOLLOW), its target untouched.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(ld, "lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(home); err == nil {
		t.Fatal("symlinked lock target accepted")
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("symlink target touched: %q", b)
	}
	// And a hardlinked regular file (nlink 2) is refused too.
	home2 := t.TempDir()
	ld2 := filepath.Join(home2, ".state")
	if err := os.MkdirAll(ld2, 0o755); err != nil {
		t.Fatal(err)
	}
	victim2 := filepath.Join(t.TempDir(), "victim2")
	if err := os.WriteFile(victim2, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim2, filepath.Join(ld2, "lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(home2); err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("hardlinked lock target accepted: %v", err)
	}
}

// Two goroutines with separate Acquire calls on one home: exactly one wins; after Release the
// loser can acquire — the in-process concurrency shape the plan names.
func TestConcurrentAcquireExactlyOneWins(t *testing.T) {
	home := t.TempDir()
	type res struct {
		h   Held
		err error
	}
	ch := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			h, err := Acquire(home)
			ch <- res{h, err}
		}()
	}
	a, b := <-ch, <-ch
	wins, losses := 0, 0
	var winner Held
	for _, r := range []res{a, b} {
		if r.err == nil {
			wins++
			winner = r.h
		} else if errors.Is(r.err, ErrBusy) {
			losses++
		} else {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d", wins, losses)
	}
	_ = Release(winner)
	h, err := Acquire(home)
	if err != nil {
		t.Fatalf("loser cannot acquire after release: %v", err)
	}
	_ = Release(h)
}
