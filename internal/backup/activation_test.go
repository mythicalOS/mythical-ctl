package backup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Inventory — NONE, and deliberately so. The PORTED:/N/A: syntax claims @tests from the frozen
// bats corpus; nothing below has a counterpart there. These guards were found by a cross-model
// review of the finished port, and the reference has the SAME defect: `mi_restore_state` asks
// `[ -f "$led" ]` and reads its false as "no active ledger", and `mi_restore_activate` finishes
// with a plain `mv`. So there is no bats test to claim, and claiming one would be a lie the
// parity audit would then happily certify. The corresponding rows of the corpus are already
// claimed by restore_test.go and guards_test.go, which port the reference's behavior; these
// assert a behavior the reference never had.

// --- the two facts these tests are about ---------------------------------------------------
//
// 1. AN ANSWER ("there is no active ledger") IS NOT A REFUSAL ("I could not determine what is
//    at that name"). `[ -f ]` folds four facts into one false: nothing is there, a DANGLING
//    symlink is there, a FIFO or a directory is there, and the path could not be examined at
//    all. Restore acts on the first by creating and filling volumes and then moving a ledger
//    onto that exact name — so the other three, read as the first, are a destination this verb
//    concludes is empty and then writes over.
//
// 2. ACTIVATION IS ATOMIC AND NO-REPLACE. A check followed by a replacing rename is a window,
//    and what is on the other side of the window is a live installation's provenance.

// mkfifo stands a named pipe — a thing that is neither absent nor a regular file, and which
// os.Stat answers about WITHOUT the ENOENT that a dangling symlink produces. It is the case
// that separates "distinguish ENOENT" from "follow symlinks less".
func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Skipf("this filesystem will not hold a named pipe at %s: %v", p, err)
	}
}

// nonRegular is the three shapes a failed restore, a hostile neighbour, or an operator's own
// hand leaves at a well-known path. None of them is an absence.
var nonRegular = []struct {
	name string
	make func(t *testing.T, p string)
}{
	{"dangling symlink", func(t *testing.T, p string) {
		t.Helper()
		if err := os.Symlink(filepath.Join(filepath.Dir(p), "nothing-is-here"), p); err != nil {
			t.Fatal(err)
		}
	}},
	{"named pipe", mkfifo},
	{"directory", func(t *testing.T, p string) {
		t.Helper()
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}},
}

// TestCurrentStateRefusesANonRegularLiveLedger: the classification itself. StateNone authorizes
// every destructive branch of the restore verb, so answering it about a path nobody could
// classify is the whole defect.
func TestCurrentStateRefusesANonRegularLiveLedger(t *testing.T) {
	for _, tc := range nonRegular {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.dropLedger()
			tc.make(t, livePath(r.home))
			r.reset()

			s, err := CurrentState(r.deps())
			if err == nil {
				t.Fatalf("a %s at the active ledger path was classified %q — an unclassifiable path was given an answer", tc.name, s)
			}
			if s == StateNone {
				t.Fatalf("a %s at the active ledger path answered %q", tc.name, s)
			}
			mustContain(t, r.stderr(), "is not a regular file", "the refusal")
			mustContain(t, r.stderr(), livePath(r.home), "the path it refused about")
		})
	}
}

// TestCurrentStateRefusesANonRegularStagingLedger: the same rule on the other half of the same
// classification. A false here means "no restore is in progress", which sends the verb down the
// fresh-start branch — and internal/prov's own first-use classifier already treats ANY presence
// at this path as an in-progress restore, so folding it into "none" here is also two modules
// giving two different answers about one path.
func TestCurrentStateRefusesANonRegularStagingLedger(t *testing.T) {
	for _, tc := range nonRegular {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.dropLedger()
			tc.make(t, stagingPath(r.home))
			r.reset()

			s, err := CurrentState(r.deps())
			if err == nil {
				t.Fatalf("a %s at the staging ledger path was classified %q", tc.name, s)
			}
			if s == StateNone {
				t.Fatalf("a %s at the staging ledger path answered %q", tc.name, s)
			}
			mustContain(t, r.stderr(), "is not a regular file", "the refusal")
			mustContain(t, r.stderr(), stagingPath(r.home), "the path it refused about")
		})
	}
}

// TestRestoreRefusesRatherThanTreatingANonRegularLiveLedgerAsAbsent states the same defect as
// the operator meets it: the verb runs, and either it refuses having touched nothing, or it
// created volumes on the strength of a machine it decided was empty.
func TestRestoreRefusesRatherThanTreatingANonRegularLiveLedgerAsAbsent(t *testing.T) {
	for _, tc := range nonRegular {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.backupOK()
			r.dropLedger()
			tc.make(t, livePath(r.home))
			r.reset()

			if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
				t.Fatalf("restore ran to completion with a %s at the active ledger path", tc.name)
			}
			if len(r.cop.fills) != 0 {
				t.Fatalf("volumes were filled: %v", r.cop.fills)
			}
			if exists(stagingPath(r.home)) {
				t.Fatal("a staging ledger was written on the strength of a classification nobody could make")
			}
			// What was there is still there, unaltered.
			if fi, err := os.Lstat(livePath(r.home)); err != nil || fi.Mode().IsRegular() {
				t.Fatalf("the %s at the active ledger path was replaced: %v", tc.name, err)
			}
		})
	}
}

// TestActivateRefusesANonRegularLiveLedger is the same fact one layer down, and it is the
// DESTRUCTIVE one: phase 6 is a rename onto the active ledger path. With a presence test that
// says "absent" and a rename that replaces, activation removes whatever is at that name and
// reports the installation live.
func TestActivateRefusesANonRegularLiveLedger(t *testing.T) {
	for _, tc := range nonRegular {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.backupOK()
			r.dropLedger()
			// A completed, intent-free staging ledger: everything phase 6 needs.
			if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
				t.Fatalf("setup restore: %v\n%s", err, r.stderr())
			}
			if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(livePath(r.home)); err != nil {
				t.Fatal(err)
			}
			tc.make(t, livePath(r.home))
			r.reset()

			if err := Activate(r.deps()); err == nil {
				t.Fatalf("activation replaced a %s at the active ledger path", tc.name)
			}
			mustContain(t, r.stderr(), "an active ledger appeared", "the refusal")
			if fi, err := os.Lstat(livePath(r.home)); err != nil || fi.Mode().IsRegular() {
				t.Fatalf("the %s was consumed by the activation: %v", tc.name, err)
			}
			if !regularFile(stagingPath(r.home)) {
				t.Fatal("the staging ledger was consumed by a refused activation")
			}
		})
	}
}

// TestActivateRenameIsNoReplace exercises the primitive itself, which is the only place the
// TOCTOU is actually closed: the check above narrows the window, the rename is what makes the
// window unable to destroy anything.
func TestActivateRenameIsNoReplace(t *testing.T) {
	for _, tc := range append(nonRegular, struct {
		name string
		make func(t *testing.T, p string)
	}{"regular file", func(t *testing.T, p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("the ledger that was already there\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}) {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			from := filepath.Join(dir, "staging")
			to := filepath.Join(dir, "live")
			if err := os.WriteFile(from, []byte("incoming\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.make(t, to)
			before, berr := os.Lstat(to)
			if berr != nil {
				t.Fatal(berr)
			}

			err := activateRename(from, to)
			if err == nil {
				t.Fatalf("activateRename replaced a %s", tc.name)
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("a destination that exists must refuse AS an exists error, so the caller can say so: %v", err)
			}
			after, aerr := os.Lstat(to)
			if aerr != nil || after.Mode() != before.Mode() {
				t.Fatalf("the %s at the destination changed: %v", tc.name, aerr)
			}
			if !regularFile(from) {
				t.Fatal("the source was consumed by a refused activation")
			}
		})
	}

	// And the success path: nothing at the destination, so the move happens and the source is
	// gone. Without this the test above is satisfied by a function that always fails.
	dir := t.TempDir()
	from := filepath.Join(dir, "staging")
	to := filepath.Join(dir, "live")
	if err := os.WriteFile(from, []byte("incoming\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := activateRename(from, to); err != nil {
		t.Fatalf("activateRename onto an unoccupied name: %v", err)
	}
	body, rerr := os.ReadFile(to)
	if rerr != nil || string(body) != "incoming\n" {
		t.Fatalf("the destination holds %q (%v)", string(body), rerr)
	}
	if exists(from) {
		t.Fatal("the source survives a completed activation")
	}
}

// TestActivateRenameFallbackIsAlsoNoReplace pins the documented fallback. renameat2 with
// RENAME_NOREPLACE (Linux) and renamex_np with RENAME_EXCL (macOS) are both refused by some
// filesystems — EINVAL/ENOSYS there, ENOTSUP here — and the fallback that catches those must
// have the SAME two properties, or the guard quietly stops holding exactly on the machines
// where the primitive was unavailable. link+unlink has them: link fails if the destination
// exists, and it is one atomic step.
func TestActivateRenameFallbackIsAlsoNoReplace(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "staging")
	to := filepath.Join(dir, "live")
	if err := os.WriteFile(from, []byte("incoming\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("already here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := linkThenUnlink(from, to)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the fallback replaced an occupied destination (or refused for another reason): %v", err)
	}
	if body, rerr := os.ReadFile(to); rerr != nil || string(body) != "already here\n" {
		t.Fatalf("the destination holds %q (%v)", string(body), rerr)
	}

	// A dangling symlink is an EXISTING directory entry, which is the case a
	// follow-the-link test would get wrong.
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nothing-is-here"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := linkThenUnlink(from, dangling); err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the fallback replaced a dangling symlink: %v", err)
	}

	// And it does complete when the destination is free.
	free := filepath.Join(dir, "free")
	if err := linkThenUnlink(from, free); err != nil {
		t.Fatalf("the fallback onto an unoccupied name: %v", err)
	}
	if body, rerr := os.ReadFile(free); rerr != nil || string(body) != "incoming\n" {
		t.Fatalf("the destination holds %q (%v)", string(body), rerr)
	}
	if exists(from) {
		t.Fatal("the source survives a completed fallback activation")
	}
}

// TestPlatformNoReplaceRenameIsAvailable is the measurement behind the fallback rather than an
// assumption about it: on the platforms this project publishes, the kernel primitive works on a
// temp directory, so the fallback is a genuine last resort and not the path everything takes.
// If this ever fails on a supported platform, the fallback is carrying the guard and that is a
// fact worth knowing rather than discovering during a restore.
func TestPlatformNoReplaceRenameIsAvailable(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "a")
	to := filepath.Join(dir, "b")
	if err := os.WriteFile(from, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := renameNoReplace(from, to)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the platform no-replace rename answered %v, want an exists refusal — %s",
			err, "the published matrix is darwin and linux, both of which have one")
	}
	if noReplaceUnsupported(err) {
		t.Fatalf("an exists refusal was also classified as 'unsupported', which would send every "+
			"occupied destination down the fallback: %v", err)
	}
	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(from, to); err != nil {
		t.Fatalf("the platform no-replace rename onto an unoccupied name: %v", err)
	}
}

// TestActivateRenameSurfacesARealFailureAsItself: a destination whose PARENT does not exist is
// neither "already there" nor "the filesystem cannot do this", and folding it into either would
// tell the operator something untrue about their machine.
func TestActivateRenameSurfacesARealFailureAsItself(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "staging")
	if err := os.WriteFile(from, []byte("incoming\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := activateRename(from, filepath.Join(dir, "no-such-dir", "live"))
	if err == nil {
		t.Fatal("a rename into a directory that does not exist reported success")
	}
	if errors.Is(err, fs.ErrExist) {
		t.Fatalf("a missing parent was reported as an occupied destination: %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the underlying reason was lost: %v", err)
	}
	if !regularFile(from) {
		t.Fatal("the source was consumed by a failed activation")
	}
}

// TestActivateReportsWhatIsAtTheOccupiedName: the refusal names the path AND what is standing
// at it. An operator meeting "an active ledger appeared" on a machine whose ledger they know
// they deleted needs to be told it is a symlink, not left to conclude the installer is wrong.
func TestActivateReportsWhatIsAtTheOccupiedName(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("setup restore: %v\n%s", err, r.stderr())
	}
	if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(livePath(r.home)); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, livePath(r.home))
	r.reset()

	if err := Activate(r.deps()); err == nil {
		t.Fatal("activation replaced a named pipe")
	}
	mustContain(t, r.stderr(), "a named pipe", "what is at the name")
	if strings.Count(r.stderr(), livePath(r.home)) == 0 {
		t.Fatalf("the refusal does not name the path:\n%s", r.stderr())
	}
}
