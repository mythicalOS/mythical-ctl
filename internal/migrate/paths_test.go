package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/runtime"
)

// Inventory — tests/unit/migrate.bats (the path, identity and secure-location half; the machine
// half is in migrate_test.go, and the two files together claim every test in that bats file
// exactly once).
//
// PORTED: tests/unit/migrate.bats: "staging is a SIBLING of the destination, never a child" -> TestStagingPathIsASibling
// PORTED: tests/unit/migrate.bats: "mount-point detection uses MOUNT-TABLE evidence, not an st_dev comparison" -> TestMountPointUsesTheMountTable
// PORTED: tests/unit/migrate.bats: "the recorded device+inode identifies the destination after the rename" -> TestIdentitySurvivesRename
// PORTED: tests/unit/migrate.bats: "phase 5 recovery: identity at the DESTINATION advances to phase 6" -> TestResolvePhase5
// PORTED: tests/unit/migrate.bats: "phase 5 recovery: identity at STAGING retries the rename" -> TestResolvePhase5
// PORTED: tests/unit/migrate.bats: "phase 5 recovery: identity NOWHERE stops and reports — never retries, never deletes" -> TestResolvePhase5
// PORTED: tests/unit/migrate.bats: "leftover staging is deleted ONLY on a nonce AND device/inode match" -> TestReclaimRemovesOnlyOnAFullMatch
// PORTED: tests/unit/migrate.bats: "reclaim moves into the INSTALLER'S OWN directory, never a sibling of the untrusted destination" -> TestReclaimUsesTheInstallersOwnDirectory
// PORTED: tests/unit/migrate.bats: "a leftover staging MISMATCH is preserved and reported — the name alone is not authority" -> TestReclaimPreservesOnMismatch
// PORTED: tests/unit/migrate.bats: "an UNPROVABLE leftover is stepped around with a FRESH nonce, never a deadlock" -> TestAFreshNonceStepsAroundALeftover
// PORTED: tests/unit/migrate.bats: "mi_mig_check_parent_trust accepts an operator-owned, non-group/other-writable parent" -> TestParentTrustAcceptsASafeChain
// PORTED: tests/unit/migrate.bats: "mi_mig_check_parent_trust REFUSES when an ancestor ABOVE the immediate parent is unsafe" -> TestParentTrustWalksTheWholeChain
// PORTED: tests/unit/migrate.bats: "_mi_mig_secure_state_dir returns the CANONICAL leaf, never a raw path through a symlinked alias" -> TestSecureStateDirReturnsTheCanonicalLeaf
// PORTED: tests/unit/migrate.bats: "mi_mig_verify_no_escaping_symlinks refuses a tree containing an escaping (absolute-target) symlink" -> TestVerifyNoEscapingSymlinks
// PORTED: tests/unit/migrate.bats: "mi_mig_verify_no_escaping_symlinks refuses a tree containing a '..'-climbing escaping symlink" -> TestVerifyNoEscapingSymlinks
// PORTED: tests/unit/migrate.bats: "mi_mig_verify_no_escaping_symlinks accepts a tree containing only an intra-tree symlink" -> TestVerifyNoEscapingSymlinks
// PORTED: tests/unit/migrate.bats: "mi_mig_verify_no_escaping_symlinks FAILS CLOSED when the walk cannot fully complete" -> TestVerifyNoEscapingSymlinksFailsClosedOnAPartialWalk
// PORTED: tests/unit/migrate.bats: "_mi_mig_secure_state_dir creates and verifies an owner-only directory under mi_home" -> TestSecureStateDirCreatesAnOwnerOnlyDirectory
// PORTED: tests/unit/migrate.bats: "the escaping-symlink re-walk still refuses even when TMPDIR points elsewhere" -> TestVerifyNoEscapingSymlinksIsIndependentOfTmpdir
// N/A: tests/unit/migrate.bats: "the escaping-symlink re-walk's scratch file lives under mi_home's own state tree, never TMPDIR" -- THERE IS NO SCRATCH FILE. The reference had to spool `find -print0` output through a temp file (a NUL-delimited list cannot survive a shell variable), and placing that file somewhere no other party could swap it is the ONLY reason the re-walk reached for the installer's secure directory. This walk holds its result in process memory, so the file both attacks targeted (redirect-onto-a-planted-symlink; swap-the-contents-before-the-read) does not exist. The secure directory itself is retained where it IS load-bearing — StagingReclaim's private rename target — and every one of its own tests ports.
// N/A: tests/unit/migrate.bats: "the re-walk FAILS CLOSED if the installer's own secure directory cannot be trusted (a symlink)" -- same: the re-walk never consults the secure directory, because it creates nothing. The equivalent refusal on the path that DOES consult it is TestReclaimFailsClosedOnAnUnsafeHome, and the symlinked-leaf refusal itself is TestSecureStateDirRefusesASymlinkedLeaf.
// N/A: tests/unit/migrate.bats: "the escaping-symlink re-walk fails closed when MYTHICAL_HOME sits under an unsafe ancestor" -- same: no scratch file, so the home's chain is not on the re-walk's path at all. The chain walk is asserted at its real callers: TestSecureStateDirWalksTheWholeChain and TestReclaimFailsClosedOnAnUnsafeHome.
// PORTED: tests/unit/migrate.bats: "_mi_mig_secure_state_dir REFUSES when MYTHICAL_HOME sits under a group/other-writable ancestor" -> TestSecureStateDirWalksTheWholeChain
// PORTED: tests/unit/migrate.bats: "_mi_mig_secure_state_dir REFUSES an unsafe home WITHOUT ever creating anything under it" -> TestSecureStateDirCreatesNothingUnderAnUnsafeHome
// PORTED: tests/unit/migrate.bats: "reclaim fails closed (removes nothing) when MYTHICAL_HOME sits under an unsafe ancestor" -> TestReclaimFailsClosedOnAnUnsafeHome
// PORTED: tests/unit/migrate.bats: "_mi_mig_secure_state_dir SUCCEEDS on a normal, fully operator-owned chain" -> TestSecureStateDirSucceedsOnASafeChain

func TestStagingPathIsASibling(t *testing.T) {
	dest := "/a/b/dest"
	got := StagingPath(dest, "nonceX")
	if want := "/a/b/.mythical-staging-nonceX"; got != want {
		t.Fatalf("StagingPath = %q, want %q", got, want)
	}
	// NEVER A CHILD: renaming a directory onto its own parent is refused by the kernel, so a
	// staging path inside the destination could never be committed atomically at all.
	if strings.HasPrefix(got, dest+"/") {
		t.Fatalf("staging %q is inside the destination %q", got, dest)
	}
}

func TestAFreshNonceStepsAroundALeftover(t *testing.T) {
	base := safeBase(t)
	dest := filepath.Join(base, "dest")
	// A leftover bearing the staging NAME, from an attempt nothing can attribute.
	leftover := filepath.Join(base, ".mythical-staging-old")
	if err := os.Mkdir(leftover, 0o755); err != nil {
		t.Fatal(err)
	}
	a, b := StagingPath(dest, "n1"), StagingPath(dest, "n2")
	if a == b {
		t.Fatal("two nonces derived the same staging path — a retry would collide with itself")
	}
	if a == leftover || b == leftover {
		t.Fatal("a fresh nonce derived the leftover's own path — that is the deadlock, not a step around it")
	}
	if !exists(leftover) {
		t.Fatal("deriving a fresh path removed the leftover; it must be preserved")
	}
}

func TestIdentitySurvivesRename(t *testing.T) {
	base := safeBase(t)
	dest := filepath.Join(base, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := Identity(dest)
	if err != nil {
		t.Fatal(err)
	}
	moved := dest + ".moved"
	if err := os.Rename(dest, moved); err != nil {
		t.Fatal(err)
	}
	got, err := Identity(moved)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("identity changed across the rename: %q -> %q", id, got)
	}
}

func TestResolvePhase5(t *testing.T) {
	base := safeBase(t)
	dest := filepath.Join(base, "dest")
	stage := StagingPath(dest, "nz")

	// identity at the DESTINATION → the rename completed.
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	did, _ := Identity(dest)
	where, err := ResolvePhase5(dest, stage, did)
	if err != nil || where != AtDestination {
		t.Fatalf("destination case: %v %v", where, err)
	}

	// identity at STAGING → retry the rename.
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(stage)
	where, err = ResolvePhase5(dest, stage, sid)
	if err != nil || where != AtStaging {
		t.Fatalf("staging case: %v %v", where, err)
	}

	// NOWHERE → stop and report. NEVER retry, NEVER delete: the refusal must not even offer
	// those as what it did.
	where, err = ResolvePhase5(dest, stage, "999999:999999")
	if where != "" {
		t.Fatalf("an unattributable identity resolved to %q", where)
	}
	mustContain(t, err, "stops")
	mustNotContain(t, err, "retry", "delete")
	if !exists(dest) || !exists(stage) {
		t.Fatal("the unattributable case removed something")
	}
}

func TestParentTrustAcceptsASafeChain(t *testing.T) {
	base := safeBase(t)
	if err := CheckParentTrust(filepath.Join(base, "dest")); err != nil {
		t.Fatalf("an operator-owned, non-group/other-writable chain was refused: %v", err)
	}
	// A TRAILING SLASH NAMES THE SAME DESTINATION. This is a public entry point, and the Go path
	// split reads `<base>/dest/` as parent `<base>/dest` where `dirname` reads it as `<base>` — so
	// without cleaning first, a perfectly ordinary spelling of a not-yet-created destination is
	// refused because its own leaf cannot be resolved as a parent.
	for _, spelling := range []string{filepath.Join(base, "dest") + "/", filepath.Join(base, "dest") + "//"} {
		if err := CheckParentTrust(spelling); err != nil {
			t.Fatalf("CheckParentTrust(%q) refused a chain it accepts without the trailing slash: %v", spelling, err)
		}
	}
}

func TestParentTrustWalksTheWholeChain(t *testing.T) {
	// The IMMEDIATE parent is owner-only; only the directory ABOVE it is group/other-writable.
	// A check of the one directory the destination's dirname resolves to would pass here.
	base := unsafeBase(t, 0o777)
	parent := filepath.Join(base, "sub")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	err := CheckParentTrust(filepath.Join(parent, "dest"))
	mustContain(t, err, "writable by its group or by everyone")
}

// --- the escaping-symlink re-check --------------------------------------------------------------

func TestVerifyNoEscapingSymlinks(t *testing.T) {
	esc := &fakeCopy{}
	t.Run("absolute target escapes", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink("/etc/passwd", filepath.Join(root, "evil")); err != nil {
			t.Fatal(err)
		}
		mustContain(t, VerifyNoEscapingSymlinks(esc, root), "escapes it")
	})
	t.Run("dot-dot climbing escapes", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../outside", filepath.Join(root, "sub", "evil")); err != nil {
			t.Fatal(err)
		}
		mustContain(t, VerifyNoEscapingSymlinks(esc, root), "escapes it")
	})
	t.Run("an intra-tree symlink is accepted", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "sub", "f"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("sub/f", filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if err := VerifyNoEscapingSymlinks(esc, root); err != nil {
			t.Fatalf("an ordinary intra-tree symlink was refused: %v", err)
		}
	})
}

func TestVerifyNoEscapingSymlinksFailsClosedOnAPartialWalk(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	err := VerifyNoEscapingSymlinks(&fakeCopy{}, root)
	// A CLEAN RESULT OVER AN INCOMPLETE SCAN IS INDISTINGUISHABLE FROM "nothing found" — which is
	// exactly why "could not fully scan" must be its own, named refusal.
	mustContain(t, err, "did not complete cleanly")
	if !errors.Is(err, ErrIncompleteWalk) {
		t.Fatalf("a partial walk is not reported as one: %v", err)
	}
}

func TestVerifyNoEscapingSymlinksIsIndependentOfTmpdir(t *testing.T) {
	// The reference's re-walk could be steered by TMPDIR, because it put a scratch file there;
	// pointing TMPDIR at a sentinel must change neither the verdict nor what lands in it.
	sentinel := t.TempDir()
	t.Setenv("TMPDIR", sentinel)
	root := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	mustContain(t, VerifyNoEscapingSymlinks(&fakeCopy{}, root), "escapes it")
	ents, err := os.ReadDir(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("the re-walk left %d entries in TMPDIR", len(ents))
	}
}

// --- the installer's own secure scratch location -------------------------------------------------

func TestSecureStateDirCreatesAnOwnerOnlyDirectory(t *testing.T) {
	home := filepath.Join(safeBase(t), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := secureStateDir(home, "probe")
	if err != nil {
		t.Fatal(err)
	}
	hcanon, _ := runtime.Canon(home)
	if want := filepath.Join(hcanon, ".state", "probe"); got != want {
		t.Fatalf("secureStateDir = %q, want %q", got, want)
	}
	st, err := os.Lstat(got)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o, want 700", st.Mode().Perm())
	}
}

func TestSecureStateDirReturnsTheCanonicalLeaf(t *testing.T) {
	// The home is reached through a symlink whose OWN containing directory is group/other-writable,
	// but whose TARGET is a safe, operator-owned tree. ACCEPTING THIS IS CORRECT — the resolved
	// target is genuinely safe, and once the canonical value is the only thing used afterwards,
	// repointing the alias has no effect on anything already committed to the resolved path. What
	// must be proven is that the RETURNED value is that canonical target, not the raw alias: a
	// caller writing inside the raw name would still resolve through a link a group member can
	// repoint the instant after this returns.
	real := filepath.Join(safeBase(t), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := unsafeBase(t, 0o777)
	alias := filepath.Join(aliasParent, "home")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	got, err := secureStateDir(alias, "probe")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(got, aliasParent+string(filepath.Separator)) {
		t.Fatalf("returned the raw alias path %q", got)
	}
	rcanon, _ := runtime.Canon(real)
	if want := filepath.Join(rcanon, ".state", "probe"); got != want {
		t.Fatalf("secureStateDir = %q, want the canonical %q", got, want)
	}
}

func TestSecureStateDirRefusesASymlinkedLeaf(t *testing.T) {
	home := filepath.Join(safeBase(t), "home")
	if err := os.MkdirAll(filepath.Join(home, ".state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(home, ".state", "probe")); err != nil {
		t.Fatal(err)
	}
	mustContain(t, secureStateDirErr(home, "probe"), "is a symlink, not a real directory")
}

func secureStateDirErr(home, name string) error {
	_, err := secureStateDir(home, name)
	return err
}

func TestSecureStateDirWalksTheWholeChain(t *testing.T) {
	// The leaf's own immediate parent IS owner-only; only the ANCESTOR above it is unsafe.
	base := unsafeBase(t, 0o777)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	mustContain(t, secureStateDirErr(home, "probe"), "writable by its group or by everyone")
}

func TestSecureStateDirCreatesNothingUnderAnUnsafeHome(t *testing.T) {
	// When the home ITSELF is unsafe, refusing must leave NOTHING created under it — proving the
	// create never ran before the safety check, not merely that the overall call failed. The
	// reference's earlier revision built the leaf from the RAW home and created it BEFORE
	// canonicalizing, so a root-run migration could be steered into creating and locking down an
	// attacker-chosen path; the refusal that followed was correct and far too late.
	home := unsafeBase(t, 0o777)
	mustContain(t, secureStateDirErr(home, "probe"), "writable by its group or by everyone")
	if exists(filepath.Join(home, ".state")) {
		t.Fatal("something was created under the unsafe home before it was refused")
	}
}

func TestSecureStateDirSucceedsOnASafeChain(t *testing.T) {
	// Constructed explicitly rather than relying on the ambient host's tmp permissions: a
	// chmod-700 base this process owns outright, with a fixed mode for every intermediate
	// directory, so the positive case is provably about the LOGIC.
	owned := filepath.Join(safeBase(t), "owned")
	home := filepath.Join(owned, "deep", "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{owned, filepath.Join(owned, "deep"), home} {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := secureStateDir(home, "probe")
	if err != nil {
		t.Fatal(err)
	}
	hcanon, _ := runtime.Canon(home)
	if want := filepath.Join(hcanon, ".state", "probe"); got != want {
		t.Fatalf("secureStateDir = %q, want %q", got, want)
	}
}

// --- reclaim --------------------------------------------------------------------------------------

func TestReclaimRemovesOnlyOnAFullMatch(t *testing.T) {
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(stage)
	if err := StagingReclaim(home, stage, "nonceX", id, "nonceX"); err != nil {
		t.Fatal(err)
	}
	if exists(stage) {
		t.Fatal("a full nonce+identity match did not reclaim the leftover")
	}
}

func TestReclaimUsesTheInstallersOwnDirectory(t *testing.T) {
	// A prior revision renamed the leftover to a DIFFERENT NAME still inside the same (untrusted)
	// parent before deleting it. That does not close the check-then-rm race — it only moves it.
	// Proven two ways: nothing is left beside the destination, and the installer's own reclaim
	// directory is EMPTY afterwards (fully removed, not merely relocated and left behind).
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(base, "dest")
	stage := StagingPath(dest, "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(stage)

	hcanon0, _ := runtime.Canon(home)
	wantParent := filepath.Join(hcanon0, ".state", "reclaim")
	var landedIn string
	origRename := renameDir
	renameDir = func(from, to string) error { landedIn = filepath.Dir(to); return origRename(from, to) }
	t.Cleanup(func() { renameDir = origRename })

	if err := StagingReclaim(home, stage, "nonceX", id, "nonceX"); err != nil {
		t.Fatal(err)
	}
	if exists(stage) {
		t.Fatal("the leftover survived a full match")
	}
	// THE RENAME ITSELF LANDED IN THE INSTALLER'S OWN DIRECTORY. Asserting only that no sibling
	// survives cannot tell that apart from a sibling rename followed by a delete — which leaves the
	// same evidence and closes nothing.
	if landedIn != wantParent {
		t.Fatalf("the reclaim renamed into %q, not the installer's own %q", landedIn, wantParent)
	}
	siblings, err := os.ReadDir(filepath.Dir(dest))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range siblings {
		if strings.HasPrefix(e.Name(), ".mythical-reclaim-") || strings.HasPrefix(e.Name(), ".mythical-staging-") {
			t.Fatalf("the reclaim left %q beside the untrusted destination", e.Name())
		}
	}
	hcanon, _ := runtime.Canon(home)
	rdir := filepath.Join(hcanon, ".state", "reclaim")
	st, err := os.Lstat(rdir)
	if err != nil {
		t.Fatalf("the installer's own reclaim directory was not created: %v", err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("reclaim directory mode %o, want 700", st.Mode().Perm())
	}
	ents, err := os.ReadDir(rdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("the reclaim directory still holds %d entries — relocated, not removed", len(ents))
	}
}

func TestReclaimPreservesOnMismatch(t *testing.T) {
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	// A NAME IS NOT AUTHORITY: the identity does not match, so nothing is removed.
	err := StagingReclaim(home, stage, "nonceX", "999:999", "nonceX")
	mustContain(t, err, "preserved")
	if !exists(stage) {
		t.Fatal("a mismatched leftover was removed")
	}

	// The NONCE half of the same rule, on its own.
	id, _ := Identity(stage)
	err = StagingReclaim(home, stage, "recorded", id, "onthepath")
	mustContain(t, err, "preserved")
	if !exists(stage) {
		t.Fatal("a nonce mismatch removed the leftover")
	}
}

func TestReclaimFailsClosedOnAnUnsafeHome(t *testing.T) {
	unsafeHomeBase := unsafeBase(t, 0o777)
	home := filepath.Join(unsafeHomeBase, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	base := safeBase(t)
	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(stage)
	err := StagingReclaim(home, stage, "nonceX", id, "nonceX")
	mustContain(t, err, "writable by its group or by everyone")
	if !exists(stage) {
		t.Fatal("the reclaim removed the leftover despite refusing")
	}
}

// --- mount-point detection -----------------------------------------------------------------------

func TestMountPointUsesTheMountTable(t *testing.T) {
	base := safeBase(t)
	dir := filepath.Join(base, "mnt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// THE CASE AN st_dev COMPARISON CANNOT SEE: a bind mount of the same filesystem carries its
	// parent's device number. `dir` here shares its parent's device — as a real same-filesystem
	// bind mount would — and is still detected, because the answer comes from the table.
	if d, _ := deviceOf(dir); true {
		pd, _ := deviceOf(filepath.Dir(dir))
		if d != pd {
			t.Skip("the test base is itself a mount boundary; the same-device case cannot be built here")
		}
	}
	isMP, err := IsMountPoint(&fakeMounts{points: []string{dir}}, dir)
	if err != nil || !isMP {
		t.Fatalf("a same-device mount point was not detected: %v %v", isMP, err)
	}

	// And the same directory, absent from the table, is NOT a mount point.
	isMP, err = IsMountPoint(&fakeMounts{}, dir)
	if err != nil || isMP {
		t.Fatalf("an ordinary directory read as a mount point: %v %v", isMP, err)
	}
}

func TestMountTableUnreadableIsItsOwnAnswer(t *testing.T) {
	base := safeBase(t)
	dir := filepath.Join(base, "mnt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	isMP, err := IsMountPoint(&fakeMounts{err: errors.New("no table")}, dir)
	if err == nil {
		t.Fatal("an unreadable mount table was folded into 'not a mount point'")
	}
	if isMP {
		t.Fatal("an unreadable table reported a positive")
	}
	mustContain(t, err, "could not determine")

	// A destination that does not exist yet is NOT a mount point even when the table cannot be
	// read — nothing there cannot be mounted, and refusing every ordinary migration on a host
	// whose table cannot be read is not what the reference does.
	if isMP, err := IsMountPoint(&fakeMounts{err: errors.New("no table")}, filepath.Join(base, "nope")); err != nil || isMP {
		t.Fatalf("an absent destination: %v %v", isMP, err)
	}
}

func TestSystemMountsAnswers(t *testing.T) {
	// The REAL reader, against the real host: it must produce a non-empty list containing "/", or
	// an error. An empty list with no error is the one outcome that would silently make every
	// mount-point check answer "no".
	points, err := SystemMounts{}.MountPoints()
	if err != nil {
		t.Skipf("this host exposes no readable mount table: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("the mount table read as EMPTY with no error — every mount-point check would answer 'no'")
	}
	found := false
	for _, p := range points {
		if p == "/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the mount table does not contain the root mount: %v", points)
	}
}

// --- guards whose failure state the filesystem will not produce on demand ------------------------
//
// These have no bats row of their own: the reference could not construct them either. They exist so
// that reverting the guard in isolation reddens something — a guard nothing can redden is a guard
// whose deletion no review would catch.

func TestDirOwnerSafeRefusesAForeignOwner(t *testing.T) {
	// A directory owned by a THIRD, non-root uid cannot be created without root, so the process's
	// own uid is moved instead: every directory this test owns is then "someone else's".
	// OWNERSHIP, NOT MODE BITS, is what excludes a third party — a privileged process bypasses mode
	// enforcement entirely, so a 0700 directory another uid owns is still theirs to rename.
	dir := safeBase(t)
	if safety, _ := dirOwnerSafe(dir); safety != dirSafe {
		t.Fatalf("the test base is not owner-safe to begin with: %v", safety)
	}
	orig := geteuid
	geteuid = func() int { return orig() + 4242 }
	t.Cleanup(func() { geteuid = orig })
	safety, detail := dirOwnerSafe(dir)
	if safety != dirForeignOwner {
		t.Fatalf("a foreign-owned directory reported %v, want dirForeignOwner", safety)
	}
	if detail == "" {
		t.Fatal("the refusal does not name the owning uid")
	}
	err := CheckParentTrust(filepath.Join(dir, "dest"))
	mustContain(t, err, "is owned by uid", "Refusing")
}

func TestDirOwnerSafeAcceptsRootOwned(t *testing.T) {
	// ROOT IS TRUSTED BY DEFINITION here: refusing every root-owned ancestor would refuse every
	// real install, because `/` and most of the path above any home are root-owned.
	if safety, detail := dirOwnerSafe("/"); safety != dirSafe {
		t.Fatalf("the root directory was refused (%v %q) — no chain walk could ever pass", safety, detail)
	}
}

func TestDirOwnerSafeRefusesWhatItCannotRead(t *testing.T) {
	// A FAILED READ IS A REFUSAL, never assumed safe.
	if safety, _ := dirOwnerSafe(filepath.Join(safeBase(t), "does-not-exist")); safety != dirUnreadable {
		t.Fatalf("an unreadable path reported %v, want dirUnreadable", safety)
	}
	mustContain(t, verifyChainOwnerSafe("/nonexistent-x/nonexistent-y", "a test path"),
		"could not verify the ownership or permissions")
}

func TestSameDeviceIDRefusesWhatItCannotCompare(t *testing.T) {
	// SAME FILESYSTEM IS REQUIRED for the reclaim's move to be the atomic rename its safety depends
	// on. A cross-device pair cannot be conjured on an arbitrary host, so the comparison itself is
	// asserted directly — an unreadable identity on either side is NOT a match.
	if !sameDeviceID("16777232:99", "16777232:100") {
		t.Fatal("two identities on the same device did not compare equal")
	}
	for _, tc := range [][2]string{
		{"16777232:99", "16777233:99"}, // different devices
		{"", "16777232:99"},            // unreadable staging identity
		{"16777232:99", ""},            // unreadable reclaim identity
		{"nodevice", "16777232:99"},    // malformed
	} {
		if sameDeviceID(tc[0], tc[1]) {
			t.Fatalf("%q and %q compared as the same device", tc[0], tc[1])
		}
	}
}

func TestReclaimVerifiesTheRenamedDirectory(t *testing.T) {
	// AFTER THE RENAME, THE RESULT IS VERIFIED TOO. A rename cannot be made to land on something
	// other than what it just moved, so the rename itself is interposed: something replaces the
	// renamed directory in the instant between the check and the move. It must be PRESERVED where
	// it now is, never deleted and never renamed back onto a name that may already be reassigned.
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(stage)

	hcanon, _ := runtime.Canon(home)
	rdir := filepath.Join(hcanon, ".state", "reclaim")
	var landed string
	orig := renameDir
	renameDir = func(from, to string) error {
		// WHERE IT LANDS IS THE WHOLE POINT (round 1, finding 6). A regression that renamed to
		// another name in the SAME untrusted parent and then deleted it would leave no sibling
		// behind and an empty reclaim directory — indistinguishable, from the outside, from doing
		// it correctly. It does not close the check-then-rm race; it only moves it.
		if got := filepath.Dir(to); got != rdir {
			t.Fatalf("the reclaim renamed into %q, not the installer's own %q", got, rdir)
		}
		if err := orig(from, to); err != nil {
			return err
		}
		// The swap: the renamed directory is replaced by a DIFFERENT one at the same name.
		if err := os.RemoveAll(to); err != nil {
			return err
		}
		if err := os.Mkdir(to, 0o755); err != nil {
			return err
		}
		landed = to
		return nil
	}
	t.Cleanup(func() { renameDir = orig })

	err := StagingReclaim(home, stage, "nonceX", id, "nonceX")
	mustContain(t, err, "no longer carries the identity just verified", "preserved at")
	if landed == "" || !exists(landed) {
		t.Fatalf("the substituted directory at %q was removed; a refusal preserves", landed)
	}
}

func TestVerifyIdentityRefusesASwappedPath(t *testing.T) {
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(dir)
	if err := verifyIdentity(dir, id, "the directory"); err != nil {
		t.Fatalf("an unchanged path was refused: %v", err)
	}
	// Replaced by a different directory at the same NAME — a name is not an identity.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustContain(t, verifyIdentity(dir, id, "the directory"), "no longer carries the identity")
	// And GONE is refused the same way, never read as "nothing to disagree with".
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	mustContain(t, verifyIdentity(dir, id, "the directory"), "<unreadable>")
}

func TestSecureStateDirResolvesASymlinkedStateDirectory(t *testing.T) {
	// The home itself is canonical, but `.state` is a symlink into another owner-safe tree. The
	// CHAIN WALK approves the resolved target — correctly — and the RETURNED value must be that
	// target, not the raw path through the link. Handing back the raw path would let the caller
	// create its private reclaim directory inside a name whose target someone could repoint after
	// this function approved the (different) canonical one: the check-canonical/use-raw gap, one
	// level down.
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	realState := filepath.Join(base, "realstate")
	if err := os.Mkdir(realState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realState, filepath.Join(home, ".state")); err != nil {
		t.Fatal(err)
	}
	got, err := secureStateDir(home, "probe")
	if err != nil {
		t.Fatal(err)
	}
	rcanon, _ := runtime.Canon(realState)
	if want := filepath.Join(rcanon, "probe"); got != want {
		t.Fatalf("secureStateDir = %q, want the canonical %q (not the path through the .state symlink)", got, want)
	}
}

func TestReclaimRefusesAColludingPrivatePath(t *testing.T) {
	// REFUSING RATHER THAN RISK NESTING. If the private reclaim path already exists, the move would
	// put the staging directory INSIDE it rather than claiming it exclusively — and the removal that
	// follows would then take whatever else was in there with it. A freshly minted nonce does not
	// collide on its own, so the mint is interposed.
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	orig := newReclaimNonce
	newReclaimNonce = func() (string, error) { return "fixedtag", nil }
	t.Cleanup(func() { newReclaimNonce = orig })

	hcanon, _ := runtime.Canon(home)
	occupied := filepath.Join(hcanon, ".state", "reclaim", "fixedtag")
	if err := os.MkdirAll(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "someone-elses"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	id, _ := Identity(stage)
	err := StagingReclaim(home, stage, "nonceX", id, "nonceX")
	mustContain(t, err, "already exists", "Refusing")
	if !exists(stage) {
		t.Fatal("the staging directory was removed despite the refusal")
	}
	if !exists(filepath.Join(occupied, "someone-elses")) {
		t.Fatal("the occupied private path's contents were disturbed")
	}
}
