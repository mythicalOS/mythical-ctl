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
	// AS PHASE 3 LEFT IT: created and stamped, so the directory substituted for it below is
	// distinguishable at all. A staging directory that merely exists is not.
	stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
	id := established(t, stage)

	hcanon, _ := runtime.Canon(home)
	rdir := filepath.Join(hcanon, ".state", "reclaim")
	var landed string
	orig := renameDir
	renameDir = func(from, to string) error {
		// WHERE IT LANDS IS THE WHOLE POINT. A regression that renamed to
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
	// ESTABLISHED, not merely created: the swap below recreates the directory at the same path,
	// which on Linux hands back the SAME device and inode. Only a witness this installer stamped
	// tells the two apart.
	id := established(t, dir)
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

func TestSplitPathIsDirnameAndBasename(t *testing.T) {
	// MEASURED AGAINST `dirname`/`basename`, not against filepath.Dir/Base — the two disagree on
	// exactly the spellings this module receives from an operator. A `..` is left ALONE for the
	// physical canonicalizer to resolve; trailing separators are stripped before the split.
	for _, tc := range []struct{ in, dir, base string }{
		{"/safe/target", "/safe", "target"},
		{"/safe/target/", "/safe", "target"},
		{"/safe/target//", "/safe", "target"},
		{"/safe/", "/", "safe"},
		{"/safe", "/", "safe"},
		{"/", "/", "/"},
		{"/safe/link/../dest", "/safe/link/..", "dest"},
		{"/safe/link/..", "/safe/link", ".."},
		{"/a//b/c", "/a//b", "c"},
		{"relative/dest", "relative", "dest"},
		{"dest", ".", "dest"},
	} {
		dir, base := splitPath(tc.in)
		if dir != tc.dir || base != tc.base {
			t.Fatalf("splitPath(%q) = (%q, %q), want (%q, %q)", tc.in, dir, base, tc.dir, tc.base)
		}
	}
}

func TestCanonDestResolvesDotDotPhysically(t *testing.T) {
	// A `..` AFTER A SYMLINK RESOLVES THROUGH THE LINK'S TARGET, NOT LEXICALLY. With
	// <base>/link -> <base>/other/child, the destination <base>/link/../dest names <base>/dest if
	// the `..` is collapsed as text, and <base>/other/dest if it is resolved on disk — two
	// different directories, and only one of them is the one the operator's path actually reaches.
	// Lexical cleaning would check one and write to the other.
	base := safeBase(t)
	child := filepath.Join(base, "other", "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	// Built by concatenation, NOT filepath.Join — Join cleans, which would collapse the '..' in the
	// test's own input and leave it asserting nothing.
	got, err := canonDest(base + "/link/../dest")
	if err != nil {
		t.Fatal(err)
	}
	otherCanon, err := runtime.Canon(filepath.Join(base, "other"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(otherCanon, "dest")
	if got != want {
		t.Fatalf("canonDest resolved the '..' to %q, want the physical %q", got, want)
	}
	baseCanon, _ := runtime.Canon(base)
	if got == filepath.Join(baseCanon, "dest") {
		t.Fatal("the '..' was collapsed lexically, naming a directory the operator's path does not reach")
	}

	// A `..` AS THE LEAF ITSELF is carried through literally, the way the reference's printf does,
	// rather than folded into the parent by a cleaning join. The two name the same directory —
	// the parent is already physical — but they are different STRINGS, and this one is recorded in
	// the ledger and written into mythical.conf.
	leaf, lerr := canonDest(base + "/other/child/..")
	if lerr != nil {
		t.Fatal(lerr)
	}
	childCanon, _ := runtime.Canon(child)
	if want := childCanon + "/.."; leaf != want {
		t.Fatalf("canonDest of a '..' leaf = %q, want the literal %q", leaf, want)
	}
}

func TestStagingPathKeepsTheParentLiteral(t *testing.T) {
	// THE SIBLING MUST STAY IN THE PARENT THE TRUST WALK VERIFIED. A cleaning join collapses a `..`
	// in the parent, and with a symlink above it that names a DIFFERENT directory — one the walk
	// never checked, and possibly on another filesystem, which is where the atomic commit stops
	// being atomic. The reference derives it with a plain printf and no cleaning at all.
	for _, tc := range []struct{ dest, want string }{
		{"/safe/link/../dest", "/safe/link/../.mythical-staging-nz"},
		{"/safe/dest", "/safe/.mythical-staging-nz"},
		{"/safe/dest/", "/safe/.mythical-staging-nz"},
		{"/dest", "/.mythical-staging-nz"},
	} {
		if got := StagingPath(tc.dest, "nz"); got != tc.want {
			t.Fatalf("StagingPath(%q) = %q, want %q", tc.dest, got, tc.want)
		}
	}
}

// --- the identity witness ------------------------------------------------------------------------
//
// THESE HAVE NO BATS ROW OF THEIR OWN, like the three guards above: the reference's identity was
// `device:inode` and its own test suite asserted exactly that. The bats row that covers the
// property — "the recorded device+inode identifies the destination after the rename" — is claimed
// by TestIdentitySurvivesRename, which is extended below to assert the witness rides the rename
// too. Everything here exists because the two-field identity was DEFEATED on Linux, where a
// directory deleted and recreated at the same path gets the same inode number back.

func TestASwappedDirectoryIsCaughtEvenWhenTheInodeIsREUSED(t *testing.T) {
	// THE DEFECT, DIRECTLY. On ext4 and on overlayfs `rm -rf dir && mkdir dir` hands the new
	// directory the OLD one's inode number — measured 200 times out of 200 on each — so the
	// `device:inode` identity reported "unchanged" for a completely different directory. tmpfs and
	// APFS happen not to reuse it, which is why this passed on macOS and failed in CI.
	//
	// The loop runs the swap many times because a SINGLE trial proves nothing on a filesystem whose
	// allocator merely usually reuses: one non-reused inode would make a broken identity look
	// correct. Every iteration must be caught.
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	for i := 0; i < 64; i++ {
		before := established(t, dir)
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		after, err := Identity(dir)
		if err != nil {
			t.Fatalf("reading the replacement's identity: %v", err)
		}
		if after == before {
			t.Fatalf("iteration %d: a directory deleted and recreated at %q reported the SAME identity %q — "+
				"the substitution this check exists to catch is invisible", i, dir, after)
		}
		if err := verifyIdentity(dir, before, "the directory"); err == nil {
			t.Fatalf("iteration %d: verifyIdentity accepted the replacement", i)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheWitnessRidesTheRenameAndTheOriginalKeepsIt(t *testing.T) {
	// rename(2) CARRYING THE WITNESS IS THE WHOLE REASON THIS IDENTITY CAN EXIST. Phase 3 stamps
	// the staging directory; phase 5 renames it onto the destination; phase 7 verifies the
	// destination against the value recorded before the rename. If the attribute did not survive
	// the rename, every migration would refuse itself at phase 5.
	base := safeBase(t)
	stage := filepath.Join(base, "stage")
	id := established(t, stage)
	dest := filepath.Join(base, "dest")
	if err := os.Rename(stage, dest); err != nil {
		t.Fatal(err)
	}
	got, err := Identity(dest)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("after the rename the destination reports %q, not the recorded %q", got, id)
	}
	if err := verifyIdentity(dest, id, "the destination"); err != nil {
		t.Fatalf("the renamed directory was refused: %v", err)
	}
}

func TestTheWitnessIsNotADirectoryEntry(t *testing.T) {
	// THE COPIER REFUSES A NON-EMPTY STAGING DESTINATION, checked inside the container atomically
	// with the copy. That is why the witness is an attribute on the inode and not a marker FILE:
	// a marker would abort every migration at the copy. If a change ever moved the witness into an
	// entry, this reddens before the copier does.
	base := safeBase(t)
	dir := filepath.Join(base, "stage")
	established(t, dir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("stamping the identity left %d directory entr(ies) %v — the copy step refuses a "+
			"staging destination that is not empty", len(ents), ents)
	}
}

func TestAnUnstampedDirectoryReportsAnAnswerNotARefusal(t *testing.T) {
	// AN ABSENT WITNESS IS AN ANSWER. Identity is asked about directories this installer never
	// created — the destination, a leftover at the staging name, and its own reclaim directory,
	// which is created for itself and deliberately never stamped. Refusing to read any of those
	// would break the reclaim's cross-device check and both resume paths.
	base := safeBase(t)
	dir := filepath.Join(base, "plain")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := Identity(dir)
	if err != nil {
		t.Fatalf("an unstamped directory was refused rather than answered: %v", err)
	}
	if !strings.HasSuffix(id, ":"+noWitness) {
		t.Fatalf("an unstamped directory reported %q, which does not carry the no-witness answer", id)
	}
	// AND IT IS STILL A DEVICE:INODE ANSWER the rest of the package can use.
	if !sameDeviceID(id, id) {
		t.Fatalf("the device half of %q is unreadable", id)
	}
	// TWO unstamped directories are still told apart by the two older fields.
	other := filepath.Join(base, "plain2")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	oid, err := Identity(other)
	if err != nil {
		t.Fatal(err)
	}
	if oid == id {
		t.Fatalf("two different unstamped directories share the identity %q", id)
	}
}

func TestAWitnessThisInstallerNeverWroteIsRefused(t *testing.T) {
	// UNTRUSTED BYTES ON AN UNTRUSTED DIRECTORY. The destination's parent is writable by parties
	// this migration does not control, so the value at the witness attribute is input, not
	// evidence. Anything outside the shape this installer writes is a REFUSAL — not silently
	// accepted as an identity, and not rendered back into a terminal.
	base := safeBase(t)
	for name, val := range map[string][]byte{
		"empty":            {},
		"a separator":      []byte("abc:def"),
		"a control byte":   {'a', 0x07, 'b'},
		"a newline":        []byte("abc\ndef"),
		"longer than ours": []byte(strings.Repeat("a", witnessMax+1)),
	} {
		dir := filepath.Join(base, "planted")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := lsetWitness(dir, val); err != nil {
			t.Fatalf("%s: planting the value: %v", name, err)
		}
		_, err := Identity(dir)
		if err == nil {
			t.Fatalf("%s: a witness this installer never writes was accepted as an identity", name)
		}
		if strings.Contains(err.Error(), string(val)) && len(val) > 0 {
			t.Fatalf("%s: the refusal renders the planted bytes back verbatim: %v", name, err)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEstablishRefusesWhenTheWitnessCannotBeMinted(t *testing.T) {
	// NO WITNESS, NO IDENTITY. A mint that cannot produce a value must not fall back to the
	// two-field identity that this whole change exists to retire — that would be the defect back,
	// silently, on exactly the hosts whose entropy source is unavailable.
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := newWitness
	newWitness = func() (string, error) { return "", errors.New("no entropy") }
	t.Cleanup(func() { newWitness = orig })
	_, err := EstablishIdentity(dir)
	mustContain(t, err, "could not mint an identity witness", "no entropy")
	// AND NOTHING WAS STAMPED: a failed mint leaves the directory exactly as it was.
	id, ierr := Identity(dir)
	if ierr != nil {
		t.Fatal(ierr)
	}
	if !strings.HasSuffix(id, ":"+noWitness) {
		t.Fatalf("a refused mint stamped the directory anyway: %q", id)
	}
}

func TestEstablishRefusesAFilesystemThatCannotCarryTheWitness(t *testing.T) {
	// REFUSED AT THE CHEAPEST POINT THERE IS. A filesystem with no extended attributes cannot
	// carry the evidence phase 5 and phase 7 depend on, so the migration stops at phase 3 with an
	// empty staging directory — nothing copied, nothing removed, no container replaced. Falling
	// back to `device:inode` instead would leave the irreversible steps guarded by a check this
	// tree has measured to be defeated.
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := setWitnessAttr
	setWitnessAttr = func(string, []byte) error { return errors.New("operation not supported") }
	t.Cleanup(func() { setWitnessAttr = orig })
	_, err := EstablishIdentity(dir)
	mustContain(t, err, "cannot carry the identity witness", "before anything is",
		"operation not supported")
}

func TestEstablishRefusesAStampThatDidNotStick(t *testing.T) {
	// A WRITE THAT RETURNS SUCCESS IS NOT EVIDENCE THE VALUE IS THERE. A filesystem that accepts
	// the attribute and drops it would hand back an identity that can never verify again — and the
	// migration would then refuse at phase 5 or 7, after the volume had been copied. The same
	// check covers a directory replaced between the stamp and the read-back, whose identity would
	// otherwise be recorded in the ledger as this migration's own.
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := setWitnessAttr
	t.Cleanup(func() { setWitnessAttr = orig })

	setWitnessAttr = func(string, []byte) error { return nil } // accepted, stored nowhere
	_, err := EstablishIdentity(dir)
	mustContain(t, err, "does not carry the identity witness this process just wrote to it",
		"Refusing to record an identity")

	// And a stamp that lands as a DIFFERENT well-formed value is refused the same way — the
	// refusal is keyed on the value matching, never on the write merely having happened.
	setWitnessAttr = func(p string, _ []byte) error { return orig(p, []byte("somebodyelses")) }
	_, err = EstablishIdentity(dir)
	mustContain(t, err, "does not carry the identity witness this process just wrote to it")
}

func TestWitnessShape(t *testing.T) {
	// The mint's own output must satisfy the shape the reader enforces, or every real migration
	// would refuse itself at phase 3 — a false RED on the ordinary path, which is as much a defect
	// as a false green on the hostile one.
	tok, err := newWitness()
	if err != nil {
		t.Fatal(err)
	}
	if !witnessOK(tok) {
		t.Fatalf("the minted witness %q is not a shape the reader accepts", tok)
	}
	for _, bad := range []string{"", noWitness, "a:b", "a b", "a\nb", "a-b", "a.b",
		strings.Repeat("a", witnessMax+1)} {
		if witnessOK(bad) {
			t.Fatalf("witnessOK accepted %q", bad)
		}
	}
	if !witnessOK(strings.Repeat("a", witnessMax)) {
		t.Fatalf("witnessOK rejected a value of exactly the maximum length")
	}
	// THE NO-WITNESS PLACEHOLDER CAN NEVER COLLIDE WITH A REAL ONE, or "this directory carries
	// nothing" and "this directory carries the recorded value" would compare equal.
	if witnessOK(noWitness) {
		t.Fatal("the no-witness placeholder is itself an acceptable witness")
	}
}

func TestEstablishRefusesAPathThatIsNotThere(t *testing.T) {
	// The stamp is the first thing that touches the path, so a missing directory surfaces as the
	// filesystem's own refusal rather than as an identity for something that does not exist.
	base := safeBase(t)
	if _, err := EstablishIdentity(filepath.Join(base, "absent")); err == nil {
		t.Fatal("an identity was established for a path that does not exist")
	}
}

func TestAnUnreadableWitnessIsARefusalNotAnAbsence(t *testing.T) {
	// THE DISTINCTION THIS PACKAGE IS BUILT ON, at the witness. "There is no witness here" and
	// "the witness could not be read" must not be the same answer: folding the second into the
	// first would let an unreadable directory compare equal to any other unreadable one, which is
	// the fail-open the whole identity exists to prevent.
	//
	// Driven without a seam and without root: reading a `user.` extended attribute is an ordinary
	// read-permission check on the inode, while Lstat needs only search permission on the PARENT.
	// So a directory whose read bit is off answers EACCES to the witness read and answers Lstat
	// normally — measured on ext4, overlayfs and APFS.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission check this drives; CI and every developer run this as a " +
			"non-root uid, where it is exercised")
	}
	base := safeBase(t)
	dir := filepath.Join(base, "d")
	id := established(t, dir)
	if err := os.Chmod(dir, 0o300); err != nil { // write + search, deliberately NOT read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	// The precondition: Lstat still answers, so the refusal below can only come from the witness.
	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("the precondition does not hold — Lstat itself failed (%v), so this proves nothing "+
			"about the witness", err)
	}
	got, err := Identity(dir)
	if err == nil {
		t.Fatalf("an unreadable witness answered %q instead of refusing", got)
	}
	mustContain(t, err, "could not be read", "Refusing")
	// AND THE REFUSAL PROPAGATES: nothing downstream may read it as agreement.
	mustContain(t, verifyIdentity(dir, id, "the directory"), "<unreadable>")
}

func TestASymlinkDoesNotBorrowItsTargetsWitness(t *testing.T) {
	// THE NO-FOLLOW READ, asserted on its own. A path swapped for a symlink into a stamped
	// directory must read as carrying NO witness — if the read followed the link it would answer
	// with the original's own evidence, which is the substitution reporting itself as unchanged.
	base := safeBase(t)
	real := filepath.Join(base, "real")
	tok := established(t, real)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	w, err := readWitness(link)
	if err != nil {
		t.Fatalf("reading the link's witness: %v", err)
	}
	if w != noWitness {
		t.Fatalf("a symlink reported the witness %q; the read followed the link to its target", w)
	}
	// And the whole identity differs, so verifyIdentity refuses the substitution.
	if err := verifyIdentity(link, tok, "the directory"); err == nil {
		t.Fatal("a symlink to the stamped directory passed as the directory itself")
	}
}
