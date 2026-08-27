package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
)

// Inventory — tests/unit/migrate.bats (the machine half; the path/identity/secure-location half is
// in paths_test.go).
//
// PORTED: tests/unit/migrate.bats: "migrate-storage with NO ROLE is rejected — a product may have several volume roles" -> cmd/mythical-ctl TestMigrateStorageDispatchRefusals ("needs exactly <product> <role>", exit 2, nothing attempted — the surface where a missing operand is expressible at all; the library signature takes product and role as separate typed parameters, so this package cannot be handed the shape)
// PORTED: tests/unit/migrate.bats: "an UNKNOWN role is rejected against the manifest, which names the valid roles" -> TestPrecheckRoleGates
// PORTED: tests/unit/migrate.bats: "a SECRETS role is REFUSED WITH THE REASON — permitted but not bindable (D53)" -> TestPrecheckRoleGates
// PORTED: tests/unit/migrate.bats: "a policy index collapsing permitted and bindable is rejected as MALFORMED (Plan 3's invariant)" -> internal/policy TestStructuralInvariants (the invariant is enforced at policy LOAD; this package can only ever hold a policy that already passed it, because policy.ParseVerified is boundary-gated to the trust acceptors)
// PORTED: tests/unit/migrate.bats: "the role must be VOLUME-BACKED, proved by POSITIVE INSPECTION of the container's mounts" -> TestPrecheckRequiresPositiveVolumeBacking
// PORTED: tests/unit/migrate.bats: "an ALREADY-BIND-BACKED role with NO live intent is refused, naming the current bind" -> TestPrecheckRefusesAnAlreadyBindBackedRole
// PORTED: tests/unit/migrate.bats: "a live intent is checked FIRST, so a present bind after a crash RESUMES rather than refusing" -> TestPrecheckResumesAMatchingLiveIntent
// PORTED: tests/unit/migrate.bats: "the live-intent early return ALSO enforces the parent-trust gate — it does not bypass it" -> TestLiveIntentEarlyReturnStillChecksParentTrust
// PORTED: tests/unit/migrate.bats: "the migrate-storage VERB's own resume-existing-intent path also enforces parent-trust" -> TestVerbResumePathEnforcesParentTrust
// PORTED: tests/unit/migrate.bats: "a live intent naming a DIFFERENT destination stops and reports BOTH paths" -> TestPrecheckRefusesADifferentInFlightDestination
// PORTED: tests/unit/migrate.bats: "a NON-EMPTY destination is refused by default, not merged" -> TestPrecheckRefusesANonEmptyDestination
// PORTED: tests/unit/migrate.bats: "a destination that is itself a MOUNT POINT is refused, naming the remedy" -> TestPrecheckRefusesAMountPoint
// PORTED: tests/unit/migrate.bats: "the migration's OWN staging does not count as a non-empty destination" -> TestOwnStagingDoesNotCountAsANonEmptyDestination
// PORTED: tests/unit/migrate.bats: "precheck REFUSES a destination whose parent directory is writable by GROUP" -> TestPrecheckRefusesAnUnsafeParent
// PORTED: tests/unit/migrate.bats: "precheck REFUSES a destination whose parent directory is writable by EVERYONE" -> TestPrecheckRefusesAnUnsafeParent
// PORTED: tests/unit/migrate.bats: "an UNSAFE parent is refused BEFORE anything else — no role/policy/volume checks run first" -> TestUnsafeParentIsRefusedBeforeAnythingElse
// PORTED: tests/unit/migrate.bats: "the full migrate-storage verb refuses through an unsafe parent, before any confirmation prompt" -> TestVerbRefusesAnUnsafeParentBeforeConfirming
// PORTED: tests/unit/migrate.bats: "mi_mig_resume ALSO refuses through an unsafe parent — it is an independent entry point" -> TestResumeRefusesAnUnsafeParent
// PORTED: tests/unit/migrate.bats: "migrate-storage is REFUSED, naming the offending ancestor, when one exists above the parent" -> TestVerbNamesTheOffendingAncestor
// PORTED: tests/unit/migrate.bats: "migrate-storage reached via a symlink into a safe tree operates on and records the CANONICAL dest" -> TestVerbRecordsTheCanonicalDestination
// PORTED: tests/unit/migrate.bats: "mi_mig_run invoked DIRECTLY refuses through an unsafe ancestor, even bypassing the verb/precheck" -> TestRunRefusesAnUnsafeAncestorDirectly
// PORTED: tests/unit/migrate.bats: "phase 3 derives the staging mkdir path from the canonical dest, ignoring a bogus carried staging field" -> TestPhase3DerivesStagingFromTheCanonicalDest
// PORTED: tests/unit/migrate.bats: "phase 5 refuses to commit a staging tree that gained an ESCAPING symlink after phase 4" -> TestPhase5RefusesAPlantedEscapingSymlink
// The compare-and-set is internal/conf's FamilyCAS, the one door authorized to CHANGE a mythical.conf
// value, and its whole attempt table is asserted there. What THIS module owns — which attempt state
// it presents to that door — is TestPhase6PresentsTheRecordedAttemptState.
// PORTED: tests/unit/migrate.bats: "compare-and-set: not started, key absent → write" -> internal/conf TestFamilyCASAttemptTable
// PORTED: tests/unit/migrate.bats: "compare-and-set: attempt in progress, key holds OUR value → advance without rewriting" -> internal/conf TestFamilyCASAttemptTable (asserted on the file's mtime — nothing was rewritten) + TestFamilyCASNarratesWhatItDid (it says so rather than looking like a write that did not happen)
// PORTED: tests/unit/migrate.bats: "compare-and-set: attempt in progress, key ABSENT → STOP and require confirmation" -> internal/conf TestFamilyCASAttemptTable (refuse without confirmation; write only WITH it)
// PORTED: tests/unit/migrate.bats: "compare-and-set: attempt in progress, key holds SOMETHING ELSE → STOP" -> internal/conf TestFamilyCASAttemptTable + TestOperatorEditIsNeverSilentlyOverwritten (the migration-level consequence: an operator's edit survives a crashed migration)
// PORTED: tests/unit/migrate.bats: "the bind reaches mythical.conf BEFORE the container is replaced" -> TestBindIsWrittenBeforeTheContainerIsReplaced
// (migrate.bats' "after the migration, a RECREATE keeps the product on the bind" row was N/A here —
// "re-claim against recreate once that verb lands". Wave 5 landed it, so the row is claimed in
// cmd/mythical-ctl/migrate_e2e_test.go by TestRecreateAfterAMigrationKeepsTheBind, where the real
// verb runs rather than a stand-in. The migration-side precondition it rests on stays
// TestBindIsWrittenBeforeTheContainerIsReplaced here.)
// PORTED: tests/unit/migrate.bats: "phase 7 REPLACES the container and tombstones the old one — mounts are immutable" -> TestPhase7ReplacesAndTombstonesInOrder
// PORTED: tests/unit/migrate.bats: "phase 8 verifies the mount BY INSPECTION and claims nothing about the container-side read" -> TestPhase8VerifiesByInspectionAndClaimsNothingMore
// PORTED: tests/unit/migrate.bats: "a migration of a desired-STOPPED product leaves it stopped and still verifies phase 8" -> TestDesiredStoppedSurvivesTheMigration
// PORTED: tests/unit/migrate.bats: "generic reconciliation is SUSPENDED for the container while the intent is live" -> TestSuspendsReconciliation
// PORTED: tests/unit/migrate.bats: "phase 9 restores the recorded desired state and only THEN may delete the source volume" -> TestPhase9RestoresDesiredStateAndRetainsTheSource
// PORTED: tests/unit/migrate.bats: "each of the nine phases resumes from the recorded phase" -> TestEveryPhaseResumesFromItsRecordedPhase
//
// Inventory — tests/acceptance/migrate.bats. These are the hostile-input and interrupted-run cases.
// The copy helper's own refusals belong to the copy module; what is asserted here is the MIGRATION's
// half of each: a refusal that still let bytes reach the destination is not a refusal.
//
// PORTED: tests/acceptance/migrate.bats: "a volume with an ESCAPING symlink fails the migration and leaves no destination behind" -> TestACopyRefusalLeavesNoDestinationAndNoBind
// PORTED: tests/acceptance/migrate.bats: "a volume with a device/socket/FIFO entry fails the migration and leaves no destination behind" -> TestACopyRefusalLeavesNoDestinationAndNoBind
// PORTED: tests/acceptance/migrate.bats: "a volume with an unrefused device entry is still caught by the closed entry-type check" -> TestACopyRefusalLeavesNoDestinationAndNoBind
// PORTED: tests/acceptance/migrate.bats: "a volume with a setuid file migrates, with the privileged bit stripped and reported" -> TestASetuidVolumeStillMigratesAndTheReportReachesTheOperator
// PORTED: tests/acceptance/migrate.bats: "a volume with a FOREIGN uid is refused by default" -> TestForeignUIDRefusedByDefaultMappedWhenAsked
// PORTED: tests/acceptance/migrate.bats: "a volume with a FOREIGN uid migrates when --map-foreign-to-operator is given" -> TestForeignUIDRefusedByDefaultMappedWhenAsked
// PORTED: tests/acceptance/migrate.bats: "a volume with an ORDINARY (non-escaping) symlink migrates — it must not be refused" -> TestAnOrdinarySymlinkMigrates
// PORTED: tests/acceptance/migrate.bats: "a destination PRE-SEEDED with an escaping symlink is refused as non-empty, never followed" -> TestAPreSeededDestinationIsRefusedAndNeverFollowed
// PORTED: tests/acceptance/migrate.bats: "a destination that is itself a MOUNT POINT is refused end to end, naming the remedy" -> TestVerbRefusesAMountPointEndToEnd
// PORTED: tests/acceptance/migrate.bats: "interrupted stopping the container (phase 2) converges cleanly on resume" -> TestInterruptedAtPhase2ConvergesOnResume
// PORTED: tests/acceptance/migrate.bats: "interrupted replacing the container (phase 7) converges cleanly on resume, and the bind survives" -> TestInterruptedAtPhase7ConvergesOnResume
// PORTED: tests/acceptance/migrate.bats: "a leftover staging directory from an interrupted attempt is stepped around, never adopted" -> TestALeftoverStagingIsSteppedAroundNeverAdopted
// PORTED: tests/acceptance/migrate.bats: "an OPERATOR EDIT of mythical.conf during a crashed migration is never silently overwritten" -> TestOperatorEditIsNeverSilentlyOverwritten
// PORTED: tests/acceptance/migrate.bats: "a resume with NO confirmation input is refused, not carried out silently" -> TestResumeWithoutConfirmationDoesNothing
// (The three CLI arity/option rows of tests/acceptance/migrate.bats are claimed by the file that
//  carries the dispatcher under test: cmd/mythical-ctl/migrate_test.go.)
// (acceptance/migrate.bats' "CLI: an unrelated verb rejects --to-bind" row was N/A here while
// install was unwired — "re-claim against install once that verb lands". It landed in Wave 5, so the
// row is claimed in cmd/mythical-ctl/lifecycle_test.go by TestCLIInstallRejectsToBind. The half this
// package owns — migrate-storage refuses every option it does not own — is still
// cmd/mythical-ctl TestMigrateStorageDispatchRefusals.)
// (acceptance/migrate.bats' "CLI: migrate-storage end to end" row was N/A here — "re-claim once the
// copy and rebuild seams are wired into the dispatcher". They are wired, and the row is claimed in
// cmd/mythical-ctl/migrate_e2e_test.go by TestMigrateStorageMovesARoleEndToEnd, which runs the verb
// through the real entrypoint against the fake daemon and the copy-helper stand-in. The in-process
// nine-phase run stays TestMigrationCompletesEndToEnd here.)

func ctx() context.Context { return context.Background() }

// --- precheck --------------------------------------------------------------------------------------

func TestPrecheckRoleGates(t *testing.T) {
	f := newFx(t)
	// An UNKNOWN role is rejected against the manifest, WHICH NAMES THE VALID ROLES — the operator
	// cannot choose a role they were never shown.
	err := Precheck(ctx(), f.l, f.d, testProduct, "nosuch", f.dest)
	mustContain(t, err, "no volume role", testRole, "secrets")

	// A SECRETS role is permitted (the product mounts it) and NOT bindable, and the refusal must say
	// SO — reporting it as an unknown role would send the operator looking for a typo.
	err = Precheck(ctx(), f.l, f.d, testProduct, "secrets", f.dest)
	mustContain(t, err, "not bindable")
	mustNotContain(t, err, "no volume role")
}

func TestPrecheckRequiresPositiveVolumeBacking(t *testing.T) {
	f := newFx(t)
	if err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest); err != nil {
		t.Fatalf("a volume-backed role was refused: %v", err)
	}
	// POSITIVE INSPECTION, not an absent config key: with the container no longer mounting the
	// source volume there is no evidence to migrate on, and the refusal says which volume it
	// looked for.
	delete(f.objs.mounts, f.container)
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	mustContain(t, err, "does not mount", f.srcvol)
}

func TestPrecheckRefusesAnAlreadyBindBackedRole(t *testing.T) {
	f := newFx(t)
	if err := conf.FamilyAdd(f.lock, f.confkey, "/already/there"); err != nil {
		t.Fatal(err)
	}
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	// It names the CURRENT bind, and says why re-running is destructive: the source volume is
	// stale, and copying it over the live bind loses everything written since.
	mustContain(t, err, "/already/there", "stale")
}

func TestPrecheckResumesAMatchingLiveIntent(t *testing.T) {
	f := newFx(t)
	// A crash after phase 6 leaves BOTH a live intent and a present bind. Checking the intent
	// FIRST is what lets this resume; a rule that refused on a present bind "before anything
	// else" would strand the migration permanently at the phase that had just succeeded.
	canon := f.canonDest()
	f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "started", Desired: "running"})
	if err := conf.FamilyAdd(f.lock, f.confkey, canon); err != nil {
		t.Fatal(err)
	}
	if err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest); err != nil {
		t.Fatalf("a live intent for exactly this destination did not resume: %v", err)
	}
}

func TestLiveIntentEarlyReturnStillChecksParentTrust(t *testing.T) {
	// The same fixture as the passing resume above, with an unsafe parent. A migration interrupted
	// while its destination's parent was safe, whose parent became world-writable since, must NOT
	// resume through the early return with the gate skipped.
	f := newFx(t)
	canon := f.canonDest()
	f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "started", Desired: "running"})
	if err := os.Chmod(f.base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	mustContain(t, err, "writable by its group or by everyone")
}

func TestVerbResumePathEnforcesParentTrust(t *testing.T) {
	// The same regression through the real verb entrypoint, not the precheck directly — the exact
	// path the finding names as reachable with the gate skipped: re-invoking the verb on an
	// already-recorded, matching-destination migration. And the refusal must be the parent one,
	// not a confirmation that was never reached.
	f := newFx(t)
	f.confirmed = false
	canon := f.canonDest()
	f.seed(record{Phase: 2, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "none", Desired: "running"})
	if err := os.Chmod(f.base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "writable by its group or by everyone")
	mustNotContain(t, err, "not confirmed")
	if len(f.prompts) != 0 {
		t.Fatalf("the operator was prompted before the gate refused: %v", f.prompts)
	}
}

func TestPrecheckRefusesADifferentInFlightDestination(t *testing.T) {
	f := newFx(t)
	other := filepath.Join(f.base, "other")
	f.seed(record{Phase: 3, Dest: other, Nonce: "nz", Staging: StagingPath(other, "nz"),
		Attempt: "none", Desired: "running"})
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	// BOTH paths, so the operator can see what they asked for and what is actually in flight.
	mustContain(t, err, other, f.canonDest())
}

func TestPrecheckRefusesANonEmptyDestination(t *testing.T) {
	f := newFx(t)
	if err := os.Mkdir(f.dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dest, "pre-existing"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	mustContain(t, err, "not empty")
	// NOT MERGED: the refusal must not offer combining the two trees as an alternative.
	mustNotContain(t, err, "merge")

	// A DANGLING SYMLINK is not an empty destination either: a plain existence test would call it
	// absent, and the copy would then be committed on top of it.
	if err := os.Remove(filepath.Join(f.dest, "pre-existing")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.base, "nowhere"), filepath.Join(f.dest, "dangling")); err != nil {
		t.Fatal(err)
	}
	mustContain(t, Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest), "not empty")
}

func TestOwnStagingDoesNotCountAsANonEmptyDestination(t *testing.T) {
	f := newFx(t)
	if err := os.Mkdir(StagingPath(f.dest, "nonceX"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest); err != nil {
		t.Fatalf("the migration's own staging blocked its own destination: %v", err)
	}
}

func TestPrecheckRefusesAMountPoint(t *testing.T) {
	f := newFx(t)
	f.mt.points = []string{f.dest}
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	// NAMING THE REMEDY: migrate into a subdirectory of the mount instead.
	mustContain(t, err, "subdirectory")
}

func TestPrecheckRefusesAnUnsafeParent(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o777} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			f := newFx(t)
			if err := os.Chmod(f.base, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
			err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
			mustContain(t, err, "writable by its group or by everyone")
		})
	}
}

func TestUnsafeParentIsRefusedBeforeAnythingElse(t *testing.T) {
	// Refusing here, FIRST, is what makes the guarantee "no party with write access on the
	// destination's path is ever let in" hold regardless of which product/role combination is
	// requested — so an unknown role under an unsafe parent must report the PARENT, not the role.
	f := newFx(t)
	if err := os.Chmod(f.base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
	err := Precheck(ctx(), f.l, f.d, testProduct, "nosuch", f.dest)
	mustContain(t, err, "writable by its group or by everyone")
	mustNotContain(t, err, "no volume role")
}

func TestVerbRefusesAnUnsafeParentBeforeConfirming(t *testing.T) {
	f := newFx(t)
	f.confirmed = false
	if err := os.Chmod(f.base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "writable by its group or by everyone")
	mustNotContain(t, err, "not confirmed")
	if len(f.prompts) != 0 {
		t.Fatalf("prompted before refusing: %v", f.prompts)
	}
}

func TestVerbNamesTheOffendingAncestor(t *testing.T) {
	f := newFx(t)
	base := unsafeBase(t, 0o777)
	parent := filepath.Join(base, "sub")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: filepath.Join(parent, "dest")})
	mustContain(t, err, "writable by its group or by everyone")
	// The OFFENDING COMPONENT is named: a chain whose broken link is not identified cannot be fixed.
	canonBase, _ := runtime.Canon(base)
	mustContain(t, err, canonBase)
}

func TestResumeRefusesAnUnsafeParent(t *testing.T) {
	// Resume is an INDEPENDENT entry point — a reconciliation sweep, not necessarily reached
	// through the verb at all — so it must establish parent trust itself.
	f := newFx(t)
	canon := f.canonDest()
	f.seed(record{Phase: 2, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "none", Desired: "running"})
	if err := os.Chmod(f.base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.base, 0o700) })
	mustContain(t, Resume(ctx(), f.l, f.d), "writable by its group or by everyone")
}

func TestRunRefusesAnUnsafeAncestorDirectly(t *testing.T) {
	// EVEN BYPASSING THE VERB AND THE PRECHECK. Run is the one mutation chokepoint, so it defends
	// itself rather than trusting that some caller already canonicalized and checked.
	f := newFx(t)
	base := unsafeBase(t, 0o777)
	dest := filepath.Join(base, "dest")
	err := Run(ctx(), f.l, f.d, testProduct, testRole, dest, 1)
	mustContain(t, err, "writable by its group or by everyone")
	if exists(dest) {
		t.Fatal("the refused phase created the destination anyway")
	}
}

// --- canonicalize once, use only that value ------------------------------------------------------

// aliasedDest builds `<base>/link -> <base>/real` and returns the RAW path through the alias plus
// the canonical path it resolves to. The alias's own parent is safe here: what is under test is
// that the raw and canonical forms are DIFFERENT STRINGS and that only the canonical one is used.
func aliasedDest(t *testing.T, base string) (raw, canon string) {
	t.Helper()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	raw = filepath.Join(base, "link", "dest")
	rc, err := runtime.Canon(real)
	if err != nil {
		t.Fatal(err)
	}
	canon = filepath.Join(rc, "dest")
	if raw == canon {
		t.Fatal("the alias and its target are the same string; the test proves nothing")
	}
	return raw, canon
}

func TestVerbRecordsTheCanonicalDestination(t *testing.T) {
	f := newFx(t)
	raw, canon := aliasedDest(t, f.base)
	f.bld.bind = canon
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: raw}); err != nil {
		t.Fatal(err)
	}
	got, err := f.confValue(f.confkey)
	if err != nil {
		t.Fatal(err)
	}
	if got != canon {
		t.Fatalf("mythical.conf records %q, want the canonical %q", got, canon)
	}
	// The container's own mount names the RESOLVED target, never the alias — and the data landed
	// there for real.
	mounts, _ := f.objs.ContainerMounts(ctx(), f.container)
	for _, m := range mounts {
		if strings.Contains(m.Source, filepath.Join(f.base, "link")) {
			t.Fatalf("the container mounts the alias path %q", m.Source)
		}
	}
	if !exists(canon) {
		t.Fatalf("nothing landed at the canonical destination %q", canon)
	}
}

func TestPhase3DerivesStagingFromTheCanonicalDest(t *testing.T) {
	// A record whose carried staging= names NEITHER the canonical nor the raw destination's sibling
	// proves the derivation is actually used: if the carried value were trusted, phase 3 would
	// operate on the bogus path instead of the real one.
	f := newFx(t)
	raw, canon := aliasedDest(t, f.base)
	bogus := filepath.Join(f.base, "nonexistent-bogus-carried-staging-path")
	f.seed(record{Phase: 3, Dest: raw, Nonce: "nz", Staging: bogus, Attempt: "none", Desired: "running"})
	derived := StagingPath(canon, "nz")
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, raw, 3); err != nil {
		t.Fatal(err)
	}
	if !exists(derived) {
		t.Fatalf("staging was not created at the derived canonical path %q", derived)
	}
	if exists(bogus) {
		t.Fatalf("the bogus carried staging path %q was operated on", bogus)
	}
}

func TestPhase5RefusesAPlantedEscapingSymlink(t *testing.T) {
	// The exact race: something with legitimate write access to the staging tree during the copy
	// plants an escaping symlink in the window between the copy's verification and the commit. The
	// staging directory's OWN identity is unchanged — it is the SAME directory phase 3 created — so
	// an inode check alone would not catch this; the content-level re-scan before the rename does.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(stage, "evil")); err != nil {
		t.Fatal(err)
	}
	sid, err := Identity(stage)
	if err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 5, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})
	err = Run(ctx(), f.l, f.d, testProduct, testRole, canon, 5)
	mustContain(t, err, "escapes it")
	if exists(canon) {
		t.Fatal("something was moved into place despite the refusal")
	}
	if !exists(stage) {
		t.Fatal("the staged tree was destroyed; a refusal preserves")
	}
}

// --- the ordered tail: config before container, replace not update, verify by inspection ---------

func TestBindIsWrittenBeforeTheContainerIsReplaced(t *testing.T) {
	f := newFx(t)
	canon := f.canonDest()
	var atRebuild string
	var atRebuildErr error
	f.bld.hook = func() { atRebuild, atRebuildErr = f.confValue(f.confkey) }
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	if atRebuildErr != nil {
		t.Fatalf("mythical.conf did not yet name the bind when the container was replaced: %v", atRebuildErr)
	}
	if atRebuild != canon {
		t.Fatalf("at replacement time mythical.conf held %q, want %q", atRebuild, canon)
	}
	// And it SURVIVES to the end, so anything later built from mythical.conf picks up the bind.
	got, err := f.confValue(f.confkey)
	if err != nil || got != canon {
		t.Fatalf("after the migration mythical.conf holds %q (%v)", got, err)
	}
}

func TestPhase7ReplacesAndTombstonesInOrder(t *testing.T) {
	f := newFx(t)
	var recordGone, tombstoned bool
	f.bld.hook = func() {
		_, ferr := prov.Find(f.l, prov.ClassContainer, f.container)
		recordGone = errors.Is(ferr, ledger.ErrAbsentRecord)
		_, terr := prov.TombstoneFind(f.l, prov.ClassContainer, f.container)
		tombstoned = terr == nil
	}
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	// MOUNTS ARE IMMUTABLE, so this is a REPLACEMENT: the old container is removed and tombstoned
	// before the new one is built. (There is no update door to take instead — the Mutator this
	// package holds exposes exactly Stop and Remove.)
	if len(f.mut.removed) != 1 || f.mut.removed[0] != f.container {
		t.Fatalf("the old container was not removed: %v", f.mut.removed)
	}
	if !recordGone || !tombstoned {
		t.Fatalf("at rebuild time: record gone=%v tombstoned=%v — the tombstone must precede the replacement",
			recordGone, tombstoned)
	}
	if len(f.bld.rebuilt) != 1 {
		t.Fatalf("the replacement was not built: %v", f.bld.rebuilt)
	}
}

func TestPhase7KeepsTheRecordWhenTheRemovalFails(t *testing.T) {
	// TOMBSTONE ONLY WHAT WAS ACTUALLY REMOVED. A transient removal failure followed by a tombstone
	// strips the old container's authority record while it is still there — recovery then reads it
	// as absent, skips the removal, and cannot create the replacement under the same name.
	f := newFx(t)
	f.mut.rmErr = errors.New("daemon says no")
	canon := f.canonDest()
	sid := f.stageAndCommit(canon)
	f.seed(record{Phase: 7, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		StageID: sid, Attempt: "started", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 7)
	mustContain(t, err, "could not remove the old container")
	if _, ferr := prov.Find(f.l, prov.ClassContainer, f.container); ferr != nil {
		t.Fatalf("the container's record was dropped despite the removal failing: %v", ferr)
	}
	if len(f.bld.rebuilt) != 0 {
		t.Fatal("a replacement was built over a container that is still there")
	}
}

// stageAndCommit puts a directory at `dest` carrying a recorded identity, as phase 5's rename
// would leave it.
func (f *fx) stageAndCommit(dest string) string {
	f.t.Helper()
	if err := os.Mkdir(dest, 0o755); err != nil {
		f.t.Fatal(err)
	}
	id, err := Identity(dest)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestPhase8VerifiesByInspectionAndClaimsNothingMore(t *testing.T) {
	f := newFx(t)
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	// Re-running phase 8 alone still passes: it is a pure inspection.
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, f.dest, 8); err != nil {
		t.Fatal(err)
	}
	out := f.log.String()
	if !strings.Contains(out, "not verified at all") {
		t.Fatalf("phase 8 does not state that the container-side read is unverified:\n%s", out)
	}
	// AND IT CLAIMS NOTHING IT DID NOT DO.
	for _, forbidden := range []string{"container-side read is verified", "container-side read is confirmed"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("phase 8 claims %q", forbidden)
		}
	}
	// A container that does NOT mount the destination is refused, not narrated as verified.
	f.objs.mounts[f.container] = []engine.MountRecord{{Type: "bind", Source: "/elsewhere", Destination: testMount}}
	mustContain(t, Run(ctx(), f.l, f.d, testProduct, testRole, f.dest, 8), "does not mount")
}

func TestDesiredStoppedSurvivesTheMigration(t *testing.T) {
	f := newFx(t)
	if err := state.Commit(f.l, f.container, state.Stopped, nil, true); err != nil {
		t.Fatal(err)
	}
	f.stt.running[f.container] = false
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	// THIS VERB STOPS THE CONTAINER AS A MEANS, NOT AS AN INTENT — the operator's recorded wish
	// survives, and phase 8 still verified the mount by inspection.
	want, err := state.DesiredGet(f.l, f.container)
	if err != nil {
		t.Fatal(err)
	}
	if want != state.Stopped {
		t.Fatalf("desired state after the migration is %q, want stopped", want)
	}
	if !strings.Contains(f.log.String(), "verified by inspection") {
		t.Fatal("phase 8 did not verify the mount for a desired-stopped product")
	}
}

func TestSuspendsReconciliation(t *testing.T) {
	// THE RECORD KIND THIS PACKAGE WRITES IS THE ONE THE RECONCILER SUSPENDS ON. Asserted against
	// state.PlanFor rather than against a second copy of the string, because two spellings of one
	// ledger kind is exactly how that suspension stops matching the records it guards.
	f := newFx(t)
	canon := f.canonDest()
	f.seed(record{Phase: 3, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "none", Desired: "running"})
	if err := state.Commit(f.l, f.container, state.Running, nil, true); err != nil {
		t.Fatal(err)
	}
	f.stt.running[f.container] = false
	plan, err := state.PlanFor(ctx(), f.l, f.stt, f.container)
	if err != nil {
		t.Fatal(err)
	}
	if plan != state.PlanSuspended {
		t.Fatalf("plan is %q while a migration intent is live, want suspended", plan)
	}
}

func TestPhase9RestoresDesiredStateAndRetainsTheSource(t *testing.T) {
	f := newFx(t)
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	want, err := state.DesiredGet(f.l, f.container)
	if err != nil || want != state.Running {
		t.Fatalf("desired state %q (%v), want running", want, err)
	}
	if len(f.bld.reconciled) != 1 {
		t.Fatalf("the container was not reconciled toward its recorded state: %v", f.bld.reconciled)
	}
	// The intent is cleared only after the last thing it authorizes has succeeded.
	if _, err := Phase(f.l, testProduct, testRole); !errors.Is(err, ErrNoMigration) {
		t.Fatalf("the intent survived a completed migration: %v", err)
	}
	// THE SOURCE VOLUME IS RETAINED. Deleting an operator's data is never automatic — and this
	// package holds no volume-removal door at all, so it could not have.
	if _, err := prov.Find(f.l, prov.ClassVolume, f.srcvol); err != nil {
		t.Fatalf("the source volume's record was dropped: %v", err)
	}
	if !strings.Contains(f.log.String(), "is retained") {
		t.Fatalf("the operator was not told the source volume is retained:\n%s", f.log.String())
	}
}

func TestMigrationCompletesEndToEnd(t *testing.T) {
	f := newFx(t)
	canon := f.canonDest()
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	got, err := f.confValue(f.confkey)
	if err != nil || got != canon {
		t.Fatalf("mythical.conf holds %q (%v), want %q", got, err, canon)
	}
	if !exists(canon) {
		t.Fatal("the destination was never created")
	}
	mounts, _ := f.objs.ContainerMounts(ctx(), f.container)
	if len(mounts) != 1 || mounts[0].Type != "bind" || mounts[0].Source != canon {
		t.Fatalf("the replacement container does not mount the bind: %v", mounts)
	}
	// The ledger the caller ends up with is the one on disk: every phase persisted before acting.
	onDisk, err := ledger.Read(ledger.LiveRead(f.home))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onDisk.Find(Kind, "key", testProduct+":"+testRole); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the persisted ledger still carries the intent: %v", err)
	}
}

func TestPhase6PresentsTheRecordedAttemptState(t *testing.T) {
	// WHICH ATTEMPT STATE THIS MODULE PRESENTS is its own contract (the compare-and-set's table is
	// internal/conf's). A fresh entry presents "none"; an entry RESUMED after a crash inside the
	// write presents "started", read from the STALE record — which is what makes a crash
	// distinguishable from a hand edit at all.
	f := newFx(t)
	canon := f.canonDest()
	// Fresh: attempt=none, key absent, prior "" → write.
	f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "none", Desired: "running"})
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.confValue(f.confkey); got != canon {
		t.Fatalf("fresh phase 6 wrote %q", got)
	}
	// Resumed: attempt=started and the key already holds our value → advance without rewriting,
	// and with no confirmation asked for.
	f.prompts = nil
	f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "started", Desired: "running"})
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6); err != nil {
		t.Fatal(err)
	}
	if len(f.prompts) != 0 {
		t.Fatalf("an already-written key asked for confirmation: %v", f.prompts)
	}
}

func TestEveryPhaseResumesFromItsRecordedPhase(t *testing.T) {
	for n := PhaseFirst; n <= PhaseLast; n++ {
		t.Run(fmt.Sprintf("phase%d", n), func(t *testing.T) {
			f := newFx(t)
			canon := f.canonDest()
			f.seed(record{Phase: n, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
				Attempt: "none", Desired: "running"})
			if err := Resume(ctx(), f.l, f.d); err != nil {
				t.Fatalf("phase %d did not resume: %v", n, err)
			}
			if _, err := Phase(f.l, testProduct, testRole); !errors.Is(err, ErrNoMigration) {
				t.Fatalf("phase %d resumed but did not complete: %v", n, err)
			}
			// THE RECORDED PHASE IS A WRITE-AHEAD INTENT, VERIFIED BEFORE IT IS TRUSTED. None of
			// these records carries a stage identity, so a phase of 6 or later does NOT prove the
			// rename ever produced a destination — the resume must re-derive phase 5 and put one
			// there. Asserting only "it returned 0" would pass just as happily if the resume had
			// trusted the record and skipped straight to writing a bind for a path that does not
			// exist.
			if !exists(canon) {
				t.Fatalf("phase %d resumed to completion without the destination ever being created", n)
			}
			if got, cerr := f.confValue(f.confkey); cerr != nil || got != canon {
				t.Fatalf("phase %d resumed but mythical.conf holds %q (%v)", n, got, cerr)
			}
		})
	}
}

// --- the source volume is untrusted ---------------------------------------------------------------

func TestACopyRefusalLeavesNoDestinationAndNoBind(t *testing.T) {
	// A REFUSAL THAT STILL LET BYTES REACH THE DESTINATION IS NOT A REFUSAL. Each of these is a
	// different refusal the copy step raises over hostile volume contents; what is asserted here is
	// the migration's half — nothing at the destination, and no bind recorded.
	for _, reason := range []string{
		"the source tree contains a symlink that escapes the migrated tree",
		"the source tree contains a device, socket or FIFO entry",
		"the source tree contains an entry of a type this copy does not carry",
	} {
		t.Run(reason[:24], func(t *testing.T) {
			f := newFx(t)
			f.cp.runErr = errors.New(reason)
			err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
			mustContain(t, err, reason)
			if exists(f.dest) || exists(f.canonDest()) {
				t.Fatal("the destination exists after a refused copy")
			}
			if _, cerr := f.confValue(f.confkey); cerr == nil {
				t.Fatal("the bind was written despite the copy refusing")
			}
		})
	}
}

func TestASetuidVolumeStillMigratesAndTheReportReachesTheOperator(t *testing.T) {
	f := newFx(t)
	f.cp.report = "copy: privileged bits stripped from 1 entry"
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.log.String(), "privileged bits stripped") {
		t.Fatalf("the stripped-privilege report did not reach the operator:\n%s", f.log.String())
	}
	if got, _ := f.confValue(f.confkey); got != f.canonDest() {
		t.Fatalf("mythical.conf holds %q, want the canonical destination", got)
	}
}

func TestForeignUIDRefusedByDefaultMappedWhenAsked(t *testing.T) {
	t.Run("refused by default", func(t *testing.T) {
		f := newFx(t)
		f.cp.refuseUnlessMapForeign = true
		err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
		mustContain(t, err, "foreign uid")
		if exists(f.canonDest()) {
			t.Fatal("the destination exists after a refused copy")
		}
	})
	t.Run("mapped when asked", func(t *testing.T) {
		f := newFx(t)
		f.cp.refuseUnlessMapForeign = true
		err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole,
			Options{ToBind: f.dest, MapForeign: true})
		if err != nil {
			t.Fatal(err)
		}
		if !f.cp.sawMapForeign {
			t.Fatal("--map-foreign-to-operator did not reach the copy step")
		}
		if got, _ := f.confValue(f.confkey); got != f.canonDest() {
			t.Fatalf("mythical.conf holds %q, want the canonical destination", got)
		}
	})
}

func TestAnOrdinarySymlinkMigrates(t *testing.T) {
	// The pre-commit re-check refuses only what ESCAPES. An intra-tree symlink must survive the
	// whole migration — a check that refused every symlink would be safe and useless.
	f := newFx(t)
	f.cp.afterRun = func(staging string) {
		if err := os.MkdirAll(filepath.Join(staging, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staging, "sub", "f"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("sub/f", filepath.Join(staging, "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(f.canonDest(), "link"))
	if err != nil || target != "sub/f" {
		t.Fatalf("the intra-tree symlink did not survive: %q %v", target, err)
	}
}

// --- the destination is untrusted -----------------------------------------------------------------

func TestAPreSeededDestinationIsRefusedAndNeverFollowed(t *testing.T) {
	f := newFx(t)
	if err := os.Mkdir(f.dest, 0o755); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(f.dest, "evil")
	if err := os.Symlink("/etc/passwd", evil); err != nil {
		t.Fatal(err)
	}
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "not empty")
	// UNTOUCHED — never adopted, never followed.
	target, rerr := os.Readlink(evil)
	if rerr != nil || target != "/etc/passwd" {
		t.Fatalf("the pre-seeded symlink was disturbed: %q %v", target, rerr)
	}
}

func TestVerbRefusesAMountPointEndToEnd(t *testing.T) {
	f := newFx(t)
	if err := os.Mkdir(f.dest, 0o755); err != nil {
		t.Fatal(err)
	}
	f.mt.points = []string{f.dest}
	mustContain(t, MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}), "subdirectory")
}

// --- interrupted at a real phase, then resumed ----------------------------------------------------

func TestInterruptedAtPhase2ConvergesOnResume(t *testing.T) {
	f := newFx(t)
	f.mut.stopErr = errors.New("interrupted")
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "could not be stopped")
	p, perr := Phase(f.l, testProduct, testRole)
	if perr != nil || p != 2 {
		t.Fatalf("the intent is at phase %d (%v), want 2", p, perr)
	}
	f.mut.stopErr = nil
	if err := Resume(ctx(), f.l, f.d); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.confValue(f.confkey); got != f.canonDest() {
		t.Fatalf("after the resume mythical.conf holds %q", got)
	}
	mounts, _ := f.objs.ContainerMounts(ctx(), f.container)
	if len(mounts) != 1 || mounts[0].Source != f.canonDest() {
		t.Fatalf("the container does not mount the bind: %v", mounts)
	}
}

func TestInterruptedAtPhase7ConvergesOnResume(t *testing.T) {
	f := newFx(t)
	f.bld.rebuildErr = errors.New("interrupted")
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	if err == nil {
		t.Fatal("the interrupted replacement reported success")
	}
	// THE CONFIG WRITE (phase 6) HAD ALREADY LANDED — it precedes the replacement this interrupted.
	if got, cerr := f.confValue(f.confkey); cerr != nil || got != f.canonDest() {
		t.Fatalf("mythical.conf holds %q (%v)", got, cerr)
	}
	f.bld.rebuildErr = nil
	if err := Resume(ctx(), f.l, f.d); err != nil {
		t.Fatal(err)
	}
	mounts, _ := f.objs.ContainerMounts(ctx(), f.container)
	if len(mounts) != 1 || mounts[0].Source != f.canonDest() {
		t.Fatalf("the container does not mount the bind after the resume: %v", mounts)
	}
	if _, err := Phase(f.l, testProduct, testRole); !errors.Is(err, ErrNoMigration) {
		t.Fatalf("the intent was not cleared by the completed resume: %v", err)
	}
}

func TestALeftoverStagingIsSteppedAroundNeverAdopted(t *testing.T) {
	f := newFx(t)
	f.cp.runErr = errors.New("interrupted mid-copy")
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err == nil {
		t.Fatal("the interrupted copy reported success")
	}
	leftovers := stagingSiblings(t, f.base)
	if len(leftovers) != 1 {
		t.Fatalf("expected exactly one staging leftover, got %v", leftovers)
	}
	first := leftovers[0]
	f.cp.runErr = nil

	// The FIRST resume re-enters phase 3 with the CARRIED nonce, and the non-adopting mkdir refuses
	// to take over a directory this attempt cannot prove is its own. It steps the record back to
	// phase 1 with the nonce cleared — "preserved and reported; re-run to proceed beside it".
	err := Resume(ctx(), f.l, f.d)
	mustContain(t, err, "already exists")
	if !exists(first) {
		t.Fatal("the leftover was adopted or removed")
	}
	p, _ := Phase(f.l, testProduct, testRole)
	if p != 1 {
		t.Fatalf("the record is at phase %d after the refusal, want 1 (a fresh nonce next time)", p)
	}

	// The SECOND resume mints a fresh nonce and proceeds BESIDE the leftover, which survives the
	// whole migration untouched: reclaiming it is never automatic.
	if err := Resume(ctx(), f.l, f.d); err != nil {
		t.Fatal(err)
	}
	if !exists(first) {
		t.Fatal("the completed migration removed the abandoned leftover")
	}
	if got, _ := f.confValue(f.confkey); got != f.canonDest() {
		t.Fatalf("mythical.conf holds %q", got)
	}
}

func stagingSiblings(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".mythical-staging-") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func TestOperatorEditIsNeverSilentlyOverwritten(t *testing.T) {
	f := newFx(t)
	canon := f.canonDest()
	seed := func() {
		f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
			Attempt: "started", Desired: "running"})
	}
	if err := conf.FamilyAdd(f.lock, f.confkey, "/operators/own/choice"); err != nil {
		t.Fatal(err)
	}

	// No confirmation input at all: the resume refuses at its own gate, and the operator's value
	// stands.
	seed()
	f.confirmed = false
	if err := Resume(ctx(), f.l, f.d); err == nil {
		t.Fatal("an unconfirmed resume proceeded")
	}
	if got, _ := f.confValue(f.confkey); got != "/operators/own/choice" {
		t.Fatalf("mythical.conf holds %q, want the operator's own value", got)
	}

	// STRONGER: the resume IS confirmed, so the phase loop runs and reaches the compare-and-set —
	// which finds a recorded write in progress over a value that is neither ours nor the recorded
	// prior. A crash and a hand edit are indistinguishable from the file alone, so it asks; declining
	// THAT question must leave the operator's edit exactly where it was.
	seed()
	f.confirmed = true
	f.d.Confirm = func(p string) bool {
		f.prompts = append(f.prompts, p)
		return !strings.Contains(p, "discarding what is there")
	}
	if err := Resume(ctx(), f.l, f.d); err == nil {
		t.Fatal("the compare-and-set overwrote a value it had not cleared")
	}
	if got, _ := f.confValue(f.confkey); got != "/operators/own/choice" {
		t.Fatalf("mythical.conf holds %q after the declined write", got)
	}
}

func TestResumeWithoutConfirmationDoesNothing(t *testing.T) {
	f := newFx(t)
	canon := f.canonDest()
	f.seed(record{Phase: 6, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "none", Desired: "running"})
	f.confirmed = false
	err := Resume(ctx(), f.l, f.d)
	mustContain(t, err, "not confirmed")
	// NOTHING WAS ATTEMPTED — not even phase 5's own "nothing to protect" fallback.
	if exists(canon) {
		t.Fatal("the destination was created by an unconfirmed resume")
	}
	if _, cerr := f.confValue(f.confkey); cerr == nil {
		t.Fatal("the bind was written by an unconfirmed resume")
	}
	if p, _ := Phase(f.l, testProduct, testRole); p != 6 {
		t.Fatalf("the record moved to phase %d, want 6 (untouched)", p)
	}
}

func TestResumeRefusesAPartialLedgerView(t *testing.T) {
	// A LISTING THAT COULD NOT BE FULLY READ IS A REFUSAL. Reading it as an empty list would report
	// success having resumed nothing at all — a migration abandoned mid-flight with a clean exit.
	//
	// The record is UNREADABLE, not merely incomplete: the two refuse in different places, and only
	// this one exercises the listing call's own error. It is built on disk, with a correct checksum
	// over a malformed record body — which is what a hand-edited or repair-written ledger actually
	// looks like, and the only state that reaches the branch, since the integrity gate validates the
	// checksum and the header while leaving record bodies for the readers.
	f := newFx(t)
	path := filepath.Join(f.home, ".state", "ledger")
	body := "#mythical-ctl-ledger schema=1\n" +
		"ident\tid=" + f.ident + "\n" +
		Kind + "\tthis-token-is-not-a-field\n"
	if err := os.WriteFile(path, []byte(body+"#sha256="+cliio.SHA256Hex([]byte(body))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(ledger.LiveRead(f.home))
	if err != nil {
		t.Fatalf("the fixture ledger does not pass the integrity gate, so it never reaches the listing: %v", err)
	}
	if _, aerr := l.All(Kind); aerr == nil {
		t.Fatal("the fixture record lists cleanly, so this test cannot reach the listing's refusal")
	}
	mustContain(t, Resume(ctx(), l, f.d), "could not be fully read", "Refusing rather than resuming a partial view")

	// And the SEMANTIC half, which refuses later and for a different reason: a record that lists
	// cleanly but does not say which migration it describes.
	f2 := newFx(t)
	if err := f2.l.Append(Kind, []ledger.Field{{Key: "key", Value: "p1:state"}, {Key: "role", Value: testRole}}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, Resume(ctx(), f2.l, f2.d), "does not name a product")
}

// --- guards with no bats row of their own ---------------------------------------------------------
//
// The reference could not construct these states either; they are here so that reverting the guard
// in isolation reddens something.

func TestPhase2RefusesWhenTheStateCannotBeAsked(t *testing.T) {
	// A FAILURE TO ANSWER IS NOT EVIDENCE THAT IT STOPPED. Folding an unanswerable observation into
	// "not running" would let the copy proceed against a volume that may still be live — on exactly
	// the flaky-daemon moment this check exists to catch.
	f := newFx(t)
	f.mut.stopErr = errors.New("daemon hiccup")
	f.stt.err = errors.New("and it cannot be asked either")
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "could not be stopped", "could not be\n  established either way")
	if len(f.cp.ranWith) != 0 {
		t.Fatal("the copy ran against a volume that may still be written to")
	}

	// And a stop that failed over a container the runtime confirms is NOT running proceeds: the
	// refusal is about the unanswerable case, not about every failed stop.
	f2 := newFx(t)
	f2.mut.stopErr = errors.New("already stopped")
	f2.stt.running[f2.container] = false
	if err := MigrateStorage(ctx(), f2.l, f2.d, testProduct, testRole, Options{ToBind: f2.dest}); err != nil {
		t.Fatalf("a failed stop over a confirmed-stopped container was refused: %v", err)
	}
}

func TestPhase4RefusesWithoutAnIdentityOrAnEntryCount(t *testing.T) {
	// Phase 3 records `stageid` in the SAME write that creates the staging directory, so reaching
	// phase 4 with the directory on disk and NO recorded identity is a corrective ledger edit, not a
	// live migration — the same ambiguity phase 5 refuses under.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 4, Dest: canon, Nonce: "nz", Staging: stage, Attempt: "none", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4)
	mustContain(t, err, "no recorded staging identity")

	// With an identity but NO entry count, the verification has nothing to bind itself to: the copy
	// step did not run in this process, and verifying against a count no step derived is verifying
	// against a number this process invented.
	sid, _ := Identity(stage)
	f.seed(record{Phase: 4, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})
	err = Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4)
	mustContain(t, err, "no source-entry count is available")

	// With BOTH, it verifies.
	f.d.Entries.Set(7)
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4); err != nil {
		t.Fatalf("a well-formed phase 4 was refused: %v", err)
	}
}

func TestPhase5RefusesWithoutAnIdentityWhenSomethingIsThere(t *testing.T) {
	// NO IDENTITY, NO COMMIT — unless there is provably nothing to protect.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 5, Dest: canon, Nonce: "nz", Staging: stage, Attempt: "none", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 5)
	mustContain(t, err, "no recorded staging identity", "Nothing is removed")
	if !exists(stage) {
		t.Fatal("the unattributable staging directory was removed")
	}
	if exists(canon) {
		t.Fatal("the destination was committed over an unattributable staging directory")
	}

	// With NOTHING anywhere there is no hostile substitution possible and nothing legitimate to
	// lose, so the destination is simply put in place empty and the phase advances.
	f2 := newFx(t)
	canon2 := f2.canonDest()
	f2.seed(record{Phase: 5, Dest: canon2, Nonce: "nz", Staging: StagingPath(canon2, "nz"),
		Attempt: "none", Desired: "running"})
	if err := Run(ctx(), f2.l, f2.d, testProduct, testRole, canon2, 5); err != nil {
		t.Fatalf("the nothing-to-protect fallback was refused: %v", err)
	}
	if !exists(canon2) {
		t.Fatal("the fallback did not create the destination")
	}
}

func TestPhase5RefusesANonEmptyDestinationAtCommitTime(t *testing.T) {
	// The precheck accepted the destination empty or absent; an attacker who controls its parent can
	// undo that afterwards. THE RMDIR'S OWN RESULT DECIDES, never an assumption: a rename onto an
	// EXISTING non-empty directory is not a replacement, so the whole copy would land one level down
	// beside whatever was planted — non-atomic, and wrong in a way nothing afterwards would notice.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "payload"), []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(stage)
	// Planted after the precheck: a non-empty directory at the destination.
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(canon, "theirs"), []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 5, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 5)
	mustContain(t, err, "no longer the empty or absent directory")
	// NOTHING WAS NESTED: the copy is intact at staging and the destination holds only what was
	// planted there.
	if !exists(filepath.Join(stage, "payload")) {
		t.Fatal("the copy was moved despite the refusal")
	}
	ents, rerr := os.ReadDir(canon)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(ents) != 1 || ents[0].Name() != "theirs" {
		t.Fatalf("the destination was modified: %v", ents)
	}
}

func TestPhase7RefusesASwappedDestination(t *testing.T) {
	// RE-VERIFIED BEFORE THE REPLACEMENT MOUNTS IT, and before the irreversible removal: the
	// destination is about to become a live bind source for the ACTUAL product container.
	f := newFx(t)
	canon := f.canonDest()
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	stale, _ := Identity(canon)
	// Replaced by a different directory at the same name.
	if err := os.RemoveAll(canon); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 7, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		StageID: stale, Attempt: "started", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 7)
	mustContain(t, err, "no longer carries the identity")
	if len(f.mut.removed) != 0 {
		t.Fatal("the old container was removed before the destination was verified")
	}
	if len(f.bld.rebuilt) != 0 {
		t.Fatal("a replacement was built over an unverified destination")
	}
}

func TestNoConfirmationSeamIsNotConsent(t *testing.T) {
	// A MISSING PROMPT IS NOT CONSENT. Without this, a caller that simply forgot to wire the
	// confirmation would get an unattended, destructive migration.
	f := newFx(t)
	f.d.Confirm = nil
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "not confirmed")
	if exists(f.canonDest()) {
		t.Fatal("a migration with no confirmation seam created the destination")
	}
}

func TestPersistIsRequired(t *testing.T) {
	// THE WRITE-AHEAD RECORD IS THE WHOLE OF THE DURABLE-PHASE CONTRACT. A phase recorded only in
	// memory is a phase no crash can resume from, so a missing persist seam is a refusal rather
	// than a silently in-memory migration.
	f := newFx(t)
	f.d.Persist = nil
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "no way to write the intent down before acting on it")
	if exists(f.canonDest()) {
		t.Fatal("a migration with no write-ahead seam created the destination")
	}
}

func TestRunRefusesAPhaseThisCoreDoesNotDefine(t *testing.T) {
	// A phase outside the nine would make the resume loop run ZERO iterations and report success —
	// a migration that reports success without doing anything.
	f := newFx(t)
	// REFUSED BEFORE ANY WORK: the docs seam is rigged to fail, so a refusal naming the DOCUMENTS
	// would prove the phase check ran too late — after the destination was canonicalized and the
	// authenticated documents were accepted (which advances the anti-rollback trust floor).
	f.d.Docs = fakeDocs{merr: errors.New("the manifest was consulted"), perr: errors.New("so was the policy")}
	for _, p := range []int{0, 10, -1} {
		err := Run(ctx(), f.l, f.d, testProduct, testRole, f.dest, p)
		mustContain(t, err, "is not a migration phase")
		mustNotContain(t, err, "was consulted")
	}
	f.d.Docs = fakeDocs{m: testManifest(t), p: testPolicy(t)}
	canon := f.canonDest()
	if err := f.l.Put(Kind, "key", testProduct+":"+testRole, []ledger.Field{
		{Key: "key", Value: testProduct + ":" + testRole},
		{Key: "product", Value: testProduct}, {Key: "role", Value: testRole},
		{Key: "phase", Value: "42"}, {Key: "dest", Value: canon},
	}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, Resume(ctx(), f.l, f.d), "not\n  one this core defines")
}

func TestPhase5VerifiesTheDestinationAfterTheRename(t *testing.T) {
	// THE RESULT IS VERIFIED TOO — not assumed from the rename's own success. A rename cannot be
	// made to land on something other than what it just moved, so the rename is interposed: if the
	// destination does not carry the identity that just moved there, continuing to phase 6 (which
	// writes this very path into mythical.conf) would commit to it anyway.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(stage)
	f.seed(record{Phase: 5, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})

	orig := renameDir
	renameDir = func(from, to string) error {
		if err := orig(from, to); err != nil {
			return err
		}
		if err := os.RemoveAll(to); err != nil {
			return err
		}
		return os.Mkdir(to, 0o755)
	}
	t.Cleanup(func() { renameDir = orig })

	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 5)
	mustContain(t, err, "no longer carries the identity")
	if _, cerr := f.confValue(f.confkey); cerr == nil {
		t.Fatal("the bind was written over a destination the rename could not be shown to have produced")
	}
}

func TestVerbRefusesARelativeToBind(t *testing.T) {
	// EVERY PATH COMPARISON HERE IS ON ABSOLUTE PATHS — the ancestor walk, the overlap check, the
	// canonicalization. A relative operand would be resolved against whatever directory the process
	// happens to be in, which is not a location the operator named.
	f := newFx(t)
	mustContain(t, MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: "relative/dest"}),
		"--to-bind needs an absolute path, not a path relative to the current directory")
	mustContain(t, MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{}),
		"needs --to-bind")
	if len(f.prompts) != 0 {
		t.Fatalf("prompted for a malformed destination: %v", f.prompts)
	}
}

// --- gate round 1: the guards findings 1-5 added -------------------------------------------------

func TestAPresentButEmptyFieldIsNotAnAbsentOne(t *testing.T) {
	// THE REFERENCE DEFAULTS ONLY ON ABSENCE. A field that is there and empty is carried verbatim,
	// so a corrupt or hand-edited record reaches the refusal it should — rather than being silently
	// upgraded into a well-formed one.
	t.Run("empty desired refuses at phase 9 and keeps the intent", func(t *testing.T) {
		f := newFx(t)
		canon := f.canonDest()
		if err := os.Mkdir(canon, 0o755); err != nil {
			t.Fatal(err)
		}
		f.seedRaw(map[string]string{
			"phase": "9", "dest": canon, "nonce": "nz", "staging": StagingPath(canon, "nz"),
			"attempt": "started", "desired": "", "confkey": f.confkey, "srcvol": f.srcvol,
			"mount": testMount, "prior": "", "stageid": "",
		})
		err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 9)
		mustContain(t, err, "neither running nor", "stopped")
		// AND THE INTENT SURVIVES. The desired state is restored BEFORE the intent is cleared, so a
		// refusal here must leave the record naming what still has to happen — an intent cleared
		// first, followed by a failed restore, would leave nothing recording that the container
		// should still reach its prior state.
		if p, perr := Phase(f.l, testProduct, testRole); perr != nil || p != 9 {
			t.Fatalf("the intent is at %d (%v) after a refused phase 9, want 9", p, perr)
		}
		if f.diskPhase() != 9 {
			t.Fatalf("the persisted intent is at %d after a refused phase 9", f.diskPhase())
		}
	})

	t.Run("empty attempt refuses at phase 6", func(t *testing.T) {
		f := newFx(t)
		canon := f.canonDest()
		f.seedRaw(map[string]string{
			"phase": "6", "dest": canon, "nonce": "nz", "staging": StagingPath(canon, "nz"),
			"attempt": "", "desired": "running", "confkey": f.confkey, "srcvol": f.srcvol,
			"mount": testMount, "prior": "", "stageid": "",
		})
		err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6)
		mustContain(t, err, "is neither 'none' nor", "'started'")
		if _, cerr := f.confValue(f.confkey); cerr == nil {
			t.Fatal("mythical.conf was written from an unrecognised attempt state")
		}
	})

	t.Run("an ABSENT field still defaults", func(t *testing.T) {
		// The other half of the same rule: no record at all, and a record that simply does not carry
		// the field, both default — which is what makes phase 1's own entry and a
		// pre-this-core record work.
		f := newFx(t)
		canon := f.canonDest()
		if err := os.Mkdir(canon, 0o755); err != nil {
			t.Fatal(err)
		}
		f.seedRaw(map[string]string{
			"phase": "9", "dest": canon, "nonce": "nz", "staging": StagingPath(canon, "nz"),
			"confkey": f.confkey, "srcvol": f.srcvol, "mount": testMount,
		})
		if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 9); err != nil {
			t.Fatalf("a record carrying no desired field did not default to running: %v", err)
		}
		want, err := state.DesiredGet(f.l, f.container)
		if err != nil || want != state.Running {
			t.Fatalf("desired state %q (%v)", want, err)
		}
	})
}

func TestAFailedWriteLeavesTheCallersLedgerAlone(t *testing.T) {
	// THE RECORD IS WRITTEN AHEAD OF THE ACTION, OR NOTHING IS. A phase published into the caller's
	// ledger before the write succeeded reads as durable and is not — and at phase 9 the same
	// pattern would leave the intent GONE in memory while disk still carried it, so a same-process
	// resume would answer "nothing to resume" about a migration that is still recorded.
	f := newFx(t)
	before := len(f.l.Lines())
	f.d.Persist = func(*ledger.Ledger) error { return errors.New("disk is full") }
	err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest})
	mustContain(t, err, "could not be persisted")
	if got := len(f.l.Lines()); got != before {
		t.Fatalf("the caller's ledger grew from %d to %d lines despite the write failing", before, got)
	}
	if _, perr := Phase(f.l, testProduct, testRole); !errors.Is(perr, ErrNoMigration) {
		t.Fatalf("an unpersisted phase is visible in the caller's ledger: %v", perr)
	}

	// The same at the OTHER end: a phase 9 whose write fails must not leave the intent cleared in
	// memory while it is still on disk.
	f2 := newFx(t)
	canon := f2.canonDest()
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	f2.seed(record{Phase: 9, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "started", Desired: "running"})
	f2.d.Persist = func(*ledger.Ledger) error { return errors.New("disk is full") }
	if err := Run(ctx(), f2.l, f2.d, testProduct, testRole, canon, 9); err == nil {
		t.Fatal("a phase 9 whose write failed reported success")
	}
	if p, perr := Phase(f2.l, testProduct, testRole); perr != nil || p != 9 {
		t.Fatalf("the intent was cleared in memory despite the write failing: %d %v", p, perr)
	}

	// AND THE SECOND STAGED WRITE OF THE SAME PHASE. Phase 9 restores the desired state and THEN
	// clears the intent; a Persist that fails immediately only ever exercises the first of those,
	// so the deletion could still be mutating the caller's ledger before its own write and nothing
	// would notice. Here the restore is allowed to land and only the DELETION's write fails.
	f3 := newFx(t)
	canon3 := f3.canonDest()
	if err := os.Mkdir(canon3, 0o755); err != nil {
		t.Fatal(err)
	}
	f3.seed(record{Phase: 9, Dest: canon3, Nonce: "nz", Staging: StagingPath(canon3, "nz"),
		Attempt: "started", Desired: "running"})
	real := f3.d.Persist
	writes := 0
	f3.d.Persist = func(l *ledger.Ledger) error {
		writes++
		if writes > 1 {
			return errors.New("disk is full")
		}
		return real(l)
	}
	if err := Run(ctx(), f3.l, f3.d, testProduct, testRole, canon3, 9); err == nil {
		t.Fatal("a phase 9 whose second write failed reported success")
	}
	if writes < 2 {
		t.Fatalf("phase 9 performed %d staged writes; the second one was never reached", writes)
	}
	// The restore landed; the deletion did not, in memory OR on disk.
	if want, werr := state.DesiredGet(f3.l, f3.container); werr != nil || want != state.Running {
		t.Fatalf("the desired state was not restored: %q %v", want, werr)
	}
	if p, perr := Phase(f3.l, testProduct, testRole); perr != nil || p != 9 {
		t.Fatalf("the intent was cleared in memory despite its write failing: %d %v", p, perr)
	}
	if f3.diskPhase() != 9 {
		t.Fatalf("the persisted intent is at %d, want 9", f3.diskPhase())
	}
}

func TestPhase3NamesTheLeftoverItPreserves(t *testing.T) {
	// PRESERVED AND REPORTED — and "reported" means NAMED. The record steps back to phase 1 with the
	// staging path cleared so the next attempt mints a fresh one, but a refusal that does not say
	// WHICH directory it is preserving leaves the operator with nothing to inspect or reclaim.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 3, Dest: canon, Nonce: "nz", Staging: stage, Attempt: "none", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 3)
	mustContain(t, err, stage, "already exists")
	mustNotContain(t, err, `""`)
	if !exists(stage) {
		t.Fatal("the leftover was removed")
	}
}

func TestASymlinkAtTheStagingNameIsReportedNotSwallowed(t *testing.T) {
	// "IS THERE A DIRECTORY HERE" FOLLOWS THE SYMLINK, as `[ -d ]` does; the IDENTITY question is
	// what uses Lstat. Reading a symlink-to-directory as "there is nothing here" would skip the
	// verification entirely at phase 4, and would make the reclaim return SUCCESS having said
	// nothing about an object standing where this installer's own staging directory should be.
	t.Run("phase 4 verifies rather than skipping", func(t *testing.T) {
		f := newFx(t)
		canon := f.canonDest()
		stage := StagingPath(canon, "nz")
		real := filepath.Join(f.base, "elsewhere")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, stage); err != nil {
			t.Fatal(err)
		}
		f.seed(record{Phase: 4, Dest: canon, Nonce: "nz", Staging: stage, StageID: "1:2",
			Attempt: "none", Desired: "running"})
		f.d.Entries.Set(3)
		err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4)
		mustContain(t, err, "no longer carries the identity")
		if len(f.cp.ranWith) != 0 {
			t.Fatal("the copy helper was handed a substituted staging path")
		}
	})

	t.Run("reclaim reports the mismatch", func(t *testing.T) {
		base := safeBase(t)
		home := filepath.Join(base, "home")
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
		stage := StagingPath(filepath.Join(base, "dest"), "nonceX")
		real := filepath.Join(base, "elsewhere")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, stage); err != nil {
			t.Fatal(err)
		}
		err := StagingReclaim(home, stage, "nonceX", "1:2", "nonceX")
		mustContain(t, err, "does not match the recorded intent", "preserved")
		if !exists(stage) {
			t.Fatal("the substituted object was removed")
		}
	})
}

func TestPhase5PreservesASubstitutedNonDirectoryDestination(t *testing.T) {
	// rmdir(2), NOT a general remove. A general remove unlinks a NON-directory too, so a symlink
	// planted at the destination after the precheck would be silently deleted and the staged tree
	// committed in its place — quietly redefining where the operator's destination points.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "payload"), []byte("ours"), 0o644); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(stage)
	// Planted after the precheck: a symlink where the destination directory should be.
	target := filepath.Join(f.base, "somewhere-else")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, canon); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 5, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 5)
	mustContain(t, err, "no longer the empty or absent directory")
	st, lerr := os.Lstat(canon)
	if lerr != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the planted symlink was removed; a substitution is preserved, not deleted")
	}
	if !exists(filepath.Join(stage, "payload")) {
		t.Fatal("the copy was moved despite the refusal")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("the symlink was followed and the copy landed at its target: %v", ents)
	}
}

// --- gate round 1: the temporal properties the state-machine tests claimed ------------------------

func TestThePhaseIsDurableBeforeItsActionRuns(t *testing.T) {
	// THE WRITE-AHEAD CONTRACT, OBSERVED FROM INSIDE THE ACTION. A test that inspects only the
	// finished ledger cannot tell record-before-action from action-before-record; these read the
	// PERSISTED ledger at the moment the phase's own side effect is happening, which is the only
	// copy a crash there would leave behind.
	f := newFx(t)
	var atStop, atCopy int
	var stageIDAtCopy string
	f.mut.onStop = func() { atStop = f.diskPhase() }
	f.cp.afterRun = func(string) {
		atCopy = f.diskPhase()
		r, err := find(f.onDisk(), testProduct, testRole)
		if err != nil {
			t.Fatal(err)
		}
		stageIDAtCopy = r.StageID
	}
	var confAtRebuild string
	var diskAtRebuild, diskAtRemove int
	// OBSERVED AT THE FIRST DESTRUCTIVE ACT, not merely somewhere inside phase 7. The container
	// removal is irreversible and comes BEFORE the rebuild, so a marker persisted between the two
	// would satisfy an observation taken at the rebuild while leaving a crash after the removal
	// with no write-ahead phase at all.
	prevOnRemove := f.mut.onRemove
	f.mut.onRemove = func() {
		diskAtRemove = f.diskPhase()
		if prevOnRemove != nil {
			prevOnRemove()
		}
	}
	f.bld.hook = func() {
		diskAtRebuild = f.diskPhase()
		confAtRebuild, _ = f.confValue(f.confkey)
	}
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatal(err)
	}
	if atStop != 2 {
		t.Fatalf("while the container was being stopped, disk named phase %d, want 2", atStop)
	}
	if atCopy != 3 {
		t.Fatalf("while the copy was running, disk named phase %d, want 3", atCopy)
	}
	// The staging identity is recorded in the SAME write that creates the directory, never one
	// without the other — that is what makes phase 4 and phase 5 able to refuse an unattributable
	// tree at all.
	if stageIDAtCopy == "" {
		t.Fatal("the copy ran with no staging identity persisted alongside the staging path")
	}
	if diskAtRemove != 7 {
		t.Fatalf("while the old container was being REMOVED, disk named phase %d, want 7", diskAtRemove)
	}
	if diskAtRebuild != 7 {
		t.Fatalf("while the container was being replaced, disk named phase %d, want 7", diskAtRebuild)
	}
	if confAtRebuild != f.canonDest() {
		t.Fatalf("at replacement time mythical.conf held %q", confAtRebuild)
	}
}

func TestPhases6To9ResumeAtTheirRecordedPhase(t *testing.T) {
	// THE OTHER HALF OF "each of the nine phases resumes". When the destination VERIFIABLY carries
	// phase 5's result, phases 6-9 resume WHERE THEY ARE RECORDED — they do not fall back to 5. A
	// fixture with no recorded identity can only ever exercise the fallback, so it cannot show that
	// the recorded phase is ever honoured at all.
	for n := 6; n <= PhaseLast; n++ {
		t.Run(fmt.Sprintf("phase%d", n), func(t *testing.T) {
			f := newFx(t)
			canon := f.canonDest()
			if err := os.Mkdir(canon, 0o755); err != nil {
				t.Fatal(err)
			}
			sid, err := Identity(canon)
			if err != nil {
				t.Fatal(err)
			}
			attempt := "none"
			if n >= 7 {
				// Phases 7 on follow a completed compare-and-set, so the bind is already recorded.
				attempt = "started"
				if err := conf.FamilyAdd(f.lock, f.confkey, canon); err != nil {
					t.Fatal(err)
				}
			}
			if n >= 8 {
				// Phase 7 has already replaced the container, so it mounts the bind.
				f.objs.mounts[f.container] = []engine.MountRecord{
					{Type: "bind", Source: canon, Destination: testMount, RW: true},
				}
			}
			f.seed(record{Phase: n, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
				StageID: sid, Attempt: attempt, Desired: "running"})
			if err := Resume(ctx(), f.l, f.d); err != nil {
				t.Fatalf("phase %d did not resume: %v", n, err)
			}
			if !strings.Contains(f.log.String(), fmt.Sprintf("resuming %s/%s at phase %d.", testProduct, testRole, n)) {
				t.Fatalf("phase %d was not resumed AT its recorded phase:\n%s", n, f.log.String())
			}
			if strings.Contains(f.log.String(), "Re-deriving from observable state") {
				t.Fatalf("phase %d fell back to phase 5 despite a verifiable destination", n)
			}
			if _, err := Phase(f.l, testProduct, testRole); !errors.Is(err, ErrNoMigration) {
				t.Fatalf("phase %d resumed but did not complete: %v", n, err)
			}
		})
	}
}

func TestPhase4VerifiesARealStagedTreeOnResume(t *testing.T) {
	// The nine-phase resume fixtures reach phase 4 with no staging tree, which exercises only its
	// no-op path. This one resumes at phase 4 over a tree that IS there, so the verification, the
	// host access check and the identity re-checks actually run.
	f := newFx(t)
	canon := f.canonDest()
	stage := StagingPath(canon, "nz")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(stage)
	f.seed(record{Phase: 4, Dest: canon, Nonce: "nz", Staging: stage, StageID: sid,
		Attempt: "none", Desired: "running"})
	f.d.Entries.Set(3)
	f.cp.verifyErr = errors.New("the copy does not match the source")
	mustContain(t, Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4), "does not match the source")

	f.cp.verifyErr = nil
	f.cp.hostErr = errors.New("the staged tree is not readable by the operator")
	mustContain(t, Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4), "not readable by the operator")

	f.cp.hostErr = nil
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 4); err != nil {
		t.Fatalf("a well-formed phase 4 over a real staged tree was refused: %v", err)
	}
}

// --- gate round 2 ---------------------------------------------------------------------------------

func TestPhase9KeepsTheIntentWhenTheRestoreITSELFFails(t *testing.T) {
	// RESTORE FIRST, CLEAR SECOND — and the ordering only bites when the restore FAILS on a desired
	// value that is otherwise VALID. A refusal raised while merely validating the value proves
	// nothing about the order, because an implementation that validated, cleared, and only then
	// restored would refuse at exactly the same point. Here the desired state is `running` and the
	// commit itself fails, which is the case the ordering exists for: an intent cleared first,
	// followed by a failed restore, leaves nothing recording that the container should still reach
	// its prior state.
	f := newFx(t)
	canon := f.canonDest()
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	f.seed(record{Phase: 9, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		Attempt: "started", Desired: "running"})
	// An empty network id makes the owed alias check unrecordable, so state.Commit refuses — a
	// genuine restore failure over a well-formed desired state.
	f.bld.netID = ""
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 9)
	if err == nil {
		t.Fatal("a failed desired-state restore reported success")
	}
	if p, perr := Phase(f.l, testProduct, testRole); perr != nil || p != 9 {
		t.Fatalf("the intent is at %d (%v) after a failed restore, want 9 — it must outlive the failure", p, perr)
	}
	if f.diskPhase() != 9 {
		t.Fatalf("the persisted intent is at %d after a failed restore", f.diskPhase())
	}
	if len(f.bld.reconciled) != 0 {
		t.Fatal("the container was reconciled toward a state that was never restored")
	}
}

func TestPhase6RecordsTheAttemptBeforeJudgingIt(t *testing.T) {
	// THE WRITE-AHEAD RECORD LANDS FIRST, EVEN FOR A STATE THIS PHASE IS ABOUT TO REFUSE. The
	// reference rewrites the record with attempt=started and only then presents the STALE value to
	// the compare-and-set, so an unrecognised value is refused ONCE and the next attempt takes the
	// resumable recovery path. Judging first and returning early would leave the unrecognised value
	// in the ledger for ever — every retry reaching the same refusal, with no way forward.
	f := newFx(t)
	canon := f.canonDest()
	f.seedRaw(map[string]string{
		"phase": "6", "dest": canon, "nonce": "nz", "staging": StagingPath(canon, "nz"),
		"attempt": "", "desired": "running", "confkey": f.confkey, "srcvol": f.srcvol,
		"mount": testMount, "prior": "", "stageid": "",
	})
	mustContain(t, Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6), "is neither 'none' nor")

	// The record now describes a write IN PROGRESS, in memory and on disk.
	for _, l := range []*ledger.Ledger{f.l, f.onDisk()} {
		r, err := find(l, testProduct, testRole)
		if err != nil {
			t.Fatal(err)
		}
		if r.Phase != 6 || r.Attempt != "started" {
			t.Fatalf("after the refusal the record is phase=%d attempt=%q, want 6/started", r.Phase, r.Attempt)
		}
	}
	// So the retry proceeds down the recovery path instead of the same refusal.
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6); err != nil {
		t.Fatalf("the retry did not take the recovery path: %v", err)
	}
	if got, _ := f.confValue(f.confkey); got != canon {
		t.Fatalf("the retry did not write the bind: %q", got)
	}
}

func TestPhase7DefaultsAnAbsentAttemptToStarted(t *testing.T) {
	// PHASE 7 IS ONLY EVER REACHED THROUGH A COMPLETED PHASE 6, so a record that does not carry the
	// attempt field at all describes a migration whose write was already begun. Defaulting it to
	// "none" — the default every EARLIER phase uses — makes a later fall-back to phase 5 re-present
	// an already-written bind to the compare-and-set as a FRESH write, which then refuses against
	// the very value phase 6 put there: a migration wedged by its own recovery path.
	f := newFx(t)
	canon := f.canonDest()
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(canon)
	// A repaired record: phase 7, no attempt field, and the bind phase 6 already wrote.
	if err := conf.FamilyAdd(f.lock, f.confkey, canon); err != nil {
		t.Fatal(err)
	}
	f.seedRaw(map[string]string{
		"phase": "7", "dest": canon, "nonce": "nz", "staging": StagingPath(canon, "nz"),
		"desired": "running", "confkey": f.confkey, "srcvol": f.srcvol,
		"mount": testMount, "prior": "", "stageid": sid,
	})
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 7); err != nil {
		t.Fatal(err)
	}
	r, err := find(f.l, testProduct, testRole)
	if err != nil {
		t.Fatal(err)
	}
	if r.Attempt != "started" {
		t.Fatalf("phase 7 recorded attempt=%q, want started", r.Attempt)
	}
	// And the recovery path it enables actually works: re-running phase 6 over the already-written
	// bind advances rather than refusing.
	if err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 6); err != nil {
		t.Fatalf("re-running phase 6 over the bind phase 6 already wrote refused: %v", err)
	}
	if got, _ := f.confValue(f.confkey); got != canon {
		t.Fatalf("mythical.conf holds %q", got)
	}
}

// --- gate round 3 ---------------------------------------------------------------------------------

func TestATrailingSlashNamesTheSameDestination(t *testing.T) {
	// A TRAILING SLASH IS AN ORDINARY WAY TO WRITE A DIRECTORY PATH. `dirname`/`basename` strip it
	// before splitting, so the reference reads `/target/dir/` as parent `/target`, leaf `dir`. The
	// Go split does not: Dir answers `/target/dir` while Base still answers `dir`, and joining the
	// two lands one level BELOW the directory the operator named — a migration into the wrong place,
	// under a name that looks right.
	f := newFx(t)
	want := f.canonDest()
	for _, spelling := range []string{f.dest, f.dest + "/", f.dest + "//"} {
		got, err := canonDest(spelling)
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if got != want {
			t.Fatalf("--to-bind %q resolves to %q, want %q", spelling, got, want)
		}
		// The staging sibling is derived from the same split, so it must not move either.
		if s := StagingPath(spelling, "nz"); s != StagingPath(f.dest, "nz") {
			t.Fatalf("--to-bind %q derives staging %q, want %q", spelling, s, StagingPath(f.dest, "nz"))
		}
	}

	// End to end: the trailing-slash spelling migrates to the SAME directory and records it.
	f2 := newFx(t)
	if err := MigrateStorage(ctx(), f2.l, f2.d, testProduct, testRole, Options{ToBind: f2.dest + "/"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f2.confValue(f2.confkey); got != f2.canonDest() {
		t.Fatalf("mythical.conf holds %q, want %q", got, f2.canonDest())
	}
	if !exists(f2.canonDest()) {
		t.Fatal("nothing landed at the destination the operator named")
	}
	if exists(filepath.Join(f2.canonDest(), filepath.Base(f2.dest))) {
		t.Fatal("the migration landed one level below the destination the operator named")
	}
}

func TestPhase7PreparesTheReplacementBeforeRemovingTheOldOne(t *testing.T) {
	// THE REMOVAL CANNOT BE UNDONE, so every fallible step of working out WHAT to build runs while
	// the old container is still there. A launch spec that could not be resolved — a missing image,
	// a secret that will not render — must fail with the old container standing and the migration
	// resumable, not after the product has been left with no container at all.
	f := newFx(t)
	canon := f.canonDest()
	if err := os.Mkdir(canon, 0o755); err != nil {
		t.Fatal(err)
	}
	sid, _ := Identity(canon)
	f.seed(record{Phase: 7, Dest: canon, Nonce: "nz", Staging: StagingPath(canon, "nz"),
		StageID: sid, Attempt: "started", Desired: "running"})
	f.bld.prepareErr = errors.New("the product's secrets could not be rendered")
	err := Run(ctx(), f.l, f.d, testProduct, testRole, canon, 7)
	mustContain(t, err, "could not be prepared", "nothing was", "removed")
	if len(f.mut.removed) != 0 {
		t.Fatalf("the old container was removed before the replacement could be prepared: %v", f.mut.removed)
	}
	if _, ferr := prov.Find(f.l, prov.ClassContainer, f.container); ferr != nil {
		t.Fatalf("the old container's record was consumed despite the preparation failing: %v", ferr)
	}
	if p, perr := Phase(f.l, testProduct, testRole); perr != nil || p != 7 {
		t.Fatalf("the intent is at %d (%v), want 7 — the migration must stay resumable", p, perr)
	}

	// PREPARE PRECEDES THE REMOVAL on the ordinary path too, and whatever it rendered is released
	// on every path out, built or abandoned.
	f2 := newFx(t)
	var removedAtPrepare int
	f2.bld.hook = func() { removedAtPrepare = len(f2.mut.removed) }
	if err := MigrateStorage(ctx(), f2.l, f2.d, testProduct, testRole, Options{ToBind: f2.dest}); err != nil {
		t.Fatal(err)
	}
	if len(f2.bld.prepared) != 1 || len(f2.bld.rebuilt) != 1 {
		t.Fatalf("prepared=%v rebuilt=%v", f2.bld.prepared, f2.bld.rebuilt)
	}
	if removedAtPrepare != 1 {
		t.Fatalf("the replacement was created with %d containers removed, want 1", removedAtPrepare)
	}
	if f2.bld.discarded != 1 {
		t.Fatalf("the prepared replacement was discarded %d times, want 1", f2.bld.discarded)
	}

	// ON EVERY PATH OUT means every one — not just success and a failed create. After Prepare has
	// rendered something (a secrets env file, say), each early return below it must release it too,
	// or the phase leaks it. The reference removes its rendered file before every one of those
	// returns as well as after bring-up.
	for _, tc := range []struct {
		name  string
		arm   func(*fx)
		wants string
	}{
		{"the removal fails", func(x *fx) { x.mut.rmErr = errors.New("the daemon refused") },
			"could not remove the old container"},
		{"the container is not ours", func(x *fx) {
			x.prv.put(prov.ClassContainer, x.container, "another-installation", "n-con")
		}, "refusing to replace"},
		{"the create fails", func(x *fx) { x.bld.rebuildErr = errors.New("the daemon refused the create") },
			""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newFx(t)
			cd := x.canonDest()
			if err := os.Mkdir(cd, 0o755); err != nil {
				t.Fatal(err)
			}
			id, _ := Identity(cd)
			x.seed(record{Phase: 7, Dest: cd, Nonce: "nz", Staging: StagingPath(cd, "nz"),
				StageID: id, Attempt: "started", Desired: "running"})
			tc.arm(x)
			err := Run(ctx(), x.l, x.d, testProduct, testRole, cd, 7)
			if err == nil {
				t.Fatal("the armed failure reported success")
			}
			if tc.wants != "" {
				mustContain(t, err, tc.wants)
			}
			if len(x.bld.prepared) != 1 {
				t.Fatalf("the replacement was prepared %d times, want 1", len(x.bld.prepared))
			}
			if x.bld.discarded != 1 {
				t.Fatalf("what Prepare rendered was discarded %d times, want 1 — this path leaks it",
					x.bld.discarded)
			}
		})
	}
}

func TestPrecheckRefusesAPartialMountInspection(t *testing.T) {
	// POSITIVE INSPECTION MEANS THE INSPECTION SUCCEEDED. An inspection that FAILED carries no
	// evidence, whatever rows it also returned — and half an answer that happens to contain the
	// source volume is not an observation that the container mounts it. The reference discards the
	// output on failure for exactly this reason; keeping the rows and dropping the error is how a
	// failed question turns into a positive answer, and this gate stands between an operator and a
	// destructive migration.
	f := newFx(t)
	// The rows DO name the source volume — the check would pass on them alone.
	f.objs.err = errors.New("the container runtime did not finish answering")
	err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest)
	mustContain(t, err, "does not mount", f.srcvol)

	// And with the inspection succeeding over the same rows, it passes.
	f.objs.err = nil
	if err := Precheck(ctx(), f.l, f.d, testProduct, testRole, f.dest); err != nil {
		t.Fatalf("a successful inspection naming the source volume was refused: %v", err)
	}
}

func TestPhase9PreservesAStoppedContainersOutstandingCheck(t *testing.T) {
	// A COMMIT PRESERVES THE OUTSTANDING SET; IT VERIFIES NOTHING. The reference restores a
	// desired-stopped container with no checks AND no declaration that none are owed — declaring
	// "nothing is owed" beside a check that IS owed is a contradiction the state module refuses,
	// and that refusal would wedge phase 9 for exactly the products most likely to be migrated: a
	// stopped one whose deferred alias check is still waiting for it to come back up.
	f := newFx(t)
	if err := state.Commit(f.l, f.container, state.Stopped,
		[]state.Check{{Kind: state.CheckAlias, Param: "netid-family"}}, false); err != nil {
		t.Fatal(err)
	}
	f.stt.running[f.container] = false
	if err := MigrateStorage(ctx(), f.l, f.d, testProduct, testRole, Options{ToBind: f.dest}); err != nil {
		t.Fatalf("a stopped product with an outstanding check could not finish its migration: %v", err)
	}
	want, err := state.DesiredGet(f.l, f.container)
	if err != nil || want != state.Stopped {
		t.Fatalf("desired state %q (%v), want stopped", want, err)
	}
	// The check SURVIVES: nothing here verified it, so nothing here may retire it.
	out, oerr := state.Outstanding(f.l, f.container)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if len(out) != 1 || out[0].Kind != state.CheckAlias {
		t.Fatalf("the outstanding set is %v — a migration must not retire a check it did not perform", out)
	}
	if _, perr := Phase(f.l, testProduct, testRole); !errors.Is(perr, ErrNoMigration) {
		t.Fatalf("the intent survived a completed migration: %v", perr)
	}
}
