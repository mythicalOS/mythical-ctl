package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — tests/unit/backup.bats, the restore half.
//
// PORTED: tests/unit/backup.bats: "restore REFUSES when an active ledger is present, naming it" -> TestRestoreRefusesAnActiveLedger
// PORTED: tests/unit/backup.bats: "with no active AND no staging ledger, mi_restore_state answers none" -> TestCurrentStateClassifies
// PORTED: tests/unit/backup.bats: "ordinary commands finding staging-without-active do NOT read the machine as first use" -> TestStagingWithoutActiveIsNotFirstUse
// PORTED: tests/unit/backup.bats: "restore writes a STAGING ledger with the intent inside it, before anything is created" -> TestPhase1StagesTheIncomingLedgerWithItsIntent
// PORTED: tests/unit/backup.bats: "a CORRUPT staging ledger authorizes no cleanup: preserved aside, volumes named as blocking" -> TestCorruptStagingLedgerAuthorizesNoCleanup
// PORTED: tests/unit/backup.bats: "phase 2 creates each volume WITH the recorded nonce, then RE-INSPECTS for label AND emptiness" -> TestPhase2CreatesWithTheRecordedNonceAndReInspects
// PORTED: tests/unit/backup.bats: "a same-name SURVIVOR fails the re-inspection and the restore refuses, naming it" -> TestSameNameSurvivorIsRefused
// PORTED: tests/unit/backup.bats: "phase 4 verifies against the backup's per-entry manifest" -> TestPhase4VerifiesAgainstThePerEntryManifest
// PORTED: tests/unit/backup.bats: "a restore that re-created a symlink as a FILE fails verification" -> TestVerificationCatchesASymlinkRecreatedAsAFile
// PORTED: tests/unit/backup.bats: "a restore that FLATTENED a hardlink group fails verification" -> TestVerificationCatchesAFlattenedHardlinkGroup
// PORTED: tests/unit/backup.bats: "a restore that DROPPED modes fails verification" -> TestVerificationCatchesDroppedModes
// PORTED: tests/unit/backup.bats: "a verification that never states a checked count is refused, not read as a vacuous pass" -> TestVerificationWithNoCheckedCountIsRefused
// PORTED: tests/unit/backup.bats: "a verification that UNDERSTATES its checked count against the manifest is refused" -> TestVerificationUnderstatingItsCountIsRefused
// PORTED: tests/unit/backup.bats: "phase 5 rewrites the staging ledger to its intent-free form, atomically" -> TestPhase5LeavesTheLedgerIntentFree
// PORTED: tests/unit/backup.bats: "phase 6 activates by atomic rename, and only then does anything claim the volumes" -> TestPhase6ActivatesByRename
// PORTED: tests/unit/backup.bats: "a crash between 5 and 6 leaves staging-without-intent, and the next run ACTIVATES" -> TestCrashBetweenPhase5And6Activates
// PORTED: tests/unit/backup.bats: "a crash during FILLING leaves labelled partial volumes and NO active ledger" -> TestCrashDuringFillingLeavesNoActiveLedger
// PORTED: tests/unit/backup.bats: "a full round trip ends with every identity check passing" -> TestFullRoundTripPassesEveryIdentityCheck
// PORTED: tests/unit/backup.bats: "abandonment removes volumes matching exact name+nonce BEFORE deleting the staging file" -> TestAbandonRemovesMatchingVolumesBeforeTheStagingFile
// PORTED: tests/unit/backup.bats: "abandonment PRESERVES a volume whose nonce does not match, and reports it" -> TestAbandonPreservesANonMatchingVolume
// PORTED: tests/unit/backup.bats: "abandon without confirmation is refused, and the staging ledger survives" -> TestAbandonWithoutConfirmationIsRefused
// PORTED: tests/unit/backup.bats: "abandon on a machine with no restore in progress is refused" -> TestAbandonWithNoRestoreInProgress
// PORTED: tests/unit/backup.bats: "abandon on a machine with an ACTIVE ledger (no restore) is refused, distinctly" -> TestAbandonWithAnActiveLedgerIsRefusedDistinctly
// PORTED: tests/unit/backup.bats: "abandon on a CORRUPT staging ledger authorizes no cleanup either" -> TestAbandonOnACorruptStagingLedger
// PORTED: tests/unit/backup.bats: "fix6: restore also fails closed on a volume record missing name/nonce in the staged ledger" -> TestRestoreFailsClosedOnAStagedVolumeRecordWithNoNonce
//
// N/A: tests/unit/backup.bats: "mi_restore_run rejects the wrong number of arguments" -- an arity guard on a shell function has no Go analogue: Restore takes exactly (ctx, Deps, string) and the compiler refuses anything else. The load-bearing half — a malformed INVOCATION is a usage error with nothing attempted — is the CLI's, claimed in cmd/mythical-ctl/backup_test.go by TestRestoreOperandMatrix.
//
// Deferred rows owned HERE — tests/acceptance/restore.bats. These exercise the same library
// functions the verb layer wraps; the wrapper's own contract (preflight, layout, the family
// lock, the exit-code mapping and the option matrix) is claimed in cmd/mythical-ctl.
//
// PORTED: tests/acceptance/restore.bats: "backup then restore: a full round trip through mi_verb_backup/mi_verb_restore" -> TestFullRoundTripPassesEveryIdentityCheck
// PORTED: tests/acceptance/restore.bats: "restore through the verb refuses while the current installation is still active" -> TestRestoreRefusesAnActiveLedger
// PORTED: tests/acceptance/restore.bats: "a crash during fill resumes cleanly on the next mi_verb_restore call" -> TestCrashDuringFillResumesCleanly
// PORTED: tests/acceptance/restore.bats: "a same-name survivor volume is refused end to end, and abandonment PRESERVES it" -> TestSurvivorRefusedEndToEndThenAbandonPreservesIt
// PORTED: tests/acceptance/restore.bats: "restore --abandon through the CLI removes the partial volumes with confirmation" -> TestAbandonRefusedThenConfirmedRemovesThePartials
// PORTED: tests/acceptance/restore.bats: "a corrupt staging ledger is preserved aside and blocks both restore and abandon, through the verb" -> TestCorruptStagingBlocksBothRestoreAndAbandon
// PORTED: tests/acceptance/restore.bats: "fix2: restore refuses an existing backup root that is group/other-writable, checksums notwithstanding" -> TestRestoreRefusesAnUnsafeExistingBackupRoot
// PORTED: tests/acceptance/restore.bats: "fix3: a SAFE-looking symlink pointing at an UNSAFE target is refused, not trusted by alias" -> TestSafeLookingSymlinkToAnUnsafeTargetIsRefused
// PORTED: tests/acceptance/restore.bats: "fix3: a symlink to a SAFE backup directory is followed and restore succeeds through it" -> TestSymlinkToASafeBackupIsFollowed
// PORTED: tests/acceptance/restore.bats: "fix4: MI_CONFIRM=no refuses restore before creating or filling anything" -> TestUnconfirmedRestoreCreatesAndFillsNothing
// PORTED: tests/acceptance/restore.bats: "fix4: MI_CONFIRM=no also refuses a bare activate (staging-no-intent)" -> TestUnconfirmedBareActivateIsRefused

func TestRestoreRefusesAnActiveLedger(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("restore proceeded over a live installation")
	}
	mustContain(t, r.stderr(), "active installer state ledger is present", "the refusal")
	mustContain(t, r.stderr(), livePath(r.home), "the refusal names the ledger")
	// The live installation is untouched, and the refusal happened before the confirmation gate
	// — a pure refusal never asks.
	if len(r.prompts) != 0 {
		t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
	}
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := l.IdentGet(); got != r.ident {
		t.Fatalf("the live installation's identity changed: %q", got)
	}
}

func TestCurrentStateClassifies(t *testing.T) {
	r := newRig(t)
	if s, err := CurrentState(r.deps()); err != nil || s != StateActive {
		t.Fatalf("with a ledger installed: %q %v", s, err)
	}
	r.dropLedger()
	if s, err := CurrentState(r.deps()); err != nil || s != StateNone {
		t.Fatalf("with neither ledger: %q %v", s, err)
	}
}

func TestStagingWithoutActiveIsNotFirstUse(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// Interrupt right after phase 1 and the volume creates, so an ACTIVE ledger never appears.
	r.cop.fillErr = errors.New("interrupted")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("the interrupted fill was not reported")
	}
	if s, err := CurrentState(r.deps()); err != nil || s != StateWithIntent {
		t.Fatalf("after an interrupted fill: %q %v", s, err)
	}
	// prov.FirstUse must NOT read this machine as a fresh install: nil is "genuinely first
	// use", which is the one answer that would let an ordinary command initialise over an
	// in-progress restore.
	err := prov.FirstUse(context.Background(), r.home, r.objs)
	if err == nil {
		t.Fatal("a machine with an in-progress restore was read as genuinely first use")
	}
	if errors.Is(err, prov.ErrNotFirstUse) {
		t.Fatalf("classified as 'a ledger exists' rather than as an in-progress restore: %v", err)
	}
	mustContain(t, err.Error(), "restore is in progress", "the classification")
}

func TestPhase1StagesTheIncomingLedgerWithItsIntent(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	r.dropLedger()
	r.cop.fillErr = errors.New("interrupted")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("the interrupted fill was not reported")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("phase 1 did not write the staging ledger")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("something was activated before every volume verified")
	}
	if s, _ := CurrentState(r.deps()); s != StateWithIntent {
		t.Fatalf("state after phase 1: %q", s)
	}
	// The intent is INSIDE the staged ledger, and it names the directory phase 1 committed to
	// — a resume reads its source from there and never re-trusts the operand.
	staging, err := ledger.OpenStaging(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(staging)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := l.Find(restoreKind, "key", "restore")
	if err != nil {
		t.Fatalf("the staged ledger carries no restore intent: %v", err)
	}
	if src, _ := ledger.FieldOf(fields, "source"); src != dir {
		t.Fatalf("the intent names %q, not the verified backup root %q", src, dir)
	}
}

func TestCorruptStagingLedgerAuthorizesNoCleanup(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	write(t, stagingPath(r.home), []byte("not a ledger at all\n"))
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a corrupt staging ledger authorized a restore")
	}
	out := r.stderr()
	mustContain(t, out, "does not validate", "the refusal")
	mustContain(t, out, "PRESERVED", "the refusal")
	// A PURE REFUSAL: nothing is touched, so it returns BEFORE the confirmation gate rather
	// than through it. Asking an operator to confirm a restore that cannot happen is how a
	// refusal turns into a prompt they learn to answer yes to.
	if len(r.prompts) != 0 {
		t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
	}
	if !r.hasCorruptAside() {
		t.Fatal("the corrupt staging ledger was not preserved aside")
	}
	if regularFile(stagingPath(r.home)) {
		t.Fatal("the corrupt staging ledger is still sitting at the well-known name")
	}
	// The volumes that may belong to the abandoned attempt are NAMED, never removed.
	for _, v := range r.vols {
		mustContain(t, out, v.name, "the blocking-volume report")
		if _, err := r.nonceOf(v.name); err != nil {
			t.Fatalf("%s was removed on the authority of a file whose checksum failed: %v", v.name, err)
		}
	}
}

func (r *rig) hasCorruptAside() bool {
	matches, err := filepath.Glob(stagingPath(r.home) + ".corrupt.*")
	return err == nil && len(matches) > 0
}

func TestPhase2CreatesWithTheRecordedNonceAndReInspects(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	r.dropLedger()
	// Remove the volumes first, so the create in phase 2 is the thing that applies the label —
	// otherwise this test would pass on the label the install left behind.
	for _, v := range r.vols {
		r.removeVolume(v.name)
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	for _, v := range r.vols {
		recorded, err := os.ReadFile(filepath.Join(dir, "volumes", v.name+".nonce"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.nonceOf(v.name)
		if err != nil {
			t.Fatal(err)
		}
		if got != strings.TrimSuffix(string(recorded), "\n") {
			t.Fatalf("%s carries %q, not the recorded %q", v.name, got, recorded)
		}
	}
}

func TestSameNameSurvivorIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// A volume already sits at this name with a DIFFERENT nonce. `volume create` against an
	// existing name succeeds WITHOUT applying the new label (D56), so this is exactly the
	// survivor case. The volume install created (with the CORRECT nonce) must be removed
	// first: create-over-existing does not relabel, so poisoning it without removing it would
	// be a no-op and this test would pass for the wrong reason.
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "not-our-nonce", "some-other-identity")

	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a same-name survivor was filled")
	}
	out := r.stderr()
	mustContain(t, out, "SURVIVOR", "the refusal")
	mustContain(t, out, victim, "the refusal names the volume")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume this restore could not prove it created was filled")
	}
	if got, _ := r.nonceOf(victim); got != "not-our-nonce" {
		t.Fatalf("the survivor was relabelled: %q", got)
	}
}

func TestPhase4VerifiesAgainstThePerEntryManifest(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	mustContain(t, r.stdout(), "verified against the backup's per-entry manifest", "the progress record")
	for _, v := range r.vols {
		if r.cop.verified[v.name] == 0 {
			t.Fatalf("%s was never verified", v.name)
		}
	}
}

// mismatchRig is the shared shape of the three contract-loss tests: a verifier that reports one
// named mismatch, which the restore must treat as a failure and never activate over.
func mismatchRig(t *testing.T, what string) *rig {
	t.Helper()
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.verify = func(vol string, man []byte) (Transcript, error) {
		return Transcript{Code: 1, Text: "mismatch=" + what + "\nchecked=4\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a restore that lost the manifest's contract reported success")
	}
	mustContain(t, r.stderr(), "VERIFICATION MISMATCH", "the refusal")
	mustContain(t, r.stderr(), what, "the refusal names the entry")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a failed verification")
	}
	return r
}

func TestVerificationCatchesASymlinkRecreatedAsAFile(t *testing.T) {
	r := mismatchRig(t, "/src/l: type symlink recorded, file found")
	mustContain(t, r.stderr(), "no bytes to mismatch", "the explanation")
}

func TestVerificationCatchesAFlattenedHardlinkGroup(t *testing.T) {
	r := mismatchRig(t, "/src/h: hardlink group flattened")
	mustContain(t, r.stderr(), "flattened hardlinks digest identically", "the explanation")
}

func TestVerificationCatchesDroppedModes(t *testing.T) {
	mismatchRig(t, "/src/a: mode 0644 recorded, 0600 found")
}

func TestVerificationWithNoCheckedCountIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// The helper exits 0 and states its completion but never says how many entries it checked.
	// An exit status is not a result: unmeasured is not measured-clean.
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "done=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a verification that measured nothing was read as a pass")
	}
	mustContain(t, r.stderr(), "stated nothing", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a vacuous verification")
	}
}

func TestVerificationUnderstatingItsCountIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "checked=1\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a verification that checked fewer entries than the manifest names was accepted")
	}
	mustContain(t, r.stderr(), "the manifest names", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a partial verification")
	}
}

func TestPhase5LeavesTheLedgerIntentFree(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	if !regularFile(livePath(r.home)) {
		t.Fatal("nothing was activated")
	}
	// THE ACTIVATED LEDGER CARRIES NO INTENT. Renaming the staging ledger unchanged would
	// activate one that still says a restore is in progress, and every later command would
	// meet a live intent on a finished restore. Re-staging the activated file is the direct
	// way to ask that question of the bytes that were actually renamed into place.
	l, err := ledger.Read(mustLive(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := l.Find(restoreKind, "key", "restore"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatalf("the activated ledger still carries a restore intent: %v", ferr)
	}
}

// inodeOf identifies a file rather than describing it: a rename preserves it, a copy does not.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("this platform does not expose an inode; the rename property cannot be measured here")
	}
	return uint64(st.Ino)
}

func mustLive(t *testing.T, r *rig) ledger.Store {
	t.Helper()
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPhase6ActivatesByRename(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived activation")
	}
	if !regularFile(livePath(r.home)) {
		t.Fatal("the ledger was not activated")
	}
	mustContain(t, r.stdout(), "activated", "the progress record")
	l, err := ledger.Read(mustLive(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := l.IdentGet(); got != r.ident {
		t.Fatalf("the activated ledger's identity is %q, not the backup's %q", got, r.ident)
	}

	// ACTIVATION IS ONE RENAME, and "staging gone, live present" does not say that: a copy
	// followed by a delete satisfies both, while exposing a PARTIALLY WRITTEN authoritative
	// ledger for as long as the copy takes — the exact hazard phase 6 exists to prevent. The
	// property that separates them is IDENTITY: a rename moves the same file, so the inode
	// survives; a copy makes a new one.
	//
	// Asked of phase 6 in isolation, because phase 5 writes the staging ledger through its own
	// temp-and-rename first, so a file identified before the whole restore is not the one
	// phase 6 moves.
	if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	stagedIno := inodeOf(t, stagingPath(r.home))
	r.reset()
	if err := Activate(r.deps()); err != nil {
		t.Fatalf("Activate: %v\n%s", err, r.stderr())
	}
	if got := inodeOf(t, livePath(r.home)); got != stagedIno {
		t.Fatalf("the live ledger is a DIFFERENT file (inode %d) from the staged one (%d) — it was "+
			"copied into place, not renamed, so a crash mid-write would leave a torn authoritative ledger",
			got, stagedIno)
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived activation")
	}
}

func TestCrashBetweenPhase5And6Activates(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	// Simulate the crash directly: re-stage the completed (intent-free) ledger and confirm the
	// next call ACTIVATES rather than re-running the volume phases.
	if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if s, _ := CurrentState(r.deps()); s != StateNoIntent {
		t.Fatalf("state between phase 5 and 6: %q", s)
	}
	fillsBefore := len(r.cop.fills)
	r.reset()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("the ready-to-activate restore was not activated: %v\n%s", err, r.stderr())
	}
	if !regularFile(livePath(r.home)) || exists(stagingPath(r.home)) {
		t.Fatal("activation did not happen")
	}
	if len(r.cop.fills) != fillsBefore {
		t.Fatal("the volume phases ran again on a restore that had already completed them")
	}
}

func TestCrashDuringFillingLeavesNoActiveLedger(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	r.dropLedger()
	// The volumes are removed first so phase 2's create is what labels them — that is the
	// state this test asserts survives the crash.
	for _, v := range r.vols {
		r.removeVolume(v.name)
	}
	r.cop.fillErr = errors.New("the copy container died mid-run")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("an interrupted fill reported success")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("a restore that never finished filling activated a ledger")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was lost, so nothing records which partial volumes exist")
	}
	recorded, err := os.ReadFile(filepath.Join(dir, "volumes", r.vols[0].name+".nonce"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.nonceOf(r.vols[0].name)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSuffix(string(recorded), "\n") {
		t.Fatalf("the partial volume is not labelled: %q", got)
	}
}

func TestFullRoundTripPassesEveryIdentityCheck(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	l, err := ledger.Read(mustLive(t, r))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range r.vols {
		if err := prov.Authority(context.Background(), l, r.objs, prov.ClassVolume, v.name); err != nil {
			t.Fatalf("%s does not pass its identity check after a restore: %v", v.name, err)
		}
	}
	if got, _ := l.IdentGet(); got != r.ident {
		t.Fatalf("identity after the round trip: %q", got)
	}
}

// --- abandonment --------------------------------------------------------------------------------

// interrupted leaves the rig in the state abandonment is for: a staged restore whose fill died.
func interrupted(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.fillErr = errors.New("interrupted")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("the interrupted fill was not reported")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("no staging ledger to abandon")
	}
	r.reset()
	return r
}

func TestAbandonRemovesMatchingVolumesBeforeTheStagingFile(t *testing.T) {
	r := interrupted(t)
	if err := Abandon(context.Background(), r.deps()); err != nil {
		t.Fatalf("Abandon: %v\n%s", err, r.stderr())
	}
	for _, v := range r.vols {
		if _, err := r.nonceOf(v.name); !errors.Is(err, engine.ErrAbsent) {
			t.Fatalf("%s survived abandonment: %v", v.name, err)
		}
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived abandonment")
	}
}

func TestAbandonPreservesANonMatchingVolume(t *testing.T) {
	r := interrupted(t)
	// Simulate someone else's object landing at the same name in between: overwrite the
	// volume's own label with a nonce this staging ledger did not record.
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "somebody-elses-nonce", "somebody-elses-identity")
	if err := Abandon(context.Background(), r.deps()); err != nil {
		t.Fatalf("Abandon: %v\n%s", err, r.stderr())
	}
	mustContain(t, r.stderr(), "PRESERVED", "the report")
	mustContain(t, r.stderr(), victim, "the report names the volume")
	if got, _ := r.nonceOf(victim); got != "somebody-elses-nonce" {
		t.Fatalf("a volume this restore never created was touched: %q", got)
	}
}

func TestAbandonWithoutConfirmationIsRefused(t *testing.T) {
	r := interrupted(t)
	r.confirm = false
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded without confirmation")
	}
	mustContain(t, r.stderr(), "not confirmed", "the refusal")
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was removed without confirmation")
	}
	for _, v := range r.vols {
		if _, err := r.nonceOf(v.name); err != nil {
			t.Fatalf("%s was removed without confirmation: %v", v.name, err)
		}
	}
}

func TestAbandonWithNoRestoreInProgress(t *testing.T) {
	r := newRig(t)
	r.dropLedger()
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded with nothing to abandon")
	}
	mustContain(t, r.stderr(), "no in-progress restore", "the refusal")
	if len(r.prompts) != 0 {
		t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
	}
}

func TestAbandonWithAnActiveLedgerIsRefusedDistinctly(t *testing.T) {
	r := newRig(t)
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded on a live installation")
	}
	// DISTINCTLY: "there is no restore in progress" is a different fact from "there is nothing
	// to abandon", and an operator on a live machine must not be told the machine is empty.
	mustContain(t, r.stderr(), "there is no restore in progress", "the refusal")
	mustNotContain(t, r.stderr(), "no in-progress restore to abandon", "the refusal")
	if len(r.prompts) != 0 {
		t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
	}
	if !regularFile(livePath(r.home)) {
		t.Fatal("the live ledger was touched")
	}
}

func TestAbandonOnACorruptStagingLedger(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	write(t, stagingPath(r.home), []byte("not a ledger\n"))
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("a corrupt staging ledger authorized cleanup")
	}
	mustContain(t, r.stderr(), "does not validate", "the refusal")
	if !r.hasCorruptAside() {
		t.Fatal("the corrupt staging ledger was not preserved aside")
	}
	if len(r.prompts) != 0 {
		t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
	}
	for _, v := range r.vols {
		if _, err := r.nonceOf(v.name); err != nil {
			t.Fatalf("%s was removed on the authority of a file whose checksum failed: %v", v.name, err)
		}
	}
}

func TestRestoreFailsClosedOnAStagedVolumeRecordWithNoNonce(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	r.dropLedger()
	// Damage the BACKUP's own ledger with a semantically incomplete volume record: class=volume
	// and a name, but NO nonce. This proves restore's own loop fails closed independently of
	// the backup's (already-tested) refusal — the realistic source of such a ledger is a backup
	// this installer did not write, or one damaged after the fact.
	appendLedgerRow(t, filepath.Join(dir, "ledger"), "object\tkey=volume:ghost3\tclass=volume\tname=ghost3")

	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a semantically incomplete volume record in the staged ledger was skipped")
	}
	mustContain(t, r.stderr(), "carries no nonce", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("a ledger this restore could not fully act on was activated")
	}
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled on a partial view of which volumes this restore owns")
	}
}

// appendLedgerRow rewrites a ledger FILE with one extra record row and a recomputed checksum —
// the shape a backup written elsewhere, or damaged after the fact, would have.
func appendLedgerRow(t *testing.T, path, row string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "#sha256=") {
		t.Fatalf("%s does not end in a checksum line", path)
	}
	body := strings.Join(append(lines[:len(lines)-1], row), "\n") + "\n"
	out := body + "#sha256=" + cliio.SHA256Hex([]byte(body)) + "\n"
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- the verb-layer rows (tests/acceptance/restore.bats) -----------------------------------------

func TestCrashDuringFillResumesCleanly(t *testing.T) {
	r := interrupted(t)
	r.cop.fillErr = nil
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("the resume did not complete: %v\n%s", err, r.stderr())
	}
	if !regularFile(livePath(r.home)) || exists(stagingPath(r.home)) {
		t.Fatal("the resume did not activate")
	}
	l, err := ledger.Read(mustLive(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := l.IdentGet(); got != r.ident {
		t.Fatalf("identity after the resume: %q", got)
	}
	// A RESUME IS STATE-VERIFYING, NOT PHASE-TRUSTING: it re-ran the phases rather than
	// trusting a marker.
	if len(r.cop.fills) < 2 {
		t.Fatalf("the resume trusted a phase marker instead of re-running the fill: %d fills", len(r.cop.fills))
	}
}

// TestResumeRefusesAVolumeHoldingPartialContents is the branch between the two resume outcomes:
// a volume that carries OUR nonce and is NOT empty and does NOT verify is holding partial
// contents from an interrupted fill. Filling over them blindly is the one thing a resume must
// never do, and there is no safe way to tell that apart from a real survivor.
func TestResumeRefusesAVolumeHoldingPartialContents(t *testing.T) {
	r := interrupted(t)
	victim := r.vols[0].name
	r.cop.fillErr = nil
	// Non-empty, and it does not verify: the fill got partway.
	r.cop.count = func(vol string) (Transcript, error) {
		if vol == victim {
			return Transcript{Text: "checked=2\n"}, nil
		}
		return Transcript{Text: "checked=0\n"}, nil
	}
	r.cop.verify = func(vol string, man []byte) (Transcript, error) {
		if vol == victim {
			return Transcript{Code: 1, Text: "mismatch=/src/a: absent\nchecked=4\ndone=ok\n"}, nil
		}
		return Transcript{Text: "checked=4\ndone=ok\n"}, nil
	}
	fillsBefore := len(r.cop.fills)
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a resume filled over partial contents")
	}
	mustContain(t, r.stderr(), "NOT EMPTY", "the refusal")
	mustContain(t, r.stderr(), "restore --abandon", "the refusal names the recovery path")
	if len(r.cop.fills) != fillsBefore {
		t.Fatal("the partial volume was filled over")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a volume holding partial contents")
	}
}

// TestEmptinessThatCannotBeEstablishedRefuses: "assume empty" fills over survivors and "assume
// non-empty" wedges a fresh restore, so a count that cannot be obtained refuses instead.
func TestEmptinessThatCannotBeEstablishedRefuses(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.count = func(string) (Transcript, error) {
		return Transcript{}, errors.New("the container runtime did not answer")
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a restore proceeded without establishing whether the volume was empty")
	}
	mustContain(t, r.stderr(), "cannot determine whether volume", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled without establishing that it was empty")
	}
}

func TestSurvivorRefusedEndToEndThenAbandonPreservesIt(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "an-unrelated-nonce", "an-unrelated-identity")

	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a same-name survivor was restored over")
	}
	mustContain(t, r.stderr(), "SURVIVOR", "the refusal")
	// The staging ledger is written (phase 1) before the per-volume survivor check (phase 2)
	// ever runs, so an in-progress restore genuinely exists here — abandonment is the recovery
	// path, never a blind retry with the same directory.
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("phase 1 left no staging ledger to abandon")
	}
	r.reset()
	if err := Abandon(context.Background(), r.deps()); err != nil {
		t.Fatalf("Abandon: %v\n%s", err, r.stderr())
	}
	mustContain(t, r.stderr(), "PRESERVED", "the report")
	mustContain(t, r.stderr(), victim, "the report names the volume")
	// A same-name survivor is never abandoned or removed automatically: abandon only touches
	// volumes THIS attempt itself created (matching its recorded nonce).
	if got, _ := r.nonceOf(victim); got != "an-unrelated-nonce" {
		t.Fatalf("the survivor was touched: %q", got)
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived abandonment")
	}
}

func TestAbandonRefusedThenConfirmedRemovesThePartials(t *testing.T) {
	r := interrupted(t)
	r.confirm = false
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded unconfirmed")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was touched without confirmation")
	}
	r.confirm = true
	r.reset()
	if err := Abandon(context.Background(), r.deps()); err != nil {
		t.Fatalf("Abandon: %v\n%s", err, r.stderr())
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived a confirmed abandonment")
	}
	for _, v := range r.vols {
		if _, err := r.nonceOf(v.name); !errors.Is(err, engine.ErrAbsent) {
			t.Fatalf("%s survived a confirmed abandonment: %v", v.name, err)
		}
	}
}

func TestCorruptStagingBlocksBothRestoreAndAbandon(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	write(t, stagingPath(r.home), []byte("not a valid ledger\n"))

	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a corrupt staging ledger authorized a restore")
	}
	mustContain(t, r.stderr(), "does not validate", "the restore refusal")

	// The SAME fact reaches the same conclusion through the other verb. The file has already
	// been preserved aside by the first refusal, so the machine now reads as `none` — which is
	// its own distinct refusal, and the one an operator meets next.
	r.reset()
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded")
	}
	mustContain(t, r.stderr(), "no in-progress restore", "the abandon refusal")

	// And on a machine where the corrupt file is still at the well-known name, abandon
	// preserves it aside with its own refusal rather than acting on it.
	write(t, stagingPath(r.home), []byte("not a valid ledger either\n"))
	r.reset()
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment proceeded on a corrupt staging ledger")
	}
	mustContain(t, r.stderr(), "authorizes no cleanup", "the abandon refusal")
}

// --- location authentication (fix2/fix3) ---------------------------------------------------------

func TestRestoreRefusesAnUnsafeExistingBackupRoot(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	// The backup's own checksums are all internally consistent; that is precisely the point.
	// There is no signature, only location — an attacker who can write in the root can forge a
	// mutually consistent manifest, data directory and ledger together.
	r.safe.unsafe[dir] = true
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("restored from a backup root another party can write")
	}
	mustContain(t, r.stderr(), "unsafe", "the refusal")
	if exists(stagingPath(r.home)) {
		t.Fatal("refused after phase 1 had already written the staging ledger")
	}
}

func TestSafeLookingSymlinkToAnUnsafeTargetIsRefused(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	r.safe.unsafe[dir] = true
	// The alias's OWN parent is a fresh, operator-owned (safe) directory, so a parent-only
	// check on the RAW path would pass — while it POINTS AT an unverified location. The alias
	// and the target can have DIFFERENT safety, and it is the target that has to be proven
	// safe, because that is where the bytes actually come from.
	alias := filepath.Join(canon(t, t.TempDir()), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), alias); err == nil {
		t.Fatal("an alias to an unsafe location was trusted")
	}
	mustContain(t, r.stderr(), "unsafe", "the refusal")
	if !r.safe.sawPath(dir) {
		t.Fatalf("the RESOLVED TARGET was never checked; asked about %v", r.safe.asked)
	}
	if r.safe.sawPath(alias) {
		t.Fatalf("the alias itself was checked instead of what it names: %v", r.safe.asked)
	}
}

func TestSymlinkToASafeBackupIsFollowed(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	alias := filepath.Join(filepath.Dir(dir), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	// Resolving a symlink is not the same as refusing every symlink.
	if err := Restore(context.Background(), r.deps(), alias); err != nil {
		t.Fatalf("a symlink to a safe backup was not followed: %v\n%s", err, r.stderr())
	}
	l, err := ledger.Read(mustLive(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := l.IdentGet(); got != r.ident {
		t.Fatalf("identity after restoring through an alias: %q", got)
	}
}

// --- confirmation (fix4) -------------------------------------------------------------------------

func TestUnconfirmedRestoreCreatesAndFillsNothing(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// The volumes are removed first so "nothing was (re)created" is observable: with them in
	// place from the install, an absent-volume assertion would pass or fail for reasons that
	// have nothing to do with the confirmation gate.
	for _, v := range r.vols {
		r.removeVolume(v.name)
	}
	r.confirm = false
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("an unconfirmed restore proceeded")
	}
	mustContain(t, r.stderr(), "not confirmed", "the refusal")
	if exists(stagingPath(r.home)) {
		t.Fatal("nothing should even have been staged")
	}
	if len(r.cop.fills) != 0 {
		t.Fatal("an unconfirmed restore filled a volume")
	}
	for _, v := range r.vols {
		if _, err := r.nonceOf(v.name); !errors.Is(err, engine.ErrAbsent) {
			t.Fatalf("an unconfirmed restore created %s: %v", v.name, err)
		}
	}
}

func TestUnconfirmedBareActivateIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	// A crash strictly between phase 5 and phase 6: the now intent-free ledger is re-staged.
	if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if s, _ := CurrentState(r.deps()); s != StateNoIntent {
		t.Fatalf("state: %q", s)
	}
	r.confirm = false
	r.reset()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a bare activation proceeded without confirmation")
	}
	mustContain(t, r.stderr(), "not confirmed", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated without confirmation")
	}
}

// --- activation's own fail-closed rule -----------------------------------------------------------

// TestActivateRefusesWhenTheIntentReadFAILS is the rc-3-vs-rc-1 rule at the one place it decides
// whether a not-yet-finished restore becomes the live installation. "Absent" is the only answer
// that may activate; an AMBIGUOUS read is not absence, and folding it into one would atomically
// activate a ledger that may still record an unfinished restore.
func TestActivateRefusesWhenTheIntentReadFails(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.fillErr = errors.New("interrupted")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("the interrupted fill was not reported")
	}
	// Two intent records answer the same lookup: neither present-and-readable nor absent.
	appendLedgerRow(t, stagingPath(r.home), "restore\tkey=restore\tphase=2\tsource=/nowhere")
	r.reset()
	if err := Activate(r.deps()); err == nil {
		t.Fatal("activated on an intent read that could not be answered")
	}
	mustContain(t, r.stderr(), "could not be", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("a ledger that may still record an unfinished restore was activated")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was consumed by a refused activation")
	}
}

// TestActivateRefusesOverALiveIntent: the intent lives INSIDE the file being renamed, so
// activating it unchanged leaves every later command meeting an in-progress restore that has
// finished.
func TestActivateRefusesOverALiveIntent(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.fillErr = errors.New("interrupted")
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("the interrupted fill was not reported")
	}
	r.reset()
	if err := Activate(r.deps()); err == nil {
		t.Fatal("a staging ledger carrying a live intent was activated")
	}
	mustContain(t, r.stderr(), "intent — refusing to activate.", "the refusal")
	mustNotContain(t, r.stderr(), "could not be", "the refusal is about a KNOWN intent, not an unreadable one")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}
}

// TestDepsRefusesIncompleteSeams: "could not ask" must never arrive spelled as a nil
// dereference, and a destructive path must not discover a missing seam halfway through.
func TestDepsRefusesIncompleteSeams(t *testing.T) {
	r := newRig(t)
	for name, mangle := range map[string]func(*Deps){
		"copier":  func(d *Deps) { d.Copier = nil },
		"safe":    func(d *Deps) { d.Safe = nil },
		"confirm": func(d *Deps) { d.Confirm = nil },
		"objects": func(d *Deps) { d.Objs = nil },
		"runtime": func(d *Deps) { d.RT = nil },
		"uid":     func(d *Deps) { d.OperatorUID = "" },
	} {
		d := r.deps()
		mangle(&d)
		if err := Run(context.Background(), d, r.bk); err == nil {
			t.Fatalf("a backup ran with no %s", name)
		}
		if err := Restore(context.Background(), d, r.bk); err == nil {
			t.Fatalf("a restore ran with no %s", name)
		}
		if err := Abandon(context.Background(), d); err == nil {
			t.Fatalf("an abandonment ran with no %s", name)
		}
	}
	_ = fmt.Sprint()
}
