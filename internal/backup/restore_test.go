package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

func (r *rig) corruptAsides() []string {
	matches, err := filepath.Glob(stagingPath(r.home) + ".corrupt.*")
	if err != nil {
		r.t.Fatal(err)
	}
	return matches
}

// checksummedLedger builds a ledger file body at an ARBITRARY schema, with a checksum that is
// genuinely correct over its own bytes. A schema NEWER than this build understands is only
// interesting if everything else about the file is right: a fixture with a wrong checksum would
// be refused as corruption before the schema was ever looked at, and would prove nothing.
func checksummedLedger(schema string, rows ...string) []byte {
	body := "#mythical-ctl-ledger schema=" + schema + "\n"
	for _, r := range rows {
		body += r + "\n"
	}
	return []byte(body + "#sha256=" + cliio.SHA256Hex([]byte(body)) + "\n")
}

// stagingVerbs is the pair of entry points that act on the staging classification. BOTH of them
// move a StateCorrupt ledger aside, so every test about what may be CALLED corruption has to
// drive both — a fix applied to one path only is exactly the shape of defect this pair catches.
var stagingVerbs = []struct {
	name string
	run  func(context.Context, Deps) error
}{
	{"restore", func(ctx context.Context, d Deps) error { return Restore(ctx, d, d.Home+"/nonexistent-backup") }},
	{"restore --abandon", Abandon},
}

// TestPreservingCorruptEvidenceNeverOverwritesEarlierEvidence: the preservation step must not
// destroy the thing it exists to keep.
//
// The destination used to be `<staging>.corrupt.<pid>` moved with a REPLACING os.Rename. A PID is
// not a unique name — it is reused across processes, and within ONE process it is a constant — so
// a second corruption computed the same destination as the first and silently overwrote it. The
// bytes preserved as forensic evidence were gone, with nothing reporting that they had ever been
// there: evidence of a corruption destroyed by the next corruption.
//
// TWO CORRUPTIONS IN ONE PROCESS is the case that needs no PID reuse at all, which is why it is
// the one driven here — and it is exactly what an operator does: `restore`, read the refusal, then
// `restore --abandon`.
func TestPreservingCorruptEvidenceNeverOverwritesEarlierEvidence(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	ctx := context.Background()

	first := []byte("the FIRST corruption, and its bytes are the evidence\n")
	write(t, stagingPath(r.home), first)
	if err := Restore(ctx, r.deps(), r.bk); err == nil {
		t.Fatal("a corrupt staging ledger authorized a restore")
	}
	asides := r.corruptAsides()
	if len(asides) != 1 {
		t.Fatalf("the first corruption was not preserved exactly once: %v", asides)
	}
	kept := asides[0]

	second := []byte("the SECOND corruption, a different attempt entirely\n")
	write(t, stagingPath(r.home), second)
	r.reset()
	if err := Abandon(ctx, r.deps()); err == nil {
		t.Fatal("a corrupt staging ledger authorized an abandonment")
	}

	asides = r.corruptAsides()
	if len(asides) != 2 {
		t.Fatalf("two corruptions were preserved under %d name(s) — the second landed on the first: %v",
			len(asides), asides)
	}
	got, err := os.ReadFile(kept)
	if err != nil {
		t.Fatalf("the first preserved evidence is gone: %v", err)
	}
	if string(got) != string(first) {
		t.Fatalf("the first preserved evidence was overwritten:\n got %q\nwant %q", got, first)
	}
	// And the second is preserved too — a fix that simply refused the second preservation would
	// keep the first file while losing the second, which is the same defect facing the other way.
	var other string
	for _, a := range asides {
		if a != kept {
			other = a
		}
	}
	got, err = os.ReadFile(other)
	if err != nil {
		t.Fatalf("the second preserved evidence is gone: %v", err)
	}
	if string(got) != string(second) {
		t.Fatalf("the second preserved evidence is not the second corruption:\n got %q\nwant %q", got, second)
	}
}

// TestPreserveCorruptRefusesAFileThatChangedUnderIt: the verdict and the move must be about the
// same bytes.
//
// CurrentState judges the file, and preserveCorrupt renames whatever occupies the path afterwards.
// A manual restore, a scheduled job or another tool putting a VALID ledger there in between would
// have that intact ledger moved aside and reported corrupt — the destruction of a record nobody
// found fault with, which is the exact outcome the corrupt classification exists to prevent,
// reached by a different route. (The family lock excludes other copies of this tool; it does not
// exclude an operator with an editor, which is the case the activation path already defends
// against by name.)
func TestPreserveCorruptRefusesAFileThatChangedUnderIt(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"it now validates", string(checksummedLedger(ledger.Schema, "somekind\tkey=value"))},
		{"a newer build wrote it", string(checksummedLedger("2", "somekind\tkey=value"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sf := filepath.Join(dir, "ledger.staging")
			write(t, sf, []byte(tc.body))

			aside, residue, err := preserveCorrupt(sf)
			if err == nil {
				t.Fatalf("a ledger that does NOT fail its checksum was moved aside as corrupt (to %q)", aside)
			}
			if residue != nil {
				t.Fatalf("a refusal reported a residue: %v", residue)
			}
			if !strings.Contains(err.Error(), "CHANGED between being") {
				t.Fatalf("the refusal does not say why:\n%v", err)
			}
			// THE FILE IS THE ASSERTION: it is still at its own name, byte-identical.
			got, rerr := os.ReadFile(sf)
			if rerr != nil {
				t.Fatalf("the ledger is no longer at its own name: %v", rerr)
			}
			if string(got) != tc.body {
				t.Fatal("the ledger was rewritten")
			}
			if m, _ := filepath.Glob(sf + ".corrupt.*"); len(m) != 0 {
				t.Fatalf("an intact ledger was preserved as corrupt evidence: %v", m)
			}
		})
	}
}

// TestPreserveCorruptRefusesANonRegularSourceBeforeReadingIt: the re-read must judge a REGULAR
// FILE, which is internal/ledger's own discipline at these paths and was missing from the first
// version of the re-judge. os.ReadFile on a FIFO swapped in here BLOCKS FOREVER; on a symlink it
// follows the link and judges the TARGET while the rename moves the LINK — so the preserved
// "evidence" would be a symlink and the bytes that failed their checksum would still be elsewhere.
func TestPreserveCorruptRefusesANonRegularSourceBeforeReadingIt(t *testing.T) {
	for _, tc := range nonRegular {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sf := filepath.Join(dir, "ledger.staging")
			tc.make(t, sf)
			before := whatIsAt(sf)

			// A DEADLINE, because the defect under test is a BLOCKING read: without the regular-file
			// check a FIFO makes this call never return, and a test that hangs is not a test that
			// fails. This goroutine is the only way to tell those apart.
			done := make(chan error, 1)
			go func() {
				_, _, err := preserveCorrupt(sf)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("a %s at the staging path was moved aside as corrupt evidence", tc.name)
				}
				if !strings.Contains(err.Error(), "no longer a regular file") {
					t.Fatalf("the refusal does not say what is wrong with the path:\n%v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("preserveCorrupt did not return for a %s — it read the path without checking\n"+
					"that it is a regular file, and a FIFO makes that read block forever", tc.name)
			}
			if after := whatIsAt(sf); after != before {
				t.Fatalf("the %s was moved: %q -> %q", tc.name, before, after)
			}
			if m, _ := filepath.Glob(sf + ".corrupt.*"); len(m) != 0 {
				t.Fatalf("something that is not a regular file was preserved as evidence: %v", m)
			}
		})
	}
}

// TestPreserveCorruptTakesOnlyAFreeName is the property one layer down, and it is the one a
// same-name test cannot establish on its own: the move is a NO-REPLACE move, so a destination
// occupied by ANYTHING — a regular file, a directory, a dangling symlink — is left exactly as it
// is and the next candidate is taken. A check-then-rename would satisfy the regular-file case and
// still replace whatever appeared in the window between the two calls.
func TestPreserveCorruptTakesOnlyAFreeName(t *testing.T) {
	for _, tc := range append(nonRegular, struct {
		name string
		make func(t *testing.T, p string)
	}{"regular file", func(t *testing.T, p string) {
		t.Helper()
		write(t, p, []byte("evidence from an earlier run\n"))
	}}) {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sf := filepath.Join(dir, "ledger.staging")
			want := []byte("the corruption being preserved now\n")
			write(t, sf, want)
			occupied := sf + ".corrupt." + strconv.Itoa(os.Getpid())
			tc.make(t, occupied)
			before := whatIsAt(occupied)

			aside, residue, err := preserveCorrupt(sf)
			if err != nil {
				t.Fatalf("preserveCorrupt: %v", err)
			}
			if residue != nil {
				t.Fatalf("an ordinary preservation reported a residue: %v", residue)
			}
			if aside == occupied {
				t.Fatalf("preserveCorrupt took the occupied name %s", occupied)
			}
			if after := whatIsAt(occupied); after != before {
				t.Fatalf("the occupied name changed from %q to %q", before, after)
			}
			got, rerr := os.ReadFile(aside)
			if rerr != nil {
				t.Fatalf("the evidence is not at the name preserveCorrupt returned: %v", rerr)
			}
			if string(got) != string(want) {
				t.Fatalf("the preserved bytes are not the corrupt ledger:\n got %q\nwant %q", got, want)
			}
			if exists(sf) {
				t.Fatal("the corrupt ledger is still sitting at the well-known staging name")
			}
		})
	}
}

// TestNewerSchemaStagingLedgerIsNotCorruption pins the difference between an ANSWER about a
// file and a REFUSAL to judge it.
//
// A schema-2 staging ledger is checksum-valid and parses cleanly; the single thing wrong with it
// is that THIS build is too old to understand it. Classifying it as corruption made both verbs
// move it aside — so a record a newer mythical-ctl wrote, and could still read, disappeared from
// the well-known name because an older build met it. internal/ledger draws this line explicitly
// (ErrNewerSchema is documented as "never mistaken for corruption"); this is the restore verb
// holding the same line.
func TestNewerSchemaStagingLedgerIsNotCorruption(t *testing.T) {
	for _, v := range stagingVerbs {
		t.Run(v.name, func(t *testing.T) {
			r := newRig(t)
			r.backupOK()
			r.dropLedger()
			want := checksummedLedger("2", "somekind\tkey=value")
			write(t, stagingPath(r.home), want)
			r.reset()

			err := v.run(context.Background(), r.deps())
			if err == nil {
				t.Fatal("a staging ledger this build cannot read authorized the verb")
			}
			// A PURE REFUSAL: nothing is touched, so it must return BEFORE the confirmation gate
			// rather than through it. Asking an operator to confirm an operation that cannot
			// happen is how a refusal turns into a prompt they learn to answer yes to.
			if len(r.prompts) != 0 {
				t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
			}
			out := r.stderr()
			mustContain(t, out, "NEWER mythical-ctl", "the refusal")
			mustContain(t, out, "LEFT EXACTLY", "the promise that nothing was touched")
			mustNotContain(t, out, "does not validate", "corruption wording on a checksum-valid ledger")
			mustNotContain(t, out, "PRESERVED at", "an aside report for a file that was not moved")

			// THE FILE IS THE ASSERTION. Wording can be fixed later; a ledger that has been moved
			// is gone from the name every other tool looks at.
			if aside := r.corruptAsides(); len(aside) != 0 {
				t.Fatalf("a checksum-valid newer-schema ledger was moved aside as corrupt: %v", aside)
			}
			got, rerr := os.ReadFile(stagingPath(r.home))
			if rerr != nil {
				t.Fatalf("the staging ledger is no longer at its own name: %v", rerr)
			}
			if string(got) != string(want) {
				t.Fatalf("the staging ledger was rewritten:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// TestUnreadableStagingLedgerIsNotCorruption is the same rule for the other half of the same
// fold: a read that FAILED is not a checksum that DISAGREED. Nothing here says anything about the
// bytes, so nothing here may move them.
//
// THE PREMISE IS MEASURED, not assumed — a user that bypasses the mode bit (root, or a filesystem
// that does not enforce it) would leave the read SUCCEEDING and turn every assertion below into a
// statement about a different branch. Same discipline as TestCurrentStateRefusesAPathItCannotExamine.
func TestUnreadableStagingLedgerIsNotCorruption(t *testing.T) {
	for _, v := range stagingVerbs {
		t.Run(v.name, func(t *testing.T) {
			r := newRig(t)
			r.backupOK()
			r.dropLedger()
			sf := stagingPath(r.home)
			want := checksummedLedger(ledger.Schema, "somekind\tkey=value")
			write(t, sf, want)
			if err := os.Chmod(sf, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(sf, 0o600) })
			if _, err := os.ReadFile(sf); err == nil {
				t.Skipf("this user can still read %s — the unreadable branch is not reachable here", sf)
			}
			r.reset()

			err := v.run(context.Background(), r.deps())
			if err == nil {
				t.Fatal("a staging ledger that could not be read authorized the verb")
			}
			if len(r.prompts) != 0 {
				t.Fatalf("a pure refusal asked for confirmation: %v", r.prompts)
			}
			out := r.stderr()
			mustContain(t, out, "could not be read", "the refusal")
			mustContain(t, out, "never", "the reason: nothing was established")
			mustNotContain(t, out, "does not validate", "corruption wording on a file nobody read")
			mustNotContain(t, out, "PRESERVED at", "an aside report for a file that was not moved")

			if aside := r.corruptAsides(); len(aside) != 0 {
				t.Fatalf("a ledger nobody could read was moved aside as corrupt: %v", aside)
			}
			if err := os.Chmod(sf, 0o600); err != nil {
				t.Fatal(err)
			}
			got, rerr := os.ReadFile(sf)
			if rerr != nil {
				t.Fatalf("the staging ledger is no longer at its own name: %v", rerr)
			}
			if string(got) != string(want) {
				t.Fatalf("the staging ledger was rewritten:\n got %q\nwant %q", got, want)
			}
		})
	}
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
	//
	// THE SURVIVOR CARRIES THIS INSTALLATION'S OWN LABEL, deliberately. This test is about WHICH
	// object, and phase 2 settles WHOSE first: a FOREIGN-labelled volume is refused one question
	// earlier, by the installation check, and this assertion would then pass with the nonce
	// comparison never running at all. The foreign case has its own test
	// (TestRestoreRefusesAVolumeCarryingOurNonceUnderAnotherInstallation).
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "not-our-nonce", r.ident)

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
	// Simulate a name reassigned in between: an object of THIS installation's carrying a nonce
	// this staging ledger did not record.
	//
	// The identity stays OURS on purpose. Abandonment settles WHOSE before WHICH, so a
	// foreign-labelled volume is preserved one question earlier and the nonce comparison never
	// runs — which is a different guard, with its own test
	// (TestAbandonPreservesAVolumeCarryingOurNonceUnderAnotherInstallation).
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "somebody-elses-nonce", r.ident)
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
	// OUR OWN LABEL, A DIFFERENT NONCE — the WHICH question, for the same reason
	// TestSameNameSurvivorIsRefused stands its survivor that way.
	victim := r.vols[0].name
	r.removeVolume(victim)
	r.createVolume(victim, "an-unrelated-nonce", r.ident)

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
	//
	// THAT IS EXACTLY WHY THE FROZEN ROW FAILS. Measured with the vendored bats runner:
	// tests/acceptance/restore.bats is 20 ok / 1 not ok, and the one failure is this row — its
	// setup() installs the product (creating both named volumes) and then removes only the
	// CONTAINER, so `mi_rt_inspect volume ... "$VOL_STATE"` answers rc 0, never the rc 3 the row
	// asserts. The intent in its comment ("and nothing was (re)created") is right; the assertion
	// tests "absent" where the fixture guarantees "present". The acceptance lane is not run in CI,
	// which is the likeliest reason it was never caught. Removing the volumes first is what makes
	// the same assertion measure the gate it names.
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

// TestResumeDoesNotClaimPartialContentsItNeverMeasured is the other side of the branch above, and
// the reason the two are not one message.
//
// "IT HOLDS PARTIAL CONTENTS" IS A FINDING ABOUT THE DATA, and only a verifier that actually
// compared this volume against this manifest can make it. When the verification could not be
// PERFORMED at all — the copy image unobtainable, the manifest unreadable, the helper never
// launched — nothing has been established about the volume, and saying otherwise steers the
// operator to `restore --abandon`, which REMOVES volumes. Both outcomes refuse and neither fills
// over anything; what differs is the claim, and the claim is what the operator acts on.
func TestResumeDoesNotClaimPartialContentsItNeverMeasured(t *testing.T) {
	r := interrupted(t)
	victim := r.vols[0].name
	r.cop.fillErr = nil
	// Non-empty, exactly as the partial-contents case...
	r.cop.count = func(vol string) (Transcript, error) {
		if vol == victim {
			return Transcript{Text: "checked=2\n"}, nil
		}
		return Transcript{Text: "checked=0\n"}, nil
	}
	// ...but the verifier could not be RUN, which is not an answer.
	r.cop.verify = func(vol string, man []byte) (Transcript, error) {
		if vol == victim {
			return Transcript{}, errors.New("copy: the verify helper could not be run")
		}
		return Transcript{Text: "checked=4\ndone=ok\n"}, nil
	}
	fillsBefore := len(r.cop.fills)
	err := Restore(context.Background(), r.deps(), r.bk)
	if err == nil {
		t.Fatal("a verification that could not run was treated as a pass")
	}
	mustContain(t, r.stderr(), "NOT EMPTY", "the refusal still names what it found")
	mustContain(t, r.stderr(), "could not be established", "the refusal says the contents were not measured")
	// THE CLAIM NOTHING ESTABLISHED, and the destructive recovery that follows from it.
	mustNotContain(t, r.stderr(), "it holds partial contents from an interrupted attempt",
		"a finding about the data that nothing measured")
	if len(r.cop.fills) != fillsBefore {
		t.Fatal("the unmeasured volume was filled over")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a volume nothing verified")
	}
}

// TestLinkThenVerifiedUnlinkNeverDeletesAReplacement: the link+unlink fallback must not delete a
// file that took the source name after the link.
//
// ACTIVATION AND PRESERVATION WANT OPPOSITE THINGS FROM THAT UNLINK. Activation is consuming the
// staging ledger and tidying its name away, so removing whatever is left there is the point.
// Preservation is RESCUING bytes that failed a checksum, and the source is the well-known staging
// path — where an operator restoring a ledger by hand, or another tool, can put something else
// between the link and the unlink. Deleting THAT file while reporting the preservation a success
// leaves a valid ledger at neither name.
//
// The fallback is driven directly: the no-replace primitive succeeds on this filesystem, so a test
// routed through preserveMove would take the rename path and this branch would be exercised
// nowhere.
func TestLinkThenVerifiedUnlinkNeverDeletesAReplacement(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "ledger.staging")
	to := filepath.Join(dir, "ledger.staging.corrupt.1")
	write(t, from, []byte("the bytes that failed their checksum\n"))

	// SOMETHING ELSE TAKES THE SOURCE NAME between the link and the unlink. os.Link is called by
	// the function under test, so the swap is arranged by making `from` a DIFFERENT inode than the
	// one it will Lstat first — done by replacing it after that Lstat is impossible from here, so
	// instead the same window is reproduced by handing it a source that is replaced underneath a
	// pre-linked destination.
	if err := os.Link(from, to); err != nil {
		t.Skipf("this filesystem does not support hard links (%v) — the fallback is not reachable here", err)
	}
	replacement := checksummedLedger(ledger.Schema, "somekind\tkey=value")
	if err := os.Remove(from); err != nil {
		t.Fatal(err)
	}
	write(t, from, replacement)
	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}

	// Now the ordinary call: it links, and the source is stable, so this one SUCCEEDS — the
	// control that proves the function still does its job.
	if err := linkThenVerifiedUnlink(from, to); err != nil {
		t.Fatalf("an ordinary fallback move failed: %v", err)
	}
	if exists(from) {
		t.Fatal("the source was not unlinked on the ordinary path")
	}
	got, rerr := os.ReadFile(to)
	if rerr != nil || string(got) != string(replacement) {
		t.Fatalf("the moved bytes are wrong: %q, %v", got, rerr)
	}

	// AND THE WINDOW ITSELF, through the seam that opens it: a source whose inode changes between
	// the link and the unlink must be LEFT ALONE.
	from2 := filepath.Join(dir, "second.staging")
	to2 := filepath.Join(dir, "second.staging.corrupt.1")
	write(t, from2, []byte("evidence\n"))
	swapErr := swapAfterLink(t, from2, to2, replacement)
	// A TAKEN NAME IS ITS OWN OUTCOME, not a residue. "Residue" means a leftover copy of what was
	// moved and the report tells the operator to delete it — which, pointed at a file that merely
	// appeared at the staging name, is an instruction to destroy something nobody has read.
	if !errors.Is(swapErr, errStagingNameTaken) {
		t.Fatalf("a replaced source was not reported as a taken staging name: %v", swapErr)
	}
	if errors.Is(swapErr, errActivatedWithResidue) {
		t.Fatalf("a file that is NOT the preserved evidence was reported as a leftover copy: %v", swapErr)
	}
	back, rerr2 := os.ReadFile(from2)
	if rerr2 != nil {
		t.Fatalf("the replacement at the source name was DELETED: %v", rerr2)
	}
	if string(back) != string(replacement) {
		t.Fatal("the file at the source name is not the replacement")
	}
}

// TestReportResidueNeverTellsTheOperatorToDeleteSomethingElse: the two outcomes read differently
// because the operator does different things with them.
//
// errActivatedWithResidue means a leftover COPY of the evidence is lying about, and the report says
// to remove it. errStagingNameTaken means something ELSE arrived at the staging name while the
// evidence was being moved — possibly a valid ledger. One message for both told an operator to
// delete a file nobody had looked at.
func TestReportResidueNeverTellsTheOperatorToDeleteSomethingElse(t *testing.T) {
	r := newRig(t)
	sf := stagingPath(r.home)

	r.reset()
	r.deps().reportResidue(errStagingNameTaken, sf)
	taken := r.stderr()
	if !strings.Contains(taken, "SOMETHING ELSE now stands") || !strings.Contains(taken, "Look at what it is") {
		t.Fatalf("a taken staging name is not reported as one:\n%s", taken)
	}
	if strings.Contains(taken, "remove the leftover yourself") {
		t.Fatalf("the operator is told to delete a file that is not ours:\n%s", taken)
	}

	r.reset()
	r.deps().reportResidue(fmt.Errorf("%w: %v", errActivatedWithResidue, errors.New("permission denied")), sf)
	leftover := r.stderr()
	if !strings.Contains(leftover, "A COPY ALSO REMAINS") || !strings.Contains(leftover, "remove the leftover yourself") {
		t.Fatalf("a genuine leftover copy is not reported as one:\n%s", leftover)
	}

	// AND NOTHING AT ALL when there is nothing to say.
	r.reset()
	r.deps().reportResidue(nil, sf)
	if r.stderr() != "" {
		t.Fatalf("a clean preservation reported a residue:\n%s", r.stderr())
	}
}

// TestUnlinkIfSameTreatsAVanishedSourceAsDone: ENOENT is the state the unlink set out to reach, so
// it is success — not a residue whose report tells the operator to go and remove a file that is
// not there. The same rule residueOf already states for the unlink itself.
func TestUnlinkIfSameTreatsAVanishedSourceAsDone(t *testing.T) {
	dir := t.TempDir()
	to := filepath.Join(dir, "preserved")
	write(t, to, []byte("evidence\n"))
	linked, err := os.Lstat(to)
	if err != nil {
		t.Fatal(err)
	}
	if uerr := unlinkIfSame(linked, filepath.Join(dir, "gone")); uerr != nil {
		t.Fatalf("a source that is already gone was reported as a problem: %v", uerr)
	}
}

// swapAfterLink reproduces the window by doing the fallback's own steps with a replacement dropped
// in between, and then asking the function under test for its unlink decision about that state.
func swapAfterLink(t *testing.T, from, to string, replacement []byte) error {
	t.Helper()
	if err := os.Link(from, to); err != nil {
		t.Skipf("this filesystem does not support hard links (%v)", err)
	}
	// THE ANCHOR IS THE LINK'S OWN RESULT, exactly as the production path takes it.
	before, err := os.Lstat(to)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(from); err != nil {
		t.Fatal(err)
	}
	write(t, from, replacement)
	after, err := os.Lstat(from)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the fixture did not replace the inode — the window is not exercised")
	}
	return unlinkIfSame(before, from)
}

// TestLinkThenVerifiedUnlinkAgainstAConcurrentReplacer: the identity anchor must be the file the
// LINK created, and that choice is only observable under a real concurrent writer.
//
// Sampling the source BEFORE the link answers the wrong question: if the source changes between
// the sample and the link, the link names the NEW file at the destination while the sample still
// describes the old one — and if the old inode reappears at the source, the comparison succeeds,
// the ORIGINAL evidence is unlinked, and the destination holds unrelated bytes. Lstat of the
// destination is, by construction, the inode that is now preserved.
//
// THE INVARIANT ASSERTED IS THE ONE THAT MATTERS AND HOLDS UNDER ANY INTERLEAVING: whatever this
// call reports, the bytes it preserved at `to` and the bytes left at `from` are never a pair where
// the evidence has been destroyed — the file unlinked from `from` is always the one that is also
// at `to`. (Mirrors TestActivateRenameIsAtomicAgainstAConcurrentWriter's shape.)
func TestLinkThenVerifiedUnlinkAgainstAConcurrentReplacer(t *testing.T) {
	const rounds = 300
	for round := 0; round < rounds; round++ {
		dir := t.TempDir()
		from := filepath.Join(dir, "ledger.staging")
		to := filepath.Join(dir, "ledger.staging.corrupt.1")
		evidence := []byte("evidence-" + strconv.Itoa(round) + "\n")
		write(t, from, evidence)
		// The replacement is a DIFFERENT inode carrying different bytes, so any confusion between
		// the two is visible in the file contents rather than only in the metadata.
		other := []byte("a valid ledger somebody else put here\n")
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tmp := filepath.Join(dir, "tmp")
				if err := os.WriteFile(tmp, other, 0o600); err == nil {
					_ = os.Rename(tmp, from)
				}
			}
		}()
		err := linkThenVerifiedUnlink(from, to)
		close(stop)
		wg.Wait()

		// THE EVIDENCE IS NEVER LOST. Either the link preserved it at `to`, or the call reported a
		// failure and did not claim to have preserved anything.
		if err != nil && !errors.Is(err, errStagingNameTaken) && !errors.Is(err, errActivatedWithResidue) {
			// A link that lost the race to the replacer is an ordinary failure, not a defect.
			continue
		}
		got, rerr := os.ReadFile(to)
		if rerr != nil {
			t.Fatalf("round %d: the call returned %v but preserved nothing at %s: %v", round, err, to, rerr)
		}
		// Whatever was linked, the file left at `from` must never be the one that was unlinked out
		// from under the preserved copy: if `from` still exists it is either the SAME file as `to`
		// (nothing was removed) or a different one the replacer put there.
		if fi, serr := os.Lstat(from); serr == nil {
			ti, terr := os.Lstat(to)
			if terr != nil {
				t.Fatalf("round %d: %v", round, terr)
			}
			if os.SameFile(fi, ti) && err == nil {
				t.Fatalf("round %d: the call reported the source unlinked, but it is still the same file "+
					"as the preserved copy", round)
			}
		}
		// And the preserved bytes are one of the two real files — never a torn or absent value.
		if string(got) != string(evidence) && string(got) != string(other) {
			t.Fatalf("round %d: the preserved copy holds %q, which is neither the evidence nor the "+
				"replacement", round, string(got))
		}
	}
}

// TestAnUnconfirmablePreservedCopyIsAFailureNotAResidue: "residue" is reported as SUCCESS, and its
// words tell the operator the evidence is safe elsewhere and to remove the leftover.
//
// If the destination cannot be examined after the link — ENOENT, most sharply, meaning the new link
// has vanished — then nothing is known to be at that name, and the file still at the staging name
// is the ONLY copy. Calling that a residue tells the operator to delete the last copy of the
// evidence the function exists to keep. It is a failed preservation: nothing is claimed and nothing
// is unlinked.
func TestAnUnconfirmablePreservedCopyIsAFailureNotAResidue(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "ledger.staging")
	evidence := []byte("the only copy\n")
	write(t, from, evidence)
	to := filepath.Join(dir, "ledger.staging.corrupt.1")

	// THE ARM IS REACHED THROUGH ITS OWN SEAM, because no fixture can open the window from
	// outside: the link must SUCCEED and the destination be unexaminable only afterwards. The
	// alternative — a test that re-implements the arm and checks its own restatement — passes
	// however wrong the code is.
	orig := lstatAfterLink
	t.Cleanup(func() { lstatAfterLink = orig })
	lstatAfterLink = func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }

	err := linkThenVerifiedUnlink(from, to)
	if err == nil {
		t.Fatal("an unconfirmable preserved copy was reported as a success")
	}
	if errors.Is(err, errActivatedWithResidue) || errors.Is(err, errStagingNameTaken) {
		t.Fatalf("an unconfirmable preserved copy was reported as a residue — which preserveCorrupt reads\n"+
			"as SUCCESS, so the operator is told the evidence is safe and to delete the only copy\n"+
			"left: %v", err)
	}
	if !strings.Contains(err.Error(), "never established") {
		t.Fatalf("the refusal does not say the question failed: %v", err)
	}
	// THE EVIDENCE IS UNTOUCHED at the staging name.
	got, rerr := os.ReadFile(from)
	if rerr != nil || string(got) != string(evidence) {
		t.Fatalf("the only remaining copy was disturbed: %q, %v", got, rerr)
	}

	// preserveCorrupt's propagation of this — a plain error becomes ("", nil, err), so the caller
	// prints "cannot preserve the corrupt staging ledger" instead of naming an aside — is asserted
	// by TestPreserveCorruptPropagatesAMoveFailureAndClaimsNothing, through the preserveMoveNow
	// seam. It cannot be driven from here: on a filesystem whose no-replace rename works,
	// preserveMove never reaches the fallback at all.
	//
	// It was previously credited to TestPreserveCorruptRefusesAFileThatChangedUnderIt, which does
	// NOT reach that arm: that test stands a file which VALIDATES, so preserveCorrupt returns at
	// the re-judgement several statements before the move loop starts. Both tests passed while
	// nothing at all covered the propagation.
}

// TestPreserveCorruptPropagatesAMoveFailureAndClaimsNothing: a move that failed outright is
// reported as a failure, and NOTHING is claimed about where the evidence went.
//
// preserveCorrupt has three answers, and the caller prints a different sentence for each: an aside
// with no residue ("PRESERVED at <aside>"), an aside WITH a residue ("preserved, and a copy also
// remains at the staging name — remove it"), and a failure ("cannot preserve the corrupt staging
// ledger"). The third is the one that says the bytes were NOT rescued. A regression that returned
// the candidate name with a nil error, or folded the failure into the residue arm, would tell an
// operator the evidence is safe at a path that holds nothing — and, in the residue case, tell them
// to DELETE the only copy that still exists.
func TestPreserveCorruptPropagatesAMoveFailureAndClaimsNothing(t *testing.T) {
	dir := t.TempDir()
	sf := filepath.Join(dir, "ledger.staging")
	body := []byte("not a ledger\n")
	write(t, sf, body)

	// THE ARM IS REACHED THROUGH ITS OWN SEAM. The no-replace rename succeeds on the filesystems
	// this project is developed on, so a fixture built from outside takes the rename path and the
	// failure arm is exercised nowhere. Faking the move is what makes the branch reachable at all.
	orig := preserveMoveNow
	t.Cleanup(func() { preserveMoveNow = orig })
	boom := errors.New("the destination directory could not be written")
	var attempts int
	preserveMoveNow = func(from, to string) error {
		attempts++
		return boom
	}

	aside, residue, err := preserveCorrupt(sf)
	if err == nil {
		t.Fatalf("a move that failed outright was reported as a success (aside %q)", aside)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the move's own failure was replaced rather than propagated: %v", err)
	}
	if aside != "" {
		t.Fatalf("a failed preservation named %q as the place the evidence went — nothing is there", aside)
	}
	if residue != nil {
		t.Fatalf("a failed preservation was reported as a RESIDUE, which the caller prints as success\n"+
			"and follows by telling the operator to delete the only copy that is left: %v", residue)
	}
	// A PLAIN FAILURE IS NOT RETRIED UNDER ANOTHER NAME. Only fs.ErrExist — "that name is taken",
	// an ANSWER — advances the candidate loop; retrying a broken move 128 times says nothing new
	// and buries the real reason under the bound's own message.
	if attempts != 1 {
		t.Fatalf("a move that failed for its own reason was retried %d times", attempts)
	}
	// THE EVIDENCE IS UNTOUCHED at its own name: nothing was moved, so nothing was removed.
	got, rerr := os.ReadFile(sf)
	if rerr != nil || string(got) != string(body) {
		t.Fatalf("the corrupt ledger was disturbed by a preservation that failed: %q %v", got, rerr)
	}
	if m, _ := filepath.Glob(sf + ".corrupt.*"); len(m) != 0 {
		t.Fatalf("a failed preservation left something behind: %v", m)
	}
}

// --- WHOSE before WHICH: the installation label, on both destructive paths --------------------

// labelSeam narrows the READ-ONLY runtime seam for ONE label on ONE object, and delegates
// everything else to the production reader.
//
// It exists because two of the three answers this module must distinguish cannot be staged from
// outside: a volume with NO installation label cannot be created through the runtime facade at all
// (engine.NewProvenance refuses an empty installation, which is the point of it), and "the label
// could not be READ" is a seam failure, not a state. Faking the whole reader would be the trap the
// rig's own note describes — a suite that answers its questions from its own record of what it did
// — so this overrides one (object, label) pair and passes every other question straight through.
type labelSeam struct {
	prov.Objects
	class prov.Class
	name  string
	label string
	val   string
	err   error
}

func (s labelSeam) Label(ctx context.Context, class prov.Class, name, label string) (string, error) {
	if class == s.class && name == s.name && label == s.label {
		return s.val, s.err
	}
	return s.Objects.Label(ctx, class, name, label)
}

// TestRestoreRefusesAVolumeCarryingOurNonceUnderAnotherInstallation: WHOSE is settled before WHICH,
// and phase 2's re-inspection used to ask only WHICH.
//
// A nonce says which object; it never says whose. The backup FILE carries the recorded nonces, so
// anyone holding a copy of it can present a matching one, and `volume create` against an existing
// name SUCCEEDS without applying our labels (D56) — so what phase 2 re-inspects can be a volume
// belonging to another installation on the same daemon. Reading the nonce alone authorized FILLING
// it with this backup's data.
func TestRestoreRefusesAVolumeCarryingOurNonceUnderAnotherInstallation(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	victim := r.vols[0]
	r.removeVolume(victim.name)
	r.createVolume(victim.name, victim.nonce, "somebody-elses-identity")

	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume labelled for ANOTHER INSTALLATION was filled with this backup's data")
	}
	out := r.stderr()
	mustContain(t, out, "somebody-elses-identity", "the refusal names the installation it belongs to")
	mustContain(t, out, victim.name, "the refusal names the volume")
	if len(r.cop.fills) != 0 {
		t.Fatalf("another installation's volume was filled: %v", r.cop.fills)
	}
	got, lerr := r.objs.Label(context.Background(), prov.ClassVolume, victim.name, prov.LabelInstall)
	if lerr != nil || got != "somebody-elses-identity" {
		t.Fatalf("another installation's volume was relabelled or removed: %q %v", got, lerr)
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("a restore that could not prove it owned every volume activated")
	}
}

// TestRestoreRefusesAVolumeWithNoInstallationLabel: an UNLABELLED volume standing at a name this
// restore would create proves nothing either way — no label makes it ours, and no provenance makes
// it somebody else's. It is neither filled nor removed.
func TestRestoreRefusesAVolumeWithNoInstallationLabel(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	victim := r.vols[0]
	d := r.deps()
	d.Objs = labelSeam{Objects: r.objs, class: prov.ClassVolume, name: victim.name, label: prov.LabelInstall, val: "<no value>"}

	if err := Restore(context.Background(), d, r.bk); err == nil {
		t.Fatal("a volume carrying no installation label was filled")
	}
	mustContain(t, r.stderr(), "NO installation label", "the refusal")
	mustContain(t, r.stderr(), victim.name, "the refusal names the volume")
	if len(r.cop.fills) != 0 {
		t.Fatalf("an unattributed volume was filled: %v", r.cop.fills)
	}
}

// TestRestoreRefusesAVolumeWhoseInstallationLabelCannotBeRead: a question that was never ANSWERED
// is not an answer of "it is ours". Both outcomes refuse; only one of them may be told to the
// operator as a fact about the volume.
func TestRestoreRefusesAVolumeWhoseInstallationLabelCannotBeRead(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	victim := r.vols[0]
	d := r.deps()
	d.Objs = labelSeam{Objects: r.objs, class: prov.ClassVolume, name: victim.name, label: prov.LabelInstall,
		err: errors.New("the container runtime did not answer")}

	if err := Restore(context.Background(), d, r.bk); err == nil {
		t.Fatal("a volume whose owner was never established was filled")
	}
	mustContain(t, r.stderr(), "who owns", "the refusal says the question failed")
	mustContain(t, r.stderr(), victim.name, "the refusal names the volume")
	if len(r.cop.fills) != 0 {
		t.Fatalf("a volume of unestablished ownership was filled: %v", r.cop.fills)
	}
}

// TestRestoreRefusesAVolumeThatIsGoneAfterPhase2: absence a moment after phase 2 created the volume
// is an ANSWER — and it is not an answer this loop may fill on. The object phase 2 was supposed to
// have made was never established.
func TestRestoreRefusesAVolumeThatIsGoneAfterPhase2(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	victim := r.vols[0]
	d := r.deps()
	d.Objs = labelSeam{Objects: r.objs, class: prov.ClassVolume, name: victim.name, label: prov.LabelInstall,
		err: fmt.Errorf("engine: %w", engine.ErrAbsent)}

	if err := Restore(context.Background(), d, r.bk); err == nil {
		t.Fatal("a volume the runtime says does not exist was filled")
	}
	// THE REFUSAL'S IDENTITY, not merely that something refused. Absence folded into the
	// unlabelled branch would still refuse — and would tell the operator the volume carries no
	// installation label, which is a claim about an object that is not there.
	mustContain(t, r.stderr(), "is not there", "the refusal says the volume is absent")
	mustNotContain(t, r.stderr(), "NO installation label", "an absent volume is not an unlabelled one")
	mustContain(t, r.stderr(), victim.name, "the refusal names the volume")
	if len(r.cop.fills) != 0 {
		t.Fatalf("a volume that is not there was filled: %v", r.cop.fills)
	}
}

// TestAbandonPreservesAVolumeCarryingOurNonceUnderAnotherInstallation: abandonment REMOVES, so it
// owes the stronger half of the same rule.
//
// The staging ledger comes out of a backup file, and that file carries the nonces with it. A volume
// standing at the recorded name under ANOTHER installation's label, carrying the recorded nonce, was
// DELETED — another installation's data destroyed on the strength of a label the backup supplied.
func TestAbandonPreservesAVolumeCarryingOurNonceUnderAnotherInstallation(t *testing.T) {
	r := interrupted(t)
	victim := r.vols[0]
	r.removeVolume(victim.name)
	r.createVolume(victim.name, victim.nonce, "somebody-elses-identity")

	err := Abandon(context.Background(), r.deps())
	out := r.stderr()
	mustContain(t, out, "PRESERVED", "the report")
	mustContain(t, out, victim.name, "the report names the volume")
	mustContain(t, out, "somebody-elses-identity", "the report names the installation it belongs to")
	if _, lerr := r.nonceOf(victim.name); lerr != nil {
		t.Fatalf("another installation's volume was REMOVED by an abandonment: %v", lerr)
	}
	// Abandonment still completes: the foreign volume is not this restore's to clean up, and
	// wedging the operator between a survivor refusal and an abandonment that never finishes is
	// the state this module builds nothing on.
	if err != nil {
		t.Fatalf("abandonment did not complete over a volume that is not ours: %v\n%s", err, out)
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger survived a completed abandonment")
	}
}

// TestAbandonKeepsTheStagingLedgerWhenOwnershipCannotBeEstablished: "could not ask" is not "not
// ours". The first keeps the staging ledger so a re-run converges; the second completes.
func TestAbandonKeepsTheStagingLedgerWhenOwnershipCannotBeEstablished(t *testing.T) {
	r := interrupted(t)
	victim := r.vols[0]
	d := r.deps()
	d.Objs = labelSeam{Objects: r.objs, class: prov.ClassVolume, name: victim.name, label: prov.LabelInstall,
		err: errors.New("the container runtime did not answer")}

	if err := Abandon(context.Background(), d); err == nil {
		t.Fatal("an abandonment that could not establish ownership reported completion")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger — the only record of which partial volumes exist — was removed")
	}
	if _, lerr := r.nonceOf(victim.name); lerr != nil {
		t.Fatalf("a volume of unestablished ownership was removed: %v", lerr)
	}
}

// TestAbandonCompletesOverAVolumeTheRuntimeSaysIsGone: a 404 from the removal is the goal reached,
// not a refusal.
//
// A partial volume can disappear between the authority question and the DELETE — an operator, a
// reaper, another tool. Reading that 404 as "could not remove" kept the staging ledger for a volume
// the runtime had just said does not exist, and nothing could ever clear it: every later attempt
// gets the same 404, so the machine is left permanently unable to finish OR restart a restore.
func TestAbandonCompletesOverAVolumeTheRuntimeSaysIsGone(t *testing.T) {
	r := interrupted(t)
	victim := r.vols[0].name
	// THE WINDOW ITSELF, not the state after it: every INSPECT still answers (so authority proves
	// the volume ours and the removal IS attempted) and the DELETE alone 404s. Removing the volume
	// up front would make authority answer ErrGone and the removal would never run — a different
	// branch entirely.
	r.fake.RemoveMissing = victim

	if err := Abandon(context.Background(), r.deps()); err != nil {
		t.Fatalf("a volume the runtime says is gone was reported as a failed removal: %v\n%s", err, r.stderr())
	}
	if exists(stagingPath(r.home)) {
		t.Fatal("the staging ledger was kept for a volume the runtime says does not exist — every later " +
			"attempt gets the same answer, so nothing can ever clear it")
	}
	// AND NO REMOVAL IS CLAIMED THAT DID NOT HAPPEN. On a 404 the operation established absence
	// and removed nothing.
	mustNotContain(t, r.stdout()+r.stderr(), "removed partial volume "+victim, "the report")
}
