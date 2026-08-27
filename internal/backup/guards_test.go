package backup

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/trust"
)

// Guard coverage beyond the inventory. Every refusal in this package is reachable from a test
// that names it, so reverting any one of them in isolation reddens a NAMED test with ITS OWN
// message rather than leaving a path nothing covers. The reference's own suite exercises the
// cases an operator meets; these are the ones only a mutation would find.

// --- backup ------------------------------------------------------------------------------------

func TestBackupFailsClosedOnAVolumeRecordWithNoProduct(t *testing.T) {
	r := newRig(t)
	// class=volume, a name, a nonce — and no product. There is nothing to say which manifest
	// declares its runtime uid, and guessing is exactly what refusing exists to prevent.
	r.putObject(t, "volume:ghost4",
		ledger.Field{Key: "class", Value: "volume"},
		ledger.Field{Key: "name", Value: "ghost4"},
		ledger.Field{Key: "nonce", Value: "deadbeef"})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume record with no product was skipped")
	}
	mustContain(t, r.stderr(), "carries no product", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup was written despite refusing")
	}
}

// TestManifestWithNoRuntimeUIDIsRefusedByTheChain records WHERE that refusal actually comes
// from in the Go tree. `runtime_uid` is a REQUIRED manifest key, so a manifest without one does
// not parse and never reaches this module at all — the chain refuses it first. This module's
// own empty-value guard is therefore a SECOND door the schema currently makes unreachable; it
// is kept anyway, because "unstated silently meaning uid 0" is the one answer that is never
// safe, and a later schema change must not be able to open that path quietly. See the note on
// runtimeUID.
func TestManifestWithNoRuntimeUIDIsRefusedByTheChain(t *testing.T) {
	r := newRig(t)
	r.rewriteChain(t, func(man string) string {
		return strings.ReplaceAll(man, "runtime_uid=900\n", "")
	})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a manifest declaring no runtime uid was copied under a guessed one")
	}
	mustContain(t, r.stderr(), "refusing to guess its runtime uid", "the refusal")
	if len(r.cop.runs) != 0 {
		t.Fatal("a copy ran under a uid nothing declared")
	}
}

func TestManifestEnumerationThatFailsIsRefused(t *testing.T) {
	r := newRig(t)
	// The helper ran and FAILED. Its partial transcript is not a manifest: a per-entry contract
	// built from an enumeration that did not finish would authenticate a subset of the volume
	// and call it the whole.
	r.cop.enumerate = func(string) (Transcript, error) {
		return Transcript{Code: 2, Text: manifestTranscript() + "\n"}, nil
	}
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a failed enumeration was written as a manifest")
	}
	mustContain(t, r.stderr(), "could not enumerate volume", "the refusal")
	mustContain(t, r.stderr(), "the backup is NOT written", "the refusal")
}

func TestManifestTranscriptOutsideTheGrammarIsRefused(t *testing.T) {
	r := newRig(t)
	// A line outside the vocabulary is not harmless: it can be the unparsed CONTINUATION of a
	// value that contained a newline, at which point the record grammar is no longer reliable
	// and none of the per-key checks can be trusted.
	r.cop.enumerate = func(string) (Transcript, error) {
		return Transcript{Text: manifestTranscript() + "\nsurprise=1\n"}, nil
	}
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a transcript outside the closed grammar was written as a manifest")
	}
	mustContain(t, r.stderr(), "unexpected key", "the refusal")
	mustContain(t, r.stderr(), "is not well-formed", "the refusal")
}

func TestManifestHelperThatDoesNotReportCompletionIsRefused(t *testing.T) {
	r := newRig(t)
	// It exited 0 and its transcript conforms — and it says it did not finish. The STATED
	// result governs, not the status beside it.
	r.cop.enumerate = func(string) (Transcript, error) {
		return Transcript{Text: strings.Replace(manifestTranscript(), "done=ok", "done=truncated", 1) + "\n"}, nil
	}
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a helper that reported it had not finished was read as a pass")
	}
	mustContain(t, r.stderr(), "did not report completion", "the refusal")
}

func TestTreeCaptureExcludesLockSidecars(t *testing.T) {
	r := newRig(t)
	// The lock is ephemeral and lives beside the ledger; restoring a stale one wedges the first
	// operation after the restore. The sidecar names the lock mechanism can leave behind are
	// excluded on the same rule, not just the bare name.
	write(t, filepath.Join(r.home, ".state", "lock.holder"), []byte("pid=1\n"))
	write(t, filepath.Join(r.home, ".state", "keepme"), []byte("real state\n"))
	if err := Run(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.stderr())
	}
	dir := canon(t, r.bk)
	for _, gone := range []string{"lock", "lock.holder", "ledger"} {
		if exists(filepath.Join(dir, "tree", ".state", gone)) {
			t.Fatalf(".state/%s was carried into the backup", gone)
		}
	}
	// And the exclusion is by NAME, not by living under .state — real state is captured.
	if !exists(filepath.Join(dir, "tree", ".state", "keepme")) {
		t.Fatal(".state/keepme was dropped; the exclusion is too wide")
	}
}

func TestTreeThatCannotBeFullyWalkedRefuses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads an unreadable directory, so the walk cannot be made to fail this way")
	}
	r := newRig(t)
	// A WALK THAT COULD NOT FINISH IS NOT AN EMPTY ONE: a directory this process cannot read
	// looks exactly like "walked the whole tree and found nothing else".
	blocked := filepath.Join(r.home, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a partial tree was written as a backup")
	}
	mustContain(t, r.stderr(), "could not fully walk the installer home", "the refusal")
	mustContain(t, r.stderr(), "refusing a partial tree", "the refusal")
}

// --- restore ------------------------------------------------------------------------------------

func TestRestoreRefusesABackupWithNoLedger(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	if err := os.Remove(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("restored from a backup carrying no ledger")
	}
	mustContain(t, r.stderr(), "carries no ledger", "the refusal")
	if exists(stagingPath(r.home)) {
		t.Fatal("something was staged from a backup with no ledger")
	}
}

func TestRestoreRefusesAnIncomingLedgerThatDoesNotValidate(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	f, err := os.OpenFile(filepath.Join(dir, "ledger"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("tampered\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("an incoming ledger that does not validate was staged")
	}
	mustContain(t, r.stderr(), "does not validate", "the refusal")
	// AND THE HALF-STAGED FILE IS REMOVED: leaving it would make the next command classify
	// this machine as carrying a corrupt in-progress restore that never began.
	if exists(stagingPath(r.home)) {
		t.Fatal("a ledger that does not validate was left at the staging path")
	}
}

func TestBackupEntryEscapingTheRootIsRefused(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	// An in-root entry that RESOLVES outside the verified root. Canonicalizing at the point of
	// use is what catches it; trusting wherever it leads is what the containment check refuses.
	outside := canon(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(outside, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "volumes", r.vols[0].name+".data")
	if err := os.RemoveAll(data); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "elsewhere"), data); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("an entry escaping the verified backup root was read")
	}
	mustContain(t, r.stderr(), "OUTSIDE the verified backup root", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled from outside the verified root")
	}
}

func TestResumeReAuthenticatesTheBackupRoot(t *testing.T) {
	r := interrupted(t)
	// Phase 1 checked this location, but a crash-and-resume can span an attacker making the
	// backup root writable and swapping what is inside it. A resume must re-run the check
	// against the location's state at THIS instant, not trust the phase-1 result.
	r.safe.unsafe[canon(t, r.bk)] = true
	r.cop.fillErr = nil
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a resume trusted the phase-1 safety result")
	}
	mustContain(t, r.stderr(), "unsafe", "the refusal")
	mustContain(t, r.stderr(), "the backup directory being restored", "the refusal names what was checked")
}

func TestStagedIdentityThatCannotBeReadRefuses(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	// Two identity records: every runtime name is scoped by the identity, so which one this
	// installation is cannot be guessed — and creating volumes under a guess would adopt or
	// orphan another installation's objects.
	appendLedgerRow(t, filepath.Join(dir, "ledger"), "identity\tid=i0000000000")
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("volumes were created under an identity this process could not establish")
	}
	mustContain(t, r.stderr(), "installation identity cannot be read", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled under an unestablished identity")
	}
}

func TestRestoreRefusesAMissingContentsDirectory(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	if err := os.RemoveAll(filepath.Join(dir, "volumes", r.vols[0].name+".data")); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume with no contents in the backup was restored")
	}
	mustContain(t, r.stderr(), "no contents directory for volume", "the refusal")
}

func TestRestoreRefusesAMissingPerEntryManifest(t *testing.T) {
	r := newRig(t)
	dir := r.backupOK()
	if err := os.Remove(filepath.Join(dir, "volumes", r.vols[0].name+".manifest")); err != nil {
		t.Fatal(err)
	}
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume with no per-entry manifest was filled")
	}
	mustContain(t, r.stderr(), "no per-entry manifest for volume", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled with nothing to verify it against")
	}
}

func TestVolumeLabelThatCannotBeReadRefuses(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// The daemon does not answer the re-inspection. That is NOT "the label is absent": a
	// restore that filled here would be filling a volume it cannot prove it just created.
	r.fake.InterruptOn = "GET /volumes/" + r.vols[0].name
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume was filled without verifying it carried our nonce")
	}
	mustContain(t, r.stderr(), "the container runtime did not answer", "the refusal")
	mustContain(t, r.stderr(), "intent is retained", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled on a question that was never answered")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}
}

func TestEmptinessCountThatIsNotANumberRefuses(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.count = func(string) (Transcript, error) {
		return Transcript{Text: "checked=some\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a non-numeric entry count was acted on")
	}
	mustContain(t, r.stderr(), "is not a number", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled on a count that is not a count")
	}
}

func TestEmptinessCheckStatingNothingRefuses(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.count = func(string) (Transcript, error) { return Transcript{}, nil }
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("an emptiness check that measured nothing was read as empty")
	}
	mustContain(t, r.stderr(), "stated nothing about the entry count", "the refusal")
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled without establishing that it was empty")
	}
}

// TestVerifyRefusesANonPlainManifestFile reaches verify's own manifest check directly. The
// restore path has its own check upstream, so this one is defence in depth — and defence in
// depth that nothing exercises is defence nothing can prove.
func TestVerifyRefusesANonPlainManifestFile(t *testing.T) {
	r := newRig(t)
	d := r.deps()
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	ch := Chain{Lock: r.lock, Store: st, Index: r.idx}
	dirAsManifest := t.TempDir()
	if err := d.verify(context.Background(), ch, r.vols[0].name, dirAsManifest); err == nil {
		t.Fatal("a directory was accepted as a per-entry manifest")
	}
	mustContain(t, r.stderr(), "missing or not a plain file", "the refusal")

	link := filepath.Join(t.TempDir(), "man")
	if err := os.Symlink(filepath.Join(dirAsManifest, "nothing"), link); err != nil {
		t.Fatal(err)
	}
	r.reset()
	if err := d.verify(context.Background(), ch, r.vols[0].name, link); err == nil {
		t.Fatal("a symlink was accepted as a per-entry manifest")
	}
	mustContain(t, r.stderr(), "missing or not a plain file", "the refusal")
}

func TestVerificationTranscriptOutsideTheGrammarIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "checked=4\ndone=ok\nextra=1\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a verification transcript outside the closed grammar was accepted")
	}
	mustContain(t, r.stderr(), "unexpected key", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over an unreadable verification")
	}
}

func TestMismatchThatNamesNothingIsStillAMismatch(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// A problem record is a problem by its PRESENCE. A value-iterating loop that skips empty
	// strings skips exactly the problem it was meant to catch.
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "mismatch=\nchecked=4\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a mismatch that names nothing was read as no mismatch")
	}
	mustContain(t, r.stderr(), "names nothing — treated as a mismatch", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated over a mismatch")
	}
}

func TestVerificationThatDidNotCompleteIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// The transcript is clean and the helper FAILED. Nothing in the transcript says so, which
	// is precisely why the status is still consulted when nothing else objected.
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Code: 4, Text: "checked=4\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a verification that did not complete was read as a pass")
	}
	mustContain(t, r.stderr(), "did not complete", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}
}

func TestVerifierNotReportingCompletionIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "checked=4\ndone=partial\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a verifier reporting it had not finished was read as a pass")
	}
	mustContain(t, r.stderr(), "rather than completion", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}

	// And a verifier that never mentions completion AT ALL is refused on the same rule: the
	// ABSENCE of the expected result is never the presence of a pass.
	r2 := newRig(t)
	r2.backupOK()
	r2.dropLedger()
	r2.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "checked=4\n"}, nil
	}
	if err := Restore(context.Background(), r2.deps(), r2.bk); err == nil {
		t.Fatal("a verifier that never stated completion was read as a pass")
	}
	mustContain(t, r2.stderr(), "stated nothing about completion", "the refusal")
	if regularFile(livePath(r2.home)) {
		t.Fatal("activated")
	}
}

func TestVerifierCheckedCountThatIsNotANumberIsRefused(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	r.cop.verify = func(string, []byte) (Transcript, error) {
		return Transcript{Text: "checked=lots\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a checked count that is not a count was bound to the manifest")
	}
	mustContain(t, r.stderr(), "checked count for", "the refusal")
	mustContain(t, r.stderr(), "is not a number", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}
}

// --- activation ----------------------------------------------------------------------------------

func TestActivateRefusesWhenAnActiveLedgerAppeared(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	// A completed restore is re-staged, and an active ledger is present again. Renaming over
	// it would destroy a live installation's provenance in one step.
	if err := copyFilePreserving(livePath(r.home), stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(livePath(r.home))
	if err != nil {
		t.Fatal(err)
	}
	r.reset()
	if err := Activate(r.deps()); err == nil {
		t.Fatal("activation overwrote an active ledger")
	}
	mustContain(t, r.stderr(), "an active ledger appeared", "the refusal")
	after, err := os.ReadFile(livePath(r.home))
	if err != nil || string(after) != string(before) {
		t.Fatal("the active ledger was replaced")
	}
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was consumed by a refused activation")
	}
}

func TestActivateRefusesACorruptStagingLedger(t *testing.T) {
	r := newRig(t)
	r.dropLedger()
	write(t, stagingPath(r.home), []byte("not a ledger\n"))
	if err := Activate(r.deps()); err == nil {
		t.Fatal("a staging ledger that does not validate was activated")
	}
	mustContain(t, r.stderr(), "refusing to activate it", "the refusal")
	if regularFile(livePath(r.home)) {
		t.Fatal("activated")
	}
}

// --- abandonment ----------------------------------------------------------------------------------

func TestAbandonRefusesWhenALabelCannotBeRead(t *testing.T) {
	r := interrupted(t)
	// Absence means nothing to remove; an unreachable daemon means this loop cannot tell
	// whether the volume is ours at all, and treating it as gone would silently skip a real
	// one — with the record that proves it ours about to be destroyed.
	r.fake.InterruptOn = "GET /volumes/" + r.vols[0].name
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("abandonment completed on a question that was never answered")
	}
	mustContain(t, r.stderr(), "could not determine whether", "the refusal")
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger — the only record of which partial volumes exist — was destroyed")
	}
}

func TestAbandonKeepsTheStagingLedgerWhenARemovalFails(t *testing.T) {
	r := interrupted(t)
	// The daemon refuses the removal. Reporting "removed" here is worse than a bare failure:
	// an operator reading it has no reason to look again, while the volume and the record
	// about to be destroyed are both still live.
	victim := r.vols[0].name
	r.fake.InterruptOn = "DELETE /volumes/" + victim
	if err := Abandon(context.Background(), r.deps()); err == nil {
		t.Fatal("a refused removal was reported as an abandonment")
	}
	mustContain(t, r.stderr(), "COULD NOT remove partial volume", "the refusal")
	mustNotContain(t, r.stderr(), "removed partial volume "+victim+".", "the report")
	if !regularFile(stagingPath(r.home)) {
		t.Fatal("the staging ledger was destroyed while a volume it records is still labelled ours")
	}
	if _, err := r.nonceOf(victim); err != nil {
		t.Fatalf("%s: %v", victim, err)
	}
}

// --- phase 5 keeps what the volume loop recorded ---------------------------------------------------

// TestPhase5PreservesWhatTheVolumeLoopRecorded: the loop authenticates documents against the
// STAGED store, and a trust-floor advance is a ledger write like any other. Phase 5 must
// re-read before removing the intent — writing back the copy read before the loop would
// silently discard everything the loop recorded, and the rollback floors are exactly what a
// backup exists to carry forward.
func TestPhase5PreservesWhatTheVolumeLoopRecorded(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	// The real copy module advances the family index's own floor as part of authenticating the
	// pinned image; this stands in for that write, against the same store, at the same moment.
	r.cop.fillErr = nil
	orig := r.cop.verify
	r.cop.verify = func(vol string, man []byte) (Transcript, error) {
		if err := trust.FloorSet(r.lock, r.stagedStore(t), "manifest:other", "7"); err != nil {
			t.Fatal(err)
		}
		if orig != nil {
			return orig(vol, man)
		}
		return Transcript{Text: "checked=4\ndone=ok\n"}, nil
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	v, err := trust.FloorGet(st, "manifest:other")
	if err != nil || v != "7" {
		t.Fatalf("what the volume loop recorded did not survive phase 5: %q %v", v, err)
	}
}

// stagedStore is the staging store for a test that needs to write to it the way a real seam
// would — the same store the module hands the Copier through its Chain.
func (r *rig) stagedStore(t *testing.T) ledger.Store {
	t.Helper()
	st, err := ledger.OpenStaging(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// rewriteChain re-emits the document chain with the manifest transformed, re-deriving every
// digest and re-anchoring, so the chain still authenticates.
func (r *rig) rewriteChain(t *testing.T, f func(manifest string) string) {
	t.Helper()
	manPath := filepath.Join(r.mdir, "p1.manifest")
	polBytes, err := os.ReadFile(r.pol)
	if err != nil {
		t.Fatal(err)
	}
	manBytes, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	man := []byte(f(string(manBytes)))
	write(t, manPath, man)
	ix := []byte("mythical-index 1\nversion=2\nexpires=99999999999\npolicy_digest=" + cliio.SHA256Hex(polBytes) +
		"\nprobe_image=ghcr.io/x/probe@sha256:" + hex64 +
		"\ncopy_image=ghcr.io/x/copy@sha256:" + hex64 +
		"\nmanifest=p1:" + cliio.SHA256Hex(man) + "\n")
	write(t, r.idx, ix)
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(r.lock, st, cliio.SHA256Hex(ix)); err != nil {
		t.Fatal(err)
	}
}

// --- the transcript readers ------------------------------------------------------------------------

func TestTranscriptGrammarRefusesABlankLine(t *testing.T) {
	r := newRig(t)
	d := r.deps()
	// The capture strips trailing newlines, so a clean transcript has no empty line at all —
	// an INTERIOR one is genuine, and it can be the truncated continuation of a value that
	// contained a newline, at which point the record boundaries are no longer trustworthy.
	if err := d.grammarOK("checked=1\n\ndone=ok\n", "checked", "done"); err == nil {
		t.Fatal("an interior blank line was passed over")
	}
	mustContain(t, r.stderr(), "contains a blank line", "the refusal")
	// A line that is not a key=value record at all is refused, not ignored.
	r.reset()
	if err := d.grammarOK("checked=1\nrubbish\ndone=ok\n", "checked", "done"); err == nil {
		t.Fatal("a non-record line was passed over")
	}
	mustContain(t, r.stderr(), "not a key=value record", "the refusal")
	// A WHOLLY-EMPTY transcript is deferred to the stated-observation reader, which names
	// WHICH observation was missing.
	r.reset()
	if err := d.grammarOK("", "checked"); err != nil {
		t.Fatalf("an empty transcript was refused here rather than deferred: %v", err)
	}
	if err := d.grammarOK("checked=1\ndone=ok\n", "checked", "done"); err != nil {
		t.Fatalf("a conforming transcript was refused: %v", err)
	}
}

func TestStatedRefusesADuplicateObservation(t *testing.T) {
	r := newRig(t)
	d := r.deps()
	// An answer that says `done=ok` and then `done=fail` does not say `ok`; it says two
	// things, and reading down to whichever copy came first is how the second is lost.
	if _, err := d.stated("done=ok\ndone=fail\n", "done", "restore verification", "completion"); err == nil {
		t.Fatal("a doubly-stated observation was read")
	}
	mustContain(t, r.stderr(), "REFUSED as ambiguous", "the refusal")
	// An EMPTY value is a real answer and is handed back as one.
	r.reset()
	v, err := d.stated("done=\n", "done", "x", "completion")
	if err != nil || v != "" {
		t.Fatalf("an empty stated value is an answer: %q %v", v, err)
	}
}

// --- the record walk's own completeness rule ---------------------------------------------------

// TestVolumeWalkRefusesAnUnreadableListing: one record it cannot read refuses the WHOLE
// listing. A listing that silently omits what it could not read lets a caller act on a subset
// believing it had the set — which for a backup is a volume left out, and for a restore a
// volume never created. The damaged row is PRESERVED: a row this module cannot read is
// evidence, not tidying material.
func TestVolumeWalkRefusesAnUnreadableListing(t *testing.T) {
	r := newRig(t)
	// A record row of the right kind carrying no fields at all: it describes nothing, so it
	// matches nothing and grants nothing — and it is exactly what the completeness rule exists
	// to refuse a listing over. The typed editors will not write one, so it is put there the
	// way a damaged ledger actually carries it: in the file, with a recomputed checksum.
	appendLedgerRow(t, livePath(r.home), kindObject)
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a listing that could not be fully read was acted on")
	}
	mustContain(t, r.stderr(), "could not be listed in full", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("a backup was written on a partial view of its own volumes")
	}
}

// TestBackupIntoTheInstallerHomeDoesNotCopyItself: nothing stops an operator naming an output
// directory INSIDE the installer home, and the output directory already exists by the time the
// tree is captured (the ledger was written into it). A LIVE walk would descend into the tree it
// is itself creating and copy it into itself, again, without bound — a disk-filling loop
// reachable from an ordinary invocation. The list is taken before the first byte is written and
// the output subtree is skipped outright.
func TestBackupIntoTheInstallerHomeDoesNotCopyItself(t *testing.T) {
	r := newRig(t)
	inside := filepath.Join(r.home, "backups", "one")
	// Only the LEAF may be absent — the reference's canonicalizer requires the parent to
	// resolve, exactly as this one does.
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), r.deps(), inside); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.stderr())
	}
	dir := canon(t, inside)
	// The installation's own files are captured...
	if !exists(filepath.Join(dir, "tree", "mythical.conf")) {
		t.Fatal("the tree was not captured")
	}
	// ...and the backup does not appear inside its own tree copy, at any depth.
	nested := 0
	if err := filepath.WalkDir(filepath.Join(dir, "tree"), func(p string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() && filepath.Base(p) == "one" {
			nested++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if nested != 0 {
		t.Fatalf("the backup copied itself into its own tree %d time(s)", nested)
	}
}

// TestStagingAWriteDoesNotFollowASymlink: a failed or partial restore can leave the staging
// path as a DANGLING SYMLINK — a state this codebase already recognises elsewhere — and an
// open-and-truncate on that name would follow it, writing the incoming ledger to wherever it
// points. The staged ledger goes in through the ledger writer, which refuses a name that is
// present but not a regular file and PRESERVES it: the link is evidence about what happened
// here, and a restore that cannot use the staging name must say so rather than write past it.
func TestStagingAWriteDoesNotFollowASymlink(t *testing.T) {
	r := newRig(t)
	r.backupOK()
	r.dropLedger()
	elsewhere := filepath.Join(canon(t, t.TempDir()), "elsewhere")
	if err := os.Symlink(elsewhere, stagingPath(r.home)); err != nil {
		t.Fatal(err)
	}
	if err := Restore(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a restore wrote to a staging name that is not a regular file")
	}
	if exists(elsewhere) {
		t.Fatal("the staged ledger was written through the symlink, to a path outside .state")
	}
	fi, lerr := os.Lstat(stagingPath(r.home))
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was not preserved as evidence")
	}
	if len(r.cop.fills) != 0 {
		t.Fatal("a volume was filled by a restore that never staged its ledger")
	}
}

// TestPhase1LeavesNoIntentFreeStagingLedger is the whole point of building the staged ledger in
// memory. If the intent were a SECOND write, a failure of that write would leave the staging
// name holding a checksum-valid, intent-free ledger — byte-for-byte the state a COMPLETED phase
// 5 leaves — and the next invocation would ACTIVATE it without creating, filling or verifying a
// single volume.
//
// The trigger is not hypothetical and needs no crash: the record format refuses a field value
// carrying a newline (it would forge a whole record), so a backup directory whose name contains
// one makes the intent edit fail deterministically, every time, on a path an operator can
// create with an ordinary mkdir.
func TestPhase1LeavesNoIntentFreeStagingLedger(t *testing.T) {
	r := newRig(t)
	weird := filepath.Join(canon(t, t.TempDir()), "we\nird")
	if err := os.MkdirAll(weird, 0o755); err != nil {
		t.Skipf("this filesystem will not hold a newline in a directory name: %v", err)
	}
	bk := filepath.Join(weird, "backup")
	if err := Run(context.Background(), r.deps(), bk); err != nil {
		t.Fatalf("the backup itself must still succeed: %v\n%s", err, r.stderr())
	}
	r.dropLedger()
	r.reset()

	err := Restore(context.Background(), r.deps(), bk)
	if err == nil {
		t.Fatal("a source the record format cannot carry was recorded anyway")
	}
	mustContain(t, r.stderr(), "cannot record the restore intent", "the refusal")
	// NOTHING was staged — not a valid ledger, not an invalid one, nothing.
	if exists(stagingPath(r.home)) {
		t.Fatalf("a staging ledger survives a phase 1 that could not record its own intent: %v", err)
	}
	// So the next invocation has nothing to activate, rather than a ledger that looks finished.
	s, serr := CurrentState(r.deps())
	if serr != nil || s != StateNone {
		t.Fatalf("state after the failed phase 1: %q %v", s, serr)
	}
	if err := Restore(context.Background(), r.deps(), bk); err == nil {
		t.Fatal("the second invocation activated something")
	}
	if regularFile(livePath(r.home)) {
		t.Fatal("a ledger was activated over volumes that were never created")
	}
}

// TestVolumeWalkRefusesTwoRecordsForOneVolume: two rows for one volume are a contradiction the
// ledger cannot settle. Acting on the first fills the volume; the second is then met as
// non-empty and verifying, called "already done", and the restore ACTIVATES a ledger in which
// that volume can never be authorized again — the provenance selector refuses an ambiguous
// lookup, so the restored installation is wedged by its own consistency rules working correctly
// on inconsistent input.
func TestVolumeWalkRefusesTwoRecordsForOneVolume(t *testing.T) {
	r := newRig(t)
	// The duplicate goes in the way a damaged or foreign ledger actually carries it: a second
	// identical row in the file, with a recomputed checksum. The typed editor replaces by key,
	// so it cannot produce this state itself.
	row := volumeRowOf(t, r, r.vols[0].name)
	appendLedgerRow(t, livePath(r.home), row)

	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a backup acted on a ledger that says two contradictory things about one volume")
	}
	mustContain(t, r.stderr(), "cannot be read as the authority for it", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup was written anyway")
	}
}

// TestVolumeWalkRefusesARecordKeyedForSomethingElse: `key`, `class` and `name` are three
// INDEPENDENT fields and nothing in the format makes them agree. A row keyed `volume:X` while
// naming Y would have a restore create and fill Y on X's authority — and the restored
// installation could then never authorize Y, because the selector it authorizes through would
// refuse that very row.
func TestVolumeWalkRefusesARecordKeyedForSomethingElse(t *testing.T) {
	r := newRig(t)
	r.putObject(t, "volume:not-the-name",
		ledger.Field{Key: "class", Value: "volume"},
		ledger.Field{Key: "name", Value: "some-other-volume"},
		ledger.Field{Key: "nonce", Value: "deadbeef"},
		ledger.Field{Key: "product", Value: "p1"})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a row keyed for one object was acted on as the authority for another")
	}
	mustContain(t, r.stderr(), "cannot be read as the authority for it", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup was written anyway")
	}
}

// TestVolumeWalkRefusesASecondRowReachingOneVolume: the selector settles cardinality by KEY,
// which leaves one shape open — a row keyed for something else that NAMES a volume which does
// have its own row. Both walk to the same volume.
func TestVolumeWalkRefusesASecondRowReachingOneVolume(t *testing.T) {
	r := newRig(t)
	victim := r.vols[0].name
	r.putObject(t, "volume:phantom",
		ledger.Field{Key: "class", Value: "volume"},
		ledger.Field{Key: "name", Value: victim},
		ledger.Field{Key: "nonce", Value: "deadbeef"},
		ledger.Field{Key: "product", Value: "p1"})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("two rows reaching one volume were both acted on")
	}
	mustContain(t, r.stderr(), "more than one 'volume' object record reaches volume", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup was written anyway")
	}
}

// volumeRowOf renders the ledger row currently held for a volume, verbatim.
func volumeRowOf(t *testing.T, r *rig, name string) string {
	t.Helper()
	b, err := os.ReadFile(livePath(r.home))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, kindObject+"\t") && strings.Contains(line, "name="+name+"\t") {
			return line
		}
	}
	t.Fatalf("no object row for %s", name)
	return ""
}

// TestCopierSeamCarriesNoStateCapability is a STRUCTURAL guard on the staging boundary, and it
// is the half a call-graph gate cannot see.
//
// check.sh pins ledger.OpenStaging to this package, so nothing else can CONSTRUCT a staging
// store. That is worth nothing if this package then hands one out: an injected Copier holding a
// staging ledger.Store and the family lock could read, retain and WRITE the staging ledger
// without ever naming OpenStaging, and the gate would stay green the whole time. So the seam
// carries an authenticated *trust.Index — an answer — and never a capability.
//
// Reflection, not review: a signature that regains a Store, a lock or a raw ledger reddens here
// rather than being noticed by whoever reads the diff.
func TestCopierSeamCarriesNoStateCapability(t *testing.T) {
	forbidden := map[reflect.Type]string{
		reflect.TypeOf((*ledger.Store)(nil)).Elem(): "a ledger store",
		reflect.TypeOf((*famlock.Held)(nil)).Elem(): "the family lock",
		reflect.TypeOf((*ledger.Ledger)(nil)):       "a raw ledger",
		reflect.TypeOf(Chain{}):                     "this module's own chain (store + lock)",
		reflect.TypeOf((*Deps)(nil)).Elem():         "this module's dependencies",
	}
	iface := reflect.TypeOf((*Copier)(nil)).Elem()
	if iface.NumMethod() == 0 {
		t.Fatal("the Copier seam has no methods; this guard would pass vacuously")
	}
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		ft := m.Type
		for j := 0; j < ft.NumIn(); j++ {
			if what, bad := forbidden[ft.In(j)]; bad {
				t.Fatalf("Copier.%s takes %s (parameter %d). The seam must carry answers, not "+
					"capabilities — an implementation holding one could write the staging ledger "+
					"without ever naming ledger.OpenStaging, and the boundary gate would stay green.",
					m.Name, what, j)
			}
		}
		for j := 0; j < ft.NumOut(); j++ {
			if what, bad := forbidden[ft.Out(j)]; bad {
				t.Fatalf("Copier.%s returns %s (result %d)", m.Name, what, j)
			}
		}
	}
}
