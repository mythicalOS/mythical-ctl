package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — tests/unit/backup.bats, the backup half. The restore half is claimed in
// restore_test.go; the CLI/verb surface is claimed in cmd/mythical-ctl/backup_test.go.
//
// PORTED: tests/unit/backup.bats: "the backup manifest records TYPE, digest, link target, hardlink group, mode, owner and mtime" -> TestManifestWriteRecordsTheWholeContract
// PORTED: tests/unit/backup.bats: "a manifest transcript stating nothing is refused, not written as an empty manifest" -> TestManifestTranscriptStatingNothingIsRefused
// PORTED: tests/unit/backup.bats: "a backup that omits the ledger is refused — it would discard every rollback floor" -> TestBackupRefusesWithoutTheLedger
// PORTED: tests/unit/backup.bats: "a corrupt ledger refuses the backup rather than capturing state that cannot be read" -> TestBackupRefusesACorruptLedger
// PORTED: tests/unit/backup.bats: "a full backup writes the ledger, the tree, and every volume's contents, manifest and nonce" -> TestFullBackupWritesEverything
// PORTED: tests/unit/backup.bats: "the recorded nonce in the backup matches the ledger's own provenance for that volume" -> TestBackupNonceMatchesProvenance
// PORTED: tests/unit/backup.bats: "a backup refuses an unsafe (group-writable) output location, naming the reason" -> TestBackupRefusesAnUnsafeOutputLocation
// PORTED: tests/unit/backup.bats: "fix6: a volume object record missing its own name is refused, not silently skipped" -> TestBackupFailsClosedOnAVolumeRecordWithNoName
// PORTED: tests/unit/backup.bats: "fix6: a volume object record missing its own nonce is refused, not silently skipped" -> TestBackupFailsClosedOnAVolumeRecordWithNoNonce
//
// N/A: tests/unit/backup.bats: "mi_backup_run rejects the wrong number of arguments" -- an arity guard on a shell function has no Go analogue: Run takes exactly (ctx, Deps, string) and the compiler refuses anything else. The load-bearing half of that contract — a malformed INVOCATION is a usage error with nothing attempted — is the CLI's, claimed in cmd/mythical-ctl/backup_test.go by TestBackupOperandMatrix.
//
// Deferred rows owned HERE — tests/acceptance/restore.bats:
// PORTED: tests/acceptance/restore.bats: "fix5: backup and restore copy each volume using its product's declared runtime_uid, not 0" -> TestCopiesUseTheDeclaredRuntimeUID
// PORTED: tests/acceptance/restore.bats: "fix5: a volume whose product cannot be authenticated refuses rather than guessing uid 0" -> TestUnauthenticatedProductRefusesRatherThanGuessingUID
// PORTED: tests/acceptance/restore.bats: "fix1: an inherited MI_LEDGER_PATH_OVERRIDE cannot make an ordinary CLI command see the staging ledger" -> TestNoLedgerPathOverrideSeamExists

func TestManifestWriteRecordsTheWholeContract(t *testing.T) {
	r := newRig(t)
	d := r.deps()
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "state.manifest")
	if err := ManifestWrite(context.Background(), d, Chain{Lock: r.lock, Store: st, Index: r.idx}, r.vols[0].name, out); err != nil {
		t.Fatalf("ManifestWrite: %v\n%s", err, r.stderr())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"manifest=dir:", "manifest=file:", "manifest=symlink:", "manifest=hardlink:",
		"digest=", "linktarget=", "mode=", "owner=", "mtime=", "hardlink=", "done=ok",
	} {
		mustContain(t, got, want, "the backup manifest")
	}
}

func TestManifestTranscriptStatingNothingIsRefused(t *testing.T) {
	r := newRig(t)
	r.cop.enumerate = func(string) (Transcript, error) { return Transcript{}, nil }
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "state.manifest")
	err = ManifestWrite(context.Background(), r.deps(), Chain{Lock: r.lock, Store: st, Index: r.idx}, r.vols[0].name, out)
	if err == nil {
		t.Fatal("a transcript that states nothing was accepted")
	}
	mustContain(t, r.stderr(), "stated nothing", "the refusal")
	if exists(out) {
		t.Fatal("an empty manifest was written — a transcript that states nothing must leave no file at all")
	}
}

func TestBackupRefusesWithoutTheLedger(t *testing.T) {
	r := newRig(t)
	r.dropLedger()
	err := Run(context.Background(), r.deps(), r.bk)
	if err == nil {
		t.Fatal("a backup with no ledger was written")
	}
	mustContain(t, r.stderr(), "no installer state ledger", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup captured a ledger it said it could not find")
	}
}

func TestBackupRefusesACorruptLedger(t *testing.T) {
	r := newRig(t)
	f, err := os.OpenFile(livePath(r.home), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("garbage"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a backup captured a ledger that does not validate")
	}
	mustContain(t, r.stderr(), "does not validate", "the refusal")
}

func TestFullBackupWritesEverything(t *testing.T) {
	r := newRig(t)
	if err := Run(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.stderr())
	}
	dir := canon(t, r.bk)
	for _, p := range []string{
		filepath.Join(dir, "ledger"),
		filepath.Join(dir, "tree", "mythical.conf"),
		filepath.Join(dir, "tree", "bin", "tool"),
		filepath.Join(dir, "tree", "bin", "alias"),
	} {
		if !exists(p) {
			t.Fatalf("the backup is missing %s", p)
		}
	}
	if tgt, err := os.Readlink(filepath.Join(dir, "tree", "bin", "alias")); err != nil || tgt != "tool" {
		t.Fatalf("the symlink was not recreated verbatim: %q %v", tgt, err)
	}
	for _, v := range r.vols {
		base := filepath.Join(dir, "volumes", v.name)
		b, err := os.ReadFile(base + ".nonce")
		if err != nil || len(b) == 0 {
			t.Fatalf("the recorded nonce for %s is missing or empty: %v", v.name, err)
		}
		if !exists(base + ".manifest") {
			t.Fatalf("the per-entry manifest for %s is missing", v.name)
		}
		fi, err := os.Stat(base + ".data")
		if err != nil || !fi.IsDir() {
			t.Fatalf("the contents directory for %s is missing", v.name)
		}
	}
	// The ephemeral lock is never carried into a backup — restoring one would wedge the first
	// operation after the restore — and neither ledger is duplicated under tree/.
	for _, p := range []string{"lock", "ledger", "ledger.staging"} {
		if exists(filepath.Join(dir, "tree", ".state", p)) {
			t.Fatalf("the backup carried .state/%s into its tree copy", p)
		}
	}
}

func TestBackupNonceMatchesProvenance(t *testing.T) {
	r := newRig(t)
	if err := Run(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.stderr())
	}
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range r.vols {
		fields, err := prov.Find(l, prov.ClassVolume, v.name)
		if err != nil {
			t.Fatal(err)
		}
		recorded, _ := ledger.FieldOf(fields, "nonce")
		b, err := os.ReadFile(filepath.Join(canon(t, r.bk), "volumes", v.name+".nonce"))
		if err != nil {
			t.Fatal(err)
		}
		if recorded == "" || strings.TrimSuffix(string(b), "\n") != recorded {
			t.Fatalf("%s: backup nonce %q vs recorded %q", v.name, strings.TrimSuffix(string(b), "\n"), recorded)
		}
	}
}

func TestBackupRefusesAnUnsafeOutputLocation(t *testing.T) {
	r := newRig(t)
	parent := canon(t, t.TempDir())
	r.safe.unsafe[parent] = true
	out := filepath.Join(parent, "backup")
	if err := Run(context.Background(), r.deps(), out); err == nil {
		t.Fatal("a backup was written into an unsafe location")
	}
	mustContain(t, r.stderr(), "writable", "the refusal names the reason")
	mustContain(t, r.stderr(), "refusing to use an unsafe location", "the refusal")
	if exists(out) {
		t.Fatal("the refused location was created anyway")
	}
	// The LEAF does not exist, so it is the already-canonical PARENT whose chain is checked —
	// the leaf is safe by construction the instant this process creates it under a parent
	// nothing else can write into.
	if !r.safe.sawPath(parent) {
		t.Fatalf("the parent chain was never checked; asked about %v", r.safe.asked)
	}
}

func TestBackupFailsClosedOnAVolumeRecordWithNoName(t *testing.T) {
	r := newRig(t)
	// A checksum-valid, well-formed-per-field record — class=volume, a nonce — that is
	// nonetheless semantically incomplete: no name= at all. Skipping past it treats this
	// exactly like "not a volume record", so a backup could omit a ledger-declared volume with
	// no trace anything was skipped.
	r.putObject(t, "volume:ghost", ledger.Field{Key: "class", Value: "volume"}, ledger.Field{Key: "nonce", Value: "deadbeef"})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a semantically incomplete volume record was skipped")
	}
	mustContain(t, r.stderr(), "carries no name", "the refusal")
	if exists(filepath.Join(r.bk, "ledger")) {
		t.Fatal("the backup was written despite refusing")
	}
}

func TestBackupFailsClosedOnAVolumeRecordWithNoNonce(t *testing.T) {
	r := newRig(t)
	r.putObject(t, "volume:ghost2", ledger.Field{Key: "class", Value: "volume"}, ledger.Field{Key: "name", Value: "ghost2"})
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume record with no nonce was skipped")
	}
	mustContain(t, r.stderr(), "carries no nonce", "the refusal")
}

// putObject writes one raw `object` record into the live ledger, keyed as the given string.
func (r *rig) putObject(t *testing.T, key string, extra ...ledger.Field) {
	t.Helper()
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	fields := append([]ledger.Field{{Key: "key", Value: key}}, extra...)
	if err := l.Put("object", "key", key, fields); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(r.lock, st, l); err != nil {
		t.Fatal(err)
	}
}

// --- fix5: the declared runtime uid, never a fixed stand-in ------------------------------------

func TestCopiesUseTheDeclaredRuntimeUID(t *testing.T) {
	r := newRig(t)
	if err := Run(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.stderr())
	}
	if len(r.cop.runs) != len(r.vols) {
		t.Fatalf("expected one copy per volume, got %d", len(r.cop.runs))
	}
	for _, c := range r.cop.runs {
		if c.runtimeUID != "900" {
			t.Fatalf("%s copied as uid %q — the product declares 900; uid 0 is the old fixed stand-in", c.volume, c.runtimeUID)
		}
		if c.operatorUID != "501" {
			t.Fatalf("%s: operator uid %q", c.volume, c.operatorUID)
		}
	}
	r.dropLedger()
	r.reset()
	if err := Restore(context.Background(), r.deps(), r.bk); err != nil {
		t.Fatalf("Restore: %v\n%s", err, r.stderr())
	}
	if len(r.cop.fills) != len(r.vols) {
		t.Fatalf("expected one fill per volume, got %d", len(r.cop.fills))
	}
	for _, c := range r.cop.fills {
		if c.runtimeUID != "900" {
			t.Fatalf("%s filled as uid %q, not the declared 900", c.volume, c.runtimeUID)
		}
	}
}

func TestUnauthenticatedProductRefusesRatherThanGuessingUID(t *testing.T) {
	r := newRig(t)
	// Corrupt the product's own manifest so the chain cannot authenticate it, WITHOUT touching
	// the ledger: the volume record itself is fine, and this is specifically about the manifest
	// lookup failing rather than a malformed record.
	f, err := os.OpenFile(filepath.Join(r.mdir, "p1.manifest"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("garbage\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Run(context.Background(), r.deps(), r.bk); err == nil {
		t.Fatal("a volume whose product could not be authenticated was copied anyway")
	}
	mustContain(t, r.stderr(), "runtime uid", "the refusal")
	if len(r.cop.runs) != 0 {
		t.Fatal("a copy ran under a uid this process could not establish")
	}
}

// --- the two structural guards ------------------------------------------------------------------

// TestPathsAgreeWithLedgerStores pins this module's two path derivations to the STORES they
// stand for. internal/ledger seals its stores — nothing outside it can ask a Store where it
// points, which is what makes OpenStaging's boundary gate meaningful — so this module derives
// the two well-known paths itself for the file-level operations a restore performs (an atomic
// rename into place, a corrupt file preserved aside). Two derivations of one location drift
// silently; this makes them redden instead.
func TestPathsAgreeWithLedgerStores(t *testing.T) {
	home := canon(t, t.TempDir())
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer famlock.Release(h)

	live, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(h, live, &ledger.Ledger{}); err != nil {
		t.Fatal(err)
	}
	if !regularFile(livePath(home)) {
		t.Fatalf("ledger.Live does not write to %s", livePath(home))
	}

	staging, err := ledger.OpenStaging(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(h, staging, &ledger.Ledger{}); err != nil {
		t.Fatal(err)
	}
	if !regularFile(stagingPath(home)) {
		t.Fatalf("ledger.OpenStaging does not write to %s", stagingPath(home))
	}
	if livePath(home) == stagingPath(home) {
		t.Fatal("the staging ledger is not a distinct path — it would be authoritative by accident")
	}
}

// TestVolumeRecordsAreProvRecords pins this module's volume walk to the records internal/prov
// actually writes: the kind, the class field, and the three fields the walk requires.
func TestVolumeRecordsAreProvRecords(t *testing.T) {
	r := newRig(t)
	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	vols, err := r.deps().volumeRecords(l, "backup")
	if err != nil {
		t.Fatalf("the walk did not find the records prov.Record wrote: %v", err)
	}
	if len(vols) != len(r.vols) {
		t.Fatalf("walked %d volume records, expected %d", len(vols), len(r.vols))
	}
	for i, v := range vols {
		if v != r.vols[i] {
			t.Fatalf("record %d: %+v vs %+v", i, v, r.vols[i])
		}
	}
}

// TestNoLedgerPathOverrideSeamExists is the Go standing guard for the reference's fix 1. The
// bash reached the staging ledger through an environment-variable pair, which an inherited
// export could turn on for a WHOLE invocation — every lifecycle command, not just restore —
// making an in-progress, not-yet-verified restore look like the live installation. The bash
// closed that by scrubbing the two names at the entrypoint.
//
// THE GO DESIGN HAS NO SUCH SEAM AT ALL: a store's path derives from the lock token and
// consults nothing else, and staging is simply a different store that only this package can
// construct. That is a stronger guarantee than a scrub, and this test is what keeps it true —
// it sets both names in the process environment and proves the live store still reads the live
// ledger and the staging write still lands on the staging path.
func TestNoLedgerPathOverrideSeamExists(t *testing.T) {
	home := canon(t, t.TempDir())
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer famlock.Release(h)

	t.Setenv("MI_LEDGER_PATH_OVERRIDE", filepath.Join(home, ".state", "ledger.staging"))
	t.Setenv("_MI_LEDGER_STAGING_INTERNAL", "1")

	staging, err := ledger.OpenStaging(h)
	if err != nil {
		t.Fatal(err)
	}
	sl := &ledger.Ledger{}
	if err := sl.Put(restoreKind, "key", "restore", []ledger.Field{{Key: "key", Value: "restore"}}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(h, staging, sl); err != nil {
		t.Fatal(err)
	}

	live, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Read(live); !errors.Is(err, ledger.ErrMissingLedger) {
		t.Fatalf("with the override exported, the LIVE store saw something: %v", err)
	}
	if regularFile(livePath(home)) {
		t.Fatal("the staging write landed on the live path")
	}
	if !regularFile(stagingPath(home)) {
		t.Fatal("the staging write did not land on the staging path")
	}
}
