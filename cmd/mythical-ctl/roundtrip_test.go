package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/migrate"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
)

// safeBase is a directory whose WHOLE ancestor chain this process (or root) owns and nobody else
// can write to. It exists because the location gate these verbs now enforce is not a formality:
// the system temp root is world-writable on most Linux hosts, so a plain t.TempDir() is a
// directory `backup` correctly REFUSES, and a test that used one would be asserting the refusal
// rather than the round trip. The operator's own home is the fallback, exactly as
// internal/migrate's harness does it — and the safety question is asked through the SAME exported
// check the verb uses, never a second reading of it.
//
// Failing rather than skipping is deliberate: on a host with no owner-safe chain at all,
// migrate-storage, backup and restore would every one of them refuse to operate anywhere, and
// there would be nothing for this suite to assert.
func safeBase(t *testing.T) string {
	t.Helper()
	if d := t.TempDir(); chainSafe(d) {
		return d
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		d, derr := os.MkdirTemp(home, ".mctl-cli-test-")
		if derr == nil {
			_ = os.Chmod(d, 0o700)
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			if chainSafe(d) {
				return d
			}
		}
	}
	t.Fatalf("no directory chain this process owns is available for the test base: neither the temp\n" +
		"  root nor the operator's home has an owner-safe ancestor chain. backup, restore and\n" +
		"  migrate-storage would every one of them refuse to operate anywhere on this host.")
	return ""
}

func chainSafe(dir string) bool {
	c, err := runtime.Canon(dir)
	if err != nil {
		return false
	}
	return migrate.VerifyChainOwnerSafe(c, "the test base") == nil
}

// Inventory — the CLI round trip the backup/restore port could not claim while the copy seam was
// unwired. It is claimed HERE now, and the N/A row that stood in for it in backup_test.go is
// retired with it.
//
// PORTED: tests/acceptance/restore.bats: "backup then restore: through the actual CLI (bin/mythical-ctl)" -> TestBackupRestoreRoundTripThroughTheCLI

// bkRig is a cliRig whose fake helper image implements the WHOLE copy contract — the ordinary
// copy/verify/preflight/access commands AND the three read-only `verify` modes the backup and
// restore direction is built on. It is the pinned image's contract standing in for the image.
func bkRig(t *testing.T) (*cliRig, *enginetest.HelperImage) {
	t.Helper()
	r := newCLIRig(t)
	img := &enginetest.HelperImage{}
	base := r.fake.HelperEntry
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		switch cmd {
		case "preflight", "copy", "verify", "acl", "access":
			return img.Entry(cmd, args, view, stdin)
		}
		return base(cmd, args, view, stdin)
	}
	r.fake.PullImage(cliDigestRef("copy"))
	r.env = append(r.env, "MI_CONFIRM=yes")
	return r, img
}

// identOf reads the recorded installation identity, or "" when there is none.
func identOf(t *testing.T, home string) string {
	t.Helper()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, serr := ledger.Live(h)
	if serr != nil {
		t.Fatal(serr)
	}
	l, rerr := ledger.Read(st)
	if rerr != nil {
		return ""
	}
	id, ierr := l.IdentGet()
	if ierr != nil {
		return ""
	}
	return id
}

// TestBackupRestoreRoundTripThroughTheCLI is the whole point of wiring the copy seam: `backup`
// and `restore` are verbs that DO something, end to end, through the real dispatcher.
//
// IT ASSERTS THE ARCHIVE'S CONTENTS, NOT ONLY THE EXIT CODE. A backup that exits 0 having written
// an empty manifest is precisely the failure the manifest exists to prevent, and it is
// indistinguishable from a real one by status alone. So the per-volume manifest is read back and
// its entries counted, and the restore is then required to verify against THAT count — which is
// only possible if the manifest bytes actually reached the copy container on its stdin. A seam
// that dropped them would leave the helper counting zero entries against a manifest naming five,
// and the restore would refuse.
func TestBackupRestoreRoundTripThroughTheCLI(t *testing.T) {
	r, _ := bkRig(t)
	r.writeProduct("p1")

	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	if ident == "" {
		t.Fatal("the install recorded no identity")
	}
	bk := filepath.Join(safeBase(t), "backup")
	if rc := r.run(append([]string{"backup", bk}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("backup rc = %d\n%s", rc, r.said())
	}

	// --- the archive is REAL ---------------------------------------------------------------
	if _, err := os.Stat(filepath.Join(bk, "ledger")); err != nil {
		t.Fatalf("the backup carries no ledger: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bk, "tree")); err != nil {
		t.Fatalf("the backup carries no tree: %v", err)
	}
	var vols []string
	for _, role := range []string{"state", "secrets"} {
		v, verr := manifest.VolumeName(ident, "p1", role)
		if verr != nil {
			t.Fatal(verr)
		}
		vols = append(vols, v)
	}
	for _, v := range vols {
		base := filepath.Join(bk, "volumes", v)
		nonce, err := os.ReadFile(base + ".nonce")
		if err != nil || strings.TrimSpace(string(nonce)) == "" {
			t.Fatalf("volume %s carries no recorded nonce: %v", v, err)
		}
		man, err := os.ReadFile(base + ".manifest")
		if err != nil {
			t.Fatalf("volume %s carries no per-entry manifest: %v", v, err)
		}
		entries := 0
		for _, line := range strings.Split(string(man), "\n") {
			if strings.HasPrefix(line, "manifest=") {
				entries++
			}
		}
		// FIVE, because the pinned image's contract enumerates one example of every entry TYPE it
		// distinguishes — a directory, two regular files, a symlink and a hardlink group member.
		// A count assertion is what tells a real manifest from an empty file that exits 0.
		if entries != 5 {
			t.Fatalf("volume %s: the manifest names %d entries, want 5:\n%s", v, entries, man)
		}
		if !strings.Contains(string(man), "digest=") ||
			!strings.Contains(string(man), "linktarget=") ||
			!strings.Contains(string(man), "hardlink=") ||
			!strings.Contains(string(man), "done=ok") {
			t.Fatalf("volume %s: the manifest is not the contract's own transcript:\n%s", v, man)
		}
		if _, err := os.Stat(base + ".data"); err != nil {
			t.Fatalf("volume %s carries no contents directory: %v", v, err)
		}
	}

	// --- and it restores ---------------------------------------------------------------------
	// The machine is returned to the state a restore is FOR: no active ledger. Restore refuses
	// outright while one is present, so this is the only shape the verb can be exercised in.
	if err := os.Remove(filepath.Join(r.home, ".state", "ledger")); err != nil {
		t.Fatal(err)
	}
	if rc := r.run(append([]string{"restore", bk}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("restore rc = %d\n%s", rc, r.said())
	}
	if got := identOf(t, r.home); got != ident {
		t.Fatalf("the restored installation identity is %q, want %q", got, ident)
	}
	if _, err := os.Stat(filepath.Join(r.home, ".state", "ledger.staging")); !os.IsNotExist(err) {
		t.Fatalf("the staging ledger survived a completed restore: %v", err)
	}
	// EVERY RESTORED VOLUME IS PROVABLY THIS INSTALLATION'S. Restoring contents into volumes with
	// no nonce labels would produce an installation whose own restored ledger rejects them.
	h, err := famlock.Acquire(r.home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, serr := ledger.Live(h)
	if serr != nil {
		t.Fatal(serr)
	}
	l, rerr := ledger.Read(st)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, v := range vols {
		if aerr := prov.Authority(t.Context(), l, prov.Engine(r.fake.Client()), prov.ClassVolume, v); aerr != nil {
			t.Fatalf("restored volume %s is not provably ours: %v", v, aerr)
		}
	}
}

// TestRestoreRefusesAManifestTheVolumeDoesNotMatch is the other half of the round trip, and the
// half that proves the verification is not decorative: the SAME archive, with the copy container
// reporting one restored symlink re-created as a plain file, must fail the restore.
//
// A TYPE MISMATCH HAS NO BYTES TO MISMATCH, which is why the manifest authenticates the contract
// rather than a digest alone. If the seam were wired to something that only compared contents,
// this restore would pass.
func TestRestoreRefusesAManifestTheVolumeDoesNotMatch(t *testing.T) {
	r, img := bkRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	if ident == "" {
		t.Fatal("the install recorded no identity")
	}
	bk := filepath.Join(safeBase(t), "backup")
	if rc := r.run(append([]string{"backup", bk}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("backup rc = %d\n%s", rc, r.said())
	}
	if err := os.Remove(filepath.Join(r.home, ".state", "ledger")); err != nil {
		t.Fatal(err)
	}
	img.RestoreVerify = "type-symlink-as-file"
	if rc := r.run(append([]string{"restore", bk}, r.docArgs()...)...); rc != cliio.ExitFail {
		t.Fatalf("restore rc = %d, want 1 — a volume that does not match its manifest must refuse\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "VERIFICATION MISMATCH") {
		t.Fatalf("the refusal does not name the mismatch:\n%s", r.said())
	}
	// NOTHING WAS ACTIVATED. A restore that failed verification must leave the machine with no
	// active ledger — activating one would claim volumes that did not verify.
	if _, err := os.Stat(filepath.Join(r.home, ".state", "ledger")); !os.IsNotExist(err) {
		t.Fatalf("a failed restore activated its ledger anyway: %v", err)
	}
}

// TestRestoreBindsVerificationToTheManifestsOwnEntryCount pins the COUNT BINDING and nothing else:
// a verifier that claims completion having checked a different number of entries than the manifest
// names has not verified THAT manifest, and the restore must refuse rather than trust a partial or
// padded check.
//
// IT DOES NOT MEASURE THE STDIN TRANSPORT, deliberately, and it must not claim to. The knob it
// sets answers with a CONSTANT count, so a seam that never opened the container's stdin produces
// exactly the same refusal — the test would have passed for the wrong reason and stayed green with
// the transport broken. That property is measured where the answer actually depends on the bytes:
// internal/copyfill's TestVerifyAgainstManifestCarriesTheManifestOnStdin, and the default round
// trip above, where the helper reports the number of `manifest=` records it read and a dropped
// payload turns five into zero.
func TestRestoreBindsVerificationToTheManifestsOwnEntryCount(t *testing.T) {
	r, img := bkRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	if ident == "" {
		t.Fatal("the install recorded no identity")
	}
	bk := filepath.Join(safeBase(t), "backup")
	if rc := r.run(append([]string{"backup", bk}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("backup rc = %d\n%s", rc, r.said())
	}
	if err := os.Remove(filepath.Join(r.home, ".state", "ledger")); err != nil {
		t.Fatal(err)
	}
	// A verifier that claims completion having checked FEWER entries than the manifest names — the
	// shape a helper regression takes. The count binding is the only thing between it and a pass.
	img.RestoreVerify = "understate"
	if rc := r.run(append([]string{"restore", bk}, r.docArgs()...)...); rc != cliio.ExitFail {
		t.Fatalf("restore rc = %d, want 1 — a count that does not match the manifest cannot bind\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "but the manifest names") {
		t.Fatalf("the refusal does not name the count mismatch:\n%s", r.said())
	}
}
