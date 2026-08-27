package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// Inventory — the two seam wirings themselves. Neither has a bats row: in the reference there is
// no seam to wire, so there was nothing to observe. What is asserted here is that the CLI reaches
// the ONE implementation of each rather than a private copy or a permissive default.

// TestBackupRefusesAnUnsafeOutputLocation is the location seam, measured through the verb.
//
// THE OWNERSHIP CHAIN IS THE ONLY AUTHENTICATION A BACKUP GETS. There is no secret to sign the
// tree with, and the ledger's own checksums are exactly as recomputable by whoever can write the
// tree as they are by this code — so what stands in for a signature is that no other party can
// write anywhere on the path. The refusal's own wording is asserted because it is migrate's, and a
// second, hand-written copy of this check in the backup module is precisely the drift the seam
// exists to prevent: a private reimplementation would refuse in different words, or not at all.
func TestBackupRefusesAnUnsafeOutputLocation(t *testing.T) {
	r, _ := bkRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	// The immediate parent is owner-only; only the directory ABOVE it is world-writable, so a
	// check of one directory would pass here and only a whole-chain walk refuses.
	base := filepath.Join(safeBase(t), "open")
	if err := os.Mkdir(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	bk := filepath.Join(sub, "backup")

	if rc := r.run(append([]string{"backup", bk}, r.docArgs()...)...); rc != cliio.ExitFail {
		t.Fatalf("backup rc = %d, want 1 — an unsafe output location must refuse\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "writable by its group or by everyone") {
		t.Fatalf("the refusal is not the ownership-chain check's own:\n%s", r.said())
	}
	// NOTHING WAS WRITTEN THERE. A refusal that had already created the output directory would
	// leave a thing that looks like a backup in a location the check just rejected.
	if _, err := os.Stat(bk); !os.IsNotExist(err) {
		t.Fatalf("the refused backup directory exists anyway: %v", err)
	}
}

// TestCopierIdentAnswersFromTheLedgerOrStandsIn covers the three outcomes of resolving WHOSE the
// copy helper containers are, and keeps the two that are ANSWERS apart from the one that is a
// refusal.
func TestCopierIdentAnswersFromTheLedgerOrStandsIn(t *testing.T) {
	t.Run("the recorded installation identity", func(t *testing.T) {
		r, _ := bkRig(t)
		r.writeProduct("p1")
		if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
			t.Fatalf("install rc = %d\n%s", rc, r.said())
		}
		want := identOf(t, r.home)
		h, err := famlock.Acquire(r.home)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = famlock.Release(h) }()
		got, cerr := copierIdent(h)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if got != want {
			t.Fatalf("copierIdent = %q, want the recorded identity %q", got, want)
		}
	})

	t.Run("a stand-in when there is no installation", func(t *testing.T) {
		// THE RESTORE PATH. Restore requires that no active ledger exists, and the incoming
		// identity lives in the staging store this process may not open at all, so there is
		// genuinely no installation identity to carry.
		home := t.TempDir()
		h, err := famlock.Acquire(home)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = famlock.Release(h) }()
		got, cerr := copierIdent(h)
		if cerr != nil {
			t.Fatalf("no installation is an ANSWER, not a refusal: %v", cerr)
		}
		// NONCE-SHAPED, NOT IDENTITY-SHAPED. An installation identity is "i"+hex; a stand-in
		// that looked like one would claim an installation that does not exist, and a helper
		// container leaked by a killed process would then read as THIS installation's unrecorded
		// object — which blocks every later verb until repaired — instead of as a stranger's.
		if !strings.HasPrefix(got, "n") || len(got) != 17 {
			t.Fatalf("the stand-in %q is not a nonce-shaped token", got)
		}
		second, serr := copierIdent(h)
		if serr != nil {
			t.Fatal(serr)
		}
		if second == got {
			t.Fatal("the stand-in repeats across runs; a leaked helper from one run would be claimed by the next")
		}
	})

	t.Run("an unreadable ledger refuses", func(t *testing.T) {
		// "THERE IS NO IDENTITY" AND "THE LEDGER COULD NOT BE READ" ARE DIFFERENT FACTS. A real
		// installation may be standing right here; labelling its copy containers as a stranger's
		// would hide them from its own accounting.
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".state"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".state", "ledger"), []byte("not a ledger\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := famlock.Acquire(home)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = famlock.Release(h) }()
		got, cerr := copierIdent(h)
		if cerr == nil {
			t.Fatalf("an unreadable ledger produced the stand-in %q instead of a refusal", got)
		}
		if !strings.Contains(cerr.Error(), "could not be read") {
			t.Fatalf("the refusal does not say why: %v", cerr)
		}
	})
}
