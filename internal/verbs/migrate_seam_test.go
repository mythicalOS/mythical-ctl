package verbs

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/migrate"
)

// Inventory — the rebuild seam. IT CLAIMS NO BATS ROW: in the reference the migration's phase 7
// calls the bring-up directly, so there is no seam and there was nothing to observe. What is
// asserted here is that this side of the seam honours the contract the phase machine is written
// against — everything fallible BEFORE the irreversible removal, and a release path that really
// releases.

// preparedRig installs one product and hands back the session and rebuilder a migration would use,
// plus the two derived container names. THE NAMES ARE TAKEN BEFORE THE SESSION OPENS: the family
// lock is not reentrant, and the rig's own readers take it themselves.
func preparedRig(t *testing.T) (*rig, *session, *rebuilder, string, string) {
	t.Helper()
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	c1, c2 := r.container("p1"), r.container("p2")
	s, err := openSession(r.d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return r, s, &rebuilder{s: s, product: "p1"}, c1, c2
}

// netFor resolves the network exactly as phase 7 does, through the seam's own first method — a
// Prepare judged against a network nobody resolved would be judging a launch that cannot exist.
func netFor(t *testing.T, s *session, rb *rebuilder) string {
	t.Helper()
	id, err := rb.NetTarget(context.Background(), s.l)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestPrepareRefusesAnotherProduct: the seam's other method takes no product at all — it derives
// the alias it settles from the field this rebuilder was built with — so preparing one product
// through another's rebuilder would build one container and settle a different one.
func TestPrepareRefusesAnotherProduct(t *testing.T) {
	r, s, rb, _, c2 := preparedRig(t)
	before := r.fake.Snapshot()
	_, err := rb.Prepare(context.Background(), s.l, "p2", c2, "")
	if err == nil {
		t.Fatal("a rebuilder bound to p1 prepared p2")
	}
	if !strings.Contains(err.Error(), "rebuild seam of") {
		t.Fatalf("the refusal does not name the mismatch: %v", err)
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the refusal changed the runtime:\n%s\n---\n%s", before, after)
	}
}

// TestPrepareRefusesAContainerThisInstallationDoesNotDerive: the container name the migration
// carries is the one phase 7 is about to REMOVE. A name this installation's identity does not
// derive is not ours to replace, and preparing a replacement for it would mean building p1's
// container while the phase removes something else.
func TestPrepareRefusesAContainerThisInstallationDoesNotDerive(t *testing.T) {
	r, s, rb, _, _ := preparedRig(t)
	before := r.fake.Snapshot()
	_, err := rb.Prepare(context.Background(), s.l, "p1", "mythical-someoneelse-p1", "")
	if err == nil {
		t.Fatal("a container this installation does not derive was accepted")
	}
	if !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the refusal changed the runtime:\n%s\n---\n%s", before, after)
	}
}

// TestPrepareCreatesNothing is the ordering property itself: everything fallible about WHAT to
// build runs while the old container is still standing, and NOTHING is created. If Prepare
// created the replacement, phase 7's removal would then delete it.
func TestPrepareCreatesNothing(t *testing.T) {
	r, s, rb, c1, _ := preparedRig(t)
	netID := netFor(t, s, rb)
	before := r.fake.Snapshot()
	rep, err := rb.Prepare(context.Background(), s.l, "p1", c1, netID)
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, r.said())
	}
	defer rep.Discard()
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("Prepare created something:\n%s\n---\n%s", before, after)
	}
}

// TestPrepareRefusesBeforeTheRemovalWhenTheImageCannotBeMadeAvailable is why the seam is split in
// two. A manifest that advanced to an image nobody has must fail HERE, with the working container
// intact and the migration resumable — not after the removal, which cannot be undone.
func TestPrepareRefusesBeforeTheRemovalWhenTheImageCannotBeMadeAvailable(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	c1 := r.container("p1")
	// The product's image is re-declared as one the fake has never seen, and the registry refuses
	// to serve it — the release-or-registry problem a manifest that advanced ahead of a published
	// image produces.
	r.writeProduct("p1", imageRef(digestRef("nowhere")))
	r.fake.PullOutcome = "notfound"
	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	netID := netFor(t, s, rb)
	before := r.fake.Snapshot()
	_, err := rb.Prepare(context.Background(), s.l, "p1", c1, netID)
	if err == nil {
		t.Fatal("a replacement was prepared for an image that cannot be obtained")
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the refusal changed the runtime:\n%s\n---\n%s", before, after)
	}
	if !r.containerExists(c1) {
		t.Fatal("the working container was taken down by a preparation that failed")
	}
}

// TestPreparePreservesARecordedImageOverride: install may have been given --image X, which it
// recorded and which `status` reports as the running image. Reverting to the manifest's image here
// would move the product's storage AND silently change what it runs.
func TestPreparePreservesARecordedImageOverride(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	override := digestRef("override")
	r.fake.PullImage(override)
	if rc := r.install("p1", withImage(override)); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	s, err := openSession(r.d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	pc, perr := s.productCtx("p1", s.manifestPath("p1"))
	if perr != nil {
		t.Fatal(perr)
	}
	got, ierr := rb.image(s.l, pc)
	if ierr != nil {
		t.Fatal(ierr)
	}
	if got != override {
		t.Fatalf("the replacement would run %q, not the recorded override %q", got, override)
	}
	if !strings.Contains(r.said(), "image override preserved") {
		t.Fatalf("the operator is not told the override stands:\n%s", r.said())
	}
}

// TestPrepareRefusesAnOverrideNamingNoImage: a recorded override with no reference is a record
// that says "run something else" without saying what. Falling back to the manifest's image would
// run an image `status` does not name; the refusal is the only honest answer.
func TestPrepareRefusesAnOverrideNamingNoImage(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.editLedger(func(l *ledger.Ledger) {
		if err := l.Put(kindForced, "key", "p1:image-override", []ledger.Field{
			{Key: "key", Value: "p1:image-override"},
			{Key: "product", Value: "p1"},
			{Key: "kind", Value: "image-override"},
		}); err != nil {
			t.Fatal(err)
		}
	})
	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	pc, perr := s.productCtx("p1", s.manifestPath("p1"))
	if perr != nil {
		t.Fatal(perr)
	}
	if _, err := rb.image(s.l, pc); err == nil {
		t.Fatal("an override naming no reference was silently ignored")
	} else if !strings.Contains(err.Error(), "names no reference") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// TestDiscardedReplacementRefusesToCreate is what makes Discard a real release path rather than a
// method nobody can tell was called. The phase machine defers it on EVERY way out of phase 7,
// built or abandoned; creating from a discarded one would be building from a preparation that has
// already been given up on — and on the day this holds a resource, from one that has been freed.
func TestDiscardedReplacementRefusesToCreate(t *testing.T) {
	r, s, rb, c1, _ := preparedRig(t)
	rep, err := rb.Prepare(context.Background(), s.l, "p1", c1, netFor(t, s, rb))
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, r.said())
	}
	rep.Discard()
	before := r.fake.Snapshot()
	if cerr := rep.Create(context.Background(), s.l); cerr == nil {
		t.Fatal("a discarded replacement was created anyway")
	} else if !strings.Contains(cerr.Error(), "discarded") {
		t.Fatalf("the refusal does not say why: %v", cerr)
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("a discarded replacement still touched the runtime:\n%s\n---\n%s", before, after)
	}
}

// TestRebuilderSatisfiesThePhaseMachinesSeam is a compile-time statement rather than a behaviour:
// the two types here are only ever reached through interfaces the other package declares, so a
// signature drift would otherwise surface as a nil seam at the CLI rather than as a build failure.
func TestRebuilderSatisfiesThePhaseMachinesSeam(t *testing.T) {
	var _ migrate.Rebuilder = (*rebuilder)(nil)
	var _ migrate.Replacement = (*replacement)(nil)
	var _ migrate.Copier = migrateCopier{}
	var _ migrate.Documents = sessionDocs{}
	var _ migrate.Objects = migrateObjects{}
	// And the alias the reconcile half derives is the one the launch itself registers — the seam
	// takes no alias, so a second derivation here would settle a container under a name the
	// bring-up never registered.
	a, err := manifest.Alias("p1")
	if err != nil || a == "" {
		t.Fatalf("alias: %q %v", a, err)
	}
}
