package verbs

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/migrate"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
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
	r := newRig(t)
	// BOTH products are real, attested and launchable. A rig with only p1 would refuse p2 for a
	// reason of its own — the family index does not vouch for it — and the guard would then be
	// subsumed by an unrelated refusal rather than measured.
	r.writeProduct("p1")
	r.writeProduct("p2")
	for _, p := range []string{"p1", "p2"} {
		if rc := r.install(p); rc != 0 {
			t.Fatalf("install %s rc = %d\n%s", p, rc, r.said())
		}
	}
	c2 := r.container("p2")
	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	netID := netFor(t, s, rb)
	before := r.fake.Snapshot()
	_, err := rb.Prepare(context.Background(), s.l, "p2", c2, netID)
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
	// ANOTHER INSTALLED PRODUCT'S CONTAINER, not an invented name. A name nothing installed
	// derives has no recorded desired state either, so the readability check would refuse it first
	// and this guard would never be measured; a sibling product's real container has one, which
	// leaves the guard as the only thing that can refuse. It is also the realistic hazard: the two
	// names differ by a product, not by a stranger's spelling.
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2")
	for _, p := range []string{"p1", "p2"} {
		if rc := r.install(p); rc != 0 {
			t.Fatalf("install %s rc = %d\n%s", p, rc, r.said())
		}
	}
	c2 := r.container("p2")
	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	netID := netFor(t, s, rb)
	before := r.fake.Snapshot()
	_, err := rb.Prepare(context.Background(), s.l, "p1", c2, netID)
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
	// THE OLD CONTAINER IS GONE, exactly as it is when phase 7 reaches the create. Leaving it
	// standing would have the daemon refuse the create for a name conflict, and the release path
	// would then look like it held when it was the daemon holding.
	if err := s.rt.ContainerRemove(context.Background(), c1); err != nil {
		t.Fatal(err)
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
}

// TestReconcileSettlesUnderTheProductsOwnAlias measures the one thing the seam's shape leaves to
// this side: Reconcile takes NO alias, so it derives one, and a container settled under a name the
// bring-up never registered would never verify.
//
// THE ALIAS IS ONLY OBSERVABLE THROUGH THE PROBE. Settling an outstanding alias check resolves that
// name from inside the family network, so the name the probe is asked for IS the name this seam
// derived — and a wrong one does not merely go unnoticed, it fails to resolve and the check stays
// outstanding. Both are asserted: the name asked for, and that the check actually cleared.
func TestReconcileSettlesUnderTheProductsOwnAlias(t *testing.T) {
	r, s, rb, c1, _ := preparedRig(t)
	netID := netFor(t, s, rb)

	// Exactly what phase 9 records before it asks the seam to settle: the recorded desired state,
	// with the alias check outstanding.
	if err := state.Commit(s.l, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.persistFn()(s.l); err != nil {
		t.Fatal(err)
	}

	var asked []string
	base := r.fake.HelperEntry
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		// `resolve` ONLY. The probe first proves its own resolver works by looking up the
		// per-run alias it registered itself under (`selfcheck`); the name under discussion here
		// is the one it is then asked to RESOLVE.
		if cmd == "resolve" && len(args) > 0 {
			asked = append(asked, args[0])
		}
		return base(cmd, args, view, stdin)
	}

	if err := rb.Reconcile(context.Background(), s.l, c1, netID); err != nil {
		t.Fatalf("reconcile: %v\n%s", err, r.said())
	}
	want, aerr := manifest.Alias("p1")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if len(asked) == 0 {
		t.Fatal("nothing was resolved, so the alias this seam derived was never exercised")
	}
	for _, a := range asked {
		if a != want {
			t.Fatalf("the reconciliation resolved %q, but the launch registers %q", a, want)
		}
	}
	// AND THE CHECK CLEARED. A resolution that answered about the wrong name would leave it
	// outstanding, which is the half an alias assertion alone would miss.
	out, oerr := state.Outstanding(s.l, c1)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if len(out) != 0 {
		t.Fatalf("the alias check is still outstanding after a successful reconcile: %+v", out)
	}
}

// TestCopySeamForwardsTheEscapeRule: the phase machine re-walks the staged tree host-side
// immediately before the commit, and asks THIS seam whether each symlink target leaves the tree.
//
// IT MUST BE THE COPY MODULE'S OWN DEFINITION, forwarded. That rule is enforced during the copy
// itself by the same module; a second spelling here is how one of the two stops matching, and the
// one that stops matching is the one that lets an escaping symlink through into a tree the product
// is about to be handed. Asserted over the three shapes the rule turns on rather than by
// inspection, so a forwarding replaced by a private answer reddens.
func TestCopySeamForwardsTheEscapeRule(t *testing.T) {
	var esc migrate.Escaper = migrateCopier{}
	root := "/staging"
	for _, tc := range []struct {
		name   string
		link   string
		target string
		want   bool
	}{
		{"an absolute target leaves the tree", root + "/evil", "/etc/passwd", true},
		{"a climbing relative target leaves the tree", root + "/evil", "../../etc/passwd", true},
		{"a target inside the tree does not", root + "/data/link", "../data/f", false},
	} {
		if got := esc.LinkEscapes(tc.link, tc.target, root); got != tc.want {
			t.Fatalf("%s: LinkEscapes(%q, %q, %q) = %v, want %v",
				tc.name, tc.link, tc.target, root, got, tc.want)
		}
	}
}

// --- the ledger the phase machine holds ----------------------------------------------------------
//
// A STORAGE MIGRATION HOLDS ONE LEDGER FOR THE WHOLE VERB and hands it back through every seam
// call, and both seams below re-authenticate documents — which is a write to the ledger FILE
// performed by the acceptor itself, since the acceptors take the lock token rather than a ledger.
// So the caller's copy is stale the instant either returns, and the caller's very next write is
// what erases the floor that was just recorded. These two tests are the only thing standing
// between that and an anti-rollback floor silently reverting mid-migration.

// floorOn reads a document's recorded version floor from the store this session opened, WITHOUT
// taking the family lock — the session is already holding it.
func floorOn(t *testing.T, s *session, docid string) string {
	t.Helper()
	v, err := trust.FloorGet(s.st, docid)
	if err != nil {
		t.Fatalf("floor for %s: %v", docid, err)
	}
	return v
}

func TestPrepareLeavesTheCallersLedgerAbleToCarryTheFloor(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	c1 := r.container("p1")
	// A GENUINE DOCUMENT ADVANCE, so the acceptance inside Prepare really does write a new floor.
	r.writeProduct("p1", docVersion("2"))

	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	rb := &rebuilder{s: s, product: "p1"}
	netID := netFor(t, s, rb)
	// The ledger the phase machine holds, captured BEFORE the seam call, exactly as phase 7 holds it.
	l := s.l
	rep, err := rb.Prepare(context.Background(), l, "p1", c1, netID)
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, r.said())
	}
	defer rep.Discard()
	if got := floorOn(t, s, "manifest:p1"); got != "2" {
		t.Fatalf("the acceptance inside Prepare did not advance the floor on disk: %q", got)
	}
	// THE CALLER'S NEXT WRITE MUST NOT REVERT IT. This is the whole failure: the phase machine
	// persists the ledger it holds after every phase, and a copy that never learned about the
	// floor writes the old one straight back over it.
	if perr := s.persistFn()(l); perr != nil {
		t.Fatal(perr)
	}
	if got := floorOn(t, s, "manifest:p1"); got != "2" {
		t.Fatalf("the phase machine's own ledger reverted the trust floor to %q — an anti-rollback\n"+
			"  floor silently undone by the write that follows the phase", got)
	}
}

func TestTheDocumentSeamLeavesTheCallersLedgerAbleToCarryTheFloor(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.writeProduct("p1", docVersion("2"))

	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	l := s.l
	docs := sessionDocs{s: s}
	if _, err := docs.AcceptManifest("p1"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := floorOn(t, s, "manifest:p1"); got != "2" {
		t.Fatalf("the acceptance did not advance the floor on disk: %q", got)
	}
	// NOTHING ELSE IS CALLED IN BETWEEN. Any other seam call would re-read the ledger for its own
	// reasons and refresh the caller's copy behind this assertion, which is exactly how a missing
	// re-read on ONE of the two document acceptances hides.
	if perr := s.persistFn()(l); perr != nil {
		t.Fatal(perr)
	}
	if got := floorOn(t, s, "manifest:p1"); got != "2" {
		t.Fatalf("the caller's ledger reverted the trust floor to %q after the manifest acceptance", got)
	}
}

// The policy half, separately — see the note above: the two acceptances have to be measured on
// their own, or one of them refreshes the ledger the other's mutation would have staled.
func TestThePolicyAcceptanceLeavesTheCallersLedgerAbleToCarryTheFloor(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.policyVersion = "2"
	r.writeProduct("p1")

	s, oerr := openSession(r.d)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer s.close()
	l := s.l
	docs := sessionDocs{s: s}
	if _, err := docs.AcceptPolicy(); err != nil {
		t.Fatalf("accept policy: %v", err)
	}
	if got := floorOn(t, s, "policy"); got != "2" {
		t.Fatalf("the acceptance did not advance the policy floor on disk: %q", got)
	}
	if perr := s.persistFn()(l); perr != nil {
		t.Fatal(perr)
	}
	if got := floorOn(t, s, "policy"); got != "2" {
		t.Fatalf("the caller's ledger reverted the policy floor to %q after the policy acceptance", got)
	}
}

// TestPrepareBuildsTheBringUpDependenciesBeforeTheRemoval closes the last thing that could still
// fail on the far side of phase 7's irreversible step.
//
// ASSEMBLING THE BRING-UP DEPENDENCIES IS ITSELF FALLIBLE — the probe accounting opens the ledger
// store, the probe arm validates the installation identity and its diagnostics writer — and none
// of those failures has anything to do with the container being replaced. Built at the create,
// they fire AFTER the old container is gone and leave the product with none, for a reason that was
// fully knowable while it was still standing. So Prepare builds them, and the prepared
// replacement carries them.
//
// It reads the prepared value directly because that is the only place the ordering is visible: on
// a healthy rig the late construction SUCCEEDS, so no outcome distinguishes the two — which is
// exactly why "it worked in the test" is not evidence here.
func TestPrepareBuildsTheBringUpDependenciesBeforeTheRemoval(t *testing.T) {
	r, s, rb, c1, _ := preparedRig(t)
	rep, err := rb.Prepare(context.Background(), s.l, "p1", c1, netFor(t, s, rb))
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, r.said())
	}
	defer rep.Discard()
	rp, ok := rep.(*replacement)
	if !ok {
		t.Fatalf("Prepare returned a %T", rep)
	}
	switch {
	case rp.bd.Probe == nil:
		t.Fatal("Prepare left the probe arm to be built after the irreversible removal")
	case rp.bd.Mut == nil, rp.bd.Objs == nil, rp.bd.State == nil:
		t.Fatal("Prepare left a runtime seam to be built after the irreversible removal")
	case rp.bd.Persist == nil:
		t.Fatal("Prepare left the write-ahead seam to be built after the irreversible removal")
	case rp.bd.NewNonce == nil, rp.bd.Now == nil:
		t.Fatal("Prepare left the nonce mint or the clock to be built after the irreversible removal")
	}
	// THE NONCE IS MINTED HERE TOO, and it is the LAST fallible step of working out what to build.
	// Minting reads the system entropy source; left to the create it would fire on the far side of
	// the removal, which is the one shape this split exists to eliminate.
	if rp.nonce == "" {
		t.Fatal("Prepare left the replacement's nonce to be minted after the irreversible removal")
	}
	// AND THE PREPARED SET IS WHAT THE CREATE USES. Building it early and then ignoring it would
	// satisfy every assertion above while changing nothing, and on a healthy rig a late rebuild
	// SUCCEEDS — so no outcome distinguishes the two. What does is the nonce: a bring-up stamps
	// the one it was handed onto the container it creates, as a provenance label, so reading it
	// back off the replacement says which set was used. Nothing is substituted to make this
	// legible — the value asserted is the real prepared one.
	if err := s.rt.ContainerRemove(context.Background(), c1); err != nil {
		t.Fatal(err)
	}
	if cerr := rep.Create(context.Background(), s.l); cerr != nil {
		t.Fatalf("create: %v\n%s", cerr, r.said())
	}
	info, ierr := r.c.ContainerInspect(context.Background(), c1)
	if ierr != nil {
		t.Fatalf("the replacement was not created: %v\n%s", ierr, r.said())
	}
	found := false
	for _, v := range info.Labels {
		if v == rp.nonce {
			found = true
		}
	}
	if !found {
		t.Fatalf("the replacement does not carry the nonce Prepare minted (%q) — it was created from\n"+
			"  dependencies the create built for itself, on the far side of the removal. Labels: %v",
			rp.nonce, info.Labels)
	}
}

// TestPrepareRefusesWhenThereIsNoRecordedDesiredStateToPreserve is the last thing that could fail
// on the far side of phase 7's removal.
//
// THE CREATE PRESERVES THE RECORDED DESIRED STATE, AND PRESERVING REFUSES WHEN THERE IS NOTHING
// RECORDED — guessing "running" would start something nobody asked for and "stopped" would take a
// working install down. That refusal is correct; what is not correct is where it used to fire.
// Left to the create, it lands after the old container has been removed and tombstoned, so the
// product ends up with no container because of a missing ledger row that was fully readable while
// it was still standing. The phase machine's own phase 1 tolerates that absence and defaults its
// RECORD to running, so this is reachable rather than theoretical.
//
// PREPARE MUST NOT ANSWER THE QUESTION, only establish that it can be answered: passing the
// migration's own remembered state into the create would make the migration EXPRESS an intent,
// which is what the seam's shape forbids.
func TestPrepareRefusesWhenThereIsNoRecordedDesiredStateToPreserve(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := r.install("p1"); rc != 0 {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	c1 := r.container("p1")
	// The desired-state row goes away — a repaired or hand-edited ledger, which phase 1 accepts.
	r.editLedger(func(l *ledger.Ledger) {
		if err := l.Del("desired", "container", c1); err != nil {
			t.Fatal(err)
		}
	})

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
		t.Fatal("a replacement was prepared for a container with no recorded desired state to preserve")
	}
	if !strings.Contains(err.Error(), "must not decide for you") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	// AND NOTHING WAS TOUCHED. The whole point is that this refusal arrives while the old
	// container is still standing.
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the refusal changed the runtime:\n%s\n---\n%s", before, after)
	}
	if !r.containerExists(c1) {
		t.Fatal("the working container was taken down by a preparation that failed")
	}
}
