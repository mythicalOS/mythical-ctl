package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/runtime"
)

// Inventory — the CLI-level end-to-end migration. The dispatcher's refusal matrix is claimed in
// migrate_test.go; the library rows in internal/migrate. Two rows are claimed HERE, and both were
// N/A until the parity audit, on arguments that had since expired:
//
// PORTED: tests/acceptance/migrate.bats: "CLI: migrate-storage end to end, through the real entrypoint, moves the product onto the bind" -> TestMigrateStorageMovesARoleEndToEnd
// PORTED: tests/unit/migrate.bats: "after the migration, a RECREATE keeps the product on the bind" -> TestRecreateAfterAMigrationKeepsTheBind
//
// The first was waived because "the copy and rebuild seams are not wired into the dispatcher"; they
// are, and this file is where they are proved wired. The second was waived because `recreate` was a
// verb this build did not carry; Wave 5 landed it. Neither row needs a live runtime after all — the
// hermetic fake daemon plus the copy-helper stand-in reach the whole path.
//
// Everything else here claims no bats row: it tests that the SEAMS the phase machine is written
// against are actually connected, which is a property of the wiring rather than of either module,
// and no bats test could have observed it — in the reference there is no seam to be unwired.

// migRig is a CLI rig placed where the location gate will accept it: migrate-storage judges the
// ancestor chain of the installer home (its secure scratch location lives inside it) as well as of
// the destination, so both are put under an owner-safe base.
func migRig(t *testing.T) (*cliRig, *enginetest.HelperImage, string) {
	t.Helper()
	base := safeBase(t)
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	r := newCLIRigIn(t, home)
	img := &enginetest.HelperImage{}
	next := r.fake.HelperEntry
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		switch cmd {
		case "preflight", "copy", "verify", "acl", "access":
			return img.Entry(cmd, args, view, stdin)
		}
		return next(cmd, args, view, stdin)
	}
	r.fake.PullImage(cliDigestRef("copy"))
	r.env = append(r.env, "MI_CONFIRM=yes")
	return r, img, base
}

// TestMigrateStorageMovesARoleEndToEnd drives the whole verb through the dispatcher, and it is the
// test that the copy seam and the rebuild seam are CONNECTED — not merely declared.
//
// EVERY PHASE HAS TO HAPPEN FOR THIS TO PASS. The copy helper has to run (an unwired copy seam is
// a nil interface); the destination has to end up carrying the migration's own identity marker (an
// unwired rename leaves the staging directory behind); mythical.conf has to name the destination
// (phase 6); the container has to be REBUILT so it mounts the host directory instead of the volume
// (an unwired rebuild seam cannot create one at all, and phase 8 then reports the mount missing);
// and the intent has to be cleared (phase 9). The assertions below read those results from the
// world rather than from the verb's own words.
func TestMigrateStorageMovesARoleEndToEnd(t *testing.T) {
	r, _, base := migRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	if ident == "" {
		t.Fatal("the install recorded no identity")
	}
	container, cerr := manifest.ContainerName(ident, "p1")
	if cerr != nil {
		t.Fatal(cerr)
	}
	srcVol, verr := manifest.VolumeName(ident, "p1", "state")
	if verr != nil {
		t.Fatal(verr)
	}
	// The container really does mount the NAMED VOLUME to begin with — otherwise the assertion
	// after the migration would be measuring nothing.
	if !mountsSource(t, r, container, srcVol) {
		t.Fatalf("the installed container does not mount %s to begin with", srcVol)
	}

	dest := filepath.Join(base, "p1-state")
	args := append([]string{"migrate-storage", "p1", "state", "--to-bind", dest}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("migrate-storage rc = %d\n%s", rc, r.said())
	}

	// The destination exists, and the staging sibling it was renamed from does not survive.
	if fi, serr := os.Stat(dest); serr != nil || !fi.IsDir() {
		t.Fatalf("the destination was not created: %v", serr)
	}
	ents, rerr := os.ReadDir(base)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "p1-state.") {
			t.Fatalf("a staging directory survived the migration: %s", e.Name())
		}
	}

	// mythical.conf NAMES the destination — the durable half of the migration.
	canon, cnerr := runtime.Canon(dest)
	if cnerr != nil {
		t.Fatal(cnerr)
	}
	got, gerr := conf.Get(conf.FamilyPath(r.home), "MYTHICAL_P1_STATE_BIND")
	if gerr != nil {
		t.Fatalf("mythical.conf does not name the destination: %v", gerr)
	}
	if got != canon {
		t.Fatalf("mythical.conf names %q, want %q", got, canon)
	}

	// AND THE CONTAINER WAS REBUILT ONTO IT. This is the assertion the rebuild seam exists for:
	// mounts are fixed at creation, so a container still mounting the old named volume is a
	// migration that moved the data and left the product reading the wrong copy of it.
	if !mountsSource(t, r, container, canon) {
		t.Fatalf("the replacement container does not mount %s", canon)
	}
	if mountsSource(t, r, container, srcVol) {
		t.Fatalf("the replacement container still mounts the old volume %s", srcVol)
	}

	// The intent is cleared: `status` would otherwise report a migration still in flight.
	if rc := r.run(append([]string{"status", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	if strings.Contains(r.said(), "migration") && strings.Contains(r.said(), "in progress") {
		t.Fatalf("a completed migration is still reported as in progress:\n%s", r.said())
	}
}

// TestMigrateStorageStopsAtAFailedVerifyWithTheContainerIntACT is the refusal half, and it is what
// tells a connected copy seam from a decorative one: the phase machine must not proceed past a
// copy the copy container refused, and the product's container must still be there afterwards.
//
// THE ORDER IS THE SAFETY PROPERTY. The copy is phase 3; the irreversible container removal is
// phase 7. A refusal in the copy that still ended with the container gone would mean the phases
// are not actually sequenced through the seam at all.
func TestMigrateStorageStopsAtAFailedVerifyWithTheContainerIntact(t *testing.T) {
	r, img, base := migRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	container, cerr := manifest.ContainerName(ident, "p1")
	if cerr != nil {
		t.Fatal(cerr)
	}
	srcVol, verr := manifest.VolumeName(ident, "p1", "state")
	if verr != nil {
		t.Fatal(verr)
	}

	// The copier reports a foreign-uid entry, which is refused without --map-foreign-to-operator.
	img.Copy = "foreign"
	dest := filepath.Join(base, "p1-state")
	args := append([]string{"migrate-storage", "p1", "state", "--to-bind", dest}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitFail {
		t.Fatalf("migrate-storage rc = %d, want 1 — a refused copy must stop the migration\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "foreign") {
		t.Fatalf("the refusal does not come from the copy container:\n%s", r.said())
	}
	// THE CONTAINER IS STILL THERE, still mounting its named volume: nothing irreversible ran.
	if !mountsSource(t, r, container, srcVol) {
		t.Fatalf("a copy refusal took the container down anyway:\n%s", r.said())
	}
	// And mythical.conf was never written — phase 6 is past the copy.
	if _, gerr := conf.Get(conf.FamilyPath(r.home), "MYTHICAL_P1_STATE_BIND"); gerr == nil {
		t.Fatal("a refused copy still wrote the bind into mythical.conf")
	}
}

// mountsSource reports whether the container mounts anything from `source` — a volume NAME for a
// named volume, or a canonical host path for a bind.
func mountsSource(t *testing.T, r *cliRig, container, source string) bool {
	t.Helper()
	info, err := r.fake.Client().ContainerInspect(t.Context(), container)
	if err != nil {
		return false
	}
	for _, m := range info.Mounts {
		if m.Source == source || m.Name == source {
			return true
		}
	}
	return false
}

// TestMigrateStorageOfAStoppedProductExpressesNoIntent is the other half of the rebuild seam's
// contract: the replacement reads the desired state ALREADY RECORDED, and the migration does not
// express one of its own.
//
// A MIGRATION IS NOT A START. An operator who stopped a product and then moved its storage did not
// ask for it to come back up, and a replacement created as "running" would start it and live-verify
// it — which is also forbidden for a product whose desired state is stopped. The observable
// difference is the LIVE VERIFICATION: bringing a container up runs probe containers, and a
// migration that preserved the recorded state runs none.
func TestMigrateStorageOfAStoppedProductExpressesNoIntent(t *testing.T) {
	r, _, base := migRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	if rc := r.run(append([]string{"stop", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	container, cerr := manifest.ContainerName(ident, "p1")
	if cerr != nil {
		t.Fatal(cerr)
	}
	probesBefore := probeLaunches(r)

	dest := filepath.Join(base, "p1-state")
	args := append([]string{"migrate-storage", "p1", "state", "--to-bind", dest}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("migrate-storage rc = %d\n%s", rc, r.said())
	}
	// The data moved and the container was rebuilt onto it...
	canon, cnerr := runtime.Canon(dest)
	if cnerr != nil {
		t.Fatal(cnerr)
	}
	if !mountsSource(t, r, container, canon) {
		t.Fatalf("the replacement container does not mount %s", canon)
	}
	// ...and it is still STOPPED, having never been brought up.
	info, ierr := r.fake.Client().ContainerInspect(t.Context(), container)
	if ierr != nil {
		t.Fatal(ierr)
	}
	if info.Running {
		t.Fatalf("migrating a stopped product started it")
	}
	if got := probeLaunches(r); got != probesBefore {
		t.Fatalf("the migration live-verified a stopped product (%d probe launches, was %d) — the\n"+
			"  replacement expressed an intent instead of preserving the recorded one", got, probesBefore)
	}
}

// probeLaunches counts the live-verification probes run so far. A container that is brought UP is
// live-verified; one that is created stopped is not.
func probeLaunches(r *cliRig) int {
	n := 0
	for _, l := range r.fake.HelperLaunches() {
		if len(l.Cmd) > 0 && (l.Cmd[0] == "selfcheck" || l.Cmd[0] == "resolve") {
			n++
		}
	}
	return n
}

// TestRecreateAfterAMigrationKeepsTheBind ports migrate.bats' "after the migration, a RECREATE keeps
// the product on the bind".
//
// WHAT IT IS ACTUALLY ABOUT. Mounts are fixed at container creation, so every later rebuild reads
// its mount set from somewhere — and the only durable record of the migration is the
// MYTHICAL_<PRODUCT>_<ROLE>_BIND key the migration wrote into mythical.conf. If `recreate` built its
// spec from anything else (the manifest's default named volume, say, or the ledger's pre-migration
// record), it would quietly put the product back on the OLD storage while the migrated data sat
// untouched on the bind: the operator sees a healthy container and an empty application.
func TestRecreateAfterAMigrationKeepsTheBind(t *testing.T) {
	r, _, base := migRig(t)
	r.writeProduct("p1")
	if rc := r.run(append([]string{"install", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	ident := identOf(t, r.home)
	container, cerr := manifest.ContainerName(ident, "p1")
	if cerr != nil {
		t.Fatal(cerr)
	}
	srcVol, verr := manifest.VolumeName(ident, "p1", "state")
	if verr != nil {
		t.Fatal(verr)
	}

	dest := filepath.Join(base, "p1-state")
	if rc := r.run(append([]string{"migrate-storage", "p1", "state", "--to-bind", dest}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("migrate-storage rc = %d\n%s", rc, r.said())
	}
	canon, cnerr := runtime.Canon(dest)
	if cnerr != nil {
		t.Fatal(cnerr)
	}

	// THE VERB ITSELF, not a stand-in: recreate destroys and rebuilds the container.
	if rc := r.run(append([]string{"recreate", "p1"}, r.docArgs()...)...); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d\n%s", rc, r.said())
	}
	if !mountsSource(t, r, container, canon) {
		t.Fatalf("after recreate the container does not mount the bind %s\n%s", canon, r.said())
	}
	if mountsSource(t, r, container, srcVol) {
		t.Fatalf("recreate put the product back on the pre-migration volume %s — the data is on the bind\n%s", srcVol, r.said())
	}
}
