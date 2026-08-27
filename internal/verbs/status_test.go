package verbs

import (
	"context"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
)

// Inventory — the STATUS half of Task 23's share of tests/unit/verbs.bats, as
// internal/verbs/owners.go partitions them. The uninstall half is claimed in
// internal/verbs/uninstall_test.go, and the one CLI-surface test in
// cmd/mythical-ctl/uninstall_cli_test.go.
//
// PORTED: tests/unit/verbs.bats: "status REPORTS volumes — it used to filter them out of the ledger loop entirely" -> TestStatusReportsVolumes
// PORTED: tests/unit/verbs.bats: "status scopes volumes to the named product, like it already scoped containers" -> TestStatusScopesVolumesToTheNamedProduct
// PORTED: tests/unit/verbs.bats: "status distinguishes a volume that is RECORDED but gone from one that is present" -> TestStatusDistinguishesAGoneVolume
// PORTED: tests/unit/verbs.bats: "a role declared precious is RECORDED as such on the volume, and reported UNREGENERABLE" -> TestPreciousRoleIsRecordedAndReportedUnregenerable
// PORTED: tests/unit/verbs.bats: "a volume record with NO precious field reads as UNREGENERABLE, never as safe to delete" -> TestVolumeWithNoPreciousFieldReadsUnregenerable
// PORTED: tests/unit/verbs.bats: "the same object does NOT stop status, which reports it and exits 0" -> TestUnrecordedObjectDoesNotStopStatus
// PORTED: tests/unit/verbs.bats: "status lists unattributed objects and never proposes removing them" -> TestStatusListsUnattributedObjects
// PORTED: tests/unit/verbs.bats: "an --image override is loud, recorded, and reported by status" -> TestImageOverrideIsLoudAndReported
// PORTED: tests/unit/verbs.bats: "recreate PRESERVES an install-time --image override, so the running image and status agree (§13)" -> TestRecreatePreservesTheImageOverride
// PORTED: tests/unit/verbs.bats: "--force-install is loud and reported by status" -> TestForceInstallIsLoudAndReported
// PORTED: tests/unit/verbs.bats: "status reports an UNREADABLE identity, not 'nothing installed' (rc 1 is not rc 3)" -> TestStatusReportsAnUnreadableIdentity
// PORTED: tests/unit/verbs.bats: "status reports an UNREADABLE operator network, not 'not created yet' (rc 1 is not rc 3)" -> TestStatusReportsAnUnreadableOperatorNetwork
// PORTED: tests/unit/verbs.bats: "a plain install CLEARS a prior --image override, so status reverts to the manifest image" -> TestPlainInstallClearsAPriorImageOverride
// PORTED: tests/unit/verbs.bats: "a FAILED --image install records NO override, so a later plain install names none" -> TestFailedImageInstallRecordsNoOverride
// PORTED: tests/unit/verbs.bats: "status reports an UNREADABLE installer-owned network record, not 'not created yet' (rc 1 is not rc 3)" -> TestStatusReportsAnUnreadableInstallerNetworkRecord
// PORTED: tests/unit/verbs.bats: "status reports an UNREADABLE network-migration record, not silence (rc 1 is not rc 3)" -> TestStatusReportsAnUnreadableMigrationRecord
// PORTED: tests/unit/verbs.bats: "status reports an UNREADABLE object listing as UNREADABLE, never as an empty fleet (rc 1 is not rc 3)" -> TestStatusReportsAnUnreadableObjectListing
// PORTED: tests/unit/verbs.bats: "a FAILED forced install leaves no force-install record, so a later normal install is not falsely annotated" -> TestFailedForcedInstallLeavesNoForceRecord
// PORTED: tests/unit/verbs.bats: "status reports an installer-owned network record with no id as UNREADABLE, not empty" -> TestStatusReportsAnInstallerNetworkRecordWithNoID
// PORTED: tests/unit/verbs.bats: "status reports a container record with no name as UNREADABLE, never hiding it" -> TestStatusReportsAContainerRecordWithNoName
// PORTED: tests/unit/verbs.bats: "status reports a netmig record missing fields as UNREADABLE, not a blank migration" -> TestStatusReportsANetmigRecordMissingFields

// --- rig extensions for Task 23 ---------------------------------------------------------------
//
// They live HERE rather than in rig_test.go so the two halves of Wave 5 do not edit one file.
// Methods on *rig from another file in the same package are the same rig.

func (r *rig) status(products ...string) int {
	r.t.Helper()
	return Status(context.Background(), r.d, products)
}

func (r *rig) uninstall(product string, purge bool) int {
	r.t.Helper()
	return Uninstall(context.Background(), r.d, product, purge)
}

func (r *rig) uninstallFamily(purge bool) int {
	r.t.Helper()
	return UninstallFamily(context.Background(), r.d, purge)
}

// confirm pins the non-interactive confirmation answer — the MI_CONFIRM tri-state's two decided
// values. With neither, the rig's stdin is an empty reader, which is a FAILED read and therefore a
// refusal: that is the "no MI_CONFIRM, no tty" case, and it must stay a refusal.
func (r *rig) confirm(answer string) {
	r.t.Helper()
	r.d.Env = append(append([]string(nil), r.env...), "MI_CONFIRM="+answer)
}

// replaceRow swaps ONE ledger row for another, IN PLACE — the Go spelling of the reference tests'
// `mi_ledger_read | grep -av … | mi_ledger_write`, which is how a record is REPLACED by a damaged
// one rather than merely accompanied by it.
//
// THE POSITION IS PRESERVED, and that is not cosmetic: the removal loops walk the object records in
// ledger order, so a fixture that dropped a row and appended its replacement would silently reorder
// the very sequence a test about "it stopped HERE" depends on. (Measured: it did.)
func (r *rig) replaceRow(match, replacement string) {
	r.t.Helper()
	n := 0
	r.editLedger(func(l *ledger.Ledger) {
		lines := l.Lines()
		for i, line := range lines {
			if strings.Contains(line, match) {
				lines[i] = replacement
				n++
			}
		}
		l.ReplaceLines(lines)
	})
	if n != 1 {
		r.t.Fatalf("replaceRow: %q matched %d rows, want exactly 1", match, n)
	}
}

func (r *rig) networkExists(ref string) bool {
	r.t.Helper()
	_, err := r.c.NetworkInspect(context.Background(), ref)
	return err == nil
}

// createLabelledVolume stands a volume carrying an ARBITRARY installation label — the fixture for
// an object that belongs to somebody else on the same daemon.
func (r *rig) createLabelledVolume(name, ident, nonce string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, nonce)
		if perr != nil {
			r.t.Fatal(perr)
		}
		if err := m.VolumeCreate(context.Background(), name, p); err != nil {
			r.t.Fatal(err)
		}
	})
}

// volumeRecordNonce is the nonce the ledger records for a volume — needed to rebuild a record by
// hand without inventing one, which would make the rebuilt record fail authority for the WRONG
// reason.
func (r *rig) volumeRecordNonce(vol string) string {
	r.t.Helper()
	rec, err := prov.Find(r.ledgerNow(), prov.ClassVolume, vol)
	if err != nil {
		r.t.Fatalf("no provenance record for %s: %v", vol, err)
	}
	n, ok := ledger.FieldOf(rec, "nonce")
	if !ok {
		r.t.Fatalf("the provenance record for %s carries no nonce", vol)
	}
	return n
}

func (r *rig) networkName() string {
	r.t.Helper()
	return "mythical-" + r.ident() + "-net"
}

// --- volumes in the report ----------------------------------------------------------------------

func TestStatusReportsVolumes(t *testing.T) {
	// The report used to walk the object records with a `class=container` filter, so no product's
	// volumes were ever named — and `uninstall --purge` is the operation that destroys them.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	// THE WHOLE LINE, not a fragment — which is also how "no size" is asserted. The host cannot
	// read a named volume's contents and the runtime reports none, so any number here would have to
	// be invented or obtained by starting a container, and status starts nothing. A fragment match
	// would tolerate a size spliced in anywhere; an exact line leaves nowhere to splice one.
	for _, role := range []string{"state", "secrets"} {
		r.mustSay("volume mythical-" + ident + "-p1-" + role + ": role=" + role +
			" data=regenerable product=p1 — present, created by this installation\n")
	}
	// And the vocabulary a size would have to arrive in appears nowhere in the report either.
	for _, banned := range []string{"size", " bytes", "MiB", "GiB"} {
		r.mustNotSay(banned)
	}
}

func TestStatusScopesVolumesToTheNamedProduct(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.writeProduct("p2")
	if rc := r.install("p2"); rc != cliio.ExitOK {
		t.Fatalf("installing p2: rc = %d\n%s", rc, r.said())
	}
	ident := r.ident()
	r.reset()

	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("volume mythical-" + ident + "-p1-state")
	r.mustNotSay("mythical-" + ident + "-p2-state")
}

func TestStatusDistinguishesAGoneVolume(t *testing.T) {
	// A real shape: an ordinary uninstall removes the container and deliberately RETAINS the volume
	// records, so an operator who then removes a volume by hand leaves exactly this state behind —
	// provenance describing something that is no longer there. Reporting it as present would tell
	// them their data is safe when it is gone.
	//
	// The container goes FIRST because it has to: the runtime refuses to remove a volume that is
	// still attached.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("uninstall rc = %d\n%s", rc, r.said())
	}
	r.removeObjects("mythical-" + ident + "-p1-state")
	r.reset()

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("recorded but GONE from the runtime")
	// And its sibling, untouched, still reads as present — so the distinction is doing work rather
	// than the report having simply gone pessimistic about everything.
	r.mustSay("volume mythical-" + ident + "-p1-secrets: role=secrets data=regenerable product=p1 — present")
}

func TestPreciousRoleIsRecordedAndReportedUnregenerable(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p2", extraRole("memory"), preciousRole("memory"))
	r.mintIdentity()
	r.mustInstall("p2")
	ident := r.ident()

	// The classification travels ON the ledger record, resolved from the authenticated policy index
	// at creation time — not re-derived at destruction time, when the documents may be gone.
	for _, tc := range []struct{ vol, want string }{
		{"mythical-" + ident + "-p2-memory", "1"},
		{"mythical-" + ident + "-p2-state", "0"},
	} {
		rec, err := prov.Find(r.ledgerNow(), prov.ClassVolume, tc.vol)
		if err != nil {
			t.Fatalf("no record for %s: %v", tc.vol, err)
		}
		if got, _ := ledger.FieldOf(rec, "precious"); got != tc.want {
			t.Fatalf("%s records precious=%q, want %q", tc.vol, got, tc.want)
		}
	}

	if rc := r.status("p2"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("volume mythical-" + ident + "-p2-memory: role=memory data=UNREGENERABLE")
	r.mustSay("volume mythical-" + ident + "-p2-state: role=state data=regenerable")
}

func TestVolumeWithNoPreciousFieldReadsUnregenerable(t *testing.T) {
	// The fail-safe direction, and the one that matters: a record written before this field existed,
	// or one whose classification was lost, must not read as "a reinstall rebuilds it". Simulated by
	// REPLACING the record with one that carries no `precious` field at all.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	vol := "mythical-" + ident + "-p1-state"
	nonce := r.volumeRecordNonce(vol)

	r.replaceRow("name="+vol, "object\tkey=volume:"+vol+"\tclass=volume\tname="+vol+
		"\tnonce="+nonce+"\tgen=1\tproduct=p1\trole=state")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("UNREGENERABLE (unclassified)")

	// And the purge warning treats it the same way — it is listed under the unrecoverable heading.
	r.reset()
	r.confirm("no")
	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("a refused purge reported success\n%s", r.said())
	}
	r.mustSay("CANNOT BE REGENERATED")
}

// --- the unaccounted classes ---------------------------------------------------------------------

func TestUnrecordedObjectDoesNotStopStatus(t *testing.T) {
	// The same object that STOPS every mutating verb must not stop the read-only report: status is
	// where an operator goes to find out WHY the mutating verbs are refusing.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.createStrayVolume("mythical-" + r.ident() + "-stray")

	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("unrecorded")
}

func TestStatusListsUnattributedObjects(t *testing.T) {
	r := newRig(t)
	r.mintIdentity()
	r.createLabelledVolume("someone-elses", "iotherinst", "notherxxxx")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("unattributed")
	r.mustSay("another user")
	// AND IT PROPOSES REMOVING NOTHING. Another user's objects are not this installation's
	// business, and a diagnostic that suggested deleting one would be suggesting exactly the
	// misidentification the provenance layer exists to prevent. The assertion names the object,
	// so it cannot be satisfied by the report simply having gone quiet.
	r.mustSay("Diagnostic only.")
	r.mustNotSay("docker volume rm someone-elses")
	r.mustNotSay("remove someone-elses")
}

// --- the install-time annotations ------------------------------------------------------------------

func TestImageOverrideIsLoudAndReported(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	ref := digestRef("localbuild")

	if rc := r.install("p1", withImage(ref)); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("OVERRIDE")
	r.reset()

	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustSay(ref)
	r.mustSay("override")
}

func TestRecreatePreservesTheImageOverride(t *testing.T) {
	// install --image X records the override, runs X, and status reports X. recreate takes no
	// --image of its own; before the fix it reverted to the manifest's image — tearing down the
	// override container and, since the manifest image was never pulled, failing to rebuild it —
	// while status still claimed the override active. The invariant: the running image and what
	// status reports must AGREE.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	ref := digestRef("localbuild")
	if rc := r.install("p1", withImage(ref)); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.reset()

	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d\n%s", rc, r.said())
	}
	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Image != ref {
		t.Fatalf("the running image is %q, want the override %q", info.Image, ref)
	}
	r.reset()
	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustSay(ref)
}

func TestForceInstallIsLoudAndReported(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1", notLaunched())
	r.mintIdentity()

	if rc := r.install("p1", forced()); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("FORCED")
	r.reset()

	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustSay("force")
}

func TestPlainInstallClearsAPriorImageOverride(t *testing.T) {
	// The override record must track the install that SUCCEEDED: after install --image X, a plain
	// re-install runs the manifest image and must clear the override, or status and recreate keep
	// naming X.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	ref := digestRef("localbuild")
	if rc := r.install("p1", withImage(ref)); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.reset()
	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustSay("image override")

	r.reset()
	r.mustInstall("p1") // plain re-install, no --image
	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustNotSay("image override")
}

func TestFailedImageInstallRecordsNoOverride(t *testing.T) {
	// The override ledger record is written AFTER bring-up succeeds. A --image install that fails
	// during the pull must leave no override behind for a later recreate to run or status to report.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.fake.PullOutcome = "neterr"
	if rc := r.install("p1", withImage(digestRef("abandoned"))); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.fake.PullOutcome = ""
	r.reset()

	r.mustInstall("p1") // a clean manifest install afterwards
	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustNotSay("image override")
}

func TestFailedForcedInstallLeavesNoForceRecord(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1", notLaunched())
	r.mintIdentity()
	r.fake.PullOutcome = "neterr"
	if rc := r.install("p1", forced()); rc == cliio.ExitOK {
		t.Fatalf("the forced install whose pull failed reported success\n%s", r.said())
	}
	r.fake.PullOutcome = ""
	r.writeProduct("p1") // the product is now released
	r.reset()

	r.mustInstall("p1")
	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d\n%s", rc, r.said())
	}
	r.mustNotSay("force-install")
}

// --- the refusals, which are status's product ------------------------------------------------------

func TestStatusReportsAnUnreadableIdentity(t *testing.T) {
	// A SECOND identity record makes the identity AMBIGUOUS, which is not the same fact as absent.
	// Reporting "nothing installed" for a corrupt ledger tells an operator whose objects are
	// orphaned that the machine is clean; status must send them to repair.
	r := newRig(t)
	r.mintIdentity()
	r.appendRows("identity\tid=second")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 — status is never gated by its own findings\n%s", rc, r.said())
	}
	r.mustSay("installation: UNREADABLE")
	r.mustSay("state repair")
	r.mustNotSay("No installation state found")
}

func TestStatusReportsAnUnreadableOperatorNetwork(t *testing.T) {
	// An operator network reference recorded WITHOUT an id is unreadable, not "no operator network
	// configured". Hiding it behind the installer-owned "not created yet" would tell the operator to
	// create a network they already pointed the installation at.
	r := newRig(t)
	r.mintIdentity()
	r.appendRows("netref\tkey=family\tname=opnet\towned=no")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("network:      UNREADABLE")
	r.mustSay("state repair")
	r.mustNotSay("not created yet")
}

func TestStatusReportsAnUnreadableInstallerNetworkRecord(t *testing.T) {
	// Two provenance records answer for the same installer-owned network name, so the lookup is
	// ambiguous — NOT "no record". Written as raw rows the way a restore would, since the keyed
	// editor refuses to write a duplicate key directly.
	r := newRig(t)
	r.mintIdentity()
	n := r.networkName()
	r.appendRows(
		"object\tkey=network:"+n+"\tclass=network\tname="+n+"\tid=netid-a",
		"object\tkey=network:"+n+"\tclass=network\tname="+n+"\tid=netid-b")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("network:      UNREADABLE")
	r.mustNotSay("not created yet")
}

func TestStatusReportsAnInstallerNetworkRecordWithNoID(t *testing.T) {
	// A record that exists and names no network is not a network. Printing an empty id reads as a
	// created network whose id merely failed to render.
	r := newRig(t)
	r.mintIdentity()
	n := r.networkName()
	r.appendRows("object\tkey=network:" + n + "\tclass=network\tname=" + n)

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("network:      UNREADABLE")
	r.mustSay("carries no id")
	r.mustNotSay("not created yet")
}

func TestStatusReportsAnUnreadableMigrationRecord(t *testing.T) {
	// Two netmig records answer for the family key. A corrupt migration record must not be swallowed
	// the way "no migration" is, which would let status claim a normal network while the fleet is
	// spread across two.
	r := newRig(t)
	r.mintIdentity()
	r.appendRows(
		"netmig\tkey=family\tphase=1\tsource=neta\ttarget=netb\tcontainers=",
		"netmig\tkey=family\tphase=2\tsource=netc\ttarget=netd\tcontainers=")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("MIGRATION record UNREADABLE")
}

func TestStatusReportsANetmigRecordMissingFields(t *testing.T) {
	// A record that reads cleanly can still be missing every semantic field. Printing a blank
	// phase/source/target reads as a usable migration.
	r := newRig(t)
	r.mintIdentity()
	r.appendRows("netmig\tkey=family")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("MIGRATION record UNREADABLE")
	r.mustNotSay("IN PROGRESS")
}

func TestStatusReportsAnUnreadableObjectListing(t *testing.T) {
	// A malformed (but checksum-valid) object record must not read as an EMPTY fleet: a monitor
	// reading "no products" off a corrupt ledger is worse than one reading "UNREADABLE".
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tmalformed-no-equals")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 — read-only, never gated by its own findings\n%s", rc, r.said())
	}
	r.mustSay("products:     UNREADABLE")
	// AND NOT AN EMPTY FLEET: neither the product line nor any volume line is rendered from a
	// listing that could not be read.
	r.mustNotSay("p1: desired=")
	r.mustNotSay("volume mythical-")
}

func TestStatusReportsAContainerRecordWithNoName(t *testing.T) {
	// A container record with no readable name is corrupt, not absent: skipping past it would let
	// status show no product while its provenance stands and needs repair.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=container:nameless\tclass=container\tnonce=n\tgen=1")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("product:      UNREADABLE")
	// The healthy product is STILL reported — the corrupt record is named beside it, not instead
	// of it.
	r.mustSay("p1: desired=running")
}

// --- beyond the reference's own set ------------------------------------------------------------
//
// Three properties the bash suite leaves untested and this port must not: the empty machine (the
// ANSWER that every UNREADABLE case above has to stay distinct from), a report with no runtime
// connection at all, and an outstanding set that cannot be enumerated.

func TestStatusOnAnEmptyMachine(t *testing.T) {
	r := newRig(t)
	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("No installation state found. Nothing has been installed yet.")
	r.mustNotSay("UNREADABLE")
}

func TestStatusWithNoRuntimeConnectionReportsRatherThanPanics(t *testing.T) {
	// status is the one verb that must survive a broken installation and report it. No daemon
	// connection at all is the most broken shape there is, and the ledger half of the report is
	// still worth printing — with every live answer named as unobservable rather than invented.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.d.Engine = nil

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("runtime:      UNAVAILABLE")
	r.mustSay("observed=(unknown)")
	r.mustSay("next=?")
	// The unaccounted sweep says it could not run rather than reporting a clean machine.
	r.mustSay("UNACCOUNTED SCAN INCOMPLETE")
}

func TestStatusReportsAnUnreadableOutstandingSet(t *testing.T) {
	// The reference discarded this read's status under `pipefail` and printed `outstanding=none` —
	// a container that owes checks nobody can enumerate, reported as owing none. That is the
	// reassuring direction, which is the one direction a diagnostic may never fail in.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("outstanding\tmalformed-no-equals")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("outstanding=UNREADABLE")
	r.mustNotSay("outstanding=none")
}

func TestStatusReportsANetmigRecordWithNoSourceOrTarget(t *testing.T) {
	// A record whose PHASE reads cleanly can still name neither endpoint. Printing a blank source
	// and target reads as a usable migration, which is the shape an operator would act on: the
	// phase makes it look like real progress, and the endpoints make it look like it goes nowhere.
	r := newRig(t)
	r.mintIdentity()
	r.appendRows("netmig\tkey=family\tphase=1\tcontainers=")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("MIGRATION record UNREADABLE")
	r.mustNotSay("IN PROGRESS")
}

func TestStatusReportsAVolumeRecordWithNoName(t *testing.T) {
	// The volume loop's sibling of the container loop's rule: a record with no readable name is
	// corrupt, not absent, and skipping past it would let status show fewer volumes than the ledger
	// claims — while the operator is deciding whether to purge.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=volume:nameless\tclass=volume\tnonce=n\tgen=1")

	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("volume:       UNREADABLE")
	// The healthy volumes are still reported beside it.
	r.mustSay("volume mythical-" + r.ident() + "-p1-state")
}

func TestStatusShowsAnUnattributableVolumeEvenUnderAFilter(t *testing.T) {
	// A volume record with no readable product is shown UNFILTERED rather than hidden: it is
	// exactly the record an operator needs to see, and silently dropping it from a filtered view is
	// how an unattributable volume becomes invisible — including to the operator deciding whether
	// `--purge` has covered everything.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=volume:orphan\tclass=volume\tname=orphan\tnonce=n\tgen=1")

	if rc := r.status("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("volume orphan: role=? data=UNREGENERABLE (unclassified) product=?")
}

// TestStatusReportsOpenIntentsAndAnUnreadableIntentList pins the PENDING half of the report.
//
// IT IS THE ONE PLACE A WEDGE IS VISIBLE. An intent is opened before the object is created and
// closed after it is confirmed; one left open means a crash landed between those two points, and
// status is where an operator finds out. Both branches matter, and the UNREADABLE branch matters
// more: intent records that cannot be read must not render as "nothing pending", which is the
// reassuring direction and reads exactly like a healthy machine.
func TestStatusReportsOpenIntentsAndAnUnreadableIntentList(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	// An OPEN intent is named, with its class and its object.
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l := r.loadLedger(st)
		if err := intent.Open(l, prov.ClassVolume, "v-stuck", "n1", time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := ledger.Write(h, st, l); err != nil {
			t.Fatal(err)
		}
	})
	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("PENDING: volume v-stuck — created and not yet confirmed")

	// An intent list that cannot be READ says so. Reporting no pending work off records nobody
	// could parse is the one direction a diagnostic may never fail in.
	r.appendRows("intent\tmalformed-no-equals")
	if rc := r.status(); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("PENDING:      UNREADABLE")
	r.mustSay("state repair")
}

// TestOutstandingRenderingIsJoinedWithoutATrailingComma pins the one COSMETIC divergence in this
// report, which is otherwise the kind of difference nothing would notice until a script did.
//
// The reference built this field by piping the check kinds through `tr '\n' ','`, which turns every
// separator AND the final newline into a comma — so its output always ended in one ("alias," for a
// single check). That trailing comma is an artifact of the pipeline, not information: joining says
// the same thing. Pinned rather than left implicit because a diagnostic field's shape is the part a
// wrapper parses, and "it used to have a trailing comma" is exactly the detail a later reader would
// re-add on the theory that the reference meant it.
func TestOutstandingRenderingIsJoinedWithoutATrailingComma(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	r.withLock(func(h famlock.Held, st ledger.Store) {
		l := r.loadLedger(st)
		if err := state.Commit(l, c, state.Running, []state.Check{
			{Kind: state.CheckAlias, Param: "net-a"},
			{Kind: state.CheckAlias, Param: "net-b"},
		}, false); err != nil {
			t.Fatal(err)
		}
		if err := ledger.Write(h, st, l); err != nil {
			t.Fatal(err)
		}
	})

	l := r.ledgerOnDisk()
	got := outstandingOf(l, c)
	if got != "alias,alias" {
		t.Fatalf("outstandingOf = %q, want %q — two checks, one separator, no trailing comma", got, "alias,alias")
	}
	if strings.HasSuffix(got, ",") {
		t.Fatalf("outstandingOf = %q — the reference's `tr` artifact was re-added", got)
	}
	// And the empty case is a WORD, not an empty field: a blank there reads as a rendering bug —
	// and it is the value "UNREADABLE" has to stay distinguishable from.
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l := r.loadLedger(st)
		for _, p := range []string{"net-a", "net-b"} {
			if err := state.OutstandingClear(l, c, state.CheckAlias, p); err != nil {
				t.Fatal(err)
			}
		}
		if err := ledger.Write(h, st, l); err != nil {
			t.Fatal(err)
		}
	})
	if got := outstandingOf(r.ledgerOnDisk(), c); got != "none" {
		t.Fatalf("with nothing outstanding: %q, want %q", got, "none")
	}
}
