package verbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
)

// Inventory — the UNINSTALL half of Task 23's share of tests/unit/verbs.bats, as
// internal/verbs/owners.go partitions them. The status half is claimed in
// internal/verbs/status_test.go, and the one CLI-surface test in
// cmd/mythical-ctl/uninstall_cli_test.go.
//
// PORTED: tests/unit/verbs.bats: "the host-tool slot survives the whole lifecycle, byte-identical and mode-unchanged" -> TestHostToolSlotSurvivesTheWholeLifecycle
// PORTED: tests/unit/verbs.bats: "no verb ever creates a host-tool slot for a product that has none" -> TestNoVerbCreatesAHostToolSlot
// PORTED: tests/unit/verbs.bats: "product uninstall RETAINS the trust floor and membership (§6c) — the rollback bypass" -> TestProductUninstallRetainsFloorAndMembership
// PORTED: tests/unit/verbs.bats: "product uninstall leaves bin/ and mythical.conf, and a sibling's config, alone" -> TestProductUninstallLeavesTheRestAlone
// PORTED: tests/unit/verbs.bats: "product uninstall RETAINS named volumes, and keeps their provenance so --purge still has authority" -> TestProductUninstallRetainsVolumesAndTheirProvenance
// PORTED: tests/unit/verbs.bats: "--purge removes the volumes it has authority over and tombstones them" -> TestPurgeRemovesVolumesAndTombstonesThem
// PORTED: tests/unit/verbs.bats: "NO verb removes an image — not uninstall, not --purge" -> TestNoVerbRemovesAnImage
// PORTED: tests/unit/verbs.bats: "--purge OFFERS images as an explicitly confirmed extra step, naming the shared-use risk" -> TestPurgeOffersImagesNamingTheSharedUseRisk
// PORTED: tests/unit/verbs.bats: "uninstall with an --image override leaves the override image in place" -> TestUninstallLeavesAnOverrideImageInPlace
// PORTED: tests/unit/verbs.bats: "the purge warning separates unrecoverable volumes from regenerable ones, and names both" -> TestPurgeWarningSeparatesTheDataClasses
// PORTED: tests/unit/verbs.bats: "product uninstall --purge REFUSES without confirmation, and removes NOTHING" -> TestProductPurgeRefusesWithoutConfirmation
// PORTED: tests/unit/verbs.bats: "MI_CONFIRM=no refuses a product purge just as it refuses a family one" -> TestConfirmNoRefusesAProductPurge
// PORTED: tests/unit/verbs.bats: "a plain product uninstall does NOT prompt — the prompt stays meaningful" -> TestPlainProductUninstallDoesNotPrompt
// PORTED: tests/unit/verbs.bats: "FAMILY uninstall resets the ledger entirely WITHOUT --purge, and leaves the volumes (§6c)" -> TestFamilyUninstallResetsTheLedgerWithoutPurge
// PORTED: tests/unit/verbs.bats: "family uninstall keeps named volumes without --purge and removes them with it" -> TestFamilyUninstallKeepsVolumesWithoutPurge
// PORTED: tests/unit/verbs.bats: "family uninstall --purge removes the volumes it has authority over" -> TestFamilyPurgeRemovesTheVolumes
// PORTED: tests/unit/verbs.bats: "family uninstall removes the network it created" -> TestFamilyUninstallRemovesTheNetworkItCreated
// PORTED: tests/unit/verbs.bats: "family uninstall NEVER removes an operator-supplied network — it is attach-only" -> TestFamilyUninstallNeverRemovesAnOperatorNetwork
// PORTED: tests/unit/verbs.bats: "family uninstall PRESERVES an object whose nonce no longer matches" -> TestFamilyUninstallPreservesAnObjectWhoseNonceChanged
// PORTED: tests/unit/verbs.bats: "family uninstall removes NO image, and says so" -> TestFamilyUninstallRemovesNoImageAndSaysSo
// PORTED: tests/unit/verbs.bats: "family uninstall refuses without an explicit confirmation, and changes nothing" -> TestFamilyUninstallRefusesWithoutConfirmation
// PORTED: tests/unit/verbs.bats: "family uninstall REFUSES and does NOT reset the ledger when the object listing is unreadable" -> TestFamilyUninstallRefusesAnUnreadableObjectListing
// PORTED: tests/unit/verbs.bats: "product uninstall --purge REFUSES on an unreadable object listing rather than silently skipping volumes" -> TestProductPurgeRefusesAnUnreadableObjectListing
// PORTED: tests/unit/verbs.bats: "family --purge does NOT reset the ledger when a volume record has no readable name (fail closed)" -> TestFamilyPurgeRefusesAVolumeRecordWithNoName
// PORTED: tests/unit/verbs.bats: "family uninstall does NOT reset the ledger when the operator-network reference is unreadable" -> TestFamilyUninstallRefusesAnUnreadableOperatorReference

// --- fixtures the uninstall half needs -------------------------------------------------------

// slotState is everything the host-tool slot must carry across the whole lifecycle: its bytes, its
// mode, its inode and its owner. The inode is in there deliberately — a verb that rewrote the file
// with identical content and mode would still have replaced the operator's file, and only the inode
// can tell that apart.
type slotState struct {
	body string
	mode os.FileMode
	ino  uint64
	uid  uint32
}

func readSlot(t *testing.T, path string) slotState {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the host-tool slot: %v", err)
	}
	fi, serr := os.Lstat(path)
	if serr != nil {
		t.Fatalf("stat of the host-tool slot: %v", serr)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot read the host-tool slot's inode and owner")
	}
	return slotState{body: string(body), mode: fi.Mode().Perm(), ino: sys.Ino, uid: sys.Uid}
}

// tombstoned reports whether the ledger carries a tombstone for one object.
func (r *rig) tombstoned(class prov.Class, name string) bool {
	r.t.Helper()
	_, err := prov.TombstoneFind(r.ledgerNow(), class, name)
	return err == nil
}

// imageRemovals counts the times the daemon was asked to delete an image — the Go spelling of
// grepping the reference harness's call log for `image rm`.
func (r *rig) imageRemovals() int {
	return r.requests(func(req string) bool { return strings.HasPrefix(req, "DELETE /images/") })
}

// setFamilyKey writes one key into mythical.conf, under the family lock, as the installer would.
func (r *rig) setFamilyKey(key, value string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		if err := conf.FamilyAdd(h, key, value); err != nil {
			r.t.Fatal(err)
		}
	})
}

// standContainerWithNonce replaces the container at `name` with one carrying THIS installation's
// identity and a DIFFERENT nonce — the object that is ours by label and is no longer the one the
// ledger recorded, because a name can be reassigned.
//
// It attaches to the installer's OWN network rather than creating one, so the only object the
// fixture leaves unaccounted for is the container under test.
func (r *rig) standContainerWithNonce(name, nonce string) {
	r.t.Helper()
	ctx := context.Background()
	ident := r.ident()
	netID := r.ownedNetworkID()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if r.containerExists(name) {
			if rerr := m.ContainerRemove(ctx, name); rerr != nil {
				r.t.Fatal(rerr)
			}
		}
		attach, aerr := engine.NewNetworkAttach(netID, "reused")
		if aerr != nil {
			r.t.Fatal(aerr)
		}
		r.fake.PullImage(digestRef("reused"))
		spec, serr := engine.NewContainerSpec(name, digestRef("reused"), engine.SpecOpts{
			Network: attach,
			Labels:  map[string]string{"installation": ident, "nonce": nonce, "product": "p1"},
		})
		if serr != nil {
			r.t.Fatal(serr)
		}
		if _, cerr := m.ContainerCreate(ctx, spec); cerr != nil {
			r.t.Fatal(cerr)
		}
		if sterr := m.ContainerStart(ctx, name); sterr != nil {
			r.t.Fatal(sterr)
		}
	})
}

// standForeignContainer replaces this product's container with one labelled for ANOTHER
// installation. That is deliberately not the same fixture as standContainerWithNonce: a
// same-identity object the ledger does not account for trips the unaccounted-object GATE before any
// verb body runs, so it can never reach the authority question. A container belonging to somebody
// else is a NOTE at that gate and a refusal at prov.Authority, which is the path under test.
func (r *rig) standForeignContainer(name string) {
	r.t.Helper()
	ctx := context.Background()
	netID := r.ownedNetworkID()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if r.containerExists(name) {
			if rerr := m.ContainerRemove(ctx, name); rerr != nil {
				r.t.Fatal(rerr)
			}
		}
		attach, aerr := engine.NewNetworkAttach(netID, "foreign")
		if aerr != nil {
			r.t.Fatal(aerr)
		}
		r.fake.PullImage(digestRef("foreign"))
		spec, serr := engine.NewContainerSpec(name, digestRef("foreign"), engine.SpecOpts{
			Network: attach,
			Labels:  map[string]string{"installation": "iotherxxxxx", "nonce": "nforeignxxx", "product": "p1"},
		})
		if serr != nil {
			r.t.Fatal(serr)
		}
		if _, cerr := m.ContainerCreate(ctx, spec); cerr != nil {
			r.t.Fatal(cerr)
		}
	})
}

// ownedNetworkID is the id the ledger records for the network this installer created.
func (r *rig) ownedNetworkID() string {
	r.t.Helper()
	rec, err := prov.Find(r.ledgerNow(), prov.ClassNetwork, r.networkName())
	if err != nil {
		r.t.Fatalf("no provenance record for the installer network: %v", err)
	}
	id, ok := ledger.FieldOf(rec, "id")
	if !ok {
		r.t.Fatal("the installer network record carries no id")
	}
	return id
}

// --- the host-tool slot -------------------------------------------------------------------------

func TestHostToolSlotSurvivesTheWholeLifecycle(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	slot := filepath.Join(r.home, "p1", "cli.toml")
	if err := os.MkdirAll(filepath.Dir(slot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slot, []byte("token = \"host-only\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// DELIBERATELY NOT 0600, which is the mode the contract asks the host-side TOOL to use. The
	// property under test is that this installer leaves the mode it FINDS alone, and starting at
	// 0600 cannot show that: a regression that unconditionally ran chmod 0600 would land on the
	// same bits and the assertion would pass. Starting somewhere else makes "preserved" and
	// "normalised" distinguishable. 0640 IS NOT BLESSED BY THIS — it is group-readable and the
	// contract calls that compromised; enforcing the mode is the host-side tool's job, and this
	// installer's job is to touch nothing, INCLUDING a mode it would not itself have chosen.
	if err := os.Chmod(slot, 0o640); err != nil {
		t.Fatal(err)
	}
	want := readSlot(t, slot)
	if want.mode != 0o640 {
		t.Fatalf("the fixture is mode %v, not the 0640 this test needs", want.mode)
	}

	check := func(after string) {
		t.Helper()
		got := readSlot(t, slot)
		if got != want {
			t.Fatalf("the host-tool slot changed after %s:\n  want %+v\n  got  %+v", after, want, got)
		}
	}

	r.mustInstall("p1")
	check("the first install")
	r.mustInstall("p1")
	check("a re-install over a populated home")

	for _, step := range []struct {
		name string
		run  func() int
	}{
		{"stop", func() int { return r.stop("p1") }},
		{"start", func() int { return r.start("p1") }},
		{"restart", func() int { return r.restart("p1") }},
		{"recreate", func() int { return r.recreate("p1") }},
	} {
		if rc := step.run(); rc != cliio.ExitOK {
			t.Fatalf("%s: rc = %d\n%s", step.name, rc, r.said())
		}
		r.reset()
		check(step.name)
	}

	// And both destructive ends, purge included — the two that remove things on purpose.
	r.confirm("yes")
	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("uninstall --purge: rc = %d\n%s", rc, r.said())
	}
	r.reset()
	check("uninstall --purge")
	if rc := r.uninstallFamily(true); rc != cliio.ExitOK {
		t.Fatalf("uninstall --family --purge: rc = %d\n%s", rc, r.said())
	}
	r.reset()
	check("uninstall --family --purge")
}

func TestNoVerbCreatesAHostToolSlot(t *testing.T) {
	// The slot is the OPERATOR's file. An installer that helpfully created an empty one would be
	// creating a path it has just promised never to write, and would mask a missing host-side tool.
	//
	// Lstat, not Stat: Stat FOLLOWS a symlink, so it is false for a DANGLING one — and a verb that
	// planted a dangling cli.toml would satisfy a Stat check while having created exactly the path
	// this asserts nothing creates.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	slot := filepath.Join(r.home, "p1", "cli.toml")
	noSlot := func(after string) {
		t.Helper()
		if _, err := os.Lstat(slot); err == nil {
			t.Fatalf("a host-tool slot was CREATED by %s, for a product that has no host-side tool", after)
		} else if !os.IsNotExist(err) {
			t.Fatalf("after %s the host-tool slot path is unreadable for another reason: %v", after, err)
		}
	}

	r.mustInstall("p1")
	noSlot("install")
	for _, step := range []struct {
		name string
		run  func() int
	}{
		{"stop", func() int { return r.stop("p1") }},
		{"start", func() int { return r.start("p1") }},
		{"restart", func() int { return r.restart("p1") }},
		{"recreate", func() int { return r.recreate("p1") }},
	} {
		if rc := step.run(); rc != cliio.ExitOK {
			t.Fatalf("%s: rc = %d\n%s", step.name, rc, r.said())
		}
		r.reset()
		noSlot(step.name)
	}
	r.confirm("yes")
	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("uninstall --purge: rc = %d\n%s", rc, r.said())
	}
	noSlot("uninstall --purge")
	if rc := r.uninstallFamily(true); rc != cliio.ExitOK {
		t.Fatalf("uninstall --family --purge: rc = %d\n%s", rc, r.said())
	}
	noSlot("uninstall --family --purge")
}

// --- product uninstall: what it RETAINS -----------------------------------------------------------

func TestProductUninstallRetainsFloorAndMembership(t *testing.T) {
	// THE ROLLBACK BYPASS. If uninstall cleared the anti-rollback floor, `uninstall` then `install`
	// would be a supported one-command way to replay a withdrawn manifest and recover a vulnerable
	// image.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	floor := r.floorOf("manifest:p1")
	if floor != "1" {
		t.Fatalf("the fixture recorded no trust floor (%q) — the assertion below would prove nothing", floor)
	}

	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if got := r.floorOf("manifest:p1"); got != floor {
		t.Fatalf("the trust floor is %q after an uninstall, want %q — this is the rollback bypass", got, floor)
	}
	if !r.isMember("p1") {
		t.Fatal("uninstall dropped p1's membership; only a family uninstall may do that")
	}
}

func TestProductUninstallLeavesTheRestAlone(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.writeProduct("p2")
	if rc := r.install("p2"); rc != cliio.ExitOK {
		t.Fatalf("installing p2: rc = %d\n%s", rc, r.said())
	}
	r.reset()

	binTool := filepath.Join(r.home, "bin", "mythical-ctl")
	if err := os.WriteFile(binTool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	family := readAll(t, filepath.Join(r.home, "mythical.conf"))
	p2conf := readAll(t, filepath.Join(r.home, "p2.conf"))

	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if _, err := os.Stat(binTool); err != nil {
		t.Fatalf("uninstall removed bin/: %v", err)
	}
	if got := readAll(t, filepath.Join(r.home, "mythical.conf")); got != family {
		t.Fatal("uninstall rewrote the shared mythical.conf")
	}
	if got := readAll(t, filepath.Join(r.home, "p2.conf")); got != p2conf {
		t.Fatal("uninstalling p1 rewrote a sibling's config")
	}
}

func TestProductUninstallRetainsVolumesAndTheirProvenance(t *testing.T) {
	// The provenance must survive the container, or a later `--purge` would have no authority over
	// volumes that still exist — and the fail-safe rule would then preserve them forever.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	vol := "mythical-" + r.ident() + "-p1-state"

	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if !r.volumeExists(vol) {
		t.Fatal("a plain uninstall removed a named volume")
	}
	if _, err := prov.Find(r.ledgerNow(), prov.ClassVolume, vol); err != nil {
		t.Fatalf("the volume's provenance did not survive the uninstall: %v", err)
	}
}

// --- product --purge ------------------------------------------------------------------------------

func TestPurgeRemovesVolumesAndTombstonesThem(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	vol := "mythical-" + r.ident() + "-p1-state"
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if r.volumeExists(vol) {
		t.Fatal("--purge left the volume in place")
	}
	if !r.tombstoned(prov.ClassVolume, vol) {
		t.Fatal("--purge removed the volume and wrote no tombstone — provenance must survive what it describes")
	}
}

func TestNoVerbRemovesAnImage(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if n := r.imageRemovals(); n != 0 {
		t.Fatalf("%d image removals reached the daemon — the ledger proves acquisition, not ownership", n)
	}
}

func TestPurgeOffersImagesNamingTheSharedUseRisk(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("may be in use")
	r.mustSay("docker image")
	r.mustSay(digestRef("p1"))
}

func TestUninstallLeavesAnOverrideImageInPlace(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	if rc := r.install("p1", withImage(digestRef("local"))); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.reset()
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if n := r.imageRemovals(); n != 0 {
		t.Fatalf("%d image removals reached the daemon — an overridden image is no more the installer's to remove", n)
	}
}

func TestPurgeWarningSeparatesTheDataClasses(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p2", extraRole("memory"), preciousRole("memory"))
	r.mintIdentity()
	r.mustInstall("p2")
	ident := r.ident()
	r.confirm("no")

	if rc := r.uninstall("p2", true); rc == cliio.ExitOK {
		t.Fatalf("a refused purge reported success\n%s", r.said())
	}
	r.mustSay("CANNOT BE REGENERATED")
	r.mustSay("mythical-" + ident + "-p2-memory (role memory)")
	r.mustSay("declared regenerable")
	r.mustSay("mythical-" + ident + "-p2-state (role state)")
}

func TestProductPurgeRefusesWithoutConfirmation(t *testing.T) {
	// The gap this closes: the family verb has asked since it existed, and the product-scoped
	// --purge acquired the same power over named volumes without ever growing a prompt.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()

	// No MI_CONFIRM and no tty — the rig's stdin is an empty reader, which is a failed read and
	// therefore a refusal.
	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("an unconfirmed purge reported success\n%s", r.said())
	}
	r.mustSay("not confirmed")
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("the refused purge removed a volume")
	}
	// AND THE CONTAINER PROVES THE PROMPT CAME FIRST. A prompt that arrives after the container is
	// gone is a notification, not a decision.
	if !r.containerExists(r.container("p1")) {
		t.Fatal("the refused purge removed the container — the prompt did not come first")
	}
}

func TestConfirmNoRefusesAProductPurge(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	r.confirm("no")

	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("an explicitly refused purge reported success\n%s", r.said())
	}
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("the refused purge removed a volume")
	}
}

func TestPlainProductUninstallDoesNotPrompt(t *testing.T) {
	// Scoped to --purge on purpose. A plain uninstall KEEPS every volume, so prompting there would
	// train an operator to type y at a question that never means anything — and a confirmation that
	// is usually harmless is one nobody reads by the time it is not.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()

	// No MI_CONFIRM at all, and it must still succeed.
	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 — a plain uninstall must not be gated by a prompt\n%s", rc, r.said())
	}
	// THE PER-VOLUME STATEMENT IS THE POINT, not a summary line: an operator told "your data is
	// kept" learns nothing they can check.
	r.mustSay("keeping volume mythical-" + ident + "-p1-state (role state, regenerable) — your data.")
	r.mustSay("keeping volume mythical-" + ident + "-p1-secrets (role secrets, regenerable) — your data.")
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("a plain uninstall removed a volume")
	}
}

func TestProductPurgeRefusesAnUnreadableObjectListing(t *testing.T) {
	// CONFIRMED ON PURPOSE. Without it this test would still go red and would still look like it
	// was passing — but on the confirmation prompt, having never reached the enumeration guard it
	// exists to prove. "It failed" is not the assertion; WHICH failure is.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tmalformed-no-equals")
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("a purge over an unreadable listing reported success\n%s", r.said())
	}
	r.mustSay("could not be fully read")
	if !r.containerExists(r.container("p1")) {
		t.Fatal("the refusal still removed the container")
	}
}

// --- family uninstall ------------------------------------------------------------------------------

func TestFamilyUninstallResetsTheLedgerWithoutPurge(t *testing.T) {
	// The family reset is UNCONDITIONAL with respect to --purge: identity, membership, every floor
	// and the anchor go whether or not it is given. Only the VOLUMES' fate depends on --purge.
	// Keeping the ledger to "protect" retained volumes would leave a fresh machine still carrying
	// the old identity — a contract violation, not a safety feature.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	transcript := filepath.Join(r.home, "transcripts", "x")
	if err := os.WriteFile(transcript, []byte("note\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if r.containerExists("mythical-" + ident + "-p1") {
		t.Fatal("the container survived a family uninstall")
	}
	if _, err := r.ledgerNow().IdentGet(); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the installation identity survived the reset: %v", err)
	}
	if r.isMember("p1") {
		t.Fatal("membership survived the reset")
	}
	if got := r.floorOf("manifest:p1"); got == "1" {
		t.Fatal("the anti-rollback floor survived the reset")
	}
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("the volume did NOT survive a no-purge reset — that is the operator's data")
	}
	if _, err := os.Stat(transcript); err != nil {
		t.Fatalf("user data was touched by a verb: %v", err)
	}
}

func TestFamilyUninstallKeepsVolumesWithoutPurge(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("a family uninstall without --purge removed a named volume")
	}
	// And it NAMED it while the ledger still recorded it — after the reset this installer has no
	// authority to remove it again, so the operator is told how.
	r.mustSay("keeping volume mythical-" + ident + "-p1-state")
	r.mustSay("docker volume rm mythical-" + ident + "-p1-state")
}

func TestFamilyPurgeRemovesTheVolumes(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	r.confirm("yes")

	if rc := r.uninstallFamily(true); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("--purge left a named volume in place")
	}
}

func TestFamilyUninstallRemovesTheNetworkItCreated(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	n := r.networkName()
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if r.networkExists(n) {
		t.Fatal("the network this installer created survived the family uninstall")
	}
}

func TestFamilyUninstallNeverRemovesAnOperatorNetwork(t *testing.T) {
	// A non-owned reference is ATTACH-ONLY and carries no deletion authority: it is the operator's
	// network and this installer was never entitled to remove it.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.createNetwork("opnet")
	r.setFamilyKey("MYTHICAL_NET", "opnet")
	r.mustInstall("p1")
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	if !r.networkExists("opnet") {
		t.Fatal("the operator-supplied network was removed")
	}
	r.mustSay("LEFT ALONE")
}

func TestFamilyUninstallPreservesAnObjectWhoseNonceChanged(t *testing.T) {
	// The nonce no longer matches the ledger, so the object is same-identity-but-unaccounted: the
	// verb STOPS rather than removing something it can no longer prove is the one it recorded.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.standContainerWithNonce(c, "nreusedxxx")
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc == cliio.ExitOK {
		t.Fatalf("the family uninstall proceeded over an object it could not account for\n%s", r.said())
	}
	if !r.containerExists(c) {
		t.Fatal("the unaccounted object was removed")
	}
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset over an unaccounted object: %v", err)
	}
}

func TestFamilyUninstallRemovesNoImageAndSaysSo(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("NOT removed")
	if n := r.imageRemovals(); n != 0 {
		t.Fatalf("%d image removals reached the daemon — a family uninstall is not an exemption", n)
	}
}

func TestFamilyUninstallRefusesWithoutConfirmation(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	r.confirm("no")

	if rc := r.uninstallFamily(false); rc == cliio.ExitOK {
		t.Fatalf("an unconfirmed family uninstall reported success\n%s", r.said())
	}
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the refused family uninstall reset the ledger: %v", err)
	}
	if !r.running("mythical-" + ident + "-p1") {
		t.Fatal("the refused family uninstall stopped or removed the container")
	}
}

func TestFamilyUninstallRefusesAnUnreadableObjectListing(t *testing.T) {
	// A malformed (but checksum-valid) object record used to read as an EMPTY listing: nothing was
	// removed, `preserved` stayed clear, and the ledger was reset over containers still standing —
	// stripping their provenance while they existed.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tmalformed-no-equals")
	r.confirm("yes") // confirmed, so it is the ENUMERATION guard that stops it

	if rc := r.uninstallFamily(false); rc == cliio.ExitOK {
		t.Fatalf("the family uninstall proceeded over a listing it could not read\n%s", r.said())
	}
	r.mustSay("could not be fully read")
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset anyway: %v", err)
	}
	if !r.containerExists(r.container("p1")) {
		t.Fatal("the refusal still removed the container")
	}
}

func TestFamilyPurgeRefusesAVolumeRecordWithNoName(t *testing.T) {
	// A checksum-valid volume record missing `name=` passes the listing check and cannot be acted
	// on. Skipping it silently would leave `preserved` clear and let the reset wipe its provenance
	// while the volume stands.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=volume:nameless\tclass=volume\tnonce=n\tgen=1")
	r.confirm("yes")

	if rc := r.uninstallFamily(true); rc == cliio.ExitOK {
		t.Fatalf("the family purge proceeded over a record it could not act on\n%s", r.said())
	}
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset anyway: %v", err)
	}
}

func TestFamilyUninstallRefusesAnUnreadableOperatorReference(t *testing.T) {
	// An operator-network reference that is RECORDED and unreadable must not be flattened into
	// "none configured": the reset would then wipe the ledger that records the attachment while
	// unable to read it.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("netref\tkey=family\tname=opnet\towned=no") // recorded, but no id
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc == cliio.ExitOK {
		t.Fatalf("the family uninstall reset the ledger over an unreadable network reference\n%s", r.said())
	}
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset anyway: %v", err)
	}
}

// --- beyond the reference's own set ---------------------------------------------------------------

func TestUninstallWithNoProductIsAUsageError(t *testing.T) {
	// The LIBRARY's own arity contract: a caller reaching this package directly has no dispatcher
	// in front of it, and a missing operand is a usage error (2), never an operational failure.
	r := newRig(t)
	if rc := r.uninstall("", false); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if len(r.fake.RequestLog()) != 0 {
		t.Fatalf("the refusal reached the daemon: %v", r.fake.RequestLog())
	}
}

func TestFamilyUninstallOnAnEmptyMachineRefuses(t *testing.T) {
	// No identity is nothing to uninstall — an ANSWER, and it must not be answered by wiping a
	// ledger that records nothing anyway while claiming to have uninstalled something.
	r := newRig(t)
	r.confirm("yes")
	if rc := r.uninstallFamily(false); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay("there is no installation to uninstall")
}

func TestPurgeSaysSoWhenNoVolumeIsInScope(t *testing.T) {
	// "Are you sure?" against an unnamed set is a question the operator cannot answer. When the set
	// is EMPTY the prompt must say that too, rather than leaving the operator to assume the list
	// was omitted.
	r := newRig(t)
	r.mintIdentity()
	r.confirm("no")
	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("a refused purge reported success\n%s", r.said())
	}
	r.mustSay("No volume records are in scope, so this removes the container only.")
}

func TestPurgeCountsVolumesItCannotAttribute(t *testing.T) {
	// A volume record that names NO product is out of this verb's scope — it selects by product, so
	// acting on it would be acting on a guess. Saying nothing, though, would let "purge complete"
	// mean "and some volumes were left that I could not attribute".
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=volume:orphan\tclass=volume\tname=orphan\tnonce=n\tgen=1")
	r.confirm("no")

	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("a refused purge reported success\n%s", r.said())
	}
	r.mustSay("1 volume record(s) name no product")
	r.mustSay("will NOT remove them")
}

func TestFamilyUninstallPreservesAVolumeItCannotProveIsOurs(t *testing.T) {
	// "ANY MISMATCH PRESERVES", reached where nothing earlier can pre-empt it. Two provenance
	// records answer for one volume name, so authority over it cannot be established — and the
	// volume is NOT in the runtime, so the unaccounted sweep (which walks what the runtime holds)
	// never sees it and the gate does not stop the verb first. That is what makes this the
	// preserve arm of the family volume loop rather than a second test of the gate.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	vol := "mythical-" + ident + "-p1-state"
	// The container goes first — the runtime will not remove an attached volume — and a plain
	// uninstall deliberately RETAINS the volume records, which is the state this starts from.
	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("preparing: uninstall rc = %d\n%s", rc, r.said())
	}
	r.removeObjects(vol)
	r.appendRows("object\tkey=volume:" + vol + "\tclass=volume\tname=" + vol + "\tnonce=ncontested\tgen=1\tproduct=p1\trole=state")
	r.reset()
	r.confirm("yes")

	if rc := r.uninstallFamily(true); rc == cliio.ExitOK {
		t.Fatalf("the family purge proceeded over a volume it could not prove is ours\n%s", r.said())
	}
	r.mustSay("PRESERVED volume " + vol)
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset over a preserved object: %v", err)
	}
}

func TestUninstallDoesNotTombstoneAContainerItCouldNotRemove(t *testing.T) {
	// TOMBSTONE ONLY ON A REMOVAL THAT ACTUALLY SUCCEEDED. Recording a removal that did not happen
	// strips the container's authority record while it is still running — after which nothing can
	// ever remove it, and the unaccounted gate wedges every later operation over it.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fake.InterruptOn = "DELETE /containers/" + c

	if rc := r.uninstall("p1", false); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1 — a removal that did not happen is not a success\n%s", rc, r.said())
	}
	r.mustSay("could not remove the container")
	if !r.containerExists(c) {
		t.Fatal("the container is gone, so the fixture did not exercise a FAILED removal")
	}
	if _, err := prov.Find(r.ledgerNow(), prov.ClassContainer, c); err != nil {
		t.Fatalf("the container's provenance record was dropped for a removal that did not happen: %v", err)
	}
	if r.tombstoned(prov.ClassContainer, c) {
		t.Fatal("a tombstone was written for a removal that did not happen")
	}
}

func TestProductPurgePreservesAVolumeItCannotProveIsOurs(t *testing.T) {
	// The product-scoped sibling of the family rule, reached where nothing earlier pre-empts it:
	// two records answer for one volume name, so authority cannot be established — and the volume
	// is absent from the runtime, so the unaccounted sweep never sees it and the gate does not stop
	// the verb first.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	vol := "mythical-" + r.ident() + "-p1-state"
	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("preparing: uninstall rc = %d\n%s", rc, r.said())
	}
	r.removeObjects(vol)
	r.appendRows("object\tkey=volume:" + vol + "\tclass=volume\tname=" + vol +
		"\tnonce=ncontested\tgen=1\tproduct=p1\trole=state")
	r.reset()
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("the purge reported success over a volume it could not prove is ours\n%s", r.said())
	}
	r.mustSay("PRESERVED volume " + vol)
}

func TestFamilyUninstallRefusesAContainerRecordWithNoName(t *testing.T) {
	// The container half of the fail-closed name rule. A record that passes the listing's format
	// check but carries no `name=` cannot be acted on; skipping it silently would leave `preserved`
	// clear and let the reset wipe its provenance while the object it describes still stands.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=container:nameless\tclass=container\tnonce=n\tgen=1")
	r.confirm("yes")

	if rc := r.uninstallFamily(false); rc == cliio.ExitOK {
		t.Fatalf("the family uninstall reset the ledger over a record it could not act on\n%s", r.said())
	}
	if _, err := r.ledgerNow().IdentGet(); err != nil {
		t.Fatalf("the ledger was reset anyway: %v", err)
	}
}

func TestFamilyUninstallReadsTheListingBeforeItPrompts(t *testing.T) {
	// A prompt that arrives about work that cannot be done either way is not a decision point. The
	// listings are read FIRST, so an unreadable ledger refuses on its own terms — and so the
	// --purge warning can name what it is about to destroy, instead of the one prompt guarding
	// every volume on the machine saying "THAT IS YOUR DATA" without saying which data.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tmalformed-no-equals")

	// No MI_CONFIRM at all: if the prompt came first, the refusal would be "not confirmed".
	if rc := r.uninstallFamily(true); rc == cliio.ExitOK {
		t.Fatalf("the family purge reported success\n%s", r.said())
	}
	r.mustSay("could not be fully read")
	r.mustNotSay("not confirmed")
	r.mustNotSay("THAT IS YOUR DATA")
}

func TestPurgeRefusesAProductVolumeRecordWithNoName(t *testing.T) {
	// The product-scoped sibling of the family fail-closed name rule. A record attributed to this
	// product but carrying no `name=` cannot be acted on: `--purge` must say so and report the
	// failure, not step over it and then claim the purge completed.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("object\tkey=volume:nameless\tclass=volume\tproduct=p1\tnonce=n\tgen=1")
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc == cliio.ExitOK {
		t.Fatalf("the purge reported success over a record it could not act on\n%s", r.said())
	}
	r.mustSay("readable name; --purge cannot act on it")
	// And the warning named it too, so the operator saw it before answering.
	r.mustSay("(a volume whose record carries no readable name)")
}

func TestPurgeStopsWhenTheLedgerWillNotRecordWhatItRemoved(t *testing.T) {
	// EVERY OTHER FAILURE IN THE REMOVAL LOOP IS ABOUT ONE OBJECT and leaves the rest of the
	// operation meaningful. A ledger that will not record what was just removed is not that: from
	// there, every further removal is a removal nothing will record, which is why the reference
	// spells this one `|| return 1` in the middle of the loop.
	//
	// The fixture damages the FIRST volume's generation counter. Authority still passes (it reads
	// the nonce and the object's own labels, not the generation), the volume is really removed, and
	// the tombstone that must outlive it then refuses — the one window where the runtime has
	// already changed and the ledger will not follow.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	first := "mythical-" + ident + "-p1-state"
	second := "mythical-" + ident + "-p1-secrets"
	nonce := r.volumeRecordNonce(first)
	r.replaceRow("name="+first, "object\tkey=volume:"+first+"\tclass=volume\tname="+first+
		"\tnonce="+nonce+"\tgen=notanumber\tproduct=p1\trole=state")
	r.reset()
	r.confirm("yes")

	if rc := r.uninstall("p1", true); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay("generation that is not a number")
	if r.volumeExists(first) {
		t.Fatal("the fixture did not reach the tombstone — the volume was never removed")
	}
	// AND IT STOPPED: the sibling volume is untouched, because nothing would have recorded its
	// removal either. (The removal loop walks the object records in ledger order, and the state
	// volume is recorded before the secrets volume; if that ever changes this assertion says so.)
	if !r.volumeExists(second) {
		t.Fatal("the purge went on removing volumes after the ledger refused to record one")
	}
	// The container's removal, which happened BEFORE the failure, is durable — the reference's
	// `return 1` left its earlier writes on disk, and so must this one.
	if !r.tombstoned(prov.ClassContainer, r.container("p1")) {
		t.Fatal("the work that succeeded before the stop was not made durable")
	}
}

// TestUninstallNeverPersistsAHalfEditedLedger: the container's two ledger edits are one change.
//
// They used to run one after the other against the LIVE ledger. Each editor is individually atomic
// — prov.Tombstone and state.Forget both ask every cardinality question before writing anything —
// and stopAfterPartialRemoval's own comment rested on exactly that: "the failing edit itself mutates
// nothing, so what is persisted is exactly the work that succeeded". That argument is true of each
// editor ALONE and false of the PAIR, which is the gap a per-editor argument cannot see.
//
// With two contradicting desired rows for the container, Tombstone SUCCEEDS and Forget REFUSES —
// and stopAfterPartialRemoval then persists what is in memory. The result on disk: the container's
// provenance record is gone while the contradictory desired state SURVIVES. A ledger that says
// nothing owns this name and also says what state that name should be in, with the object it was
// about removed from the runtime and no record left that it was ever ours.
func TestUninstallNeverPersistsAHalfEditedLedger(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	// A SECOND desired row for the same container — the damaged ledger a repair or a hand edit
	// leaves, and the one shape state.Forget is specified to refuse.
	r.appendRows("desired\tcontainer=" + c + "\tstate=stopped\tverify=none")
	before := strings.Join(r.ledgerOnDisk().Lines(), "\n")
	// THE PREMISE IS MEASURED. If the fixture did not actually make Forget refuse, every assertion
	// below would be about an ordinary successful uninstall and would pass meaning nothing.
	if err := state.Forget(r.ledgerNow(), c); err == nil {
		t.Fatal("the fixture did not make state.Forget refuse — the half-edit branch is not reached")
	}
	r.reset()

	if rc := r.uninstall("p1", false); rc == cliio.ExitOK {
		t.Fatalf("an uninstall whose ledger edit cannot be made reported success\n%s", r.said())
	}

	// THE LEDGER ON DISK IS THE ASSERTION. Neither edit may have landed: they are one change.
	after := strings.Join(r.ledgerOnDisk().Lines(), "\n")
	if after != before {
		t.Fatalf("a refused uninstall persisted a half-edited ledger.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := prov.Find(r.ledgerOnDisk(), prov.ClassContainer, c); err != nil {
		t.Fatalf("the container's provenance was tombstoned while the desired state it contradicts survived: %v", err)
	}

	// AND THE RUNTIME WAS NOT TOUCHED. Computing the edits before the removal is what turns
	// "removed it, then found nothing could be written down" into a refusal that changed nothing.
	if _, err := r.c.ContainerInspect(context.Background(), c); err != nil {
		t.Fatalf("the container was removed by an uninstall that could not record the removal: %v", err)
	}
}

// TestUninstallLetsAPerObjectRefusalWinOverALedgerOne: the two refusals have different SCOPES, and
// the order they are asked in decides which the operator gets.
//
// "This container is not ours" is about ONE object — the reference reports it and carries on with
// the rest. "The ledger cannot record removals" is about ALL of them, and stopAfterPartialRemoval
// halts the verb. Building the ledger edits before asking the authority question inverted that: a
// damaged ledger hard-stopped the whole uninstall even where authority would have refused this one
// container and the verb would have gone on to the volumes. Authority is a READ, so asking it first
// costs nothing and keeps the smaller refusal smaller.
func TestUninstallLetsAPerObjectRefusalWinOverALedgerOne(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	// BOTH problems at once: the container can no longer be proven ours, AND the ledger carries
	// two contradicting desired rows so state.Forget would refuse.
	r.standForeignContainer(c)
	r.appendRows("desired\tcontainer=" + c + "\tstate=stopped\tverify=none")
	if err := state.Forget(r.ledgerNow(), c); err == nil {
		t.Fatal("the fixture did not make state.Forget refuse — the ordering is not exercised")
	}
	r.reset()

	rc := r.uninstall("p1", false)
	if rc == cliio.ExitOK {
		t.Fatalf("an uninstall over an object it cannot account for reported success\n%s", r.said())
	}
	// THE PER-OBJECT REFUSAL IS WHAT IS REPORTED, and the verb went on to the volumes rather than
	// halting on the ledger.
	r.mustSay("is preserved (see above)")
	r.mustSay("keeping volume")
	if !r.containerExists(c) {
		t.Fatal("a container that could not be proven ours was removed")
	}
	// And nothing was written: the clone is discarded on the authority refusal.
	if _, err := prov.Find(r.ledgerOnDisk(), prov.ClassContainer, c); err != nil {
		t.Fatalf("the container's provenance was tombstoned on a refusal: %v", err)
	}
}

// TestUninstallRetiresARecordForAContainerTheRuntimeSaysIsGone: a 404 from ContainerRemove is the
// goal reached, not a failure.
//
// The container can disappear between the authority question and the removal — an operator, another
// tool, a reaper. The daemon then answers 404, which is an ANSWER: the object is gone. Treating it
// as "could not remove" KEPT the provenance and desired-state records for a container the runtime
// had just said does not exist, and nothing could ever retire them, because every later attempt
// gets the same 404. internal/bringup already draws this distinction from the same call.
func TestUninstallRetiresARecordForAContainerTheRuntimeSaysIsGone(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	// THE WINDOW ITSELF, not the state after it. Removing the container up front would make
	// prov.Authority answer ErrGone and the removal would never be attempted — the test would pass
	// down a different branch entirely. RemoveMissing keeps every INSPECT answering (so authority
	// proves the container ours) and 404s the DELETE alone, which is exactly an object removed by
	// something else between those two calls.
	r.fake.RemoveMissing = c
	r.reset()

	if rc := r.uninstall("p1", false); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 — a container the runtime says is gone is not a failed removal\n%s", rc, r.said())
	}
	// THE RECORDS ARE RETIRED. A provenance record for an object that does not exist is one no
	// later run can ever clear.
	if _, err := prov.Find(r.ledgerOnDisk(), prov.ClassContainer, c); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance survived for a container the runtime says is gone: %v", err)
	}
	if _, err := state.DesiredGet(r.ledgerOnDisk(), c); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("desired state survived for a container the runtime says is gone: %v", err)
	}
}
