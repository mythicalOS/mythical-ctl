package verbs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — the Task 22 share of tests/unit/verbs.bats and tests/acceptance/lifecycle.bats, as
// internal/verbs/owners.go partitions them. Five of the fifty are CLI-surface tests and are claimed
// in cmd/mythical-ctl/main_test.go beside the dispatcher they exercise; the other forty-five are
// here.
//
// PORTED: tests/unit/verbs.bats: "install converges: identity, membership, network, volume, container, running, verified" -> TestInstallConverges
// PORTED: tests/unit/verbs.bats: "install is idempotent — a re-install leaves user-owned files byte-identical" -> TestInstallIsIdempotent
// PORTED: tests/unit/verbs.bats: "install always declares running — re-installing a stopped product brings it back up (§6b.3)" -> TestInstallAlwaysDeclaresRunning
// PORTED: tests/unit/verbs.bats: "install called as a library returns usage (2) on a value-less --image, never loops forever" -> TestInstallLibraryRefusesValuelessImage
// PORTED: tests/unit/verbs.bats: "installing a SECOND product leaves the first's config and data untouched" -> TestSecondProductLeavesTheFirstAlone
// PORTED: tests/unit/verbs.bats: "a NOT-LAUNCHED manifest prints the message, exits 3, and creates NO product state" -> TestNotLaunchedCreatesNoProductState
// PORTED: tests/unit/verbs.bats: "a not-launched attempt attempts NO PULL AT ALL" -> TestNotLaunchedPullsNothing
// PORTED: tests/unit/verbs.bats: "a not-launched attempt DOES record the trust floor — otherwise a stale manifest replays later" -> TestNotLaunchedRecordsTheTrustFloor
// PORTED: tests/unit/verbs.bats: "a LAUNCHED manifest whose image is not found is a LOUD RELEASE ERROR, never the not-launched message" -> TestUnpullableLaunchedImageIsLoud
// PORTED: tests/unit/verbs.bats: "auth and network pull failures are loud and distinguishable" -> TestPullFailuresAreDistinguishable
// PORTED: tests/unit/verbs.bats: "stop sets desired=stopped BEFORE stopping, and a later run leaves it stopped" -> TestStopSetsDesiredBeforeStopping
// PORTED: tests/unit/verbs.bats: "stop FAILS (1) when the runtime stop did not happen — a swallowed failure is not success" -> TestStopFailsOnASwallowedStop
// PORTED: tests/unit/verbs.bats: "install does NOT pull when the image-presence check could not be asked (rc1 is not absence)" -> TestInstallDoesNotPullOnAnUnaskablePresenceCheck
// PORTED: tests/unit/verbs.bats: "restart is REFUSED on a stopped product rather than silently starting it" -> TestRestartRefusedOnAStoppedProduct
// PORTED: tests/unit/verbs.bats: "restart FAILS (1) on a swallowed stop — a container that never went down is not a restart" -> TestRestartFailsOnASwallowedStop
// PORTED: tests/unit/verbs.bats: "recreate of a STOPPED product stays stopped" -> TestRecreateOfAStoppedProductStaysStopped
// PORTED: tests/unit/verbs.bats: "recreate live-verifies like a fresh install, not assumed good for replacing a working one" -> TestRecreateLiveVerifies
// PORTED: tests/unit/verbs.bats: "an ADOPTED volume keeps its product, role and data class — so --purge still finds it" -> TestAdoptedVolumeKeepsItsFields
// PORTED: tests/unit/verbs.bats: "an unrecorded same-identity object STOPS a mutating verb" -> TestUnrecordedSameIdentityObjectStopsAVerb
// PORTED: tests/unit/verbs.bats: "the shared bootstrap-secret gate refuses a secret the policy no longer grants (install+recreate share it)" -> TestSharedBootstrapSecretGate
// PORTED: tests/unit/verbs.bats: "a manifest for a DIFFERENT product is refused before any object is created" -> TestManifestForADifferentProductIsRefused
// PORTED: tests/unit/verbs.bats: "the family lock is held for the whole of a mutating verb, and released after" -> TestFamilyLockHeldThroughoutAndReleased
// PORTED: tests/unit/verbs.bats: "a verb refuses when the lock is already held by a live process" -> TestVerbRefusesWhenTheLockIsHeld
// PORTED: tests/unit/verbs.bats: "recreate ENSURES the selected image before removing the container — an unpullable image preserves it" -> TestRecreateEnsuresTheImageBeforeRemoving
// PORTED: tests/unit/verbs.bats: "a mutating verb STOPS when probe cleanup cannot complete — an unresolved probe is not stepped over" -> TestProbeCleanupFailureStopsAVerb
// PORTED: tests/unit/verbs.bats: "install REFUSES to create a volume when its provenance record is unreadable (rc 1 is not rc 3)" -> TestInstallRefusesAnUnreadableVolumeRecord
// PORTED: tests/unit/verbs.bats: "recreate NORMALIZES a context failure to operational failure (1), never a raw or undefined exit code" -> TestRecreateNormalizesAContextFailure
// PORTED: tests/unit/verbs.bats: "install REFUSES to create a container when its provenance record is ambiguous (rc 1 fail-closed)" -> TestInstallRefusesAnAmbiguousContainerRecord
// PORTED: tests/unit/verbs.bats: "a REFUSED install (unaccounted object) does NOT advance the anti-rollback trust floor" -> TestRefusedInstallDoesNotAdvanceTheFloor
// PORTED: tests/unit/verbs.bats: "start reports an ambiguous container provenance as unreadable, never 'not installed' (rc 1 is not rc 3)" -> TestStartReportsAmbiguousProvenanceAsUnreadable
// PORTED: tests/unit/verbs.bats: "start returns operational failure (1), never undefined 4, when the container needs a rebuild" -> TestStartNormalizesARebuildPlan
// PORTED: tests/unit/verbs.bats: "start/stop/restart REFUSE a foreign container that reuses our name (nonce authority, not just a record)" -> TestForeignContainerRefusedByStartStopRestart
// PORTED: tests/unit/verbs.bats: "a re-install whose container removal FAILS does not proceed to bring-up and restores the container" -> TestInstallRemovalFailurePreservesTheContainer
// PORTED: tests/unit/verbs.bats: "a recreate whose container removal FAILS does not proceed to bring-up and restores the container" -> TestRecreateRemovalFailurePreservesTheContainer
// PORTED: tests/unit/verbs.bats: "recreate HONORS a recorded force-install on a still-not-launched manifest, rather than refusing it" -> TestRecreateHonorsARecordedForceInstall
// PORTED: tests/acceptance/lifecycle.bats: "batch: all products succeed → 0" -> TestBatchAllSucceed
// PORTED: tests/acceptance/lifecycle.bats: "batch: one succeeds, one not-launched → 3" -> TestBatchOneNotLaunched
// PORTED: tests/acceptance/lifecycle.bats: "batch: any failure → 1, even when another product installed fine" -> TestBatchAnyFailure
// PORTED: tests/acceptance/lifecycle.bats: "batch: FAILING ONE PRODUCT MUST NOT ABORT THE OTHERS — the later product still installs" -> TestBatchDoesNotAbortOnTheFirstFailure
// PORTED: tests/acceptance/lifecycle.bats: "batch reports per product" -> TestBatchReportsPerProduct
// PORTED: tests/acceptance/lifecycle.bats: "a first-ever not-launched install mints NO identity or product state (§10a: no product state)" -> TestFirstEverNotLaunchedMintsNothing
// PORTED: tests/acceptance/lifecycle.bats: "an interrupted install converges on a re-run, with no half-state" -> TestInterruptedInstallConvergesOnARerun
// PORTED: tests/acceptance/lifecycle.bats: "every published port binds 127.0.0.1 on the ACTUAL runtime object" -> TestPublishedPortsBindLoopbackOnly
// PORTED: tests/acceptance/lifecycle.bats: "network mode host in mythical.conf is rejected" -> TestHostNetworkModeIsRejected
// PORTED: tests/acceptance/lifecycle.bats: "two concurrent installs are serialized under the family lock, with no lost state" -> TestConcurrentInstallsAreSerialized

// --- install -------------------------------------------------------------------------------------

func TestInstallConverges(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	c := r.container("p1")
	if !r.isMember("p1") {
		t.Fatal("p1 is not a member")
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q, want running", got)
	}
	if out := r.outstanding(c); len(out) != 0 {
		t.Fatalf("outstanding checks after a verified install: %v", out)
	}
	// The network, the volumes and the container are all really there.
	if !r.volumeExists("mythical-" + r.ident() + "-p1-state") {
		t.Fatal("the state volume was not created")
	}
	if !r.containerExists(c) {
		t.Fatal("the container was not created")
	}
	// AND THE ANTI-ROLLBACK FLOORS SURVIVED THE INSTALL THAT ESTABLISHED THEM. The document door
	// writes them to the ledger FILE itself, so an install that went on editing an in-memory copy
	// taken before that door would erase all three the moment it persisted — silently, and only a
	// later replay of a withdrawn document would reveal it.
	for _, docid := range []string{"index", "policy", "manifest:p1"} {
		if got := r.floorOf(docid); got != "1" {
			t.Fatalf("the trust floor for %s is %q after a successful install, want 1", docid, got)
		}
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	// The operator edits their own file; a re-install must leave it byte-identical.
	pconf := filepath.Join(r.home, "p1.conf")
	f, err := os.OpenFile(pconf, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n# operator note\nPEER=http://x\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before := readAll(t, pconf)
	famBefore := readAll(t, conf.FamilyPath(r.home))

	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("re-install rc = %d, want 0\n%s", rc, r.said())
	}
	if got := readAll(t, pconf); got != before {
		t.Fatalf("p1.conf changed across a re-install:\n%q\n%q", before, got)
	}
	if got := readAll(t, conf.FamilyPath(r.home)); got != famBefore {
		t.Fatalf("mythical.conf changed across a re-install:\n%q\n%q", famBefore, got)
	}
}

func TestInstallAlwaysDeclaresRunning(t *testing.T) {
	// install EXPRESSES intent and it is always `running`; only recreate preserves. Reading the
	// prior generation's desired state rebuilt the container STOPPED and reported success over a
	// product that was not running.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	if rc := r.stop("p1"); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	if got := r.observed(c); got != state.ObsStopped {
		t.Fatalf("observed %q after stop, want stopped", got)
	}
	r.reset()

	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("re-install rc = %d, want 0\n%s", rc, r.said())
	}
	if got := r.desired(c); got != state.Running {
		t.Fatalf("desired %q, want running", got)
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q, want running", got)
	}
	if out := r.outstanding(c); len(out) != 0 {
		t.Fatalf("outstanding checks: %v", out)
	}
}

func TestInstallLibraryRefusesValuelessImage(t *testing.T) {
	// THE LIBRARY CONTRACT, not the dispatcher's guard: a caller reaching this package directly has
	// no entrypoint parser in front of it, so the verb must reject its own value-less option itself
	// — at once, as a usage error, with nothing attempted. (The shell original also proves it does
	// not spin forever; here there is no option loop to spin, and the assertion that nothing was
	// attempted is what carries over.)
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	before := len(r.fake.RequestLog())

	rc := r.install("p1", withImage(""))
	if rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2 (usage)\n%s", rc, r.said())
	}
	r.mustSay("requires a value")
	if got := len(r.fake.RequestLog()); got != before {
		t.Fatalf("a usage error attempted %d daemon request(s)", got-before)
	}
}

func TestSecondProductLeavesTheFirstAlone(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	ident := r.ident()
	p1conf := readAll(t, filepath.Join(r.home, "p1.conf"))

	r.writeProduct("p2")
	if rc := r.install("p2"); rc != cliio.ExitOK {
		t.Fatalf("installing p2: rc = %d\n%s", rc, r.said())
	}
	if got := readAll(t, filepath.Join(r.home, "p1.conf")); got != p1conf {
		t.Fatal("installing a second product rewrote the first's config")
	}
	// The SHARED mythical.conf keeps its family key unclobbered.
	if v, err := conf.Get(conf.FamilyPath(r.home), "MYTHICAL_TELEMETRY_KEY"); err != nil || v != "tk" {
		t.Fatalf("the family telemetry key is %q (%v)", v, err)
	}
	if !r.isMember("p1") {
		t.Fatal("p1 lost its membership")
	}
	if !r.volumeExists("mythical-" + ident + "-p1-state") {
		t.Fatal("p1's state volume is gone")
	}
}

// --- not launched ---------------------------------------------------------------------------------

func TestNotLaunchedCreatesNoProductState(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1", notLaunched())
	r.mintIdentity()
	before := r.fake.Snapshot()

	rc := r.install("p1")
	if rc != cliio.ExitNotLaunched {
		t.Fatalf("rc = %d, want 3\n%s", rc, r.said())
	}
	r.mustSay("has not launched yet")
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the runtime changed:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(r.home, "p1.conf")); err == nil {
		t.Fatal("a not-launched install created p1.conf")
	}
}

func TestNotLaunchedPullsNothing(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1", notLaunched())
	r.mintIdentity()
	_ = r.install("p1")
	if n := r.pullCount(); n != 0 {
		t.Fatalf("a not-launched attempt made %d pull(s)", n)
	}
}

func TestNotLaunchedRecordsTheTrustFloor(t *testing.T) {
	// Otherwise a stale manifest replays later: the floor for the manifest that was READ is
	// recorded before the launch-state branch, and it is the one enumerated exempt side effect.
	r := newRig(t)
	r.writeProduct("p1", notLaunched(), docVersion("7"))
	r.mintIdentity()
	_ = r.install("p1")
	if got := r.floorOf("manifest:p1"); got != "7" {
		t.Fatalf("trust floor for manifest:p1 is %q, want 7", got)
	}
}

func TestFirstEverNotLaunchedMintsNothing(t *testing.T) {
	// On a brand-new machine — this rig mints no identity — a not-launched install must create NO
	// installer state: no identity, no membership, no product. Learning from an authentic manifest
	// that a product is unpublished cannot be the act that turns a fresh machine into an
	// installation. The trust floor IS still recorded, so the ledger file exists for that reason.
	r := newRig(t)
	r.writeProduct("p1", notLaunched())

	if rc := r.install("p1"); rc != cliio.ExitNotLaunched {
		t.Fatalf("rc = %d, want 3\n%s", rc, r.said())
	}
	r.mustSay("has not launched yet")
	l := r.ledgerNow()
	if _, err := l.IdentGet(); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("an installation identity was minted: %v", err)
	}
	if err := l.MemberHas("p1"); err == nil {
		t.Fatal("p1 was recorded as a member")
	}
}

// --- image acquisition -----------------------------------------------------------------------------

func TestUnpullableLaunchedImageIsLoud(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.fake.PullOutcome = "notfound"

	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay("could not be pulled")
	// A LAUNCHED manifest whose image is missing is a release error, never the reassuring notice.
	r.mustNotSay("has not launched yet")
}

func TestPullFailuresAreDistinguishable(t *testing.T) {
	for _, tc := range []struct{ outcome, phrase string }{
		{"auth", "denied"},
		{"neterr", "no such host"},
	} {
		r := newRig(t)
		r.writeProduct("p1")
		r.mintIdentity()
		r.fake.PullOutcome = tc.outcome
		if rc := r.install("p1"); rc != cliio.ExitFail {
			t.Fatalf("%s: rc = %d, want 1\n%s", tc.outcome, rc, r.said())
		}
		// The registry's own words ride the failure: auth and network are never folded into one
		// message a wrapper cannot tell apart.
		r.mustSay(tc.phrase)
	}
}

func TestInstallDoesNotPullOnAnUnaskablePresenceCheck(t *testing.T) {
	// The daemon answers through preflight, the gate and net setup, then goes unreachable FROM the
	// image inspect on — so both the presence check and the follow-up ping are unanswerable. A
	// daemon that could not be ASKED must STOP, not fold "could not ask" into "absent" and pull.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.fake.SetDownFrom(imageInspectKey(t, r, digestRef("p1")))

	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if n := r.pullCount(); n != 0 {
		t.Fatalf("%d pull(s) attempted on an unanswerable presence check", n)
	}
}

// imageInspectKey asks the fake for one image inspect and reads back the exact request key its
// DownFrom knob matches on, so the fixture cannot drift from the client's own URL shape.
func imageInspectKey(t *testing.T, r *rig, ref string) string {
	t.Helper()
	before := len(r.fake.RequestLog())
	_, _ = r.c.ImageInspect(context.Background(), ref)
	if len(r.fake.RequestLog()) == before {
		t.Fatal("the image inspect made no request")
	}
	req := r.fake.RequestLog()[len(r.fake.RequestLog())-1]
	method, path, ok := strings.Cut(req, " ")
	if !ok {
		t.Fatalf("unexpected request record %q", req)
	}
	return method + " " + strings.TrimPrefix(path, "/"+engine.APIVersion)
}

// --- stop -------------------------------------------------------------------------------------------

func TestStopSetsDesiredBeforeStopping(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	if rc := r.stop("p1"); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	if got := r.desired(c); got != state.Stopped {
		t.Fatalf("desired %q, want stopped", got)
	}
	// A later run leaves it stopped: nothing restarts it behind the operator's back.
	if got := r.observed(c); got != state.ObsStopped {
		t.Fatalf("observed %q, want stopped", got)
	}
}

func TestStopFailsOnASwallowedStop(t *testing.T) {
	// The stop is attempted and dies. Reporting success here would leave the product RUNNING while
	// the CLI says it stopped.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fake.InterruptOn = "POST /containers/" + c + "/stop"

	if rc := r.stop("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	// The intent was still committed FIRST, but the container is still present and running because
	// the stop never took effect.
	if got := r.desired(c); got != state.Stopped {
		t.Fatalf("desired %q, want stopped", got)
	}
	if !r.running(c) {
		t.Fatal("the container is not running, so the fixture did not fabricate a swallowed stop")
	}
}

// --- restart -----------------------------------------------------------------------------------------

func TestRestartRefusedOnAStoppedProduct(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	if rc := r.stop("p1"); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	r.reset()

	if rc := r.restart("p1"); rc == cliio.ExitOK {
		t.Fatalf("restart succeeded on a stopped product\n%s", r.said())
	}
	r.mustSay("is stopped, so there is nothing to restart")
	if got := r.observed(r.container("p1")); got != state.ObsStopped {
		t.Fatalf("observed %q — restart started a product the operator stopped", got)
	}
}

func TestRestartFailsOnASwallowedStop(t *testing.T) {
	// restart's stop is a MEANS, and a swallowed failure leaves the container RUNNING. The
	// reconciler then sees it live with a resolving alias and reports success — a restart that never
	// restarted.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fake.InterruptOn = "POST /containers/" + c + "/stop"

	if rc := r.restart("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	// The identity of the failure: it is the STOP that did not happen. Without this the reconciler
	// finds a live container whose alias resolves, clears the check and reports success — a restart
	// that never restarted, which is the whole point of the assertion.
	r.mustSay("could not be restarted")
	if !r.running(c) {
		t.Fatal("the container is not running, so the fixture did not fabricate a swallowed stop")
	}
}

// --- recreate -----------------------------------------------------------------------------------------

func TestRecreateOfAStoppedProductStaysStopped(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	if rc := r.stop("p1"); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	r.reset()

	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d, want 0\n%s", rc, r.said())
	}
	c := r.container("p1")
	if got := r.desired(c); got != state.Stopped {
		t.Fatalf("desired %q, want stopped", got)
	}
	if got := r.observed(c); got != state.ObsStopped {
		t.Fatalf("observed %q, want stopped", got)
	}
}

func TestRecreateLiveVerifies(t *testing.T) {
	// Replacing a working container is not evidence the replacement works: recreate live-verifies
	// like a fresh install.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d\n%s", rc, r.said())
	}
	if out := r.outstanding(c); len(out) != 0 {
		t.Fatalf("outstanding after a verified recreate: %v", out)
	}
	r.reset()

	// The alias now resolves to an address that is not this container's.
	r.resolveAddr = "9.9.9.9"
	_ = r.recreate("p1")
	out := r.outstanding(c)
	if len(out) == 0 {
		t.Fatal("a recreate whose alias did not resolve to itself cleared the check anyway")
	}
	found := false
	for _, ck := range out {
		if ck.Kind == state.CheckAlias {
			found = true
		}
	}
	if !found {
		t.Fatalf("the outstanding set does not owe an alias check: %v", out)
	}
}

func TestRecreateEnsuresTheImageBeforeRemoving(t *testing.T) {
	// install had an image gate BEFORE it replaced the container; recreate did not, so a manifest
	// that advanced to an unpulled image let recreate tear the container down and then fail to
	// rebuild it — leaving the operator with nothing.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q before the recreate", got)
	}
	// The selected image is now absent (a GC, or a manifest advanced to a digest never pulled) and
	// the registry cannot be reached, so it cannot be made present again.
	r.fake.InspectMissing = digestRef("p1")
	r.fake.PullOutcome = "neterr"

	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	// The container was NOT stopped or removed — it is still there and still running.
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q — the recreate tore down a working container it could not rebuild", got)
	}
}

// TestRecreateRefusesAnUnassemblableLaunchWithTheContainerIntact is not a bats port: the shell suite
// pins this ordering for the IMAGE (which is ported above), and gets it for the launch spec
// structurally, because the reference builds that spec before it stops anything. In this tree the
// spec is assembled inside the launch facade, which runs AFTER the removal — so the ordering the
// reference has for free has to be asserted here, or a recreate that could never have succeeded
// takes a working installation down on its way to finding out.
func TestRecreateRefusesAnUnassemblableLaunchWithTheContainerIntact(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	// The operator points a bindable role at a path that is not there. The launch cannot be
	// assembled from it, and finding that out must not cost them the running container.
	r.writeFile("mythical.conf", "MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_P1_STATE_BIND=/nonexistent-mythical-ctl-test/state\n")

	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q — the recreate tore down a container it could never have replaced", got)
	}
}

// TestRecreateRefusesAnUnsetSecretWithTheContainerIntact is not a bats port — the shell gets this
// ordering structurally, because it stages the secrets before it stops anything. Here the secret
// assembly lives inside the launch facade, which runs AFTER the removal, so the ordering has to be
// asserted. A declared secret that the policy grants but mythical.conf does not SET is a refusal
// the document door cannot see (it checks the GRANT, not the value), so this is the reachable half
// of the facade's own secret gate.
func TestRecreateRefusesAnUnsetSecretWithTheContainerIntact(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	// The operator empties mythical.conf of the value the manifest declares — and sets nothing else,
	// so no earlier gate has anything to object to. The secret is still GRANTED, so every document
	// still authenticates; there is simply nothing to inject.
	r.writeFile("mythical.conf", "# the operator cleared this file\n")

	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q — the recreate tore down a container it could never have replaced", got)
	}
}

// TestTheLaunchIsAssembledOnce is not a bats port — the shell gets this structurally, because it
// builds its launch arguments into an array ONCE and hands that array to the bring-up. Here the
// two halves are a dry run and a real create with a container removal between them, so the config
// that feeds both has to be read on the near side and CARRIED. Two things have to hold, and each
// is asserted against the way the other implementation would behave, not merely against a good
// outcome — an unchanged config makes read-once and read-twice produce identical results.
func TestTheLaunchIsAssembledOnce(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	// (a) CARRIED, NOT RE-DERIVED. The launcher is handed a host-port map that mythical.conf does
	// NOT say — the file names no port for this product, so anything re-deriving from it would
	// publish the manifest's 7480. The runtime object must follow what was carried.
	s, serr := openSession(r.d)
	if serr != nil {
		t.Fatal(serr)
	}
	pc, cerr := s.productCtx("p1", s.manifestPath("p1"))
	if cerr != nil {
		s.close()
		t.Fatal(cerr)
	}
	netID, nerr := s.netTarget(context.Background())
	if nerr != nil {
		s.close()
		t.Fatal(nerr)
	}
	if err := s.ensureImage(context.Background(), pc.Image, "p1"); err != nil {
		s.close()
		t.Fatal(err)
	}
	carried, lerr := s.launchConfig(pc, pc.Image, netID)
	if lerr != nil {
		s.close()
		t.Fatal(lerr)
	}
	if carried.HostPorts != nil {
		s.close()
		t.Fatalf("the fixture names a host port after all (%v) — the case cannot tell the two apart", carried.HostPorts)
	}
	carried.HostPorts = map[uint16]uint16{7480: 19999}
	// The installed container is in the way of the name; take it out as a replacement would.
	if err := s.replaceContainer(context.Background(), pc.Container, "test"); err != nil {
		s.close()
		t.Fatal(err)
	}
	launcher := &productLauncher{rt: s.rt, m: pc.Manifest, p: pc.Policy, cfg: carried}
	if _, err := launcher.Launch(context.Background(), pc.Container, "nlaunchtest"); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	info, err := r.c.ContainerInspect(context.Background(), pc.Container)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Ports) == 0 {
		t.Fatal("nothing was published")
	}
	for _, p := range info.Ports {
		if p.HostPort != "19999" {
			t.Fatalf("published on host port %q — the launcher re-derived the config instead of using the one it was carrying", p.HostPort)
		}
	}

	// (b) THE NONCE IS THE ONE THING SUBSTITUTED AT THE CREATE. The dry run stamps a placeholder on
	// its own copy because the spec validates every label; that placeholder must never reach a real
	// container, whose nonce is the intent's — the only thing that can later prove the object is
	// the one this installer recorded.
	if got := info.Labels["mythicalos.nonce"]; got != "nlaunchtest" {
		t.Fatalf("the container carries nonce %q, want the one the create was given", got)
	}
}

// TestRecreateReadsTheLaunchConfigOnce drives the REAL verb and counts. The case above proves the
// launcher honours the config it is carrying, and the one below proves the config is read on the
// near side of the teardown — but neither can see a verb that reads correctly BEFORE the preflight
// and then reads again AFTER the container is gone, which is exactly the shape the fix removed.
// Counting through the real Recreate is what distinguishes it.
func TestRecreateReadsTheLaunchConfigOnce(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	reads := 0
	real := readHostPorts
	// Every read answers a DIFFERENT port, so a second read is visible in the runtime object as
	// well as in the count — a counter alone would not say which answer was used.
	readHostPorts = func(home, product string, m *manifest.Manifest) (map[uint16]uint16, error) {
		reads++
		return map[uint16]uint16{7480: uint16(20000 + reads)}, nil
	}
	defer func() { readHostPorts = real }()

	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d\n%s", rc, r.said())
	}
	if reads != 1 {
		t.Fatalf("the verb read the launch config %d times, want 1 — the preflight and the create are judging different launches", reads)
	}
	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	// NON-VACUOUSLY: the manifest declares exactly one port, so an empty set is a recreate that
	// silently published nothing — which a bare range over the set would have passed.
	if len(info.Ports) != 1 {
		t.Fatalf("the runtime object publishes %d ports, want exactly the 1 the manifest declares", len(info.Ports))
	}
	if got := info.Ports[0].HostPort; got != "20001" {
		t.Fatalf("published on %q, want the port the FIRST read named (20001)", got)
	}
}

// TestRecreateRefusesAnUnreadableHostPortWithTheContainerIntact is not a bats port. It is the
// other half of assembling once: the config has to be read on the NEAR side of the teardown, so a
// value that cannot be used refuses while the working container is still there. Reading it inside
// the create instead would answer the same question after the container was already gone.
func TestRecreateRefusesAnUnreadableHostPortWithTheContainerIntact(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	// A configured host port that is not a port number at all.
	r.writeFile("mythical.conf", "MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_P1_PORT=notaport\n")

	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q — the recreate tore down a container before it read the config it needed", got)
	}
}

// TestStartAcceptsTheIndexOnlyWhenItProbes is not a bats port; it pins where the family index is
// read on the start path, which the shell gets from its call structure. Two halves:
// a plan that live-verifies ACCEPTS the index (advancing its anti-rollback floor, because the
// probe image is named by it and a merely-parsed index would let anyone with local write access
// name the image this installer runs); a plan that verifies nothing never touches it at all.
func TestStartAcceptsTheIndexOnlyWhenItProbes(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	if got := r.floorOf("index"); got != "1" {
		t.Fatalf("index floor is %q after the install, want 1", got)
	}

	// A NEWER index. A start that probes must ACCEPT it, not merely read it — consuming a newer
	// document while leaving the bar where the older one still clears it is the rollback window
	// the floor exists to close.
	r.indexVersion = "2"
	r.writeDocs()
	if rc := r.start("p1"); rc != cliio.ExitOK {
		t.Fatalf("start rc = %d\n%s", rc, r.said())
	}
	if got := r.floorOf("index"); got != "2" {
		t.Fatalf("index floor is %q after a start that probed, want 2 — the index was read, not accepted", got)
	}

	// And a plan that verifies NOTHING never needs it: with the container gone out of band the
	// reconciler answers "rebuild" without a probe, so an index that cannot be authenticated at all
	// must not turn that into an index complaint.
	r.reset()
	r.removeObjects(r.container("p1"))
	if err := os.Remove(filepath.Join(r.home, "index")); err != nil {
		t.Fatal(err)
	}
	if rc := r.start("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay("needs a rebuild that start/restart cannot perform")
}

func TestRecreateNormalizesAContextFailure(t *testing.T) {
	// The product is already installed, so ANY context failure — here the manifest is withdrawn to
	// not-launched — is an operational failure for a recreate, NOT a clean "not launched yet" (which
	// the batch aggregate treats as benign) and never an undefined code.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	r.writeProduct("p1", notLaunched())
	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
}

func TestRecreateHonorsARecordedForceInstall(t *testing.T) {
	// The manifest is STILL not-launched; recreate must honor the operator's force-install and
	// rebuild, not refuse — the same way it honors a recorded image override.
	r := newRig(t)
	r.writeProduct("p1", notLaunched())
	r.mintIdentity()
	if rc := r.install("p1", forced()); rc != cliio.ExitOK {
		t.Fatalf("forced install rc = %d, want 0\n%s", rc, r.said())
	}
	r.reset()

	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d, want 0\n%s", rc, r.said())
	}
}

// --- replacement removal ---------------------------------------------------------------------------

func TestInstallRemovalFailurePreservesTheContainer(t *testing.T) {
	// The replacement's removal fails, so install must NOT proceed into bring-up (which would
	// collide on the name and leave the product down): it restores the container it stopped.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fake.InterruptOn = "DELETE /containers/" + c

	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if !r.running(c) {
		t.Fatal("the container is not running — it was left stopped or removed")
	}
}

func TestRecreateRemovalFailurePreservesTheContainer(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fake.InterruptOn = "DELETE /containers/" + c

	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if !r.running(c) {
		t.Fatal("the container is not running — it was left stopped or removed")
	}
}

// --- gates ----------------------------------------------------------------------------------------

func TestAdoptedVolumeKeepsItsFields(t *testing.T) {
	// A PRE-EXISTING defect this closes. A volume that came back through adoption or reissue got a
	// provenance record with no `product` and no `role`, while the intent carrying them was
	// consumed. Product purge selects volumes by product, so such a volume matched nothing and was
	// neither removed nor reported: the purge said it was done and left the data behind.
	r := newRig(t)
	r.writeProduct("p2", extraRole("memory"), preciousRole("memory"))
	r.mintIdentity()
	ident := r.ident()
	vol := "mythical-" + ident + "-p2-memory"

	// The intent is opened and the volume created, but the confirmation never happened — the crash
	// window install's reconcile branch has to close.
	nonce := "nadoptxxxx"
	r.editLedger(func(l *ledger.Ledger) {
		if err := intent.Open(l, prov.ClassVolume, vol, nonce, time.Now(),
			ledger.Field{Key: "product", Value: "p2"},
			ledger.Field{Key: "role", Value: "memory"},
			ledger.Field{Key: "precious", Value: "1"}); err != nil {
			t.Fatal(err)
		}
	})
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, nonce)
		if perr != nil {
			t.Fatal(perr)
		}
		if err := rt.VolumeCreate(context.Background(), vol, p); err != nil {
			t.Fatal(err)
		}
	})

	if rc := r.install("p2"); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	rec, err := prov.Find(r.ledgerNow(), prov.ClassVolume, vol)
	if err != nil {
		t.Fatalf("no provenance for the adopted volume: %v", err)
	}
	for _, want := range [][2]string{{"product", "p2"}, {"role", "memory"}, {"precious", "1"}} {
		got, ok := ledger.FieldOf(rec, want[0])
		if !ok || got != want[1] {
			t.Fatalf("the adopted volume's record has %s=%q, want %q — purge selects on these", want[0], got, want[1])
		}
	}
}

func TestUnrecordedSameIdentityObjectStopsAVerb(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.createStrayVolume("mythical-" + r.ident() + "-stray")

	if rc := r.start("p1"); rc == cliio.ExitOK {
		t.Fatalf("a verb ran over an unrecorded same-identity object\n%s", r.said())
	}
	r.mustSay("unrecorded")
}

func TestProbeCleanupFailureStopsAVerb(t *testing.T) {
	// Probe cleanup runs first. Make it fail: an ambiguous identity means it cannot say which probe
	// container is ours, so the verb must not proceed to mutate state.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	r.appendRows("identity\tid=second")

	if rc := r.stop("p1"); rc == cliio.ExitOK {
		t.Fatalf("a verb stepped over an unresolved probe\n%s", r.said())
	}
	r.mustSay("probe")
}

func TestManifestForADifferentProductIsRefused(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	// p2's manifest file declares p1 — an index-vouched, digest-matching document for the WRONG
	// product. It must be refused before any object is created.
	r.writeProduct("p2", declaredAs("p1"))
	r.mintIdentity()
	before := r.fake.Snapshot()

	if rc := r.install("p2"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the runtime changed:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

func TestSharedBootstrapSecretGate(t *testing.T) {
	// install and recreate reach the bootstrap secrets through ONE path, so the gate cannot drift
	// between the verbs — which is what the case is about, and what is asserted: BOTH refuse.
	//
	// WHICH gate fires here is worth stating, because it is not the one the shell test reaches. The
	// reference calls its shared secret helper directly with a doctored policy; through the verbs,
	// a policy that no longer grants a declared secret is refused at the DOCUMENT DOOR, by
	// manifest.Check, before any launch is assembled. The facade's own per-key check behind it is
	// defence in depth, and in this tree it is unreachable through any legal document pair for
	// exactly that reason — an honest residual, not coverage. What the facade's secret assembly
	// DOES own reachably is the other half of the same rule: a granted secret that is not SET,
	// which TestRecreateRefusesAnUnsetSecretWithTheContainerIntact covers.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"MYTHICAL_TELEMETRY_KEY=tk"}
	if len(info.Env) != len(want) || info.Env[0] != want[0] {
		t.Fatalf("the container's environment is %v, want exactly %v", info.Env, want)
	}

	r.stripPolicyGrant("permitted_secret")
	if rc := r.recreate("p1"); rc != cliio.ExitFail {
		t.Fatalf("recreate rc = %d, want 1 on a revoked grant\n%s", rc, r.said())
	}
	r.mustSay("not entitled to the bootstrap secret")
	r.reset()
	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("install rc = %d, want 1 on a revoked grant\n%s", rc, r.said())
	}
	r.mustSay("not entitled to the bootstrap secret")
}

// --- the family lock ---------------------------------------------------------------------------------

func TestFamilyLockHeldThroughoutAndReleased(t *testing.T) {
	// The lock is taken at the top of a mutating verb and released on every return path. "Held for
	// the whole" is proved from INSIDE the verb: the helper fixture runs during the live
	// verification, deep inside install, and tries to take the lock there.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	var mu sync.Mutex
	probedInside := false
	busyInside := false
	base := r.helper
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		h, err := famlock.Acquire(r.home)
		mu.Lock()
		probedInside = true
		busyInside = errors.Is(err, famlock.ErrBusy)
		mu.Unlock()
		if err == nil {
			_ = famlock.Release(h)
		}
		return base(cmd, args, view, stdin)
	}

	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	mu.Lock()
	defer mu.Unlock()
	if !probedInside {
		t.Fatal("the in-flight probe never ran, so nothing was proved about the lock")
	}
	if !busyInside {
		t.Fatal("the family lock was NOT held while the verb was still working")
	}
	// And released after: the next caller takes it without waiting.
	h, err := famlock.Acquire(r.home)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	_ = famlock.Release(h)
}

func TestVerbRefusesWhenTheLockIsHeld(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	h, err := famlock.Acquire(r.home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()

	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay("in progress")
}

// --- fail-closed ledger reads -------------------------------------------------------------------------

func TestInstallRefusesAnUnreadableVolumeRecord(t *testing.T) {
	// Only ABSENT authorizes opening an intent and creating a volume; an ambiguous provenance record
	// must fail closed, never create a second volume under the same name.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	vol := "mythical-" + r.ident() + "-p1-state"
	r.appendRows("object\tkey=volume:" + vol + "\tclass=volume\tname=" + vol + "\tnonce=x\tgen=1")

	if rc := r.install("p1"); rc == cliio.ExitOK {
		t.Fatalf("install proceeded over an ambiguous volume record\n%s", r.said())
	}
	// With the volume STANDING, the unaccounted gate reaches it first and stops there — a ledger that
	// cannot say what accounts for an object it can see is exactly what that gate refuses on.
	r.mustSay("could not be asked about")

	// AND THE VERB'S OWN READ FAILS CLOSED TOO, which is the guard this test is really about. Take
	// the objects away so the gate has nothing to see — it scans what the runtime holds — and the
	// ambiguous record is then met by install's own provenance read, which must refuse rather than
	// create a second volume under the same name.
	r.reset()
	r.removeObjects(r.container("p1"), vol)
	if rc := r.install("p1"); rc == cliio.ExitOK {
		t.Fatalf("install created over an ambiguous volume record\n%s", r.said())
	}
	r.mustSay("could not be read; refusing to create a")
}

func TestInstallRefusesAnAmbiguousContainerRecord(t *testing.T) {
	// Two provenance records answer for the same container name. Install must NOT read that as "no
	// prior container" and create one over an unreadable ledger.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	c := r.container("p1")
	row := "object\tkey=container:" + c + "\tclass=container\tname=" + c + "\tnonce=%s\tgen=1"
	r.appendRows(strings.Replace(row, "%s", "a", 1), strings.Replace(row, "%s", "b", 1))

	if rc := r.install("p1"); rc == cliio.ExitOK {
		t.Fatalf("install proceeded over an ambiguous container record\n%s", r.said())
	}
	// The identity of the refusal: this install cannot TELL whether a container already stands
	// under that name. Removing the guard lets the ownership check downstream refuse instead, for a
	// different reason — an assertion that accepts either proves nothing about this one.
	r.mustSay("ambiguous or unreadable, so this")
	if r.containerExists(c) {
		t.Fatal("a container was created over an ambiguous ledger")
	}
}

func TestRefusedInstallDoesNotAdvanceTheFloor(t *testing.T) {
	// The unaccounted-object gate runs BEFORE the document door that records the manifest's trust
	// floor. A refused install must not advance the floor — otherwise a newer manifest fed to a
	// refused install would permanently block a rollback for an install that never happened.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	before := r.floorOf("manifest:p1")

	r.createStrayVolume("mythical-" + r.ident() + "-stray")
	r.writeProduct("p1", docVersion("99"))

	if rc := r.install("p1"); rc == cliio.ExitOK {
		t.Fatalf("the install was not refused\n%s", r.said())
	}
	if got := r.floorOf("manifest:p1"); got != before {
		t.Fatalf("the trust floor advanced from %q to %q on a REFUSED install", before, got)
	}
}

func TestStartReportsAmbiguousProvenanceAsUnreadable(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.appendRows("object\tkey=container:" + c + "\tclass=container\tname=" + c + "\tnonce=dup\tgen=1")

	if rc := r.start("p1"); rc == cliio.ExitOK {
		t.Fatalf("start ran over an ambiguous container record\n%s", r.said())
	}
	// An unreadable record is NOT "not installed": that answer sends the operator to install rather
	// than to repair.
	r.mustNotSay("is not installed")

	// The container STANDING is what the unaccounted gate stops on first. Take it away — the gate
	// scans what the runtime holds — and start's own record read is what must draw the same
	// distinction, because "absent" and "the ledger cannot say" send the operator to opposite places.
	r.reset()
	r.removeObjects(r.container("p1"))
	if rc := r.start("p1"); rc == cliio.ExitOK {
		t.Fatalf("start ran over an ambiguous container record\n%s", r.said())
	}
	r.mustNotSay("is not installed")
	r.mustSay("ambiguous or unreadable — this is not the same")
}

func TestStartNormalizesARebuildPlan(t *testing.T) {
	// The reconciler reports "needs a rebuild" for a plan only install/recreate can carry out.
	// Relaying that verdict as-is would leak an exit code the contract does not define.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.ContainerRemove(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	})

	if rc := r.start("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	// It is the REBUILD verdict that was normalized, named as such — not some other failure that
	// happens to also exit 1.
	r.mustSay("needs a rebuild that start/restart cannot perform")
}

// TestStartBringsAStoppedProductBackUp is not a bats port: it is the positive half of the
// reconciliation seam, and it exists because the negative half can pass for the wrong reason.
// MEASURED: reconcile was handing the probe arm an empty installation identity, so start and
// restart refused before the reconciler ever ran — and every owned test that expected a failure
// still passed, because it got one. A verb whose success path nothing exercises is a verb whose
// failure assertions prove nothing.
func TestStartBringsAStoppedProductBackUp(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	if rc := r.stop("p1"); rc != cliio.ExitOK {
		t.Fatalf("stop rc = %d\n%s", rc, r.said())
	}
	r.reset()

	if rc := r.start("p1"); rc != cliio.ExitOK {
		t.Fatalf("start rc = %d, want 0\n%s", rc, r.said())
	}
	if got := r.desired(c); got != state.Running {
		t.Fatalf("desired %q, want running", got)
	}
	if got := r.observed(c); got != state.ObsRunning {
		t.Fatalf("observed %q, want running", got)
	}
	// And the alias check it owed was PERFORMED, not merely declared.
	if out := r.outstanding(c); len(out) != 0 {
		t.Fatalf("start left %v outstanding — it did not verify what it started", out)
	}
}

func TestForeignContainerRefusedByStartStopRestart(t *testing.T) {
	// A container stands under OUR name but belongs to another installation, as if ours were deleted
	// out of band and the name reused. The unaccounted gate treats a foreign-LABELLED object as
	// unattributed and permits the verb — so the nonce-and-ownership check is what must stop it.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")
	r.fabricateForeignContainer(c)

	for name, run := range map[string]func(string) int{"start": r.start, "stop": r.stop, "restart": r.restart} {
		r.reset()
		if rc := run("p1"); rc == cliio.ExitOK {
			t.Fatalf("%s acted on another installation's container\n%s", name, r.said())
		}
	}
	if !r.containerExists(c) {
		t.Fatal("the foreign container was removed")
	}
	info, err := r.c.ContainerInspect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got := runtime.InstallLabel(info); got != "iotherinst" {
		t.Fatalf("the foreign container's installation label is %q — it was acted on", got)
	}
}

// --- batch ---------------------------------------------------------------------------------------------

func TestBatchAllSucceed(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2")
	if rc := Batch(context.Background(), r.d, "install", []string{"p1", "p2"}); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
}

func TestBatchOneNotLaunched(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2", notLaunched())
	if rc := Batch(context.Background(), r.d, "install", []string{"p1", "p2"}); rc != cliio.ExitNotLaunched {
		t.Fatalf("rc = %d, want 3\n%s", rc, r.said())
	}
	r.mustSay("p1")
	r.mustSay("has not launched yet")
}

func TestBatchAnyFailure(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	if rc := Batch(context.Background(), r.d, "install", []string{"p1", "nosuch"}); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
}

func TestBatchDoesNotAbortOnTheFirstFailure(t *testing.T) {
	// The whole reason the batch driver exists: one product failing must not take the others with
	// it. The FAILING product is first, so a driver that aborts never reaches p1.
	r := newRig(t)
	r.writeProduct("p1")
	if rc := Batch(context.Background(), r.d, "install", []string{"nosuch", "p1"}); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	if !r.isMember("p1") {
		t.Fatal("the later product was never installed — the batch aborted on the first failure")
	}
}

// TestBatchMapsAPerProductUsageErrorToAFailure is not a bats port: the shell aggregate's own
// refusals live in tests/unit/exit.bats. It is here because the MAPPING is this driver's, and it is
// what keeps the aggregate's contract reachable — a usage error means nothing was attempted, so it
// cannot be one product's outcome inside a batch that attempted others. Without the mapping the
// aggregate is handed a code it must refuse, and the batch reports a malformed call as a plain
// failure with no report of its own.
func TestBatchMapsAPerProductUsageErrorToAFailure(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	// An empty product name is a usage error from the verb — and the batch's own invocation was
	// still correct, so from here it is that product's operational failure.
	if rc := Batch(context.Background(), r.d, "install", []string{"", "p1"}); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay(": failed")
	r.mustNotSay(": usage error")
	// The later product still ran.
	if !r.isMember("p1") {
		t.Fatal("the batch aborted on the malformed product")
	}
}

func TestBatchReportsPerProduct(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2", notLaunched())
	_ = Batch(context.Background(), r.d, "install", []string{"p1", "p2"})
	r.mustSay("p1: completed")
	r.mustSay("p2: not launched yet")
}

// --- the runtime object -----------------------------------------------------------------------------------

func TestInterruptedInstallConvergesOnARerun(t *testing.T) {
	// Interrupted AFTER the volume and container intents are written but before the container
	// exists. A re-run must converge, with no half-state left to trip over.
	r := newRig(t)
	r.writeProduct("p1")
	r.fake.InterruptOn = "POST /containers/create"
	if rc := r.install("p1"); rc == cliio.ExitOK {
		t.Fatalf("the interrupted install reported success\n%s", r.said())
	}
	r.reset()

	r.fake.InterruptOn = ""
	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("the re-run did not converge: rc = %d\n%s", rc, r.said())
	}
	if got := r.observed(r.container("p1")); got != state.ObsRunning {
		t.Fatalf("observed %q after convergence", got)
	}
}

func TestPublishedPortsBindLoopbackOnly(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")

	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Ports) == 0 {
		t.Fatal("the manifest declares a port and the runtime object publishes none")
	}
	for _, p := range info.Ports {
		if p.HostIP != "127.0.0.1" {
			t.Fatalf("port %s is published on %q, not the loopback wall", p.ContainerPort, p.HostIP)
		}
	}
}

func TestHostNetworkModeIsRejected(t *testing.T) {
	// MYTHICAL_NET names a network to ATTACH to. It is never a network MODE, and the two halves of
	// that are asserted separately because they fail differently.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.writeFile("mythical.conf", "MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_NET=host\n")

	// (a) With nothing of that name to attach to, the install REFUSES. It does not fall back to the
	// installer's own network — silently taking that branch would join the family to a network
	// nobody named.
	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay(`no network named "host" exists`)
	if r.containerExists(r.container("p1")) {
		t.Fatal("a container was created despite the unusable network")
	}

	// (b) And when a network of that name DOES exist, it is joined as an ordinary network, by id,
	// with the product's alias on it — never as a namespace the container shares. That is the half
	// the name of this case is really about, and in this tree it holds structurally: the launch
	// spec cannot express a network mode at all, only an attachment. Asserting it means the day
	// someone adds a mode there, this fails.
	r.reset()
	want := r.createNetwork("host")
	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 once the named network exists\n%s", rc, r.said())
	}
	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Networks) != 1 {
		t.Fatalf("the container has %d attachments, want exactly 1 — a shared namespace has none", len(info.Networks))
	}
	for _, ep := range info.Networks {
		if ep.NetworkID != want {
			t.Fatalf("attached to %q, want the operator's network %q", ep.NetworkID, want)
		}
	}
}

func TestConcurrentInstallsAreSerialized(t *testing.T) {
	// The family lock serializes the two: the loser refuses cleanly, BEFORE any state write, rather
	// than corrupting the winner's ledger. Whichever product IS a member has its named volume
	// recorded and present — a lost or clobbered install would leave a member with no volume.
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2")

	// THE OVERLAP IS FORCED, not hoped for. Left to the scheduler the two installs can run one
	// after the other, and then this passes with no locking at all — which is the whole thing it
	// claims to prove.
	//
	// The barrier is the PROGRESS SEAM, and it has to be: the first install's last narration is
	// emitted while it still holds the family lock (the release is deferred), and it is emitted
	// from the verb rather than from inside the fake daemon's dispatcher — so the contender can
	// still reach the daemon while it is parked here. A barrier inside the helper fixture instead
	// deadlocks: the fake holds its own mutex across a helper's start, so the contender's very
	// first daemon call would block behind it and never get as far as the lock.
	holding := make(chan struct{})
	contended := make(chan struct{})
	var once sync.Once

	var rc1, rc2 int
	var ledgerBefore, ledgerAfter []byte
	var worldBefore, worldAfter string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		d := r.d
		d.Stdout, d.Stderr = nil, nil // the buffers are not concurrency-safe
		d.Progress = func(ProgressEvent) {
			once.Do(func() {
				ledgerBefore, _ = os.ReadFile(r.ledgerPath())
				worldBefore = r.fake.Snapshot()
				close(holding)
				select {
				case <-contended:
				case <-time.After(30 * time.Second):
				}
			})
		}
		rc1 = Install(context.Background(), d, InstallOpts{Product: "p1"})
	}()
	go func() {
		defer wg.Done()
		defer close(contended)
		select {
		case <-holding:
		case <-time.After(30 * time.Second):
			return
		}
		d := r.d
		d.Stdout, d.Stderr = nil, nil
		rc2 = Install(context.Background(), d, InstallOpts{Product: "p2"})
		ledgerAfter, _ = os.ReadFile(r.ledgerPath())
		worldAfter = r.fake.Snapshot()
	}()
	wg.Wait()

	// The winner completed; the contender REFUSED, and it refused cleanly rather than waiting.
	if rc1 != cliio.ExitOK {
		t.Fatalf("the install holding the lock returned %d, want 0", rc1)
	}
	if rc2 != cliio.ExitFail {
		t.Fatalf("the contender returned %d, want 1 — it did not refuse", rc2)
	}
	// AND IT WROTE NOTHING AT ALL — not merely no membership. Measured across the contender's whole
	// run, while the winner was still parked: a refusal that had already created a volume, opened
	// an intent or moved a trust floor would be a refusal in name only, and membership is the last
	// thing an install records, so its absence proves almost nothing on its own.
	if string(ledgerAfter) != string(ledgerBefore) {
		t.Fatalf("the contender changed the ledger:\n--- before ---\n%s\n--- after ---\n%s", ledgerBefore, ledgerAfter)
	}
	if worldAfter != worldBefore {
		t.Fatalf("the contender changed the runtime:\n--- before ---\n%s\n--- after ---\n%s", worldBefore, worldAfter)
	}

	ident := r.ident()
	any := false
	for _, p := range []string{"p1", "p2"} {
		if !r.isMember(p) {
			continue
		}
		any = true
		if !r.volumeExists("mythical-" + ident + "-" + p + "-state") {
			t.Fatalf("%s is a member with no state volume — its install was clobbered", p)
		}
	}
	if !any {
		t.Fatal("neither install completed")
	}
}

// TestImageOverrideRunsWhatItRecords is not a bats port — the shell tests that report an override
// through `status` belong to the task that lands status. It is here because THIS task added the
// launch parameter the override travels on, and an override that is recorded but not RUN is the
// worst of both: `status` names one image while the container runs another, and a later recreate
// rebuilds from the recorded reference against an image that was never pulled.
func TestImageOverrideRunsWhatItRecords(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	override := digestRef("p1-local-build")

	if rc := r.install("p1", withImage(override)); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	// It is LOUD.
	r.mustSay("IMAGE OVERRIDE")
	// The container really runs the overridden reference, not the manifest's.
	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Image != override {
		t.Fatalf("the container runs %q, not the overridden %q", info.Image, override)
	}
	// And it is recorded, so a later recreate rebuilds from the same reference.
	rec, ferr := r.ledgerNow().Find("forced", "key", "p1:image-override")
	if ferr != nil {
		t.Fatalf("no override record: %v", ferr)
	}
	if ref, ok := ledger.FieldOf(rec, "ref"); !ok || ref != override {
		t.Fatalf("the override record names %q, want %q", ref, override)
	}
	r.reset()
	if rc := r.recreate("p1"); rc != cliio.ExitOK {
		t.Fatalf("recreate rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("image override preserved")
	// SAYING SO IS NOT DOING IT: the rebuilt container must actually run the recorded reference,
	// or `status` names one image while the container runs another.
	after, aerr := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if aerr != nil {
		t.Fatal(aerr)
	}
	if after.Image != override {
		t.Fatalf("recreate rebuilt from %q, not the recorded override %q", after.Image, override)
	}

	// A plain re-install CLEARS it: with no --image the manifest's image is what runs, so a record
	// naming the old override would send a later recreate at an image nothing selected.
	r.reset()
	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("plain re-install rc = %d\n%s", rc, r.said())
	}
	if _, ferr := r.ledgerNow().Find("forced", "key", "p1:image-override"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatalf("a plain install left the override record behind: %v", ferr)
	}
}

// TestConfirmAndProgressSeams is not a bats port — the shell has one confirmation implementation
// and no progress seam at all. It is here because these two seams are DEFINED by this task and
// consumed by later ones: a front-end that runs a verb on a goroutine supplies a Confirm that
// blocks on an overlay and a Progress that posts messages, and the verb must be unable to tell.
// So the contract is pinned now, while there is still exactly one implementation of each.
func TestConfirmAndProgressSeams(t *testing.T) {
	var out, errb bytes.Buffer

	// DEFAULT Progress: the plain line, on stdout, and nothing else.
	d := Deps{Stdout: &out, Stderr: &errb}
	d.say("stage", "%s: installed and running.", "p1")
	if out.String() != "p1: installed and running.\n" {
		t.Fatalf("default progress wrote %q", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("progress leaked to stderr: %q", errb.String())
	}

	// SUPPLIED Progress: it receives the event, and stdout is left alone.
	out.Reset()
	var got []ProgressEvent
	d.Progress = func(ev ProgressEvent) { got = append(got, ev) }
	d.say("install", "%s: installed and running.", "p1")
	if len(got) != 1 || got[0].Stage != "install" || got[0].Detail != "p1: installed and running." {
		t.Fatalf("the seam received %+v", got)
	}
	if out.Len() != 0 {
		t.Fatal("a supplied Progress still wrote to stdout — the front-end would see the line twice")
	}

	// DEFAULT Confirm: the environment decides, and the prompt renders on stderr, not stdout.
	for _, tc := range []struct {
		env  []string
		want bool
	}{{[]string{"MI_CONFIRM=yes"}, true}, {[]string{"MI_CONFIRM=no"}, false}, {nil, false}} {
		out.Reset()
		errb.Reset()
		c := Deps{Stdout: &out, Stderr: &errb, Env: tc.env}
		if got := c.ask("Proceed?"); got != tc.want {
			t.Fatalf("env %v: ask = %v, want %v", tc.env, got, tc.want)
		}
		if out.Len() != 0 {
			t.Fatalf("env %v: the prompt reached stdout: %q", tc.env, out.String())
		}
	}
	// A NIL STDIN IS A CLOSED STDIN, not an empty accept: with no decision in the environment the
	// read fails, and a failed read refuses. A purge cannot be carried by a pipe that was not there.
	if (Deps{Stderr: &errb}).ask("Proceed?") {
		t.Fatal("a nil stdin was read as consent")
	}

	// SUPPLIED Confirm: it is asked, with the prompt, and its answer is the answer — the seam a
	// blocking overlay plugs into.
	asked := ""
	sc := Deps{Stdout: &out, Stderr: &errb, Env: []string{"MI_CONFIRM=no"},
		Confirm: func(prompt string) bool { asked = prompt; return true }}
	if !sc.ask("Remove every named volume?") {
		t.Fatal("the supplied Confirm was not consulted")
	}
	if asked != "Remove every named volume?" {
		t.Fatalf("the seam was asked %q", asked)
	}
}

// stubProber stands in for the probe arm. It writes the ledger FILE the way the real one does —
// the accounting holds the lock token, not a ledger — and then fails, which is the case that
// deliberately RETAINS what it wrote.
type stubProber struct {
	write func()
	err   error
}

func (sp stubProber) SelfCheck(context.Context, *trust.Index, string) error {
	sp.write()
	return sp.err
}

func (sp stubProber) Resolve(context.Context, *trust.Index, string, string) (string, error) {
	sp.write()
	return "", sp.err
}

// TestAFailedProbeKeepsItsRetainedIntent is not a bats port — the shell has no in-memory ledger,
// so it cannot have this bug. It is here because THIS tree does: the probe arm writes the ledger
// file itself, and on a reap it could not settle it retains the probe intent on purpose, because
// the container may still be standing and that intent is the only record that would ever authorize
// removing it. A session that then persisted the copy it read earlier would write that intent
// straight back out of existence — leaving a possibly-live probe container that nothing accounts
// for, and an unaccounted gate that wedges every later verb over an object no record points at.
func TestAFailedProbeKeepsItsRetainedIntent(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	s, err := openSession(r.d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	acct, aerr := intent.NewProbeAccounting(s.h, time.Now)
	if aerr != nil {
		t.Fatal(aerr)
	}
	const probeName = "mythical-iprobetest-probe-nprobexxxx"
	sp := sessionProber{s: s, p: stubProber{
		write: func() { _ = acct.OpenProbe(probeName, "nprobexxxx") },
		err:   errors.New("probe: the leftover probe container could not be removed — its intent is preserved"),
	}}

	if _, perr := sp.Resolve(context.Background(), nil, "netid", "mythical-p1"); perr == nil {
		t.Fatal("the stub was supposed to fail")
	}
	// The session's OWN ledger now carries what the probe arm wrote, so persisting it preserves it.
	if _, ferr := intent.Find(s.l, prov.ClassProbe, probeName); ferr != nil {
		t.Fatalf("the session's ledger does not carry the retained probe intent: %v", ferr)
	}
	if perr := s.persist(); perr != nil {
		t.Fatal(perr)
	}
	if _, ferr := intent.Find(r.ledgerOnDisk(), prov.ClassProbe, probeName); ferr != nil {
		t.Fatalf("persisting the session erased the retained probe intent: %v", ferr)
	}
	// AND IT ADOPTS IN PLACE. The bring-up sequence holds the very ledger the session handed it and
	// keeps editing it after the probe returns; a fresh pointer here would strand those edits on an
	// object nothing persists.
	held := s.l
	if _, perr := sp.Resolve(context.Background(), nil, "netid", "mythical-p1"); perr == nil {
		t.Fatal("the stub was supposed to fail")
	}
	if s.l != held {
		t.Fatal("the session published a NEW ledger — whoever held the old one is now editing a copy nothing persists")
	}
	// AND THE WRAPPER IS WHAT THE BRING-UP SEQUENCE ACTUALLY GETS. Everything above is about a type
	// nothing reaches unless bringupDeps installs it — so that is asserted too, or the fix is one
	// assignment away from being inert with every test still green.
	ident, ierr := s.l.IdentGet()
	if ierr != nil {
		t.Fatal(ierr)
	}
	bd, berr := s.bringupDeps(nil, ident)
	if berr != nil {
		t.Fatal(berr)
	}
	if _, ok := bd.Probe.(sessionProber); !ok {
		t.Fatalf("the bring-up sequence is handed a %T — nothing adopts what the probe arm writes", bd.Probe)
	}
}

// TestAFailedAdoptionRefusesToWrite is not a bats port. It is the other half of the retained-intent
// case above: when the ledger was written during the operation and cannot be re-read, the session's
// copy is no longer known to contain everything on disk — so writing it could erase exactly what it
// cannot see. It refuses instead, which is the same fail-closed direction every other unreadable
// answer in this tree takes.
func TestAFailedAdoptionRefusesToWrite(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	s, err := openSession(r.d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	probeErr := errors.New("probe: the leftover probe container could not be removed — its intent is preserved")
	sp := sessionProber{s: s, p: stubProber{
		write: func() { _ = os.Remove(r.ledgerPath()) },
		err:   probeErr,
	}}
	// The probe's OWN error still comes back unchanged — the callers distinguish a failed check
	// from an unavailable probe from an unaccounted one, and that identity must survive the wrapper.
	if _, perr := sp.Resolve(context.Background(), nil, "netid", "mythical-p1"); !errors.Is(perr, probeErr) {
		t.Fatalf("the wrapper replaced the probe's error with %v", perr)
	}
	if !s.stale {
		t.Fatal("a ledger that could not be re-read left the session willing to write over it")
	}
	if perr := s.persist(); !errors.Is(perr, errStaleLedger) {
		t.Fatalf("persist returned %v — it wrote a copy that may be missing what was written", perr)
	}
	if perr := s.persistFn()(s.l); !errors.Is(perr, errStaleLedger) {
		t.Fatalf("the write-ahead seam returned %v — bring-up would still write the stale copy", perr)
	}
}

// --- the aggregate's own refusals ---------------------------------------------------------------------

// Inventory — tests/unit/exit.bats, the mi_ex_worst/mi_ex_name half.
//
// THESE SEVEN ROWS WERE, UNTIL THE PARITY AUDIT, CLAIMED BY NOBODY. cliio/exit_test.go noted that
// they "are inventoried by the verbs wave"; this file said they "live in tests/unit/exit.bats,
// which Wave 1 claimed". Each side pointed at the other in prose neither the inventory nor any
// gate could read, so the whole aggregate contract sat outside the checked corpus. That is the
// exact shape the audit exists to find: not a missing test, a missing CLAIM, with a real test
// beside it making the hole invisible to anyone reading the code.
//
// PORTED: tests/unit/exit.bats: "batch precedence is worst-wins: all success is 0" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "success plus not-launched is 3" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "any operational failure wins over not-launched" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "a usage error is never aggregated, wherever it sits in the batch" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "an empty batch is a usage error, not a success" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "an unknown code is refused rather than mapped to failure, wherever it sits in the batch" -> TestWorstRefusals
// PORTED: tests/unit/exit.bats: "every code has a human name, for reports" -> TestExitNameNamesEveryCode
//
// THIS package owns them because it owns the aggregate: cliio holds the four code CONSTANTS (its
// one row), and mi_ex_worst/mi_ex_name became Worst/ExitName here.
func TestWorstRefusals(t *testing.T) {
	for _, tc := range []struct {
		in   []int
		want int
		bad  bool
		// The bats rows assert the MESSAGE, not merely a non-zero status: the two refusals are
		// different bugs in the caller (a code that must not be aggregated vs. a code that is not
		// in the contract at all), and a test that only checks "it failed" cannot tell a port that
		// swapped them from one that did not.
		msg string
	}{
		{in: []int{0, 0, 0}, want: cliio.ExitOK},
		{in: []int{0, 3, 0}, want: cliio.ExitNotLaunched},
		{in: []int{0, 3, 1}, want: cliio.ExitFail},
		{in: []int{1, 3}, want: cliio.ExitFail},
		// BOTH ORDERINGS FOR EACH REFUSAL, as the bats rows spell out. The shell's refusal was
		// once reachable only when the bad code came FIRST — the loop returned on the first 1 it
		// saw and never validated what followed — so `mi_ex_worst 1 2` answered 1 and exited 0.
		// The Go loop validates the whole list before aggregating; these rows are what proves it.
		{in: []int{0, 2}, bad: true, msg: "usage errors are not batch outcomes"},
		{in: []int{2, 1}, bad: true, msg: "usage errors are not batch outcomes"},
		{in: []int{1, 2}, bad: true, msg: "usage errors are not batch outcomes"},
		{in: []int{0, 7}, bad: true, msg: "not an exit code this contract defines"},
		{in: []int{7, 1}, bad: true, msg: "not an exit code this contract defines"},
		{in: []int{1, 7}, bad: true, msg: "not an exit code this contract defines"},
		{in: nil, bad: true, msg: "at least one per-product outcome"},
	} {
		got, err := Worst(tc.in)
		if tc.bad {
			if err == nil {
				t.Fatalf("Worst(%v) = %d, want a refusal", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("Worst(%v) refused with %q, which does not name %q — the two refusals are different caller bugs",
					tc.in, err, tc.msg)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("Worst(%v) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
}

// TestExitNameNamesEveryCode ports exit.bats' row about every code having a human name for reports
// (quoted verbatim only in the machine-readable claim above, never in prose). The bats row checks
// one code; every code is checked here because the batch report prints this string per
// product, and a code with no name of its own would surface as another code's word — a report that
// is wrong rather than a report that is missing.
func TestExitNameNamesEveryCode(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{
		{cliio.ExitOK, "completed"},
		{cliio.ExitFail, "failed"},
		{cliio.ExitUsage, "usage error"},
		{cliio.ExitNotLaunched, "not launched"},
	} {
		if got := ExitName(tc.code); !strings.Contains(got, tc.want) {
			t.Fatalf("ExitName(%d) = %q, want it to contain %q", tc.code, got, tc.want)
		}
	}
	// A code outside the contract must be reported AS unknown, carrying the number. Returning one
	// of the four names would put a plausible word in a report about an outcome nobody defined.
	got := ExitName(7)
	if !strings.Contains(got, "unknown") || !strings.Contains(got, "7") {
		t.Fatalf("ExitName(7) = %q, want it to say unknown and carry the code", got)
	}
	for _, name := range []string{"completed", "failed", "usage error", "not launched"} {
		if strings.Contains(got, name) {
			t.Fatalf("ExitName(7) = %q, which reads as %q — an undefined code must not borrow a defined code's word", got, name)
		}
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestTheNetworkReferenceIsDurableBeforeTheImageGate is not a bats port; the reference gets it
// structurally, because its record-writer writes the ledger FILE. Here the first-time adoption of
// an operator network records the reference by editing the ledger in MEMORY, and the next write in
// an install is on the far side of the image gate — so a pull that fails would discard the pinned
// network id, and a re-run would resolve the configured NAME again. If that name has been
// re-pointed in between, the second run adopts the replacement network with no recorded reference
// left for the split refusal to disagree with.
func TestTheNetworkReferenceIsDurableBeforeTheImageGate(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	want := r.createNetwork("operator-net")
	r.writeFile("mythical.conf", "MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_NET=operator-net\n")

	// The install gets as far as the image and dies there.
	r.fake.PullOutcome = "neterr"
	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}

	// The reference the install pinned is ON DISK, so a re-run re-verifies THAT id rather than
	// resolving the name afresh.
	got, err := netref.RefGet(r.ledgerNow())
	if err != nil {
		t.Fatalf("no operator-network reference survived the failed install: %v", err)
	}
	if got != want {
		t.Fatalf("the recorded reference is %q, want the network that was resolved (%q)", got, want)
	}
}

// TestStopCommitsTheIntentBeforeItActs is not a bats port — the shell gets the ordering from its
// call structure and pins the outcome. Asserting the outcome cannot see the ordering: moving the
// commit to AFTER the runtime stop, but before its result is handled, leaves every outcome
// assertion in this file passing while reopening the crash window the ordering exists to close (a
// container stopped with no record saying that is what was wanted).
//
// So the ordering is proved by REFUSING THE WRITE. With the session poisoned, the commit cannot be
// made durable — and if the commit really does come first, the verb stops there and the runtime is
// never asked to do anything. A commit that had moved after the stop would have issued it.
func TestStopCommitsTheIntentBeforeItActs(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.mustInstall("p1")
	c := r.container("p1")

	s, serr := openSession(r.d)
	if serr != nil {
		t.Fatal(serr)
	}
	defer s.close()
	before := len(r.fake.RequestLog())
	s.stale = true // every write from here refuses

	if rc := s.stop(context.Background(), "p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1 — the verb wrote nothing and must not report success", rc)
	}
	for _, req := range r.fake.RequestLog()[before:] {
		if strings.Contains(req, "/containers/"+c+"/stop") {
			t.Fatal("the runtime was asked to stop the container even though the intent was never recorded — the commit does not come first")
		}
	}
	// And the container is untouched, which is the operator-visible half of the same fact.
	if !r.running(c) {
		t.Fatal("the container is not running")
	}
}

// TestNoValueFromAProductConfReachesTheLaunch ports bringup.bats' "no value from <product>.conf
// reaches any launch argument".
//
// PORTED: tests/unit/bringup.bats: "no value from <product>.conf reaches any launch argument" -> TestNoValueFromAProductConfReachesTheLaunch
//
// IT WAS N/A ON A STRUCTURAL ARGUMENT THAT DOES NOT HOLD. The claim was that the launch seam takes
// only a container name and a nonce, so this package could not pass a config value into a launch
// argument even by mistake. But an interface says nothing about what an implementation carries:
// the real launcher carries the launch config, the manifest and the policy into LaunchProduct, so
// the subject of this row exists here — it is simply not exercised today. "Nothing currently reads
// it" is not a guard; it is the state a guard exists to preserve.
//
// WHAT THE ROW IS ABOUT. <product>.conf is written by the PRODUCT, inside its container: it is the
// one file in this system an attacker who owns a product can choose the contents of. If any of it
// reached the container spec, a value like `--privileged` would be a container escape authored by
// the thing being contained. The reference plants exactly that and asserts the launch happened and
// the value did not travel; so does this.
func TestNoValueFromAProductConfReachesTheLaunch(t *testing.T) {
	// TWO PLANTED VALUES, AND BOTH ARE DELIBERATE. The first is an option a container escape would
	// be spelled with; the second is a NUMBER, product-scoped and distinctive, because the fields a
	// value could reach are not all option-shaped — a published port is a number, and a check that
	// only looks for a flag cannot see a port arriving from the product's own file. It must not be
	// the manifest's own port either, or the assertion would pass on a value that is legitimately
	// there.
	const hostile = "--privileged"
	const hostilePort = "65123"
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	// The product writes its own conf, and it writes things it should never be able to use. The
	// bytes are planted BEFORE the install so every step of bring-up sees them.
	r.writeFile("p1.conf", "PEER="+hostile+"\nMYTHICAL_P1_PORT="+hostilePort+"\n")
	r.mustInstall("p1")

	c := r.container("p1")
	info, err := r.c.ContainerInspect(context.Background(), c)
	if err != nil {
		t.Fatalf("the launch did not happen, so this test would pass for the wrong reason: %v", err)
	}
	// THE LAUNCH REALLY HAPPENED — without this the assertions below hold just as well for a
	// bring-up that never ran, which is the shape the reference guards against with its alias check.
	if !info.Running {
		t.Fatalf("the container is not running; the assertions below would prove nothing")
	}

	// Nothing the product wrote may appear anywhere the daemon acts on: not the env, not the
	// labels, not the image, not a mount, not a published port.
	for _, e := range info.Env {
		if strings.Contains(e, hostile) || strings.Contains(e, hostilePort) || strings.HasPrefix(e, "PEER=") {
			t.Fatalf("a <product>.conf value reached the container environment: %q", e)
		}
	}
	for k, v := range info.Labels {
		if strings.Contains(k, hostile) || strings.Contains(v, hostile) ||
			strings.Contains(k, hostilePort) || strings.Contains(v, hostilePort) {
			t.Fatalf("a <product>.conf value reached a label: %s=%s", k, v)
		}
	}
	if strings.Contains(info.Image, hostile) || strings.Contains(info.Image, hostilePort) {
		t.Fatalf("a <product>.conf value reached the image reference: %q", info.Image)
	}
	for _, m := range info.Mounts {
		if strings.Contains(m.Source, hostile) || strings.Contains(m.Destination, hostile) ||
			strings.Contains(m.Source, hostilePort) || strings.Contains(m.Destination, hostilePort) {
			t.Fatalf("a <product>.conf value reached a mount: %+v", m)
		}
	}
	// THE NETWORK ATTACHMENT, ALIASES INCLUDED. An alias is a caller-supplied string that the daemon
	// records and resolves; it is as much a launch argument as an env entry, and it was the half an
	// earlier version of this test did not look at.
	for name, ep := range info.Networks {
		if strings.Contains(name, hostile) || strings.Contains(name, hostilePort) {
			t.Fatalf("a <product>.conf value reached a network name: %q", name)
		}
		for _, a := range ep.Aliases {
			if strings.Contains(a, hostile) || strings.Contains(a, hostilePort) {
				t.Fatalf("a <product>.conf value reached a network alias: %q", a)
			}
		}
		if strings.Contains(ep.IPAddress, hostile) || strings.Contains(ep.IPAddress, hostilePort) {
			t.Fatalf("a <product>.conf value reached an endpoint address: %q", ep.IPAddress)
		}
	}
	// AND THE PUBLISHED PORTS, which decide what of this container is reachable from the host — the
	// single most consequential thing a hostile value could choose.
	for _, pb := range info.Ports {
		for _, f := range []string{pb.ContainerPort, pb.HostIP, pb.HostPort} {
			if strings.Contains(f, hostile) || strings.Contains(f, hostilePort) {
				t.Fatalf("a <product>.conf value reached a published port: %+v", pb)
			}
		}
	}
	// The request log is a WEAKER backstop than it looks — the fake records method and URL, not
	// bodies — so it is here to catch a value smuggled into a PATH or query, not as the main
	// assertion. The typed inspect above is what actually covers the create body.
	for _, req := range r.fake.RequestLog() {
		if strings.Contains(req, hostile) || strings.Contains(req, hostilePort) {
			t.Fatalf("a <product>.conf value reached the daemon in %q", req)
		}
	}
}

// TestTheReconcilersDidNothingNoteIsWiredToStderr is the WIRING half of the reconciler's two
// informational verdicts, and the test the round-5 gate asked for.
//
// internal/bringup asserts that Reconcile CALLS its Note seam. Nothing asserted that this package
// HANDS it one — so deleting the single `Note:` assignment in bringupDeps would have made the CLI
// silently lose an operator-facing message while both the parity audit and the whole suite stayed
// green. A seam nothing drives is a diagnostic nobody reads, and "the fix is one assignment away
// from being inert with every test still green" is the same hazard this file already guards for the
// probe wrapper, two tests up.
//
// STDERR, NOT STDOUT: these are notes, not output, and a caller parsing this verb's stdout must
// never receive them.
func TestTheReconcilersDidNothingNoteIsWiredToStderr(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	s, err := openSession(r.d)
	if err != nil {
		t.Fatal(err)
	}
	ident, ierr := s.l.IdentGet()
	if ierr != nil {
		t.Fatal(ierr)
	}
	bd, berr := s.bringupDeps(nil, ident)
	if berr != nil {
		t.Fatal(berr)
	}
	if bd.Note == nil {
		t.Fatal("the bring-up sequence is handed no Note seam — the reconciler's two did-nothing verdicts go nowhere")
	}
	r.reset()
	bd.Note("note: a reconciler verdict")
	if got := r.errb.String(); !strings.Contains(got, "note: a reconciler verdict") {
		t.Fatalf("the note did not reach stderr: %q", got)
	}
	if got := r.out.String(); strings.Contains(got, "a reconciler verdict") {
		t.Fatalf("the note reached STDOUT, which callers parse: %q", got)
	}
}

// TestBatchRefusesAVerbItDoesNotDriveAndAnEmptyBatch. Both refusals were implemented and
// unasserted: deleting either left the suite green.
//
// A VERB OUTSIDE THE FIVE IS REFUSED WITH NOTHING ATTEMPTED — never a silent no-op over the whole
// product list, which is how a mistyped verb over three products would report success having done
// nothing to any of them. An EMPTY batch is a usage error for the same reason: exit 0 from a batch
// that ran nothing tells a caller everything is installed.
func TestBatchRefusesAVerbItDoesNotDriveAndAnEmptyBatch(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()

	if rc := Batch(context.Background(), r.d, "uninstall", []string{"p1"}); rc != cliio.ExitUsage {
		t.Fatalf("a non-batchable verb: rc = %d, want 2\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "not a batchable verb") {
		t.Fatalf("no diagnostic naming the verb:\n%s", r.said())
	}
	if r.isMember("p1") {
		t.Fatal("the refused batch ran anyway")
	}
	if len(r.fake.RequestLog()) != 0 {
		t.Fatalf("the refusal reached the daemon: %v", r.fake.RequestLog())
	}
	r.reset()
	if rc := Batch(context.Background(), r.d, "install", nil); rc != cliio.ExitUsage {
		t.Fatalf("an empty batch: rc = %d, want 2\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "needs at least one product") {
		t.Fatalf("no diagnostic for the empty batch:\n%s", r.said())
	}
}

// TestAVolumeThatIsNotOursIsNeitherAdoptedNorRemoved is the fail-closed half of volume adoption.
//
// THE SUCCESS HALF IS TESTED ELSEWHERE — a volume this installation created, standing at the name we
// would create, is adopted with its role, data class and product. THIS is the half that costs
// something when it is wrong: a volume carrying somebody ELSE'S nonce may hold another
// installation's data, so it must not be taken over and must not be removed.
//
// WHICH GATE REFUSES IS ITSELF THE FINDING, and it is why this test asserts the OUTCOME rather than
// one diagnostic. The nonce comparison in the confirm step is written as the backstop, but it is not
// what fires: the §6b.2 unaccounted-object gate reaches this situation FIRST, because a volume
// labelled for this installation that the ledger does not account for is refused before any verb
// touches anything. So the confirm-step comparison is defence in depth behind an earlier refusal —
// reachable only if that gate ever stopped covering it — and what this test pins is the property
// both exist for: the operation stops, the volume survives, and nothing was adopted.
func TestAVolumeThatIsNotOursIsNeitherAdoptedNorRemoved(t *testing.T) {
	r := newRig(t)
	r.writeProduct("p2")
	r.mintIdentity()
	ident := r.ident()
	vol := "mythical-" + ident + "-p2-memory"

	// The intent is opened under OUR nonce; the volume standing at that name carries a different
	// one — the shape a second installation, or a name reused after a crash, produces.
	const ours, theirs = "nadoptxxxx", "nSOMEONEELSE"
	r.editLedger(func(l *ledger.Ledger) {
		if err := intent.Open(l, prov.ClassVolume, vol, ours, time.Now(),
			ledger.Field{Key: "product", Value: "p2"},
			ledger.Field{Key: "role", Value: "memory"}); err != nil {
			t.Fatal(err)
		}
	})
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, theirs)
		if perr != nil {
			t.Fatal(perr)
		}
		if err := rt.VolumeCreate(context.Background(), vol, p); err != nil {
			t.Fatal(err)
		}
	})

	if rc := r.install("p2"); rc == cliio.ExitOK {
		t.Fatalf("a volume carrying another nonce was adopted\n%s", r.said())
	}
	// The operator is TOLD, and told something actionable — silence here would leave a refused
	// install with no explanation of what is standing in the way.
	if !strings.Contains(r.said(), "state repair") {
		t.Fatalf("the refusal does not tell the operator what to do:\n%s", r.said())
	}
	// NEITHER ADOPTED NOR REMOVED: the volume is still there, and it is still theirs.
	if !r.volumeExists(vol) {
		t.Fatal("the volume was removed — it may hold another installation's data")
	}
	if _, err := prov.Find(r.ledgerNow(), prov.ClassVolume, vol); err == nil {
		t.Fatal("the volume was adopted into our provenance despite carrying another nonce")
	}
	// AND THE INTENT IS RETAINED, so the situation is recorded rather than vanishing.
	if _, err := intent.Find(r.ledgerNow(), prov.ClassVolume, vol); err != nil {
		t.Fatalf("the intent was dropped, so nothing records that this is unresolved: %v", err)
	}
}
