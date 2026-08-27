package verbs

import (
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
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
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
	before := len(r.fake.Requests)

	rc := r.install("p1", withImage(""))
	if rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2 (usage)\n%s", rc, r.said())
	}
	r.mustSay("requires a value")
	if got := len(r.fake.Requests); got != before {
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
	before := len(r.fake.Requests)
	_, _ = r.c.ImageInspect(context.Background(), ref)
	if len(r.fake.Requests) == before {
		t.Fatal("the image inspect made no request")
	}
	req := r.fake.Requests[len(r.fake.Requests)-1]
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
	r.mustSay("stopped")
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
	// install and recreate reach the bootstrap secrets through ONE path, so the entitlement gate
	// cannot drift between the verbs. GRANTED: the secret is really injected — positive evidence,
	// not merely the absence of a refusal. REVOKED: the same manifest against a policy with the
	// grant stripped is refused by BOTH verbs, and nothing is staged.
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
	// A network the family cannot be placed on is a refusal, not a fallback to the installer's own:
	// silently taking that branch would join the family to a network nobody named.
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	r.writeFile("mythical.conf", "MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_NET=host\n")

	if rc := r.install("p1"); rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want 1\n%s", rc, r.said())
	}
	r.mustSay(`no network named "host" exists`)
	if r.containerExists(r.container("p1")) {
		t.Fatal("a container was created despite the unusable network")
	}
}

func TestConcurrentInstallsAreSerialized(t *testing.T) {
	// The family lock serializes the two: the loser refuses cleanly, BEFORE any state write, rather
	// than corrupting the winner's ledger. Whichever product IS a member has its named volume
	// recorded and present — a lost or clobbered install would leave a member with no volume.
	r := newRig(t)
	r.writeProduct("p1")
	r.writeProduct("p2")

	var wg sync.WaitGroup
	for _, p := range []string{"p1", "p2"} {
		wg.Add(1)
		go func(product string) {
			defer wg.Done()
			d := r.d
			d.Stdout, d.Stderr = nil, nil // the buffers are not concurrency-safe
			_ = Install(context.Background(), d, InstallOpts{Product: product})
		}(p)
	}
	wg.Wait()

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

// --- the aggregate's own refusals ---------------------------------------------------------------------

// TestWorstRefusals is not a bats port: the shell's mi_ex_worst refusals live in tests/unit/exit.bats,
// which Wave 1 claimed. It is here because THIS package now owns the aggregate, and the refusals are
// position-dependent in a way only a direct call can reach — Batch maps a per-product usage error to
// a failure before aggregating, so no batch can hand Worst a 2.
func TestWorstRefusals(t *testing.T) {
	for _, tc := range []struct {
		in   []int
		want int
		bad  bool
	}{
		{in: []int{0, 0}, want: cliio.ExitOK},
		{in: []int{0, 3}, want: cliio.ExitNotLaunched},
		{in: []int{0, 3, 1}, want: cliio.ExitFail},
		{in: []int{2, 1}, bad: true},
		{in: []int{1, 2}, bad: true}, // the forbidden code AFTER the worst one
		{in: []int{1, 7}, bad: true}, // an undefined code AFTER the worst one
		{in: nil, bad: true},
	} {
		got, err := Worst(tc.in)
		if tc.bad {
			if err == nil {
				t.Fatalf("Worst(%v) = %d, want a refusal", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("Worst(%v) = %d, %v; want %d", tc.in, got, err, tc.want)
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
