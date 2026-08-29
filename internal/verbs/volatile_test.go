package verbs

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/volatile"
)

// The credential-home mount reaches the verbs with NO verb-level code, because the launch
// assembly lives in the runtime facade and every verb reaches a launch through it. That is a
// claim about this layer, so it is VERIFIED here rather than assumed: these tests would fail if a
// verb assembled its own mounts, cached a spec built before the guard, or reported an effect the
// refusal prevented.

// TestInstallCarriesTheCredentialHomeMount: the field travels end to end, from the authenticated
// manifest through install to the running container's hardening.
func TestInstallCarriesTheCredentialHomeMount(t *testing.T) {
	root := volatile.Root()
	r := newRig(t)
	r.writeProduct("p1", withVolatileMount(root))
	r.mintIdentity()

	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	info, err := r.c.ContainerInspect(context.Background(), r.container("p1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Tmpfs[root]; got != "nodev,nosuid,noexec" {
		t.Fatalf("the installed container's credential home at %q carries %q, want the frozen hardening; whole map %v",
			root, got, info.Tmpfs)
	}
}

// TestInstallRefusesAnOverlappingCredentialHome is the one that matters, and it asserts three
// separate things about the refusal.
//
// A durable mount under the credential-home root must refuse the install; the refusal must SAY
// what was wrong; and — the invariant that is easiest to break and hardest to see — a refusal
// partway through must leave NO partial state behind. An installer that refuses the launch but
// still records membership has told the operator "no" and the ledger "yes".
func TestInstallRefusesAnOverlappingCredentialHome(t *testing.T) {
	root := volatile.Root()
	r := newRig(t)
	// The reachable form: the manifest places the state role INSIDE the credential-home root.
	r.writeProduct("p1", withVolatileMount(root), withStateTarget(root+"/session"))
	r.mintIdentity()

	rc := r.install("p1")
	if rc == cliio.ExitOK {
		t.Fatalf("the install succeeded with a durable volume inside the credential-home root\n%s", r.said())
	}
	if !strings.Contains(r.said(), "overlaps the volatile credential-home mount") {
		t.Fatalf("the operator was not told WHY the install was refused:\n%s", r.said())
	}
	// AND IT MUST NOT ALSO REPORT THE INSTALL AS DONE. A non-zero exit and a refusal sentence are
	// not the same as the ABSENCE of a success sentence: an implementation that printed
	// "p1: installed and running." and then returned the error satisfied every other assertion
	// here, and the operator reading the output would see both. The success line is asserted absent
	// because that is the only assertion that can fail on that implementation.
	r.mustNotSay("installed and running")
	// NO PARTIAL EFFECT. The refusal happens during assembly, before anything is created, so
	// there is no container and no membership — and the report must not claim an effect that did
	// not happen.
	if r.isMember("p1") {
		t.Errorf("a refused install left p1 recorded as a member")
	}
	if r.containerExists(r.container("p1")) {
		t.Errorf("a refused install left a container behind")
	}
}

// TestRecreateRefusesAnOverlappingCredentialHome: recreate must refuse BEFORE it tears the
// working container down. That is what PrelaunchCheck is for, and this is the test that proves
// the volatile guard is inside the shared assembly rather than only on the create path — if it
// were only on create, the container would already be gone by the time the refusal arrived.
func TestRecreateRefusesAnOverlappingCredentialHome(t *testing.T) {
	root := volatile.Root()
	r := newRig(t)
	r.writeProduct("p1")
	r.mintIdentity()
	if rc := r.install("p1"); rc != cliio.ExitOK {
		t.Fatalf("baseline install rc = %d\n%s", rc, r.said())
	}
	before := r.container("p1")
	if !r.containerExists(before) {
		t.Fatal("the baseline container is not there")
	}

	// The publisher now ships a manifest whose state volume sits inside the credential-home root.
	r.writeProduct("p1", docVersion("2"), withVolatileMount(root), withStateTarget(root+"/session"))

	rc := r.recreate("p1")
	if rc == cliio.ExitOK {
		t.Fatalf("recreate accepted an overlapping credential-home mount\n%s", r.said())
	}
	if !strings.Contains(r.said(), "overlaps the volatile credential-home mount") {
		t.Fatalf("the operator was not told why recreate refused:\n%s", r.said())
	}
	// THE WORKING CONTAINER SURVIVED. A refusal that has already removed it is not a refusal.
	if !r.containerExists(before) {
		t.Fatalf("recreate refused, but the working container was already destroyed:\n%s", r.said())
	}
}
