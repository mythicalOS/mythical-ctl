package runtime_test

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/volatile"
)

// launchWith assembles and creates a container for this manifest, returning the inspected
// container or the refusal. The volatile arm is the only thing under test, so the rig is the
// plainest one that reaches it.
func launchWith(t *testing.T, m *manifest.Manifest, p *policy.Policy) (*engine.ContainerInfo, error) {
	t.Helper()
	r := newRig(t, "brokkr")
	ctx := context.Background()
	r.writeFamilyConf(t, "MYTHICAL_NET=fam")
	r.fake.PullImage(m.Image())
	prov, err := engine.NewProvenance("inst1", "netnonce")
	if err != nil {
		t.Fatal(err)
	}
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	cfg := runtime.LaunchConfig{Identity: "inst1", Nonce: "n1", NetworkID: netID}

	// PrelaunchCheck must agree with the create path on every refusal — it is the SAME
	// assembly, and the lifecycle verbs refuse through it BEFORE tearing a working container
	// down. Asserting the agreement here is what makes that guarantee real for this arm rather
	// than assumed.
	preErr := r.rt.PrelaunchCheck(m, p, cfg)

	id, err := r.rt.LaunchProduct(ctx, m, p, cfg)
	if (preErr == nil) != (err == nil) {
		t.Fatalf("PrelaunchCheck and LaunchProduct disagree: prelaunch=%v launch=%v", preErr, err)
	}
	if err != nil {
		return nil, err
	}
	info, ierr := r.c.ContainerInspect(ctx, id)
	if ierr != nil {
		t.Fatal(ierr)
	}
	return info, nil
}

// TestVolatileMountEmittedForCanonicalRoot: the spec-assembly seam wires the manifest field to
// the hardened tmpfs, on the PRODUCTION path. This is the only place the manifest field, the
// production-root guard and the rendered mount meet, so it is tested across the seam rather than
// in each function's own suite.
func TestVolatileMountEmittedForCanonicalRoot(t *testing.T) {
	root := volatile.Root()
	m := man(t, nil, "volume=state:/var/lib/brokkr", "volatile_mount="+root)
	p := pol(t, "brokkr.permitted_role=state")
	info, err := launchWith(t, m, p)
	if err != nil {
		t.Fatalf("a canonical volatile mount was refused: %v", err)
	}
	if got := info.Tmpfs[root]; got != "nodev,nosuid,noexec" {
		t.Fatalf("the credential home at %q mounted with %q, want the frozen hardening; whole map %v", root, got, info.Tmpfs)
	}
	// It coexists with the ordinary mounts — the guard rejects OVERLAP, not coexistence.
	var sawVolume bool
	for _, mt := range info.Mounts {
		if mt.Type == "volume" {
			sawVolume = true
		}
		if mt.Destination == root {
			t.Errorf("the credential home also appears as a durable %s mount at %q", mt.Type, mt.Destination)
		}
	}
	if !sawVolume {
		t.Error("the unbound state role did not ride a named volume — the fixture no longer proves coexistence")
	}
}

// TestVolatileMountRefusesNonCanonicalRoot: production may not point credential homes at a state
// directory, a bind, a named volume or the writable layer. A perfectly VALID path that is not the
// canonical root is refused, and nothing is created for it.
func TestVolatileMountRefusesNonCanonicalRoot(t *testing.T) {
	m := man(t, nil, "volume=state:/var/lib/brokkr", "volatile_mount=/tmp/credential-homes")
	p := pol(t, "brokkr.permitted_role=state")
	info, err := launchWith(t, m, p)
	if err == nil {
		t.Fatalf("a non-canonical volatile root was accepted; container %v", info)
	}
	if !strings.Contains(err.Error(), "must be rooted at "+volatile.Root()) {
		t.Fatalf("the refusal does not name the required root: %v", err)
	}
}

// TestVolatileMountRefusesOverlappingMounts is the isolation rule at the seam.
//
// A durable mount inside — or OVER — the credential-home root would shadow the tmpfs with
// persistent, backed-up storage: the one thing this mount must never allow. The manifest is
// authenticated, but the TARGET is still the manifest's to choose, so it is enforced here rather
// than trusted.
//
// The container root `/` is included deliberately. The looser mount-target grammar accepts it, so
// it is REACHABLE, and it is the case a naive prefix check misses — appending a boundary slash to
// `/` yields `//`, which prefix-matches nothing.
func TestVolatileMountRefusesOverlappingMounts(t *testing.T) {
	root := volatile.Root()
	for _, target := range []string{
		root,              // the root itself
		root + "/session", // a child
		"/run/mythical/./credential-homes/session", // an equivalent SPELLING of that child
		"/run/mythical", // an ancestor
		"/",             // the container root — an ancestor of everything
	} {
		m := man(t, nil, "volume=state:"+target, "volatile_mount="+root)
		p := pol(t, "brokkr.permitted_role=state")
		_, err := launchWith(t, m, p)
		if err == nil {
			t.Errorf("a durable mount at %q was accepted alongside the credential home at %q", target, root)
			continue
		}
		if !strings.Contains(err.Error(), "overlaps the volatile credential-home mount") {
			t.Errorf("the mount at %q was refused, but not as an overlap: %v", target, err)
		}
	}
}

// TestVolatileMountAllowsDisjointMounts: the guard rejects overlap, not coexistence. A sibling and
// an unrelated tree launch fine — including a name that shares a prefix STRING but not a path
// boundary.
func TestVolatileMountAllowsDisjointMounts(t *testing.T) {
	root := volatile.Root()
	for _, target := range []string{"/data", "/run/mythical/other", root + "-2"} {
		m := man(t, nil, "volume=state:"+target, "volatile_mount="+root)
		p := pol(t, "brokkr.permitted_role=state")
		info, err := launchWith(t, m, p)
		if err != nil {
			t.Errorf("a disjoint mount at %q was refused beside the credential home: %v", target, err)
			continue
		}
		if info.Tmpfs[root] != "nodev,nosuid,noexec" {
			t.Errorf("with a disjoint mount at %q the credential home was not mounted: %v", target, info.Tmpfs)
		}
	}
}

// TestVolatileMountAbsentEmitsNothing: absence is not a mount. A manifest declaring none must
// produce no tmpfs at all — not an empty one, not one at a default path.
func TestVolatileMountAbsentEmitsNothing(t *testing.T) {
	m := man(t, nil, "volume=state:/var/lib/brokkr")
	p := pol(t, "brokkr.permitted_role=state")
	info, err := launchWith(t, m, p)
	if err != nil {
		t.Fatalf("a manifest with no volatile mount was refused: %v", err)
	}
	if len(info.Tmpfs) != 0 {
		t.Fatalf("a tmpfs appeared for a manifest that declared none: %v", info.Tmpfs)
	}
}

// TestVolatileMountGuardsTheCoreFixedTargetsToo: the compared set is EVERY mount target, not only
// the manifest's volumes. The core-fixed mounts are computed by the core itself, so a manifest
// cannot move them — but they are still targets inside the container, and a credential-home root
// declared at or over one of them would overlap it. The manifest CAN move the root, which is the
// reachable half of this pair.
//
// `/home/mythical` is an ancestor of the core-fixed transcripts and logs targets, and it is a
// valid cpath — so it passes the grammar and reaches the guard. It is refused by the production
// -root check FIRST (it is not the canonical root), which is the honest outcome and is what this
// asserts: the two guards are ordered so the more specific production rule answers first.
func TestVolatileMountGuardsTheCoreFixedTargetsToo(t *testing.T) {
	m := man(t, nil, "volume=state:/var/lib/brokkr", "mount=transcripts", "volatile_mount=/home/mythical")
	p := pol(t, "brokkr.permitted_role=state", "brokkr.permitted_mount=transcripts")
	_, err := launchWith(t, m, p)
	if err == nil {
		t.Fatal("a credential-home root containing the core-fixed transcripts target was accepted")
	}
	if !strings.Contains(err.Error(), "must be rooted at "+volatile.Root()) &&
		!strings.Contains(err.Error(), "overlaps the volatile credential-home mount") {
		t.Fatalf("refused, but by neither of the two guards that should have caught it: %v", err)
	}
}
