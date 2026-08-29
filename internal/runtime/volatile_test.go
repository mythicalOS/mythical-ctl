package runtime_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/volatile"
)

// Inventory — tests/unit/mounts.bats (the credential-home mount rows):
// PORTED: tests/unit/mounts.bats: "mi_bringup_specs emits the volatile mount for the canonical root" -> TestVolatileMountEmittedForCanonicalRoot -- the Go seam is buildSpec, shared by LaunchProduct and PrelaunchCheck, and the assertion is on the mount the daemon actually received rather than on an emitted spec string
// PORTED: tests/unit/mounts.bats: "mi_bringup_specs refuses a non-canonical volatile root and emits no spec for it" -> TestVolatileMountRefusesNonCanonicalRoot -- Go emits no spec STRING, so the bats "emits no spec" half is asserted as the effect it stands for: the refusal names the required root AND the product container is provably absent afterwards
// PORTED: tests/unit/mounts.bats: "mi_bringup_specs refuses a mount that overlaps the volatile credential-home root" -> TestVolatileMountRefusesOverlappingMounts TestVolatileMountAllowsDisjointMounts -- the bats row carries both halves: the overlap refusals (equal, child, an equivalent spelling of that child, the container root) and the disjoint volume that must still launch
// PORTED: tests/unit/mounts.bats: "mi_bringup_specs emits no volatile spec when the manifest declares none" -> TestVolatileMountAbsentEmitsNothing -- absence is not a mount: no tmpfs at all, not an empty one and not one at a default path

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
		// A REFUSAL CREATES NOTHING, and that is CHECKED rather than inferred from the error.
		// The refusals under test happen during assembly, before any request is issued — but
		// "the call returned an error" and "the call had no effect" are different claims, and an
		// implementation that created the container and then refused would satisfy the first
		// while breaking the second. Only this assertion can tell them apart.
		name, nerr := manifest.ContainerName(cfg.Identity, m.Product())
		if nerr != nil {
			t.Fatal(nerr)
		}
		if _, ierr := r.c.ContainerInspect(ctx, name); !errors.Is(ierr, engine.ErrAbsent) {
			t.Fatalf("the launch was refused, but inspecting %q returned %v — want ErrAbsent; "+
				"a refusal that left a container behind is not a refusal", name, ierr)
		}
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

// TestVolatileMountProductionRootGuardAnswersBeforeTheOverlapGuard: `volatileMountFor` has two
// guards in order, and this pins WHICH of them answers a manifest that trips both. `/home/mythical`
// is an ancestor of the core-fixed transcripts and logs targets and is a valid cpath, so it passes
// the grammar and would overlap — but it is not the canonical root, and the production-root check
// is first. An operator moving the credential home must hear the specific deployment reason, not a
// downstream complaint about some other mount.
//
// IT IS NOT THE OVERLAP TEST, AND ITS OLD NAME SAID IT WAS. As
// TestVolatileMountGuardsTheCoreFixedTargetsToo it read as the isolation test while never reaching
// the isolation loop: measured, an implementation that skipped every non-volume mount — ignoring
// binds and the core-fixed targets entirely — kept `go test ./...` green across the whole tree. The
// guard itself is exercised by TestVolatileMountRefusesADurableMountOverlappingTheCanonicalRoot in
// mounts_internal_test.go, which has to be white-box: no production bring-up can be arranged to
// present the canonical root together with a durable mount overlapping it, because the assembly
// path refuses such a manifest earlier for a different reason.
func TestVolatileMountProductionRootGuardAnswersBeforeTheOverlapGuard(t *testing.T) {
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
