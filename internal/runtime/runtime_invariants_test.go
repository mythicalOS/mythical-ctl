package runtime_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
)

// The comma-grammar attack class, inventoried as PORTED-BY-TYPE. The reference adapter's
// `--mount` flag was a COMMA-separated option list, so a comma inside a component opened
// Docker's option grammar — `volume-opt=device=/etc` turned a named volume into a host bind.
// On the API a mount crosses as one JSON field per component, so a comma moves no boundary;
// these tests construct the NEAREST EXPRESSIBLE spec and assert the serialized result carries
// no user-controlled option keys.
//
// Inventory — tests/unit/runtime.bats (the rows that belong to this package):
// PORTED: tests/unit/runtime.bats: "a comma in a bind spec cannot smuggle a Docker mount option" -> TestCommaInBindSourceStaysAPath
// PORTED: tests/unit/runtime.bats: "a comma in a volume spec cannot convert a named volume into a host bind" -> TestCommaInVolumeNameIsJustAName

func TestCommaInBindSourceStaysAPath(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	// The bash attack string, as close as the types can spell it: a bind source that CONTAINS
	// the option-list suffix. It is now merely a strange directory name.
	odd := t.TempDir() + "/host,bind-propagation=rshared"
	if err := os.MkdirAll(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := engine.NewBindMount(odd, "/container", false)
	if err != nil {
		t.Fatalf("a comma in a PATH is legal — the grammar it attacked is gone: %v", err)
	}
	r.fake.PullImage("img:v1")
	prov, _ := engine.NewProvenance("i", "n")
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := engine.NewNetworkAttach(netID, "a1")
	spec, err := engine.NewContainerSpec("c1", "img:v1", engine.SpecOpts{Network: na, Mounts: []engine.Mount{b}})
	if err != nil {
		t.Fatal(err)
	}
	// Through the ONE launch door's underlying create (the facade's Mutator is sealed; the
	// serializer is what this asserts, via the daemon's own record of the mount).
	id, err := createViaFacade(t, r, ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	info, err := r.c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	mounts := info.Mounts
	if len(mounts) != 1 || mounts[0].Type != "bind" || mounts[0].Source != odd {
		t.Fatalf("the comma must stay INSIDE the path — one bind, the whole string as its source: %+v", mounts)
	}
}

func TestCommaInVolumeNameIsJustAName(t *testing.T) {
	// The serious bash case: `volume=v,volume-opt=o=bind,volume-opt=device=/etc:/d:rw` — a
	// named volume converted into a host bind. As a TYPED volume name the comma-bearing
	// string is just a (weird) name — and the daemon's own name class refuses it, exactly as
	// a real daemon does, so nothing resembling an option list ever reaches a mount.
	r := newRig(t, "brokkr")
	ctx := context.Background()
	v, err := engine.NewVolumeMount("v,volume-opt=device=/etc", "/d")
	if err != nil {
		t.Fatalf("the constructor's job is name-vs-path, not Docker's name class: %v", err)
	}
	r.fake.PullImage("img:v1")
	prov, _ := engine.NewProvenance("i", "n")
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := engine.NewNetworkAttach(netID, "a1")
	spec, err := engine.NewContainerSpec("c1", "img:v1", engine.SpecOpts{Network: na, Mounts: []engine.Mount{v}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = createViaFacade(t, r, ctx, spec)
	if err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Fatalf("the daemon refuses the comma-bearing NAME — no bind ever appears: %v", err)
	}
}

// createViaFacade reaches the sealed create door the way only a test may: tests are exempt
// from the boundary gate precisely to exercise boundaries, so a Mutator is built directly on
// the rig's held lock. Production code has no such road — that is the gate's assertion.
func createViaFacade(t *testing.T, r *rig, ctx context.Context, spec engine.ContainerSpec) (string, error) {
	t.Helper()
	m, err := engine.NewMutator(r.h, r.c)
	if err != nil {
		t.Fatal(err)
	}
	return m.ContainerCreate(ctx, spec)
}
