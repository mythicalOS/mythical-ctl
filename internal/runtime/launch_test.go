package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/runtime"
)

// rig is a full facade over the fake: a healthy home, the family lock, and a Runtime.
type rig struct {
	fake *enginetest.Fake
	c    *engine.Client
	rt   *runtime.Runtime
	home string
	h    famlock.Held
}

func newRig(t *testing.T, product string) *rig {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	home := mkHome(t, product)
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	c := f.Client()
	rt, err := runtime.New(h, c)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{fake: f, c: c, rt: rt, home: home, h: h}
}

func (r *rig) writeFamilyConf(t *testing.T, lines ...string) {
	t.Helper()
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(r.home, "mythical.conf"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchProductMounts(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	// One bound role (through a SYMLINK spelling), one unbound role riding its named volume.
	real := filepath.Join(t.TempDir(), "workdir")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(real), "worklink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	r.writeFamilyConf(t, "MYTHICAL_NET=fam", "MYTHICAL_BROKKR_WORK_BIND="+link)
	m := man(t, nil, "volume=work:/work", "volume=state:/var/lib/brokkr", "port=7480")
	p := pol(t, "brokkr.permitted_role=work", "brokkr.permitted_role=state", "brokkr.bindable_role=work")

	r.fake.PullImage(m.Image())
	prov, err := engine.NewProvenance("inst1", "netnonce")
	if err != nil {
		t.Fatal(err)
	}
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{
		Identity: "inst1", Nonce: "n1", NetworkID: netID,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := r.c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// Created STOPPED (D42 step 1: the verify/start protocol is the bring-up layer's).
	if runtime.Running(info) || info.Status != "created" {
		t.Fatalf("created stopped: %+v", info)
	}
	// The assembled labels — installation, nonce, product.
	if runtime.InstallLabel(info) != "inst1" || runtime.Nonce(info) != "n1" || runtime.ProductLabel(info) != "brokkr" {
		t.Fatalf("labels: %v", info.Labels)
	}
	// The family alias, on exactly one network.
	alias, err := manifest.Alias("brokkr")
	if err != nil {
		t.Fatal(err)
	}
	pairs := runtime.NetPairs(info)
	if len(pairs) != 1 || pairs[0].Name != "family" {
		t.Fatalf("networks: %+v", pairs)
	}
	if pairs[0].Aliases[0] != alias {
		t.Fatalf("the family alias must be registered explicitly: %v", pairs[0].Aliases)
	}
	// The bound role mounts the VALIDATED CANONICAL source at the manifest's declared target —
	// never the operator's symlink spelling, which appears nowhere.
	realCanon, err := runtime.Canon(real)
	if err != nil {
		t.Fatal(err)
	}
	mounts := runtime.MountsOf(info)
	var work, state *engine.MountRecord
	for i := range mounts {
		switch mounts[i].Destination {
		case "/work":
			work = &mounts[i]
		case "/var/lib/brokkr":
			state = &mounts[i]
		}
	}
	if work == nil || work.Type != "bind" || work.Source != realCanon {
		t.Fatalf("bound role: %+v", work)
	}
	for _, mt := range mounts {
		if strings.Contains(mt.Source, filepath.Base(link)) {
			t.Fatalf("the operator's un-resolved spelling reached the launch: %+v", mt)
		}
	}
	// The role with no bind key rides its NAMED VOLUME at the declared target.
	volName, err := manifest.VolumeName("inst1", "brokkr", "state")
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Type != "volume" || state.Name != volName {
		t.Fatalf("volume fallback: %+v", state)
	}
	// The three core-fixed mounts are present, rw.
	var fixedCount int
	for _, mt := range mounts {
		switch mt.Destination {
		case "/etc/mythical/brokkr.conf", "/home/mythical/transcripts", "/home/mythical/logs":
			fixedCount++
			if !mt.RW {
				t.Fatalf("core-fixed mounts are rw: %+v", mt)
			}
		}
	}
	if fixedCount != 3 {
		t.Fatalf("core-fixed set: %+v", mounts)
	}
	// The declared port, published on 127.0.0.1 at its own number.
	ports := runtime.Ports(info)
	if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" || ports[0].HostPort != "7480" {
		t.Fatalf("ports: %+v", ports)
	}
}

func TestLaunchProductHostPortOverride(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	m := man(t, nil, "volume=state:/var/lib/brokkr", "port=7480")
	p := pol(t, "brokkr.permitted_role=state")
	r.fake.PullImage(m.Image())
	prov, _ := engine.NewProvenance("inst1", "nn")
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{
		Identity: "inst1", Nonce: "n1", NetworkID: netID,
		HostPorts: map[uint16]uint16{7480: 17480},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := r.c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	ports := runtime.Ports(info)
	if len(ports) != 1 || ports[0].HostPort != "17480" || ports[0].HostIP != "127.0.0.1" {
		t.Fatalf("override: %+v", ports)
	}
}

func TestMountsForUnbindableKeySet(t *testing.T) {
	r := newRig(t, "brokkr")
	dir := t.TempDir()
	// The operator names the SECRETS bind key; the policy does not make secrets bindable.
	// Silently ignoring it would leave them believing a bind is in effect when the role's
	// whole protection is that it is not one (D53).
	r.writeFamilyConf(t, "MYTHICAL_BROKKR_SECRETS_BIND="+dir)
	m := man(t, nil, "volume=secrets:/run/secrets")
	p := pol(t, "brokkr.permitted_role=secrets")
	_, err := r.rt.MountsFor(m, p)
	if err == nil || !strings.Contains(err.Error(), "does not make \"secrets\" bindable") {
		t.Fatalf("unbindable key set: %v", err)
	}
}

func TestMountsForPairwise(t *testing.T) {
	r := newRig(t, "brokkr")
	base := t.TempDir()
	nested := filepath.Join(base, "project")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	r.writeFamilyConf(t,
		"MYTHICAL_BROKKR_WORK_BIND="+base,
		"MYTHICAL_BROKKR_PROJECT_BIND="+nested,
	)
	m := man(t, nil, "volume=work:/work", "volume=project:/project")
	p := pol(t, "brokkr.permitted_role=work", "brokkr.permitted_role=project",
		"brokkr.bindable_role=work", "brokkr.bindable_role=project")
	_, err := r.rt.MountsFor(m, p)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("the pairwise rule must apply to the whole emitted set: %v", err)
	}
	// And it still emits BOTH when they do not overlap — a check that refused everything
	// would pass the assertion above while making the function useless.
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r.writeFamilyConf(t,
		"MYTHICAL_BROKKR_WORK_BIND="+a,
		"MYTHICAL_BROKKR_PROJECT_BIND="+b,
	)
	mounts, err := r.rt.MountsFor(m, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 5 { // three core-fixed + two binds
		t.Fatalf("want 5 mounts, got %d", len(mounts))
	}
}

func TestFacadeDeadAfterRelease(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	if err := famlock.Release(r.h); err != nil {
		t.Fatal(err)
	}
	before := len(r.fake.Requests)
	m := man(t, nil, "volume=state:/var/lib/brokkr")
	p := pol(t, "brokkr.permitted_role=state")
	if _, err := r.rt.MountsFor(m, p); err == nil {
		t.Fatal("MountsFor after Release")
	}
	if _, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{Identity: "i", Nonce: "n", NetworkID: "x"}); err == nil {
		t.Fatal("LaunchProduct after Release")
	}
	if err := r.rt.ContainerStart(ctx, "c1"); err == nil {
		t.Fatal("delegate after Release")
	}
	if len(r.fake.Requests) != before {
		t.Fatalf("a dead facade issued %d request(s)", len(r.fake.Requests)-before)
	}
}

func TestAccessorsAndResolve(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	m := man(t, nil, "volume=state:/var/lib/brokkr")
	p := pol(t, "brokkr.permitted_role=state")
	r.fake.PullImage(m.Image())
	prov, _ := engine.NewProvenance("inst1", "nn")
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{Identity: "inst1", Nonce: "n1", NetworkID: netID})
	if err != nil {
		t.Fatal(err)
	}
	// NEVER-STARTED: the endpoint id is empty; ResolveNetPairs resolves it through the
	// network NAME — the reader the pre-start attach check uses.
	info, err := r.c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if pairs := runtime.NetPairs(info); pairs[0].ID != "" {
		t.Fatalf("a never-started endpoint must report no id: %+v", pairs)
	}
	resolved, err := runtime.ResolveNetPairs(ctx, r.c, info)
	if err != nil || len(resolved) != 1 || resolved[0].ID != netID {
		t.Fatalf("resolved: %+v %v", resolved, err)
	}
	// FAIL CLOSED: an endpoint whose name resolves to nothing refuses the whole read — a
	// name is never substituted for an id.
	ghost := &engine.ContainerInfo{
		Name:     "c1",
		Networks: map[string]engine.NetEndpoint{"ghost-net": {}},
	}
	if _, err := runtime.ResolveNetPairs(ctx, r.c, ghost); err == nil {
		t.Fatal("an unresolvable attachment must fail the whole read")
	}
	// Started: address and id materialize; Nets carries the id-keyed view.
	if err := r.rt.ContainerStart(ctx, id); err != nil {
		t.Fatal(err)
	}
	info, err = r.c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	nets := runtime.Nets(info)
	if len(nets) != 1 || nets[0].ID != netID || nets[0].Addr == "" {
		t.Fatalf("running nets: %+v", nets)
	}
}
