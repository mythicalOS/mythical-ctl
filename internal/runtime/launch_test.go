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
	"mythicalos.ai/ctl/internal/policy"
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
	// Both directory core-fixed mounts SELECTED and PERMITTED — the three-present case; the
	// selection rule itself is TestCoreFixedSelection.
	m := man(t, nil, "volume=work:/work", "volume=state:/var/lib/brokkr", "port=7480",
		"mount=transcripts", "mount=logs")
	p := pol(t, "brokkr.permitted_role=work", "brokkr.permitted_role=state", "brokkr.bindable_role=work",
		"brokkr.permitted_mount=transcripts", "brokkr.permitted_mount=logs")

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
	// The three core-fixed mounts are present (all selected above), rw.
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
	if len(mounts) != 3 { // <product>.conf (always) + two binds; no `mount=` selected, so no dirs
		t.Fatalf("want 3 mounts, got %d", len(mounts))
	}
}

// §4.3 secret injection. The three bringup.bats rows below are claimed HERE, beside the test that
// asserts them, because Wave 3 moved the behaviour here: secrets are assembled inside
// runtime.LaunchProduct (secretsFor) and ride the create body over the local socket. They used to
// be claimed in TWO places at once — as N/A in internal/bringup ("relocated, internal/runtime
// asserts it") and as PORTED here, wrapped into the middle of this paragraph where the inventory
// parser does not read it. Two statements about one row, disagreeing, with only the wrong one
// checkable.
//
// PORTED: tests/unit/bringup.bats: "the secret env file holds ONLY the product's declared keys, is 0600, and outlives the call" -> TestSecretsInjection -- the ONLY-declared-keys half; the FILE half is a stated residual — there is no env file on this transport, so nothing has a mode or a lifetime to assert
// PORTED: tests/unit/bringup.bats: "a secret the product is not entitled to is REFUSED, not silently dropped" -> TestSecretsInjection
// PORTED: tests/unit/bringup.bats: "a declared secret that is not set REFUSES and leaves no file behind" -> TestSecretsInjection -- the refusal; no file to leave
func TestSecretsInjection(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	prov, err := engine.NewProvenance("inst1", "netnonce")
	if err != nil {
		t.Fatal(err)
	}
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	launchEnv := func(t *testing.T, name string, m *manifest.Manifest, p *policy.Policy) ([]string, error) {
		t.Helper()
		r.fake.PullImage(m.Image())
		id, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{Identity: name, Nonce: "n-" + name, NetworkID: netID})
		if err != nil {
			return nil, err
		}
		info, err := r.c.ContainerInspect(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return info.Env, nil
	}
	// The family file holds the telemetry key AND the network name. A product that declares
	// the secret gets EXACTLY that key — and nothing else from the file.
	r.writeFamilyConf(t, "MYTHICAL_NET=fam", "MYTHICAL_TELEMETRY_KEY=tk-123")
	env, err := launchEnv(t, "declared", man(t, nil, "secret=MYTHICAL_TELEMETRY_KEY"), pol(t, "brokkr.permitted_secret=MYTHICAL_TELEMETRY_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 || env[0] != "MYTHICAL_TELEMETRY_KEY=tk-123" {
		t.Fatalf("exactly the declared secret, nothing else from the file: %v", env)
	}
	// A product that declares NO secret gets NOTHING — the file's other keys never ride in.
	env, err = launchEnv(t, "none", man(t, nil), pol(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 0 {
		t.Fatalf("no declared secret means an empty environment: %v", env)
	}
	// Not entitled: REFUSED, not silently dropped.
	if _, err := launchEnv(t, "denied", man(t, nil, "secret=MYTHICAL_TELEMETRY_KEY"), pol(t)); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("an unentitled secret must refuse: %v", err)
	}
	// Declared and granted but NOT SET: refused.
	r.writeFamilyConf(t, "MYTHICAL_NET=fam")
	if _, err := launchEnv(t, "unset", man(t, nil, "secret=MYTHICAL_TELEMETRY_KEY"), pol(t, "brokkr.permitted_secret=MYTHICAL_TELEMETRY_KEY")); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("a declared-but-unset secret must refuse: %v", err)
	}
	// A key the family file does not DEFINE: a manifest error, refused.
	if _, err := launchEnv(t, "undefined", man(t, nil, "secret=MYTHICAL_BOGUS"), pol(t, "brokkr.permitted_secret=MYTHICAL_BOGUS")); err == nil || !strings.Contains(err.Error(), "does not define") {
		t.Fatalf("an undefined key must refuse: %v", err)
	}
}

// §4.1a SELECTION, as the reference's launch verb does it: <product>.conf is ALWAYS mounted;
// transcripts and logs ONLY when the manifest selects them (`mount=`) AND the policy permits
// the selection; anything else a manifest names is a refusal. A product granted neither
// receives neither — the first port mounted all three unconditionally (gate round-9 P1).
func TestCoreFixedSelection(t *testing.T) {
	r := newRig(t, "brokkr")
	ctx := context.Background()
	prov, err := engine.NewProvenance("inst1", "netnonce")
	if err != nil {
		t.Fatal(err)
	}
	netID, err := r.rt.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	launchDests := func(t *testing.T, name string, m *manifest.Manifest, p *policy.Policy) map[string]bool {
		t.Helper()
		r.fake.PullImage(m.Image())
		id, err := r.rt.LaunchProduct(ctx, m, p, runtime.LaunchConfig{Identity: name, Nonce: "n-" + name, NetworkID: netID})
		if err != nil {
			t.Fatal(err)
		}
		info, err := r.c.ContainerInspect(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		dests := map[string]bool{}
		for _, mt := range runtime.MountsOf(info) {
			dests[mt.Destination] = true
		}
		return dests
	}
	// No selection: the conf alone.
	d := launchDests(t, "none", man(t, nil), pol(t))
	if !d["/etc/mythical/brokkr.conf"] {
		t.Fatalf("<product>.conf is always mounted: %v", d)
	}
	if d["/home/mythical/transcripts"] || d["/home/mythical/logs"] {
		t.Fatalf("an UNSELECTED directory core-fixed mount must not be mounted: %v", d)
	}
	// One selected and permitted: that one, not the other.
	d = launchDests(t, "one", man(t, nil, "mount=transcripts"), pol(t, "brokkr.permitted_mount=transcripts"))
	if !d["/home/mythical/transcripts"] || d["/home/mythical/logs"] {
		t.Fatalf("exactly the selected directory is mounted: %v", d)
	}
	// Selected but NOT permitted: a refusal at the selection site (manifest.Check refuses it
	// too, upstream; MountsFor must not depend on that).
	if _, err := r.rt.MountsFor(man(t, nil, "mount=logs"), pol(t)); err == nil || !strings.Contains(err.Error(), "does not permit") {
		t.Fatalf("an unpermitted selection must refuse: %v", err)
	}
	// A selection outside the closed set: refused, never invented.
	if _, err := r.rt.MountsFor(man(t, nil, "mount=secrets"), pol(t, "brokkr.permitted_mount=secrets")); err == nil || !strings.Contains(err.Error(), "not a core-fixed mount") {
		t.Fatalf("a selection outside the closed set must refuse: %v", err)
	}
	if _, err := r.rt.MountsFor(man(t, nil, "mount=conf"), pol(t, "brokkr.permitted_mount=conf")); err == nil || !strings.Contains(err.Error(), "not a core-fixed mount") {
		t.Fatalf("the conf is not a selectable name: %v", err)
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
