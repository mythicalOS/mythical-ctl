package enginetest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
)

// The fake's OWN fidelity suite — behaviors the client cannot (by design) express are proven
// over raw HTTP against the fake's socket, so the fake stays a faithful stand-in even for
// requests only a defective caller would build. Inventory entries pointing here are listed in
// client_test.go's block.

func setup(t *testing.T) (*enginetest.Fake, *engine.Client, *engine.Mutator) {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	c := f.Client()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatal(err)
	}
	return f, c, m
}

// raw issues a request straight at the fake's socket, bypassing the typed client.
func raw(t *testing.T, f *enginetest.Fake, method, path string, body any) (int, []byte) {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", f.Socket())
		},
	}}
	var rd io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, "http://docker/"+engine.APIVersion+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("raw %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func prov(t *testing.T) engine.Provenance {
	t.Helper()
	p, err := engine.NewProvenance("inst1", "nonce1")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSnapshot(t *testing.T) {
	f, _, m := setup(t)
	ctx := context.Background()
	f.PullImage("img:v1")
	if err := m.VolumeCreate(ctx, "vol1", prov(t)); err != nil {
		t.Fatal(err)
	}
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	na, err := engine.NewNetworkAttach(netID, "a1")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := engine.NewContainerSpec("c1", "img:v1", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	snap := f.Snapshot()
	for _, want := range []string{
		"volume vol1 labels=mythicalos.installation=inst1,mythicalos.nonce=nonce1",
		"network family driver=bridge labels=mythicalos.installation=inst1,mythicalos.nonce=nonce1",
		"container c1 state=created image=img:v1",
	} {
		if !strings.Contains(snap, want) {
			t.Errorf("snapshot lacks %q:\n%s", want, snap)
		}
	}
	// Stable across a no-op.
	if f.Snapshot() != snap {
		t.Fatal("snapshot must be deterministic")
	}
}

func TestCreateNameValidation(t *testing.T) {
	_, _, m := setup(t)
	ctx := context.Background()
	// The daemon's own name class, on every create — the fake must never be MORE PERMISSIVE
	// than the daemon it stands in for. Traversal spellings are members of the refused class.
	bad := []string{"../../escapee", "-leading-dash", ".hidden", "has space", "x"}
	for _, name := range bad {
		if err := m.VolumeCreate(ctx, name, prov(t)); err == nil ||
			!strings.Contains(err.Error(), "invalid characters") {
			t.Errorf("volume %q: %v", name, err)
		}
		if _, err := m.NetworkCreate(ctx, name, prov(t)); err == nil ||
			!strings.Contains(err.Error(), "invalid network name") {
			t.Errorf("network %q: %v", name, err)
		}
	}
	// Containers: the argOK gate lets these through to the daemon, which refuses them.
	f2, _, m2 := setup(t)
	f2.PullImage("img:v1")
	netID, err := m2.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	na, err := engine.NewNetworkAttach(netID, "a1")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range bad {
		spec, err := engine.NewContainerSpec(name, "img:v1", engine.SpecOpts{Network: na})
		if err != nil {
			continue // the constructor already refused (e.g. the space) — equally closed
		}
		if _, err := m2.ContainerCreate(ctx, spec); err == nil ||
			!strings.Contains(err.Error(), "Invalid container name") {
			t.Errorf("container %q: %v", name, err)
		}
	}
	// And a name well inside the class works.
	if err := m.VolumeCreate(ctx, "good-name.1", prov(t)); err != nil {
		t.Fatal(err)
	}
}

func TestImageKeyExactRef(t *testing.T) {
	f, _, m := setup(t)
	ctx := context.Background()
	f.PullImage("foo/bar:tag")
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	na, err := engine.NewNetworkAttach(netID, "a1")
	if err != nil {
		t.Fatal(err)
	}
	// A character-folded sibling must NOT satisfy the gate — an aliasing key would mean the
	// gate no longer asserts "this reference was pulled" at all.
	spec, err := engine.NewContainerSpec("c1", "foo_bar:tag", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec); err == nil {
		t.Fatal("a folded ref must not satisfy the pull gate")
	}
	spec, err = engine.NewContainerSpec("c1", "foo/bar:tag", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatalf("the exact ref: %v", err)
	}
}

func TestImageIDStable(t *testing.T) {
	f, c, _ := setup(t)
	f.PullImage("img:v1")
	ctx := context.Background()
	one, err := c.ImageInspect(ctx, "img:v1")
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.ImageInspect(ctx, "img:v1")
	if err != nil {
		t.Fatal(err)
	}
	if one.ID == "" || one.ID != two.ID {
		t.Fatalf("an image must not change identity between two reads: %q vs %q", one.ID, two.ID)
	}
}

func TestUnimplementedRouteIsFatal(t *testing.T) {
	f, _, _ := setup(t)
	code, body := raw(t, f, http.MethodGet, "/secrets", nil)
	if code != 500 || !strings.Contains(string(body), "unimplemented route") {
		t.Fatalf("an unknown route must die loudly: %d %s", code, body)
	}
}

func TestListRefusesNonLabelFilter(t *testing.T) {
	f, _, _ := setup(t)
	code, body := raw(t, f, http.MethodGet, `/containers/json?filters=%7B%22name%22%3A%5B%22x%22%5D%7D`, nil)
	if code != 400 || !strings.Contains(string(body), "only label= filters") {
		t.Fatalf("a non-label filter must be refused, never an empty match: %d %s", code, body)
	}
}

// rawCreate creates a container through the fake's API directly, for shapes the typed client
// deliberately cannot express.
func rawCreate(t *testing.T, f *enginetest.Fake, name string, body map[string]any) {
	t.Helper()
	code, out := raw(t, f, http.MethodPost, "/containers/create?name="+name, body)
	if code != 200 {
		t.Fatalf("raw create: %d %s", code, out)
	}
}

func TestEmptyHostIPReportsAllInterfaces(t *testing.T) {
	f, c, m := setup(t)
	ctx := context.Background()
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	// An empty HostIp binds ALL interfaces — the daemon reports 0.0.0.0, the very address the
	// loopback wall exists to prevent. Only a raw request can say it; the fake must report it
	// as what it is, so a test asking "is anything published off-loopback?" gets the address
	// it is looking for.
	rawCreate(t, f, "offloop", map[string]any{
		"Image": "img:v1",
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{"7480/tcp": []map[string]string{{"HostIp": "", "HostPort": "7480"}}},
		},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{netID: map[string]any{}}},
	})
	info, err := c.ContainerInspect(ctx, "offloop")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Ports) != 1 || info.Ports[0].HostIP != "0.0.0.0" {
		t.Fatalf("an all-interfaces binding must be reported as 0.0.0.0: %+v", info.Ports)
	}
}

// MEASURED 2026-08-25 (Engine 28.4.0 / API 1.51): a create keyed by the network ID is reported
// under the ID until the first start, then under the name. The typed client resolves its attach
// reference to the NAME before creating; this fixture is what makes that resolution
// load-bearing in the hermetic suite — a client that stopped resolving would fail the
// never-started name-keyed assertions instead of being quietly forgiven by a fake that
// normalized for it. The acceptance lane re-measures this exact shape against the real daemon
// (its "SUBMITTED key" case) so the model here cannot drift unnoticed.
func TestCreateKeyPreservedUntilStart(t *testing.T) {
	f, c, m := setup(t)
	ctx := context.Background()
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	rawCreate(t, f, "bykey", map[string]any{
		"Image":            "img:v1",
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{netID: map[string]any{}}},
	})
	info, err := c.ContainerInspect(ctx, "bykey")
	if err != nil {
		t.Fatal(err)
	}
	if _, byName := info.Networks["family"]; byName {
		t.Fatal("a never-started ID-keyed create must NOT be reported under the network name (measured)")
	}
	if _, byID := info.Networks[netID]; !byID {
		t.Fatalf("a never-started create is reported under the SUBMITTED key: %v", info.Networks)
	}
	if code, out := raw(t, f, http.MethodPost, "/containers/bykey/start", nil); code >= 300 {
		t.Fatalf("start: %d %s", code, out)
	}
	info, err = c.ContainerInspect(ctx, "bykey")
	if err != nil {
		t.Fatal(err)
	}
	if _, byName := info.Networks["family"]; !byName {
		t.Fatalf("after start the endpoint is reported under the network NAME: %v", info.Networks)
	}
}

func TestHelperCrashWindowLeavesContainer(t *testing.T) {
	f, c, m := setup(t)
	ctx := context.Background()
	f.PullImage("probe:pinned")
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 0, []byte("egress=ok\n")
	}
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	// Create + start WITHOUT the removal the client always performs — the crash window. The
	// container persists, exited, exactly as a real daemon leaves a non-rm run: this is what
	// the probe's write-ahead accounting exists to find.
	rawCreate(t, f, "crashed-helper", map[string]any{
		"Image":            "probe:pinned",
		"Cmd":              []string{"egress"},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{netID: map[string]any{}}},
	})
	code, out := raw(t, f, http.MethodPost, "/containers/crashed-helper/start", nil)
	if code >= 300 {
		t.Fatalf("start: %d %s", code, out)
	}
	info, err := c.ContainerInspect(ctx, "crashed-helper")
	if err != nil {
		t.Fatalf("the helper container must SURVIVE when nothing removed it: %v", err)
	}
	if info.Status != "exited" {
		t.Fatalf("status: %+v", info)
	}
}

// A force-remove (or stop) must WAKE a waiter blocked on a helper that never received its
// stdin — the waiter holds the container pointer, not the map entry, so removal without a
// broadcast would strand it forever.
func TestRemoveWakesStrandedWaiter(t *testing.T) {
	f, _, m := setup(t)
	ctx := context.Background()
	f.PullImage("probe:pinned")
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 0, nil
	}
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	rawCreate(t, f, "stranded", map[string]any{
		"Image": "probe:pinned", "Cmd": []string{"egress"}, "OpenStdin": true,
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{netID: map[string]any{}}},
	})
	if code, out := raw(t, f, http.MethodPost, "/containers/stranded/start", nil); code >= 300 {
		t.Fatalf("start: %d %s", code, out)
	}
	waited := make(chan int, 1)
	go func() {
		code, _ := raw(t, f, http.MethodPost, "/containers/stranded/wait", nil)
		waited <- code
	}()
	// Give the waiter time to block on the awaiting-stdin predicate, then remove.
	time.Sleep(50 * time.Millisecond)
	if err := m.ContainerRemove(ctx, "stranded"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("a force-remove must wake a blocked waiter, not strand it")
	}
}

func TestPrivateModeConnectRefused(t *testing.T) {
	f, _, m := setup(t)
	ctx := context.Background()
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	rawCreate(t, f, "priv1", map[string]any{
		"Image":      "img:v1",
		"HostConfig": map[string]any{"NetworkMode": "none"},
	})
	err = m.NetworkConnect(ctx, netID, "priv1", "a1", 0)
	if err == nil || !strings.Contains(err.Error(), "private (none) mode") {
		t.Fatalf("a private-mode container can never join the family network: %v", err)
	}
}

func TestHelperNetViewSurfaces(t *testing.T) {
	f, _, m := setup(t)
	ctx := context.Background()
	f.PullImage("img:v1")
	f.PullImage("probe:pinned")
	netID, err := m.NetworkCreate(ctx, "family", prov(t))
	if err != nil {
		t.Fatal(err)
	}
	// A running sibling registers name + alias with the RESOLVER; a stopped one contributes
	// nothing (its address is released).
	na, err := engine.NewNetworkAttach(netID, "brokkr")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := engine.NewContainerSpec("sib1", "img:v1", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := m.ContainerStart(ctx, "sib1"); err != nil {
		t.Fatal(err)
	}
	spec2, err := engine.NewContainerSpec("sib2", "img:v1", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec2); err != nil {
		t.Fatal(err)
	}
	var got enginetest.HelperNetView
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		got = view
		return 0, nil
	}
	hs, err := engine.NewHelperSpec("probe:pinned", "probe1", engine.HelperResolve, prov(t), engine.HelperOpts{
		Network: netID, Alias: "probe-alias",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.HelperRun(ctx, hs); err != nil {
		t.Fatal(err)
	}
	// The RUNNING sibling resolves by name and alias; the created-never-started one does not.
	if got.DNS["sib1"] == "" || got.DNS["brokkr"] == "" {
		t.Fatalf("running sibling missing from the resolver view: %v", got.DNS)
	}
	if _, present := got.DNS["sib2"]; present {
		t.Fatalf("a never-started sibling must not resolve: %v", got.DNS)
	}
	// The helper's OWN registrations are in the resolver view; its HOSTNAME is only in the
	// hosts view, and is neither its name nor its alias — the D49 separation.
	if got.DNS["probe-alias"] == "" || got.DNS["probe1"] == "" {
		t.Fatalf("own registrations: %v", got.DNS)
	}
	if got.Hostname == "probe1" || got.Hostname == "probe-alias" {
		t.Fatalf("the hostname must be the daemon-minted id, not a resolvable name: %q", got.Hostname)
	}
	if got.Hosts[got.Hostname] == "" || len(got.Hosts) != 2 {
		t.Fatalf("hosts view holds localhost + hostname and nothing else: %v", got.Hosts)
	}
	if _, present := got.Hosts["probe-alias"]; present {
		t.Fatal("an alias must NEVER be in the hosts file — that is the selfcheck property")
	}
}

func TestDownFromLatches(t *testing.T) {
	f, c, m := setup(t)
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	f.DownFrom = "POST /volumes/create"
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("answers until the named operation: %v", err)
	}
	err := m.VolumeCreate(ctx, "vol1", prov(t))
	if !errors.Is(err, engine.ErrDaemonDown) {
		t.Fatalf("the named operation dies as down: %v", err)
	}
	// LATCHED: everything after it dies too, ping included — so the adapter's follow-up
	// question is unanswerable, which is what separates this from an object being gone.
	if err := c.Ping(ctx); !errors.Is(err, engine.ErrDaemonDown) {
		t.Fatalf("latched: %v", err)
	}
}

func TestInterruptOn(t *testing.T) {
	f, c, m := setup(t)
	ctx := context.Background()
	f.InterruptOn = "POST /volumes/create"
	err := m.VolumeCreate(ctx, "vol1", prov(t))
	if err == nil || !strings.Contains(err.Error(), "interrupted at") {
		t.Fatalf("the named step dies before its work: %v", err)
	}
	// The object it would have created never exists, and the daemon stays up.
	if _, verr := c.VolumeInspect(ctx, "vol1"); !errors.Is(verr, engine.ErrAbsent) {
		t.Fatalf("nothing may exist: %v", verr)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("the daemon stays up: %v", err)
	}
}

func TestDownAfterCounts(t *testing.T) {
	f, c, _ := setup(t)
	ctx := context.Background()
	f.DownAfter = 2
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); !errors.Is(err, engine.ErrDaemonDown) {
		t.Fatalf("the third call dies: %v", err)
	}
}
