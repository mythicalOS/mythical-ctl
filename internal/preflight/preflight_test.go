package preflight

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
)

// Inventory — tests/unit/preflight.bats:
// PORTED: tests/unit/preflight.bats: "a healthy local rootful Engine 28 daemon passes" -> TestDaemonHealthy
// PORTED: tests/unit/preflight.bats: "Engine 27 is refused, naming the version and the reason" -> TestEngineVersionGate
// PORTED: tests/unit/preflight.bats: "a version we cannot parse is refused, never treated as new enough" -> TestEngineVersionGate
// PORTED: tests/unit/preflight.bats: "a 100-major engine is accepted — the comparison is numeric, not lexical" -> TestEngineVersionGate
// PORTED: tests/unit/preflight.bats: "a rootless daemon is refused with the reason" -> TestRootless
// PORTED: tests/unit/preflight.bats: "a remote DOCKER_HOST is refused" -> TestResolveEndpointDockerHost (engine/endpoint_test.go — locality moved into the fail-closed resolver, before a client exists to preflight)
// PORTED: tests/unit/preflight.bats: "an ssh:// context is refused" -> TestResolveEndpointContextSelection (engine/endpoint_test.go)
// PORTED: tests/unit/preflight.bats: "Docker Desktop's managed VM socket is ACCEPTED" -> TestResolveEndpointDockerHost (engine/endpoint_test.go)
// PORTED: tests/unit/preflight.bats: "an npipe:// endpoint is accepted (Docker Desktop on Windows) but tcp:// is not" -> TestResolveEndpointDockerHost (the tcp half; the npipe half is a DECLARED N/A — this arc ships no Windows binary, so the resolver refuses npipe NAMING the platform gap, and that refusal is what the test asserts)
// PORTED: tests/unit/preflight.bats: "a REMOTE named pipe is refused — the scheme alone is not the locality" -> TestResolveEndpointDockerHost (engine/endpoint_test.go: with no Windows target BOTH pipe spellings refuse, the remote one included — the local/remote split returns with a Windows port)
// PORTED: tests/unit/preflight.bats: "an absent daemon is refused, distinctly from a policy refusal" -> TestDaemonDown
// PORTED: tests/unit/preflight.bats: "a daemon we cannot ask about rootlessness is refused, not assumed rootful" -> TestRootless
// PORTED: tests/unit/preflight.bats: "a bridge network with no trusted_host_interfaces passes" -> TestNetwork
// PORTED: tests/unit/preflight.bats: "a macvlan network is refused" -> TestNetwork
// PORTED: tests/unit/preflight.bats: "an ipvlan network is refused" -> TestNetwork
// PORTED: tests/unit/preflight.bats: "trusted_host_interfaces set to ANY value is refused, naming the setting" -> TestNetworkTHI
// N/A: tests/unit/preflight.bats: "trusted_host_interfaces rendered as Go's '<no value>' is ABSENT, not set" -- a template artifact: on the API an absent option is an absent map key, and no '<no value>' spelling exists to mis-read
// PORTED: tests/unit/preflight.bats: "a network that does not exist is refused, not silently skipped" -> TestNetwork
// N/A: tests/unit/preflight.bats: "no docker command at all is refused before anything else is asked" -- no docker BINARY is consulted anywhere: the client dials the resolved socket, and the analogous absence is the transport refusal (TestDaemonDown)
// PORTED: tests/unit/preflight.bats: "mi_preflight_all runs the daemon half even when no network is named" -> TestAll
// PORTED: tests/unit/preflight.bats: "mi_preflight_all refuses when the network half refuses" -> TestAll
// N/A: tests/unit/preflight.bats: "allow-direct-routing is documented as undetectable and no check claims to detect it" -- carried as this package's doc comment verbatim; nothing executable claims detection, so there is nothing executable to assert
// PORTED: tests/unit/preflight.bats: "the engine-version grammar refuses every malformed shape, not just the reported one" -> TestEngineVersionGrammar
// PORTED: tests/unit/preflight.bats: "every real Docker version shape is still accepted — the grammar must not over-refuse" -> TestEngineVersionGrammar
// PORTED: tests/unit/preflight.bats: "a malformed version is refused through the public preflight path, not only the helper" -> TestEngineVersionGate
//
// Deferred from Task 14 (tests/unit/runtime.bats):
// PORTED: tests/unit/runtime.bats: "rootless is read from the daemon's SecurityOptions, and 'cannot ask' is not 'rootful'" -> TestRootless

func newFake(t *testing.T) (*enginetest.Fake, *engine.Client) {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	return f, f.Client()
}

func TestDaemonHealthy(t *testing.T) {
	_, c := newFake(t)
	if err := Daemon(context.Background(), c); err != nil {
		t.Fatalf("a healthy rootful Engine 28 daemon must pass: %v", err)
	}
}

func TestDaemonDown(t *testing.T) {
	f, c := newFake(t)
	f.Down = true
	err := Daemon(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("an absent daemon is its own refusal, distinct from a policy one: %v", err)
	}
}

func TestRootless(t *testing.T) {
	f, c := newFake(t)
	f.Rootless = true
	err := Daemon(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "ROOTLESS") {
		t.Fatalf("rootless: %v", err)
	}
	// The THREE-outcome rule: a daemon that cannot be ASKED is refused, never assumed
	// rootful — /info fails alone while ping keeps answering, so this refusal is reachable
	// past the ping.
	f.Rootless = false
	f.InfoFail = true
	err = Daemon(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "refusing rather than assuming") {
		t.Fatalf("cannot-ask: %v", err)
	}
}

func TestEngineVersionGate(t *testing.T) {
	f, c := newFake(t)
	// Engine 27: refused, naming the version and the reason.
	f.ServerVersionValue = "27.5.1"
	err := Daemon(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "27.5.1") || !strings.Contains(err.Error(), "L2 segment") {
		t.Fatalf("engine 27: %v", err)
	}
	// A version we cannot parse — through the PUBLIC preflight path, not only the helper.
	f.ServerVersionValue = "dev"
	if err := Daemon(context.Background(), c); err == nil {
		t.Fatal("unparseable version treated as new enough")
	}
	// A 100-major engine: the comparison is numeric, not lexical.
	f.ServerVersionValue = "100.0.1"
	if err := Daemon(context.Background(), c); err != nil {
		t.Fatalf("100-major: %v", err)
	}
}

func TestEngineVersionGrammar(t *testing.T) {
	// The full malforming matrix — every shape a reviewer produced, closed as a class.
	refuse := []string{"", "dev", "28.", "28..", "28.0..", "28.0__", "28.0-", "28.0.0--",
		".28", "-28.0", "27.9.9", "0.28", "28.1234567890", "2 8", "28.x"}
	for _, v := range refuse {
		if engineMajorOK(v) {
			t.Errorf("%q accepted", v)
		}
	}
	// Every real Docker shape still accepted — the grammar must not over-refuse: a false
	// refusal strands every install on a supported daemon.
	accept := []string{"28", "28.1.4", "2025.1", "28.0.0-beta.1", "28.0.0-rc.1", "28.0.0+build.7", "29.0.0-dev"}
	for _, v := range accept {
		if !engineMajorOK(v) {
			t.Errorf("%q refused", v)
		}
	}
}

func TestNetwork(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatal(err)
	}
	prov, _ := engine.NewProvenance("i", "n")
	netID, err := m.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	// A bridge with no trusted_host_interfaces passes — by ID and by name.
	if err := Network(ctx, c, netID); err != nil {
		t.Fatalf("bridge by id: %v", err)
	}
	if err := Network(ctx, c, "family"); err != nil {
		t.Fatalf("bridge by name: %v", err)
	}
	// Absent: refused, not silently skipped.
	if err := Network(ctx, c, "no-such-net"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("absent: %v", err)
	}
	// macvlan / ipvlan: the driver override knob fabricates what the client cannot
	// legitimately create — the reason the knob exists.
	for _, drv := range []string{"macvlan", "ipvlan"} {
		f.NetDriverOverride = drv
		id, err := m.NetworkCreate(ctx, "net-"+drv, prov)
		if err != nil {
			t.Fatal(err)
		}
		if err := Network(ctx, c, id); err == nil || !strings.Contains(err.Error(), drv) {
			t.Errorf("%s: %v", drv, err)
		}
	}
	// An unknown driver: refused for the same reason an unparseable version is.
	f.NetDriverOverride = "weirddriver"
	id, err := m.NetworkCreate(ctx, "net-weird", prov)
	if err != nil {
		t.Fatal(err)
	}
	if err := Network(ctx, c, id); err == nil {
		t.Fatal("unknown driver accepted")
	}
}

func TestNetworkTHI(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatal(err)
	}
	prov, _ := engine.NewProvenance("i", "n")
	f.NetTHI = "eth0"
	netID, err := m.NetworkCreate(ctx, "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	err = Network(ctx, c, netID)
	if err == nil || !strings.Contains(err.Error(), "trusted_host_interfaces") || !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("ANY non-empty value refuses, naming the setting: %v", err)
	}
}

func TestAll(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	// The daemon half runs even when no network is named — a first install has no network
	// yet, and stop/uninstall must work when it is gone.
	if err := All(ctx, c, ""); err != nil {
		t.Fatalf("no network named: %v", err)
	}
	f.Rootless = true
	if err := All(ctx, c, ""); err == nil {
		t.Fatal("the daemon half must still run with no network named")
	}
	f.Rootless = false
	// And it refuses when the network half refuses.
	if err := All(ctx, c, "no-such-net"); err == nil {
		t.Fatal("the network half must be able to refuse the whole preflight")
	}
}
