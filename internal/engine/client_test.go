package engine_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
)

// Inventory — tests/unit/harness.bats:
// PORTED: tests/unit/harness.bats: "fake docker records and inspects a labelled volume, with no Id" -> TestVolumeCreateExistingKeepsLabels (labels round-trip; VolumeInfo has no ID field at the type level)
// PORTED: tests/unit/harness.bats: "creating an existing volume does not overwrite labels (real semantics)" -> TestVolumeCreateExistingKeepsLabels
// PORTED: tests/unit/harness.bats: "pull outcome is programmable" -> TestImagePullOutcomes
// PORTED: tests/unit/harness.bats: "every call is logged" -> TestRequestsLogged
// PORTED: tests/unit/harness.bats: "info reports a programmable server version" -> TestInfoAndVersionKnobs
// PORTED: tests/unit/harness.bats: "the info-failure knob breaks info ONLY, and version keeps answering" -> TestInfoFailOnly
// N/A: tests/unit/harness.bats: "fs snapshot is stable across a no-op and detects a new file" -- the fs-snapshot instrument is the bash harness's own; Go tests assert filesystem state directly
// N/A: tests/unit/harness.bats: "fs snapshot detects an in-place content change with the SAME mode" -- same: bash-harness instrument, not adapter behavior
// N/A: tests/unit/harness.bats: "fs snapshot is robust to a filename containing a newline and a tab" -- same: bash-harness instrument
// N/A: tests/unit/harness.bats: "fs snapshot does not hang on a FIFO — special files are recorded, never read" -- same: bash-harness instrument
// PORTED: tests/unit/harness.bats: "runtime snapshot captures volumes and their labels" -> TestSnapshot (enginetest/fake_test.go)
// PORTED: tests/unit/harness.bats: "a name that traverses out of the state directory is refused for every resource kind" -> TestCreateNameValidation (enginetest/fake_test.go; the traversal MECHANICS are structurally absent in map-backed state — what survives is the daemon's own name class on every create, so the fake is never more permissive than the daemon)
// N/A: tests/unit/harness.bats: "a traversing name cannot read or rewrite a file that already exists outside the state dir" -- map-backed state: no name is ever resolved as a filesystem path
// PORTED: tests/unit/harness.bats: "every subcommand that takes a name validates it, not only create" -> TestCreateNameValidation (creates refuse the class; lookups of a nonexistent weird name answer 404, a real daemon's answer, exercised by TestAbsentVsDown)
// PORTED: tests/unit/harness.bats: "image records are keyed by the exact reference, not a character-folded one" -> TestImageKeyExactRef (enginetest/fake_test.go)
// PORTED: tests/unit/harness.bats: "a container cannot be created on a network that does not exist" -> TestCreateUnknownNetwork
// PORTED: tests/unit/harness.bats: "network connect refuses a network that does not exist, and attaches by ID" -> TestConnectResolvesNetwork
// PORTED: tests/unit/harness.bats: "network create records the driver it was ASKED for, not an assumed one" -> TestNetworkCreateExplicitBridge
// PORTED: tests/unit/harness.bats: "an unimplemented flag is refused by every arm, never silently ignored" -> TestUnimplementedRouteIsFatal (enginetest/fake_test.go; the API-level closed surface: an unimplemented ROUTE or filter kind is a hard error, never a silent no-op)
// N/A: tests/unit/harness.bats: "a subcommand that acts on one object refuses a second one" -- an API path addresses exactly one object structurally; the multi-positional grammar does not exist
// N/A: tests/unit/harness.bats: "version, info and context answer only the templates they implement" -- Go templates are CLI grammar; the API returns typed documents (the closed-surface rule is the route test above)
// PORTED: tests/unit/harness.bats: "ls answers only the templates and filters it implements" -> TestListRefusesNonLabelFilter (enginetest/fake_test.go; the filter half — the template half is CLI grammar with no API analogue)
// PORTED: tests/unit/harness.bats: "a resource that is still referenced cannot be removed" -> TestReferencedResourcesCannotBeRemoved
// PORTED: tests/unit/harness.bats: "network connect refuses a duplicate endpoint and a private-mode container, and the container name is always an alias" -> TestConnectDuplicateAndPrivate + TestCreateStoppedAttachedAliased (name-always-an-alias)
// PORTED: tests/unit/harness.bats: "network disconnect resolves its network and refuses a container that is not attached" -> TestDisconnectResolution
// PORTED: tests/unit/harness.bats: "a missing --env-file is refused, and a two-field publish records the address the daemon binds" -> TestEmptyHostIPReportsAllInterfaces (enginetest/fake_test.go; the publish half — the env-file half is N/A: env rides the create body over the local socket, there is no file vehicle to be missing, see the SpecOpts.Env doc)
// PORTED: tests/unit/harness.bats: "container run without --rm leaves the container behind, as a real daemon does" -> TestHelperCrashWindowLeavesContainer (enginetest/fake_test.go; the Go client always removes — the fake keeps the fidelity that an UNREMOVED helper persists, which is the crash window the probe's accounting covers)
// PORTED: tests/unit/harness.bats: "a named volume a container mounts is auto-created, as the daemon does" -> TestAutoCreatedVolumeUnlabelled
// PORTED: tests/unit/harness.bats: "an image id is stable across inspects" -> TestImageIDStable (enginetest/fake_test.go)
// N/A: tests/unit/harness.bats: "the lock file and its temps (incl. the recovery gate) are excluded from the fs snapshot" -- fs-snapshot instrument (see above)
//
// Inventory — tests/unit/runtime.bats (the transport half; the spec-assembly half is Task 15's):
// PORTED: tests/unit/runtime.bats: "ping succeeds against the fake runtime and reports the engine version" -> TestPingAndServerVersion
// PORTED: tests/unit/runtime.bats: "an engine version can be faked, so the preflight gate is testable" -> TestInfoAndVersionKnobs
// N/A: tests/unit/runtime.bats: "the engine version is read from the SERVER, not from the client" -- the API /version document carries the SERVER's Version field and the client binary has no version of its own here; the client/server template confusion is a CLI-grammar hazard with no API analogue
// PORTED: tests/unit/runtime.bats: "the daemon endpoint is read from the active context (D30)" -> TestResolveEndpointContextSelection (endpoint_test.go)
// PORTED: tests/unit/runtime.bats: "ping FAILS when the daemon is unreachable" -> TestPingDown
// PORTED: tests/unit/runtime.bats: "inspect returns 3 for an absent object and 1 when the daemon cannot answer" -> TestAbsentVsDown
// N/A: tests/unit/runtime.bats: "a caller cannot supply its own Go template" -- no template surface exists: inspects return typed documents, so the closed template map's job is done by the types
// PORTED: tests/unit/runtime.bats: "an argument containing a control byte is refused before it reaches the runtime" -> TestControlByteRefusal
// PORTED: tests/unit/runtime.bats: "a created container is stopped, on exactly one network, with the alias" -> TestCreateStoppedAttachedAliased
// PORTED: tests/unit/runtime.bats: "a stopped container has NO address; starting it assigns one" -> TestAddressLifecycle
// PORTED: tests/unit/runtime.bats: "EVERY published port is on 127.0.0.1 — a caller cannot ask for anything else" -> TestLoopbackWall
// N/A: tests/unit/runtime.bats: "publish=<host>:<container> is the only accepted publish shape" -- the publish spec grammar is gone: NewPortPublish(containerPort, hostPort uint16) IS the shape (port 0 refused, TestConstructorRefusals)
// PORTED: tests/unit/runtime.bats: "host / none / container: network modes are refused at creation" -> TestNetmodeRefusals
// PORTED: tests/unit/runtime.bats: "find_by_label lists STOPPED containers too" -> TestListIncludesStopped
// PORTED: tests/unit/runtime.bats: "find_by_label rejects a label key outside the closed set" -> TestListClosedLabelKeys
// PORTED: tests/unit/runtime.bats: "volume create against an existing name does NOT apply labels (real semantics)" -> TestVolumeCreateExistingKeepsLabels
// PORTED: tests/unit/runtime.bats: "network create can be made to produce a duplicate, so D38 is testable" -> TestDuplicateNetworkKnob
// PORTED: tests/unit/runtime.bats: "the family network is created with an EXPLICIT bridge driver (D29)" -> TestNetworkCreateExplicitBridge
// PORTED: tests/unit/runtime.bats: "image pull failures are distinguishable" -> TestImagePullOutcomes
// PORTED: tests/unit/runtime.bats: "snap_runtime captures containers and networks, not only volumes" -> TestSnapshot (enginetest/fake_test.go)
// PORTED: tests/unit/runtime.bats: "the helper's three mount specs are validated, not interpolated" -> TestHelperMountVocabulary (the closed helper-mount constructors pin target AND writability; path/name rules in TestConstructorRefusals)
// PORTED: tests/unit/runtime.bats: "a container cannot be created from an image that was never pulled" -> TestUnpulledImageRefused
// PORTED: tests/unit/runtime.bats: "a bind whose source does not exist is refused, never silently created" -> TestAbsentBindSourceRefused
// PORTED: tests/unit/runtime.bats: "the helper container is always --rm — no helper outlives its own invocation" -> TestHelperRunLeavesNothing
// PORTED: tests/unit/runtime.bats: "container rm force-removes a RUNNING container" -> TestForceRemoveRunning
// PORTED: tests/unit/runtime.bats: "connect passes the alias EXPLICITLY, so a sibling can reach the peer (§6b.2)" -> TestConnectExplicitAlias
// N/A: tests/unit/runtime.bats: "an env file that does not exist is refused by the ADAPTER, before the runtime" -- there is no env-file vehicle to be missing: env rides the create body over the local socket (SpecOpts.Env doc carries the §4.3 equivalence)
// N/A: tests/unit/runtime.bats: "gateway priority must be an integer, not merely made of integer characters" -- gwPriority is an int parameter; the grammar IS the type
// PORTED: tests/unit/runtime.bats: "helper arguments keep their exact argv boundaries — no splitting, no globbing" -> TestHelperArgvBoundaries
// (deferred to Task 15, runtime_invariants_test.go: "a comma in a bind spec cannot smuggle a Docker mount option"; "a comma in a volume spec cannot convert a named volume into a host bind")
// (deferred to Task 16, preflight_test.go: "rootless is read from the daemon's SecurityOptions, and 'cannot ask' is not 'rootful'")

func newFake(t *testing.T) (*enginetest.Fake, *engine.Client) {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	return f, f.Client()
}

func newMutator(t *testing.T, c *engine.Client) (*engine.Mutator, famlock.Held) {
	t.Helper()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatalf("NewMutator: %v", err)
	}
	return m, h
}

func mustProv(t *testing.T) engine.Provenance {
	t.Helper()
	p, err := engine.NewProvenance("inst1", "nonce1")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// launchSpec builds a minimal valid product spec on the given network.
func launchSpec(t *testing.T, name, image, network, alias string, opts engine.SpecOpts) engine.ContainerSpec {
	t.Helper()
	na, err := engine.NewNetworkAttach(network, alias)
	if err != nil {
		t.Fatal(err)
	}
	opts.Network = na
	spec, err := engine.NewContainerSpec(name, image, opts)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestPingAndServerVersion(t *testing.T) {
	_, c := newFake(t)
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	v, api, err := c.ServerVersion(ctx)
	if err != nil || v != "28.0.0" || api == "" {
		t.Fatalf("version: %q %q %v", v, api, err)
	}
}

func TestInfoAndVersionKnobs(t *testing.T) {
	f, c := newFake(t)
	f.ServerVersionValue = "27.5.1"
	v, _, err := c.ServerVersion(context.Background())
	if err != nil || v != "27.5.1" {
		t.Fatalf("faked version: %q %v", v, err)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.ServerVersion != "27.5.1" {
		t.Fatalf("info: %+v %v", info, err)
	}
	f.Rootless = true
	info, err = c.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range info.SecurityOptions {
		if s == "name=rootless" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rootless not reported: %v", info.SecurityOptions)
	}
}

func TestInfoFailOnly(t *testing.T) {
	f, c := newFake(t)
	f.InfoFail = true
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping must keep answering: %v", err)
	}
	if _, _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatalf("version must keep answering: %v", err)
	}
	_, err := c.Info(context.Background())
	if err == nil || errors.Is(err, engine.ErrDaemonDown) {
		t.Fatalf("info must fail on its own, not as daemon-down: %v", err)
	}
}

func TestPingDown(t *testing.T) {
	f, c := newFake(t)
	f.Down = true
	err := c.Ping(context.Background())
	if !errors.Is(err, engine.ErrDaemonDown) {
		t.Fatalf("want ErrDaemonDown, got %v", err)
	}
}

func TestAbsentVsDown(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	// Absent: the daemon ANSWERS and the object is not there — an rc-3 fact a later run may
	// act on. This is also the lookup answer for any name no create would accept.
	_, err := c.ContainerInspect(ctx, "no-such-container")
	if !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("absent container: %v", err)
	}
	if _, err := c.VolumeInspect(ctx, "no-such-volume"); !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("absent volume: %v", err)
	}
	if _, err := c.NetworkInspect(ctx, "no-such-net"); !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("absent network: %v", err)
	}
	if _, err := c.ImageInspect(ctx, "img:none"); !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("absent image: %v", err)
	}
	// Down: the question could not be asked — never folded into absent.
	f.Down = true
	_, err = c.ContainerInspect(ctx, "no-such-container")
	if !errors.Is(err, engine.ErrDaemonDown) || errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("down: %v", err)
	}
}

func TestInspectMissingKnob(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	if err := m.VolumeCreate(ctx, "vol1", mustProv(t)); err != nil {
		t.Fatal(err)
	}
	f.InspectMissing = "vol1"
	f.InspectMissingAfter = 1
	if _, err := c.VolumeInspect(ctx, "vol1"); err != nil {
		t.Fatalf("survives its first inspection: %v", err)
	}
	_, err := c.VolumeInspect(ctx, "vol1")
	if !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("vanishes before the second: %v", err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("the daemon keeps answering: %v", err)
	}
}

func TestControlByteRefusal(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	before := len(f.Requests)
	if _, err := c.ContainerInspect(ctx, "a\x01b"); err == nil || errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("control byte: %v", err)
	}
	if _, err := c.NetworkInspect(ctx, "a\tb"); err == nil || errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("tab: %v", err)
	}
	if _, err := c.ContainerList(ctx, map[string]string{"nonce": "x\x00y"}); err == nil {
		t.Fatal("control byte in a filter value")
	}
	if len(f.Requests) != before {
		t.Fatalf("a refused argument must never reach the runtime; %d request(s) got through", len(f.Requests)-before)
	}
}

func TestRequestsLogged(t *testing.T) {
	f, c := newFake(t)
	_ = c.Ping(context.Background())
	_, _, _ = c.ServerVersion(context.Background())
	if len(f.Requests) != 2 {
		t.Fatalf("want 2 logged requests, got %v", f.Requests)
	}
}

// --- the Mutator lock boundary ---------------------------------------------------------------

func TestMutatorRequiresHeldLock(t *testing.T) {
	_, c := newFake(t)
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := famlock.Release(h); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewMutator(h, c); err == nil {
		t.Fatal("a released token must not construct a Mutator")
	}
}

// The round-4 correction pinned: a retained Mutator must stop mutating at Release — every
// method fails the assert and the fake records NO request.
func TestMutatorDeadAfterRelease(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatal(err)
	}
	prov := mustProv(t)
	f.PullImage("img:v1")
	if _, err := m.NetworkCreate(ctx, "net1", prov); err != nil {
		t.Fatalf("while held: %v", err)
	}
	if err := famlock.Release(h); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests)
	spec := launchSpec(t, "c1", "img:v1", "net1", "alias1", engine.SpecOpts{})
	hs, err := engine.NewHelperSpec("img:v1", "h1", engine.HelperResolve, prov, engine.HelperOpts{})
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		name string
		call func() error
	}{
		{"ContainerCreate", func() error { _, err := m.ContainerCreate(ctx, spec); return err }},
		{"ContainerStart", func() error { return m.ContainerStart(ctx, "c1") }},
		{"ContainerStop", func() error { return m.ContainerStop(ctx, "c1") }},
		{"ContainerRemove", func() error { return m.ContainerRemove(ctx, "c1") }},
		{"VolumeCreate", func() error { return m.VolumeCreate(ctx, "v1", prov) }},
		{"VolumeRemove", func() error { return m.VolumeRemove(ctx, "v1") }},
		{"NetworkCreate", func() error { _, err := m.NetworkCreate(ctx, "net2", prov); return err }},
		{"NetworkRemove", func() error { return m.NetworkRemove(ctx, "net2") }},
		{"NetworkConnect", func() error { return m.NetworkConnect(ctx, "net1", "c1", "a", 0) }},
		{"NetworkDisconnect", func() error { return m.NetworkDisconnect(ctx, "net1", "c1") }},
		{"ImagePull", func() error { return m.ImagePull(ctx, "img:v2") }},
		{"HelperRun", func() error { _, err := m.HelperRun(ctx, hs); return err }},
	}
	for _, tc := range calls {
		if err := tc.call(); err == nil {
			t.Errorf("%s succeeded after Release", tc.name)
		}
	}
	if len(f.Requests) != before {
		t.Fatalf("a dead Mutator issued %d request(s): %v", len(f.Requests)-before, f.Requests[before:])
	}
}

// --- creation, attachment, lifecycle ---------------------------------------------------------

func TestCreateStoppedAttachedAliased(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "brokkr-alias", engine.SpecOpts{})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Running || info.Status != "created" {
		t.Fatalf("created STOPPED: %+v", info)
	}
	if len(info.Networks) != 1 {
		t.Fatalf("exactly one network: %+v", info.Networks)
	}
	// The NAME key must be PRESENT — asserted, not assumed: a missing key yields a zero
	// NetEndpoint whose empty NetworkID would satisfy the next check for the wrong reason. The
	// fake reports a never-started endpoint under the SUBMITTED key (measured), so this is what
	// makes the client's resolve-to-name before create load-bearing in the hermetic suite.
	ep, present := info.Networks["family"]
	if !present {
		t.Fatalf("the never-started endpoint must be keyed by the network NAME; got keys %v", keysOf(info.Networks))
	}
	// NEVER-STARTED fidelity: NetworkID empty while the name key is present.
	if ep.NetworkID != "" {
		t.Fatalf("a never-started container must report an empty NetworkID, got %q", ep.NetworkID)
	}
	// The explicit alias AND the container's own name — an omitted alias is observable.
	if len(ep.Aliases) != 2 || ep.Aliases[0] != "brokkr-alias" || ep.Aliases[1] != "c1" {
		t.Fatalf("aliases: %v", ep.Aliases)
	}
}

func TestAddressLifecycle(t *testing.T) {
	f, c, m := newFakePair(t)
	ctx := context.Background()
	fakeSetup(t, f, m, ctx)
	info, _ := c.ContainerInspect(ctx, "c1")
	created, present := info.Networks["family"]
	if !present {
		t.Fatalf("the never-started endpoint must be keyed by the network NAME; got keys %v", keysOf(info.Networks))
	}
	if created.IPAddress != "" {
		t.Fatal("a created container must have no address")
	}
	if err := m.ContainerStart(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	info, _ = c.ContainerInspect(ctx, "c1")
	started := info.Networks["family"]
	if started.IPAddress == "" || started.NetworkID == "" {
		t.Fatalf("start assigns address and endpoint id: %+v", started)
	}
	if err := m.ContainerStop(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	info, _ = c.ContainerInspect(ctx, "c1")
	stopped := info.Networks["family"]
	// Docker RELEASES the address on stop; the endpoint id PERSISTS.
	if stopped.IPAddress != "" {
		t.Fatal("a stopped container must have no address")
	}
	if stopped.NetworkID == "" {
		t.Fatal("the endpoint id persists across stop")
	}
}

// keysOf lists a Networks map's keys for a failure message.
func keysOf(m map[string]engine.NetEndpoint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// fakeSetup pulls img:v1, creates network "family" and container c1 on it.
func fakeSetup(t *testing.T, f *enginetest.Fake, m *engine.Mutator, ctx context.Context) string {
	t.Helper()
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "alias1", engine.SpecOpts{})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	return netID
}

func newFakePair(t *testing.T) (*enginetest.Fake, *engine.Client, *engine.Mutator) {
	t.Helper()
	f, c := newFake(t)
	m, _ := newMutator(t, c)
	return f, c, m
}

func TestLoopbackWall(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	p1, err := engine.NewPortPublish(7480, 7480)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := engine.NewPortPublish(9000, 19000)
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "a1", engine.SpecOpts{Ports: []engine.PortPublish{p1, p2}})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Ports) != 2 {
		t.Fatalf("ports: %+v", info.Ports)
	}
	for _, p := range info.Ports {
		if p.HostIP != "127.0.0.1" {
			t.Fatalf("EVERY published port must be on 127.0.0.1, got %+v", p)
		}
	}
}

func TestNetmodeRefusals(t *testing.T) {
	for _, mode := range []string{"host", "none", "container:other"} {
		if _, err := engine.NewNetworkAttach(mode, "a"); err == nil {
			t.Errorf("network mode %q must be refused at the type", mode)
		}
	}
	// And at the connect door.
	f, c := newFake(t)
	m, _ := newMutator(t, c)
	before := len(f.Requests)
	for _, mode := range []string{"host", "none", "container:other"} {
		if err := m.NetworkConnect(context.Background(), mode, "c1", "a", 0); err == nil {
			t.Errorf("connect to %q must be refused", mode)
		}
	}
	if len(f.Requests) != before {
		t.Fatal("a refused mode must never reach the daemon")
	}
}

func TestConstructorRefusals(t *testing.T) {
	if _, err := engine.NewPortPublish(0, 7480); err == nil {
		t.Error("container port 0")
	}
	if _, err := engine.NewPortPublish(7480, 0); err == nil {
		t.Error("host port 0")
	}
	if _, err := engine.NewBindMount("relative/path", "/dst", false); err == nil {
		t.Error("relative bind source")
	}
	if _, err := engine.NewBindMount("/a/../b", "/dst", false); err == nil {
		t.Error("a .. component")
	}
	if _, err := engine.NewBindMount("/a", "dst", false); err == nil {
		t.Error("relative target")
	}
	if _, err := engine.NewVolumeMount("/abs", "/dst"); err == nil {
		t.Error("an absolute path is not a volume name")
	}
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{}); err == nil {
		t.Error("a spec with no network attachment")
	}
	na, _ := engine.NewNetworkAttach("net", "a")
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: na, Labels: map[string]string{"evil": "x"},
	}); err == nil {
		t.Error("a label key outside the closed set")
	}
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: na, Env: []string{"NOEQUALS"},
	}); err == nil {
		t.Error("env without =")
	}
	// NESTED zero values: constructible anywhere (`var m engine.Mount`), so the spec
	// constructors must re-check the constructor bit or an unvalidated wire value gets through.
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: na, Mounts: []engine.Mount{{}},
	}); err == nil {
		t.Error("a zero-value Mount in a product spec")
	}
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: na, Ports: []engine.PortPublish{{}},
	}); err == nil {
		t.Error("a zero-value PortPublish in a product spec")
	}
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: engine.NetworkAttach{},
	}); err == nil {
		t.Error("a zero-value NetworkAttach")
	}
	// A helper-vocabulary mount is not a product mount: the read-only volume variants exist
	// only for helpers, and a product spec must not be able to smuggle one in.
	srcRO, _ := engine.NewHelperSrcVolume("v1")
	if _, err := engine.NewContainerSpec("c1", "img", engine.SpecOpts{
		Network: na, Mounts: []engine.Mount{srcRO},
	}); err == nil {
		t.Error("a helper-vocabulary mount in a product spec")
	}
	prov := engine.Provenance{}
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperResolve, prov, engine.HelperOpts{}); err == nil {
		t.Error("a helper without provenance")
	}
	good, _ := engine.NewProvenance("i", "n")
	if _, err := engine.NewHelperSpec("img", "h1", "evilcmd", good, engine.HelperOpts{}); err == nil {
		t.Error("a command word outside the closed set")
	}
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperResolve, good, engine.HelperOpts{Alias: "a"}); err == nil {
		t.Error("an alias with no network — no resolver exists to register it with")
	}
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperResolve, good, engine.HelperOpts{RunAs: "10x0"}); err == nil {
		t.Error("a non-numeric uid")
	}
}

func TestHelperMountVocabulary(t *testing.T) {
	// The closed vocabulary pins target AND writability — a caller cannot mount the source
	// writable or stage anywhere but /dst, because no constructor says it.
	cases := []struct {
		name string
		make func() (engine.Mount, error)
	}{
		{"srcvol", func() (engine.Mount, error) { return engine.NewHelperSrcVolume("v1") }},
		{"staging", func() (engine.Mount, error) { return engine.NewHelperStaging("/tmp/stage") }},
		{"dstro", func() (engine.Mount, error) { return engine.NewHelperDstRO("/tmp/tree") }},
		{"srcbind", func() (engine.Mount, error) { return engine.NewHelperSrcBind("/tmp/backup") }},
		{"dstvol", func() (engine.Mount, error) { return engine.NewHelperDstVolume("v2") }},
	}
	for _, tc := range cases {
		if _, err := tc.make(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := engine.NewHelperSrcVolume("/abs"); err == nil {
		t.Error("srcvol with a path")
	}
	if _, err := engine.NewHelperStaging("rel"); err == nil {
		t.Error("staging with a relative path")
	}
	if _, err := engine.NewHelperDstVolume("/abs"); err == nil {
		t.Error("dstvol with a path")
	}
	// THE VOCABULARY IS ENFORCED AT THE SPEC, not merely offered: a general bind — an
	// arbitrary writable host tree — is refused by NewHelperSpec, as are a general volume
	// mount and a zero value. Each of the five words is accepted.
	prov := mustProv(t)
	bind, _ := engine.NewBindMount("/etc", "/dst", false)
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperCopy, prov, engine.HelperOpts{Mounts: []engine.Mount{bind}}); err == nil {
		t.Error("a general bind mount in a helper spec — an arbitrary writable host tree")
	}
	vol, _ := engine.NewVolumeMount("v1", "/data")
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperCopy, prov, engine.HelperOpts{Mounts: []engine.Mount{vol}}); err == nil {
		t.Error("a general volume mount in a helper spec")
	}
	if _, err := engine.NewHelperSpec("img", "h1", engine.HelperCopy, prov, engine.HelperOpts{Mounts: []engine.Mount{{}}}); err == nil {
		t.Error("a zero-value mount in a helper spec")
	}
	for _, tc := range cases {
		mt, _ := tc.make()
		if _, err := engine.NewHelperSpec("img", "h1", engine.HelperCopy, prov, engine.HelperOpts{Mounts: []engine.Mount{mt}}); err != nil {
			t.Errorf("%s refused by NewHelperSpec: %v", tc.name, err)
		}
	}
}

func TestUnpulledImageRefused(t *testing.T) {
	_, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "never-pulled:v1", netID, "a1", engine.SpecOpts{})
	_, err = m.ContainerCreate(ctx, spec)
	if err == nil || !errors.Is(err, engine.ErrAbsent) || !strings.Contains(err.Error(), "No such image") {
		t.Fatalf("unpulled image: %v", err)
	}
	if _, ierr := c.ContainerInspect(ctx, "c1"); !errors.Is(ierr, engine.ErrAbsent) {
		t.Fatal("a refused create must leave nothing behind")
	}
}

func TestAbsentBindSourceRefused(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := engine.NewBindMount("/nonexistent/source/path", "/dst", false)
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "a1", engine.SpecOpts{Mounts: []engine.Mount{b}})
	_, err = m.ContainerCreate(ctx, spec)
	if err == nil || !strings.Contains(err.Error(), "bind source path does not exist") {
		t.Fatalf("absent bind source: %v", err)
	}
}

func TestAutoCreatedVolumeUnlabelled(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	v, err := engine.NewVolumeMount("freshvol", "/data")
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "a1", engine.SpecOpts{Mounts: []engine.Mount{v}})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	info, err := c.VolumeInspect(ctx, "freshvol")
	if err != nil {
		t.Fatalf("the daemon auto-creates a missing named volume: %v", err)
	}
	if len(info.Labels) != 0 {
		t.Fatalf("the auto-created volume carries NO labels (invisible to find-by-label): %v", info.Labels)
	}
}

func TestVolumeCreateExistingKeepsLabels(t *testing.T) {
	_, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	if err := m.VolumeCreate(ctx, "vol1", mustProv(t)); err != nil {
		t.Fatal(err)
	}
	other, err := engine.NewProvenance("other-install", "other-nonce")
	if err != nil {
		t.Fatal(err)
	}
	// REAL semantics (D56): the second create SUCCEEDS and applies nothing.
	if err := m.VolumeCreate(ctx, "vol1", other); err != nil {
		t.Fatalf("create-on-existing must succeed: %v", err)
	}
	info, err := c.VolumeInspect(ctx, "vol1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Labels[engine.LabelNS+"nonce"] != "nonce1" || info.Labels[engine.LabelNS+"installation"] != "inst1" {
		t.Fatalf("the original labels must survive: %v", info.Labels)
	}
}

func TestCreateUnknownNetwork(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	spec := launchSpec(t, "c1", "img:v1", "no-such-network", "a1", engine.SpecOpts{})
	_, err := m.ContainerCreate(ctx, spec)
	if !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("unknown network: %v", err)
	}
}

func TestNetworkCreateExplicitBridge(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	// D29's stated threat: a daemon whose DEFAULT is not a NAT bridge. The Mutator asks for
	// bridge explicitly, so the created network is bridge anyway.
	f.NetDefaultDriver = "macvlan"
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.NetworkInspect(ctx, netID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Driver != "bridge" {
		t.Fatalf("the family network must be EXPLICITLY bridge, got %q", info.Driver)
	}
}

func TestDuplicateNetworkKnob(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	id1, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	// Without the knob, a duplicate name is refused — the common case.
	if _, err := m.NetworkCreate(ctx, "family", mustProv(t)); err == nil {
		t.Fatal("duplicate refused without the knob")
	}
	// D38: Docker does not guarantee name-conflict detection, so the knob makes the delayed
	// original + reissue pair reproducible.
	f.DuplicateNetworkNames = true
	id2, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("two networks, two ids")
	}
	_ = c
}

func TestConnectResolvesNetwork(t *testing.T) {
	f, c, m := newFakePair(t)
	ctx := context.Background()
	netID := fakeSetup(t, f, m, ctx)
	if err := m.NetworkConnect(ctx, "no-such-net", "c1", "a2", -10); err == nil {
		t.Fatal("connect to an absent network")
	}
	// A second network, connected BY NAME — the attachment must be recorded under its ID.
	id2, err := m.NetworkCreate(ctx, "second", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.NetworkConnect(ctx, "second", "c1", "a2", -10); err != nil {
		t.Fatal(err)
	}
	if err := m.ContainerStart(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	ep, present := info.Networks["second"]
	if !present || ep.NetworkID != id2 {
		t.Fatalf("attached by name, recorded under the ID: %+v", info.Networks)
	}
	if ep.GwPriority != -10 {
		t.Fatalf("gw priority recorded: %+v", ep)
	}
	_ = netID
}

func TestConnectExplicitAlias(t *testing.T) {
	f, c, m := newFakePair(t)
	ctx := context.Background()
	fakeSetup(t, f, m, ctx)
	id2, err := m.NetworkCreate(ctx, "second", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.NetworkConnect(ctx, id2, "c1", "peer-alias", 0); err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	al := info.Networks["second"].Aliases
	if len(al) != 2 || al[0] != "peer-alias" || al[1] != "c1" {
		t.Fatalf("the explicit alias plus the container's own name: %v", al)
	}
	// The alias is REQUIRED by the signature; an empty one is refused before any request.
	if err := m.NetworkConnect(ctx, id2, "c1", "", 0); err == nil {
		t.Fatal("an empty alias must be refused")
	}
}

func TestConnectDuplicateAndPrivate(t *testing.T) {
	f, _, m := newFakePair(t)
	ctx := context.Background()
	netID := fakeSetup(t, f, m, ctx)
	// On a NON-running container the daemon accepts a second connect and updates the endpoint
	// config (measured 2026-08-25); the CONFLICT is a running-container fact.
	if err := m.NetworkConnect(ctx, netID, "c1", "replaced", 5); err != nil {
		t.Fatalf("non-running duplicate connect updates config: %v", err)
	}
	if err := m.ContainerStart(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	err := m.NetworkConnect(ctx, netID, "c1", "again", 0)
	if err == nil || !strings.Contains(err.Error(), "already exists in network") {
		t.Fatalf("duplicate endpoint on a running container: %v", err)
	}
	// The private-mode refusal ("container cannot be connected … in private (none) mode") is
	// asserted in enginetest/fake_test.go's TestPrivateModeConnectRefused: a standing
	// private-mode container is only expressible there — HelperRun (the one private-mode door
	// in this client) removes its container before returning, which is its own guarantee.
}

func TestForceRemoveRunning(t *testing.T) {
	f, c, m := newFakePair(t)
	ctx := context.Background()
	fakeSetup(t, f, m, ctx)
	if err := m.ContainerStart(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := m.ContainerRemove(ctx, "c1"); err != nil {
		t.Fatalf("force-remove of a RUNNING container is what reconciliation depends on: %v", err)
	}
	if _, err := c.ContainerInspect(ctx, "c1"); !errors.Is(err, engine.ErrAbsent) {
		t.Fatal("removed")
	}
}

func TestDisconnectResolution(t *testing.T) {
	f, _, m := newFakePair(t)
	ctx := context.Background()
	netID := fakeSetup(t, f, m, ctx)
	if err := m.NetworkDisconnect(ctx, "no-such-net", "c1"); err == nil {
		t.Fatal("disconnect from an absent network must be an error, not success-that-detached-nothing")
	}
	id2, err := m.NetworkCreate(ctx, "second", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	// Not attached is an ERROR, not a no-op.
	if err := m.NetworkDisconnect(ctx, id2, "c1"); err == nil {
		t.Fatal("disconnect of a never-attached container")
	}
	// By NAME, resolving exactly as connect does.
	if err := m.NetworkDisconnect(ctx, "family", "c1"); err != nil {
		t.Fatalf("disconnect by name: %v", err)
	}
	// The silent-failure knob: success reported, attachment survives.
	if err := m.NetworkConnect(ctx, netID, "c1", "a1", 0); err != nil {
		t.Fatal(err)
	}
	f.DisconnectSilent = true
	if err := m.NetworkDisconnect(ctx, netID, "c1"); err != nil {
		t.Fatalf("the silent knob reports success: %v", err)
	}
	info, err := f.Client().ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if _, still := info.Networks["family"]; !still {
		t.Fatal("the attachment must survive a silent detach")
	}
}

func TestReferencedResourcesCannotBeRemoved(t *testing.T) {
	f, _, m := newFakePair(t)
	ctx := context.Background()
	netID := fakeSetup(t, f, m, ctx)
	// A network with an ACTIVE endpoint — a RUNNING container (measured 2026-08-25: a
	// created-or-stopped attachment does not block removal; only a live endpoint does).
	if err := m.ContainerStart(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := m.NetworkRemove(ctx, netID); err == nil || !strings.Contains(err.Error(), "active endpoints") {
		t.Fatalf("network with endpoints: %v", err)
	}
	// A volume a container mounts.
	v, err := engine.NewVolumeMount("data1", "/data")
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c2", "img:v1", netID, "a2", engine.SpecOpts{Mounts: []engine.Mount{v}})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := m.VolumeRemove(ctx, "data1"); err == nil || !strings.Contains(err.Error(), "volume is in use") {
		t.Fatalf("volume in use: %v", err)
	}
	// Detach, remove the containers, and both removals go through — the teardown ordering.
	if err := m.ContainerRemove(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := m.ContainerRemove(ctx, "c2"); err != nil {
		t.Fatal(err)
	}
	if err := m.VolumeRemove(ctx, "data1"); err != nil {
		t.Fatal(err)
	}
	if err := m.NetworkRemove(ctx, netID); err != nil {
		t.Fatal(err)
	}
}

func TestListIncludesStopped(t *testing.T) {
	f, c, m := newFakePair(t)
	ctx := context.Background()
	fakeSetup(t, f, m, ctx)
	// c1 is created (never started): a listing that missed it would reissue and collide.
	got, err := c.ContainerList(ctx, map[string]string{"installation": "inst1"})
	if err != nil {
		t.Fatal(err)
	}
	// The spec carried no labels, so filter by what fakeSetup labels — nothing. Re-create
	// with labels to make the filter observable.
	if len(got) != 0 {
		t.Fatalf("no labelled containers yet: %+v", got)
	}
	netID, err := m.NetworkCreate(ctx, "second", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c2", "img:v1", netID, "a2", engine.SpecOpts{
		Labels: map[string]string{"installation": "inst1", "product": "brokkr"},
	})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	got, err = c.ContainerList(ctx, map[string]string{"installation": "inst1"})
	if err != nil || len(got) != 1 || got[0].Names[0] != "c2" {
		t.Fatalf("a STOPPED container must be listed: %+v %v", got, err)
	}
	if got[0].State != "created" {
		t.Fatalf("state: %+v", got[0])
	}
	// Both labels must match (AND semantics).
	got, err = c.ContainerList(ctx, map[string]string{"installation": "inst1", "product": "saga"})
	if err != nil || len(got) != 0 {
		t.Fatalf("AND semantics: %+v %v", got, err)
	}
}

func TestListClosedLabelKeys(t *testing.T) {
	f, c := newFake(t)
	before := len(f.Requests)
	if _, err := c.ContainerList(context.Background(), map[string]string{"generation": "3"}); err == nil {
		t.Fatal("generation is create-only vocabulary, not a list key")
	}
	if _, err := c.VolumeList(context.Background(), map[string]string{"evil": "x"}); err == nil {
		t.Fatal("a key outside the closed set")
	}
	if _, err := c.NetworkList(context.Background(), nil); err == nil {
		t.Fatal("a listing with no label at all — discovery is by label, never unscoped")
	}
	if len(f.Requests) != before {
		t.Fatal("refused filters must never reach the daemon")
	}
}

func TestImagePullOutcomes(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	// ok: the image becomes locally present, keyed by the exact ref.
	if err := m.ImagePull(ctx, "reg.example/probe@sha256:0000000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Fatal(err)
	}
	if f.LastPullRef != "reg.example/probe@sha256:0000000000000000000000000000000000000000000000000000000000000001" {
		t.Fatalf("digest ref round-trip: %q", f.LastPullRef)
	}
	if _, err := c.ImageInspect(ctx, f.LastPullRef); err != nil {
		t.Fatalf("pulled image present: %v", err)
	}
	// The three failure kinds stay DISTINGUISHABLE — the registry's own words ride the error.
	cases := map[string]string{
		"notfound":  "manifest unknown",
		"auth":      "denied: requested access to the resource is denied",
		"neterr":    "no such host",
		"streamerr": "unexpected EOF",
	}
	for outcome, want := range cases {
		f.PullOutcome = outcome
		err := m.ImagePull(ctx, "img:v9")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", outcome, err)
		}
	}
}

// --- helpers ---------------------------------------------------------------------------------

func TestHelperRunLeavesNothing(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 0, []byte("alias=a1\naddress=10.88.0.5\nselfcheck=ok\n")
	}
	hs, err := engine.NewHelperSpec("probe:pinned", "probe1", engine.HelperSelfcheck, mustProv(t), engine.HelperOpts{
		Network: netID, Alias: "a1", Args: []string{"a1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.HelperRun(ctx, hs)
	if err != nil || res.Code != 0 {
		t.Fatalf("helper: %d %v", res.Code, err)
	}
	if !strings.Contains(string(res.Stdout), "selfcheck=ok") {
		t.Fatalf("output: %q", res.Stdout)
	}
	// NO HELPER OUTLIVES ITS OWN INVOCATION — and a FAILING helper is removed too.
	if n := f.ContainerCount(); n != 0 {
		t.Fatalf("%d container(s) survived a successful helper run", n)
	}
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 1, []byte("selfcheck=fail\n")
	}
	res, err = m.HelperRun(ctx, hs)
	if err != nil || res.Code != 1 {
		t.Fatalf("failing helper reports its code: %d %v", res.Code, err)
	}
	if n := f.ContainerCount(); n != 0 {
		t.Fatalf("%d container(s) survived a FAILED helper run", n)
	}
}

func TestHelperArgvBoundaries(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	var gotCmd string
	var gotArgs []string
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		gotCmd, gotArgs = cmd, args
		return 0, nil
	}
	hs, err := engine.NewHelperSpec("probe:pinned", "h1", engine.HelperVerify, mustProv(t), engine.HelperOpts{
		Args: []string{"two words", "*", "-looks-like-a-flag"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.HelperRun(ctx, hs); err != nil {
		t.Fatal(err)
	}
	if gotCmd != "verify" {
		t.Fatalf("cmd: %q", gotCmd)
	}
	// Exact argv boundaries: no splitting, no globbing, and a dash-leading argument is an
	// ARGUMENT, never a flag.
	if len(gotArgs) != 3 || gotArgs[0] != "two words" || gotArgs[1] != "*" || gotArgs[2] != "-looks-like-a-flag" {
		t.Fatalf("args: %q", gotArgs)
	}
}

func TestHelperStdin(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	var gotStdin []byte
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		gotStdin = stdin
		return 0, []byte("verified=ok\n")
	}
	manifest := []byte("mythical-backup 1\nentry.a=1\n")
	hs, err := engine.NewHelperSpec("probe:pinned", "h1", engine.HelperVerify, mustProv(t), engine.HelperOpts{
		Stdin: manifest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.HelperRun(ctx, hs); err != nil {
		t.Fatal(err)
	}
	if string(gotStdin) != string(manifest) {
		t.Fatalf("stdin: %q", gotStdin)
	}
}

func TestHelperFailKnob(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	f.HelperFail = "fabricated launch failure"
	hs, err := engine.NewHelperSpec("probe:pinned", "h1", engine.HelperEgress, mustProv(t), engine.HelperOpts{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.HelperRun(ctx, hs)
	if err == nil || !strings.Contains(err.Error(), "fabricated launch failure") {
		t.Fatalf("launch failure surfaces the daemon's words: %v", err)
	}
	// Even a helper that never RAN is removed — the create succeeded, so an object existed.
	if n := f.ContainerCount(); n != 0 {
		t.Fatalf("%d container(s) survived a failed helper launch", n)
	}
}

// Stdout is the ANSWER and stderr is diagnostics — the reference captured `$(…)` (stdout) and
// let stderr through to the operator. A protocol field printed on stderr must not reach the
// reader through Stdout.
func TestHelperStderrIsNotTheAnswer(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 1, []byte("egress=fail\n")
	}
	f.HelperStderr = []byte("egress=ok\nwarning: a diagnostic line\n")
	hs, err := engine.NewHelperSpec("probe:pinned", "h1", engine.HelperEgress, mustProv(t), engine.HelperOpts{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.HelperRun(ctx, hs)
	if err != nil || res.Code != 1 {
		t.Fatalf("run: %d %v", res.Code, err)
	}
	if string(res.Stdout) != "egress=fail\n" {
		t.Fatalf("Stdout must carry ONLY the helper's answer, got %q", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "warning: a diagnostic line") {
		t.Fatalf("Stderr must carry the diagnostics, got %q", res.Stderr)
	}
}

// The force-remove must not inherit the caller's cancellation: a context that dies mid-run is
// exactly when a survivor is most likely, and a removal that failed before reaching the daemon
// would be a survivor created by the mechanism meant to prevent one.
func TestHelperRunCleanupSurvivesCancellation(t *testing.T) {
	f, c := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, _ := newMutator(t, c)
	f.PullImage("probe:pinned")
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		cancel() // the caller's context dies WHILE the helper runs
		return 0, []byte("egress=ok\n")
	}
	hs, err := engine.NewHelperSpec("probe:pinned", "h1", engine.HelperEgress, mustProv(t), engine.HelperOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.HelperRun(ctx, hs); err == nil {
		t.Fatal("a run whose context was cancelled mid-flight must report it")
	}
	if n := f.ContainerCount(); n != 0 {
		t.Fatalf("%d container(s) survived a cancelled helper run — the removal inherited the cancellation", n)
	}
}

// The wire half of registry auth (round-8): the pull carries X-Registry-Auth resolved from
// the docker config, and the fake DECODES it and the test compares the EXACT AuthConfig —
// not mere header presence.
func TestPullAuthHeader(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	home := t.TempDir()
	root := home + "/.docker"
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"auths":{"reg.example":{"username":"wireuser","password":"wirepass"}}}`
	if err := os.WriteFile(root+"/config.json", []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c.SetDockerConfig(nil, home)
	m, _ := newMutator(t, c)
	if err := m.ImagePull(ctx, "reg.example/img:v1"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"username": "wireuser", "password": "wirepass", "serveraddress": "reg.example",
	}
	if len(f.LastPullAuth) != len(want) {
		t.Fatalf("decoded AuthConfig: %v", f.LastPullAuth)
	}
	for k, v := range want {
		if f.LastPullAuth[k] != v {
			t.Fatalf("decoded AuthConfig[%s] = %q, want %q (%v)", k, f.LastPullAuth[k], v, f.LastPullAuth)
		}
	}
	// An anonymous pull sends NO header, and the fake records nil.
	if err := m.ImagePull(ctx, "unnamed.example/img:v1"); err != nil {
		t.Fatal(err)
	}
	if f.LastPullAuth != nil {
		t.Fatalf("anonymous pull must carry no header: %v", f.LastPullAuth)
	}
}
