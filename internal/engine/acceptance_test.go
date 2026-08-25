//go:build acceptance

package engine_test

// The REAL-DAEMON acceptance lane (Task 17): re-measures against a live local daemon the
// behaviors the hermetic fake asserts, so the fake can never quietly drift from the runtime
// it stands in for. Opt-in — `bash check.sh acceptance` — because it needs a local daemon and
// (once, for the pinned test image) the network; CI's default path stays hermetic. Run before
// every wave gate from here on; the measured Engine/API version is logged into the output.
//
// Every resource this suite creates carries a per-process name prefix and is removed on
// cleanup; the suite refuses to run if the resolved daemon is not local (ResolveEndpoint
// already guarantees that structurally).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
)

// acceptImage is a tiny image whose entrypoint STAYS RUNNING with no arguments — a product
// container's shape (the spec type has no command override, by design). busybox was the first
// choice and MEASURED wrong: with no TTY its default shell exits at once, so every "running"
// assertion inspected an exited container. Tag-addressed on purpose: this is the test rig's
// scaffolding, not a family artifact — nothing here exercises the trust chain, which pins by
// digest.
const acceptImage = "registry.k8s.io/pause:3.9"

type acceptRig struct {
	c   *engine.Client
	m   *engine.Mutator
	pfx string
}

func acceptClient(t *testing.T) *acceptRig {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	socket, err := engine.ResolveEndpoint(os.Environ(), home)
	if err != nil {
		t.Fatalf("acceptance needs a local daemon: %v", err)
	}
	c := engine.Dial(socket)
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("acceptance needs a RUNNING local daemon at %s: %v", socket, err)
	}
	v, api, err := c.ServerVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The record the plan asks for: which engine actually answered these measurements.
	t.Logf("MEASURED against Engine %s (API %s) at %s", v, api, socket)
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	m, err := engine.NewMutator(h, c)
	if err != nil {
		t.Fatal(err)
	}
	r := &acceptRig{c: c, m: m, pfx: fmt.Sprintf("mctlacc%d", os.Getpid())}
	if _, ierr := c.ImageInspect(ctx, acceptImage); errors.Is(ierr, engine.ErrAbsent) {
		if perr := m.ImagePull(ctx, acceptImage); perr != nil {
			t.Fatalf("acceptance needs %s (one pull): %v", acceptImage, perr)
		}
	}
	return r
}

func (r *acceptRig) cleanupContainer(t *testing.T, name string) {
	t.Cleanup(func() { _ = r.m.ContainerRemove(context.Background(), name) })
}

func (r *acceptRig) cleanupNetwork(t *testing.T, ref string) {
	t.Cleanup(func() { _ = r.m.NetworkRemove(context.Background(), ref) })
}

func (r *acceptRig) cleanupVolume(t *testing.T, name string) {
	t.Cleanup(func() { _ = r.m.VolumeRemove(context.Background(), name) })
}

func (r *acceptRig) network(t *testing.T, ctx context.Context, name string) string {
	t.Helper()
	prov, _ := engine.NewProvenance("acceptance", "n1")
	id, err := r.m.NetworkCreate(ctx, name, prov)
	if err != nil {
		t.Fatal(err)
	}
	r.cleanupNetwork(t, name)
	return id
}

func (r *acceptRig) container(t *testing.T, ctx context.Context, name, netID, alias string) string {
	t.Helper()
	spec := launchSpec(t, name, acceptImage, netID, alias, engine.SpecOpts{})
	id, err := r.m.ContainerCreate(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	r.cleanupContainer(t, name)
	return id
}

func TestAcceptanceFidelity(t *testing.T) {
	r := acceptClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	t.Run("volume create on existing keeps labels (D56)", func(t *testing.T) {
		name := r.pfx + "-vol1"
		provA, _ := engine.NewProvenance("acceptance", "orig")
		if err := r.m.VolumeCreate(ctx, name, provA); err != nil {
			t.Fatal(err)
		}
		r.cleanupVolume(t, name)
		provB, _ := engine.NewProvenance("other", "later")
		if err := r.m.VolumeCreate(ctx, name, provB); err != nil {
			t.Fatalf("create-on-existing must succeed: %v", err)
		}
		info, err := r.c.VolumeInspect(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Labels[engine.LabelNS+"nonce"] != "orig" {
			t.Fatalf("the original labels must survive: %v", info.Labels)
		}
	})

	t.Run("never-started endpoint id, address lifecycle (D48 + the 2026-08-04 lesson)", func(t *testing.T) {
		netID := r.network(t, ctx, r.pfx+"-net1")
		name := r.pfx + "-c1"
		r.container(t, ctx, name, netID, r.pfx+"-alias")
		info, err := r.c.ContainerInspect(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		ep, present := info.Networks[r.pfx+"-net1"]
		if !present {
			t.Fatalf("the name key must be present from creation: %+v", info.Networks)
		}
		if ep.NetworkID != "" {
			t.Fatalf("a NEVER-STARTED container must report an empty NetworkID (measured 2026-08-04), got %q", ep.NetworkID)
		}
		found := false
		for _, a := range ep.Aliases {
			if a == r.pfx+"-alias" {
				found = true
			}
		}
		if !found {
			t.Fatalf("the explicit alias must be registered: %v", ep.Aliases)
		}
		if err := r.m.ContainerStart(ctx, name); err != nil {
			t.Fatal(err)
		}
		info, _ = r.c.ContainerInspect(ctx, name)
		started := info.Networks[r.pfx+"-net1"]
		if started.NetworkID == "" || started.IPAddress == "" {
			t.Fatalf("start assigns endpoint id and address: %+v", started)
		}
		if err := r.m.ContainerStop(ctx, name); err != nil {
			t.Fatal(err)
		}
		info, _ = r.c.ContainerInspect(ctx, name)
		stopped := info.Networks[r.pfx+"-net1"]
		if stopped.IPAddress != "" {
			t.Fatalf("stop RELEASES the address: %+v", stopped)
		}
		if stopped.NetworkID == "" {
			t.Fatalf("the endpoint id PERSISTS across stop: %+v", stopped)
		}
	})

	t.Run("absent is an answer; unpulled image refused", func(t *testing.T) {
		if _, err := r.c.ContainerInspect(ctx, r.pfx+"-ghost"); !errors.Is(err, engine.ErrAbsent) {
			t.Fatalf("absent: %v", err)
		}
		netID := r.network(t, ctx, r.pfx+"-net2")
		spec := launchSpec(t, r.pfx+"-c2", r.pfx+"-neverpulled:v1", netID, "a1", engine.SpecOpts{})
		_, err := r.m.ContainerCreate(ctx, spec)
		if !errors.Is(err, engine.ErrAbsent) || !strings.Contains(err.Error(), "No such image") {
			t.Fatalf("unpulled image: %v", err)
		}
	})

	t.Run("bind mount refuses an absent source", func(t *testing.T) {
		netID := r.network(t, ctx, r.pfx+"-net3")
		b, err := engine.NewBindMount("/nonexistent/mctl/acceptance/source", "/dst", false)
		if err != nil {
			t.Fatal(err)
		}
		spec := launchSpec(t, r.pfx+"-c3", acceptImage, netID, "a1", engine.SpecOpts{Mounts: []engine.Mount{b}})
		_, cerr := r.m.ContainerCreate(ctx, spec)
		if cerr == nil || !strings.Contains(cerr.Error(), "bind source path does not exist") {
			t.Fatalf("absent bind source: %v", cerr)
		}
	})

	t.Run("referenced resources cannot be removed; force-remove clears a running container", func(t *testing.T) {
		netID := r.network(t, ctx, r.pfx+"-net4")
		name := r.pfx + "-c4"
		r.container(t, ctx, name, netID, "a4")
		// MEASURED 2026-08-25: a created-but-never-started attachment does NOT block network
		// removal (no active endpoint exists yet); a running one does.
		if err := r.m.ContainerStart(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := r.m.NetworkRemove(ctx, netID); err == nil {
			t.Fatal("a network with a RUNNING container attached must refuse removal")
		}
		// The client always force-removes — reconciliation must be able to clear a live one.
		if err := r.m.ContainerRemove(ctx, name); err != nil {
			t.Fatalf("force-remove of a running container: %v", err)
		}
		if err := r.m.NetworkRemove(ctx, netID); err != nil {
			t.Fatalf("after detach-by-removal the network goes: %v", err)
		}
	})

	t.Run("duplicate endpoint and private-mode connect refusals", func(t *testing.T) {
		netID := r.network(t, ctx, r.pfx+"-net5")
		name := r.pfx + "-c5"
		r.container(t, ctx, name, netID, "a5")
		// MEASURED 2026-08-25: on a NON-running container a second connect of the same network
		// is ACCEPTED (the stored endpoint config is updated); the conflict is a running-
		// container fact.
		if err := r.m.NetworkConnect(ctx, netID, name, "again", 0); err != nil {
			t.Fatalf("non-running duplicate connect is accepted by the daemon: %v", err)
		}
		if err := r.m.ContainerStart(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := r.m.NetworkConnect(ctx, netID, name, "again2", 0); err == nil {
			t.Fatal("connecting the same network twice to a RUNNING container must refuse")
		}
		// The private-mode (`none`) connect refusal is not measurable through this client: the
		// only `none`-mode door is HelperRun, which removes its container before returning.
		// It stays a bash-measured fidelity in the fake until the pinned helper image exists.
	})

	t.Run("gw-priority round-trips at v1.48 (the rebind case)", func(t *testing.T) {
		netA := r.network(t, ctx, r.pfx+"-neta")
		netB := r.network(t, ctx, r.pfx+"-netb")
		name := r.pfx + "-c6"
		r.container(t, ctx, name, netA, "a6")
		if err := r.m.ContainerStart(ctx, name); err != nil {
			t.Fatal(err)
		}
		// The target is attached at LOWER priority than the source, so the route must not
		// move before the migration's final phase — the reason APIVersion is v1.48.
		if err := r.m.NetworkConnect(ctx, netB, name, "a6", -10); err != nil {
			t.Fatalf("connect with gw-priority: %v", err)
		}
		info, err := r.c.ContainerInspect(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		ep := info.Networks[r.pfx+"-netb"]
		if ep.GwPriority != -10 {
			t.Fatalf("GwPriority must round-trip: %+v", ep)
		}
		if err := r.m.NetworkDisconnect(ctx, netA, name); err != nil {
			t.Fatalf("rebind detach: %v", err)
		}
		info, _ = r.c.ContainerInspect(ctx, name)
		if _, still := info.Networks[r.pfx+"-neta"]; still {
			t.Fatal("detached")
		}
		if err := r.m.ContainerRemove(ctx, name); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("helper launch failure removes the container", func(t *testing.T) {
		// No pinned helper image exists yet, and MEASURED 2026-08-25: a missing executable
		// fails the container at START (the daemon's 400, in containerd's words), not as an
		// exit code — so what this measures is HelperRun's failure path: the daemon's own
		// words ride the error, and the created container does NOT survive. The helper's
		// success path (wait / logs demultiplex / stdin attach) remains UNMEASURED against a
		// real daemon until the pinned probe image exists; the wave that builds it must add
		// that case here.
		// busybox, NOT the pause image: pause's entrypoint ignores argv and runs for ever, so
		// the closed command word would never fail — busybox has no entrypoint, and the word
		// is then the executable the daemon cannot find.
		const helperImage = "busybox:1.36"
		if _, ierr := r.c.ImageInspect(ctx, helperImage); errors.Is(ierr, engine.ErrAbsent) {
			if perr := r.m.ImagePull(ctx, helperImage); perr != nil {
				t.Fatalf("the helper case needs %s: %v", helperImage, perr)
			}
		}
		prov, _ := engine.NewProvenance("acceptance", "h1")
		hs, err := engine.NewHelperSpec(helperImage, r.pfx+"-h1", engine.HelperResolve, prov, engine.HelperOpts{})
		if err != nil {
			t.Fatal(err)
		}
		r.cleanupContainer(t, r.pfx+"-h1")
		_, _, herr := r.m.HelperRun(ctx, hs)
		if herr == nil || !strings.Contains(herr.Error(), "resolve") {
			t.Fatalf("the daemon's own words must ride the launch failure: %v", herr)
		}
		if _, ierr := r.c.ContainerInspect(ctx, r.pfx+"-h1"); !errors.Is(ierr, engine.ErrAbsent) {
			t.Fatal("no helper outlives its own invocation — a failed launch included")
		}
	})

	t.Run("authenticated registry pull", func(t *testing.T) {
		ref := os.Getenv("MYTHICAL_ACCEPTANCE_AUTH_REF")
		if ref == "" {
			t.Skip("SKIPPED LOUDLY: no authenticated registry configured — set MYTHICAL_ACCEPTANCE_AUTH_REF to a ref whose registry needs the docker login this machine holds, and re-run")
		}
		home, _ := os.UserHomeDir()
		r.c.SetDockerConfig(os.Environ(), home)
		if err := r.m.ImagePull(ctx, ref); err != nil {
			t.Fatalf("authenticated pull of %s: %v", ref, err)
		}
	})
}
