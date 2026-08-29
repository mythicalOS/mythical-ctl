package engine_test

import (
	"context"
	"errors"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/volatile"
)

// Inventory — tests/unit/runtime.bats (the credential-home mount rows):
// PORTED: tests/unit/runtime.bats: "a volatile spec renders a NON-PERSISTENT tmpfs carrying the fixed nodev,nosuid,noexec" -> TestTmpfsMountRendersFrozenHardening -- the COMPLETE option string is asserted, not a substring — its order is a byte-parity contract with producers outside this repository
// PORTED: tests/unit/runtime.bats: "the volatile mount is not a named volume — nothing for the volume-backup path to see" -> TestTmpfsMountIsNotADurableMount -- nothing in the durable mount record at all, so no backup or removal sweep can enumerate it
// PORTED: tests/unit/runtime.bats: "teardown wipes: removing the container discards the volatile tmpfs" -> TestTeardownWipesTheCredentialHome -- and the post-removal inspect must be ErrAbsent specifically — an ANSWER that the object is gone, never a transport failure read as a successful wipe
// PORTED: tests/unit/runtime.bats: "a volatile spec with a path the wire rejects is refused at the launch site" -> TestTmpfsMountRefusedAtTheLaunchSite -- the constructor is the wall: refused before any container exists, not filtered afterwards

// createWithTmpfs launches a container carrying one tmpfs mount at the canonical
// credential-home root, and returns the inspected result.
func createWithTmpfs(t *testing.T, target string) *engine.ContainerInfo {
	t.Helper()
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	tm, err := engine.NewTmpfsMount(target)
	if err != nil {
		t.Fatalf("NewTmpfsMount(%q): %v", target, err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "brokkr-alias", engine.SpecOpts{Mounts: []engine.Mount{tm}})
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// TestTmpfsMountRendersFrozenHardening: a tmpfs mount reaches the daemon as a HostConfig.Tmpfs
// entry carrying EXACTLY the frozen option set.
//
// It must be a tmpfs and not a typed Mount, because a tmpfs is the one mount form that carries
// the kernel security flags — a Mounts entry has nowhere to put nodev/nosuid/noexec, so the
// mount would exist with the hardening silently absent, which is the failure this whole wire
// exists to prevent. The COMPLETE option string is asserted, not a substring: see the wire
// package for why its ORDER is a contract with producers outside this repository.
func TestTmpfsMountRendersFrozenHardening(t *testing.T) {
	root := volatile.Root()
	info := createWithTmpfs(t, root)

	if len(info.Tmpfs) != 1 {
		t.Fatalf("expected exactly one tmpfs mount, got %v", info.Tmpfs)
	}
	opts, present := info.Tmpfs[root]
	if !present {
		t.Fatalf("no tmpfs mount at %q; the daemon was given %v", root, info.Tmpfs)
	}
	if opts != "nodev,nosuid,noexec" {
		t.Fatalf("tmpfs at %q mounted with %q, want exactly \"nodev,nosuid,noexec\"", root, opts)
	}
	// The same string, through the wire's own fail-closed predicate — a weakened or reordered
	// set is a DIFFERENT, weaker mount and must not read as hardened.
	if !volatile.SecOptsOK(opts) {
		t.Fatalf("the rendered hardening %q is not the frozen set", opts)
	}
}

// TestTmpfsMountIsNotADurableMount: the credential home is a tmpfs precisely because it is never
// durable storage. It must not surface as a named volume or a bind — nothing for a volume-backup
// or volume-removal sweep to enumerate, because there is no volume.
func TestTmpfsMountIsNotADurableMount(t *testing.T) {
	info := createWithTmpfs(t, volatile.Root())
	for _, m := range info.Mounts {
		t.Errorf("the volatile mount surfaced in the durable mount record as %s %q at %q — "+
			"a tmpfs must not appear where a backup or removal sweep enumerates storage",
			m.Type, m.Name, m.Destination)
	}
}

// TestTeardownWipesTheCredentialHome: teardown IS a wipe, and that is a property of the mount
// KIND rather than of any cleanup code. The tmpfs is non-persistent, so removing the container
// discards the mount and everything materialized on it — there is no volume to remove, no
// directory to unlink, and nothing a missed cleanup step could leave behind. After the removal
// the object is GONE (an answer), not merely unreadable (no answer).
func TestTeardownWipesTheCredentialHome(t *testing.T) {
	root := volatile.Root()
	f, c := newFake(t)
	ctx := context.Background()
	m, _ := newMutator(t, c)
	f.PullImage("img:v1")
	netID, err := m.NetworkCreate(ctx, "family", mustProv(t))
	if err != nil {
		t.Fatal(err)
	}
	tm, err := engine.NewTmpfsMount(root)
	if err != nil {
		t.Fatal(err)
	}
	spec := launchSpec(t, "c1", "img:v1", netID, "brokkr-alias", engine.SpecOpts{Mounts: []engine.Mount{tm}})
	id, err := m.ContainerCreate(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Tmpfs[root] != "nodev,nosuid,noexec" {
		t.Fatalf("the credential home was not mounted before teardown: %v", info.Tmpfs)
	}
	if err := m.ContainerRemove(ctx, id); err != nil {
		t.Fatal(err)
	}
	// ErrAbsent, specifically: "the object is gone" is an ANSWER and authorizes reconciliation;
	// a transport failure is not, and must not be read as a successful wipe.
	if _, err := c.ContainerInspect(ctx, id); !errors.Is(err, engine.ErrAbsent) {
		t.Fatalf("after removal the container inspect returned %v, want ErrAbsent — "+
			"the mount is only wiped if the container really went with it", err)
	}
}

// TestTmpfsMountRefusedAtTheLaunchSite: the constructor is the wall. A manifest cannot smuggle a
// traversal, an unbounded path, or a second token to the mount — the value is refused before any
// container exists, not filtered afterwards.
func TestTmpfsMountRefusedAtTheLaunchSite(t *testing.T) {
	for _, bad := range []string{
		"/run/../etc",                         // traversal
		"relative/path",                       // not absolute
		"/",                                   // the bare container root
		"/run/mythical/credential-homes/",     // trailing slash
		"/run/mythical/credential-homes:rw",   // a second token
		"/run/mythical/credential-homes exec", // an option behind a space
		"",                                    // empty
	} {
		if _, err := engine.NewTmpfsMount(bad); err == nil {
			t.Errorf("NewTmpfsMount(%q) was accepted — the launch site is not the wall", bad)
		}
	}
	// A valid bounded path is accepted: the guard refuses bad values, it does not refuse the
	// feature.
	if _, err := engine.NewTmpfsMount(volatile.Root()); err != nil {
		t.Fatalf("the canonical root was refused: %v", err)
	}
}

// TestTmpfsMountIsNotAHelperMount: the closed helper vocabulary stays closed. A helper handed a
// tmpfs would be a helper handed a mount whose target the vocabulary never pinned.
func TestTmpfsMountIsNotAHelperMount(t *testing.T) {
	tm, err := engine.NewTmpfsMount(volatile.Root())
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.NewHelperSpec("img:v1", "h1", engine.HelperResolve, mustProv(t),
		engine.HelperOpts{Mounts: []engine.Mount{tm}})
	if err == nil {
		t.Fatal("a helper accepted a tmpfs mount — the closed helper vocabulary is no longer closed")
	}
}
