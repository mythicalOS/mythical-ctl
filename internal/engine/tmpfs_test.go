package engine_test

import (
	"context"
	"testing"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/volatile"
)

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
