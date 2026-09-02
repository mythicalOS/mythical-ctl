package engine

import (
	"strings"
	"testing"
)

// TestSpecRefusesUnfrozenTmpfs reaches the door the exported constructors close.
//
// Every other test in this package builds mounts through NewTmpfsMount, which can only ever
// produce the frozen hardening — so none of them can tell whether NewContainerSpec's re-check
// does anything. This one hand-assembles the Mount that only in-package code could assemble: the
// `ok` bit set, so it is not caught as a zero value, and a WEAKENED option set. That is the same
// hazard the `ok` bit itself exists for, one field along, and it is the only way a weaker mount
// could reach the daemon under the credential home's name.
func TestSpecRefusesUnfrozenTmpfs(t *testing.T) {
	na, err := NewNetworkAttach("family", "brokkr")
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []string{
		"nodev,nosuid",             // a flag dropped
		"nosuid,nodev,noexec",      // reordered — same kernel flags, different bytes
		"nodev,nosuid,noexec,exec", // an option added back
		"",                         // no hardening at all
		"rw,nodev,nosuid,noexec",   // prefixed
	} {
		bad := Mount{typ: "tmpfs", target: "/run/mythical/credential-homes", opts: opts, ok: true}
		_, err := NewContainerSpec("c1", "img:v1", SpecOpts{Network: na, Mounts: []Mount{bad}})
		if err == nil {
			t.Errorf("a tmpfs carrying %q was accepted into a container spec — a weaker mount can reach the daemon", opts)
			continue
		}
		if !strings.Contains(err.Error(), "frozen credential-home hardening") {
			t.Errorf("the tmpfs carrying %q was refused, but not as a hardening failure: %v", opts, err)
		}
	}
	// The frozen set is accepted — the guard refuses weakening, not the mount.
	good, err := NewTmpfsMount("/run/mythical/credential-homes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewContainerSpec("c1", "img:v1", SpecOpts{Network: na, Mounts: []Mount{good}}); err != nil {
		t.Fatalf("the frozen hardening was refused: %v", err)
	}
}
