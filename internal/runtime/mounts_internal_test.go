package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// White-box: the protected-identity set covers the DIRECTORIES — the family home itself,
// bin/, and every other direct-child directory (the product dirs holding the user-owned
// host-tool slot) — while the two directory core-fixed SOURCES (logs, transcripts) stay out,
// or every launch would refuse its own mounts. An OS-level bind mount is the aliasing this
// set exists to catch, and a unit test cannot perform one, so the SET is what is asserted.
func TestProtectedIdentitiesCoverDirectories(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"bin", "transcripts", "logs", "brokkr"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"brokkr/nested", ".state"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, fpath := range []string{"mythical.conf", "brokkr.conf", "saga.conf", "bin/mythical-ctl", "brokkr/cli.toml", "brokkr/nested/artifact", ".state/ledger", "logs/x.log", "transcripts/t.txt"} {
		if err := os.WriteFile(filepath.Join(home, fpath), []byte("#x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// SYMLINKED children: a directory and a file living OUTSIDE the home, linked from it
	// (MkdirAll accepts a symlinked bin/ or .state/) — their targets must join the set.
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "realbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, fpath := range []string{"realbin/tool", "real.conf"} {
		if err := os.WriteFile(filepath.Join(outside, fpath), []byte("#x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "realbin"), filepath.Join(home, "linkbin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "real.conf"), filepath.Join(home, "link.conf")); err != nil {
		t.Fatal(err)
	}
	homeCanon, err := Canon(home)
	if err != nil {
		t.Fatal(err)
	}
	outsideCanon, err := Canon(outside)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protectedIdentities(homeCanon, "brokkr")
	if err != nil {
		t.Fatal(err)
	}
	// The product's OWN conf is a core-fixed SOURCE and must not refuse itself.
	if ino, ierr := identity(homeCanon + "/brokkr.conf"); ierr != nil || got[ino] {
		t.Fatalf("the product's own <product>.conf must NOT be in the protected set (%v)", ierr)
	}
	// The directories, their CONTENTS at any depth (the user-owned host-tool slot
	// `<product>/cli.toml` above all — gate round-18 P1), and the two named files.
	for _, p := range []string{homeCanon, homeCanon + "/bin", homeCanon + "/brokkr", homeCanon + "/mythical.conf", homeCanon + "/bin/mythical-ctl",
		homeCanon + "/brokkr/cli.toml", homeCanon + "/brokkr/nested", homeCanon + "/brokkr/nested/artifact", homeCanon + "/.state", homeCanon + "/.state/ledger",
		homeCanon + "/saga.conf",                                                               // a SIBLING product's conf (gate round-19 P2)
		outsideCanon + "/realbin", outsideCanon + "/realbin/tool", outsideCanon + "/real.conf", // symlink TARGETS (gate round-19 P1)
	} {
		ino, ierr := identity(p)
		if ierr != nil {
			t.Fatal(ierr)
		}
		if !got[ino] {
			t.Errorf("%s missing from the protected set", p)
		}
	}
	// The two core-fixed SOURCES and their contents are NOT protected — they are what the
	// product is meant to write.
	for _, p := range []string{homeCanon + "/logs", homeCanon + "/transcripts", homeCanon + "/logs/x.log", homeCanon + "/transcripts/t.txt"} {
		ino, ierr := identity(p)
		if ierr != nil {
			t.Fatal(ierr)
		}
		if got[ino] {
			t.Errorf("%s must NOT be protected — it is a core-fixed source", p)
		}
	}
}
