package runtime

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/volatile"
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

// THE OVERLAP GUARD, REACHED. `volatileMountFor` has two guards in order — the production-root
// check, then the isolation rule that no OTHER mount may sit at, under or over the credential-home
// root — and only the first was ever exercised.
//
// Its sibling in volatile_test.go — now named for what it does prove, that the production-root
// guard answers first — read as the isolation test and was not one: it declares `volatile_mount=/home/mythical`, which is refused by the production-root
// check first, so the loop below it never runs. MEASURED: with the loop rewritten to skip every
// non-volume mount — ignoring binds and the core-fixed targets entirely, which is exactly the
// implementation the test's name says cannot pass — `go test ./...` was GREEN across the whole
// tree. The guard was covered by nothing.
//
// It has to be a white-box test, and that is the reason this one lives here rather than beside its
// sibling. Reaching the second guard needs the CANONICAL root in the manifest and a durable mount
// overlapping it in the same launch, and no production bring-up can be arranged to produce that
// pair: the assembly path that would supply it refuses the manifest earlier for a different reason.
// Calling the function is the only way to ask it the question.
func TestVolatileMountRefusesADurableMountOverlappingTheCanonicalRoot(t *testing.T) {
	root := volatile.Root()
	m := volatileManifest(t, root)

	// A BIND, NOT A NAMED VOLUME, and under the root rather than at it: the shape of a core-fixed
	// target sitting inside the credential home. Both halves matter — a guard that only compared
	// named volumes, or only exact equality, would pass a test that used a volume or the root
	// itself, and durable bytes would still land inside the tmpfs tree.
	inside := rawMount{target: root + "/session", source: "/host/somewhere"}
	if _, ok, err := volatileMountFor(m, []rawMount{inside}); err == nil {
		t.Fatalf("a BIND at %q, inside the credential-home root %q, was accepted (ok=%v) — durable storage inside the tmpfs tree persists past teardown and is captured by backup, which is the whole property this mount exists to provide", inside.target, root, ok)
	} else if !strings.Contains(err.Error(), "overlaps the volatile credential-home mount") {
		t.Fatalf("refused, but not by the isolation guard: %v", err)
	}

	// AND SYMMETRICALLY, a bind ABOVE the root. `PathDisjoint` is symmetric; this proves the caller
	// passes its arguments in an order that keeps it so.
	over := rawMount{target: path.Dir(root), source: "/host/elsewhere"}
	if _, _, err := volatileMountFor(m, []rawMount{over}); err == nil {
		t.Fatalf("a bind at %q, an ANCESTOR of the credential-home root %q, was accepted", over.target, root)
	}

	// AND A DISJOINT MOUNT STILL PASSES. The rule is isolation, not a refusal of every launch that
	// has other mounts in it — a guard that refused everything would also kill both cases above and
	// prove nothing.
	away := rawMount{target: "/var/lib/brokkr", source: "brokkr-state", volume: true}
	got, ok, err := volatileMountFor(m, []rawMount{away})
	if err != nil {
		t.Fatalf("a mount disjoint from the credential-home root was refused: %v", err)
	}
	if !ok || !got.tmpfs || got.target != root {
		t.Fatalf("the resolved credential-home mount is not the tmpfs at the canonical root: ok=%v mount=%+v", ok, got)
	}
}

// volatileManifest builds an authenticated manifest declaring a credential-home mount at target.
func volatileManifest(t *testing.T, target string) *manifest.Manifest {
	t.Helper()
	body := strings.Join([]string{
		"mythical-manifest 1",
		"version=1",
		"expires=99999999999",
		"product=brokkr",
		"launched=true",
		"image=ghcr.io/mythicalos/brokkr@sha256:" + strings.Repeat("ab", 32),
		"min_core=0.1.0",
		"runtime_uid=900",
		"volatile_mount=" + target,
		"",
	}, "\n")
	m, err := manifest.ParseVerified([]byte(body), "t")
	if err != nil {
		t.Fatal(err)
	}
	return m
}
