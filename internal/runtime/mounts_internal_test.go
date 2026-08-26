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
	for _, fpath := range []string{"mythical.conf", "bin/mythical-ctl"} {
		if err := os.WriteFile(filepath.Join(home, fpath), []byte("#x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	homeCanon, err := Canon(home)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protectedIdentities(homeCanon)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{homeCanon, homeCanon + "/bin", homeCanon + "/brokkr", homeCanon + "/mythical.conf", homeCanon + "/bin/mythical-ctl"} {
		ino, ierr := identity(p)
		if ierr != nil {
			t.Fatal(ierr)
		}
		if !got[ino] {
			t.Errorf("%s missing from the protected set", p)
		}
	}
	for _, p := range []string{homeCanon + "/logs", homeCanon + "/transcripts"} {
		ino, ierr := identity(p)
		if ierr != nil {
			t.Fatal(ierr)
		}
		if got[ino] {
			t.Errorf("%s must NOT be protected — it is a core-fixed source", p)
		}
	}
}
