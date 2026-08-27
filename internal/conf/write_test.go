package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// Inventory — tests/unit/config_family.bats:
// PORTED: tests/unit/config_family.bats: "the path is ~/.mythical/mythical.conf" -> TestFamilyPathShape
// PORTED: tests/unit/config_family.bats: "the first set creates the file at mode 0600" -> TestFamilyAddCreatesAt0600
// PORTED: tests/unit/config_family.bats: "a second key is added additively, leaving the first untouched" -> TestFamilyAddPreservesBytes
// PORTED: tests/unit/config_family.bats: "adding a key preserves comments, blank lines, order and unrelated keys byte-for-byte" -> TestFamilyAddPreservesBytes
// PORTED: tests/unit/config_family.bats: "adding a key that already holds a DIFFERENT value is refused, and the file is untouched" -> TestFamilyAddAdditiveGate
// PORTED: tests/unit/config_family.bats: "adding a key that already holds the SAME value is a no-op success" -> TestFamilyAddAdditiveGate
// N/A: tests/unit/config_family.bats: "a call with the wrong number of arguments refuses instead of aborting under set -u" -- Go signatures fix arity at compile time
// PORTED: tests/unit/config_family.bats: "a new key is appended at the end, after existing content" -> TestFamilyAddPreservesBytes
// PORTED: tests/unit/config_family.bats: "a value invalid for its type is refused before the additive gate" -> TestFamilyAddValidation
// PORTED: tests/unit/config_family.bats: "a value that would forge a second key is refused" -> TestFamilyAddValidation
// PORTED: tests/unit/config_family.bats: "a value with a shell metacharacter is refused" -> TestFamilyAddValidation
// PORTED: tests/unit/config_family.bats: "a key outside the core spec is refused" -> TestFamilyAddValidation
// PORTED: tests/unit/config_family.bats: "a value invalid for its type is refused" -> TestFamilyAddValidation
// PORTED: tests/unit/config_family.bats: "an existing file with an off-schema key is never modified" -> TestFamilyAddNeverModifiesUnparseable
// PORTED: tests/unit/config_family.bats: "a change landing under us is refused, not overwritten" -> TestFamilyAddCASRefusesConcurrentChange (the CAS seam is exercised at the narrowest point Go exposes)
// N/A: tests/unit/config_family.bats: "bytes swapped in during the copy are validated, not persisted" -- the Go writer reads ONCE and builds from those bytes; there is no copy window with a second read to swap under (structural: single os.ReadFile)
// PORTED: tests/unit/config_family.bats: "same-value no-op does not report success if the file changed under us" -> TestFamilyAddCASRefusesConcurrentChange
// PORTED: tests/unit/config_family.bats: "a symlink planted after the first identity check is still refused before the replace" -> TestFamilySymlinkRefused (the pre-replace identity re-check is the same code path; the plant-between-checks window is the accepted pathname residual, as in bash)
// PORTED: tests/unit/config_family.bats: "a symlinked mythical.conf is refused, not followed and adopted" -> TestFamilySymlinkRefused
// PORTED: tests/unit/config_family.bats: "a hardlinked mythical.conf is refused, leaving the other name untouched" -> TestFamilyHardlinkRefused
// PORTED: tests/unit/config_family.bats: "an existing file that does not parse is never overwritten" -> TestFamilyAddNeverModifiesUnparseable
// PORTED: tests/unit/config_family.bats: "mi_conf_family_load validates against the core spec" -> TestLoadFamilyValid
// PORTED: tests/unit/config_family.bats: "writing without the family lock is refused" -> TestWritesRequireTheLock
// PORTED: tests/unit/config_family.bats: "a forged lock token does not authorize a write" -> TestWritesRequireTheLock (a nil/foreign Held fails famlock.Assert — the sealed-type port of the token forgery test)
// N/A: tests/unit/config_family.bats: "mi_lock_assert_held refuses a no-argument call in its own words" -- Go arity is compile-time
// N/A: tests/unit/config_family.bats: "the ledger's lock refusal is unchanged by the extraction" -- bash source-extraction regression; Go has no extraction seam
// PORTED: tests/unit/config_family.bats: "a foreign-owned mythical.conf is refused" -> TestForeignOwnedRefused (identityOK's uid branch; STATED RESIDUAL — creating a foreign-owned file needs root, so the test skips on an unprivileged run and only a root run exercises it)
// PORTED: tests/unit/config_family.bats: "a non-regular mythical.conf is refused" -> TestNonRegularRefused
//
// Inventory — tests/unit/config_product.bats:
// PORTED: tests/unit/config_product.bats: "the path is ~/.mythical/<product>.conf" -> TestProductPathShape
// PORTED: tests/unit/config_product.bats: "a write creates the file with a trailing integrity marker" -> TestProductAddCreatesMarkered
// PORTED: tests/unit/config_product.bats: "mi_conf_get refuses a marker-bearing file — product confs go through mi_conf_product_load" -> TestGetRefusesMarkeredFile
// PORTED: tests/unit/config_product.bats: "the marker is a checksum of everything above it" -> TestProductAddCreatesMarkered
// PORTED: tests/unit/config_product.bats: "the file lands at 0660 with the family gid when chgrp succeeds" -> TestProductOwnershipApplied
// PORTED: tests/unit/config_product.bats: "when chgrp fails the write reports rc 5 and leaves the file at 0600" -> TestProductOwnershipFailure
// N/A: tests/unit/config_product.bats: "a failure while re-reading the body refuses instead of writing a truncated file" -- the Go writer never re-reads: the body is built from the one snapshot already in memory (structural)
// PORTED: tests/unit/config_product.bats: "an oversized product conf is refused, and leaves no snapshot behind" -> TestProductOversizedRefused (Go's snapshot is in-memory; "no snapshot file behind" has no on-disk artifact to leak)
// PORTED: tests/unit/config_product.bats: "a retry after rc 5 repairs the mode and the group" -> TestProductOwnershipFailure
// PORTED: tests/unit/config_product.bats: "a no-op merge does not rewrite the file" -> TestProductNoOpKeepsBytesAndInode
// PORTED: tests/unit/config_product.bats: "a chmod failure after the bytes have landed reports rc 5, not rc 1" -> TestProductOwnershipFailure (the rc-5 semantics the row exists for: the bytes ARE committed and the file is left at the 0600 fallback, reported as OwnershipError rather than a plain failure. STATED RESIDUAL — the TRIGGER differs: an unprivileged process cannot make chmod fail on a file it owns after a successful chgrp (the bash shimmed it), so the Go induces the same state through StateGroupFailed)
// PORTED: tests/unit/config_product.bats: "a rewrite keeps the same inode — a bind mount must not be detached" -> TestProductRewriteKeepsInode
// PORTED: tests/unit/config_product.bats: "a value containing a newline is refused and nothing is written" -> TestProductAddRefusals
// PORTED: tests/unit/config_product.bats: "a key outside the product spec is refused on write, leaving no partial file" -> TestProductAddRefusals
// PORTED: tests/unit/config_product.bats: "one bad pair in a batch rejects the whole write — no partial file" -> TestProductAddRefusals
// PORTED: tests/unit/config_product.bats: "the same key given twice in one call is refused" -> TestProductAddRefusals
// N/A: tests/unit/config_product.bats: "an odd number of arguments is refused" -- []KV cannot express an odd pair; the shape is the type
// PORTED: tests/unit/config_product.bats: "a KEYLESS create produces a valid, marker-terminated, 0660 file that loads" -> TestProductEnsureKeylessCreate
// PORTED: tests/unit/config_product.bats: "adding a key preserves comments, ordering and untouched keys" -> TestProductAddPreservesBytes
// PORTED: tests/unit/config_product.bats: "adding a key that already holds a different value is refused" -> TestProductAdditiveGate
// PORTED: tests/unit/config_product.bats: "a marker-prefix line in the body is rejected, not treated as a comment" -> TestScanRefusals
// N/A: tests/unit/config_product.bats: "a call with too few arguments refuses instead of aborting under set -u" -- compile-time arity
// PORTED: tests/unit/config_product.bats: "a set into a torn file is refused rather than re-blessing damage" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "a launch-spec key is not in the product spec, so reading it is a rejection" -> TestProductAddRefusals (spec-driven: an off-spec key rejects on read and write alike)
// PORTED: tests/unit/config_product.bats: "a symlinked product conf is refused on both read and write" -> TestProductSymlinkRefused
// PORTED: tests/unit/config_product.bats: "a product conf hardlinked to mythical.conf is refused" -> TestProductHardlinkRefused
// PORTED: tests/unit/config_product.bats: "a product conf hardlinked to a file under bin/ is refused" -> TestProductHardlinkRefused
// PORTED: tests/unit/config_product.bats: "a product conf owned by another uid is refused on both read and write" -> TestForeignOwnedRefused (identityOK's uid branch, the same code path every identity test exercises; same STATED RESIDUAL — it skips off-root)
// N/A: tests/unit/config_product.bats: "an unreadable owner is refused rather than assumed to be ours" -- the bash parsed `ls` output which could be garbled; os.Lstat's Stat_t either exists or the assertion fails closed (that fail-closed branch is in identityOK and cannot be induced portably)
// PORTED: tests/unit/config_product.bats: "a matching marker reads silently" -> TestProductLoadRoundTrip
// PORTED: tests/unit/config_product.bats: "a stale marker over a parseable body is torn, not accepted" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "a write torn at a line boundary is detected, not silently applied" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "a matching marker over a malformed body is rejected, not reported as torn" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "reading never rewrites the file" -> TestProductLoadRoundTrip
// PORTED: tests/unit/config_product.bats: "a torn file reports rc 4 so the caller uses defaults, and names both remedies" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "a file with no marker at all is torn — a writer that skipped the contract is not trusted" -> TestProductTornAndMalformed
// N/A: tests/unit/config_product.bats: "the torn contract holds under set -euo pipefail" -- shell-option machinery; Go error returns cannot be silently exited past
// PORTED: tests/unit/config_product.bats: "an invalid product name is refused and creates nothing" -> TestProductPathShape
// PORTED: tests/unit/config_product.bats: "valid product names are accepted" -> TestProductPathShape
// N/A: tests/unit/config_product.bats: "mi_conf_product_load refuses bad arity instead of aborting under set -u" -- compile-time arity
// N/A: tests/unit/config_product.bats: "no live-file CONTENT read happens outside the snapshot" -- the bash proved this with a tracing shim over its many readers; the Go load performs exactly one content read (SnapProduct) by construction, and the writer's only live-file reads are the digest CAS and Lstat identity
// PORTED: tests/unit/config_product.bats: "a file that does not end in a newline is torn, not a parse error" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_product.bats: "a failing load still returns its contract code and leaves no snapshot behind" -> TestProductTornAndMalformed (typed errors ARE the contract codes; no on-disk snapshot exists to leak)
// PORTED: tests/unit/config_product.bats: "a missing product conf reports rc 3, distinct from torn" -> TestProductMissingDistinct
// PORTED: tests/unit/config_product.bats: "writing without the family lock is refused" -> TestWritesRequireTheLock
// PORTED: tests/unit/config_product.bats: "a FIFO at the product path is refused, and does not block" -> TestNonRegularRefused
// PORTED: tests/unit/config_product.bats: "a directory at the product path is refused" -> TestNonRegularRefused
//
// Inventory — tests/unit/config_contract.bats (the doc-contract file; several rows exercise
// the bundled bash CLI end-to-end and port as behavior of the same functions):
// PORTED: tests/unit/config_contract.bats: "both documented recipes agree with the CLI, on a multi-line body" -> TestMarkerRecipeAgreesWithDoc
// PORTED: tests/unit/config_contract.bats: "a file built by hand from the document is accepted by the CLI" -> TestMarkerRecipeAgreesWithDoc
// N/A: tests/unit/config_contract.bats: "the command-substitution shortcut the document warns against really does differ" -- a bash-pipeline pitfall (command substitution strips trailing newlines); Go's hashing takes explicit bytes and has no such shortcut to warn against
// PORTED: tests/unit/config_contract.bats: "the marker prefix in the document matches the constant in the code" -> TestMarkerRecipeAgreesWithDoc
// PORTED: tests/unit/config_contract.bats: "the documented value rules match what the parser enforces" -> TestValueMetacharactersRefused
// PORTED: tests/unit/config_contract.bats: "an UPPERCASE marker is rejected even when the digest itself is correct" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_contract.bats: "a marker-only file is valid and loads as an empty configuration" -> TestProductEnsureKeylessCreate
// PORTED: tests/unit/config_contract.bats: "a zero-byte file is torn, not an empty configuration" -> TestProductTornAndMalformed
// PORTED: tests/unit/config_contract.bats: "a <product>.conf of exactly 1048576 bytes is accepted — the ceiling is inclusive" -> TestProductOversizedRefused
// PORTED: tests/unit/config_contract.bats: "a <product>.conf of 1048577 bytes is refused outright, marker or no marker" -> TestProductOversizedRefused
// PORTED: tests/unit/config_contract.bats: "the doc path in the shipped torn-file message resolves to a real file" -> TestTornMessageNamesRealDoc
// PORTED: tests/unit/config_contract.bats: "every row of the document's marker-precedence table matches the CLI" -> TestProductTornAndMalformed (the table's rows: match+parse=accept, absent/mismatch=torn, match+broken=malformed)
// PORTED: tests/unit/config_contract.bats: "the product-name grammar the document publishes is the grammar the CLI enforces" -> internal/layout TestProductNameGrammar

func lockFor(t *testing.T, home string) famlock.Held {
	t.Helper()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	return h
}

func TestFamilyPathShape(t *testing.T) {
	if FamilyPath("/h/.mythical") != "/h/.mythical/mythical.conf" {
		t.Fatal(FamilyPath("/h/.mythical"))
	}
}

func TestFamilyAddCreatesAt0600(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := FamilyAdd(h, "MYTHICAL_NET", "mythical-net"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(FamilyPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != "MYTHICAL_NET=mythical-net\n" {
		t.Fatalf("content %q", b)
	}
}

func TestFamilyAddPreservesBytes(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	orig := "# my comment\n\nMYTHICAL_NET=n1\n# trailing note\n"
	if err := os.WriteFile(FamilyPath(home), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "k1"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(FamilyPath(home))
	if string(b) != orig+"MYTHICAL_TELEMETRY_KEY=k1\n" {
		t.Fatalf("bytes not preserved+appended: %q", b)
	}
}

func TestFamilyAddAdditiveGate(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := FamilyAdd(h, "MYTHICAL_NET", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_NET", "n1"); err != nil {
		t.Fatalf("same-value no-op errored: %v", err)
	}
	before, _ := os.ReadFile(FamilyPath(home))
	err := FamilyAdd(h, "MYTHICAL_NET", "n2")
	if !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("want ErrKeyConflict, got %v", err)
	}
	after, _ := os.ReadFile(FamilyPath(home))
	if string(before) != string(after) {
		t.Fatal("refused write still modified the file")
	}
}

func TestFamilyAddValidation(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	cases := []struct{ key, val string }{
		{"MYTHICAL_NET", "host"},                             // invalid for netname, refused before the additive gate
		{"MYTHICAL_NET", "a\nMYTHICAL_EVIL=x"},               // newline forgery
		{"MYTHICAL_NET", "n$(x)"},                            // shell metacharacter
		{"MYTHICAL_SURPRISE", "x"},                           // outside the core spec (and not bind-shaped)
		{"MYTHICAL_TELEMETRY_KEY", strings.Repeat("x", 600)}, // over str:512
	}
	for _, c := range cases {
		if err := FamilyAdd(h, c.key, c.val); err == nil {
			t.Errorf("FamilyAdd(%q, %.20q...) accepted", c.key, c.val)
		}
	}
	if _, err := os.Lstat(FamilyPath(home)); !os.IsNotExist(err) {
		t.Fatal("a refused write created the file")
	}
	// The bind SHAPE is accepted at this write door.
	if err := FamilyAdd(h, "MYTHICAL_BROKKR_DATA_BIND", "/srv/data"); err != nil {
		t.Fatalf("bind-shaped key refused: %v", err)
	}
}

func TestFamilyAddNeverModifiesUnparseable(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	bad := "MYTHICAL_NET=n1\ngarbage line\n"
	if err := os.WriteFile(FamilyPath(home), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "k"); err == nil {
		t.Fatal("wrote into an unparseable file")
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != bad {
		t.Fatal("unparseable file was modified")
	}
}

func TestFamilyAddCASRefusesConcurrentChange(t *testing.T) {
	// The narrowest seam Go exposes: run the write with a pre-digest that no longer matches
	// (the file "changed under us" between read and replace). unchanged() is the gate.
	home := t.TempDir()
	f := FamilyPath(home)
	if err := os.WriteFile(f, []byte("MYTHICAL_NET=n1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if unchanged(f, "not-the-digest") {
		t.Fatal("unchanged() accepted a mismatched baseline")
	}
	data, _ := os.ReadFile(f)
	if !unchanged(f, cliio.SHA256Hex(data)) {
		t.Fatal("unchanged() refused a true baseline")
	}
}

func TestFamilySymlinkRefused(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, FamilyPath(home)); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_NET", "n1"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink not refused: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep\n" {
		t.Fatal("symlink target adopted")
	}
}

func TestFamilyHardlinkRefused(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	other := filepath.Join(home, "other-name")
	if err := os.WriteFile(other, []byte("MYTHICAL_NET=n1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, FamilyPath(home)); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "k"); err == nil || !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("hardlink not refused: %v", err)
	}
	if b, _ := os.ReadFile(other); string(b) != "MYTHICAL_NET=n1\n" {
		t.Fatal("the other name was touched")
	}
}

func TestNonRegularRefused(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	// A directory at the family path.
	if err := os.Mkdir(FamilyPath(home), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_NET", "n"); err == nil {
		t.Fatal("directory accepted")
	}
	// A FIFO at the product path — refused WITHOUT opening, so this must not block.
	home2 := t.TempDir()
	fifo := filepath.Join(home2, "brokkr.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := LoadProduct(home2, "brokkr", Spec{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO not refused: %v", err)
	}
}

func TestForeignOwnedRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a foreign-owned file; the uid comparison itself is identityOK's, exercised on every identity test")
	}
	home := t.TempDir()
	f := FamilyPath(home)
	if err := os.WriteFile(f, []byte("MYTHICAL_NET=n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(f, 12345, -1); err != nil {
		t.Fatal(err)
	}
	if err := identityOK(f); err == nil {
		t.Fatal("foreign-owned file accepted")
	}
}

func TestWritesRequireTheLock(t *testing.T) {
	if err := FamilyAdd(nil, "MYTHICAL_NET", "n"); err == nil || !strings.Contains(err.Error(), "family lock") {
		t.Fatalf("nil token authorized a family write: %v", err)
	}
	if err := ProductAdd(nil, "brokkr", "20", Spec{}, nil); err == nil {
		t.Fatal("nil token authorized a product write")
	}
	if err := FamilyCAS(nil, "MYTHICAL_BROKKR_DATA_BIND", "/x", "", AttemptNone, nil, nil); err == nil {
		t.Fatal("nil token authorized a CAS")
	}
}

// --- product ------------------------------------------------------------------------------------

func TestProductPathShape(t *testing.T) {
	home := t.TempDir()
	p, err := ProductPath(home, "brokkr")
	if err != nil || p != filepath.Join(home, "brokkr.conf") {
		t.Fatalf("%q, %v", p, err)
	}
	for _, bad := range []string{"mythical", "../evil", "bin/x", "Brokkr", ""} {
		if _, err := ProductPath(home, bad); err == nil {
			t.Errorf("ProductPath(%q) accepted", bad)
		}
	}
	for _, good := range []string{"saga", "skuld", "a-2"} {
		if _, err := ProductPath(home, good); err != nil {
			t.Errorf("ProductPath(%q) refused: %v", good, err)
		}
	}
	// An invalid name creates nothing anywhere.
	h := lockFor(t, home)
	_ = ProductAdd(h, "../evil", "20", Spec{}, nil)
	entries, _ := os.ReadDir(home)
	for _, e := range entries {
		if strings.Contains(e.Name(), "evil") {
			t.Fatal("invalid product name created a file")
		}
	}
}

var testSpec = Spec{"MYTHICAL_BROKKR_PORT": "int:1:65535", "MYTHICAL_BROKKR_NAME": "str:64"}

func gidStr() string { return strconv.Itoa(os.Getgid()) }

func TestProductAddCreatesMarkered(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, "brokkr.conf"))
	if err != nil {
		t.Fatal(err)
	}
	body, sum, ok := splitMarker(data)
	if !ok {
		t.Fatalf("no trailing marker: %q", data)
	}
	// The marker is a checksum of everything above it.
	if cliio.SHA256Hex(body) != sum {
		t.Fatal("marker does not checksum the body")
	}
	if string(body) != "MYTHICAL_BROKKR_PORT=7480\n" {
		t.Fatalf("body %q", body)
	}
}

func TestGetRefusesMarkeredFile(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(filepath.Join(home, "brokkr.conf"), "MYTHICAL_BROKKR_PORT"); err == nil {
		t.Fatal("Get read a marker-bearing file; product confs go through LoadProduct")
	}
}

func TestProductOwnershipApplied(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, nil); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(home, "brokkr.conf"))
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("mode %o, want 0660", st.Mode().Perm())
	}
	sys := st.Sys().(*syscall.Stat_t)
	if int(sys.Gid) != os.Getgid() {
		t.Fatalf("gid %d, want %d", sys.Gid, os.Getgid())
	}
}

func TestProductOwnershipFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown to any group; the failure branch needs an unprivileged run")
	}
	home := t.TempDir()
	h := lockFor(t, home)
	// gid 0: an unprivileged user is not a member, so the group set fails EPERM. Bytes must
	// still be committed (rc 5 semantics), file at 0600.
	err := ProductAdd(h, "brokkr", "0", testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}})
	var oe *OwnershipError
	if !errors.As(err, &oe) || oe.State != StateGroupFailed {
		t.Fatalf("want OwnershipError/StateGroupFailed, got %v", err)
	}
	f := filepath.Join(home, "brokkr.conf")
	st, serr := os.Stat(f)
	if serr != nil {
		t.Fatal("bytes were NOT committed on rc 5")
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want the 0600 fallback", st.Mode().Perm())
	}
	// A retry with a settable group repairs mode+group even though the merge is a no-op.
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatalf("repair retry: %v", err)
	}
	st, _ = os.Stat(f)
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("retry did not repair the mode: %o", st.Mode().Perm())
	}
}

func TestProductOversizedRefused(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, "brokkr.conf")
	// Exactly MaxBytes is ACCEPTED (inclusive ceiling): a marker-terminated file padded with
	// comments to precisely 1048576 bytes.
	marker := MarkerPrefix + cliio.SHA256Hex(nil) + "\n"
	pad := MaxBytes - len(marker)
	content := strings.Repeat("#", pad-1) + "\n" + marker
	if len(content) != MaxBytes {
		t.Fatalf("fixture math: %d", len(content))
	}
	// Body is all-comment, so the marker over the empty... no: the marker must checksum the
	// body (everything above it). Recompute.
	body := strings.Repeat("#", pad-1) + "\n"
	content = body + MarkerPrefix + cliio.SHA256Hex([]byte(body)) + "\n"
	// Trim/regrow to EXACTLY MaxBytes by adjusting the pad for the real digest length (the
	// digest is fixed-width, so one construction suffices).
	over := len(content) - MaxBytes
	if over != 0 {
		body = strings.Repeat("#", pad-1-over) + "\n"
		content = body + MarkerPrefix + cliio.SHA256Hex([]byte(body)) + "\n"
	}
	if len(content) != MaxBytes {
		t.Fatalf("fixture math 2: %d", len(content))
	}
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProduct(home, "brokkr", Spec{}); err != nil {
		t.Fatalf("exactly-at-ceiling refused: %v", err)
	}
	// One byte over refuses outright, marker or no marker.
	if err := os.WriteFile(f, append([]byte(content), '#'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProduct(home, "brokkr", Spec{}); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("over-ceiling accepted: %v", err)
	}
}

func TestProductNoOpKeepsBytesAndInode(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, "brokkr.conf")
	st1, _ := os.Stat(f)
	before, _ := os.ReadFile(f)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(f)
	after, _ := os.ReadFile(f)
	if string(before) != string(after) {
		t.Fatal("no-op changed bytes")
	}
	if st1.Sys().(*syscall.Stat_t).Ino != st2.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("no-op changed the inode")
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("no-op touched the mtime")
	}
}

func TestProductRewriteKeepsInode(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, "brokkr.conf")
	st1, _ := os.Stat(f)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_NAME", "b1"}}); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(f)
	if st1.Sys().(*syscall.Stat_t).Ino != st2.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("a rewrite replaced the inode — the bind mount would detach")
	}
}

func TestProductAddRefusals(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	f := filepath.Join(home, "brokkr.conf")
	cases := [][]KV{
		{{"MYTHICAL_BROKKR_NAME", "a\nMYTHICAL_EVIL=x"}},                                      // newline value
		{{"MYTHICAL_OFFSPEC", "x"}},                                                           // outside the spec
		{{"MYTHICAL_BROKKR_PORT", "7480"}, {"MYTHICAL_BROKKR_PORT", "7481"}},                  // same key twice
		{{"MYTHICAL_BROKKR_PORT", "7480"}, {"MYTHICAL_BROKKR_NAME", strings.Repeat("x", 65)}}, // one bad pair rejects the whole batch
	}
	for i, kvs := range cases {
		if err := ProductAdd(h, "brokkr", gidStr(), testSpec, kvs); err == nil {
			t.Errorf("case %d accepted", i)
		}
		if _, err := os.Lstat(f); !os.IsNotExist(err) {
			t.Fatalf("case %d left a partial file", i)
		}
	}
}

func TestProductEnsureKeylessCreate(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductEnsure(h, "brokkr", gidStr()); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, "brokkr.conf")
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	// Marker-only: the marker over the empty body.
	if string(data) != MarkerPrefix+cliio.SHA256Hex(nil)+"\n" {
		t.Fatalf("keyless create content %q", data)
	}
	st, _ := os.Stat(f)
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	got, err := LoadProduct(home, "brokkr", testSpec)
	if err != nil || len(got) != 0 {
		t.Fatalf("marker-only file must load as an empty configuration: %v, %v", got, err)
	}
	// Ensure on an existing file leaves it exactly as found.
	if err := ProductEnsure(h, "brokkr", gidStr()); err != nil {
		t.Fatal(err)
	}
}

func TestProductAddPreservesBytes(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	body := "# product notes\nMYTHICAL_BROKKR_PORT=7480\n\n# more\n"
	content := body + MarkerPrefix + cliio.SHA256Hex([]byte(body)) + "\n"
	f := filepath.Join(home, "brokkr.conf")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_NAME", "b1"}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f)
	nb, _, _ := splitMarker(data)
	if string(nb) != body+"MYTHICAL_BROKKR_NAME=b1\n" {
		t.Fatalf("comments/order not preserved: %q", nb)
	}
}

func TestProductAdditiveGate(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7999"}})
	if !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("want ErrKeyConflict, got %v", err)
	}
}

func TestProductTornAndMalformed(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	f := filepath.Join(home, "brokkr.conf")
	body := "MYTHICAL_BROKKR_PORT=7480\n"
	good := body + MarkerPrefix + cliio.SHA256Hex([]byte(body)) + "\n"

	cases := []struct {
		name    string
		content string
		torn    bool
	}{
		{"stale marker over a parseable body", body + MarkerPrefix + cliio.SHA256Hex([]byte("other\n")) + "\n", true},
		{"no marker at all", body, true},
		{"zero-byte file", "", true},
		{"no trailing newline (cut at line boundary...)", strings.TrimSuffix(good, "\n"), true},
		{"UPPERCASE marker with correct digest", body + strings.ToUpper(MarkerPrefix) + cliio.SHA256Hex([]byte(body)) + "\n", true},
		{"matching marker over a malformed body", "garbage line\n" + MarkerPrefix + cliio.SHA256Hex([]byte("garbage line\n")) + "\n", false},
	}
	for _, c := range cases {
		if err := os.WriteFile(f, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadProduct(home, "brokkr", testSpec)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := errors.Is(err, ErrTorn); got != c.torn {
			t.Errorf("%s: torn=%v, want %v (%v)", c.name, got, c.torn, err)
		}
		// A write into the same state is refused too — never re-bless damage. (For the
		// malformed case it refuses as unloadable, not torn.)
		if werr := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_NAME", "x"}}); werr == nil {
			t.Errorf("%s: write accepted", c.name)
		}
		if b, _ := os.ReadFile(f); string(b) != c.content {
			t.Errorf("%s: refused write modified the file", c.name)
		}
	}
	// And the good file loads silently — the precedence table's accept row.
	if err := os.WriteFile(f, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProduct(home, "brokkr", testSpec)
	if err != nil || got["MYTHICAL_BROKKR_PORT"] != "7480" {
		t.Fatalf("clean load: %v, %v", got, err)
	}
}

func TestProductLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, []KV{{"MYTHICAL_BROKKR_PORT", "7480"}}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(home, "brokkr.conf")
	before, _ := os.ReadFile(f)
	st1, _ := os.Stat(f)
	got, err := LoadProduct(home, "brokkr", testSpec)
	if err != nil || got["MYTHICAL_BROKKR_PORT"] != "7480" {
		t.Fatalf("%v, %v", got, err)
	}
	// Reading never rewrites: bytes and mtime identical after the read.
	after, _ := os.ReadFile(f)
	st2, _ := os.Stat(f)
	if string(before) != string(after) || !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("a read mutated the file")
	}
}

func TestProductMissingDistinct(t *testing.T) {
	_, err := LoadProduct(t.TempDir(), "brokkr", testSpec)
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("want ErrMissing, got %v", err)
	}
	if errors.Is(err, ErrTorn) {
		t.Fatal("missing conflated with torn")
	}
}

func TestProductSymlinkRefused(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(home, "brokkr.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProduct(home, "brokkr", testSpec); err == nil {
		t.Fatal("read followed a symlink")
	}
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, nil); err == nil {
		t.Fatal("write followed a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("symlink target touched")
	}
}

func TestProductHardlinkRefused(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	// Hardlinked to mythical.conf — the exact escalation the check exists for.
	fam := FamilyPath(home)
	if err := os.WriteFile(fam, []byte("MYTHICAL_NET=n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fam, filepath.Join(home, "brokkr.conf")); err != nil {
		t.Fatal(err)
	}
	if err := ProductAdd(h, "brokkr", gidStr(), testSpec, nil); err == nil {
		t.Fatal("hardlink to mythical.conf accepted")
	}
	if b, _ := os.ReadFile(fam); string(b) != "MYTHICAL_NET=n\n" {
		t.Fatal("mythical.conf rewritten through the link")
	}
	// Hardlinked to a file under bin/.
	home2 := t.TempDir()
	h2 := lockFor(t, home2)
	if err := os.MkdirAll(filepath.Join(home2, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(home2, "bin", "mythical-ctl")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(cli, filepath.Join(home2, "saga.conf")); err != nil {
		t.Fatal(err)
	}
	if err := ProductAdd(h2, "saga", gidStr(), Spec{}, nil); err == nil {
		t.Fatal("hardlink to bin/ accepted")
	}
}

// --- contract -----------------------------------------------------------------------------------

func TestMarkerRecipeAgreesWithDoc(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "CONFIG-FORMAT.md"))
	if err != nil {
		t.Fatal(err)
	}
	// The prefix constant in the code is the one the document publishes.
	if !strings.Contains(string(doc), MarkerPrefix) {
		t.Fatalf("docs/CONFIG-FORMAT.md no longer spells the marker prefix %q", MarkerPrefix)
	}
	// A file built by hand per the document — body, then prefix+sha256(body) — is accepted,
	// on a multi-line body.
	home := t.TempDir()
	body := "# hand-built\nMYTHICAL_BROKKR_PORT=7480\nMYTHICAL_BROKKR_NAME=b1\n"
	content := body + MarkerPrefix + cliio.SHA256Hex([]byte(body)) + "\n"
	if err := os.WriteFile(filepath.Join(home, "brokkr.conf"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProduct(home, "brokkr", testSpec)
	if err != nil || got["MYTHICAL_BROKKR_NAME"] != "b1" {
		t.Fatalf("hand-built file refused: %v, %v", got, err)
	}
}

func TestTornMessageNamesRealDoc(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, "brokkr.conf")
	if err := os.WriteFile(f, []byte("MYTHICAL_BROKKR_PORT=7480\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProduct(home, "brokkr", testSpec)
	if err == nil {
		t.Fatal("markerless accepted")
	}
	// The remedy names docs/CONFIG-FORMAT.md, and that path resolves to a real file.
	if !strings.Contains(err.Error(), "docs/CONFIG-FORMAT.md") {
		t.Fatalf("torn message names no doc: %v", err)
	}
	if _, serr := os.Stat(filepath.Join("..", "..", "docs", "CONFIG-FORMAT.md")); serr != nil {
		t.Fatal("the doc the message names does not exist")
	}
}

// FamilyCAS's attempt table, pinned directly (its bats coverage arrives with migrate-storage,
// whose inventory will point here): none writes over the expected prior or over absence;
// started advances on our value, refuses otherwise without explicit confirmation — absent
// after a started attempt is EQUALLY a crash and a hand delete, and guessing overwrites the
// edit the additive-only rule promises to keep.
func TestFamilyCASAttemptTable(t *testing.T) {
	key := "MYTHICAL_BROKKR_DATA_BIND"
	setup := func(content string) (famlock.Held, string) {
		home := t.TempDir()
		h := lockFor(t, home)
		if content != "" {
			if err := os.WriteFile(FamilyPath(home), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return h, home
	}

	// none + absent + prior "" => write.
	h, home := setup("")
	if err := FamilyCAS(h, key, "/new", "", AttemptNone, nil, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != key+"=/new\n" {
		t.Fatalf("%q", b)
	}

	// none + holds prior => write, preserving other lines.
	h, home = setup("# note\n" + key + "=/old\nMYTHICAL_NET=n\n")
	if err := FamilyCAS(h, key, "/new", "/old", AttemptNone, nil, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != "# note\n"+key+"=/new\nMYTHICAL_NET=n\n" {
		t.Fatalf("%q", b)
	}

	// none + holds something else => refuse untouched.
	h, home = setup(key + "=/theirs\n")
	if err := FamilyCAS(h, key, "/new", "/old", AttemptNone, nil, nil); err == nil {
		t.Fatal("mismatched prior accepted")
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != key+"=/theirs\n" {
		t.Fatal("refused CAS modified the file")
	}

	// started + holds our value => advance without rewriting.
	h, home = setup(key + "=/new\n")
	st1, _ := os.Stat(FamilyPath(home))
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, nil, nil); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(FamilyPath(home))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("advance rewrote the file")
	}

	// started + absent => refuse without confirmation; write only WITH it.
	h, home = setup("MYTHICAL_NET=n\n")
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, func(string) bool { return false }, nil); err == nil {
		t.Fatal("started+absent wrote without consent")
	}
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, func(string) bool { return true }, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != "MYTHICAL_NET=n\n"+key+"=/new\n" {
		t.Fatalf("%q", b)
	}

	// The door is bind-shaped only: a core key is refused outright.
	h, _ = setup("")
	if err := FamilyCAS(h, "MYTHICAL_NET", "n2", "n1", AttemptNone, nil, nil); err == nil {
		t.Fatal("CAS accepted a core key")
	}
}

// TestFamilyCASNarratesWhatItDid pins the three lines this door says out loud.
//
// THEY ARE NOT COSMETIC. This compare-and-set is DELIBERATELY not atomic against a human editor —
// the operation lock has no authority over a text editor — and the reference accepts that window on
// three stated grounds, the third being that "the command REPORTS the value it wrote, so a lost
// edit is visible immediately". A silent version keeps the window and drops the mitigation. It
// drops it hardest exactly when it matters: a migration that fails at a LATER phase never prints
// its own success narrative, so without this line the operator sees an error and nothing anywhere
// saying mythical.conf had already been rewritten.
//
// The prompt is pinned for the same reason on the other side of the door: the explanation used to
// live only in the error returned when the operator DECLINED, which reaches nobody who says yes —
// and the person who says yes is the one about to discard what may be their own hand edit.
func TestFamilyCASNarratesWhatItDid(t *testing.T) {
	const key = "MYTHICAL_BROKKR_STATE_BIND"
	setup := func(content string) (famlock.Held, string) {
		t.Helper()
		home := t.TempDir()
		h := lockFor(t, home)
		if content != "" {
			if err := os.WriteFile(FamilyPath(home), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return h, home
	}
	var notes []string
	note := func(s string) { notes = append(notes, s) }

	// A write REPORTS the value it wrote, and names the file it wrote it in.
	h, home := setup("")
	notes = nil
	if err := FamilyCAS(h, key, "/new", "", AttemptNone, nil, note); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"set " + key + "=/new", FamilyPath(home), "the one setting migrate-storage may change"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the write said %q, which does not carry %q", joined, want)
		}
	}

	// A REFUSED write says nothing: a report of a value that was not written is worse than silence.
	h, _ = setup(key + "=/theirs\n")
	notes = nil
	if err := FamilyCAS(h, key, "/new", "/old", AttemptNone, nil, note); err == nil {
		t.Fatal("mismatched prior accepted")
	}
	if len(notes) != 0 {
		t.Fatalf("a refused CAS reported a write: %q", notes)
	}

	// The no-op advance says so, rather than looking like a write that did not happen.
	h, _ = setup(key + "=/new\n")
	notes = nil
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, nil, note); err != nil {
		t.Fatal(err)
	}
	if j := strings.Join(notes, "\n"); !strings.Contains(j, "already holds the migrated destination") {
		t.Fatalf("the advance said %q", j)
	}

	// The PROMPT the operator answers carries the whole explanation — including the value actually
	// found, which is the thing they are being asked to discard.
	h, _ = setup(key + "=/somebody-elses-edit\n")
	var asked string
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, func(p string) bool { asked = p; return false }, note); err == nil {
		t.Fatal("started+different wrote without consent")
	}
	for _, want := range []string{
		"recorded as IN PROGRESS",
		"/somebody-elses-edit",
		"deleted or changed the line by hand",
		"additive-only rule promises to keep",
		"write " + key + "=/new, discarding what is there?",
	} {
		if !strings.Contains(asked, want) {
			t.Fatalf("the confirmation prompt does not carry %q — the operator consents uninformed:\n%s", want, asked)
		}
	}

	// ...and when the key is ABSENT the prompt says so in words, rather than showing an empty line.
	h, _ = setup("MYTHICAL_NET=n\n")
	asked = ""
	if err := FamilyCAS(h, key, "/new", "/old", AttemptStarted, func(p string) bool { asked = p; return false }, note); err == nil {
		t.Fatal("started+absent wrote without consent")
	}
	if !strings.Contains(asked, "<nothing>") {
		t.Fatalf("an absent key rendered as blank in the prompt:\n%s", asked)
	}

	// A WRITE THAT FAILED AT THE LAST STEP MUST NOT REPORT SUCCESS. This is the report's worst
	// possible lie: the operator is told mythical.conf now names the destination when the rename
	// never happened, and every later decision — theirs and the migration's — is made against a
	// file that says something else. The refusal above covers the paths that return early; this
	// covers the one that gets all the way to the replace and loses.
	h, home = setup("")
	if os.Getuid() == 0 {
		t.Log("running as root: an unwritable directory does not stop the write, so this case is skipped")
	} else {
		dir := filepath.Dir(FamilyPath(home))
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		notes = nil
		if err := FamilyCAS(h, key, "/new", "", AttemptNone, nil, note); err == nil {
			t.Fatal("a write into an unwritable directory reported success")
		}
		if len(notes) != 0 {
			t.Fatalf("a write that never landed was reported as done: %q", notes)
		}
	}

	// A nil note is a caller with nowhere to write, not a crash.
	h, _ = setup("")
	if err := FamilyCAS(h, key, "/new", "", AttemptNone, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// Through-FamilyAdd concurrency: the reader seam hands back a STALE snapshot while the disk
// holds newer bytes — both the same-value no-op and the append must refuse with
// ErrCASMismatch rather than reporting success (or overwriting) from bytes that are no longer
// the file.
func TestFamilyAddThroughCASRefusal(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	f := FamilyPath(home)
	stale := []byte("MYTHICAL_NET=n1\n")
	fresh := []byte("MYTHICAL_NET=n1\n# operator note landed here\n")
	if err := os.WriteFile(f, fresh, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := osReadFile
	osReadFile = func(path string) ([]byte, error) {
		if path == f {
			return stale, nil // the writer's one read sees yesterday's bytes
		}
		return orig(path)
	}
	t.Cleanup(func() { osReadFile = orig })

	// Same-value no-op: must NOT report success from the stale snapshot.
	if err := FamilyAdd(h, "MYTHICAL_NET", "n1"); !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("stale same-value no-op: %v", err)
	}
	// Append: must refuse rather than overwrite the operator's landed note.
	if err := FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "k"); !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("stale append: %v", err)
	}
	if b, _ := os.ReadFile(f); string(b) != string(fresh) {
		t.Fatal("a stale writer modified the fresh file")
	}
}

// Round-2 wave-gate pins: the full-load gate (an off-schema family file is never modified),
// and the all-digits gid rule (a "-1" gid must refuse, not silently skip the group set).
func TestFamilyAddRefusesOffSchemaFile(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	off := "MYTHICAL_UNKNOWN=x\n"
	if err := os.WriteFile(FamilyPath(home), []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FamilyAdd(h, "MYTHICAL_NET", "n1"); err == nil {
		t.Fatal("appended beside an off-schema key")
	}
	if b, _ := os.ReadFile(FamilyPath(home)); string(b) != off {
		t.Fatal("off-schema file modified")
	}
}

func TestProductAddRefusesNegativeGid(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	if err := ProductAdd(h, "brokkr", "-1", testSpec, nil); err == nil {
		t.Fatal("gid -1 accepted — os.Chown(-1) would silently skip the group set")
	}
	if _, err := os.Lstat(filepath.Join(home, "brokkr.conf")); !os.IsNotExist(err) {
		t.Fatal("refused gid still created a file")
	}
}

func TestProductAddRefusesChownSentinelGid(t *testing.T) {
	home := t.TempDir()
	h := lockFor(t, home)
	for _, gid := range []string{"4294967295", "4294967296", "99999999999999999999"} {
		if err := ProductAdd(h, "brokkr", gid, testSpec, nil); err == nil {
			t.Fatalf("gid %s accepted — chown would silently change nothing", gid)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, "brokkr.conf")); !os.IsNotExist(err) {
		t.Fatal("refused gid still created a file")
	}
}
