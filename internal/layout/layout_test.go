package layout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Inventory — tests/unit/layout.bats:
// PORTED: tests/unit/layout.bats: "harness runs and MYTHICAL_HOME is isolated" -> TestHomeResolution
// N/A: tests/unit/layout.bats: "__selftest asserts the whole library surface is present" -- bash bundle-mode artifact; Go links the surface at compile time
// PORTED: tests/unit/layout.bats: "mi_ensure_layout creates the managed subtree, idempotently" -> TestEnsureCreatesManagedSubtreeIdempotently
// PORTED: tests/unit/layout.bats: "mi_ensure_layout never touches transcripts or logs" -> TestEnsureNeverTouchesUserData
// PORTED: tests/unit/layout.bats: "mi_zone classifies paths by ownership class" -> TestZoneClassification
// PORTED: tests/unit/layout.bats: "the host-tool slot is user-owned, at exactly one level under a product directory" -> TestZoneClassification
// PORTED: tests/unit/layout.bats: "a traversal spelling is not the host-tool slot, and neither is a dot-leading directory" -> TestZoneClassification
// PORTED: tests/unit/layout.bats: "the installer's own zones keep the slot's name — the carve-out is only in a product directory" -> TestZoneClassification
// PORTED: tests/unit/layout.bats: "the three product names that CANNOT carry a slot are pinned as a known limit" -> TestReservedDirsCannotCarrySlot
// PORTED: tests/unit/layout.bats: "a component that could not BEGIN a legal product name is not the slot" -> TestZoneClassification
// PORTED: tests/unit/layout.bats: "the slot's uppercase refusal survives a non-C collation, end to end" -> TestSlotCaseExactness -- Go strings have no ambient collation; the refusal is asserted directly
// PORTED: tests/unit/layout.bats: "the slot's leading component must satisfy the FULL product-name grammar, not just its start" -> TestProductNameGrammar
// PORTED: tests/unit/layout.bats: "the reserved leaf is exact even under nocasematch — a case glob would not be" -> TestSlotCaseExactness
// PORTED: tests/unit/layout.bats: "an uppercase product NAME is refused under nocasematch too — the validator is called with it off" -> TestSlotCaseExactness
// N/A: tests/unit/layout.bats: "nocasematch reaching the CLI through BASH_ENV does not promote a path to the slot" -- shell-option machinery; Go comparison is case-exact by construction (asserted in TestSlotCaseExactness)
// N/A: tests/unit/layout.bats: "mi_zone fails CLOSED for the slot when the name authority is not loaded" -- the authority is a compile-time link in Go; it cannot be absent
// N/A: tests/unit/layout.bats: "only a shell FUNCTION may answer the name question — a program on PATH may not" -- Go performs no PATH resolution for the grammar
// PORTED: tests/unit/layout.bats: "the host-tool amendment changed NO pre-existing classification" -> TestZoneClassification -- the pre-amendment table is asserted in full
// PORTED: tests/unit/layout.bats: "the host-tool slot the document publishes is the one the classifier implements" -> TestSlotMatchesPublishedDocument
// PORTED: tests/unit/layout.bats: "mi_ensure_layout neither creates nor disturbs a host-tool slot" -> TestEnsureLeavesSlotAlone
// (layout.bats' mi_digest known-vector row is claimed in internal/cliio/confirm_test.go, its one
// owner. Named rather than quoted: a comment quoting a row verbatim is claim-shaped, and the audit
// reports one the parser cannot read.)
// PORTED: tests/unit/layout.bats: "mi_ensure_layout fails loudly when it cannot create the subtree" -> TestEnsureFailsLoudly

func TestHomeResolution(t *testing.T) {
	h, err := Home([]string{"HOME=/home/op", "MYTHICAL_HOME=/tmp/isolated"})
	if err != nil || h != "/tmp/isolated" {
		t.Fatalf("override: %q, %v", h, err)
	}
	h, err = Home([]string{"HOME=/home/op"})
	if err != nil || h != filepath.Join("/home/op", ".mythical") {
		t.Fatalf("default: %q, %v", h, err)
	}
	if _, err = Home(nil); err == nil {
		t.Fatal("no HOME at all must be an error, not a guess")
	}
}

func TestEnsureCreatesManagedSubtreeIdempotently(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 2; i++ { // twice: idempotency is the claim
		if err := Ensure(home); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	for _, d := range []string{"bin", ".state"} {
		if st, err := os.Stat(filepath.Join(home, d)); err != nil || !st.IsDir() {
			t.Fatalf("%s missing after Ensure: %v", d, err)
		}
	}
}

func TestEnsureNeverTouchesUserData(t *testing.T) {
	// The bats premise, verbatim: an EXISTING transcripts marker survives Ensure untouched.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "transcripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "transcripts", "keep")
	if err := os.WriteFile(marker, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(home); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "secret\n" {
		t.Fatalf("transcripts marker disturbed: %q, %v", b, err)
	}
	// And absent user-data stays absent: Ensure never creates it either.
	home2 := t.TempDir()
	if err := Ensure(home2); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"transcripts", "logs"} {
		if _, err := os.Stat(filepath.Join(home2, d)); !os.IsNotExist(err) {
			t.Fatalf("%s was created; user-data appears when a product binds it, never here", d)
		}
	}
}

func TestEnsureLeavesSlotAlone(t *testing.T) {
	home := t.TempDir()
	slotDir := filepath.Join(home, "brokkr")
	if err := os.MkdirAll(slotDir, 0o755); err != nil {
		t.Fatal(err)
	}
	slot := filepath.Join(slotDir, "cli.toml")
	if err := os.WriteFile(slot, []byte("token = \"secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(home); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(slot)
	if err != nil || string(b) != "token = \"secret\"\n" {
		t.Fatalf("slot disturbed: %q, %v", b, err)
	}
	// And Ensure never CREATES one either.
	home2 := t.TempDir()
	if err := Ensure(home2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home2, "brokkr", "cli.toml")); !os.IsNotExist(err) {
		t.Fatal("Ensure created a host-tool slot")
	}
}

func TestEnsureFailsLoudly(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	err := Ensure(filepath.Join(parent, "home"))
	if err == nil {
		t.Fatal("Ensure on an unwritable parent returned nil")
	}
	if !strings.Contains(err.Error(), "cannot create") {
		t.Fatalf("error %q does not name the failure", err)
	}
}

func TestZoneClassification(t *testing.T) {
	cases := []struct {
		path string
		want Zone
	}{
		{".state/ledger", ZoneInstallerState},
		{".state/lock", ZoneInstallerState},
		{"bin", ZoneInstallerManaged},
		{"bin/mythical-ctl", ZoneInstallerManaged},
		{"transcripts", ZoneUserData},
		{"transcripts/x.jsonl", ZoneUserData}, // the bats path, verbatim
		{"transcripts/2026-08/x.md", ZoneUserData},
		{"logs", ZoneUserData},
		{"logs/sessions/y", ZoneUserData}, // the bats path, verbatim
		{"logs/brokkr.log", ZoneUserData},
		{"mythical.conf", ZoneUserOwned},
		{"brokkr.conf", ZoneUserOwned},
		{"brokkr/compose.yaml", ZoneInstallerManaged},
		{"brokkr/generated.conf", ZoneInstallerManaged},     // nested .conf is NOT user-owned
		{"brokkr/cli.toml", ZoneUserOwned},                  // the host-tool slot
		{"brokkr/generated/cli.toml", ZoneInstallerManaged}, // deeper than one level: not the slot
		{"../cli.toml", ZoneInstallerManaged},               // traversal spelling is not the slot
		{".hidden/cli.toml", ZoneInstallerManaged},          // dot-leading directory is not the slot
		{"9lives/cli.toml", ZoneInstallerManaged},           // cannot BEGIN a legal product name
		{"mythical/cli.toml", ZoneInstallerManaged},         // reserved product name
		{"bin/a/b/c", ZoneInstallerManaged},                 // the pre-amendment depths, verbatim
		{".state/a/b", ZoneInstallerState},
		{"brokkr/a/b/c", ZoneInstallerManaged},
		{"", ZoneUnknown},
		{".state", ZoneUnknown},         // bare .state matches no arm, like bash
		{"something-else", ZoneUnknown}, // the bats path, verbatim
		{"README", ZoneUnknown},
	}
	for _, c := range cases {
		if got := ZoneOf(c.path); got != c.want {
			t.Errorf("ZoneOf(%q) = %s, want %s", c.path, got, c.want)
		}
	}
}

func TestReservedDirsCannotCarrySlot(t *testing.T) {
	// The three product names that CANNOT carry a slot — their arms sit above the slot arm,
	// exactly as documented. The classification they get instead is pinned, not just "not
	// user-owned".
	if got := ZoneOf("bin/cli.toml"); got != ZoneInstallerManaged {
		t.Fatalf("bin/cli.toml = %s", got)
	}
	if got := ZoneOf("logs/cli.toml"); got != ZoneUserData {
		t.Fatalf("logs/cli.toml = %s", got)
	}
	if got := ZoneOf("transcripts/cli.toml"); got != ZoneUserData {
		t.Fatalf("transcripts/cli.toml = %s", got)
	}
}

func TestSlotCaseExactness(t *testing.T) {
	// The leaf is exact: an uppercase spelling is a different file and takes the class the
	// directory gives it.
	if got := ZoneOf("brokkr/CLI.TOML"); got != ZoneInstallerManaged {
		t.Fatalf("brokkr/CLI.TOML = %s", got)
	}
	// An uppercase product NAME is refused by the grammar.
	for _, p := range []string{"Brokkr/cli.toml", "BROKKR/cli.toml"} {
		if got := ZoneOf(p); got != ZoneInstallerManaged {
			t.Fatalf("%s = %s", p, got)
		}
	}
}

func TestProductNameGrammar(t *testing.T) {
	ok := []string{"brokkr", "saga", "skuld", "a", "a-b-2"}
	for _, p := range ok {
		if !ProductNameOK(p) {
			t.Errorf("ProductNameOK(%q) = false", p)
		}
	}
	bad := []string{"", "mythical", "Brokkr", "fooBAR", "foo bar", "9lives", "-x", "a_b",
		strings.Repeat("a", 65)}
	for _, p := range bad {
		if ProductNameOK(p) {
			t.Errorf("ProductNameOK(%q) = true", p)
		}
	}
	// The FULL grammar, not just the start: a legal prefix with an illegal tail refuses,
	// which is the exact overmatch the bash fixed.
	if ProductNameOK("foo!bar") || ZoneOf("foo!bar/cli.toml") == ZoneUserOwned {
		t.Fatal("illegal tail accepted")
	}
}

// The published document and the classifier must agree on the slot. The doc is the contract
// product authors read; if it and ZoneOf drift, one of them is lying to someone.
func TestSlotMatchesPublishedDocument(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "CONFIG-FORMAT.md"))
	if err != nil {
		t.Fatalf("cannot read the published contract: %v", err)
	}
	if !strings.Contains(string(doc), "~/.mythical/<product>/cli.toml") {
		t.Fatal("docs/CONFIG-FORMAT.md no longer publishes the slot's exact path spelling")
	}
	if ZoneOf("brokkr/cli.toml") != ZoneUserOwned {
		t.Fatal("the classifier does not implement the published slot")
	}
}
