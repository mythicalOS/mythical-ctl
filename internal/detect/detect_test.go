package detect

import (
	"errors"
	"strings"
	"testing"
)

// Inventory — tests/unit/detect.bats:
// PORTED: tests/unit/detect.bats: "the three required flat fields are extracted" -> TestFlatFields
// PORTED: tests/unit/detect.bats: "whitespace around the colon is tolerated" -> TestWhitespace
// PORTED: tests/unit/detect.bats: "leading and trailing JSON whitespace (space, tab, CR) outside the root object is accepted" -> TestWhitespace
// PORTED: tests/unit/detect.bats: "non-whitespace content after the root object is still refused" -> TestMalformed
// PORTED: tests/unit/detect.bats: "an absent field reports rc 3, distinct from unreadable" -> TestAbsentVsUnreadable
// PORTED: tests/unit/detect.bats: "a nested field is reported unreadable, never guessed at" -> TestAbsentVsUnreadable
// PORTED: tests/unit/detect.bats: "a value containing an escape is refused rather than mis-decoded" -> TestEscapes
// PORTED: tests/unit/detect.bats: "a non-string value is refused" -> TestAbsentVsUnreadable
// PORTED: tests/unit/detect.bats: "a field name is matched whole, not as a substring" -> TestWholeNameMatch
// PORTED: tests/unit/detect.bats: "a repeated field is refused as ambiguous, not merely refused for some other reason" -> TestRepeats
// PORTED: tests/unit/detect.bats: "only a repeat of the requested field is refused; a repeat of a different top-level key is not inspected" -> TestRepeats
// PORTED: tests/unit/detect.bats: "T3: a raw control byte inside a JSON string cannot forge a field via the TAB-delimited record format" -> TestEscapes
// PORTED: tests/unit/detect.bats: "a key spelled only with an escape is reported absent, never matched by its decoded spelling" -> TestEscapes
// PORTED: tests/unit/detect.bats: "an escaped-spelling key never masks or collides with the literal key of the same name" -> TestEscapes
// PORTED: tests/unit/detect.bats: "malformed JSON is refused, including bad member sequencing" -> TestMalformed
// PORTED: tests/unit/detect.bats: "malformed literals, delimiters and escapes are refused" -> TestMalformed
// PORTED: tests/unit/detect.bats: "valid literals, numbers and escapes still read" -> TestValidShapes
// PORTED: tests/unit/detect.bats: "a raw LF inside a bare literal is refused, matching the same bytes refused on one line" -> TestMalformed
// PORTED: tests/unit/detect.bats: "a pretty-printed response ending each member, including bare literals, on its own line still reads" -> TestValidShapes
// PORTED: tests/unit/detect.bats: "well-formed responses with every value kind still read" -> TestValidShapes
// PORTED: tests/unit/detect.bats: "a response over the byte cap is refused before parsing, and the message names the cap" -> TestByteCap
// PORTED: tests/unit/detect.bats: "a response exactly at the byte cap is still read" -> TestByteCap
// PORTED: tests/unit/detect.bats: "version is preferred, and image_version is the fallback" -> TestVersionFallback
// PORTED: tests/unit/detect.bats: "a response with neither version field reports the unknown marker, never a fabricated value" -> TestVersionFallback
// PORTED: tests/unit/detect.bats: "a version is never inherited from a sibling field" -> TestVersionFallback
// PORTED: tests/unit/detect.bats: "an empty version string falls back to the deprecated alias, exactly like an absent one" -> TestVersionFallback
// PORTED: tests/unit/detect.bats: "a present-but-unreadable version is reported unknown and never falls back to the alias" -> TestVersionFallback

const sample = `{"product":"brokkr","version":"0.1.13","ui_url":"http://mythical-brokkr:7480"}`

func TestFlatFields(t *testing.T) {
	for field, want := range map[string]string{
		"product": "brokkr", "version": "0.1.13", "ui_url": "http://mythical-brokkr:7480",
	} {
		got, err := Field([]byte(sample), field)
		if err != nil || got != want {
			t.Fatalf("%s: %q %v", field, got, err)
		}
	}
}

func TestWhitespace(t *testing.T) {
	got, err := Field([]byte("  \t\r\n{ \"product\" : \"brokkr\" }\r\n \t"), "product")
	if err != nil || got != "brokkr" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestAbsentVsUnreadable(t *testing.T) {
	if _, err := Field([]byte(sample), "missing"); !errors.Is(err, ErrAbsent) {
		t.Fatalf("absent: %v", err)
	}
	// A nested field is unreadable at the top level, never guessed at — and the nested
	// spelling of a requested key must NOT answer.
	nested := `{"components":{"version":"evil"},"product":"x"}`
	if _, err := Field([]byte(nested), "version"); !errors.Is(err, ErrAbsent) {
		t.Fatalf("a nested key answered a top-level lookup: %v", err)
	}
	if _, err := Field([]byte(`{"components":{"a":1}}`), "components"); err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("object value read: %v", err)
	}
	for _, body := range []string{`{"version":123}`, `{"version":null}`, `{"version":true}`} {
		_, err := Field([]byte(body), "version")
		if err == nil || errors.Is(err, ErrAbsent) {
			t.Fatalf("non-string value %s: %v", body, err)
		}
	}
}

func TestEscapes(t *testing.T) {
	// A value with ANY escape refuses rather than mis-decodes.
	if _, err := Field([]byte(`{"version":"1\n2"}`), "version"); err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("escaped value read: %v", err)
	}
	if _, err := Field([]byte(`{"version":"1\u0032"}`), "version"); err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("unicode-escaped value read: %v", err)
	}
	// A key spelled ONLY with an escape is absent — never matched by decoding: \u0069 is 'i',
	// and a decoder would match "vers\u0069on" to "version".
	if _, err := Field([]byte(`{"vers\u0069on":"1.0"}`), "version"); !errors.Is(err, ErrAbsent) {
		t.Fatalf("escaped-spelling key matched: %v", err)
	}
	// And it never masks or collides with the literal key of the same spelling.
	both := `{"vers\u0069on":"evil","version":"good"}`
	got, err := Field([]byte(both), "version")
	if err != nil || got != "good" {
		t.Fatalf("literal key beside escaped spelling: %q %v", got, err)
	}
	// T3: a raw control byte inside a string is malformed — it cannot forge a field through
	// the record stream (the bash's TAB-framed stream was the attack surface; the typed
	// members carry no framing, and the byte still refuses the document).
	raw := []byte(`{"a":"x` + "\t" + `version` + "\t" + `s` + "\t" + `9.9","version":"1.0"}`)
	if _, err := Field(raw, "version"); err == nil {
		t.Fatalf("raw control byte accepted: %v", err)
	}
}

func TestWholeNameMatch(t *testing.T) {
	body := `{"versions":"9.9","aversion":"8.8","version":"1.0"}`
	got, err := Field([]byte(body), "version")
	if err != nil || got != "1.0" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestRepeats(t *testing.T) {
	// The REQUESTED field repeated → ambiguous, refused (not absent, not some other refusal).
	_, err := Field([]byte(`{"version":"1","version":"2"}`), "version")
	if err == nil || errors.Is(err, ErrAbsent) || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("repeat: %v", err)
	}
	// A repeat of a DIFFERENT field does not poison this lookup.
	got, err := Field([]byte(`{"other":"1","other":"2","version":"1.0"}`), "version")
	if err != nil || got != "1.0" {
		t.Fatalf("unrelated repeat: %q %v", got, err)
	}
}

func TestMalformed(t *testing.T) {
	cases := []string{
		`{"a":"unterminated`,
		`{"a":1,}` + `x`,    // trailing garbage
		`{"a":"1"} extra`,   // non-whitespace after the root
		`{"a" "b"}`,         // missing colon
		`{"a":"1" "b":"2"}`, // missing comma (bad member sequencing)
		`{,}`,               // bare comma
		`{"a":[1,2}`,        // mismatched nesting
		`{"a":truthy}`,      // malformed literal
		`{"a":01}`,          // leading-zero number
		`{"a":"\q"}`,        // invalid escape
		"{\"a\":tr\nue}",    // raw LF splitting a bare literal
		`{"a":1`,            // unclosed root
	}
	for _, body := range cases {
		if _, err := Field([]byte(body), "a"); err == nil || errors.Is(err, ErrAbsent) {
			t.Errorf("malformed %q read", body)
		}
	}
}

func TestValidShapes(t *testing.T) {
	// Every value kind beside the requested string still reads; bare literals — pretty-printed
	// on their own lines included — terminate correctly.
	body := "{\n  \"n\": -12.5e3,\n  \"t\": true\n,\n  \"z\": null,\n  \"o\": {\"deep\": [1,2]},\n  \"version\": \"1.0\"\n}\n"
	got, err := Field([]byte(body), "version")
	if err != nil || got != "1.0" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestByteCap(t *testing.T) {
	over := []byte(`{"version":"1.0"}` + strings.Repeat(" ", MaxBytes))
	_, err := Field(over, "version")
	// Refused BEFORE parsing, and the message names BOTH numbers.
	if err == nil || !strings.Contains(err.Error(), "32785") || !strings.Contains(err.Error(), "32768") {
		t.Fatalf("over-cap: %v", err)
	}
	// Exactly AT the cap still reads.
	at := `{"version":"1.0"}`
	at += strings.Repeat(" ", MaxBytes-len(at))
	if len(at) != MaxBytes {
		t.Fatal("fixture math")
	}
	got, err := Field([]byte(at), "version")
	if err != nil || got != "1.0" {
		t.Fatalf("at-cap: %q %v", got, err)
	}
}

func TestVersionFallback(t *testing.T) {
	if v := Version([]byte(sample)); v != "0.1.13" {
		t.Fatalf("%q", v)
	}
	if v := Version([]byte(`{"product":"x","image_version":"9.9"}`)); v != "9.9" {
		t.Fatalf("alias fallback: %q", v)
	}
	if v := Version([]byte(`{"product":"x"}`)); v != Unknown {
		t.Fatalf("neither field: %q", v)
	}
	// Never inherited from a sibling.
	if v := Version([]byte(`{"product":"x","components":{"ui":"1.2.3"}}`)); v != Unknown {
		t.Fatalf("sibling inheritance: %q", v)
	}
	// Empty falls back exactly like absent.
	if v := Version([]byte(`{"product":"x","version":"","image_version":"9.9"}`)); v != "9.9" {
		t.Fatalf("empty-version fallback: %q", v)
	}
	// Present-but-unreadable NEVER falls back.
	if v := Version([]byte(`{"product":"x","version":123,"image_version":"9.9"}`)); v != Unknown {
		t.Fatalf("unreadable version fell back: %q", v)
	}
}
