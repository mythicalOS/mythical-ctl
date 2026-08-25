// Package docfmt is the authenticated-document format (D8/D21): family index, per-product
// manifests, family policy index. One grammar, three types, distinguished by a mandatory
// header line.
//
// These documents are MORE privileged than <product>.conf, not less — a manifest names the
// image to run, the mounts to make and the secrets to inject (§8.1). Every rule D19 places on
// the product config binds here: never evaluated or expanded; byte-gated before any field is
// handed on; keys allowlisted; values typed.
//
// There is deliberately NO path-taking parse: Snapshot is a bounded read and NOTHING else, and
// the caller that authenticates (the trust acceptors) snapshots once, verifies the digest over
// those bytes, and Parses the same bytes — the anti-TOCTOU order is snapshot → digest →
// byte/grammar/schema inspection, so content validation never precedes authentication.
package docfmt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"mythicalos.ai/ctl/internal/conf"
)

// Format is the one document format version this build understands.
const Format = "1"

// MaxKeys caps a document's keys, enforced DURING the scan — the cost it bounds is incurred
// while accumulating. Matches the config cap, for the same reason.
const MaxKeys = 1024

// ErrMissingDoc — the file is absent (the rc-3 analogue), distinct from every refusal.
var ErrMissingDoc = errors.New("document is missing")

// Card is the spec cardinality vocabulary, whole: one (required, at most once), opt (at most
// once), many (any number, order preserved). Requiredness is DERIVED from One — never a
// second, separately-maintained list.
type Card int

const (
	One Card = iota
	Opt
	Many
)

// KeySpec types one key. Validate is the value rule; a nil Validate is a schema bug Parse
// refuses loudly (a rule that validates nothing must not look like one that does).
type KeySpec struct {
	Card     Card
	Validate func(string) bool
}

// Schema is one document type's contract. Fixed is the ENUMERABLE key set — required keys can
// only live here; Dynamic (optional) resolves scope-sensitive keys a map cannot express (the
// policy index's product-prefixed entitlements) and may return only Opt/Many specs — a One
// from Dynamic is unverifiable by construction and Parse rejects it at first use.
type Schema struct {
	Type    string
	Fixed   map[string]KeySpec
	Dynamic func(key string) (KeySpec, bool)
}

// check validates the SCHEMA ITSELF before it judges any document (the bash's _mi_doc_spec_ok,
// amendment A8): schemas are built by this repository's own code, so a malformed one is a
// programming error — but the failure modes are silent and two of them degrade security (a
// required key quietly becoming optional is the indefinite-replay hole §8.1 closes).
func (s Schema) check() error {
	if s.Type == "" {
		return errors.New("docfmt: internal error — a schema with no document type")
	}
	if len(s.Fixed) == 0 && s.Dynamic == nil {
		return errors.New("docfmt: internal error — a schema with no keys at all")
	}
	for k, ks := range s.Fixed {
		if !KeyOK(k) {
			return fmt.Errorf("docfmt: internal error — schema key %q is not a legal document key", k)
		}
		if ks.Validate == nil {
			return fmt.Errorf("docfmt: internal error — schema key %q has no value rule", k)
		}
		if ks.Card != One && ks.Card != Opt && ks.Card != Many {
			// An out-of-vocabulary cardinality silently reads as optional-at-most-once — the
			// exact required-key relaxation this self-check exists to prevent.
			return fmt.Errorf("docfmt: internal error — schema key %q has an unknown cardinality", k)
		}
	}
	return nil
}

// KeyOK: lowercase, with an optional SINGLE dotted prefix (`brokkr.permitted_role`) so the
// policy index can scope entries by product without nesting. Exactly one dot — `a.b.c` would
// imply a hierarchy this format does not have. Both halves: [a-z][a-z0-9_]*, whole ≤128.
func KeyOK(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	head, rest, dotted := strings.Cut(k, ".")
	if dotted {
		if strings.Contains(rest, ".") {
			return false
		}
		return bareKeyOK(head) && bareKeyOK(rest)
	}
	return bareKeyOK(k)
}

func bareKeyOK(k string) bool {
	if k == "" || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for i := 1; i < len(k); i++ {
		b := k[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return true
}

// Snapshot is exactly ONE bounded read (conf.MaxBytes+1 over-ceiling proof) and nothing else —
// no byte gate, no grammar: the normative order runs digest verification BETWEEN this read and
// Parse, and content validation must not precede authentication. ErrMissingDoc wraps absence.
func Snapshot(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("doc: %s: %w", path, ErrMissingDoc)
		}
		return nil, fmt.Errorf("doc: cannot read %s — refusing to parse it: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, conf.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("doc: cannot read %s — refusing to parse it: %w", path, err)
	}
	if len(data) > conf.MaxBytes {
		return nil, fmt.Errorf("doc: %s is larger than %d bytes — refusing to read it", path, conf.MaxBytes)
	}
	return data, nil
}

// Doc is a parsed, validated, IMMUTABLE document: ordered key/value pairs, repeats preserved
// (cardinality already enforced).
type Doc struct {
	pairs []pair
}

type pair struct{ key, value string }

// Parse runs every gate over one in-hand byte slice: the byte-class rule (conf.DataBytesOK —
// the ONE audited implementation), the trailing newline, the line grammar, the key grammar and
// value rules, the key-count cap, the header (checked AFTER the body is scanned but BEFORE
// anything is returned, so a wrong-type document never yields a field to a caller that forgot
// to check), then the schema: unknown key rejects the whole document, one/opt at most once,
// every Fixed One key present. All-or-nothing; label names the source in diagnostics.
func Parse(data []byte, label string, s Schema) (*Doc, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if conf.DataBytesOK(data) != nil {
		return nil, fmt.Errorf("doc: %s contains control bytes (NUL, CR, TAB or similar) — refusing to parse it", label)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("doc: %s is empty — not a mythical-%s document", label, s.Type)
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("doc: %s does not end in a newline (truncated?) — refusing to parse it", label)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")

	// Body first, header verdict afterwards — but nothing is RETURNED before both pass.
	var pairs []pair
	keys := 0
	for i, line := range lines[1:] {
		n := i + 2
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("doc: %s line %d: not a key=value assignment", label, n)
		}
		if !KeyOK(key) {
			return nil, fmt.Errorf("doc: %s line %d: invalid key name", label, n)
		}
		if !conf.ValueOK(val) {
			return nil, fmt.Errorf("doc: %s line %d: value for %s contains a forbidden character or is too long", label, n, key)
		}
		keys++
		if keys > MaxKeys {
			return nil, fmt.Errorf("doc: %s line %d: more than %d keys — refusing to parse it", label, n, MaxKeys)
		}
		pairs = append(pairs, pair{key, val})
	}

	header := lines[0]
	want := "mythical-" + s.Type + " " + Format
	if header != want {
		if v, ok := strings.CutPrefix(header, "mythical-"+s.Type+" "); ok {
			return nil, fmt.Errorf("doc: %s declares format version %q, and this mythical-ctl understands %s", label, v, Format)
		}
		return nil, fmt.Errorf("doc: %s is not a mythical-%s document (its first line is not the expected header)", label, s.Type)
	}

	// The schema pass: unknown rejects, types check, cardinality holds.
	seen := map[string]int{}
	for _, p := range pairs {
		ks, ok := s.Fixed[p.key]
		if !ok && s.Dynamic != nil {
			ks, ok = s.Dynamic(p.key)
			if ok && ks.Card == One {
				return nil, fmt.Errorf("docfmt: internal error — dynamic key %q resolved as required, which is unverifiable by construction", p.key)
			}
		}
		if !ok {
			return nil, fmt.Errorf("doc: %s: unknown key %s — not permitted by this document's schema", label, p.key)
		}
		if ks.Validate == nil || !ks.Validate(p.value) {
			return nil, fmt.Errorf("doc: %s: value for %s is not valid", label, p.key)
		}
		seen[p.key]++
		if ks.Card != Many && seen[p.key] > 1 {
			return nil, fmt.Errorf("doc: %s: %s may appear at most once", label, p.key)
		}
	}
	for k, ks := range s.Fixed {
		if ks.Card == One && seen[k] == 0 {
			return nil, fmt.Errorf("doc: %s: required key %s is missing", label, k)
		}
	}
	return &Doc{pairs: pairs}, nil
}

// Keys returns the document's keys in first-appearance order, each once — the enumeration
// surface consumers with prefix-scoped keys (the policy index) walk.
func (d *Doc) Keys() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range d.pairs {
		if !seen[p.key] {
			seen[p.key] = true
			out = append(out, p.key)
		}
	}
	return out
}

// Value returns the FIRST value for key.
func (d *Doc) Value(key string) (string, bool) {
	for _, p := range d.pairs {
		if p.key == key {
			return p.value, true
		}
	}
	return "", false
}

// Values returns every value for key, in document order.
func (d *Doc) Values(key string) []string {
	var out []string
	for _, p := range d.pairs {
		if p.key == key {
			out = append(out, p.value)
		}
	}
	return out
}

// Version returns the document's own `version` value.
func (d *Doc) Version() (string, bool) { return d.Value("version") }

// HasExpiry reports whether the document carries an `expires` key at all — the trust gate
// requires one (absence would replay forever), and the schemas already do; this is the
// belt for a docid whose schema ever relaxed it.
func (d *Doc) HasExpiry() bool { _, ok := d.Value("expires"); return ok }

// Expired: inclusive of the stated instant — a document expiring at T is valid AT T and
// invalid after it (stated because "expires" reads either way, and the two differ by one
// second at exactly the moment someone is debugging). No expiry ⇒ never expires. An
// unreadable expiry or clock is an error, never a guess.
func (d *Doc) Expired(nowUnix int64) (bool, error) {
	exp, ok := d.Value("expires")
	if !ok {
		return false, nil
	}
	if !TypeOK("epoch", exp) {
		return false, fmt.Errorf("doc: expiry %q is not readable", exp)
	}
	if nowUnix < 0 {
		return false, errors.New("doc: the clock is not readable")
	}
	// Digit-string compare against the bounded epoch — both ≤18 digits, so int64 is exact.
	var e int64
	for i := 0; i < len(exp); i++ {
		e = e*10 + int64(exp[i]-'0')
	}
	return nowUnix > e, nil
}
