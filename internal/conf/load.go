package conf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// small seams so tests and scan.go share one read path.
var (
	osReadFile = os.ReadFile
	isNotExist = os.IsNotExist
)

// Spec is a key allowlist with types — a PARAMETER, not a constant, because <product>.conf's
// vocabulary comes from that product's manifest while mythical.conf's core set is fixed here.
// One engine, several vocabularies. (The bash spelled a spec as KEY<TAB>TYPE lines; the map
// carries the same relation.)
type Spec map[string]string

// FamilySpec is the CORE vocabulary of mythical.conf: keys that are product-independent.
// Product-scoped keys (MYTHICAL_<PRODUCT>_PORT and friends) are declared by that product's
// manifest and MERGED IN by the caller that authenticated it — a family LOAD sees the merged
// spec; the bind-key SHAPE is recognised only at the write doors (FamilyAdd, FamilyCAS), never
// by the validator.
func FamilySpec() Spec {
	return Spec{
		"MYTHICAL_NET":           "netname",
		"MYTHICAL_TELEMETRY_KEY": "str:512",
	}
}

// Validate checks scanned records against a spec. An UNKNOWN key is a rejection, never a skip
// (D19): ignoring it would let a compromised container accumulate keys that a later, wider
// spec silently activates. All-or-nothing: a rejected file yields NO records — nothing escapes
// a rejected file, not even a valid prefix.
func Validate(records []KV, label string, spec Spec) (map[string]string, error) {
	out := make(map[string]string, len(records))
	for _, r := range records {
		typ, ok := spec[r.Key]
		if !ok {
			return nil, fmt.Errorf("config: %s: unknown key %s — not permitted by this configuration schema", label, r.Key)
		}
		if !TypeOK(typ, r.Value) {
			return nil, fmt.Errorf("config: %s: value for %s is not valid for type %s", label, r.Key, typ)
		}
		out[r.Key] = r.Value
	}
	return out, nil
}

// FamilyPath is ~/.mythical/mythical.conf.
func FamilyPath(home string) string { return filepath.Join(home, "mythical.conf") }

// LoadFamily scans and validates mythical.conf against the given (usually merged) spec.
// ErrMissing wraps through for an absent file — an absent key in a PRESENT file is not an
// error; defaults are the caller's business.
func LoadFamily(home string, spec Spec) (map[string]string, error) {
	path := FamilyPath(home)
	records, err := ScanFile(path)
	if err != nil {
		return nil, err
	}
	return Validate(records, path, spec)
}

// ErrAbsent reports a key not present in a file that itself parsed cleanly. It is DISTINCT
// from a parse failure by design: "the file is hostile" and "the key is not set" must never
// look the same to a caller deciding whether to write.
var ErrAbsent = errors.New("key is absent")

// Get returns one raw (scanned, not spec-validated) value from a MARKER-LESS file —
// mythical.conf, or a body already separated from its marker. A <product>.conf still carrying
// its marker is rejected by the scanner outright; the way to read a product config is the
// product loader, which strips and validates the marker first.
func Get(path, key string) (string, error) {
	records, err := ScanFile(path)
	if err != nil {
		return "", err
	}
	for _, r := range records {
		if r.Key == key {
			return r.Value, nil
		}
	}
	return "", fmt.Errorf("config: %s: %s: %w", path, key, ErrAbsent)
}
