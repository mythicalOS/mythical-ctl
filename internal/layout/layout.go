// Package layout is the ~/.mythical/ family home (D1) and its ownership zones (§6c).
// Non-destructive (D9): the layout helper creates only what is missing and never touches
// user data.
package layout

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Home resolves the family home: MYTHICAL_HOME when set, else $HOME/.mythical. env is the
// process environment (os.Environ() shape) — a parameter, not a global read, so tests isolate
// without touching the process.
func Home(env []string) (string, error) {
	var home string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "MYTHICAL_HOME="); ok && v != "" {
			return v, nil
		}
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	if home == "" {
		return "", fmt.Errorf("layout: neither MYTHICAL_HOME nor HOME is set")
	}
	return filepath.Join(home, ".mythical"), nil
}

// Ensure creates only what is missing under home — bin/ and .state/ — and touches nothing
// else. transcripts/ and logs/ are user-data (MYTHICAL_HOME's original meaning): never created
// here, never removed here; they appear when a product binds them. Idempotent; fails loudly
// when a directory cannot be made.
func Ensure(home string) error {
	for _, d := range []string{"bin", ".state"} {
		p := filepath.Join(home, d)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("layout: cannot create %s: %w", p, err)
		}
	}
	return nil
}

// ProductNameOK is the product-name grammar, and this is its ONE authority in the Go tree —
// the bash kept it in the config module and had the layout call it so two versions could not
// drift; Go inverts the import direction (conf imports layout) but keeps the single
// implementation. Non-empty, at most 64 bytes, first byte [a-z], rest [a-z0-9-]; `mythical`
// is RESERVED — it would collide with the host-only mythical.conf.
func ProductNameOK(p string) bool {
	if p == "" || len(p) > 64 || p == "mythical" {
		return false
	}
	if p[0] < 'a' || p[0] > 'z' {
		return false
	}
	for i := 1; i < len(p); i++ {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
