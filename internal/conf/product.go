package conf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// ErrTorn: an existing <product>.conf whose integrity marker is absent, mismatched, or whose
// final line was cut — the last write was interrupted (or a hand edit skipped the recompute).
// The caller uses defaults; the report names BOTH causes because the operator cannot tell them
// apart from the file alone. The marker DETECTS TEARING; it does not authenticate content —
// the container writes both body and marker, so the parser remains the security control (D19)
// and the marker is a crash detector. Strictly: a torn file is rc-4 territory even when its
// body would parse — an in-place write torn at a line boundary parses perfectly and is missing
// every setting after the cut, and accepting it would silently revert settings to defaults.
var ErrTorn = errors.New("does not match its integrity marker — torn write or un-recomputed hand edit")

// OwnershipError: the bytes ARE committed and the marker is valid, but the file does not carry
// the published ownership spec (owner=operator, family group, 0660). Three distinct states —
// a caller relaying one message for all three would print a false diagnosis:
//
//	StateGroupFailed:  the family group could not be set; mode forced to 0600 (the product's
//	                   own settings screen cannot write the file until the group is fixed)
//	StateModeFailed:   the group IS set; only the 0660 mode is not
//	StateBothFailed:   neither the group nor the 0600 fallback applied — inspect by hand
type OwnershipError struct {
	State OwnershipState
	Path  string
	GID   int
}

type OwnershipState int

const (
	StateGroupFailed OwnershipState = iota
	StateModeFailed
	StateBothFailed
)

func (e *OwnershipError) Error() string {
	switch e.State {
	case StateModeFailed:
		return fmt.Sprintf("config: wrote %s and set the family group %d, but could not set mode 0660 — the group IS set, only the mode is not", e.Path, e.GID)
	case StateBothFailed:
		return fmt.Sprintf("config: wrote %s, but could not set the family group %d OR mode 0600 — check its mode by hand before relying on it", e.Path, e.GID)
	}
	return fmt.Sprintf("config: wrote %s, but could not set the family group %d — it is mode 0600 and the product's settings screen will be READ-ONLY until the group is set", e.Path, e.GID)
}

// ProductPath validates the product name (it becomes a PATHNAME — unchecked, `mythical`
// resolves to the host-only file and `../outside` leaves the namespace) and returns
// <home>/<product>.conf.
func ProductPath(home, product string) (string, error) {
	if !ProductNameOK(product) {
		return "", fmt.Errorf("config: %q is not a valid product name (lowercase letters, digits and hyphens; 'mythical' is reserved)", product)
	}
	return filepath.Join(home, product+".conf"), nil
}

// splitMarker returns (body, sum) when data's LAST line is a marker line, or ok=false.
func splitMarker(data []byte) (body []byte, sum string, ok bool) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, "", false
	}
	idx := bytes.LastIndexByte(data[:len(data)-1], '\n')
	last := string(data[idx+1 : len(data)-1])
	rest, found := strings.CutPrefix(last, MarkerPrefix)
	if !found {
		return nil, "", false
	}
	return data[:idx+1], rest, true
}

// loadSnapshot runs every gate over ONE set of bytes: byte class, trailing newline, the
// marker (strict, first), then the scan and the spec. All-or-nothing.
func loadSnapshot(snap []byte, label string, spec Spec) (map[string]string, error) {
	if DataBytesOK(snap) != nil {
		return nil, fmt.Errorf("config: %s %w — refusing to parse it", label, ErrControlBytes)
	}
	if len(snap) > 0 && snap[len(snap)-1] != '\n' {
		return nil, fmt.Errorf("config: %s does not end in a newline — the last write was interrupted: %w", label, ErrTorn)
	}
	body, sum, hasMarker := splitMarker(snap)
	if !hasMarker || sum == "" || cliio.SHA256Hex(body) != sum {
		return nil, fmt.Errorf("config: %s %w — if you edited it by hand, recompute the marker (see docs/CONFIG-FORMAT.md); otherwise the last write was interrupted", label, ErrTorn)
	}
	records, err := ScanData(body, label)
	if err != nil {
		return nil, err // intact bytes that are not valid config: MALFORMED, never torn
	}
	return Validate(records, label, spec)
}

// LoadProduct reads a product's config: identity gate, then ONE bounded snapshot, then every
// check on those same bytes — this file is bind-mounted read-write into a container, the most
// exposed input in the design, and re-opening it per check is a TOCTOU the container wins.
// errors.Is: ErrMissing (absent — defaults), ErrTorn (defaults, reported), other (rejected).
// Reading NEVER rewrites the file.
func LoadProduct(home, product string, spec Spec) (map[string]string, error) {
	f, err := ProductPath(home, product)
	if err != nil {
		return nil, err
	}
	if err := identityOK(f); err != nil {
		return nil, err
	}
	snap, err := SnapProduct(f)
	if err != nil {
		return nil, err
	}
	return loadSnapshot(snap, f, spec)
}

// ProductEnsure creates a missing <product>.conf — a KEYLESS create is the fresh-install path
// (the product's own UI writes the settings, D3). An existing file is left exactly as found.
func ProductEnsure(h famlock.Held, product, gid string) error {
	home, err := famlock.HomeOf(h)
	if err != nil {
		return err
	}
	f, perr := ProductPath(home, product)
	if perr != nil {
		return perr
	}
	if _, err := os.Lstat(f); err == nil {
		return nil
	}
	return ProductAdd(h, product, gid, Spec{}, nil)
}

// ProductAdd merges KEY/VALUE pairs into <product>.conf. Requires the family lock; the home
// comes from the token. MERGE, not replace (comments, blank lines, order and untouched keys
// survive), ADDITIVE only (same value ⇒ no-op; different ⇒ ErrKeyConflict), and IN PLACE,
// never temp+rename: the file is bind-mounted as a SINGLE FILE and a rename would silently
// detach the container's view — it would keep reading and writing the orphaned old inode
// forever. The residual is that an in-place write can tear; mitigated: the whole body is built
// in memory, emitted in ONE write, the marker LAST, under the family lock.
//
// Outcomes: nil (written, or content no-op) · ErrTorn (existing file torn — merging would
// re-bless damage) · *OwnershipError (bytes COMMITTED, ownership spec not fully applied — the
// group+mode are re-applied even on content no-ops, which is what makes the documented repair
// "fix the group and run again" actually work) · any other error: refused, file untouched.
func ProductAdd(h famlock.Held, product, gid string, spec Spec, kvs []KV) error {
	// ALL DIGITS, exactly as the bash's `''|*[!0-9]*` refusal: strconv alone accepts "-1",
	// and os.Chown(path, -1, -1) silently leaves the group UNCHANGED while chmod 0660 then
	// exposes the file to whatever group it already had.
	if gid == "" || strings.IndexFunc(gid, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return fmt.Errorf("config: %q is not a numeric group id", gid)
	}
	gidN, err := strconv.Atoi(gid)
	if err != nil {
		return fmt.Errorf("config: %q is not a numeric group id", gid)
	}
	home, herr := famlock.HomeOf(h)
	if herr != nil {
		return herr
	}
	// Path first — resolving it VALIDATES the product name, and an unvalidated name must not
	// reach even the refusal message. Then the lock.
	f, perr := ProductPath(home, product)
	if perr != nil {
		return perr
	}
	if err := famlock.Assert(h, "write "+product+".conf"); err != nil {
		return err
	}
	if err := identityOK(f); err != nil {
		return err
	}

	// Validate EVERY pair before touching the file; the same key twice in one call refuses.
	seen := map[string]bool{}
	for _, kv := range kvs {
		if !KeyOK(kv.Key) {
			return fmt.Errorf("config: refusing to write invalid key name %q to %s.conf", kv.Key, product)
		}
		typ, ok := spec[kv.Key]
		if !ok {
			return fmt.Errorf("config: %s is not a key %s.conf accepts", kv.Key, product)
		}
		if !ValueOK(kv.Value) || !TypeOK(typ, kv.Value) {
			return fmt.Errorf("config: refusing to write an invalid value for %s", kv.Key)
		}
		if seen[kv.Key] {
			return fmt.Errorf("config: %s given twice — refusing to write %s.conf", kv.Key, product)
		}
		seen[kv.Key] = true
	}

	// An existing file must load cleanly before we merge into it — merging into a torn or
	// off-spec file would re-bless damage under a fresh, valid marker. Snapshot ONCE; build
	// the new body from THE SAME BYTES; never look at the live file's content again.
	var body []byte
	var existing map[string]string
	pre := ""
	had := false
	if _, lerr := os.Lstat(f); lerr == nil {
		snap, serr := SnapProduct(f)
		if serr != nil {
			return serr
		}
		existing, serr = loadSnapshot(snap, f, spec)
		if serr != nil {
			if errors.Is(serr, ErrTorn) {
				return serr
			}
			return fmt.Errorf("config: %s.conf does not load cleanly — refusing to modify it; fix or remove it first: %w", product, serr)
		}
		b, _, _ := splitMarker(snap)
		body = append([]byte{}, b...)
		had = true
		pre = cliio.SHA256Hex(snap)
	}
	orig := append([]byte{}, body...)

	// The additive gate, decided from the records the snapshot already yielded.
	for _, kv := range kvs {
		if cur, ok := existing[kv.Key]; ok {
			if cur != kv.Value {
				return fmt.Errorf("config: %s is already set to %q in %s.conf: %w", kv.Key, cur, product, ErrKeyConflict)
			}
			continue // already exactly right: the existing line stays untouched
		}
		body = append(body, []byte(kv.Key+"="+kv.Value+"\n")...)
	}
	sum := cliio.SHA256Hex(body)

	// CAS + identity immediately before we MUTATE anything — including the create: a dangling
	// symlink planted just before it would otherwise make the create write THROUGH the link.
	if !unchangedProduct(f, pre) {
		return fmt.Errorf("config: %s.conf %w", product, ErrCASMismatch)
	}
	if err := identityOK(f); err != nil {
		return err
	}
	if !had {
		nf, cerr := os.OpenFile(f, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if cerr != nil {
			return fmt.Errorf("config: cannot create %s: %w", f, cerr)
		}
		nf.Close()
	}

	// A pure content no-op leaves bytes, inode and mtime exactly as they are — re-installing
	// with the values the file already holds is the ORDINARY path, and a truncate-rewrite
	// would let a concurrently reading container observe the truncated intermediate. The
	// group/mode re-application below is deliberately NOT skipped.
	if !(had && bytes.Equal(body, orig)) {
		full := append(append([]byte{}, body...), []byte(MarkerPrefix+sum+"\n")...)
		// ONE open, truncate-and-write on the SAME inode: os.WriteFile is O_TRUNC on the
		// existing file, never a rename. The marker is last, so a crash leaves it stale
		// rather than wrong.
		if err := os.WriteFile(f, full, 0o600); err != nil {
			return fmt.Errorf("config: cannot write %s: %w", f, err)
		}
	}

	// D60: owner=operator, family group, 0660 — applied numerically, on every invocation.
	// Failures past this point are *OwnershipError: the bytes ARE committed, which is what
	// separates these from every plain refusal above.
	if err := os.Chown(f, -1, gidN); err != nil {
		if err := os.Chmod(f, 0o600); err != nil {
			return &OwnershipError{State: StateBothFailed, Path: f, GID: gidN}
		}
		return &OwnershipError{State: StateGroupFailed, Path: f, GID: gidN}
	}
	if err := os.Chmod(f, 0o660); err != nil {
		return &OwnershipError{State: StateModeFailed, Path: f, GID: gidN}
	}
	return nil
}
