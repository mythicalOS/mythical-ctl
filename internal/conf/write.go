package conf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// ErrKeyConflict: the additive rule's refusal — a key already present with a DIFFERENT value
// is either the operator's or the product UI's, and the installer cannot tell those from its
// own earlier value.
var ErrKeyConflict = errors.New("key already set to a different value — refusing to overwrite it")

// digestOf hashes an on-disk file's bytes, "" for an absent file — the whole-file
// compare-and-swap baseline. This is the ONE sanctioned live-file read a writer makes besides
// its own snapshot: it compares a digest and never derives configuration from what it reads,
// so it cannot become an injection path.
func digestOf(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("config: cannot digest %s: %w", path, err)
	}
	return cliio.SHA256Hex(data), nil
}

// unchanged reports whether the live file still digests to pre.
func unchanged(path, pre string) bool {
	now, err := digestOf(path)
	return err == nil && now == pre
}

// atomicReplace lands content at path via temp-file + fsync + rename in the same directory.
// CORRECT FOR mythical.conf AND ONLY mythical.conf: the family file is never bind-mounted, so
// swapping the inode detaches nothing. The product writer is IN-PLACE for the inverse reason.
func atomicReplace(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mythical.conf.*")
	if err != nil {
		return fmt.Errorf("config: cannot create a temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("config: cannot write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: cannot replace %s: %w", path, err)
	}
	return nil
}

// familyKeyType resolves a key against the CORE spec, falling back to the ONE product-scoped
// shape the core recognises by pattern (the bind key). Write-door logic only — the validator
// used by loads has no such fallback.
func familyKeyType(key string) (string, error) {
	if typ, ok := FamilySpec()[key]; ok {
		return typ, nil
	}
	if typ, ok := BindKeyType(key); ok {
		return typ, nil
	}
	return "", fmt.Errorf("config: %s is not a key mythical.conf accepts", key)
}

// FamilyAdd ADDS one key to mythical.conf, preserving the rest of the file byte-for-byte (D9).
// Additive only: absent ⇒ written; present with the SAME value ⇒ no-op success; present with a
// DIFFERENT value ⇒ ErrKeyConflict, file untouched. The home comes from the lock token.
func FamilyAdd(h famlock.Held, key, value string) error {
	if err := famlock.Assert(h, "write mythical.conf"); err != nil {
		return err
	}
	home, err := famlock.HomeOf(h)
	if err != nil {
		return err
	}
	f := FamilyPath(home)

	// Validate BEFORE touching the file. A newline in a value would forge a second key on the
	// next read — ValueOK rejects it along with every other control byte.
	if !KeyOK(key) {
		return fmt.Errorf("config: refusing to write invalid key name %q", key)
	}
	typ, err := familyKeyType(key)
	if err != nil {
		return err
	}
	if !ValueOK(value) || !TypeOK(typ, value) {
		return fmt.Errorf("config: refusing to write an invalid value for %s", key)
	}
	if err := identityOK(f); err != nil {
		return err
	}

	// ONE read serves the scan, the additive gate, and the CAS baseline — the same bytes
	// decide everything (strictly stronger than the bash, which read per purpose).
	existing, err := os.ReadFile(f)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		existing = nil
	default:
		return fmt.Errorf("config: cannot read %s: %w", f, err)
	}
	if len(existing) > 0 {
		if DataBytesOK(existing) != nil {
			return fmt.Errorf("config: %s %w — refusing to modify it", f, ErrControlBytes)
		}
		if existing[len(existing)-1] != '\n' {
			return fmt.Errorf("config: %s does not end in a newline (truncated?) — refusing to modify it", f)
		}
		records, err := ScanData(existing, f)
		if err != nil {
			return fmt.Errorf("config: %s does not parse — never modifying a file that does not load cleanly: %w", f, err)
		}
		for _, r := range records {
			if r.Key == key {
				if r.Value == value {
					return nil // already exactly this value: a no-op success
				}
				return fmt.Errorf("config: %s is already set to %q in %s: %w", key, r.Value, f, ErrKeyConflict)
			}
		}
	}
	pre := ""
	if existing != nil {
		pre = cliio.SHA256Hex(existing)
	}

	content := append(append([]byte{}, existing...), []byte(key+"="+value+"\n")...)

	// CAS + identity immediately before the replace: a save landing between our read and this
	// write must be refused, not silently discarded, and a symlink swapped in after the first
	// identity check must not be adopted by the rename.
	if !unchanged(f, pre) {
		return fmt.Errorf("config: %s changed while we were reading it — refusing to overwrite that change; re-run", f)
	}
	if err := identityOK(f); err != nil {
		return err
	}
	return atomicReplace(f, content)
}

// Attempt is FamilyCAS's recorded write-attempt state.
type Attempt int

const (
	// AttemptNone: no write of this key has been attempted yet.
	AttemptNone Attempt = iota
	// AttemptStarted: a write was recorded as in progress — absent-or-different now means a
	// crash OR a hand edit, indistinguishable, so the operator confirms.
	AttemptStarted
)

// FamilyCAS is THE ONE function authorized to CHANGE a value in mythical.conf — the narrow,
// stated exception to additive-only (§5.2), invoked only by migrate-storage. It writes only a
// MYTHICAL_<product>_<role>_BIND key, never a core setting. The attempt table:
//
//	none    + key absent and prior==""        → write
//	none    + key holds prior                 → write
//	none    + anything else                   → refuse
//	started + key holds value                 → already written — advance, no rewrite
//	started + anything else                   → stop; only an explicit confirmation proceeds
//
// The rewrite re-verifies the expected value AT the write, per line, and a key deleted between
// check and rewrite refuses — nothing acts on a fact this call did not re-establish.
func FamilyCAS(h famlock.Held, key, value, prior string, attempt Attempt, confirm cliio.ConfirmFunc) error {
	if err := famlock.Assert(h, "compare-and-set a value in mythical.conf"); err != nil {
		return err
	}
	home, err := famlock.HomeOf(h)
	if err != nil {
		return err
	}
	f := FamilyPath(home)
	if !KeyOK(key) {
		return fmt.Errorf("config: refusing to write invalid key name %q", key)
	}
	typ, ok := BindKeyType(key)
	if !ok {
		return fmt.Errorf("config: refusing to compare-and-set %q — this door writes only a MYTHICAL_<product>_<role>_BIND key, never a core setting", key)
	}
	if !ValueOK(value) || !TypeOK(typ, value) {
		return fmt.Errorf("config: refusing to write an invalid value for %s", key)
	}
	if err := identityOK(f); err != nil {
		return err
	}

	cur, err := Get(f, key)
	haveCur := err == nil
	if err != nil && !errors.Is(err, ErrAbsent) && !errors.Is(err, ErrMissing) {
		return err
	}

	switch attempt {
	case AttemptNone:
		switch {
		case !haveCur && prior == "":
		case haveCur && cur == prior:
		default:
			return fmt.Errorf("config: %s holds %q, not the expected prior value %q — refusing", key, cur, prior)
		}
	case AttemptStarted:
		if haveCur && cur == value {
			return nil // already holds the migrated destination; advance without rewriting
		}
		if confirm == nil || !confirm(fmt.Sprintf("config: write %s=%s, discarding what is there?", key, value)) {
			return fmt.Errorf("config: a write of %s was recorded as IN PROGRESS and the key now holds %q — a crash and a hand edit are indistinguishable from the file alone; refusing without explicit confirmation", key, cur)
		}
	default:
		return fmt.Errorf("config: %d is not an attempt state", attempt)
	}

	// expected = what THIS call cleared to write over.
	expected := prior
	if attempt == AttemptStarted {
		expected = cur
		if !haveCur {
			expected = ""
		}
	}

	var out strings.Builder
	wrote, sawKey := false, false
	if data, rerr := os.ReadFile(f); rerr == nil {
		if DataBytesOK(data) != nil {
			return fmt.Errorf("config: %s %w — refusing to modify it", f, ErrControlBytes)
		}
		for _, line := range strings.SplitAfter(string(data), "\n") {
			if line == "" {
				continue
			}
			bare := strings.TrimSuffix(line, "\n")
			if now, ok := strings.CutPrefix(bare, key+"="); ok {
				sawKey = true
				if now != expected {
					return fmt.Errorf("config: %s now holds %q, not %q as this call verified — it changed between check and rewrite; refusing", key, now, expected)
				}
				out.WriteString(key + "=" + value + "\n")
				wrote = true
				continue
			}
			out.WriteString(line)
		}
	} else if !os.IsNotExist(rerr) {
		return fmt.Errorf("config: cannot read %s: %w", f, rerr)
	}
	if !sawKey && expected != "" {
		return fmt.Errorf("config: %s is no longer present in %s (expected %q) — it was removed between check and rewrite; refusing", key, f, expected)
	}
	if !wrote {
		out.WriteString(key + "=" + value + "\n")
	}
	if err := identityOK(f); err != nil {
		return err
	}
	return atomicReplace(f, []byte(out.String()))
}
