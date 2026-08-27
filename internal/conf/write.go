package conf

import (
	"errors"
	"fmt"
	"io"
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

// ErrCASMismatch: a compare-and-swap's expectation no longer holds — the file (or the key)
// changed between this call's check and its write. Distinct from every operational failure,
// so a caller can offer "re-run" rather than diagnose.
var ErrCASMismatch = errors.New("changed between check and write — refusing; re-run")

// digestOf hashes an on-disk file's bytes, "" for an absent file — the whole-file
// compare-and-swap baseline. This is the ONE sanctioned live-file read a writer makes besides
// its own snapshot: it compares a digest and never derives configuration from what it reads,
// so it cannot become an injection path. limit < 0 reads unbounded — the FAMILY file has no
// byte ceiling and its CAS must not invent one; the PRODUCT file is attacker-growable, so its
// CAS bounds the re-read at MaxBytes+1 and anything over the ceiling reads as "changed".
func digestOf(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("config: cannot digest %s: %w", path, err)
	}
	defer f.Close()
	var r io.Reader = f
	if limit >= 0 {
		r = io.LimitReader(f, limit+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("config: cannot digest %s: %w", path, err)
	}
	if limit >= 0 && int64(len(data)) > limit {
		return "over-ceiling", nil // never a real digest: always reads as "changed"
	}
	return cliio.SHA256Hex(data), nil
}

// unchanged (family: unbounded) / unchangedProduct (bounded) report whether the live file
// still digests to pre.
func unchanged(path, pre string) bool {
	now, err := digestOf(path, -1)
	return err == nil && now == pre
}

func unchangedProduct(path, pre string) bool {
	now, err := digestOf(path, MaxBytes)
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
	// decide everything (strictly stronger than the bash, which read per purpose). Through the
	// package's one read seam, so tests can interpose the stale-snapshot race.
	existing, err := osReadFile(f)
	switch {
	case err == nil:
	case isNotExist(err):
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
		// Gate on the FULL load, not merely the syntax scan (lib/config.sh:558): a file holding
		// a key outside the core schema scans perfectly and fails the schema check, and
		// "succeeding" here would produce a file this package's own reader rejects. FROZEN
		// QUIRK, ported deliberately: the bash validates against the CORE spec only, so a
		// mythical.conf legitimately carrying a migrate-storage bind key refuses family_add —
		// the migrate wave re-examines that sequence against migrate.bats; inventing a bind
		// fallback here would be a divergence, not a fix.
		if _, verr := Validate(records, f, FamilySpec()); verr != nil {
			return fmt.Errorf("config: %s does not load cleanly — refusing to modify it; fix or remove it first: %w", f, verr)
		}
		for _, r := range records {
			if r.Key == key {
				if r.Value == value {
					// A no-op success must not be reported from a STALE snapshot (the bash
					// pins this): re-verify the file still holds the bytes that said "already
					// set" before saying anything.
					if !unchanged(f, cliio.SHA256Hex(existing)) {
						return fmt.Errorf("config: %s %w", f, ErrCASMismatch)
					}
					if err := identityOK(f); err != nil {
						return err
					}
					return nil
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
		return fmt.Errorf("config: %s %w", f, ErrCASMismatch)
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
//
// THIS DOOR NARRATES, and that is not decoration — it is one of the three grounds on which the
// reference accepts that the compare-and-set is NOT atomic against a human editor. The operation
// lock serializes mythical-ctl processes; it has no authority over a text editor, so an operator
// who saves mythical.conf inside the read-to-rename window loses that edit. The reference accepts
// that window because it is milliseconds long, because the operator invoked the command that
// touches this key, and because "the command REPORTS the value it wrote, so a lost edit is visible
// immediately". A silent version of this function keeps the window and drops the mitigation the
// design leaned on — and drops it hardest when it matters most: if the migration fails at a later
// phase, its own success narrative never runs, and the operator sees an error with no statement
// anywhere that mythical.conf was already rewritten. So `note` carries the three lines the
// reference printed. A nil note is allowed (a caller with nowhere to write), never assumed.
func FamilyCAS(h famlock.Held, key, value, prior string, attempt Attempt, confirm cliio.ConfirmFunc, note func(string)) error {
	say := func(format string, a ...any) {
		if note != nil {
			note(fmt.Sprintf(format, a...))
		}
	}
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
			return fmt.Errorf("config: %s holds %q, not the expected prior value %q: %w", key, cur, prior, ErrCASMismatch)
		}
	case AttemptStarted:
		if haveCur && cur == value {
			say("config: %s already holds the migrated destination; advancing without rewriting.", key)
			return nil
		}
		// THE EXPLANATION GOES IN THE PROMPT, not only in the refusal. It used to be in the error
		// returned when the operator DECLINED — which reaches nobody who says yes, and the person
		// who says yes is the one about to discard something. What they may be discarding is their
		// own hand edit, and nothing else on this path would have told them so.
		found := cur
		if !haveCur {
			found = "<nothing>"
		}
		prompt := fmt.Sprintf(
			"config: a write of %s was recorded as IN PROGRESS, and the key now holds\n"+
				"    %s\n"+
				"  rather than the value this write was in the middle of landing. The write may have\n"+
				"  crashed before it landed, or you may have deleted or changed the line by hand — the\n"+
				"  two are equally possible from the file alone, and guessing which one happened would\n"+
				"  overwrite exactly the edit this file's additive-only rule promises to keep.\n"+
				"  Stopping. Confirm explicitly to write %q anyway.\n"+
				"config: write %s=%s, discarding what is there?", key, found, value, key, value)
		if confirm == nil || !confirm(prompt) {
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
					return fmt.Errorf("config: %s now holds %q, not %q as this call verified: %w", key, now, expected, ErrCASMismatch)
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
		return fmt.Errorf("config: %s is no longer present in %s (expected %q): %w", key, f, expected, ErrCASMismatch)
	}
	if !wrote {
		out.WriteString(key + "=" + value + "\n")
	}
	if err := identityOK(f); err != nil {
		return err
	}
	if err := atomicReplace(f, []byte(out.String())); err != nil {
		return err
	}
	say("config: set %s=%s in %s (this is the one setting migrate-storage may change).", key, value, f)
	return nil
}
