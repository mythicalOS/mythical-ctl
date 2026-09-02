package conf

import (
	"fmt"
	"strings"
)

// KV is one scanned assignment, key and value inert from the byte they are read to the byte
// they are handed on.
type KV struct{ Key, Value string }

// ScanData scans an in-hand body (already byte-gated by the caller's read path) into records.
// Comments (#) and blank lines are skipped; every other line is KEY=value split on the FIRST
// '=' so a value keeps any later '='. label only names the source in diagnostics.
//
// A marker line may appear ONLY as a file's last line, and the product reader strips it before
// scanning — so one reaching a body means either a second marker or a comment masquerading as
// one; both refuse. The key-count cap is checked before anything else per key, and a duplicate
// key is refused as ambiguous — it is exactly what a newline-forging write would produce.
func ScanData(data []byte, label string) ([]KV, error) {
	var out []KV
	seen := map[string]bool{}
	body := string(data)
	if body == "" {
		return nil, nil
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	keys := 0
	for i, line := range lines {
		n := i + 1
		switch {
		case strings.HasPrefix(line, MarkerPrefix):
			return nil, fmt.Errorf("config: %s line %d: an integrity marker may only be the final line", label, n)
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case !strings.Contains(line, "="):
			return nil, fmt.Errorf("config: %s line %d: not a KEY=value assignment", label, n)
		}
		key, val, _ := strings.Cut(line, "=")
		if !KeyOK(key) {
			return nil, fmt.Errorf("config: %s line %d: invalid key name", label, n)
		}
		if !ValueOK(val) {
			return nil, fmt.Errorf("config: %s line %d: value for %s contains a forbidden character or is too long", label, n, key)
		}
		keys++
		if keys > MaxKeys {
			return nil, fmt.Errorf("config: %s line %d: more than %d keys — refusing to parse it", label, n, MaxKeys)
		}
		if seen[key] {
			return nil, fmt.Errorf("config: %s line %d: duplicate key %s", label, n, key)
		}
		seen[key] = true
		out = append(out, KV{Key: key, Value: val})
	}
	return out, nil
}

// ScanFile applies the file-level preconditions, then scans: ErrMissing when absent (wrapped —
// use errors.Is); the byte gate's unreadable/hostile distinction; a non-empty file that does
// not end in a newline was truncated mid-write and refuses. mythical.conf comes through here
// (uncapped); <product>.conf does NOT — it is read once through SnapProduct into a private
// copy and parsed from that, which is where the validate-then-reread race actually matters.
func ScanFile(path string) ([]KV, error) {
	data, err := readWholeFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("config: %s does not end in a newline (truncated?) — refusing to parse it", path)
	}
	return ScanData(data, path)
}

func readWholeFile(path string) ([]byte, error) {
	data, err := osReadFile(path)
	if err != nil {
		if isNotExist(err) {
			return nil, fmt.Errorf("config: %s: %w", path, ErrMissing)
		}
		return nil, fmt.Errorf("config: cannot read %s — refusing to parse it: %w", path, ErrUnreadable)
	}
	if DataBytesOK(data) != nil {
		return nil, fmt.Errorf("config: %s %w — refusing to parse it", path, ErrControlBytes)
	}
	return data, nil
}
