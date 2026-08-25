// Package conf reads and writes the two configuration files (D2/D4):
// ~/.mythical/mythical.conf is host-only and never mounted; ~/.mythical/<product>.conf is
// bind-mounted read-write into that product's container.
//
// <product>.conf is UNTRUSTED INPUT (D19). It is attacker-controlled after a container
// compromise, so nothing here ever evaluates, expands, or executes a value — everything is a
// pure scanner over inert bytes.
package conf

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// The format's numeric law, verbatim from docs/CONFIG-FORMAT.md and the bash constants.
const (
	// MaxLen caps one value, in BYTES.
	MaxLen = 4096
	// MaxKeys caps the keys per file — format law (the bash also needed it to bound a
	// quadratic duplicate scan; Go's scan is linear, the cap stays because the format says so).
	MaxKeys = 1024
	// MaxBytes is the whole-file ceiling for the container-writable <product>.conf and the
	// authenticated documents ONLY — mythical.conf has NO byte ceiling (the family file
	// streams, key-capped but not byte-capped).
	MaxBytes = 1048576
	// MarkerPrefix opens the integrity marker line a <product>.conf ends with.
	MarkerPrefix = "#mythical-conf-sha256="
)

// The byte-gate outcomes. The unreadable/hostile distinction matters: reporting a permission
// problem as hostile content sends an operator chasing the wrong failure.
var (
	ErrControlBytes = errors.New("contains control bytes (NUL, CR, TAB or similar)")
	ErrUnreadable   = errors.New("cannot be read")
	// ErrMissing is the rc-3 analogue: the file does not exist, which is a DISTINCT outcome
	// from malformed — callers deciding whether to create branch on it.
	ErrMissing = errors.New("file is missing")
)

// DataBytesOK refuses data containing ANY control byte other than the line separator (\n):
// NUL, CR, TAB, vertical tab, DEL, the lot. It operates on bytes, with NO size ceiling — the
// ceiling belongs to the bounded product snapshot, not to the byte-class rule (the bash's
// file-level gate is likewise uncapped). One audited implementation: lib/doc.sh reused the
// bash's for the authenticated documents, and docfmt reuses this one.
func DataBytesOK(data []byte) error {
	for _, b := range data {
		if (b < 0x20 && b != '\n') || b == 0x7f {
			return ErrControlBytes
		}
	}
	return nil
}

// BytesOK is the path form: nil, ErrControlBytes, or ErrUnreadable — the bash rc 0/1/2
// trichotomy.
func BytesOK(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s %w", path, ErrUnreadable)
	}
	if DataBytesOK(data) != nil {
		return fmt.Errorf("%s %w", path, ErrControlBytes)
	}
	return nil
}

// SnapProduct is the BOUNDED snapshot for `<product>.conf`: exactly one read into a private
// buffer, at MaxBytes+1 — a full read at limit+1 proves the original was over the ceiling
// without trusting a size a racer could change (the bash SNAP_LIMIT discipline). Everything
// downstream parses the returned copy, never the live file: the copy is what closes the
// validate-then-reread race on the one attacker-controlled file.
func SnapProduct(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s: %w", path, ErrMissing)
		}
		return nil, fmt.Errorf("%s %w", path, ErrUnreadable)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s %w", path, ErrUnreadable)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%s: over the %d-byte ceiling", path, MaxBytes)
	}
	return data, nil
}
