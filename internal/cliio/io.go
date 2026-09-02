package cliio

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Warnf writes one diagnostic line, prefixed the way every mythical-ctl message is. Callers
// pass their stderr; nothing in this package reaches for the process globals.
func Warnf(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "mythical-ctl: "+format+"\n", a...)
}

// SHA256Hex is the digest helper the trust chain and the ledger checksum share — one
// implementation, lowercase hex, matching `sha256sum`'s output format byte for byte.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
