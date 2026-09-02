// Package trust is the trust chain (D21/§8.1): one authenticated root, digest gating,
// anti-rollback, expiry.
//
// The load-bearing sentence of §8.1 is "A DIGEST IS NOT AUTHENTICATION": verifying a document
// against a digest that arrived beside it proves only that an attacker can compute sha256. A
// digest is meaningful ONLY when the expected value came from a document that was itself
// authenticated — the family index, anchored by a previous successful verification. Nothing
// here bootstraps its own trust.
package trust

import (
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
)

const (
	floorKind     = "trust-floor"
	anchorKind    = "trust-anchor"
	downgradeKind = "trust-downgrade"
)

var (
	// ErrUntrusted classifies every refusal where the CONTENT failed the chain — a digest
	// mismatch, an expired document, a replay below the floor — as distinct from unreadable
	// (I/O, absence) failures, so callers branch on errors.Is rather than message text.
	ErrUntrusted = errors.New("untrusted")
	// ErrNoAnchor (the rc-4 analogue): no family-index anchor has EVER been recorded — first
	// use, establish one online. NEVER conflated with an unreadable anchor, which is a damaged
	// trust record: folding the two would tell a damaged installation to re-bootstrap,
	// replacing the anchor with whatever the origin serves next — the one thing an anchor
	// exists to prevent.
	ErrNoAnchor = errors.New("no family-index anchor has been recorded; run once with network access — a local copy is not evidence")
	// ErrNotLaunched (the rc-3 analogue): the manifest is AUTHENTIC, entitled and compatible,
	// and declares launched=false. An acceptance, not a refusal — the floor has already
	// advanced.
	ErrNotLaunched = errors.New("this product has not launched yet")
	// ErrNotVouched: the family index does not list the requested product — not silence, a
	// refusal.
	ErrNotVouched = errors.New("the family index does not vouch for this product")
)

func hex64OK(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

// VerifyDigestData verifies in-hand bytes against an expectation obtained from an
// authenticated document. A malformed expectation is a REFUSAL, not a comparison — it would
// otherwise "not match" for the right reason by accident, hiding the caller's own bug. label
// names the operator's pathname (every caller verifies a private snapshot whose temp name
// would be meaningless in a diagnostic).
func VerifyDigestData(data []byte, expected, label string) error {
	if !hex64OK(expected) {
		return fmt.Errorf("trust: %q is not a sha256 digest (64 lowercase hex characters) — refusing to compare", expected)
	}
	actual := cliio.SHA256Hex(data)
	if actual != expected {
		return fmt.Errorf("trust: %s does not match the digest the family index vouches for (%w)\n  expected: %s\n  actual:   %s", label, ErrUntrusted, expected, actual)
	}
	return nil
}

// docidOK: `<kind>:<product>` or a bare kind — a ledger key, so bounded and separator-free.
func docidOK(d string) bool {
	if d == "" || len(d) > 128 {
		return false
	}
	for i := 0; i < len(d); i++ {
		b := d[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != ':' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

// --- ledger-backed trust state over RAW rows ----------------------------------------------------
// Trust keeps its own record shape (docids contain ':', which the provenance field grammar
// refuses) — the bash likewise had a second, first-field editor here. Trust records are the
// one place where "I could not read this" must NEVER resolve to "there is nothing here": a
// bare row, a non-name=value token, a doubled key, and a present-but-empty value all REFUSE.

// readTrustValues returns every value recorded for key under kind, having first refused any
// malformed record of that kind. (found, values, error)
func readTrustValues(st ledger.Store, kind, key string) ([]string, error) {
	l, err := ledger.Read(st)
	if err != nil {
		if errors.Is(err, ledger.ErrMissingLedger) {
			return nil, nil // no ledger yet: genuinely absent
		}
		return nil, err
	}
	var vals []string
	for _, line := range l.Lines() {
		if line == "" {
			continue
		}
		rest, ok := cutKind(line, kind)
		if !ok {
			continue
		}
		if rest == "" {
			return nil, fmt.Errorf("trust: a %q record in the ledger has no fields at all — refusing rather than reading it as absent; run 'mythical-ctl state repair'", kind)
		}
		for _, tok := range strings.Split(rest, "\t") {
			name, val, hasEq := strings.Cut(tok, "=")
			if !hasEq {
				return nil, fmt.Errorf("trust: a %q record contains %q, which is not a name=value field — refusing rather than reading around it; run 'mythical-ctl state repair'", kind, tok)
			}
			if name == key {
				vals = append(vals, val)
			}
		}
	}
	return vals, nil
}

func cutKind(line, kind string) (rest string, ok bool) {
	if line == kind {
		return "", true
	}
	return strings.CutPrefix(line, kind+"\t")
}

// oneTrustValue applies the single-answer rule: 0 values = ErrAbsentRecord (first use);
// >1 = refuse (an ambiguous floor is how a rollback floor silently becomes the wrong number —
// and the failure direction is availability, never authenticity); exactly one EMPTY value =
// present-but-unreadable, refuse (reading it as never-seen turns anti-rollback off for the one
// record that was damaged).
func oneTrustValue(vals []string, what string) (string, error) {
	switch {
	case len(vals) == 0:
		return "", fmt.Errorf("trust: no %s recorded: %w", what, ledger.ErrAbsentRecord)
	case len(vals) > 1:
		return "", fmt.Errorf("trust: the %s is recorded more than once — refusing rather than choosing one; run 'mythical-ctl state repair'", what)
	case vals[0] == "":
		return "", fmt.Errorf("trust: a %s is recorded but carries no value — refusing rather than treating it as never-seen; run 'mythical-ctl state repair'", what)
	}
	return vals[0], nil
}

// FloorGet returns the recorded version floor for docid. errors.Is(ledger.ErrAbsentRecord) is
// the first-use branch; every other error refuses.
func FloorGet(st ledger.Store, docid string) (string, error) {
	if !docidOK(docid) {
		return "", fmt.Errorf("trust: invalid document id %q", docid)
	}
	vals, err := readTrustValues(st, floorKind, docid)
	if err != nil {
		return "", err
	}
	return oneTrustValue(vals, fmt.Sprintf("version floor for %q", docid))
}

// AnchorGet returns the recorded family-index anchor digest, same three-way contract.
func AnchorGet(st ledger.Store) (string, error) {
	vals, err := readTrustValues(st, anchorKind, "digest")
	if err != nil {
		return "", err
	}
	return oneTrustValue(vals, "trust anchor digest")
}

// putMany replaces SEVERAL trust records in ONE ledger write, preserving every other record.
// One write, not two: the floor and the anchor must move together or not at all — a
// half-applied pair is an anchor vouching for bytes the floor rejects, or a floor above
// anything the cache satisfies.
func putMany(h famlock.Held, st ledger.Store, triples [][3]string) error {
	if err := famlock.Assert(h, "record trust state"); err != nil {
		return err
	}
	l, err := ledger.Read(st)
	if err != nil {
		if !errors.Is(err, ledger.ErrMissingLedger) {
			return err
		}
		l = &ledger.Ledger{}
	}
	drop := map[string]bool{}
	for _, t := range triples {
		drop[t[0]+"\t"+t[1]+"="] = true
	}
	var out []string
	for _, line := range l.Lines() {
		if line == "" {
			out = append(out, line)
			continue
		}
		// Drop ONLY an exact SINGLE-FIELD row for the key being replaced (this writer only
		// ever writes single-field rows). A restored ledger can hold a multi-field trust row
		// carrying several keys; dropping it wholesale would erase ANOTHER document's
		// rollback floor (wave-2 gate P1) — such a row is preserved verbatim, the appended
		// replacement then makes the read ambiguous, and ambiguity refuses toward repair.
		pfx := line
		if i := strings.IndexByte(line, '='); i >= 0 {
			pfx = line[:i+1]
		}
		if drop[pfx] && !strings.Contains(line[strings.IndexByte(line, '\t')+1:], "\t") {
			continue
		}
		out = append(out, line)
	}
	for _, t := range triples {
		out = append(out, t[0]+"\t"+t[1]+"="+t[2])
	}
	l.ReplaceLines(out)
	return ledger.Write(h, st, l)
}

func digitsOK(v string) bool {
	if v == "" || len(v) > 18 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

func decGT(a, b string) bool {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

// FloorSet raises (or first-records) a floor. It can NEVER lower one — FloorOverride is the
// only function that can, because §8.1 requires a downgrade to be explicit, reasoned and
// recorded.
func FloorSet(h famlock.Held, st ledger.Store, docid, version string) error {
	if !docidOK(docid) {
		return fmt.Errorf("trust: invalid document id %q", docid)
	}
	if !digitsOK(version) {
		return fmt.Errorf("trust: %q is not a document version", version)
	}
	cur, err := FloorGet(st, docid)
	switch {
	case err == nil:
		if decGT(cur, version) {
			return fmt.Errorf("trust: refusing to lower the recorded version floor for %s (%s → %s)", docid, cur, version)
		}
	case errors.Is(err, ledger.ErrAbsentRecord):
	default:
		return err
	}
	return putMany(h, st, [][3]string{{floorKind, docid, version}})
}

// FloorOverride is §8.1's explicit operator downgrade: it demands a reason (recorded in the
// ledger BESIDE the new floor, in the same single write — a failed write leaves neither the
// floor lowered nor a partial audit record), refuses when no floor exists to override, and
// returns a headline that follows the ACTUAL direction of the change (an override is not
// restricted to lowering, and announcing "DOWNGRADED" on a raise misleads the operator).
func FloorOverride(h famlock.Held, st ledger.Store, docid, version, reason string) (string, error) {
	if !docidOK(docid) {
		return "", fmt.Errorf("trust: invalid document id %q", docid)
	}
	if !digitsOK(version) {
		return "", fmt.Errorf("trust: %q is not a document version", version)
	}
	if len(reason) > 4096 {
		return "", errors.New("trust: a downgrade reason must be 4096 characters or fewer")
	}
	if reason == "" || strings.ContainsFunc(reason, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("trust: a downgrade needs a one-line reason, recorded with it")
	}
	cur, err := FloorGet(st, docid)
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return "", fmt.Errorf("trust: there is no recorded floor for %s to override", docid)
	}
	if err != nil {
		return "", err
	}
	audit := fmt.Sprintf("from=%s to=%s reason=%s", cur, version, reason)
	if err := putMany(h, st, [][3]string{
		{floorKind, docid, version},
		{downgradeKind, docid, audit},
	}); err != nil {
		return "", fmt.Errorf("trust: the override of %s's version floor was NOT applied — the ledger write failed; the floor is unchanged at %s and no downgrade record was written: %w", docid, cur, err)
	}
	// The announcement FOLLOWS the write — announced first, it once described a downgrade a
	// failed write never performed.
	switch {
	case decGT(cur, version):
		return fmt.Sprintf("trust: DOWNGRADED the version floor for %s: %s → %s (reason: %s) — every document between these versions becomes acceptable again, including any that were withdrawn; this is recorded in the ledger", docid, cur, version, reason), nil
	case decGT(version, cur):
		return fmt.Sprintf("trust: RAISED the version floor for %s via override: %s → %s (reason: %s)", docid, cur, version, reason), nil
	}
	return fmt.Sprintf("trust: RE-RECORDED the version floor for %s at its current value (%s) (reason: %s)", docid, version, reason), nil
}

// AnchorSet records the family-index anchor.
func AnchorSet(h famlock.Held, st ledger.Store, digest string) error {
	if !hex64OK(digest) {
		return fmt.Errorf("trust: %q is not a sha256 digest", digest)
	}
	return putMany(h, st, [][3]string{{anchorKind, "digest", digest}})
}
