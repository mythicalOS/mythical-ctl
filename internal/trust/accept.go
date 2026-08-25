package trust

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/version"
)

// IndexSpec is the family index — the one trust root (§8.1). probe_image and copy_image are
// the two pinned helper images (D49/D54), named in the one document verified against the
// persisted anchor so they ride the same chain as everything else — never "whatever busybox
// is around". REQUIRED (D49 stops rather than proceeding unverified; an absent key would make
// that stop unreachable), and digestref refuses a tag by construction (D22).
func IndexSpec() docfmt.Schema {
	return docfmt.Schema{
		Type: "index",
		Fixed: map[string]docfmt.KeySpec{
			"version":       docfmt.Typed(docfmt.One, "docver"),
			"expires":       docfmt.Typed(docfmt.One, "epoch"),
			"policy_digest": docfmt.Typed(docfmt.One, "sha256"),
			"manifest":      docfmt.Typed(docfmt.Many, "productdigest"),
			"probe_image":   docfmt.Typed(docfmt.One, "digestref"),
			"copy_image":    docfmt.Typed(docfmt.One, "digestref"),
		},
	}
}

// Index is a parsed (and, via the acceptors, authenticated) family index.
type Index struct {
	doc *docfmt.Doc
}

// parseIndex refuses an index listing any product twice — refused at LOAD, not at lookup: an
// ambiguous index that parses can still accept a policy, so catching it only when someone
// looks that product up is not catching it.
func parseIndex(data []byte, label string) (*Index, error) {
	doc, err := docfmt.Parse(data, label, IndexSpec())
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, v := range doc.Values("manifest") {
		product, _, _ := strings.Cut(v, ":")
		if seen[product] {
			return nil, fmt.Errorf("trust: the family index lists %s more than once — refusing an ambiguous index", product)
		}
		seen[product] = true
	}
	return &Index{doc: doc}, nil
}

// PolicyDigest is the digest the index vouches the policy by.
func (ix *Index) PolicyDigest() (string, bool) { return ix.doc.Value("policy_digest") }

// ManifestDigest returns the digest the index vouches for ONE product — ErrNotVouched when
// the index does not list it, which is not "carry on" but a refusal.
func (ix *Index) ManifestDigest(product string) (string, error) {
	for _, v := range ix.doc.Values("manifest") {
		if rest, ok := strings.CutPrefix(v, product+":"); ok {
			return rest, nil
		}
	}
	return "", fmt.Errorf("trust: %q: %w", product, ErrNotVouched)
}

// ProbeImage / CopyImage: the pinned helper images.
func (ix *Index) ProbeImage() string { v, _ := ix.doc.Value("probe_image"); return v }
func (ix *Index) CopyImage() string  { v, _ := ix.doc.Value("copy_image"); return v }

// Doc exposes the immutable document for the freshness gate.
func (ix *Index) Doc() *docfmt.Doc { return ix.doc }

// --- the freshness gate (AMENDMENT A2: split check / commit) ------------------------------------

// CheckOnly is the anchored freshness gate, PURE — it commits nothing. errors.Is(ErrNoAnchor)
// = first use, establish one online; an anchor that is RECORDED but unreadable refuses (it is
// never first use — re-anchoring would replace the root with whatever the origin serves).
// Then the pure predicate: version present, expiry present (a document with no expiry replays
// indefinitely — mandatory here, not merely typed), not expired against the REAL clock (no
// environment override: an ambient knob would ship "make an expired document look current" as
// a supported invocation), and not below the recorded floor. An absent floor is FIRST USE, not
// a rollback.
func CheckOnly(st ledger.Store, docid string, d *docfmt.Doc, nowUnix int64) error {
	if _, err := AnchorGet(st); err != nil {
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return fmt.Errorf("trust: %s cannot be verified offline: %w", docid, ErrNoAnchor)
		}
		return fmt.Errorf("trust: this installation HAS a recorded family-index anchor and it could not be read — a damaged trust record, not a new installation; %s is refused rather than anchored afresh; repair the ledger and re-run: %w", docid, err)
	}
	return freshOK(st, docid, d, nowUnix)
}

func freshOK(st ledger.Store, docid string, d *docfmt.Doc, nowUnix int64) error {
	ver, ok := d.Version()
	if !ok {
		return fmt.Errorf("trust: %s carries no version — refusing (freshness is part of authenticity)", docid)
	}
	if !d.HasExpiry() {
		return fmt.Errorf("trust: %s carries no expiry — refusing; without one it replays indefinitely (§8.1)", docid)
	}
	expired, err := d.Expired(nowUnix)
	if err != nil {
		return fmt.Errorf("trust: %s has an unreadable expiry — refusing: %w", docid, err)
	}
	if expired {
		return fmt.Errorf("trust: %s has expired — refusing; a stale document replays indefinitely otherwise", docid)
	}
	cur, err := FloorGet(st, docid)
	switch {
	case err == nil:
		if decGT(cur, ver) {
			return fmt.Errorf("trust: %s version %s is older than the highest already seen (%s) — refusing as replay", docid, ver, cur)
		}
	case errors.Is(err, ledger.ErrAbsentRecord):
		// First use (§10a): trust-on-first-use; treating it as an attack would make every
		// second product uninstallable.
	default:
		return err
	}
	return nil
}

// Commit advances the floor — and the anchor when one is given — in ONE ledger write. The
// floor cannot go DOWN here either; FloorOverride is the only path that lowers.
func Commit(h famlock.Held, st ledger.Store, docid string, d *docfmt.Doc, anchor string) error {
	if !docidOK(docid) {
		return fmt.Errorf("trust: invalid document id %q", docid)
	}
	ver, ok := d.Version()
	if !ok {
		return fmt.Errorf("trust: %s carries no version — refusing to record a floor for it", docid)
	}
	if !digitsOK(ver) {
		return fmt.Errorf("trust: %q is not a document version", ver)
	}
	cur, err := FloorGet(st, docid)
	switch {
	case err == nil:
		if decGT(cur, ver) {
			return fmt.Errorf("trust: refusing to lower the recorded version floor for %s (%s → %s)", docid, cur, ver)
		}
	case errors.Is(err, ledger.ErrAbsentRecord):
	default:
		return err
	}
	if anchor != "" {
		if !hex64OK(anchor) {
			return fmt.Errorf("trust: %q is not a sha256 digest", anchor)
		}
		return putMany(h, st, [][3]string{{floorKind, docid, ver}, {anchorKind, "digest", anchor}})
	}
	return putMany(h, st, [][3]string{{floorKind, docid, ver}})
}

// --- the acceptors: the ONLY doorway to authenticated documents ---------------------------------
// Each takes FILES and re-establishes the chain itself: a record blob is data any caller can
// fabricate, and "these records came from the acceptor" is a claim a callee cannot check.
// Authenticated state must not be representable as data a caller can construct — so paths
// cross the boundary, and everything is re-derived from the anchor, the one thing this
// process did not receive from its caller. Each snapshots ONCE and verifies-then-parses the
// SAME bytes: hashing a path and re-opening it is a TOCTOU a rename wins.

// AcceptIndex is THE ROOT OF THE CHAIN.
func AcceptIndex(h famlock.Held, st ledger.Store, indexPath string) (*Index, error) {
	ix, err := checkIndex(st, indexPath, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if err := Commit(h, st, "index", ix.doc, ""); err != nil {
		return nil, err
	}
	return ix, nil
}

// CheckIndex is the read-only sibling: verifies against the stored anchor and floor without
// writing anything.
func CheckIndex(st ledger.Store, indexPath string) (*Index, error) {
	return checkIndex(st, indexPath, time.Now().Unix())
}

func checkIndex(st ledger.Store, indexPath string, now int64) (*Index, error) {
	anchor, err := AnchorGet(st)
	if err != nil {
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return nil, fmt.Errorf("trust: %s cannot be verified: %w", indexPath, ErrNoAnchor)
		}
		return nil, fmt.Errorf("trust: this installation HAS a recorded family-index anchor and it could not be read — a damaged trust record, not a new installation; %s is refused rather than anchored afresh; repair the ledger and re-run: %w", indexPath, err)
	}
	snap, err := docfmt.Snapshot(indexPath)
	if err != nil {
		return nil, err
	}
	if err := VerifyDigestData(snap, anchor, indexPath); err != nil {
		return nil, err
	}
	ix, err := parseIndex(snap, indexPath)
	if err != nil {
		return nil, err
	}
	if err := freshOK(st, "index", ix.doc, now); err != nil {
		return nil, err
	}
	return ix, nil
}

// AcceptPolicy authenticates the policy under a freshly re-verified index.
func AcceptPolicy(h famlock.Held, st ledger.Store, indexPath, policyPath string) (*policy.Policy, error) {
	pol, ix, err := checkPolicy(st, indexPath, policyPath, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if err := Commit(h, st, "index", ix.doc, ""); err != nil {
		return nil, err
	}
	if err := Commit(h, st, "policy", pol.Doc(), ""); err != nil {
		return nil, err
	}
	return pol, nil
}

// CheckPolicy is the read-only sibling.
func CheckPolicy(st ledger.Store, indexPath, policyPath string) (*policy.Policy, error) {
	pol, _, err := checkPolicy(st, indexPath, policyPath, time.Now().Unix())
	return pol, err
}

func checkPolicy(st ledger.Store, indexPath, policyPath string, now int64) (*policy.Policy, *Index, error) {
	ix, err := checkIndex(st, indexPath, now)
	if err != nil {
		return nil, nil, err
	}
	expected, ok := ix.PolicyDigest()
	if !ok {
		return nil, nil, errors.New("trust: the family index names no policy digest")
	}
	snap, err := docfmt.Snapshot(policyPath)
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyDigestData(snap, expected, policyPath); err != nil {
		return nil, nil, err
	}
	pol, err := policy.ParseVerified(snap, policyPath)
	if err != nil {
		return nil, nil, err
	}
	if err := freshOK(st, "policy", pol.Doc(), now); err != nil {
		return nil, nil, err
	}
	return pol, ix, nil
}

// AcceptManifest is THE SINGLE DOOR for a product manifest — the only composition of the
// steps, because a chain nobody is forced to walk is not a boundary. The order is the
// contract, transcribed from the reference:
//
//  1. the family index authenticated against the anchor
//  2. the policy authenticated against THAT index (a digest is not authentication, and
//     entitlement against a merely-parsed policy would let a tampered one grant anything)
//  3. the index must vouch for THIS product
//  4. the bytes must hash to the digest the index names
//  5. only then parse
//  6. the manifest's own product must equal the requested one
//  7. freshness CHECKED — but the floor NOT yet committed
//  8. entitlements (nothing beyond what the policy grants)
//  9. min_core BEFORE any floor movement
//  10. THEN the floor commits: a manifest refused for entitlement or min_core must not have
//     raised the replay bar, or a publisher's typo permanently blocks every version at or
//     below the refused one (AMENDMENT A2 — this door is why the check/commit split exists)
//  11. launch state LAST — "not launched" is only trustworthy from an authenticated document,
//     and it is still an ACCEPTANCE (the floor stays advanced): ErrNotLaunched, with the
//     manifest still returned for the caller's report.
func AcceptManifest(h famlock.Held, st ledger.Store, indexPath, policyPath, manifestPath, product string) (*manifest.Manifest, error) {
	now := time.Now().Unix()
	ix, err := checkIndex(st, indexPath, now)
	if err != nil {
		return nil, err
	}
	pol, _, err := checkPolicy(st, indexPath, policyPath, now)
	if err != nil {
		return nil, err
	}
	expected, err := ix.ManifestDigest(product)
	if err != nil {
		return nil, fmt.Errorf("trust: refusing to install an unattested product: %w", err)
	}
	snap, err := docfmt.Snapshot(manifestPath)
	if err != nil {
		return nil, err
	}
	if err := VerifyDigestData(snap, expected, manifestPath); err != nil {
		return nil, err
	}
	m, err := manifest.ParseVerified(snap, manifestPath)
	if err != nil {
		return nil, err
	}
	if got := m.Product(); got != product {
		return nil, fmt.Errorf("trust: %s is the manifest for %q, but %q was requested — refusing", manifestPath, got, product)
	}
	docid := "manifest:" + product
	if err := freshOK(st, docid, m.Doc(), now); err != nil {
		return nil, err
	}
	if err := manifest.Check(m, pol); err != nil {
		return nil, err
	}
	if err := manifest.CoreOK(m, version.Version); err != nil {
		return nil, err
	}
	// Every gate that can REFUSE has run: commit the whole chain's floors in this door's one
	// authoritative pass (index, policy, then the manifest's own).
	if err := Commit(h, st, "index", ix.doc, ""); err != nil {
		return nil, err
	}
	if err := Commit(h, st, "policy", pol.Doc(), ""); err != nil {
		return nil, err
	}
	if err := Commit(h, st, docid, m.Doc(), ""); err != nil {
		return nil, err
	}
	if !m.Launched() {
		return m, ErrNotLaunched
	}
	return m, nil
}
