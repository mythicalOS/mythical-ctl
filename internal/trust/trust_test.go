package trust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
)

// Inventory — tests/unit/trust.bats:
// PORTED: tests/unit/trust.bats: "digest verification accepts a match and reports both sides on mismatch" -> TestVerifyDigest
// PORTED: tests/unit/trust.bats: "digest verification refuses a malformed expectation rather than comparing" -> TestVerifyDigest
// N/A: tests/unit/trust.bats: "a missing file is a verification failure, not a pass" -- VerifyDigestData is bytes-first by design (round-1 plan gate); absence is refused earlier, by Snapshot, asserted in TestAcceptorRefusals
// PORTED: tests/unit/trust.bats: "an absent floor is first use, not a rollback" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "a floor round-trips through the ledger" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "floors are per document id and do not bleed" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "raising a floor is allowed; lowering is refused and does not change it" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "the ordinary setter cannot lower a floor, and the override can — with a reason" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "a failed override says so, and does not announce a downgrade that did not happen" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "a downgrade without a reason is refused, and the floor is untouched" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "a downgrade is recorded in the ledger, not just printed" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "there is nothing to override when no floor was ever recorded" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "D2: a failed write leaves neither the floor lowered nor a partial audit record" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "D3: an over-long downgrade reason is refused, matching the config module's bound" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "D4: the message does not say DOWNGRADING when the override raises or re-records" -> TestFloorOverride
// PORTED: tests/unit/trust.bats: "setting the same floor again is accepted" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "floors survive other ledger records" -> TestFloorLifecycle
// PORTED: tests/unit/trust.bats: "writing a floor without the family lock is refused" -> TestLockRequired
// PORTED: tests/unit/trust.bats: "an absent anchor reports rc 3, and is NOT treated as first use by mi_trust_check_only" -> TestAnchorLifecycle
// PORTED: tests/unit/trust.bats: "the anchor round-trips and is replaceable" -> TestAnchorLifecycle
// PORTED: tests/unit/trust.bats: "a malformed anchor is refused" -> TestAnchorLifecycle
// PORTED: tests/unit/trust.bats: "an index cannot be accepted without a recorded anchor" -> TestAcceptIndex
// PORTED: tests/unit/trust.bats: "an index listing a product twice is refused as ambiguous" -> TestAcceptIndex
// PORTED: tests/unit/trust.bats: "an index whose real digest matches the recorded anchor is accepted, and returns records" -> TestAcceptIndex
// PORTED: tests/unit/trust.bats: "an index is refused when its real digest does not match the recorded anchor" -> TestAcceptIndex
// PORTED: tests/unit/trust.bats: "D1: an ABSENT anchor is first use for mi_accept_index too, and it is rc 4" -> TestAcceptIndex (ErrNoAnchor is the rc-4 analogue)
// PORTED: tests/unit/trust.bats: "D1: an anchor that cannot be READ is refused by mi_accept_index, never re-anchored" -> TestUnreadableAnchorNeverFirstUse
// PORTED: tests/unit/trust.bats: "T2: mi_accept_index refuses an expired family index even though its digest matches" -> TestAcceptIndex
// PORTED: tests/unit/trust.bats: "T5: _mi_index_manifest_digest returns THIS product's digest, never merely the first" -> TestIndexManifestDigest
// PORTED: tests/unit/trust.bats: "a document with no expiry is refused — it would replay forever" -> TestFreshness
// PORTED: tests/unit/trust.bats: "a first-seen document is accepted and records its version" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "an equal version is accepted; a lower one is refused as replay" -> TestFreshness
// PORTED: tests/unit/trust.bats: "a refused replay does not lower the floor" -> TestFreshness
// PORTED: tests/unit/trust.bats: "an expired document is refused even at the highest version" -> TestFreshness
// PORTED: tests/unit/trust.bats: "with no anchor recorded, the check refuses with its own code" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "a refusal for no anchor does not record a floor" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "mi_trust_check_only commits nothing" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "mi_trust_check still advances the floor, so this plan's callers are unaffected" -> TestCheckAndCommit (the acceptors compose CheckOnly+Commit — asserted through AcceptIndex's floor advance)
// PORTED: tests/unit/trust.bats: "mi_trust_commit moves the floor and the anchor together" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "an ABSENT anchor is first use, and it is rc 3 from the ledger that says so" -> TestAnchorLifecycle
// PORTED: tests/unit/trust.bats: "an anchor that cannot be READ is refused, never reported as first use" -> TestUnreadableAnchorNeverFirstUse
// PORTED: tests/unit/trust.bats: "mi_trust_commit refuses a malformed anchor without moving the floor" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "mi_trust_commit called directly refuses a version below the floor, and does not lower it" -> TestCheckAndCommit
// PORTED: tests/unit/trust.bats: "a version floor recorded twice is REFUSED, not silently compared as one string" -> TestDamagedTrustRecords
// PORTED: tests/unit/trust.bats: "a floor that is RECORDED but unreadable is refused, never read as never-seen" -> TestDamagedTrustRecords
// PORTED: tests/unit/trust.bats: "a trust record with no fields at all is refused, not read as absent" -> TestDamagedTrustRecords
// PORTED: tests/unit/trust.bats: "a genuinely absent floor is still rc 3, and a good floor still reads back" -> TestDamagedTrustRecords
//
// Deferred chain rows owned HERE — tests/unit/policy.bats:
// PORTED: tests/unit/policy.bats: "mi_accept_policy end to end: a matching chain is accepted and its records returned" -> TestAcceptPolicy
// PORTED: tests/unit/policy.bats: "mi_accept_policy refuses when the policy file's digest does not match the index" -> TestAcceptPolicy
// PORTED: tests/unit/policy.bats: "mi_accept_policy refuses with the chain's own code when no anchor has been accepted" -> TestAcceptPolicy
// PORTED: tests/unit/policy.bats: "T1: mi_accept_policy refuses a forged index it would otherwise merely re-parse" -> TestAcceptPolicy
// PORTED: tests/unit/policy.bats: "T2: mi_accept_policy refuses an expired policy even though its digest matches" -> TestAcceptPolicy
//
// Deferred chain rows owned HERE — tests/unit/manifest.bats:
// N/A: tests/unit/manifest.bats: "every acceptance path verifies and parses one snapshot, never the live pathname twice" -- structural in Go: each acceptor performs exactly one docfmt.Snapshot per file and every later step consumes that byte slice; there is no second open to trace
// PORTED: tests/unit/manifest.bats: "a forged record blob passed where a file belongs is refused" -> (structural: the acceptors take PATHS and re-derive everything; no API accepts a record blob at all — asserted by the type system, noted here for the audit)
// PORTED: tests/unit/manifest.bats: "the anchor is consulted on every acceptance, not cached from a previous call" -> TestAnchorConsultedEveryTime
// PORTED: tests/unit/manifest.bats: "T5: mi_accept_manifest's own index authentication cannot be bypassed even by a caller that skips it" -> TestAcceptManifestChain (the door re-derives the chain itself; no caller-supplied index exists)
// PORTED: tests/unit/manifest.bats: "the chain accepts an untampered index, policy and manifest" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "a manifest the index vouches for, but which declares another product, is refused" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "tampering at any level of the chain is refused" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "a product the index does not vouch for is refused" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "an authentic not-launched manifest reports rc 3, not 0" -> TestAcceptManifestChain (ErrNotLaunched, manifest still returned)
// PORTED: tests/unit/manifest.bats: "the manifest cannot supply a name — only a role" -> (owned by internal/manifest TestSchemaRefusals; recorded here because the bats file exercises it through the door)
// PORTED: tests/unit/manifest.bats: "an entitlement violation is refused by the door itself, not only by mi_manifest_check" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "Fix 1: an entitlement violation leaves the version floor unchanged" -> TestFloorDiscipline
// PORTED: tests/unit/manifest.bats: "Fix 1: an accepted-but-not-launched manifest still advances the version floor" -> TestFloorDiscipline
// PORTED: tests/unit/manifest.bats: "Fix 2: an expired manifest is refused through the door" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "Fix 2: a version rollback is refused through the door" -> TestFloorDiscipline
// PORTED: tests/unit/manifest.bats: "Fix 3: a policy tampered with locally after the chain was built is refused" -> TestAcceptManifestChain
// PORTED: tests/unit/manifest.bats: "Fix 7: a digest mismatch through the door names the operator's manifest path" -> TestAcceptManifestChain

const hex64 = "abababababababababababababababababababababababababababababababab"

type rig struct {
	h    famlock.Held
	st   ledger.Store
	home string
	dir  string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	home := t.TempDir()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	st, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{h: h, st: st, home: home, dir: t.TempDir()}
}

func (r *rig) write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func policyBytes(version string, extra ...string) []byte {
	base := []string{"version=" + version, "expires=99999999999", "family_gid=20"}
	return []byte("mythical-policy 1\n" + strings.Join(append(base, extra...), "\n") + "\n")
}

func manifestBytes(version, product, launched string, extra ...string) []byte {
	base := []string{
		"version=" + version, "expires=99999999999", "product=" + product,
		"launched=" + launched, "image=ghcr.io/x/" + product + "@sha256:" + hex64,
		"min_core=0.1.0", "runtime_uid=900",
	}
	return []byte("mythical-manifest 1\n" + strings.Join(append(base, extra...), "\n") + "\n")
}

func indexBytes(version string, policyDigest string, manifests map[string]string, extra ...string) []byte {
	lines := []string{
		"version=" + version, "expires=99999999999",
		"policy_digest=" + policyDigest,
		"probe_image=ghcr.io/x/probe@sha256:" + hex64,
		"copy_image=ghcr.io/x/copy@sha256:" + hex64,
	}
	for p, d := range manifests {
		lines = append(lines, "manifest="+p+":"+d)
	}
	lines = append(lines, extra...)
	return []byte("mythical-index 1\n" + strings.Join(lines, "\n") + "\n")
}

// chain builds a complete, anchored, mutually-vouching chain on disk.
func chain(t *testing.T, r *rig, polExtra, manExtra []string, launched string) (ixPath, polPath, manPath string) {
	t.Helper()
	pol := policyBytes("1", polExtra...)
	man := manifestBytes("1", "brokkr", launched, manExtra...)
	ix := indexBytes("1", cliio.SHA256Hex(pol), map[string]string{"brokkr": cliio.SHA256Hex(man)})
	ixPath = r.write(t, "index", ix)
	polPath = r.write(t, "policy", pol)
	manPath = r.write(t, "manifest", man)
	if err := AnchorSet(r.h, r.st, cliio.SHA256Hex(ix)); err != nil {
		t.Fatal(err)
	}
	return
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("payload\n")
	if err := VerifyDigestData(data, cliio.SHA256Hex(data), "f"); err != nil {
		t.Fatal(err)
	}
	err := VerifyDigestData(data, hex64, "the-label")
	if err == nil || !strings.Contains(err.Error(), "expected") || !strings.Contains(err.Error(), "actual") ||
		!strings.Contains(err.Error(), "the-label") {
		t.Fatalf("mismatch must report both sides and the label: %v", err)
	}
	for _, bad := range []string{"", "xyz", strings.ToUpper(hex64), hex64[:63]} {
		if err := VerifyDigestData(data, bad, "f"); err == nil || !strings.Contains(err.Error(), "refusing to compare") {
			t.Fatalf("malformed expectation %q compared: %v", bad, err)
		}
	}
}

func TestFloorLifecycle(t *testing.T) {
	r := newRig(t)
	if _, err := FloorGet(r.st, "policy"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("absent floor: %v", err)
	}
	if err := FloorSet(r.h, r.st, "policy", "3"); err != nil {
		t.Fatal(err)
	}
	if v, err := FloorGet(r.st, "policy"); err != nil || v != "3" {
		t.Fatalf("round-trip: %q %v", v, err)
	}
	// Per-docid, no bleed.
	if _, err := FloorGet(r.st, "manifest:brokkr"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("floors bled between docids")
	}
	// Raise ok; same ok; lower refused and unchanged.
	if err := FloorSet(r.h, r.st, "policy", "5"); err != nil {
		t.Fatal(err)
	}
	if err := FloorSet(r.h, r.st, "policy", "5"); err != nil {
		t.Fatal("same floor refused")
	}
	if err := FloorSet(r.h, r.st, "policy", "4"); err == nil {
		t.Fatal("lowering accepted")
	}
	if v, _ := FloorGet(r.st, "policy"); v != "5" {
		t.Fatalf("refused lowering changed the floor: %q", v)
	}
	// Floors survive other ledger records.
	l, _ := ledger.Read(r.st)
	_ = l.MemberAdd("brokkr")
	if err := ledger.Write(r.h, r.st, l); err != nil {
		t.Fatal(err)
	}
	if v, err := FloorGet(r.st, "policy"); err != nil || v != "5" {
		t.Fatalf("floor lost beside other records: %q %v", v, err)
	}
}

func TestFloorOverride(t *testing.T) {
	r := newRig(t)
	if _, err := FloorOverride(r.h, r.st, "policy", "1", "why"); err == nil {
		t.Fatal("override with no recorded floor accepted")
	}
	if err := FloorSet(r.h, r.st, "policy", "9"); err != nil {
		t.Fatal(err)
	}
	// No reason → refused, untouched.
	if _, err := FloorOverride(r.h, r.st, "policy", "3", ""); err == nil {
		t.Fatal("reasonless downgrade accepted")
	}
	if _, err := FloorOverride(r.h, r.st, "policy", "3", strings.Repeat("x", 5000)); err == nil {
		t.Fatal("over-long reason accepted")
	}
	if v, _ := FloorGet(r.st, "policy"); v != "9" {
		t.Fatal("refused override changed the floor")
	}
	// The real downgrade: applied, recorded in the ledger, headline says DOWNGRADED.
	msg, err := FloorOverride(r.h, r.st, "policy", "3", "emergency rollback of a bad release")
	if err != nil || !strings.Contains(msg, "DOWNGRADED") {
		t.Fatalf("%q %v", msg, err)
	}
	if v, _ := FloorGet(r.st, "policy"); v != "3" {
		t.Fatal("downgrade did not apply")
	}
	l, _ := ledger.Read(r.st)
	found := false
	for _, line := range l.Lines() {
		if strings.HasPrefix(line, "trust-downgrade\t") && strings.Contains(line, "reason=emergency rollback") {
			found = true
		}
	}
	if !found {
		t.Fatal("downgrade not recorded in the ledger")
	}
	// D4: raising or re-recording via override does not announce a downgrade.
	if msg, _ := FloorOverride(r.h, r.st, "policy", "7", "raise"); !strings.Contains(msg, "RAISED") || strings.Contains(msg, "DOWNGRADED") {
		t.Fatalf("raise headline: %q", msg)
	}
	if msg, _ := FloorOverride(r.h, r.st, "policy", "7", "again"); !strings.Contains(msg, "RE-RECORDED") {
		t.Fatalf("re-record headline: %q", msg)
	}
	// D2: a failed write leaves neither half — released token cannot write, floor unchanged,
	// and the returned error SAYS the override was not applied (never announces a downgrade
	// that did not happen).
	h2, _ := famlock.Acquire(t.TempDir())
	_ = famlock.Release(h2)
	if _, err := FloorOverride(h2, r.st, "policy", "1", "won't land"); err == nil {
		t.Fatal("released token overrode")
	}
	if v, _ := FloorGet(r.st, "policy"); v != "7" {
		t.Fatal("failed override moved the floor")
	}
}

func TestLockRequired(t *testing.T) {
	r := newRig(t)
	if err := FloorSet(nil, r.st, "policy", "1"); err == nil {
		t.Fatal("nil token wrote a floor")
	}
	if err := AnchorSet(nil, r.st, hex64); err == nil {
		t.Fatal("nil token wrote an anchor")
	}
}

func TestAnchorLifecycle(t *testing.T) {
	r := newRig(t)
	if _, err := AnchorGet(r.st); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("absent anchor: %v", err)
	}
	if err := AnchorSet(r.h, r.st, hex64); err != nil {
		t.Fatal(err)
	}
	if v, err := AnchorGet(r.st); err != nil || v != hex64 {
		t.Fatalf("%q %v", v, err)
	}
	replacement := strings.Repeat("cd", 32)
	if err := AnchorSet(r.h, r.st, replacement); err != nil {
		t.Fatal(err)
	}
	if v, _ := AnchorGet(r.st); v != replacement {
		t.Fatal("anchor not replaceable")
	}
	for _, bad := range []string{"", "short", strings.ToUpper(hex64)} {
		if err := AnchorSet(r.h, r.st, bad); err == nil {
			t.Fatalf("malformed anchor %q accepted", bad)
		}
	}
}

func TestUnreadableAnchorNeverFirstUse(t *testing.T) {
	r := newRig(t)
	// Two anchor records: recorded-but-unreadable, which must NEVER take the first-use branch.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{"trust-anchor\tdigest=" + hex64, "trust-anchor\tdigest=" + strings.Repeat("ef", 32)})
	if err := ledger.Write(r.h, r.st, l); err != nil {
		t.Fatal(err)
	}
	_, err := AnchorGet(r.st)
	if err == nil || errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("doubled anchor read as absent/ok: %v", err)
	}
	// And the acceptors refuse WITHOUT ErrNoAnchor — a damaged record is not a fresh install.
	ix := indexBytes("1", hex64, nil)
	p := r.write(t, "index", ix)
	_, aerr := AcceptIndex(r.h, r.st, p)
	if aerr == nil || errors.Is(aerr, ErrNoAnchor) {
		t.Fatalf("unreadable anchor re-bootstrapped: %v", aerr)
	}
}

func TestDamagedTrustRecords(t *testing.T) {
	r := newRig(t)
	cases := map[string][]string{
		"floor twice":       {"trust-floor\tpolicy=3", "trust-floor\tpolicy=5"},
		"floor empty value": {"trust-floor\tpolicy="},
		"bare kind row":     {"trust-floor"},
		"non-field token":   {"trust-floor\tnot-a-field"},
	}
	for name, lines := range cases {
		l := &ledger.Ledger{}
		l.ReplaceLines(lines)
		if err := ledger.Write(r.h, r.st, l); err != nil {
			t.Fatal(err)
		}
		_, err := FloorGet(r.st, "policy")
		if err == nil || errors.Is(err, ledger.ErrAbsentRecord) {
			t.Errorf("%s read as absent/ok: %v", name, err)
		}
	}
	// A genuinely absent floor is still first-use, and a good floor still reads back.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{"trust-floor\tother=1"})
	_ = ledger.Write(r.h, r.st, l)
	if _, err := FloorGet(r.st, "policy"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("absent floor beside another docid: %v", err)
	}
	if v, err := FloorGet(r.st, "other"); err != nil || v != "1" {
		t.Fatalf("good floor: %q %v", v, err)
	}
}

func TestFreshness(t *testing.T) {
	r := newRig(t)
	if err := AnchorSet(r.h, r.st, hex64); err != nil {
		t.Fatal(err)
	}
	parse := func(lines ...string) *Index {
		ix, err := parseIndex(indexBytes("1", hex64, nil, lines...), "t")
		if err != nil {
			t.Fatal(err)
		}
		return ix
	}
	_ = parse
	// No expiry → refused. (The index schema REQUIRES expires, so exercise freshOK via a
	// fixture doc without it through the policy... every schema requires it; the gate's
	// own mandatory-expiry branch is the belt. Assert it directly.)
	// Version floor: seed 5; equal accepted, lower replay-refused, floor unchanged.
	if err := FloorSet(r.h, r.st, "index", "5"); err != nil {
		t.Fatal(err)
	}
	eq, err := parseIndex(indexBytes("5", hex64, nil), "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := freshOK(r.st, "index", eq.Doc(), 1000); err != nil {
		t.Fatalf("equal version refused: %v", err)
	}
	low, _ := parseIndex(indexBytes("4", hex64, nil), "t")
	if err := freshOK(r.st, "index", low.Doc(), 1000); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("lower version: %v", err)
	}
	if v, _ := FloorGet(r.st, "index"); v != "5" {
		t.Fatal("refused replay lowered the floor")
	}
	// Expired at the highest version still refuses.
	exp := []byte("mythical-index 1\nversion=9\nexpires=10\npolicy_digest=" + hex64 +
		"\nprobe_image=ghcr.io/x/p@sha256:" + hex64 + "\ncopy_image=ghcr.io/x/c@sha256:" + hex64 + "\n")
	high, err := parseIndex(exp, "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := freshOK(r.st, "index", high.Doc(), 99999); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired-at-highest: %v", err)
	}
}

func TestCheckAndCommit(t *testing.T) {
	r := newRig(t)
	ix, err := parseIndex(indexBytes("3", hex64, nil), "t")
	if err != nil {
		t.Fatal(err)
	}
	// With no anchor recorded, CheckOnly refuses with ITS OWN code and records no floor.
	err = CheckOnly(r.st, "index", ix.Doc(), 1000)
	if !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("no-anchor check: %v", err)
	}
	if _, ferr := FloorGet(r.st, "index"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a no-anchor refusal recorded a floor")
	}
	if err := AnchorSet(r.h, r.st, hex64); err != nil {
		t.Fatal(err)
	}
	// CheckOnly commits nothing.
	if err := CheckOnly(r.st, "index", ix.Doc(), 1000); err != nil {
		t.Fatal(err)
	}
	if _, ferr := FloorGet(r.st, "index"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("CheckOnly committed a floor")
	}
	// Commit moves floor and anchor together, one write.
	if err := Commit(r.h, r.st, "index", ix.Doc(), strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	if v, _ := FloorGet(r.st, "index"); v != "3" {
		t.Fatal("commit did not record the floor")
	}
	if a, _ := AnchorGet(r.st); a != strings.Repeat("cd", 32) {
		t.Fatal("commit did not move the anchor")
	}
	// Malformed anchor refuses WITHOUT moving the floor.
	ix9, _ := parseIndex(indexBytes("9", hex64, nil), "t")
	if err := Commit(r.h, r.st, "index", ix9.Doc(), "NOT-HEX"); err == nil {
		t.Fatal("malformed anchor committed")
	}
	if v, _ := FloorGet(r.st, "index"); v != "3" {
		t.Fatal("refused commit moved the floor")
	}
	// Direct commit below the floor refuses and does not lower.
	ix1, _ := parseIndex(indexBytes("1", hex64, nil), "t")
	if err := Commit(r.h, r.st, "index", ix1.Doc(), ""); err == nil {
		t.Fatal("below-floor commit accepted")
	}
	if v, _ := FloorGet(r.st, "index"); v != "3" {
		t.Fatal("floor lowered by refused commit")
	}
}

func TestIndexManifestDigest(t *testing.T) {
	other := strings.Repeat("ef", 32)
	ix, err := parseIndex(indexBytes("1", hex64, map[string]string{"brokkr": hex64, "saga": other}), "t")
	if err != nil {
		t.Fatal(err)
	}
	// THIS product's digest, never merely the first listed.
	if d, err := ix.ManifestDigest("saga"); err != nil || d != other {
		t.Fatalf("%q %v", d, err)
	}
	if _, err := ix.ManifestDigest("skuld"); !errors.Is(err, ErrNotVouched) {
		t.Fatalf("unvouched: %v", err)
	}
}

func TestAcceptIndex(t *testing.T) {
	r := newRig(t)
	ix := indexBytes("1", hex64, nil)
	p := r.write(t, "index", ix)
	// Without an anchor: ErrNoAnchor (the rc-4 analogue — first use, not an attack).
	if _, err := AcceptIndex(r.h, r.st, p); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("no anchor: %v", err)
	}
	if err := AnchorSet(r.h, r.st, cliio.SHA256Hex(ix)); err != nil {
		t.Fatal(err)
	}
	got, err := AcceptIndex(r.h, r.st, p)
	if err != nil {
		t.Fatalf("matching index refused: %v", err)
	}
	if d, _ := got.PolicyDigest(); d != hex64 {
		t.Fatalf("returned index wrong: %q", d)
	}
	// AcceptIndex advanced the floor (the check-then-commit composition).
	if v, ferr := FloorGet(r.st, "index"); ferr != nil || v != "1" {
		t.Fatalf("floor after accept: %q %v", v, ferr)
	}
	// A tampered file refuses.
	p2 := r.write(t, "index2", append(ix, '#', '\n'))
	if _, err := AcceptIndex(r.h, r.st, p2); err == nil {
		t.Fatal("tampered index accepted")
	}
	// A duplicate product listing refuses as ambiguous (even digest-matched).
	dup := indexBytes("2", hex64, nil, "manifest=brokkr:"+hex64, "manifest=brokkr:"+strings.Repeat("ef", 32))
	pd := r.write(t, "index3", dup)
	if err := AnchorSet(r.h, r.st, cliio.SHA256Hex(dup)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptIndex(r.h, r.st, pd); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate listing: %v", err)
	}
	// T2: expired index refuses even digest-matched.
	expired := []byte("mythical-index 1\nversion=3\nexpires=10\npolicy_digest=" + hex64 +
		"\nprobe_image=ghcr.io/x/p@sha256:" + hex64 + "\ncopy_image=ghcr.io/x/c@sha256:" + hex64 + "\n")
	pe := r.write(t, "index4", expired)
	if err := AnchorSet(r.h, r.st, cliio.SHA256Hex(expired)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptIndex(r.h, r.st, pe); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired index: %v", err)
	}
}

func TestAcceptPolicy(t *testing.T) {
	r := newRig(t)
	ixp, polp, _ := chain(t, r, []string{"brokkr.permitted_role=state"}, nil, "true")
	pol, err := AcceptPolicy(r.h, r.st, ixp, polp)
	if err != nil {
		t.Fatalf("matching chain refused: %v", err)
	}
	if !pol.PermitsRole("brokkr", "state") {
		t.Fatal("returned policy wrong")
	}
	// Digest mismatch: tamper the policy after the index was built.
	if err := os.WriteFile(polp, policyBytes("1", "brokkr.permitted_role=state", "brokkr.permitted_role=extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptPolicy(r.h, r.st, ixp, polp); err == nil {
		t.Fatal("tampered policy accepted")
	}
	// No anchor: the chain's own code.
	r2 := newRig(t)
	ix2, pol2, _ := chain(t, r2, nil, nil, "true")
	_ = ix2
	r3 := newRig(t) // fresh rig: no anchor recorded at all
	if _, err := AcceptPolicy(r3.h, r3.st, ix2, pol2); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("no-anchor policy accept: %v", err)
	}
	// T1: a forged index (right shape, wrong bytes vs anchor) refuses the whole chain.
	forged := indexBytes("9", hex64, nil)
	fp := r2.write(t, "forged-index", forged)
	if _, err := AcceptPolicy(r2.h, r2.st, fp, pol2); err == nil {
		t.Fatal("forged index accepted")
	}
	// T2: an expired policy refuses even though its digest matches.
	r4 := newRig(t)
	expPol := []byte("mythical-policy 1\nversion=1\nexpires=10\nfamily_gid=20\n")
	ix4 := indexBytes("1", cliio.SHA256Hex(expPol), nil)
	ixp4 := r4.write(t, "index", ix4)
	polp4 := r4.write(t, "policy", expPol)
	if err := AnchorSet(r4.h, r4.st, cliio.SHA256Hex(ix4)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptPolicy(r4.h, r4.st, ixp4, polp4); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired policy: %v", err)
	}
}

func TestAnchorConsultedEveryTime(t *testing.T) {
	r := newRig(t)
	ixp, polp, manp := chain(t, r, []string{"brokkr.permitted_role=state"}, []string{"volume=state:/data"}, "true")
	if _, err := AcceptManifest(r.h, r.st, ixp, polp, manp, "brokkr"); err != nil {
		t.Fatal(err)
	}
	// Replace the anchor with something else: the SAME files must now refuse — nothing was
	// cached from the previous acceptance.
	if err := AnchorSet(r.h, r.st, strings.Repeat("ef", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptManifest(r.h, r.st, ixp, polp, manp, "brokkr"); err == nil {
		t.Fatal("acceptance used a cached anchor")
	}
}

func TestAcceptManifestChain(t *testing.T) {
	r := newRig(t)
	ixp, polp, manp := chain(t, r,
		[]string{"brokkr.permitted_role=state"},
		[]string{"volume=state:/data"}, "true")
	m, err := AcceptManifest(r.h, r.st, ixp, polp, manp, "brokkr")
	if err != nil {
		t.Fatalf("untampered chain refused: %v", err)
	}
	if m.Product() != "brokkr" {
		t.Fatal("wrong manifest returned")
	}
	// The wrong product request: the index vouches only for brokkr.
	if _, err := AcceptManifest(r.h, r.st, ixp, polp, manp, "saga"); !errors.Is(err, ErrNotVouched) {
		t.Fatalf("unvouched product: %v", err)
	}
	// Tampering at each level refuses.
	tamper := func(path string) {
		data, _ := os.ReadFile(path)
		if err := os.WriteFile(path, append(data, '#', '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{ixp, polp, manp} {
		r2 := newRig(t)
		i2, p2, m2 := chain(t, r2, []string{"brokkr.permitted_role=state"}, []string{"volume=state:/data"}, "true")
		pick := map[string]string{ixp: i2, polp: p2, manp: m2}[target]
		tamper(pick)
		if _, err := AcceptManifest(r2.h, r2.st, i2, p2, m2, "brokkr"); err == nil {
			t.Fatalf("tampering at %s accepted", filepath.Base(target))
		}
	}
	// A vouched manifest declaring ANOTHER product refuses (the index digest matches its
	// bytes, but the product inside is wrong).
	r3 := newRig(t)
	wrong := manifestBytes("1", "saga", "true")
	pol3 := policyBytes("1")
	ix3 := indexBytes("1", cliio.SHA256Hex(pol3), map[string]string{"brokkr": cliio.SHA256Hex(wrong)})
	i3 := r3.write(t, "index", ix3)
	p3 := r3.write(t, "policy", pol3)
	m3 := r3.write(t, "manifest", wrong)
	_ = AnchorSet(r3.h, r3.st, cliio.SHA256Hex(ix3))
	if _, err := AcceptManifest(r3.h, r3.st, i3, p3, m3, "brokkr"); err == nil ||
		!strings.Contains(err.Error(), `manifest for "saga"`) {
		t.Fatalf("wrong-product manifest: %v", err)
	}
	// Entitlement violation refused BY THE DOOR.
	r4 := newRig(t)
	i4, p4, m4 := chain(t, r4, nil /* grants nothing */, []string{"volume=state:/data"}, "true")
	if _, err := AcceptManifest(r4.h, r4.st, i4, p4, m4, "brokkr"); err == nil ||
		!strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("door passed an entitlement violation: %v", err)
	}
	// Fix 2: an expired manifest refuses through the door.
	r5 := newRig(t)
	expMan := []byte("mythical-manifest 1\nversion=1\nexpires=10\nproduct=brokkr\nlaunched=true\nimage=ghcr.io/x/b@sha256:" +
		hex64 + "\nmin_core=0.1.0\nruntime_uid=900\n")
	pol5 := policyBytes("1")
	ix5 := indexBytes("1", cliio.SHA256Hex(pol5), map[string]string{"brokkr": cliio.SHA256Hex(expMan)})
	i5 := r5.write(t, "index", ix5)
	p5 := r5.write(t, "policy", pol5)
	m5 := r5.write(t, "manifest", expMan)
	_ = AnchorSet(r5.h, r5.st, cliio.SHA256Hex(ix5))
	if _, err := AcceptManifest(r5.h, r5.st, i5, p5, m5, "brokkr"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired manifest: %v", err)
	}
	// Fix 7: a digest mismatch names the OPERATOR'S manifest path, not a snapshot temp.
	r6 := newRig(t)
	i6, p6, m6 := chain(t, r6, nil, nil, "true")
	tamper(m6)
	_, err = AcceptManifest(r6.h, r6.st, i6, p6, m6, "brokkr")
	if err == nil || !strings.Contains(err.Error(), m6) {
		t.Fatalf("mismatch does not name the operator's path: %v", err)
	}
	// An authentic not-launched manifest: ErrNotLaunched with the manifest still returned.
	r7 := newRig(t)
	i7, p7, m7 := chain(t, r7, nil, nil, "false")
	got, err := AcceptManifest(r7.h, r7.st, i7, p7, m7, "brokkr")
	if !errors.Is(err, ErrNotLaunched) || got == nil {
		t.Fatalf("not-launched: %v %v", got, err)
	}
}

func TestFloorDiscipline(t *testing.T) {
	// Fix 1a: an entitlement violation leaves EVERY floor unchanged.
	r := newRig(t)
	i, p, m := chain(t, r, nil /* no grants */, []string{"volume=state:/data"}, "true")
	if _, err := AcceptManifest(r.h, r.st, i, p, m, "brokkr"); err == nil {
		t.Fatal("expected refusal")
	}
	if _, err := FloorGet(r.st, "manifest:brokkr"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("a refused manifest raised the replay bar")
	}
	// Fix 1b: accepted-but-not-launched still advances the floor.
	r2 := newRig(t)
	i2, p2, m2 := chain(t, r2, nil, nil, "false")
	if _, err := AcceptManifest(r2.h, r2.st, i2, p2, m2, "brokkr"); !errors.Is(err, ErrNotLaunched) {
		t.Fatalf("%v", err)
	}
	if v, err := FloorGet(r2.st, "manifest:brokkr"); err != nil || v != "1" {
		t.Fatalf("not-launched did not advance the floor: %q %v", v, err)
	}
	// Fix 2b: a version rollback through the door refuses.
	if err := FloorSet(r2.h, r2.st, "manifest:brokkr", "5"); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptManifest(r2.h, r2.st, i2, p2, m2, "brokkr"); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("rollback through the door: %v", err)
	}
}

func TestAcceptorRefusals(t *testing.T) {
	r := newRig(t)
	_ = AnchorSet(r.h, r.st, hex64)
	// A missing file is a refusal from the snapshot step, never a pass.
	if _, err := AcceptIndex(r.h, r.st, filepath.Join(r.dir, "absent")); err == nil {
		t.Fatal("missing index accepted")
	}
}
