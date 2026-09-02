package policy

import (
	"strings"
	"testing"
)

// Inventory — tests/unit/policy.bats (this task owns the load/predicate rows; the acceptance
// rows — mi_accept_policy end-to-end, digest mismatch, no-anchor, T1 forged index, T2 expired
// policy — are owned by the trust task, which builds the acceptors):
// PORTED: tests/unit/policy.bats: "a valid policy index loads" -> TestValidPolicyLoads
// PORTED: tests/unit/policy.bats: "a bindable role that is not permitted is rejected" -> TestStructuralInvariants
// PORTED: tests/unit/policy.bats: "a precious role that is also permitted loads" -> TestPrecious
// PORTED: tests/unit/policy.bats: "a precious role that is NOT permitted is rejected as malformed, not silently ignored" -> TestStructuralInvariants
// PORTED: tests/unit/policy.bats: "precious and bindable COMPOSE — precious data is exactly what an operator relocates" -> TestPrecious
// PORTED: tests/unit/policy.bats: "mi_policy_precious matches whole records — never a prefix, and never another product's" -> TestWholeRecordMatching
// PORTED: tests/unit/policy.bats: "a bindable SECRETS role is rejected outright" -> TestStructuralInvariants
// PORTED: tests/unit/policy.bats: "a permitted secrets role that is NOT bindable is fine — that is the point of two lists" -> TestValidPolicyLoads
// PORTED: tests/unit/policy.bats: "entitlements do not bleed between products" -> TestWholeRecordMatching
// PORTED: tests/unit/policy.bats: "an unknown product is entitled to nothing" -> TestWholeRecordMatching
// PORTED: tests/unit/policy.bats: "bindable is queried separately from permitted" -> TestBindableQuery
// PORTED: tests/unit/policy.bats: "a value substring does not satisfy an entitlement" -> TestWholeRecordMatching
// PORTED: tests/unit/policy.bats: "a product name that is not an identifier is rejected" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "a policy without family_gid is rejected" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "a repeated document key is rejected — freshness must not be ambiguous" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "document keys may not be product-prefixed" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "entitlement keys must be product-prefixed" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "an unknown entitlement key is rejected, not ignored" -> TestSchemaRefusals
// PORTED: tests/unit/policy.bats: "the wrong document type is rejected" -> TestSchemaRefusals
// N/A: tests/unit/policy.bats: "the query functions refuse bad arity instead of aborting under set -u" -- compile-time arity
// PORTED: tests/unit/policy.bats: "a policy that declares a gid returns it via mi_policy_family_gid" -> TestFamilyGID
// PORTED: tests/unit/policy.bats: "family_gid absence is propagated as a failure, never a default" -> TestSchemaRefusals -- absence rejects at parse — a Policy value always answers; no default exists anywhere
// PORTED: tests/unit/policy.bats: "a malformed or out-of-range family_gid is rejected at load, not waved through" -> TestSchemaRefusals
// (policy.bats: "mi_accept_policy end to end: a matching chain is accepted and its records returned" — owned by the trust task)
// (policy.bats: "mi_accept_policy refuses when the policy file's digest does not match the index" — owned by the trust task)
// (policy.bats: "mi_accept_policy refuses with the chain's own code when no anchor has been accepted" — owned by the trust task)
// (policy.bats: "T1: mi_accept_policy refuses a forged index it would otherwise merely re-parse" — owned by the trust task)
// (policy.bats: "T2: mi_accept_policy refuses an expired policy even though its digest matches" — owned by the trust task)

func doc(lines ...string) []byte {
	base := []string{"version=1", "expires=99999999999", "family_gid=20"}
	return []byte("mythical-policy 1\n" + strings.Join(append(base, lines...), "\n") + "\n")
}

func mustParse(t *testing.T, data []byte) *Policy {
	t.Helper()
	p, err := ParseVerified(data, "t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidPolicyLoads(t *testing.T) {
	p := mustParse(t, doc(
		"brokkr.permitted_role=data",
		"brokkr.permitted_role=secrets", // permitted and NOT bindable: that is the point
		"brokkr.bindable_role=data",
		"brokkr.permitted_secret=bootstrap-token",
		"brokkr.permitted_mount=transcripts",
	))
	if !p.PermitsRole("brokkr", "data") || !p.PermitsRole("brokkr", "secrets") {
		t.Fatal("permitted roles missing")
	}
	if !p.PermitsSecret("brokkr", "bootstrap-token") || !p.PermitsMount("brokkr", "transcripts") {
		t.Fatal("typed predicates missing")
	}
}

func TestStructuralInvariants(t *testing.T) {
	// bindable not permitted → malformed.
	if _, err := ParseVerified(doc("brokkr.bindable_role=data"), "t"); err == nil ||
		!strings.Contains(err.Error(), "subset of permitted") {
		t.Fatalf("bindable⊄permitted: %v", err)
	}
	// precious not permitted → malformed, NOT silently ignored.
	if _, err := ParseVerified(doc("brokkr.precious_role=data"), "t"); err == nil ||
		!strings.Contains(err.Error(), "precious") {
		t.Fatalf("precious⊄permitted: %v", err)
	}
	// a bindable SECRETS role → rejected outright, even when permitted.
	if _, err := ParseVerified(doc(
		"brokkr.permitted_role=secrets", "brokkr.bindable_role=secrets"), "t"); err == nil ||
		!strings.Contains(err.Error(), "secrets") {
		t.Fatalf("bindable secrets: %v", err)
	}
}

func TestPrecious(t *testing.T) {
	p := mustParse(t, doc(
		"brokkr.permitted_role=data",
		"brokkr.bindable_role=data",
		"brokkr.precious_role=data", // precious AND bindable compose freely
	))
	if !p.Precious("brokkr", "data") {
		t.Fatal("declared precious not reported")
	}
	if !p.Bindable("brokkr", "data") {
		t.Fatal("precious flattened bindability")
	}
	// Absence of a claim is false — the CALLER treats unknown as precious; the predicate
	// answers only what the document says.
	if p.Precious("brokkr", "logs") {
		t.Fatal("silence read as a claim")
	}
}

func TestWholeRecordMatching(t *testing.T) {
	p := mustParse(t, doc(
		"brokkr.permitted_role=state",
		"saga.permitted_role=metrics",
	))
	// Never a prefix.
	if p.PermitsRole("brokkr", "stat") || p.PermitsRole("brokkr", "state2") {
		t.Fatal("substring satisfied an entitlement")
	}
	// Never across products.
	if p.PermitsRole("saga", "state") || p.PermitsRole("brokkr", "metrics") {
		t.Fatal("entitlement bled between products")
	}
	// An unknown product is entitled to nothing (including a non-ident name).
	if p.PermitsRole("skuld", "state") || p.PermitsRole("../evil", "state") {
		t.Fatal("unknown product entitled")
	}
	if p.Precious("saga", "metricsX") || p.Precious("brokkr", "metrics") {
		t.Fatal("precious matched loosely")
	}
}

func TestBindableQuery(t *testing.T) {
	p := mustParse(t, doc("brokkr.permitted_role=data", "brokkr.permitted_role=logs",
		"brokkr.bindable_role=data"))
	if !p.Bindable("brokkr", "data") {
		t.Fatal("bindable role missing")
	}
	if p.Bindable("brokkr", "logs") {
		t.Fatal("permitted read as bindable")
	}
}

func TestSchemaRefusals(t *testing.T) {
	cases := map[string][]byte{
		"product-prefixed document key": doc("brokkr.version=99"),
		"unprefixed entitlement":        doc("permitted_role=state"),
		"unknown entitlement key":       doc("brokkr.surprise_role=x"),
		"non-ident product prefix":      []byte("mythical-policy 1\nversion=1\nexpires=1\nfamily_gid=20\n2bad.permitted_role=x\n"),
		"missing family_gid":            []byte("mythical-policy 1\nversion=1\nexpires=1\n"),
		"repeated document key":         []byte("mythical-policy 1\nversion=1\nversion=2\nexpires=1\nfamily_gid=20\n"),
		"wrong document type":           []byte("mythical-manifest 1\nversion=1\nexpires=1\nfamily_gid=20\n"),
		"family_gid zero":               []byte("mythical-policy 1\nversion=1\nexpires=1\nfamily_gid=0\n"),
		"family_gid non-numeric":        []byte("mythical-policy 1\nversion=1\nexpires=1\nfamily_gid=staff\n"),
	}
	for name, data := range cases {
		if _, err := ParseVerified(data, "t"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFamilyGID(t *testing.T) {
	p := mustParse(t, doc())
	if v, ok := p.FamilyGID(); !ok || v != "20" {
		t.Fatalf("FamilyGID = %q, %v", v, ok)
	}
}
