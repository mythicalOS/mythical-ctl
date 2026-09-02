// Package policy is the family policy index (D21/D53, §8.1): product identity → what it may
// have.
//
// This document exists because AUTHENTICITY IS NOT AUTHORIZATION. A manifest signed by its
// real publisher can still ask for a sibling's state volume or another product's bootstrap
// secret; signature checking answers "who wrote this", never "may it have this". Entitlements
// therefore cannot come from the manifest — and cannot be hardcoded in the core, which carries
// no product-specific logic (§7). So they come from this third authenticated document.
package policy

import (
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/docfmt"
)

// SecretsRole is the role whose entire purpose is to be permitted but never bindable (D5).
const SecretsRole = "secrets"

// Spec is the policy schema: TWO scopes, and the split is enforced, because a single union
// spec accepts two kinds of nonsense a publisher would never see — `brokkr.version=99` (a
// product-prefixed DOCUMENT key: meaningless, and it would validate) and
// `permitted_role=state` (an UNPREFIXED entitlement: it entitles nobody, silently — on the one
// document whose whole job is authorization, a typo that grants nothing and reports nothing is
// the worst possible failure mode). The Fixed map carries the never-prefixed document keys;
// the Dynamic resolver admits ONLY product-prefixed entitlement keys whose prefix is a valid
// identifier.
func Spec() docfmt.Schema {
	entitlements := map[string]docfmt.KeySpec{
		"permitted_role": docfmt.Typed(docfmt.Many, "ident"),
		"bindable_role":  docfmt.Typed(docfmt.Many, "ident"),
		// A data-class declaration, not a permission: a role whose volume holds data that
		// CANNOT be regenerated. It grants and denies nothing; the purge and status paths key
		// on it. It lives HERE because a manifest that under-declared its own data class would
		// buy itself a quieter purge — authenticity is not authorization, self-description
		// included. Deliberately composable with bindable: precious data is exactly what an
		// operator most legitimately relocates.
		"precious_role":    docfmt.Typed(docfmt.Many, "ident"),
		"permitted_secret": docfmt.Typed(docfmt.Many, "str:128"),
		"permitted_mount":  docfmt.Typed(docfmt.Many, "ident"),
	}
	return docfmt.Schema{
		Type: "policy",
		Fixed: map[string]docfmt.KeySpec{
			"version": docfmt.Typed(docfmt.One, "docver"),
			"expires": docfmt.Typed(docfmt.One, "epoch"),
			// D60: the canonical family gid is "fixed in the policy index". REQUIRED — a
			// policy that cannot answer it leaves the core with no authenticated value, and a
			// hard-coded default is exactly the authority model D60 replaces.
			"family_gid": docfmt.Typed(docfmt.One, "int:1:4294967295"),
		},
		Dynamic: func(key string) (docfmt.KeySpec, bool) {
			head, rest, dotted := strings.Cut(key, ".")
			if !dotted || !docfmt.IdentOK(head) {
				return docfmt.KeySpec{}, false
			}
			ks, ok := entitlements[rest]
			return ks, ok
		},
	}
}

// Policy is a parsed, structurally-validated policy index. Constructible ONLY through
// ParseVerified — which the trust acceptors alone may call (check.sh's boundary gate) — so
// lifecycle code cannot hold a policy that did not pass through authentication.
type Policy struct {
	doc *docfmt.Doc
}

// ParseVerified parses already-digest-verified bytes and enforces the structural invariants
// (D53/§10a): bindable ⊆ permitted, ALWAYS; the secrets role is never bindable; precious ⊆
// permitted. A policy that collapses the lists is REJECTED AS MALFORMED, never silently
// repaired — "permitted" would otherwise quietly come to mean "migratable to any host path",
// which is precisely how a product's 0600 credential store becomes a one-liner to relocate.
func ParseVerified(data []byte, label string) (*Policy, error) {
	doc, err := docfmt.Parse(data, label, Spec())
	if err != nil {
		return nil, err
	}
	p := &Policy{doc: doc}
	for _, kv := range pairsOf(doc, "bindable_role") {
		if kv.value == SecretsRole {
			return nil, fmt.Errorf("policy: %s: %s's %q role is declared bindable — a secrets role must be permitted and NOT bindable (D53)", label, kv.product, kv.value)
		}
		if !p.PermitsRole(kv.product, kv.value) {
			return nil, fmt.Errorf("policy: %s: %s's %q role is bindable but not permitted — bindable must be a subset of permitted (D53)", label, kv.product, kv.value)
		}
	}
	for _, kv := range pairsOf(doc, "precious_role") {
		// A declaration about an unpermitted role classifies a volume this installation will
		// never create — the operator believes their unrecoverable data is flagged while the
		// purge path will never see the flag. Malformed, not ignored.
		if !p.PermitsRole(kv.product, kv.value) {
			return nil, fmt.Errorf("policy: %s: %s's %q role is declared precious but not permitted — precious must be a subset of permitted", label, kv.product, kv.value)
		}
	}
	return p, nil
}

type prodVal struct{ product, value string }

// pairsOf lists every `<product>.<key>` entry. The docfmt schema already proved every dynamic
// key well-formed, so the split cannot fail.
func pairsOf(doc *docfmt.Doc, key string) []prodVal {
	var out []prodVal
	for _, full := range doc.Keys() {
		head, rest, dotted := strings.Cut(full, ".")
		if !dotted || rest != key {
			continue
		}
		for _, v := range doc.Values(full) {
			out = append(out, prodVal{head, v})
		}
	}
	return out
}

// has answers one whole-record entitlement lookup: the exact `<product>.<key>` carrying the
// exact value — never a substring (`state` must not satisfy `stat`), never bleeding between
// products.
func (p *Policy) has(product, key, value string) bool {
	if !docfmt.IdentOK(product) {
		return false
	}
	for _, v := range p.doc.Values(product + "." + key) {
		if v == value {
			return true
		}
	}
	return false
}

// PermitsRole / PermitsSecret / PermitsMount — one method per entitlement class, never a
// stringly capability argument that collapses kind and value.
func (p *Policy) PermitsRole(product, role string) bool {
	return p.has(product, "permitted_role", role)
}
func (p *Policy) PermitsSecret(product, name string) bool {
	return p.has(product, "permitted_secret", name)
}
func (p *Policy) PermitsMount(product, mount string) bool {
	return p.has(product, "permitted_mount", mount)
}

// Bindable is queried separately from permitted — the subset rule is load-time structure, the
// query is its own question.
func (p *Policy) Bindable(product, role string) bool {
	return p.has(product, "bindable_role", role)
}

// Precious: true iff the role is DECLARED unregenerable. False means "this policy made no
// claim" — which is NOT "safe to delete": callers deciding whether to destroy data treat the
// absence of a claim as unknown, and unknown as precious. This predicate answers what the
// document says; not reading silence as permission is the caller's job.
func (p *Policy) Precious(product, role string) bool {
	return p.has(product, "precious_role", role)
}

// Doc exposes the underlying immutable document for the trust gate's freshness checks —
// internal wiring, nothing a consumer can mutate.
func (p *Policy) Doc() *docfmt.Doc { return p.doc }

// FamilyGID is D60's canonical family gid, from the authenticated index and nowhere else.
// The schema requires it, so a parsed policy always answers.
func (p *Policy) FamilyGID() (string, bool) { return p.doc.Value("family_gid") }

// Expired proxies the document's freshness check for the acceptors.
func (p *Policy) Expired(nowUnix int64) (bool, error) { return p.doc.Expired(nowUnix) }
