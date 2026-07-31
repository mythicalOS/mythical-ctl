#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env
  load_mctl
  # mi_accept_policy's tests (below) write trust state through the family lock, the same way
  # tests/unit/trust.bats' setup() does — an empty ledger is a valid one, and every other test in
  # this file simply ignores the lock/ledger it does not need.
  mi_ensure_layout
  mi_lock_acquire
  printf '' | mi_ledger_write          # an empty but valid ledger
  F="$MYTHICAL_HOME/policy"
}

# family_gid is REQUIRED (D60), so every fixture that is meant to be otherwise valid carries it.
pol() { { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'; printf '%s\n' "$1"; } > "$F"; }

VALID='brokkr.permitted_role=state
brokkr.permitted_role=secrets
brokkr.bindable_role=state
brokkr.permitted_secret=MYTHICAL_TELEMETRY_KEY
brokkr.permitted_mount=transcripts
skuld.permitted_role=state
skuld.bindable_role=state'

@test "a valid policy index loads" {
  pol "$VALID"
  run mi_policy_load "$F"
  [ "$status" -eq 0 ]
}

# D53 / §10a: "policy index collapsing permitted and bindable | rejected as malformed — a secrets
# role must be permitted AND non-bindable, which one list cannot express".
@test "a bindable role that is not permitted is rejected" {
  pol "$(printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=logs')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *logs* ]] || { echo "output missing logs: $output" >&2; return 1; }
  [[ "$output" == *permitted* ]]
}

@test "a bindable SECRETS role is rejected outright" {
  pol "$(printf 'brokkr.permitted_role=secrets\nbrokkr.bindable_role=secrets')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *secrets* ]]
}

@test "a permitted secrets role that is NOT bindable is fine — that is the point of two lists" {
  pol "$(printf 'brokkr.permitted_role=secrets\nbrokkr.permitted_role=state\nbrokkr.bindable_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 0 ]
}

@test "entitlements do not bleed between products" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" brokkr role secrets;  [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  role secrets;  [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr secret MYTHICAL_TELEMETRY_KEY; [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  secret MYTHICAL_TELEMETRY_KEY; [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr mount transcripts; [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  mount transcripts; [ "$status" -ne 0 ]
}

@test "an unknown product is entitled to nothing" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" ghost role state
  [ "$status" -ne 0 ]
}

@test "bindable is queried separately from permitted" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_bindable "$p" brokkr state;   [ "$status" -eq 0 ]
  run mi_policy_bindable "$p" brokkr secrets; [ "$status" -ne 0 ]
  run mi_policy_permits  "$p" brokkr role secrets; [ "$status" -eq 0 ]
}

@test "a value substring does not satisfy an entitlement" {
  pol "$(printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state')"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" brokkr role stat;    [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr role states;  [ "$status" -ne 0 ]
}

@test "a product name that is not an identifier is rejected" {
  pol "$(printf 'Brokkr.permitted_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

# A product-prefixed document key is meaningless; an unprefixed entitlement grants nobody anything.
# Both used to validate, which on the authorization document is a silent misconfiguration.
# D60's gid is what makes the amended Plan 2 signature answerable. Declared `one` in the spec and
# required by nothing, a policy would authenticate, load, and then answer "absent" to it.
@test "a policy without family_gid is rejected" {
  { printf 'mythical-policy 1\nversion=1\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *family_gid* ]]
}

@test "a repeated document key is rejected — freshness must not be ambiguous" {
  pol "$(printf 'brokkr.permitted_role=state')"
  # two version lines: the header already supplies one
  { printf 'mythical-policy 1\nversion=1\nversion=2\nfamily_gid=60748\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *version* ]] || { echo "output missing version: $output" >&2; return 1; }
  { printf 'mythical-policy 1\nversion=1\nfamily_gid=60748\nexpires=1\nexpires=2\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "document keys may not be product-prefixed" {
  pol "$(printf 'brokkr.version=99')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  pol "$(printf 'brokkr.expires=5')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "entitlement keys must be product-prefixed" {
  pol "$(printf 'permitted_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *permitted_role* ]]
}

@test "an unknown entitlement key is rejected, not ignored" {
  pol "$(printf 'brokkr.permitted_everything=yes')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "the wrong document type is rejected" {
  { printf 'mythical-manifest 1\nversion=1\nfamily_gid=60748\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "the query functions refuse bad arity instead of aborting under set -u" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger doc trust policy; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_policy_permits "" brokkr; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]] || { echo "continued past UNREACHABLE (arity guard did not abort): $output" >&2; return 1; }
  [[ "$output" != *"unbound variable"* ]]
}

# --- D60: the family gid, and nowhere else ----------------------------------------------------------
#
# mi_policy_family_gid is "the sole authenticated source of the family group id" (lib/policy.sh) — the
# config writer's own hardcoded default was deliberately removed so that this function would be the
# only authority left for it. A regression that quietly reintroduced one here would be the exact
# second-authority problem D60 exists to close, and nothing above catches it: every test that reaches
# this function so far does so through a fixture that always carries a real family_gid.

@test "a policy that declares a gid returns it via mi_policy_family_gid" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_family_gid "$p"
  [ "$status" -eq 0 ]
  [ "$output" = "60748" ]
}

# mi_policy_load already refuses to load a policy with no family_gid at all (D60, tested above), so
# the front door cannot be used to hand mi_policy_family_gid a family_gid-less record set — its own
# contract has to be pinned directly, on hand-built records, the same way tests/unit/trust.bats pins
# mi_doc_value's absence behaviour rather than only exercising it through a full document load.
#
# THIS is the test that catches a fallback: mutate the function to print a hardcoded gid when the key
# is absent instead of failing, and this is the only assertion in the suite that goes red for it —
# every other test here supplies a family_gid and would not notice a default sitting behind it.
@test "family_gid absence is propagated as a failure, never a default" {
  local records; records="$(printf 'version\t1\nexpires\t4102444800\n')"
  run mi_policy_family_gid "$records"
  [ "$status" -eq 3 ]
  [ -z "$output" ] || { echo "absence produced output '$output' instead of nothing" >&2; return 1; }
}

# D60's typed floor (int:1:4294967295) is enforced where the value is PARSED — mi_policy_load, via the
# doc-spec type check — not re-checked by mi_policy_family_gid, which is a pure accessor over already-
# validated records and has no type rule of its own. Pinning the rejection here, at the site that
# actually performs it, is what keeps this test meaningful if mi_policy_family_gid's implementation
# ever changes: asserting it on the accessor instead would pass vacuously, because a malformed value
# never reaches it — mi_policy_load has already refused the whole document.
@test "a malformed or out-of-range family_gid is rejected at load, not waved through" {
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=notanumber\n'
    printf 'brokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]

  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=0\n'
    printf 'brokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]

  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=4294967296\n'
    printf 'brokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

# --- mi_accept_policy: the acceptance door (§8.1 — "a digest is not authentication") -----------------
#
# No test above calls mi_accept_policy at all: everything else exercises mi_policy_load directly, on a
# file the test wrote and trusts by construction. mi_accept_policy is the function that decides whether
# an OPERATOR's policy file may be trusted — it re-establishes the chain from the persisted anchor
# through the authenticated family index (mi_accept_index, covered on its own in tests/unit/trust.bats)
# and only then checks the policy file's own digest against what that index vouches for. What is
# missing is proof that mi_accept_policy actually wires those two checks together end to end, in the
# order that makes the digest check an authentication boundary rather than a bare comparison.

mkchain() {   # writes $MYTHICAL_HOME/{policy,index}; does NOT set the anchor
  local d="$MYTHICAL_HOME"
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state\n'; } > "$d/policy"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' \
      "$(mi_digest "$d/policy")"
    index_helper_images; } > "$d/index"
}

@test "mi_accept_policy end to end: a matching chain is accepted and its records come back" {
  mkchain
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  run mi_accept_policy "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy"
  [ "$status" -eq 0 ]
  [[ "$output" == *$'family_gid\t60748'* ]] \
    || { echo "output missing a family_gid record: $output" >&2; return 1; }
}

# The case that must never pass. Everything about the chain is genuinely valid — the anchor matches
# the index's real bytes, the index parses, the policy file parses — EXCEPT the index vouches for a
# different policy digest than the file's real one. A digest is not authentication (§8.1): the index
# saying "the policy is X" is only as good as checking the file actually hashes to X, and this is the
# only test in the suite that exercises that check with everything else around it held valid. A
# reviewer who forces mi_accept_policy's digest gate to succeed unconditionally passes every other
# test in this file and fails only this one.
@test "mi_accept_policy refuses when the policy file's digest does not match what the index vouches for" {
  mkchain
  local d="$MYTHICAL_HOME" bogus
  bogus="$(printf 'b%.0s' {1..64})"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$bogus"
    index_helper_images; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_policy "$d/index" "$d/policy"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$bogus"* ]] \
    || { echo "output missing the vouched-for (expected) digest $bogus: $output" >&2; return 1; }
}

# §8.1: without a recorded anchor there is no offline reuse. mi_accept_index reports this with its own
# code (4), distinct from a refused digest (1), because the two need different operator responses — and
# mi_accept_policy is documented to propagate that same code (rc 0 · 1 refused · 4 no anchor) rather
# than flattening it to a generic refusal. Asserting the specific code, not just non-zero, is what
# distinguishes this case from the digest-mismatch one above.
@test "mi_accept_policy refuses with the chain's own code when no anchor has ever been recorded" {
  mkchain
  run mi_accept_policy "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy"
  [ "$status" -eq 4 ]
}

# T1: mi_accept_policy's own first step is to AUTHENTICATE the family index (mi_accept_index), not
# merely parse it (mi_index_load) — the two have the same signature and same success shape (records
# on stdout), so a swap at this call site changes nothing about how the rest of the function reads.
# Every other test in this file either never reaches mi_accept_index at all, or supplies a chain
# where the index file on disk still matches the recorded anchor — so a swap to the unauthenticated
# parser is invisible to them. This is the one case that is not: the anchor is recorded for the
# REAL index, then the cached index file is rewritten (as an attacker with local write access but
# not the anchor could) to vouch for a forged policy that grants an unentitled role. An authenticated
# door refuses on the digest mismatch; a door that merely parsed the index would sail through and
# hand back the forged entitlements.
@test "T1: mi_accept_policy refuses a forged index it would otherwise merely have parsed" {
  mkchain
  local d="$MYTHICAL_HOME"
  mi_trust_anchor_set "$(mi_digest "$d/index")"     # anchors the REAL, untampered index
  # D53-valid on its own (permitted, not bindable) so the only thing standing between an attacker
  # and acceptance is the index's OWN authentication — not an unrelated structural refusal.
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=1\n'
    printf 'brokkr.permitted_role=secrets\n'; } > "$d/forged-policy"
  # An attacker who can write the cached index (but not the anchor) points it at the forged policy,
  # without ever touching the recorded anchor.
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' \
      "$(mi_digest "$d/forged-policy")"
    index_helper_images; } > "$d/index"
  run mi_accept_policy "$d/index" "$d/forged-policy"
  [ "$status" -eq 1 ] || { echo "a forged index was accepted, status=$status: $output" >&2; return 1; }
  [[ "$output" == *digest* ]] || { echo "output missing a digest-mismatch message: $output" >&2; return 1; }
}

# T2: the freshness gate (mi_trust_check policy "$records") is the WIRING at this door, not the
# predicate itself — _mi_trust_fresh_ok is already well tested on its own. Nothing above exercises an
# EXPIRED policy through mi_accept_policy: every fixture in this file uses the same far-future
# `expires=4102444800`. Deleting the mi_trust_check call would accept an expired policy forever, which
# is the exact replay §8.1's mandatory expiry field exists to close.
@test "T2: mi_accept_policy refuses an expired policy even though its digest matches the index" {
  local d="$MYTHICAL_HOME"
  { printf 'mythical-policy 1\nversion=1\nexpires=1\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state\n'; } > "$d/policy"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' \
      "$(mi_digest "$d/policy")"
    index_helper_images; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_policy "$d/index" "$d/policy"
  [ "$status" -eq 1 ] || { echo "an expired policy was accepted, status=$status: $output" >&2; return 1; }
  [[ "$output" == *expired* ]] || { echo "output missing 'expired': $output" >&2; return 1; }
}
