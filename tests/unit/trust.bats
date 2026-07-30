#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env
  load_mctl
  mi_ensure_layout
  mi_lock_acquire
  printf '' | mi_ledger_write          # an empty but valid ledger
}

@test "digest verification accepts a match and reports both sides on mismatch" {
  local f="$MYTHICAL_HOME/x"; printf 'hello\n' > "$f"
  run mi_trust_verify_digest "$f" "$(mi_digest "$f")"
  [ "$status" -eq 0 ]
  run mi_trust_verify_digest "$f" "0000000000000000000000000000000000000000000000000000000000000000"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$(mi_digest "$f")"* ]] || { echo "output missing digest $(mi_digest "$f"): $output" >&2; return 1; }
  [[ "$output" == *0000000000* ]]
}

@test "digest verification refuses a malformed expectation rather than comparing strings" {
  local f="$MYTHICAL_HOME/x"; printf 'hello\n' > "$f"
  local e
  for e in '' 'notahex' 'ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789'; do
    run mi_trust_verify_digest "$f" "$e"
    [ "$status" -eq 1 ] || { echo "accepted malformed expectation '$e'" >&2; return 1; }
  done
}

@test "a missing file is a verification failure, not a pass" {
  run mi_trust_verify_digest "$MYTHICAL_HOME/nope" "$(printf '%064d' 0)"
  [ "$status" -eq 1 ]
}

# --- version floors ---

@test "an absent floor is first use, not a rollback" {
  run mi_trust_floor_get manifest:brokkr
  [ "$status" -eq 3 ]
}

@test "a floor round-trips through the ledger" {
  mi_trust_floor_set manifest:brokkr 5
  [ "$(mi_trust_floor_get manifest:brokkr)" = "5" ]
}

@test "floors are per document id and do not bleed" {
  mi_trust_floor_set manifest:brokkr 5
  run mi_trust_floor_get manifest:skuld
  [ "$status" -eq 3 ]
}

@test "raising a floor is allowed; lowering is refused and does not change it" {
  mi_trust_floor_set manifest:brokkr 5
  run mi_trust_floor_set manifest:brokkr 7
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "7" ]
  run mi_trust_floor_set manifest:brokkr 6
  [ "$status" -ne 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "7" ]
}

# §8.1: "Downgrade is possible only through an explicit, loud operator override."
@test "the ordinary setter cannot lower a floor, and the override can — with a reason" {
  mi_trust_floor_set manifest:brokkr 7
  run mi_trust_floor_set manifest:brokkr 3
  [ "$status" -ne 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "7" ]

  run mi_trust_floor_override manifest:brokkr 3 "emergency rollback of a bad release"
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "3" ]
  [[ "$output" == *DOWNGRADING* ]] || { echo "output missing DOWNGRADING: $output" >&2; return 1; }
  [[ "$output" == *"emergency rollback"* ]]
}

@test "a downgrade without a reason is refused, and the floor is untouched" {
  mi_trust_floor_set manifest:brokkr 7
  run mi_trust_floor_override manifest:brokkr 3 ""
  [ "$status" -ne 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "7" ]
}

@test "a downgrade is recorded in the ledger, not just printed" {
  mi_trust_floor_set manifest:brokkr 7
  mi_trust_floor_override manifest:brokkr 3 "rollback 2026-07-28"
  run mi_ledger_get trust-downgrade manifest:brokkr
  [ "$status" -eq 0 ]
  [[ "$output" == *from=7* ]] || { echo "output missing from=7: $output" >&2; return 1; }
  [[ "$output" == *to=3* ]] || { echo "output missing to=3: $output" >&2; return 1; }
  [[ "$output" == *rollback* ]]
}

@test "there is nothing to override when no floor was ever recorded" {
  run mi_trust_floor_override manifest:never 1 "reason"
  [ "$status" -ne 0 ]
}

@test "setting the same floor again is accepted" {
  mi_trust_floor_set manifest:brokkr 5
  run mi_trust_floor_set manifest:brokkr 5
  [ "$status" -eq 0 ]
}

@test "floors survive other ledger records" {
  mi_trust_floor_set manifest:brokkr 5
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  [ "$(mi_trust_floor_get manifest:brokkr)" = "5" ]
}

@test "writing a floor without the family lock is refused" {
  mi_lock_release
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger doc trust; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_trust_floor_set manifest:brokkr 1'
  [ "$status" -ne 0 ]
  [[ "$output" == *"family lock"* ]]
}

# --- the anchor ---

@test "an absent anchor reports rc 3, and is NOT treated as first use by mi_trust_check" {
  run mi_trust_anchor_get
  [ "$status" -eq 3 ]
}

@test "the anchor round-trips and is replaceable" {
  local a b
  a="$(printf 'a%.0s' {1..64})"; b="$(printf 'b%.0s' {1..64})"
  mi_trust_anchor_set "$a"; [ "$(mi_trust_anchor_get)" = "$a" ]
  mi_trust_anchor_set "$b"; [ "$(mi_trust_anchor_get)" = "$b" ]
}

@test "a malformed anchor is refused" {
  run mi_trust_anchor_set "nothex"
  [ "$status" -ne 0 ]
}

# --- the family index: the trust ROOT ---

mkindex() {   # writes $MYTHICAL_HOME/{policy,mb,ms,index}; prints nothing
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  { printf 'mythical-policy 1\nversion=1\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state\n'
    printf 'skuld.permitted_role=state\n'; } > "$d/policy"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=skuld\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/ms"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb")" "$(mi_digest "$d/ms")"; } > "$d/index"
}

@test "an index cannot be accepted without a recorded anchor" {
  mkindex
  run mi_accept_index "$MYTHICAL_HOME/index"
  [ "$status" -eq 4 ]
}

# Acceptance takes FILES. Handing a function "the authenticated index records" would be trusting the
# caller to have authenticated them — a convention, not a boundary. These two tests prove the
# property BEHAVIOURALLY; grepping the source for a comment would pass on a function that still
# accepted a fabricated blob.

# Verification and parsing must read ONE private copy. Hashing $f and then re-opening it is a TOCTOU:
# an attacker who can replace the pathname in between presents digest-matching bytes for the check
# and unauthenticated bytes for the parse. A behavioural test cannot interleave that replacement
# without a hook, so this locks in the structure — mutation-verified: pointing either the verify or
# the parse back at "$f" in any of the three acceptors is caught.
@test "an index listing a product twice is refused as ambiguous" {
  mkindex
  local d="$MYTHICAL_HOME"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=brokkr:%s\n' "$(mi_digest "$d/mb")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  # refused at LOAD, not merely at lookup: an ambiguous index that parses could still be used to
  # accept a policy, so catching it only when someone looks up that product is not catching it.
  run mi_accept_index "$d/index"
  [ "$status" -eq 1 ]
  [[ "$output" == *"more than once"* ]]
}

# --- the combined check ---

# An expiry is mandatory, so the default is far future; a test wanting an expired document passes
# a past one explicitly.
mkdoc() {   # <version> [<expires>]
  local f="$MYTHICAL_HOME/m"
  printf 'mythical-manifest 1\nproduct=brokkr\nversion=%s\nexpires=%s\n' "$1" "${2:-4102444800}" > "$f"
  MSPEC="$(printf 'product\tident\tone\nversion\tdocver\tone\nexpires\tepoch\tone')"
  mi_doc_load "$f" manifest "$MSPEC"
}

@test "a document with no expiry is refused — it would replay forever" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  local f="$MYTHICAL_HOME/m"
  printf 'mythical-manifest 1\nproduct=brokkr\nversion=3\n' > "$f"
  local recs; recs="$(mi_doc_load "$f" manifest "$(printf 'product\tident\tone\nversion\tdocver\tone\nexpires\tepoch\topt')")"
  run mi_trust_check manifest:brokkr "$recs"
  [ "$status" -eq 1 ]
  [[ "$output" == *expiry* ]]
}

@test "a first-seen document is accepted and records its version" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  run mi_trust_check manifest:brokkr "$(mkdoc 3)"
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "3" ]
}

@test "an equal version is accepted; a lower one is refused as replay" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  mi_trust_check manifest:brokkr "$(mkdoc 3)"
  run mi_trust_check manifest:brokkr "$(mkdoc 3)"
  [ "$status" -eq 0 ]
  run mi_trust_check manifest:brokkr "$(mkdoc 2)"
  [ "$status" -eq 1 ]
  [[ "$output" == *replay* ]] || [[ "$output" == *older* ]]
}

@test "a refused replay does not lower the floor" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  mi_trust_check manifest:brokkr "$(mkdoc 3)"
  mi_trust_check manifest:brokkr "$(mkdoc 2)" || true
  [ "$(mi_trust_floor_get manifest:brokkr)" = "3" ]
}

@test "an expired document is refused even at the highest version" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  # expires=1 is in the past for every real clock, so no injected clock is needed — and there is
  # deliberately no way to inject one.
  run mi_trust_check manifest:brokkr "$(mkdoc 9 1)"
  [ "$status" -eq 1 ]
  [[ "$output" == *expire* ]]
}

# §8.1: "Without a recorded anchor there is no offline reuse: the installer says it cannot verify
# and stops, rather than falling back to trusting the cache because it is local."
@test "with no anchor recorded, the check refuses with its own code" {
  run mi_trust_check manifest:brokkr "$(mkdoc 3)"
  [ "$status" -eq 4 ]
  [[ "$output" == *anchor* ]]
}

@test "a refusal for no anchor does not record a floor" {
  mi_trust_check manifest:brokkr "$(mkdoc 3)" || true
  run mi_trust_floor_get manifest:brokkr
  [ "$status" -eq 3 ]
}

# --- amendment A2: the split ------------------------------------------------------------------------
#
# Every case below builds its records with this file's own `mkdoc` helper, and that is not a style
# choice. Document *records* are TAB-separated `<key><TAB><value>` lines produced by mi_doc_load —
# mi_doc_value matches `"$key"$'\t'*` and nothing else — so the FILE syntax (`version=9`) is not a
# record at all. Fed that, mi_doc_version returns 3 and the predicates refuse with "carries no
# version": several of these would go red against a CORRECT implementation, and the malformed-anchor
# case would go GREEN without ever reaching _mi_trust_hex64_ok, which is the only thing it exists to
# prove. A vacuous pass on the anchor-ordering suite is the worst place in this plan to have one.

@test "mi_trust_check_only commits nothing" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  mi_trust_floor_set manifest:brokkr 5
  run mi_trust_check_only manifest:brokkr "$(mkdoc 9)"
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "5" ]      # NOT 9
}

@test "mi_trust_check still advances the floor, so this plan's callers are unaffected" {
  mi_trust_anchor_set "$(printf 'a%.0s' {1..64})"
  mi_trust_floor_set manifest:brokkr 5
  run mi_trust_check manifest:brokkr "$(mkdoc 9)"
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get manifest:brokkr)" = "9" ]
}

@test "mi_trust_commit moves the floor and the anchor together" {
  local a; a="$(printf 'b%.0s' {1..64})"
  mi_trust_floor_set index 1
  run mi_trust_commit index "$(mkdoc 4)" "$a"
  [ "$status" -eq 0 ]
  [ "$(mi_trust_floor_get index)" = "4" ]
  [ "$(mi_trust_anchor_get)" = "$a" ]
}

@test "an ABSENT anchor is first use, and it is rc 3 from the ledger that says so" {
  # The positive half of the pair below, so the two codes are pinned in both directions and a later
  # simplification back to `if ! mi_trust_anchor_get` fails one of them.
  mi_trust_anchor_get() { return 3; }
  run mi_trust_check_only index "$(mkdoc 9)"
  [ "$status" -eq 4 ]
}

@test "an anchor that cannot be READ is refused, never reported as first use" {
  # rc 1 from mi_trust_anchor_get means the record is there and unreadable — a torn ledger write, a
  # malformed digest field. A later caller reads rc 4 as "FIRST USE, establish an anchor", so folding
  # the two would let a damaged installation have its anchor silently replaced by whatever the origin
  # served on the next run, with nothing compared against the anchor it already had.
  mi_trust_anchor_get() { return 1; }
  run mi_trust_check_only index "$(mkdoc 9)"
  [ "$status" -eq 1 ]                                   # emphatically NOT 4
  printf '%s' "$output" | grep -aq 'could not be read'
}

@test "mi_trust_commit refuses a malformed anchor without moving the floor" {
  # The half-applied pair, from the other direction: a validation failure must not leave the floor
  # advanced with no anchor beside it. One write means one refusal.
  #
  # The records must be VALID for this case to mean anything: the refusal under test is
  # _mi_trust_hex64_ok, which sits after the version and floor checks, so a document that fails
  # earlier passes this test without ever reaching the line it is about. The message assertion is
  # here for the same reason — it names the digest, not a missing version.
  mi_trust_floor_set index 1
  run mi_trust_commit index "$(mkdoc 4)" "nothex"
  [ "$status" -ne 0 ]
  printf '%s' "$output" | grep -aq 'is not a sha256 digest'
  [ "$(mi_trust_floor_get index)" = "1" ]
}
