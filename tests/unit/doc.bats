#!/usr/bin/env bats
load '../lib/test_helper'

# setup_test_env FIRST — bats does not chain setup(), so defining one here REPLACES the helper's
# isolation and the suite would write into the engineer's real home.
setup() {
  setup_test_env
  load_mctl
  F="$MYTHICAL_HOME/d.txt"
  SPEC="$(printf 'product\tident\tone\nversion\tdocver\tone\nexpires\tepoch\topt\nvolume\trolemount\tmany\nport\tint:1:65535\topt')"
}

doc() { printf 'mythical-manifest 1\n%s\n' "$1" > "$F"; }

@test "a well-formed document scans to records, repeats preserved in order" {
  doc "$(printf 'product=brokkr\nversion=3\nvolume=state:/data\nvolume=secrets:/run/secrets')"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "$(printf 'product\tbrokkr')" ]
  [ "${lines[2]}" = "$(printf 'volume\tstate:/data')" ]
  [ "${lines[3]}" = "$(printf 'volume\tsecrets:/run/secrets')" ]
}

@test "the header is mandatory and its type must match" {
  printf 'product=brokkr\n' > "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]

  printf 'mythical-policy 1\nproduct=brokkr\n' > "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
  [[ "$output" == *manifest* ]]
}

@test "an unknown format version in the header is refused, naming it" {
  printf 'mythical-manifest 2\nproduct=brokkr\n' > "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
  [[ "$output" == *2* ]]
}

# Everything D19 forbids in <product>.conf is forbidden here too — a manifest is MORE privileged.
@test "a command substitution never executes and is refused" {
  local sentinel="$MYTHICAL_HOME/PWNED"
  doc "$(printf 'product=$(touch %s)' "$sentinel")"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
  [ ! -e "$sentinel" ]
}

# The fixture must contain REAL control bytes. Passing '\r' as a %s ARGUMENT writes a backslash
# and an 'r', which the value rule rejects for the wrong reason — the byte gate never sees a CR and
# the test proves nothing about it. $'\r' is the actual byte. NUL cannot survive a shell variable at
# all, which is the whole reason the byte gate exists, so it goes in the FORMAT string.
@test "control bytes are refused, and the fixtures really contain them" {
  local b
  for b in $'\r' $'\t' $'\013' $'\177'; do
    printf 'mythical-manifest 1\nproduct=a%sb\n' "$b" > "$F"
    # prove the fixture has no backslash, so a rejection can only come from the byte gate
    [ -z "$(tr -d -c '\\' < "$F")" ]
    run mi_doc_scan "$F" manifest
    [ "$status" -eq 1 ] || { echo "control byte accepted" >&2; return 1; }
  done
  printf 'mythical-manifest 1\nproduct=a\000b\n' > "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
}

@test "keys are lowercase with an optional single dotted prefix" {
  local k
  for k in 'Product' 'PRODUCT' 'pro duct' 'pro-duct' '.product' 'product.' 'a.b.c' ''; do
    doc "${k}=x"
    run mi_doc_scan "$F" manifest
    [ "$status" -eq 1 ] || { echo "key '${k}' accepted" >&2; return 1; }
  done
  doc "$(printf 'brokkr.permitted_role=state')"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 0 ]
}

@test "a line with no = is refused rather than skipped" {
  doc 'product'
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
}

@test "a file without a trailing newline is refused as truncated" {
  printf 'mythical-manifest 1\nproduct=brokkr' > "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
}

@test "comments and blank lines are ignored" {
  doc "$(printf '# note\n\nproduct=brokkr\nversion=1')"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 2 ]
}

@test "a missing file reports rc 3" {
  run mi_doc_scan "$MYTHICAL_HOME/absent" manifest
  [ "$status" -eq 3 ]
}

# --- cardinality ---

@test "a 'one' key appearing twice is rejected" {
  doc "$(printf 'product=brokkr\nproduct=skuld\nversion=1')"
  run mi_doc_load "$F" manifest "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *product* ]]
}

@test "a missing 'one' key is rejected, naming it" {
  doc 'version=1'
  run mi_doc_load "$F" manifest "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *product* ]]
}

@test "an 'opt' key may appear zero or one times, never twice" {
  doc "$(printf 'product=brokkr\nversion=1\nport=7480')"
  run mi_doc_load "$F" manifest "$SPEC"
  [ "$status" -eq 0 ]
  doc "$(printf 'product=brokkr\nversion=1\nport=7480\nport=7481')"
  run mi_doc_load "$F" manifest "$SPEC"
  [ "$status" -eq 1 ]
}

@test "a 'many' key may appear zero, one or several times" {
  doc "$(printf 'product=brokkr\nversion=1')"
  run mi_doc_load "$F" manifest "$SPEC"; [ "$status" -eq 0 ]
  doc "$(printf 'product=brokkr\nversion=1\nvolume=state:/data\nvolume=logs:/var/log')"
  run mi_doc_load "$F" manifest "$SPEC"; [ "$status" -eq 0 ]
}

@test "an unknown key is REJECTED, not ignored" {
  doc "$(printf 'product=brokkr\nversion=1\nbindable_role=secrets')"
  run mi_doc_load "$F" manifest "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *bindable_role* ]]
}

# --- the spec itself (amendment A8) ---
#
# Three malformed-schema shapes that all used to fail silently. The document in each case is fine —
# what is wrong is the schema, and the point of these three is that the schema is what gets blamed.

@test "a spec with the cardinality omitted is refused, not read as 'optional'" {
  # `product<TAB>ident` leaves card="ident", which is not "one", so the REQUIRED product key would
  # have been treated as optional and this document — which lacks it — would have loaded cleanly.
  doc 'version=1'
  run mi_doc_load "$F" manifest "$(printf 'product\tident\nversion\tdocver\tone')"
  [ "$status" -eq 1 ]
  printf '%s' "$output" | grep -aq 'malformed'
}

@test "a spec written with spaces instead of TABs is refused, not read as unknown keys" {
  doc "$(printf 'product=brokkr\nversion=1')"
  run mi_doc_load "$F" manifest "$(printf 'product ident one\nversion docver one')"
  [ "$status" -eq 1 ]
  printf '%s' "$output" | grep -aq 'malformed'
  printf '%s' "$output" | grep -avq 'unknown key' || { echo "blamed the document, not the schema: $output" >&2; return 1; }
}

@test "a duplicate key in the spec is refused rather than resolving to the first" {
  doc "$(printf 'product=brokkr\nversion=1')"
  run mi_doc_load "$F" manifest "$(printf 'product\tident\tone\nproduct\tstr\tmany\nversion\tdocver\tone')"
  [ "$status" -eq 1 ]
  printf '%s' "$output" | grep -aq 'malformed'
}

# --- the new types ---

@test "rolemount requires a role and an absolute path" {
  local v
  for v in 'state:/data' 'logs:/var/log' 'a-b:/x'; do
    doc "$(printf 'product=brokkr\nversion=1\nvolume=%s' "$v")"
    run mi_doc_load "$F" manifest "$SPEC"
    [ "$status" -eq 0 ] || { echo "rejected valid rolemount '$v'" >&2; return 1; }
  done
  for v in 'state:data' '/data' 'state:' ':/data' 'state:/x/../y' 'State:/data' 'state:/data:extra'; do
    doc "$(printf 'product=brokkr\nversion=1\nvolume=%s' "$v")"
    run mi_doc_load "$F" manifest "$SPEC"
    [ "$status" -eq 1 ] || { echo "accepted invalid rolemount '$v'" >&2; return 1; }
  done
}

@test "docver and epoch are non-negative bounded digits" {
  local v
  for v in '-1' '+1' '1.0' 'x' '' '9999999999999999999'; do
    doc "$(printf 'product=brokkr\nversion=%s' "$v")"
    run mi_doc_load "$F" manifest "$SPEC"
    [ "$status" -eq 1 ] || { echo "accepted bad docver '$v'" >&2; return 1; }
  done
}

# --- accessors ---

@test "mi_doc_value returns the first value; mi_doc_values returns all" {
  doc "$(printf 'product=brokkr\nversion=1\nvolume=state:/data\nvolume=logs:/var/log')"
  local recs; recs="$(mi_doc_load "$F" manifest "$SPEC")"
  [ "$(mi_doc_value "$recs" product)" = "brokkr" ]
  [ "$(mi_doc_values "$recs" volume | wc -l | tr -d ' ')" = "2" ]
  run mi_doc_value "$recs" nothing
  [ "$status" -eq 3 ]
}

@test "mi_doc_version returns the document version" {
  doc "$(printf 'product=brokkr\nversion=42')"
  [ "$(mi_doc_version "$(mi_doc_load "$F" manifest "$SPEC")")" = "42" ]
}

@test "expiry compares against a supplied clock" {
  doc "$(printf 'product=brokkr\nversion=1\nexpires=1000')"
  local recs; recs="$(mi_doc_load "$F" manifest "$SPEC")"
  run mi_doc_expired "$recs" 999;  [ "$status" -eq 1 ]   # not yet
  run mi_doc_expired "$recs" 1000; [ "$status" -eq 1 ]   # inclusive: still valid at the instant
  run mi_doc_expired "$recs" 1001; [ "$status" -eq 0 ]   # expired
}

@test "a document with no expiry never expires" {
  doc "$(printf 'product=brokkr\nversion=1')"
  run mi_doc_expired "$(mi_doc_load "$F" manifest "$SPEC")" 99999999
  [ "$status" -eq 1 ]
}

@test "the public functions refuse bad arity instead of aborting under set -u" {
  local call
  for call in 'mi_doc_scan' 'mi_doc_load "$MYTHICAL_HOME/x"' 'mi_doc_value' 'mi_doc_version'; do
    run bash -c 'set -euo pipefail
      for m in common layout config lock ledger doc; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
      '"$call"'; echo UNREACHABLE'
    [ "$status" -ne 0 ] || { echo "no refusal for: $call" >&2; return 1; }
    [[ "$output" != *UNREACHABLE* ]] || { echo "continued after: $call" >&2; return 1; }
    [[ "$output" != *"unbound variable"* ]] || { echo "aborted on unbound for: $call" >&2; return 1; }
  done
}
