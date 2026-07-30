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

# Every byte-gate failure used to be reported as "contains control bytes (NUL, CR, TAB or similar)",
# including a file that exists and simply cannot be OPENED — see lib/config.sh's mi_conf_scan, which
# fixed the same conflation. _mi_conf_bytes_ok returns 2 for unreadable and 1 for a control byte
# precisely so the caller can tell them apart; mi_doc_scan must branch on that instead of collapsing
# both into one message.
@test "an unreadable document is reported as unreadable, not as containing control bytes" {
  # Not staged as root: root reads a mode-000 file regardless, so there the fixture would simply be
  # readable and the test would assert the wrong thing rather than fail honestly.
  if [ "$EUID" -eq 0 ]; then skip "root bypasses mode 000, so an unreadable file cannot be staged"; fi
  doc 'product=brokkr'
  chmod 000 "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 1 ]
  [[ "$output" == *"cannot read"* ]] \
    || { echo "an unreadable document was not reported as unreadable: $output" >&2; return 1; }
  [[ "$output" != *"control bytes"* ]] \
    || { echo "an unreadable document was blamed on control bytes: $output" >&2; return 1; }
  # …and the same file, readable, parses fine — so the message above is about the mode and nothing else.
  chmod 600 "$F"
  run mi_doc_scan "$F" manifest
  [ "$status" -eq 0 ]
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

# --- the key-count cap ---
#
# mi_doc_scan builds its `body` string one key at a time, and every `body+=...` append copies the
# whole string accumulated so far — the same class of superlinear cost lib/config.sh's MI_CONF_MAXKEYS
# bounds, just without that scanner's separate quadratic duplicate check (mi_doc_scan allows repeats;
# cardinality is mi_doc_load's job). Measured on this code path with no cap: 1000 keys 1.23s, 2000
# keys 2.72s, 4000 keys 6.66s — and mi_doc_scan sits on the path this plan calls host-launch authority.
#
# awk builds the fixture: an append loop of this length costs seconds under bats' per-command DEBUG
# trap, for no benefit.
many_doc_keys() {   # <n> <file> — N "volume=state:/data" lines under a valid manifest header
  { printf 'mythical-manifest 1\n'; awk -v n="$1" 'BEGIN{for(i=0;i<n;i++)print "volume=state:/data"}'; } > "$2"
}

@test "the key-count cap is exact: 1024 keys accepted, 1025 refused, and names the cap" {
  local f="$MYTHICAL_HOME/many.txt"
  [ "$MI_DOC_MAXKEYS" -eq 1024 ]
  many_doc_keys 1024 "$f"
  run mi_doc_scan "$f" manifest
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 1024 ]
  many_doc_keys 1025 "$f"
  run mi_doc_scan "$f" manifest
  [ "$status" -eq 1 ]
  # `|| { …; return 1; }`, not a bare `[[ ]]`: bash 3.2 does not apply errexit to a failing `[[ ]]`
  # unless it is the body's final command.
  [[ "$output" == *"more than 1024 keys"* ]] \
    || { echo "the refusal does not name the cap: $output" >&2; return 1; }
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

# <label> exists so a caller validating a private SNAPSHOT (Task 2 closes a TOCTOU this way) can
# still report the operator's real pathname while every byte examined comes from the snapshot.
# mi_doc_load forwards $label into mi_doc_scan correctly, but its own four diagnostics (unknown key,
# bad type, cardinality violation, missing required key) printed the raw path instead.
@test "mi_doc_load's diagnostics report the label, not the raw file path" {
  local label="/home/operator/real-manifest.mf"

  doc "$(printf 'product=brokkr\nversion=1\nbindable_role=secrets')"   # unknown key
  run mi_doc_load "$F" manifest "$SPEC" "$label"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$label"* ]] || { echo "label missing (unknown key): $output" >&2; return 1; }
  [[ "$output" != *"$F"* ]] || { echo "raw path leaked (unknown key): $output" >&2; return 1; }

  doc "$(printf 'product=brokkr\nversion=x')"                          # bad type
  run mi_doc_load "$F" manifest "$SPEC" "$label"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$label"* ]] || { echo "label missing (bad type): $output" >&2; return 1; }
  [[ "$output" != *"$F"* ]] || { echo "raw path leaked (bad type): $output" >&2; return 1; }

  doc "$(printf 'product=brokkr\nversion=1\nport=1\nport=2')"          # cardinality violation
  run mi_doc_load "$F" manifest "$SPEC" "$label"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$label"* ]] || { echo "label missing (cardinality): $output" >&2; return 1; }
  [[ "$output" != *"$F"* ]] || { echo "raw path leaked (cardinality): $output" >&2; return 1; }

  doc 'version=1'                                                      # missing required key
  run mi_doc_load "$F" manifest "$SPEC" "$label"
  [ "$status" -eq 1 ]
  [[ "$output" == *"$label"* ]] || { echo "label missing (missing key): $output" >&2; return 1; }
  [[ "$output" != *"$F"* ]] || { echo "raw path leaked (missing key): $output" >&2; return 1; }
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

# digestref, productdigest and coreversion had zero test coverage — three of the nine new types in
# the most privileged input layer, and each is exactly the kind of %/%%/#/## parameter-expansion
# boundary logic that fails silently. A dedicated spec is used because $SPEC (above) declares none
# of them.
HEXA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
HEXB='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

@test "digestref requires <repository>@sha256:<64 hex>, exactly one @" {
  local spec; spec="$(printf 'ref\tdigestref\topt')"
  doc "ref=brokkr@sha256:${HEXA}"
  run mi_doc_load "$F" manifest "$spec"
  [ "$status" -eq 0 ] || { echo "rejected a valid digestref: $output" >&2; return 1; }

  # Two "@sha256:" occurrences: `%` strips the SHORTEST trailing match, which is the LAST occurrence,
  # leaving an '@' inside what mi_doc_load treats as the repository.
  #
  # What this asserts is that the value is REFUSED — deliberately not which gate refuses it. Two
  # independent checks reject it (the "exactly one @" case and the repository charset bound, since
  # `@` is not in that charset), so removing either one on its own leaves this test green. That is a
  # property of the code, not a weakness of the test: no input can isolate the `@` rule, which is why
  # lib/doc.sh marks it redundant-by-construction and says why it is kept anyway.
  doc "ref=repo@sha256:${HEXA}@sha256:${HEXB}"
  run mi_doc_load "$F" manifest "$spec"
  [ "$status" -eq 1 ] || { echo "accepted a digestref with two @sha256: occurrences" >&2; return 1; }

  local v
  for v in 'brokkr' 'brokkr@sha256:tooshort' "brokkr@sha256:${HEXA}x" '@sha256:'"$HEXA"; do
    doc "ref=${v}"
    run mi_doc_load "$F" manifest "$spec"
    [ "$status" -eq 1 ] || { echo "accepted invalid digestref '$v'" >&2; return 1; }
  done
}

@test "digestref's repository component is constrained: lowercase, digits, . _ - / : only" {
  local spec; spec="$(printf 'ref\tdigestref\topt')"
  local v
  for v in 'Brokkr' 'BROKKR' 'brokkr;pwned' '/brokkr' 'brokkr/' 'brokkr:' ':brokkr'; do
    doc "ref=${v}@sha256:${HEXA}"
    run mi_doc_load "$F" manifest "$spec"
    [ "$status" -eq 1 ] || { echo "accepted invalid repository '$v'" >&2; return 1; }
  done
  # A legitimate registry-host-with-port, multi-segment repository is still accepted — the digest
  # half carries the security property; this is only a sanity bound on the half that does not.
  doc "ref=registry.example.com:5000/team/brokkr@sha256:${HEXA}"
  run mi_doc_load "$F" manifest "$spec"
  [ "$status" -eq 0 ] || { echo "rejected a legitimate registry:port repository: $output" >&2; return 1; }
}

@test "productdigest requires <product>:<64 hex>, exactly one colon" {
  local spec; spec="$(printf 'pd\tproductdigest\topt')"
  doc "pd=brokkr:${HEXA}"
  run mi_doc_load "$F" manifest "$spec"
  [ "$status" -eq 0 ] || { echo "rejected a valid productdigest: $output" >&2; return 1; }

  # Two colons: must be refused rather than resolving to the first, exactly like the spec-duplicate-key
  # rule above — a second delimiter is ambiguity, not data. As with digestref's `@` above, this asserts
  # the refusal and not which gate produces it: a `:` cannot appear in a 64-character hex digest, so
  # the sha256 check would reject this value even with the explicit colon check removed.
  doc "pd=brokkr:extra:${HEXA}"
  run mi_doc_load "$F" manifest "$spec"
  [ "$status" -eq 1 ] || { echo "accepted a productdigest with two colons" >&2; return 1; }

  local v
  for v in 'brokkr' "BROKKR:${HEXA}" 'brokkr:tooshort'; do
    doc "pd=${v}"
    run mi_doc_load "$F" manifest "$spec"
    [ "$status" -eq 1 ] || { echo "accepted invalid productdigest '$v'" >&2; return 1; }
  done
}

@test "coreversion is MAJOR[.MINOR[.PATCH]], bounded numeric components" {
  local spec; spec="$(printf 'cv\tcoreversion\topt')"
  local v
  for v in '1' '1.2' '1.2.3' '0.0.1'; do
    doc "cv=${v}"
    run mi_doc_load "$F" manifest "$spec"
    [ "$status" -eq 0 ] || { echo "rejected valid coreversion '$v'" >&2; return 1; }
  done
  for v in '' '1.' '.1' '1..2' '1.2.3.4' '1.x'; do
    doc "cv=${v}"
    run mi_doc_load "$F" manifest "$spec"
    [ "$status" -eq 1 ] || { echo "accepted invalid coreversion '$v'" >&2; return 1; }
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
