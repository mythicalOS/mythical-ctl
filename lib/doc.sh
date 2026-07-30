#!/usr/bin/env bash
# The authenticated-document format (D8/D21): family index, per-product manifests, family policy
# index. One grammar, three types, distinguished by a mandatory header line.
#
# These documents are MORE privileged than <product>.conf, not less — a manifest names the image to
# run, the mounts to make and the secrets to inject (§8.1). So every rule D19 places on the product
# config binds here: never sourced, never eval'd, never expanded; byte-gated before any line reaches
# a variable; keys allowlisted; values typed.
#
# The format is line-oriented key=value rather than JSON because §7.5's dependency floor has no JSON
# parser, and the two ways to get one are both worse: adding jq is a new mandatory dependency on
# every host, and hand-rolling a JSON parser in bash would read the most security-sensitive input in
# the system with the least reviewable code in the repository. See the plan's Decisions item 1.
#
# PURE library — no side effects at source time, and no `set -euo pipefail` (that would flip the
# sourcing shell). Every function checks statuses explicitly.

MI_DOC_FORMAT=1

# Per-document KEY COUNT cap, enforced by mi_doc_scan INSIDE its read loop — for the same reason
# lib/config.sh's MI_CONF_MAXKEYS is: the cost this bounds is incurred WHILE accumulating, so checking
# it afterwards would bound nothing. mi_doc_scan does not scan for duplicates (repeats are meaningful
# here — cardinality is mi_doc_load's job), but it does build a `body` string one key at a time, and
# every `body="${body}..."` append copies the whole string accumulated so far, so the total work is
# superlinear in the number of keys. Measured on this code path with no cap: 1000 keys 1.23s, 2000
# keys 2.72s, 4000 keys 6.66s — and mi_doc_scan sits on the path this plan calls host-launch authority,
# so an attacker able to grow a manifest could grow the cost of merely reading it.
#
# 1024 matches lib/config.sh's MI_CONF_MAXKEYS for the same reason: generous for any real document,
# cheap to reject once exceeded.
MI_DOC_MAXKEYS=1024

# A key is lowercase, and may carry ONE dotted prefix (`brokkr.permitted_role`) so the policy index
# can scope entries by product without needing nesting. Exactly one dot: `a.b.c` would imply a
# hierarchy this format does not have, and silently accepting it invites one.
_mi_doc_key_ok() {
  local k="$1" head rest
  local LC_ALL=C            # byte order, not locale collation: [a-z] must mean ASCII
  # An `if`, not `A && B || return 1` (amendment A6) — the Global Constraints require it and this
  # repository has already shipped a fix for exactly that shape.
  if [ -z "$k" ] || [ "${#k}" -gt 128 ]; then return 1; fi
  case "$k" in
    *.*.*) return 1 ;;
    *.*)   head="${k%%.*}"; rest="${k#*.}"
           _mi_doc_bare_key_ok "$head" || return 1
           _mi_doc_bare_key_ok "$rest" || return 1
           return 0 ;;
  esac
  _mi_doc_bare_key_ok "$k"
}

_mi_doc_bare_key_ok() {
  local k="$1"
  local LC_ALL=C
  case "$k" in
    ''|[!a-z]*) return 1 ;;
  esac
  case "${k#?}" in *[!a-z0-9_]*) return 1 ;; esac
  return 0
}

# Emit KEY<TAB>VALUE for every assignment, IN ORDER, repeats preserved. Cardinality is the spec's
# job (mi_doc_load); this layer only refuses what is not a document at all.
# rc: 0 ok · 1 malformed (reported) · 3 file missing.
# <label> names the source in diagnostics and defaults to <file>. It exists so a caller that has
# snapshotted a document to a private inode can still report the operator's pathname while every
# byte examined comes from the snapshot.
mi_doc_scan() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then mi_warn "doc: mi_doc_scan needs a <file>, a <type> and an optional <label>"; return 1; fi
  # `f` is a safe scalar name here: lib/ledger.sh's mi_ledger_get is the one function in this
  # repository that needs an array-typed local, and it names that local `fields` for exactly this
  # reason — see the note there.
  local f="$1" type="$2" label="${3:-$1}" brc
  [ -f "$f" ] || return 3

  # Same byte gate as the config reader, and for the same reason: a bash string cannot hold a NUL,
  # so a grep/read-based check physically cannot see one. Reused rather than reimplemented — one
  # audited implementation of this check, not two.
  #
  # `if cmd; then rc=0; else rc=$?; fi`, not `if ! cmd; then rc=$?; fi`: inside the then-branch of a
  # NEGATED condition `$?` is the status of the `!`, which is 0 — see lib/config.sh's mi_conf_scan,
  # which has the same shape for the same reason. _mi_conf_bytes_ok returns 2 for an unreadable file
  # and 1 for a control byte so the two can be told apart; collapsing both into one message sends an
  # operator with a permission problem after a hostile-content problem instead.
  if _mi_conf_bytes_ok "$f"; then brc=0; else brc=$?; fi
  if [ "$brc" -eq 2 ]; then
    mi_warn "doc: cannot read $label — refusing to parse it"
    return 1
  fi
  if [ "$brc" -ne 0 ]; then
    mi_warn "doc: $label contains control bytes (NUL, CR, TAB or similar) — refusing to parse it"
    return 1
  fi
  if [ -s "$f" ] && [ -n "$(tail -c1 "$f" 2>/dev/null)" ]; then
    mi_warn "doc: $label does not end in a newline (truncated?) — refusing to parse it"
    return 1
  fi

  local first line key val n=0 keys=0 body=""
  while IFS= read -r line; do
    n=$((n + 1))
    if [ "$n" -eq 1 ]; then
      first="$line"
      continue
    fi
    case "$line" in
      ''|'#'*) continue ;;
      *'='*)   : ;;
      *) mi_warn "doc: $label line $n: not a key=value assignment"; return 1 ;;
    esac
    key="${line%%=*}"
    val="${line#*=}"
    if ! _mi_doc_key_ok "$key"; then
      mi_warn "doc: $label line $n: invalid key name"
      return 1
    fi
    # Value rules are Plan 2's, unchanged: no control characters (a newline here would forge a
    # record), no $ ` \, bounded length, no leading or trailing space.
    if ! _mi_conf_value_ok "$val"; then
      mi_warn "doc: $label line $n: value for $key contains a forbidden character or is too long"
      return 1
    fi
    # The key-count cap, checked BEFORE the body accumulation below — which is the step it exists to
    # bound: every `body="${body}..."` append copies the whole string accumulated so far, so the cost
    # is incurred WHILE accumulating. Checking it afterwards would bound nothing. See MI_DOC_MAXKEYS.
    keys=$(( keys + 1 ))
    if [ "$keys" -gt "$MI_DOC_MAXKEYS" ]; then
      mi_warn "doc: $label line $n: more than $MI_DOC_MAXKEYS keys — refusing to parse it"
      return 1
    fi
    body="${body}${key}"$'\t'"${val}"$'\n'
  done < "$f"

  # The header is checked AFTER the body is read but BEFORE anything is emitted, so a document of
  # the wrong type never yields a single record to a caller that forgot to check the status.
  if [ "${first:-}" != "mythical-${type} ${MI_DOC_FORMAT}" ]; then
    case "${first:-}" in
      "mythical-${type} "*)
        mi_warn "doc: $label declares format version '${first#mythical-"${type}" }', and this mythical-ctl understands ${MI_DOC_FORMAT}" ;;
      *)
        mi_warn "doc: $label is not a mythical-${type} document (its first line is not the expected header)" ;;
    esac
    return 1
  fi
  if [ -n "$body" ]; then printf '%s' "$body"; fi
  return 0
}

# --- types beyond Plan 2's ------------------------------------------------------------------------

_mi_doc_digits_ok() {   # non-negative, non-empty, bounded so shell arithmetic stays reliable
  local v="$1"
  case "$v" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#v}" -le 18 ]
}

_mi_doc_type_ok() {
  local type="$1" v="$2" role path
  local LC_ALL=C
  case "$type" in
    docver|epoch) _mi_doc_digits_ok "$v" ;;
    ident)
      if [ -z "$v" ] || [ "${#v}" -gt 64 ]; then return 1; fi     # an `if`, not A && B || C (A6)
      case "$v" in [!a-z]*) return 1 ;; esac
      case "${v#?}" in *[!a-z0-9-]*) return 1 ;; esac
      return 0 ;;
    sha256)
      [ "${#v}" -eq 64 ] || return 1
      case "$v" in *[!0-9a-f]*) return 1 ;; esac
      return 0 ;;
    digestref)
      # <repository>@sha256:<64 hex>. A TAG IS NOT A DIGEST (D22): `latest` is not a supported
      # default and no floating reference is accepted here at all, so the check is for the pinned
      # shape rather than a denylist of tags an attacker would simply avoid.
      case "$v" in *@sha256:*) : ;; *) return 1 ;; esac
      local repo="${v%@sha256:*}" hex="${v##*@sha256:}"
      [ -n "$repo" ] || return 1
      # Exactly one @. REDUNDANT BY CONSTRUCTION, and kept on purpose: `@` is not in the repository
      # charset enforced below, so this can never be the check that rejects a value — no input reaches
      # the charset gate with an `@` still in it. It stays as an explicit statement of the rule so that
      # relaxing the charset later cannot silently drop the "exactly one @" guarantee. Do not "clean it
      # up" as dead code without moving the guarantee somewhere it is still stated.
      case "$repo" in *@*) return 1 ;; esac
      # The digest half is what carries the security property here — it pins the image to one exact
      # content hash, so a floating reference is structurally impossible. This is only a SANITY bound
      # on the half that does NOT carry that property: lowercase letters, digits, and `. _ - / :` (a
      # registry host may need a port), non-empty, capped at 255, and not starting or ending on a
      # separator. OCI repository names are already required to be lowercase, so this rejects nothing
      # a real registry would ever hand back.
      if [ "${#repo}" -gt 255 ]; then return 1; fi     # an `if`, not A && B || C (A6)
      case "$repo" in *[!a-z0-9._/:-]*) return 1 ;; esac
      case "$repo" in /*|:*|*/|*:) return 1 ;; esac
      _mi_doc_type_ok sha256 "$hex" ;;
    productdigest)
      # <product>:<64 hex> — the family index's flat encoding of "this product's manifest must
      # hash to this".
      case "$v" in *:*) : ;; *) return 1 ;; esac
      local pd_p="${v%%:*}" pd_h="${v#*:}"
      # Exactly one colon — redundant by construction for the same reason as digestref's `@` check
      # above: a `:` is not a hex character, so a pd_h holding one can never satisfy the fixed-length
      # sha256 check below, and this can never be the sole rejector. Retained as the explicit
      # statement of the rule rather than leaving it implied by a downstream type check.
      case "$pd_h" in *:*) return 1 ;; esac
      _mi_doc_type_ok ident "$pd_p" || return 1
      _mi_doc_type_ok sha256 "$pd_h" ;;
    coreversion)
      # MAJOR[.MINOR[.PATCH]] — bounded numeric components, nothing else. Deliberately not full
      # semver: pre-release and build metadata have ordering rules a shell comparator would get
      # subtly wrong, and a minimum-core requirement has no need of them.
      case "$v" in ''|*[!0-9.]*) return 1 ;; esac
      case "$v" in .*|*.|*..*) return 1 ;; esac
      local cv_n=0 cv_p
      local IFS=.
      for cv_p in $v; do
        if [ -z "$cv_p" ] || [ "${#cv_p}" -gt 18 ]; then return 1; fi   # an `if`, not A && B || C (A6)
        cv_n=$((cv_n + 1))
      done
      [ "$cv_n" -ge 1 ] && [ "$cv_n" -le 3 ] ;;
    rolemount)
      # <role>:<absolute path> — the flat encoding of what would be an object in a nested format.
      case "$v" in *:*) : ;; *) return 1 ;; esac
      role="${v%%:*}"; path="${v#*:}"
      case "$path" in *:*) return 1 ;; esac      # exactly one colon: no room for ambiguity
      _mi_doc_type_ok ident "$role" || return 1
      case "$path" in /*) : ;; *) return 1 ;; esac
      case "/${path}/" in */../*) return 1 ;; esac
      [ "${#path}" -le 4096 ] ;;
    *)
      # Everything else is Plan 2's vocabulary, so there is one implementation of str/int/enum/
      # bool/path/netname rather than a second that can drift from it.
      _mi_conf_type_ok "$type" "$v" ;;
  esac
}

# --- spec-driven validation ------------------------------------------------------------------------
# A spec line is KEY<TAB>TYPE<TAB>CARD, CARD ∈ one|opt|many.

# Validate the SPEC ITSELF before trusting it (amendment A8). Specs are built by this repository's own
# code and never come from a document, so a malformed one is a programming error rather than an
# attack — but it is checked anyway, because all three ways to get it wrong fail SILENTLY and two of
# them degrade security:
#
#   * `KEY<TAB>TYPE` with the cardinality omitted leaves `card` holding the TYPE string. That is not
#     "one", so the required-key loop treats the key as optional and a MANDATORY key quietly stops
#     being mandatory. An `expires` that stops being required is precisely the indefinite-replay hole
#     §8.1 exists to close, arriving through the validator instead of through the document.
#   * A spec written with spaces instead of TABs matches no key at all, so every key in a perfectly
#     good document reads as "unknown key" — a document-shaped error for a schema-shaped bug.
#   * A duplicate spec KEY resolves to whichever line comes first, so the second type or cardinality
#     is silently discarded.
#
# Plan 2 deferred exactly these three to this plan's spec handling rather than patching them there.
# This is where they are closed.
_mi_doc_spec_ok() {
  if [ "$#" -ne 1 ]; then return 1; fi
  local spec="$1" line k t c rest seen=""
  [ -n "$spec" ] || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in *$'\t'*) : ;; *) return 1 ;; esac      # no TAB at all: spaces, most likely
    k="${line%%$'\t'*}"; rest="${line#*$'\t'}"
    case "$rest" in *$'\t'*) : ;; *) return 1 ;; esac      # only two fields: cardinality omitted
    t="${rest%%$'\t'*}"; c="${rest#*$'\t'}"
    case "$c" in one|opt|many) : ;; *) return 1 ;; esac    # also catches a spurious fourth field
    [ -n "$t" ] || return 1
    _mi_doc_key_ok "$k" || return 1
    case "$seen" in *"|${k}|"*) return 1 ;; esac           # duplicate KEY
    seen="${seen}|${k}|"
  done <<< "$spec"
  return 0
}

_mi_doc_spec_lookup() {   # <spec> <key> → prints "TYPE<TAB>CARD"; rc 1 if not in the spec
  local spec="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in
      "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}"; return 0 ;;
    esac
  done <<< "$spec"
  return 1
}

# Parse and validate. rc: 0 ok · 1 rejected (reported) · 3 file missing.
#
# Output is BUFFERED and emitted only if everything validates. Emitting as we go would hand a
# consumer a PREFIX of a rejected document — and this document decides which image to run.
mi_doc_load() {
  if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then mi_warn "doc: mi_doc_load needs a <file>, a <type>, a <spec> and an optional <label>"; return 1; fi
  # `f` is safe as a scalar here too — see mi_doc_scan's note: the array-typed local in
  # lib/ledger.sh's mi_ledger_get is named `fields`, not `f`.
  local f="$1" type="$2" spec="$3" label="${4:-$1}" records rc=0 line key val tc tp card seen="" out=""
  # The schema is checked before the document is, so a schema bug is never reported as a document
  # error and can never silently relax a requirement (amendment A8).
  if ! _mi_doc_spec_ok "$spec"; then
    mi_warn "doc: internal error — the schema for a $type document is malformed; expected"
    mi_warn "  KEY<TAB>TYPE<TAB>one|opt|many per line, with no duplicate keys"
    return 1
  fi
  records="$(mi_doc_scan "$f" "$type" "$label")" || return $?

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="${line%%$'\t'*}"
    val="${line#*$'\t'}"
    if ! tc="$(_mi_doc_spec_lookup "$spec" "$key")"; then
      mi_warn "doc: $label: unknown key $key — not permitted by this document's schema"
      rc=1; continue
    fi
    tp="${tc%%$'\t'*}"; card="${tc#*$'\t'}"
    if ! _mi_doc_type_ok "$tp" "$val"; then
      mi_warn "doc: $label: value for $key is not valid for type $tp"
      rc=1; continue
    fi
    case "$card" in
      many) : ;;
      one|opt)
        case "$seen" in
          *"|${key}|"*) mi_warn "doc: $label: $key may appear at most once"; rc=1; continue ;;
        esac ;;
      *) mi_warn "doc: internal error — unknown cardinality '$card' for $key"; rc=1; continue ;;
    esac
    seen="${seen}|${key}|"
    out="${out}${key}"$'\t'"${val}"$'\n'
  done <<< "$records"

  # Required keys, checked against what was actually seen.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="${line%%$'\t'*}"
    tc="${line#*$'\t'}"
    card="${tc#*$'\t'}"
    if [ "$card" = "one" ]; then
      case "$seen" in
        *"|${key}|"*) : ;;
        *) mi_warn "doc: $label: required key $key is missing"; rc=1 ;;
      esac
    fi
  done <<< "$spec"

  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  if [ -n "$out" ]; then printf '%s' "$out"; fi
  return 0
}

# --- accessors ------------------------------------------------------------------------------------

mi_doc_value() {   # first value for <key>; rc 3 absent
  if [ "$#" -ne 2 ]; then mi_warn "doc: mi_doc_value needs <records> and a <key>"; return 1; fi
  local records="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}"; return 0 ;; esac
  done <<< "$records"
  return 3
}

mi_doc_values() {  # every value for <key>, one per line
  if [ "$#" -ne 2 ]; then mi_warn "doc: mi_doc_values needs <records> and a <key>"; return 1; fi
  local records="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}" ;; esac
  done <<< "$records"
  return 0
}

mi_doc_version() {
  if [ "$#" -ne 1 ]; then mi_warn "doc: mi_doc_version needs <records>"; return 1; fi
  mi_doc_value "$1" version
}

# rc 0 EXPIRED · 1 not expired · 2 unreadable. <now> defaults to the system clock.
#
# Expiry is INCLUSIVE of the stated instant: a document expiring at T is valid at T and invalid
# after it. Stated because "expires" reads either way and the two differ by one second at exactly
# the moment someone is debugging.
mi_doc_expired() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then mi_warn "doc: mi_doc_expired needs <records> [<now>]"; return 2; fi
  local records="$1" now="${2:-}" exp
  if ! exp="$(mi_doc_value "$records" expires)"; then return 1; fi   # no expiry ⇒ never expires
  _mi_doc_digits_ok "$exp" || return 2
  if [ -z "$now" ]; then now="$(date +%s 2>/dev/null)" || return 2; fi
  _mi_doc_digits_ok "$now" || return 2
  [ "$now" -gt "$exp" ]
}
