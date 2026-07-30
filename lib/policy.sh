#!/usr/bin/env bash
# The family policy index (D21/D53, §8.1): product identity → what it may have.
#
# This document exists because AUTHENTICITY IS NOT AUTHORIZATION. A manifest signed by its real
# publisher can still ask for a sibling's state volume or another product's bootstrap secret;
# signature checking answers "who wrote this", never "may it have this". Entitlements therefore
# cannot come from the manifest — and cannot be hardcoded in the core either, which carries no
# product-specific logic (§7). So they come from a third authenticated document.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

# The role name whose entire purpose is to be permitted but never bindable (D5, §4.3).
MI_POLICY_SECRETS_ROLE=secrets

# TWO specs, and the split is enforced, because a single union spec accepts two kinds of nonsense
# that a publisher would never see:
#   `brokkr.version=99`   — a product-prefixed DOCUMENT key: meaningless, and it validates.
#   `permitted_role=state` — an UNPREFIXED entitlement: it entitles nobody, silently. On the one
#                            document whose whole job is authorization, a typo that grants nothing
#                            and reports nothing is the worst possible failure mode.
mi_policy_doc_spec() {          # document-level: NEVER product-prefixed
  printf 'version\tdocver\tone\n'
  printf 'expires\tepoch\tone\n'
  # D60: the canonical family gid is "fixed in the policy index". Required, because a policy index
  # that cannot answer it leaves the core with no authenticated value to use — and the alternative,
  # a hard-coded default, is exactly the authority model D60 replaces.
  printf 'family_gid\tint:1:4294967295\tone\n'
}

mi_policy_entitlement_spec() {  # entitlements: ALWAYS product-prefixed
  printf 'permitted_role\tident\tmany\n'
  printf 'bindable_role\tident\tmany\n'
  printf 'permitted_secret\tstr:128\tmany\n'
  printf 'permitted_mount\tident\tmany\n'
}

# Look up the spec entry for a key, choosing the spec by whether the key is prefixed. The prefix
# itself must be a product identifier.
_mi_policy_spec_for() {
  local key="$1" head rest
  case "$key" in
    *.*) head="${key%%.*}"; rest="${key#*.}"
         _mi_doc_type_ok ident "$head" || return 1
         _mi_doc_spec_lookup "$(mi_policy_entitlement_spec)" "$rest" ;;
    *)   _mi_doc_spec_lookup "$(mi_policy_doc_spec)" "$key" ;;
  esac
}

# Load and structurally validate. rc 0 · 1 rejected (reported) · 3 missing.
mi_policy_load() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then mi_warn "policy: mi_policy_load needs a <file> and an optional <label>"; return 1; fi
  local f="$1" label="${2:-$1}" records rc=0 line key val out="" seen="" card

  # The generic loader cannot validate this document, because its keys are product-prefixed and it
  # therefore has no fixed key set. Scan, then validate each key against the un-prefixed spec.
  records="$(mi_doc_scan "$f" policy "$label")" || return $?

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="${line%%$'\t'*}"
    val="${line#*$'\t'}"
    local tc tp
    if ! tc="$(_mi_policy_spec_for "$key")"; then
      mi_warn "policy: $f: unknown entitlement key $key — not permitted by the policy schema"
      rc=1; continue
    fi
    tp="${tc%%$'\t'*}"; card="${tc#*$'\t'}"
    if ! _mi_doc_type_ok "$tp" "$val"; then
      mi_warn "policy: $f: value for $key is not valid for type $tp"
      rc=1; continue
    fi
    # Cardinality is enforced here too. Reading TYPE and discarding CARD would accept a second
    # `version=` line, and mi_doc_version silently returns the FIRST — an ambiguous freshness field
    # on the document that decides authorization.
    case "$card" in
      many) : ;;
      one|opt)
        case "$seen" in
          *"|${key}|"*) mi_warn "policy: $f: $key may appear at most once"; rc=1; continue ;;
        esac ;;
      *) mi_warn "policy: internal error — unknown cardinality '$card' for $key"; rc=1; continue ;;
    esac
    seen="${seen}|${key}|"
    out="${out}${key}"$'\t'"${val}"$'\n'
  done <<< "$records"

  # EVERY required document key, not just `version`. Tracking one by hand is how `family_gid` came
  # to be declared `one` in the spec and required by nothing — the policy would authenticate, load,
  # and then answer "absent" to the one question D60 says it exists to answer.
  local dk dcard
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    dk="${line%%$'\t'*}"
    dcard="${line##*$'\t'}"
    if [ "$dcard" = "one" ]; then
      case "$seen" in
        *"|${dk}|"*) : ;;
        *) mi_warn "policy: $f: required key $dk is missing"; rc=1 ;;
      esac
    fi
  done <<< "$(mi_policy_doc_spec)"
  [ "$rc" -eq 0 ] || return 1

  # --- D53's structural invariant -----------------------------------------------------------------
  # bindable ⊆ permitted, ALWAYS, and the secrets role is never bindable. §10a requires a policy
  # index that collapses the two lists to be REJECTED AS MALFORMED rather than silently repaired:
  # "permitted" would otherwise quietly come to mean "migratable to any host path the operator
  # names", which is precisely how a product's 0600 credential store would become a one-liner to
  # relocate.
  local prod role
  while IFS= read -r line; do
    case "$line" in *.bindable_role$'\t'*) : ;; *) continue ;; esac
    prod="${line%%.*}"
    role="${line#*$'\t'}"
    if [ "$role" = "$MI_POLICY_SECRETS_ROLE" ]; then
      mi_warn "policy: $f: ${prod}'s '$role' role is declared bindable — a secrets role must be permitted and NOT bindable (D53)"
      rc=1
      continue
    fi
    if ! printf '%s' "$out" | grep -qxF "${prod}.permitted_role"$'\t'"${role}"; then
      mi_warn "policy: $f: ${prod}'s '$role' role is bindable but not permitted — bindable must be a subset of permitted (D53)"
      rc=1
    fi
  done <<< "$out"

  [ "$rc" -eq 0 ] || return 1
  if [ -n "$out" ]; then printf '%s' "$out"; fi
  return 0
}

# rc 0 iff <product> is entitled to <what> = <value>. <what> ∈ role|secret|mount.
#
# Matching is a WHOLE-RECORD comparison, never a substring: `grep -qxF` on the exact
# `<product>.permitted_<what><TAB><value>` line. A substring match would make `state` satisfy a
# request for `stat`, and entitlement checks that can be satisfied by a prefix are not checks.
mi_policy_permits() {
  if [ "$#" -ne 4 ]; then mi_warn "policy: mi_policy_permits needs <records> <product> <what> <value>"; return 1; fi
  local records="$1" product="$2" what="$3" value="$4" key
  case "$what" in
    role)   key="permitted_role" ;;
    secret) key="permitted_secret" ;;
    mount)  key="permitted_mount" ;;
    *) mi_warn "policy: unknown entitlement class '$what'"; return 1 ;;
  esac
  printf '%s' "$records" | grep -qxF "${product}.${key}"$'\t'"${value}"
}

# D60's canonical family gid, from the authenticated index and nowhere else.
mi_policy_family_gid() {
  if [ "$#" -ne 1 ]; then mi_warn "policy: mi_policy_family_gid needs <records>"; return 1; fi
  mi_doc_value "$1" family_gid
}

# Accept a policy index. Takes FILES, and re-establishes the chain itself.
#
# It deliberately does NOT take the index's records as an argument. A record string is an ordinary
# newline-delimited blob: any caller can hand a fabricated one across the boundary, and "records
# that came from mi_accept_index" is a claim the callee cannot check. Authenticated state must not
# be representable as data a caller can construct — so the file is the only thing crossing, and the
# verification is re-done here from the anchor. Re-verifying two small files is a trade this
# function should always make.
#
# rc 0 · 1 refused (reported) · 4 no anchor.
mi_accept_policy() {
  if [ "$#" -ne 2 ]; then mi_warn "policy: mi_accept_policy needs an <index file> and a <policy file>"; return 1; fi
  local ixf="$1" f="$2" idx expected records rc
  if idx="$(mi_accept_index "$ixf")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  expected="$(_mi_index_policy_digest "$idx")" || { mi_warn "policy: the family index names no policy digest"; return 1; }
  # Same snapshot discipline as mi_accept_index: verify and parse one private copy.
  local snap rc2
  snap="$(_mi_conf_snap "$f")" || return 1
  if mi_trust_verify_digest "$snap" "$expected" "$f"; then rc2=0; else rc2=$?; fi
  if [ "$rc2" -eq 0 ]; then
    if records="$(mi_policy_load "$snap" "$f")"; then rc2=0; else rc2=$?; fi
  fi
  rm -f "$snap"
  [ "$rc2" -eq 0 ] || return 1
  mi_trust_check policy "$records" || return $?
  printf '%s' "$records"
}

mi_policy_bindable() {
  if [ "$#" -ne 3 ]; then mi_warn "policy: mi_policy_bindable needs <records> <product> <role>"; return 1; fi
  printf '%s' "$1" | grep -qxF "${2}.bindable_role"$'\t'"${3}"
}
