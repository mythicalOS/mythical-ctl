#!/usr/bin/env bash
# The trust chain (D21/§8.1): one authenticated root, digest gating, anti-rollback, expiry.
#
# The load-bearing sentence of §8.1 is "a digest is not authentication": verifying a document
# against a digest that arrived beside it proves only that an attacker can compute sha256. A digest
# is meaningful ONLY when the expected value came from a document that was itself authenticated —
# the family index, fetched over TLS from a known origin. Nothing here bootstraps its own trust, and
# any code path that accepts a document on its own say-so defeats the whole section.
#
# Trust state lives in Plan 1's ledger as records, so MI_LEDGER_SCHEMA stays 1: a schema bump would
# trigger D35's newer-refusal on every existing installation for a change that adds no field to any
# existing record.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_TRUST_FLOOR_KIND=trust-floor
MI_TRUST_ANCHOR_KIND=trust-anchor
MI_TRUST_DOWNGRADE_KIND=trust-downgrade

_mi_trust_hex64_ok() {
  local v="$1"
  local LC_ALL=C
  [ "${#v}" -eq 64 ] || return 1
  case "$v" in *[!0-9a-f]*) return 1 ;; esac
  return 0
}

# Verify a file against an EXPECTED digest that the caller obtained from an authenticated document.
# rc 0 match · 1 mismatch, unreadable file, or malformed expectation (all reported).
#
# The malformed-expectation case is a refusal, not a comparison: an empty or uppercase expectation
# would otherwise "not match" for the right reason by accident, and a caller that built the
# expectation wrongly would see a plain mismatch instead of its own bug.
#
# <label> names the source in diagnostics and defaults to <file> — the same convention
# mi_doc_load/mi_doc_scan use, and for the same reason: every caller here verifies a PRIVATE
# snapshot (see mi_accept_index/mi_accept_policy/mi_accept_manifest's snapshot discipline), so
# without a label a mismatch would report a `mktemp` path that no longer exists by the time an
# operator reads it, naming neither the document nor which one it was.
mi_trust_verify_digest() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    mi_warn "trust: mi_trust_verify_digest needs a <file>, an <expected digest> and an optional <label>"
    return 1
  fi
  local f="$1" expected="$2" label="${3:-$1}" actual
  if ! _mi_trust_hex64_ok "$expected"; then
    mi_warn "trust: '$expected' is not a sha256 digest (64 lowercase hex characters) — refusing to compare"
    return 1
  fi
  if [ ! -f "$f" ]; then
    mi_warn "trust: cannot verify $label — it does not exist"
    return 1
  fi
  actual="$(mi_digest "$f")" || { mi_warn "trust: cannot digest $label"; return 1; }
  [ -n "$actual" ] || { mi_warn "trust: empty digest for $label"; return 1; }
  if [ "$actual" != "$expected" ]; then
    mi_warn "trust: $label does not match the digest the family index vouches for"
    mi_warn "  expected: $expected"
    mi_warn "  actual:   $actual"
    return 1
  fi
  return 0
}

# --- ledger-backed trust state ---------------------------------------------------------------------

# A document id is `<kind>:<product>` (`manifest:brokkr`) or a bare kind (`policy`). Constrained
# because it is a ledger key: no tabs, no spaces, no newlines, bounded.
_mi_trust_docid_ok() {
  local d="$1"
  local LC_ALL=C
  if [ -z "$d" ] || [ "${#d}" -gt 128 ]; then return 1; fi         # an `if`, not A && B || C (A6)
  case "$d" in *[!a-z0-9:_-]*) return 1 ;; esac
  return 0
}

mi_trust_floor_get() {
  if [ "$#" -ne 1 ]; then mi_warn "trust: mi_trust_floor_get needs a <docid>"; return 1; fi
  local docid="$1" v
  _mi_trust_docid_ok "$docid" || { mi_warn "trust: invalid document id '$docid'"; return 1; }
  # mi_ledger_get propagates a corrupt ledger as a failure rather than reporting "no records", which
  # is what keeps "the ledger is damaged" from looking like "this is a first install".
  _mi_trust_kind_wellformed "$MI_TRUST_FLOOR_KIND" || return 1
  v="$(mi_ledger_get "$MI_TRUST_FLOOR_KIND" "$docid")" || return $?
  if [ -z "$v" ]; then
    # EMPTY IS NOT ABSENT. rc 3 here means "no floor has ever been recorded", which is the first-use
    # branch that accepts any version on trust. A floor that IS recorded but carries no value must
    # not take that branch: it is a floor we cannot read, and reading it as "never seen" turns the
    # anti-rollback guarantee off for the one document whose record was damaged.
    if _mi_trust_key_present "$MI_TRUST_FLOOR_KIND" "$docid"; then
      mi_warn "trust: a version floor for '$docid' is recorded but carries no value."
      mi_warn "  Refusing rather than treating it as never-seen — that branch accepts any version."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    return 3
  fi
  _mi_trust_single_value "$v" "version floor for '$docid'" || return 1
  printf '%s\n' "$v"
}

# Is a key recorded at all under <kind>, whatever its value? This is the "present but unreadable"
# versus "absent" question, and it cannot be answered from `mi_ledger_get`'s output alone, because
# both cases print nothing.
#
# The walk consumes one separator at a time rather than using `IFS=$'\t'; set -- $record`, which
# would both drop empty fields (TAB is IFS whitespace, so adjacent separators collapse) and
# glob-expand each token against the working directory.
_mi_trust_key_present() {
  local kind="$1" key="$2" records line rest tok
  records="$(mi_ledger_read)" || return $?
  while IFS= read -r line; do
    case "$line" in "$kind"$'\t'*) : ;; *) continue ;; esac
    rest="${line#*$'\t'}"
    while [ -n "$rest" ]; do
      tok="${rest%%$'\t'*}"
      case "$tok" in "${key}="*) return 0 ;; esac
      if [ "$rest" = "$tok" ]; then rest=""; else rest="${rest#*$'\t'}"; fi
    done
  done <<< "$records"
  return 1
}

# Every record of <kind> must be well formed: at least one field, and every field `name=value`.
# A bare `trust-floor` row with no fields at all is the other half of the same defect — it carries
# no key, so the presence check above cannot see it, and the getter would report "never recorded".
# Trust records are the one place where "I could not read this" must never resolve to "there is
# nothing here", so a malformed record of a trust kind refuses the whole read.
_mi_trust_kind_wellformed() {
  local kind="$1" records line rest tok
  records="$(mi_ledger_read)" || return 0        # unreadable ledger is the caller's rc to propagate
  while IFS= read -r line; do
    case "$line" in "$kind"$'\t'*) : ;; "$kind") : ;; *) continue ;; esac
    if [ "$line" = "$kind" ]; then
      mi_warn "trust: a '$kind' record in the ledger has no fields at all."
      mi_warn "  Refusing rather than reading it as absent. Run 'mythical-ctl state repair'."
      return 1
    fi
    rest="${line#*$'\t'}"
    while [ -n "$rest" ]; do
      tok="${rest%%$'\t'*}"
      case "$tok" in
        *=*) : ;;
        *) mi_warn "trust: a '$kind' record contains '$tok', which is not a name=value field."
           mi_warn "  Refusing rather than reading around it. Run 'mythical-ctl state repair'."
           return 1 ;;
      esac
      if [ "$rest" = "$tok" ]; then rest=""; else rest="${rest#*$'\t'}"; fi
    done
  done <<< "$records"
  return 0
}

# A floor or anchor must be ONE value. `mi_ledger_get` prints every matching field, so a record
# carrying its key twice — which a restored ledger can — comes back as several lines, and the
# comparison below then runs on a string containing a newline.
#
# Measured impact, stated precisely because the direction matters: this does NOT fail open.
# `_mi_num_gt` compares by digit count first, and a two-line value is always longer than any single
# value below the real floor, so every rollback attempt is still refused — exhaustively checked over
# a matrix of floors and lower versions, with no accepting case. What it does instead is refuse
# LEGITIMATE upgrades: with a duplicated floor of 99999, moving to 100000 is rejected as a downgrade.
# So the failure is availability, not authenticity — a wedged installation whose refusal message is
# actively misleading, because it names a rollback that is not happening.
#
# Refuse and report, rather than picking the first line or the largest: an ambiguous floor is exactly
# the case where guessing is how a rollback floor silently becomes the wrong number.
_mi_trust_single_value() {
  local v="$1" what="$2"
  # `$'\n'`, NOT `"$(printf '\n')"`. Command substitution strips trailing newlines, so the latter is
  # the EMPTY string and the pattern degrades to `*` — matching every value and refusing every read.
  # Caught by running the suite: it broke 25 trust tests at once.
  case "$v" in
    *$'\n'*)
      mi_warn "trust: the $what is recorded more than once in the ledger, with differing values."
      mi_warn "  Refusing rather than choosing one — an ambiguous floor is how a rollback floor"
      mi_warn "  silently becomes the wrong number. Run 'mythical-ctl state repair'."
      return 1 ;;
  esac
  return 0
}

# No arity guard: this takes no arguments, so there is nothing to expand and nothing that could
# abort under `set -u`. Adding one would also make shellcheck read the function as argument-taking
# (SC2120) and then flag every call site (SC2119).
mi_trust_anchor_get() {
  local v
  _mi_trust_kind_wellformed "$MI_TRUST_ANCHOR_KIND" || return 1
  v="$(mi_ledger_get "$MI_TRUST_ANCHOR_KIND" digest)" || return $?
  if [ -z "$v" ]; then
    # Same rule as the floor: an anchor that is recorded but unreadable must not take the
    # no-anchor branch, which is where trust-on-first-use accepts a root it has never seen.
    if _mi_trust_key_present "$MI_TRUST_ANCHOR_KIND" digest; then
      mi_warn "trust: a trust anchor is recorded but carries no value."
      mi_warn "  Refusing rather than treating it as never-seen — that branch accepts a new root."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    return 3
  fi
  _mi_trust_single_value "$v" "trust anchor digest" || return 1
  printf '%s\n' "$v"
}

# Replace SEVERAL ledger records in ONE read-modify-write, preserving every other record.
# Read-modify-write under the lock; mi_ledger_write proves lock ownership itself.
#
# Why it must be one write rather than two calls to _mi_trust_put: mi_ledger_write replaces the
# whole ledger atomically, so two calls are two atomic writes with a window between them. The
# floor and the anchor must move together or not at all — a half-applied pair is either an anchor
# vouching for bytes the floor will reject, or a floor above anything the cache can satisfy, and
# the second one makes an installation refuse its own verified cache.
_mi_trust_put_many() {      # <kind> <key> <value> [<kind> <key> <value>...]
  local records line out="" drop="" pfx rc
  # ARRAY-TYPED LOCAL. tools/bundle.sh concatenates every module into one file in MODULES order, and
  # in a flat file shellcheck's array tracking is no longer per-function — so a later module that uses
  # this name for an ordinary scalar draws SC2178 there plus an SC2128 on every use, while the repo
  # tree lints clean and only `shellcheck dist/mythical-ctl` goes red. The names already spoken for
  # this way are `args`, `pk`, `pv`, `placed` (lib/config.sh), `fields` (lib/ledger.sh) and `triples`
  # here; a module loaded after them must not reuse one for a string. `f` was on that list until it
  # was deliberately freed for filenames.
  local -a triples
  mi_lock_assert_held "record trust state"
  if [ "$#" -lt 3 ] || [ "$(( $# % 3 ))" -ne 0 ]; then
    mi_warn "trust: _mi_trust_put_many needs one or more <kind> <key> <value> triples"
    return 1
  fi
  triples=( "$@" )
  # The records being replaced, as `|<kind><TAB><key>=|` tokens, so the ledger is filtered in ONE
  # pass however many are being written.
  while [ "$#" -gt 0 ]; do
    drop="${drop}|$1"$'\t'"$2=|"
    shift 3
  done
  if records="$(mi_ledger_read)"; then :; else
    rc=$?
    # rc 3 is "no ledger yet", which is a legitimate first write. Anything else is corruption and
    # mi_ledger_read has already reported it — never overwrite a ledger we could not read.
    [ "$rc" -eq 3 ] || return "$rc"
    records=""
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pfx="${line%%=*}="                 # `<kind><TAB><key>=`; the first `=` is the separator
    case "$drop" in
      *"|${pfx}|"*) continue ;;        # drop the records we are replacing
    esac
    out="${out}${line}"$'\n'
  done <<< "$records"
  set -- ${triples[@]+"${triples[@]}"}
  while [ "$#" -gt 0 ]; do
    out="${out}${1}"$'\t'"${2}=${3}"$'\n'
    shift 3
  done
  printf '%s' "$out" | mi_ledger_write
}

_mi_trust_put() {           # one triple; the single-record spelling every existing caller uses
  if [ "$#" -ne 3 ]; then mi_warn "trust: _mi_trust_put needs a <kind>, <key> and <value>"; return 1; fi
  _mi_trust_put_many "$1" "$2" "$3"
}

mi_trust_floor_set() {
  if [ "$#" -ne 2 ]; then mi_warn "trust: mi_trust_floor_set needs a <docid> and a <version>"; return 1; fi
  local docid="$1" version="$2" cur rc
  _mi_trust_docid_ok "$docid" || { mi_warn "trust: invalid document id '$docid'"; return 1; }
  _mi_doc_digits_ok "$version" || { mi_warn "trust: '$version' is not a document version"; return 1; }
  if cur="$(mi_trust_floor_get "$docid")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    # Compare as decimal strings via the ledger's overflow-safe helper: a version long enough to
    # overflow `[ -gt ]` would otherwise wrap and read as smaller than it is.
    if _mi_num_gt "$cur" "$version"; then
      mi_warn "trust: refusing to lower the recorded version floor for $docid ($cur → $version)"
      return 1
    fi
  elif [ "$rc" -ne 3 ]; then
    return "$rc"
  fi
  _mi_trust_put "$MI_TRUST_FLOOR_KIND" "$docid" "$version"
}

# §8.1's explicit operator downgrade. A legitimate emergency rollback must not require editing
# installer state by hand, so the mechanism exists here — but it is deliberately NOT quiet:
#
#   * it demands a reason, which is recorded in the ledger beside the new floor, so the downgrade
#     survives in the audit trail rather than living in someone's shell history;
#   * it refuses to masquerade as an ordinary write — mi_trust_floor_set still cannot lower a floor,
#     and this is the only function that can.
#
# The LOUDNESS an operator sees (a confirmation prompt, a --downgrade flag, the warning banner) is
# the verb's job in Plan 4; what belongs here is that the capability is separate, named, reasoned
# and recorded.
mi_trust_floor_override() {
  if [ "$#" -ne 3 ]; then mi_warn "trust: mi_trust_floor_override needs a <docid>, a <version> and a <reason>"; return 1; fi
  local docid="$1" version="$2" reason="$3" cur rc
  _mi_trust_docid_ok "$docid" || { mi_warn "trust: invalid document id '$docid'"; return 1; }
  _mi_doc_digits_ok "$version" || { mi_warn "trust: '$version' is not a document version"; return 1; }
  # Same value rule as lib/config.sh's _mi_conf_value_ok, checked the same way and in the same
  # order (length first): this string is written verbatim into a ledger record, so it gets the
  # same LC_ALL=C byte-order guard every other validator in this file uses for a character class,
  # and the same bound the config module's value rule enforces (MI_CONF_MAXLEN).
  local LC_ALL=C
  if [ "${#reason}" -gt "$MI_CONF_MAXLEN" ]; then
    mi_warn "trust: a downgrade reason must be $MI_CONF_MAXLEN characters or fewer"
    return 1
  fi
  case "$reason" in
    ''|*[[:cntrl:]]*) mi_warn "trust: a downgrade needs a one-line reason, recorded with it"; return 1 ;;
  esac
  if cur="$(mi_trust_floor_get "$docid")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "trust: there is no recorded floor for $docid to override"
    return 1
  fi
  [ "$rc" -eq 0 ] || return "$rc"
  # ONE ledger write, not two. _mi_trust_put_many exists precisely so a pair lands together —
  # mi_trust_commit uses it for the floor+anchor pair for the same reason. Two separate
  # _mi_trust_put calls here would be two atomic writes with a window between them: if the second
  # (the audit record) failed, the floor would already be lowered with no reason recorded beside
  # it, while the operator is told the command failed — the exact opposite of surviving in the
  # audit trail rather than living in someone's shell history.
  #
  # THE WRITE HAPPENS BEFORE THE ANNOUNCEMENT, and that ordering is the fix to a real defect rather
  # than a preference. The banner below is written in the past tense and says "This is recorded in
  # the ledger"; emitted first, it said exactly that on a run where the write then FAILED and
  # nothing was recorded at all — the function returned 1, the floor was untouched, and the operator
  # reading the log of a failed emergency rollback was told the downgrade had happened. Announcing
  # an act before performing it means announcing it whether or not it happens. Nothing is lost by
  # waiting: the banner exists to be loud in the record, not to be a progress indicator.
  if ! _mi_trust_put_many "$MI_TRUST_FLOOR_KIND" "$docid" "$version" \
                          "$MI_TRUST_DOWNGRADE_KIND" "$docid" "from=${cur} to=${version} reason=${reason}"; then
    mi_warn "trust: the override of $docid's version floor was NOT applied — the ledger write failed."
    mi_warn "  The floor is unchanged at $cur and no downgrade record was written."
    return 1
  fi
  # The headline verb follows the ACTUAL direction of the change, compared via the ledger's
  # overflow-safe decimal comparator (never `[ -gt ]`, for the same reason every other version
  # comparison in this file uses it) — this override is not restricted to lowering a floor, so
  # printing "DOWNGRADING" unconditionally would mislead an operator on a same-or-higher override.
  if _mi_num_gt "$cur" "$version"; then
    mi_warn "trust: DOWNGRADED the version floor for $docid: $cur → $version"
    mi_warn "  reason: $reason"
    mi_warn "  Every document between these versions becomes acceptable again, including any that were"
    mi_warn "  withdrawn. This is recorded in the ledger."
  elif _mi_num_gt "$version" "$cur"; then
    mi_warn "trust: RAISED the version floor for $docid via override: $cur → $version"
    mi_warn "  reason: $reason"
  else
    mi_warn "trust: RE-RECORDED the version floor for $docid at its current value ($version)"
    mi_warn "  reason: $reason"
  fi
  return 0
}

mi_trust_anchor_set() {
  if [ "$#" -ne 1 ]; then mi_warn "trust: mi_trust_anchor_set needs a <digest>"; return 1; fi
  _mi_trust_hex64_ok "$1" || { mi_warn "trust: '$1' is not a sha256 digest"; return 1; }
  _mi_trust_put "$MI_TRUST_ANCHOR_KIND" digest "$1"
}

# --- the family index: the one trust root (§8.1) --------------------------------------------------

mi_index_spec() {
  printf 'version\tdocver\tone\n'
  printf 'expires\tepoch\tone\n'
  printf 'policy_digest\tsha256\tone\n'
  printf 'manifest\tproductdigest\tmany\n'
}

# Parse an index file. NOT an authentication step — mi_accept_index is. Kept separate so the
# duplicate check below has somewhere to live, and PRIVATE-BY-CONVENTION callers cannot mistake a
# parsed index for a verified one.
mi_index_load() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then mi_warn "trust: mi_index_load needs a <file> and an optional <label>"; return 1; fi
  local records product seen="" v
  records="$(mi_doc_load "$1" index "$(mi_index_spec)" "${2:-$1}")" || return $?
  # A product listed twice makes the index ambiguous about which digest vouches for it. Refuse at
  # LOAD time, not at lookup: an ambiguous index that parses can still be used to accept a policy,
  # so catching it only when someone happens to look up that one product is not catching it.
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    product="${v%%:*}"
    case "$seen" in
      *"|${product}|"*) mi_warn "trust: the family index lists $product more than once — refusing an ambiguous index"; return 1 ;;
    esac
    seen="${seen}|${product}|"
  done <<< "$(mi_doc_values "$records" manifest)"
  printf '%s' "$records"
}

_mi_index_policy_digest() {
  mi_doc_value "$1" policy_digest
}

# The digest the index vouches for, for ONE product. rc 3 if the index does not list it — which is
# not "no digest recorded, carry on" but "this index does not vouch for that product at all".
_mi_index_manifest_digest() {
  local records="$1" product="$2" v
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in "${product}:"*) printf '%s\n' "${v#*:}"; return 0 ;; esac
  done <<< "$(mi_doc_values "$records" manifest)"
  return 3
}

# THE ROOT OF THE CHAIN. Verify a family index against the persisted anchor, then apply freshness.
# rc 0 accept · 1 refused (reported) · 4 no anchor recorded.
#
# Everything else in this plan verifies AGAINST something. This is the only function that decides
# what "something" is, and it never accepts an index on its own say-so: the anchor comes from the
# ledger, and the ledger's anchor was written by a previous successful verification (or, on a first
# online run, by the bootstrap after a live TLS fetch — Plan 5).
mi_accept_index() {
  if [ "$#" -ne 1 ]; then mi_warn "trust: mi_accept_index needs an <index file>"; return 1; fi
  local f="$1" anchor records rc
  if anchor="$(mi_trust_anchor_get)"; then rc=0; else rc=$?; fi
  # ABSENT and UNREADABLE are not the same answer, and here the difference is the trust root
  # itself — see mi_trust_check_only's own note, which this mirrors. rc 3 is FIRST USE (no anchor
  # has ever been recorded); anything else means a recorded anchor exists and could not be read,
  # which is a damaged trust record, not a fresh installation. Folding the two into one rc 4 would
  # tell a damaged installation to re-bootstrap — replacing the anchor with whatever the origin
  # serves next, with nothing compared against the anchor it already had, which is the one thing
  # an anchor exists to prevent.
  case "$rc" in
    0) : ;;
    3)
      mi_warn "trust: no family-index anchor has been recorded, so $f cannot be verified."
      mi_warn "  Run once with network access to establish the anchor; a local copy is not evidence."
      return 4
      ;;
    *)
      mi_warn "trust: this installation HAS a recorded family-index anchor and it could not be read."
      mi_warn "  That is a damaged trust record, not a new installation, so $f is refused rather than"
      mi_warn "  anchored afresh — re-anchoring here would replace the anchor with whatever the origin"
      mi_warn "  served, which is the one thing an anchor exists to prevent. Repair the ledger"
      mi_warn "  ('mythical-ctl state repair') and re-run."
      return 1
      ;;
  esac
  # SNAPSHOT, then verify and parse THE SAME BYTES. Hashing $f and then re-opening it is a TOCTOU:
  # an attacker who can replace the pathname between the two presents digest-matching bytes for
  # verification and unauthenticated bytes for parsing, which is D21's boundary defeated by a
  # rename. The label keeps diagnostics naming the operator's file.
  local snap rc2
  snap="$(_mi_conf_snap "$f")" || return 1
  if mi_trust_verify_digest "$snap" "$anchor" "$f"; then rc2=0; else rc2=$?; fi
  if [ "$rc2" -eq 0 ]; then
    if records="$(mi_index_load "$snap" "$f")"; then rc2=0; else rc2=$?; fi
  fi
  rm -f "$snap"
  [ "$rc2" -eq 0 ] || return 1
  mi_trust_check index "$records" || return $?
  printf '%s' "$records"
}

# The combined freshness gate for one already-parsed document.
# AMENDMENT A2 — the freshness gate is SPLIT into a pure check and an explicit commit.
#
# An earlier draft of this plan shipped a single `mi_trust_check` that advanced the version floor as
# part of checking it. That is a real defect and not a style difference: "check freshness, then decide
# whether to advance the anchor" could not be expressed, because by the time the anchor decision was
# reached the floor had already moved — so a document refused for some LATER reason had still raised
# the bar for every future one. Plan 5's review found it; the correct shape is built here, once,
# rather than landed broken and rewritten by a plan that did not build this module.
#
# The four functions below are the whole of the split. `mi_trust_check` remains as the composition,
# so every caller in THIS plan is unaffected.

# The freshness predicate, PURE: version present, expiry present, not expired, and not below the
# recorded floor. rc 0 accept · 1 refused (reported).
#
# It exists as its own function so a later caller's first-use branch can run EXACTLY these checks
# rather than a second hand-rolled set beside them. Two implementations of one rule, on the trust
# root, is not a thing to have.
_mi_trust_fresh_ok() {
  if [ "$#" -ne 2 ]; then mi_warn "trust: _mi_trust_fresh_ok needs a <docid> and <records>"; return 1; fi
  local docid="$1" records="$2" version cur rc

  if ! version="$(mi_doc_version "$records")"; then
    mi_warn "trust: $docid carries no version — refusing (freshness is part of authenticity)"
    return 1
  fi

  # An expiry is MANDATORY here, not merely typed in the schema. §8.1 requires it precisely so that
  # a stale-but-highest document cannot be replayed indefinitely against a machine that has been
  # offline — and a document with no expiry is exactly that document. Treating absence as "never
  # expires" would leave the highest version anyone ever served replayable forever.
  if ! mi_doc_value "$records" expires >/dev/null; then
    mi_warn "trust: $docid carries no expiry — refusing; without one it replays indefinitely (§8.1)"
    return 1
  fi

  # The REAL clock, with no environment override. An ambient MI_TRUST_NOW would ship
  # `MI_TRUST_NOW=0 mythical-ctl …` as a supported way to make an expired document look current —
  # defeating the replay protection this call exists to provide. mi_doc_expired still takes an
  # explicit `now` so it stays unit-testable; acceptance simply never passes one.
  if mi_doc_expired "$records"; then
    mi_warn "trust: $docid has expired — refusing; a stale document replays indefinitely otherwise"
    return 1
  elif [ "$?" -eq 2 ]; then
    mi_warn "trust: $docid has an unreadable expiry — refusing"
    return 1
  fi

  if cur="$(mi_trust_floor_get "$docid")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    if _mi_num_gt "$cur" "$version"; then
      mi_warn "trust: $docid version $version is older than the highest already seen ($cur) — refusing as replay"
      return 1
    fi
  elif [ "$rc" -ne 3 ]; then
    return "$rc"
  fi
  # An absent floor is FIRST USE, not a rollback (§10a): the ledger's initialized-product set makes
  # a never-seen document trust-on-first-use, and treating it as an attack would make every second
  # product uninstallable.
  return 0
}

# The anchored freshness gate, PURE. rc 0 accept · 1 refused and reported — replay, expired, or a
# recorded anchor that could not be read · 4 no anchor has ever been recorded.
#
# Rc 4 is its own code because the two refusals need different operator responses: a replay means
# someone served old bytes, while a missing anchor means this installation has never successfully
# verified a family index and cannot start from a cache (§8.1). Collapsing them would tell an
# operator to investigate an attack when they simply need to be online once.
#
# "ABSENT" AND "UNREADABLE" ARE NOT THE SAME ANSWER, and here the difference is the trust root
# itself. mi_trust_anchor_get returns 3 for absent and 1 for unreadable; `if ! mi_trust_anchor_get`
# folds them, and rc 4 does not mean "cannot verify offline" to a later caller — it means FIRST USE,
# ESTABLISH AN ANCHOR. So an installation whose anchor record is there but torn or malformed would
# take the first-use branch and have its anchor replaced with whatever the origin served on that run,
# with nothing compared against the anchor it already had. That is the trust root being
# re-bootstrapped on a condition that is not a fresh installation.
#
# An unreadable ledger therefore refuses, as rc 1 — the code this plan already documents for "refused
# and reported". It deliberately does NOT get a new code: mi_accept_index's published contract is
# 0/1/4, and widening a shipped function's return set to carry a distinction only one caller wants is
# a bigger change than the defect. The message carries the distinction instead, and the property that
# matters — an unreadable anchor is never first use — is a property of the CODE PATH, not the number.
mi_trust_check_only() {
  if [ "$#" -ne 2 ]; then mi_warn "trust: mi_trust_check_only needs a <docid> and <records>"; return 1; fi
  local arc
  if mi_trust_anchor_get >/dev/null 2>&1; then arc=0; else arc=$?; fi
  case "$arc" in
    0) : ;;
    3)
      mi_warn "trust: no family-index anchor has been recorded, so $1 cannot be verified offline."
      mi_warn "  Run once with network access to establish the anchor; a local copy is not evidence."
      return 4
      ;;
    *)
      mi_warn "trust: this installation HAS a recorded family-index anchor and it could not be read."
      mi_warn "  That is a damaged trust record, not a new installation, so $1 is refused rather than"
      mi_warn "  anchored afresh — re-anchoring here would replace the anchor with whatever the origin"
      mi_warn "  served, which is the one thing an anchor exists to prevent. Repair the ledger"
      mi_warn "  ('mythical-ctl state repair') and re-run."
      return 1
      ;;
  esac
  _mi_trust_fresh_ok "$1" "$2"
}

# Advance the floor, and the anchor when one is given, in ONE ledger write under the lock already
# held. rc 0 · 1 refused (reported).
#
# The floor cannot go DOWN here either. mi_trust_floor_override remains the only function that can
# lower one, because §8.1 requires a downgrade to be explicit, reasoned and recorded — and a
# downgrade that could arrive through the ordinary commit path is a downgrade that stops being any
# of the three.
mi_trust_commit() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    mi_warn "trust: mi_trust_commit needs a <docid>, <records> and an optional <anchor digest>"
    return 1
  fi
  local docid="$1" records="$2" anchor="${3:-}" version cur rc
  _mi_trust_docid_ok "$docid" || { mi_warn "trust: invalid document id '$docid'"; return 1; }
  if ! version="$(mi_doc_version "$records")"; then
    mi_warn "trust: $docid carries no version — refusing to record a floor for it"
    return 1
  fi
  _mi_doc_digits_ok "$version" || { mi_warn "trust: '$version' is not a document version"; return 1; }
  if cur="$(mi_trust_floor_get "$docid")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    if _mi_num_gt "$cur" "$version"; then
      mi_warn "trust: refusing to lower the recorded version floor for $docid ($cur → $version)"
      return 1
    fi
  elif [ "$rc" -ne 3 ]; then
    return "$rc"
  fi
  # The anchor is validated BEFORE the write, so a malformed digest cannot land half of the pair.
  if [ -n "$anchor" ]; then
    _mi_trust_hex64_ok "$anchor" || { mi_warn "trust: '$anchor' is not a sha256 digest"; return 1; }
    _mi_trust_put_many "$MI_TRUST_FLOOR_KIND" "$docid" "$version" \
                       "$MI_TRUST_ANCHOR_KIND" digest "$anchor"
  else
    _mi_trust_put_many "$MI_TRUST_FLOOR_KIND" "$docid" "$version"
  fi
}

# rc 0 accept (and the floor is advanced) · 1 replay or expired (reported) · 4 no anchor recorded.
# The composition of the two above, so this plan's own callers see no change.
mi_trust_check() {
  if [ "$#" -ne 2 ]; then mi_warn "trust: mi_trust_check needs a <docid> and <records>"; return 1; fi
  local rc
  if mi_trust_check_only "$1" "$2"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  mi_trust_commit "$1" "$2"
}
