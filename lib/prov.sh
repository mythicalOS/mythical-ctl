#!/usr/bin/env bash
# §6a — provenance: the record of what THIS installer created, and the only authority for deleting it.
#
# Why it lives in the ledger and nowhere else: every other location is disqualified. A generated
# artifact under ~/.mythical/<product>/ cannot carry it, because §4.1a forbids reading those back as
# authority. The manifest cannot: it describes the product, not this machine's history. The runtime
# objects cannot: an image digest is identical whether the installer pulled it or the operator built
# it. So the design was relying on a record that had nowhere to live.
#
# The invariant that shapes every function here: ANY MISMATCH PRESERVES. A checksum failure, an
# unparseable ledger, an identity that does not match what is actually there, or an object present
# with no record — all resolve to leave it alone and report. No ambiguity is ever resolved in favour
# of deletion.
#
# PUBLIC SURFACE: mi_led_put, mi_led_del, mi_led_find, mi_led_all, mi_led_field, mi_ident_get,
# mi_ident_ensure, mi_member_add, mi_member_has, mi_member_del, mi_prov_record, mi_prov_find,
# mi_prov_tombstone, mi_prov_authority, mi_prov_image_record, mi_prov_gen, mi_first_use.
# mi_led_field is named here because it is easy to miss in the list above it and re-implement: it is
# the ONLY reader of a single field out of a record printed by mi_led_find / mi_led_all.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_PROV_KIND=object
MI_PROV_TOMB=tombstone
MI_PROV_IMAGE=image
MI_IDENT_KIND=identity
MI_MEMBER_KIND=product

# --- the generalized ledger editor -----------------------------------------------------------------
# The trust module's own record editor replaces a record matched by its FIRST field. Provenance
# records have several fields and a key that is not always first, so the read-modify-write is
# generalized here, once. Two implementations of a ledger edit are two chances to drop a record.

# A field must be KEY=VALUE with no TAB and no newline in either half: a TAB forges a field boundary
# and a newline forges a whole record, which is the same serialize-safely-on-write rule the family
# config writer applies to mythical.conf. Refuse rather than escape — there is no escaping in this
# format, so an escape would have to be invented and then honoured by every reader.
_mi_led_field_ok() {
  local f="$1"
  case "$f" in *=*) : ;; *) return 1 ;; esac
  local k="${f%%=*}"
  case "$k" in ''|*[!a-z_]*) return 1 ;; esac
  case "$f" in *$'\t'*) return 1 ;; esac
  case "$f" in *$'\n'*) return 1 ;; esac
  [ "${#f}" -le 1024 ]
}

# Does <record> carry <field>=<value>? Used to key an edit.
_mi_led_record_matches() {
  local record="$1" field="$2" value="$3" tok
  local IFS
  IFS=$'\t'
  # shellcheck disable=SC2086   # deliberate IFS split on TAB of a record we wrote ourselves
  set -- $record
  for tok in "$@"; do
    [ "$tok" = "${field}=${value}" ] && return 0
  done
  return 1
}

# Replace (or insert) one record of <kind> whose <field> equals <value>, preserving every other
# record. Read-modify-write under the lock; mi_ledger_write proves lock ownership itself, and this
# function asserts it too so the refusal names the caller's operation rather than "write the ledger".
mi_led_put() {
  if [ "$#" -lt 4 ]; then mi_warn "prov: mi_led_put needs <kind> <key-field> <key-value> <field>..."; return 1; fi
  local kind="$1" kf="$2" kv="$3"; shift 3
  mi_lock_assert_held "record installer state"
  local f rec="" records line out=""
  for f in "$@"; do
    if ! _mi_led_field_ok "$f"; then
      mi_warn "prov: refusing to write ledger field '$f' — fields are key=value, with no tab or newline"
      return 1
    fi
    rec="${rec}"$'\t'"${f}"
  done
  if records="$(mi_ledger_read)"; then :; else
    local rc=$?
    # rc 3 is "no ledger yet", a legitimate first write. Anything else is corruption, already
    # reported by mi_ledger_read — never overwrite a ledger we could not read.
    [ "$rc" -eq 3 ] || return "$rc"
    records=""
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$kind"$'\t'*)
        if _mi_led_record_matches "${line#*$'\t'}" "$kf" "$kv"; then continue; fi ;;
    esac
    out="${out}${line}"$'\n'
  done <<< "$records"
  out="${out}${kind}${rec}"$'\n'
  printf '%s' "$out" | mi_ledger_write
}

# Delete every record of <kind> whose <field> equals <value>. rc 0 even when none matched — a
# deletion that finds nothing has achieved its purpose.
mi_led_del() {
  if [ "$#" -ne 3 ]; then mi_warn "prov: mi_led_del needs <kind> <key-field> <key-value>"; return 1; fi
  local kind="$1" kf="$2" kv="$3" records line out=""
  mi_lock_assert_held "remove installer state"
  if records="$(mi_ledger_read)"; then :; else
    local rc=$?
    [ "$rc" -eq 3 ] && return 0
    return "$rc"
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$kind"$'\t'*)
        if _mi_led_record_matches "${line#*$'\t'}" "$kf" "$kv"; then continue; fi ;;
    esac
    out="${out}${line}"$'\n'
  done <<< "$records"
  printf '%s' "$out" | mi_ledger_write
}

# Print the one record of <kind> whose <field> equals <value> (field list, TAB-separated, without the
# kind). rc 0 found · 3 absent · 1 the ledger could not be read.
mi_led_find() {
  if [ "$#" -ne 3 ]; then mi_warn "prov: mi_led_find needs <kind> <key-field> <key-value>"; return 1; fi
  local kind="$1" kf="$2" kv="$3" records line
  records="$(mi_ledger_read)" || return $?
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$kind"$'\t'*)
        if _mi_led_record_matches "${line#*$'\t'}" "$kf" "$kv"; then
          printf '%s\n' "${line#*$'\t'}"; return 0
        fi ;;
    esac
  done <<< "$records"
  return 3
}

# Every record of <kind>, one per line, without the kind prefix.
mi_led_all() {
  if [ "$#" -ne 1 ]; then mi_warn "prov: mi_led_all needs <kind>"; return 1; fi
  local kind="$1" records line
  records="$(mi_ledger_read)" || return $?
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in "$kind"$'\t'*) printf '%s\n' "${line#*$'\t'}" ;; esac
  done <<< "$records"
  return 0
}

# Read one field out of a record printed by mi_led_find / mi_led_all.
mi_led_field() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_led_field needs <record> <field>"; return 1; fi
  # Save the field name BEFORE `set --`, which REPLACES the positional parameters: reading "$2"
  # afterwards would compare against the record's second field instead of the name we were asked for.
  # Found by executing this function, not by reading it.
  local tok want="$2"
  local IFS
  IFS=$'\t'
  # shellcheck disable=SC2086   # deliberate IFS split of a record we wrote ourselves
  set -- $1
  for tok in "$@"; do
    case "$tok" in "${want}="*) printf '%s\n' "${tok#*=}"; return 0 ;; esac
  done
  return 3
}

# --- installation identity (D32/§4b.4) ------------------------------------------------------------
# ~/.mythical/ is per-user, but container and volume names are daemon-GLOBAL: two OS users on one
# daemon would otherwise compute the same names and adopt or delete each other's containers. So every
# runtime name is scoped by an identity minted once per installation.
#
# It must be a valid `ident` (the document type: lowercase letter, then [a-z0-9-]) because every
# mi_name_* validates each component against it. 10 hex characters from the digest of a value that is
# unique per installation: enough that two installations on one machine will not collide, short
# enough that `docker ps` output stays readable.
#
# NO HYPHEN, FIXED LENGTH, AND BOTH ARE LOAD-BEARING. The flat `<prefix>-<a>-<b>-<c>` join the naming
# helpers perform is not injective, because `-` is inside the `ident` charset — so an identity
# carrying a hyphen could make two different (product, role) pairs derive the SAME name. `i` + 10 hex
# digits contributes no hyphen at all and a constant 11 characters, which is what keeps the join
# unambiguous at this end. A test pins both properties so a later change to the mint cannot
# reintroduce the ambiguity silently.

_mi_ident_mint() {
  local seed h
  # Seed from things that differ between installations on one machine, and hash them. Not from
  # $RANDOM alone: a mint that is not reproducible from its inputs cannot be debugged, and not from
  # the hostname alone, which two users share.
  seed="$(mi_home)|${USER:-unknown}|$(id -u 2>/dev/null || printf '0')|$(date +%s 2>/dev/null || printf '0')|${RANDOM}${RANDOM}"
  h="$(printf '%s' "$seed" | mi_digest /dev/stdin)" || return 1
  [ -n "$h" ] || return 1
  # Lead with a letter so the result is a valid `ident` even when the digest starts with a digit.
  printf 'i%s\n' "$(printf '%s' "$h" | cut -c1-10)"
}

# rc 0 prints the identity · 3 no ledger / no identity recorded · 1 the ledger could not be read.
#
# The 3-vs-1 split is what keeps a CORRUPT ledger from looking like a fresh machine. §6b: "cannot
# answer 'is this installation mine?' ⇒ refuse to act on any container".
mi_ident_get() {
  local v
  v="$(mi_ledger_get "$MI_IDENT_KIND" id)" || return $?
  [ -n "$v" ] || return 3
  printf '%s\n' "$v"
}

# Mint the identity if there is none, and print it either way. This is also where the ledger comes
# into existence: §6b makes identity initialization part of creating the ledger rather than a separate
# bit, so there is no state in which trust exists but identity is unknowable.
mi_ident_ensure() {
  # `if cmd; then …; fi` followed by `rc=$?` reads the status of the IF STATEMENT, which is 0 when the
  # condition was false and there is no else-branch — so the mint below was never reached and this
  # returned 0 with no output. Capture the status in the else-branch, where it is still the command's.
  local v rc
  if v="$(mi_ident_get)"; then printf '%s\n' "$v"; return 0; else rc=$?; fi
  [ "$rc" -eq 3 ] || return "$rc"
  v="$(_mi_ident_mint)" || { mi_warn "prov: cannot mint an installation identity"; return 1; }
  mi_led_put "$MI_IDENT_KIND" id "$v" "id=${v}" || return 1
  printf '%s\n' "$v"
}

# --- the initialized-product set (§6b) ------------------------------------------------------------
# A product NOT in the set is first-use: accept and record its trust floor (TOFU, §7.4d). A product
# IN the set with no floor is FAIL-CLOSED. A family-scoped marker made every SECOND product fail
# closed, which is why membership is a set and not a flag.

mi_member_add() {
  if [ "$#" -ne 1 ]; then mi_warn "prov: mi_member_add needs <product>"; return 1; fi
  mi_led_put "$MI_MEMBER_KIND" name "$1" "name=${1}"
}

mi_member_has() {
  if [ "$#" -ne 1 ]; then mi_warn "prov: mi_member_has needs <product>"; return 1; fi
  mi_led_find "$MI_MEMBER_KIND" name "$1" >/dev/null
}

# §6c: an ordinary product uninstall does NOT remove membership or the trust floor — clearing them
# would make `uninstall` then `install` a supported one-command rollback bypass. Only a FAMILY
# uninstall calls this.
mi_member_del() {
  if [ "$#" -ne 1 ]; then mi_warn "prov: mi_member_del needs <product>"; return 1; fi
  mi_led_del "$MI_MEMBER_KIND" name "$1"
}

# --- provenance records ---------------------------------------------------------------------------
# Objects are recorded by IMMUTABLE IDENTITY. For a network that is the runtime's own ID; for a
# container likewise; for a VOLUME there is no ID at all (D56 — `docker volume inspect` returns Name,
# Driver, Labels, Mountpoint, CreatedAt and nothing else, verified), so a volume's identity is the
# composite `name + nonce label`. Everywhere this code says "identify the volume", it means that pair.
#
# A name alone can be reassigned by ACCIDENT — `docker volume create` against an existing name
# succeeds — and a record naming `mythical-brokkr:0.1.0` would authorize deleting whatever holds that
# tag TODAY. The nonce closes that. It is MISIDENTIFICATION protection, not authentication: labels are
# world-readable, so any daemon-authorized actor can copy one nonce onto another object — and that
# actor can also simply read the volume. The threat model is accident and cross-installation
# collision (§4b.4), and the claim is scoped to it.

_mi_prov_class_ok() {
  case "$1" in container|volume|network|probe) return 0 ;; esac
  mi_warn "prov: '$1' is not a provenance class"
  return 1
}

# THE KEY IS CLASS + NAME, and it must be a single field because mi_led_put matches one field.
#
# Keying on the name alone is not merely imprecise, it is a REACHABLE collision: a product literally
# named `p1-state` derives the container name `mythical-<id>-p1-state`, which is byte-identical to the
# volume name for product `p1` role `state`. Recording either would then DELETE the other's record —
# and an object whose provenance vanished is unauthorized for deletion forever and trips §6b.2's
# unrecorded-same-identity gate on every later operation. Same shape as an intent's key, for the same
# reason.
_mi_prov_key() { printf '%s:%s\n' "$1" "$2"; }

# The generation of the record currently held for <class>/<name>, or 0.
mi_prov_gen() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_gen needs <class> <name>"; return 1; fi
  local rec g rc
  if rec="$(mi_prov_find "$1" "$2")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then printf '0\n'; return 0; fi
  [ "$rc" -eq 0 ] || return "$rc"
  if g="$(mi_led_field "$rec" gen)"; then printf '%s\n' "$g"; else printf '0\n'; fi
}

# Record (or supersede) provenance for one object. Extra `key=value` fields are passed through — an
# `id=` for a container or network, a `product=`/`role=` for reporting.
#
# GENERATION-AWARE BY REWRITING: mi_led_put drops the existing record for this name before appending,
# so reinstalling supersedes rather than appending beside. An append-only log of three installs
# otherwise leaves three claims about one object, the oldest as authoritative as the newest. The
# `gen=` counter is diagnostic — §10a tests "superseded generation" and "reinstall" explicitly, and a
# monotonic number is what makes a stale record recognisable in a report — but the KEY is class+name.
mi_prov_record() {
  if [ "$#" -lt 3 ]; then mi_warn "prov: mi_prov_record needs <class> <name> <nonce> [field...]"; return 1; fi
  local class="$1" name="$2" nonce="$3"; shift 3
  _mi_prov_class_ok "$class" || return 1
  local gen
  gen="$(mi_prov_gen "$class" "$name")" || return 1
  gen=$((gen + 1))
  mi_led_put "$MI_PROV_KIND" key "$(_mi_prov_key "$class" "$name")" \
    "key=$(_mi_prov_key "$class" "$name")" "class=${class}" "name=${name}" "nonce=${nonce}" \
    "gen=${gen}" "$@"
}

# rc 0 prints the record · 3 no record · 1 unreadable ledger.
mi_prov_find() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_find needs <class> <name>"; return 1; fi
  mi_led_find "$MI_PROV_KIND" key "$(_mi_prov_key "$1" "$2")"
}

# Removal: write the tombstone FIRST, then drop the object record — and do both in one ledger write,
# because two writes leave a window in which the object is neither recorded nor tombstoned, and a
# crash there loses the fact that it ever existed.
#
# §6b: provenance survives what it describes. An ordinary uninstall RETAINS named volumes, so removing
# a product's records outright would leave a later `--purge` with no authority over volumes that still
# exist — and the fail-safe rule would then preserve them forever. So uninstall tombstones what it
# removed and keeps the rest.
mi_prov_tombstone() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_tombstone needs <class> <name>"; return 1; fi
  local class="$1" name="$2" rec nonce="" gen="0" records line out=""
  _mi_prov_class_ok "$class" || return 1
  mi_lock_assert_held "tombstone an object"
  if rec="$(mi_prov_find "$class" "$name")"; then
    nonce="$(mi_led_field "$rec" nonce)" || nonce=""
    gen="$(mi_led_field "$rec" gen)" || gen=0
  fi
  records="$(mi_ledger_read)" || {
    local rc=$?; [ "$rc" -eq 3 ] || return "$rc"; records="";
  }
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$MI_PROV_KIND"$'\t'*)
        # CLASS AND NAME, not name alone: a container and a volume can derive the same name (see
        # _mi_prov_key), and tombstoning one must not silently erase the other's provenance.
        if _mi_led_record_matches "${line#*$'\t'}" key "$(_mi_prov_key "$class" "$name")"; then continue; fi ;;
      "$MI_PROV_TOMB"$'\t'*)
        # A second removal of the same object supersedes the earlier tombstone rather than appending
        # beside it — otherwise a reinstall/uninstall cycle accumulates one tombstone per generation.
        if _mi_led_record_matches "${line#*$'\t'}" key "$(_mi_prov_key "$class" "$name")"; then continue; fi ;;
    esac
    out="${out}${line}"$'\n'
  done <<< "$records"
  out="${out}${MI_PROV_TOMB}"$'\t'"key=$(_mi_prov_key "$class" "$name")"$'\t'"class=${class}"$'\t'"name=${name}"$'\t'"nonce=${nonce}"$'\t'"gen=${gen}"$'\n'
  printf '%s' "$out" | mi_ledger_write
}

# --- images (D37) ---------------------------------------------------------------------------------
# Docker fixes image labels at BUILD time, so a digest-pinned image pulled from a registry cannot
# carry an installation-specific label and the nonce scheme simply does not apply. The same digest may
# also legitimately back several installations, or have been pulled by the operator for unrelated
# work.
#
# And the ledger proves ACQUISITION, not OWNERSHIP: even an intact ledger records only that THIS
# installer pulled that digest. It cannot know whether another installation on the same daemon, or the
# operator's own work, also depends on it.

mi_prov_image_record() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_image_record needs <ref> <product>"; return 1; fi
  mi_led_put "$MI_PROV_IMAGE" ref "$1" "ref=${1}" "product=${2}"
}

# --- deletion authority ---------------------------------------------------------------------------
# THE function every removal path must call, and the only one that may say yes.
#
# rc 0 authorized · 3 the object is already gone (nothing to do) · 1 NOT authorized (reported).
#
# Every "no" preserves. There is no argument that flips it, and no caller may fall back to deleting by
# name when this returns 1 — that is exactly the misidentification the nonce exists to catch.
mi_prov_authority() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_authority needs <class> <name>"; return 1; fi
  local class="$1" name="$2" rec recorded actual rc

  if [ "$class" = image ]; then
    mi_warn "prov: images are never removed automatically (D37) — the ledger proves acquisition, not"
    mi_warn "  ownership, and the same digest may back another installation or a local build."
    return 1
  fi
  _mi_prov_class_ok "$class" || return 1

  if rec="$(mi_prov_find "$class" "$name")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "prov: '$name' has no provenance record — preserving it and reporting."
    mi_warn "  The installer cannot prove it created this, so it will not remove it."
    return 1
  fi
  [ "$rc" -eq 0 ] || return 1

  recorded="$(mi_led_field "$rec" nonce)" || recorded=""
  if [ -z "$recorded" ]; then
    mi_warn "prov: the record for '$name' carries no nonce — preserving it and reporting."
    return 1
  fi

  # Compare against what is ACTUALLY there. A record is a claim about the past; the nonce label is the
  # object's own answer about the present.
  local field
  case "$class" in
    volume)             field=v.nonce ;;
    container|probe)    field=c.nonce ;;
    network)            field=n.nonce ;;
  esac
  local ikind="$class"
  [ "$ikind" = probe ] && ikind=container
  if actual="$(mi_rt_inspect "$ikind" "$field" "$name")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 3; fi          # already gone: nothing to authorize, nothing to fear
  [ "$rc" -eq 0 ] || return 1                    # daemon unreachable: authorize nothing

  if [ "$actual" != "$recorded" ]; then
    mi_warn "prov: '$name' carries nonce '$actual' but the ledger recorded '$recorded' — it does not match."
    mi_warn "  A name can be reassigned to an object this installer never created, so this is"
    mi_warn "  PRESERVED and reported rather than removed."
    return 1
  fi
  return 0
}

# --- first use (§6b.3) ----------------------------------------------------------------------------
# "No ledger" is only first use when nothing else is there either. An earlier revision said absence
# means a fresh installation AND claimed a backup restored without the ledger would be detected —
# which cannot both hold if absence is unconditionally benign. The distinguishing evidence is not the
# ledger; it is everything else the installer would have created.
#
# rc 0 genuinely first use · 3 a ledger exists (not first use) · 1 INCONSISTENT (reported).
mi_first_use() {
  local h; h="$(mi_home)"
  if [ -f "$h/.state/ledger" ]; then return 3; fi

  local found=""
  local p
  for p in "$h"/*.conf; do
    [ -e "$p" ] || continue
    case "$(basename "$p")" in mythical.conf) continue ;; esac   # the family file alone is not product state
    found="${found} $(basename "$p")"
  done
  for p in "$h"/*/; do
    [ -d "$p" ] || continue
    case "$(basename "$p")" in bin|.state|transcripts|logs) continue ;; esac
    found="${found} $(basename "$p")/"
  done

  # A STAGING ledger is its own third state (§6c/D59): an in-progress restore is not first use and not
  # inconsistent. Reported here so ordinary commands refuse and name it rather than proceeding.
  if [ -f "$h/.state/ledger.staging" ]; then
    mi_warn "prov: there is no active ledger, but a restore is in progress (.state/ledger.staging)."
    mi_warn "  Resume it with 'mythical-ctl restore --resume', or abandon it with 'restore --abandon'."
    return 1
  fi

  if [ -n "$found" ]; then
    mi_warn "prov: there is no installer state ledger, but this home already holds:${found}"
    mi_warn "  A fresh machine does not have product configs or generated directories, so this is"
    mi_warn "  inconsistent — most often a backup restored without the installer state ledger."
    mi_warn "  Run 'mythical-ctl state repair' to rebuild what is reconstructible."
    return 1
  fi

  # And labelled runtime objects, which survive `rm -rf ~/.mythical` entirely (§3a).
  #
  # We have no identity to filter by (the ledger that held it is absent), so ask a question that does
  # not need one: does ANY object carry a name this installer's scheme would produce? The prefix is
  # ours by construction (mi_name_* / MI_NAME_PREFIX), so a match is either our own object from a
  # previous install or a collision — both of which make "fresh machine" false. A find-by-label sweep
  # cannot stand in for this: every label filter needs the installation identity as its value, and the
  # identity is precisely what is missing.
  local anyobj="" kind
  for kind in container volume network; do
    local n
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      case "$n" in "${MI_NAME_PREFIX}-"*) anyobj="${anyobj} ${kind}:${n}" ;; esac
    done <<< "$(_mi_prov_list_all "$kind")"
  done
  if [ -n "$anyobj" ]; then
    mi_warn "prov: there is no installer state ledger, but the container runtime already holds"
    mi_warn "  labelled or family-named objects:${anyobj}"
    mi_warn "  This is inconsistent — refusing to treat the machine as a first install."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  return 0
}

# List every object of <kind>, unfiltered. Only mi_first_use needs this — everything else works from
# labels, because §6a rejects names as reassignable. Kept private for that reason.
_mi_prov_list_all() {
  case "$1" in
    container) _mi_rt container ls -a --format '{{.Names}}' 2>/dev/null || true ;;
    network)   _mi_rt network   ls    --format '{{.Name}}'  2>/dev/null || true ;;
    volume)    _mi_rt volume    ls    --format '{{.Name}}'  2>/dev/null || true ;;
  esac
}
