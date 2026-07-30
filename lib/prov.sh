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

# THE SAME RULE, ON EVERY INPUT THAT REACHES THE SERIALIZER — which was the defect, not the rule.
# A record is `<kind>` TAB `<field>` TAB `<field>`…, so the KIND is written to the same line by the
# same function, and a TAB or newline in it forges precisely what a TAB or newline in a field forges:
#
#   mi_led_put $'identity\tid=forged\nobject' … 'x=y'
#
# wrote an `identity` record carrying `id=forged` followed by a second record, and the identity
# reader then answered `forged`. Validating one of the three arguments is not validating the rule.
#
# A kind is a CLOSED vocabulary (the five constants at the top of this file), so it is held to the
# grammar those already use rather than merely scrubbed of the two dangerous bytes: a kind outside
# the grammar is a caller bug whatever it contains.
_mi_led_kind_ok() {
  case "$1" in ''|*[!a-z_]*) return 1 ;; esac
  [ "${#1}" -le 64 ]
}

# <kind> [<key-field> <key-value>] — the arguments every entry point of the editor takes (mi_led_all
# has no selector; the other three do). The selector IS a field split in two: it has to equal a
# serialized field byte for byte to match one, so it is judged by the FIELD rule rather than by a
# second rule that would drift from it. A selector no field could ever equal supersedes nothing and
# deletes nothing, silently.
_mi_led_args_ok() {
  if ! _mi_led_kind_ok "$1"; then
    mi_warn "prov: refusing ledger record kind '$1' — a kind is lowercase letters and underscore"
    return 1
  fi
  if [ "$#" -eq 3 ] && ! _mi_led_field_ok "${2}=${3}"; then
    mi_warn "prov: refusing ledger key selector '${2}=${3}' — a selector is one key=value field"
    return 1
  fi
  return 0
}

# Judge a whole field list. It lives beside the rule rather than inside mi_led_put because
# mi_prov_tombstone serializes a record itself and must reach the identical check — two copies of a
# serialization rule drift, and this one is the difference between a record and a forged record.
_mi_led_fields_ok() {
  local f k seen=""
  for f in "$@"; do
    if ! _mi_led_field_ok "$f"; then
      mi_warn "prov: refusing to write ledger field '$f' — fields are key=value, with no tab or newline"
      return 1
    fi
    # ONE NAME, ONE FIELD — and this is a property of the LIST, not of a field, which is why it is
    # judged here rather than inside _mi_led_field_ok.
    #
    # A record's extra fields are passed through from the caller, so a record could be given a SECOND
    # `key=`. The matcher below accepts a record when ANY of its fields equals the selector, so such a
    # record answers the lookup for a DIFFERENT object's key while describing its own — and the
    # authority check then reads ITS nonce and compares it against the OTHER object's label. That is
    # authority over something this installer never created, assembled entirely out of accepted field
    # syntax. Every reader here (mi_led_field, mi_ledger_get) also takes the first hit and ignores the
    # rest, so a duplicate name is ambiguous even where it is not hostile.
    k="${f%%=*}"
    # `seen` is one space-delimited string on purpose: bash 3.2 has no associative arrays, and
    # _mi_led_field_ok has already proved the name is [a-z_]+, so no name can contain a space and the
    # padded comparison below cannot match a prefix by accident.
    case " ${seen} " in
      *" ${k} "*)
        mi_warn "prov: refusing a ledger record that carries '${k}' twice — one name, one field"
        return 1 ;;
    esac
    seen="${seen} ${k}"
  done
  return 0
}

# Does <record> carry <field>=<value>, EXACTLY ONCE? Used to key an edit.
#
# "Exactly once" is the whole guarantee, and returning on the first hit was not it: a record carrying
# two `key=` fields matched two different selectors, so one record could be superseded, deleted or
# retrieved as if it were another object's. mi_led_put refuses to write such a record, but the ledger
# is a file — a restore puts one there that this installation never authored, and a checksum proves
# integrity, not provenance. So the reader has to refuse it too, and independently.
#
# An ambiguous record matches NOTHING, including its own key: it is inert rather than deleted. Any
# mismatch preserves — the record stays on disk, is reported, and grants nothing.
_mi_led_record_matches() {
  local record="$1" field="$2" value="$3" tok hits=0 matched=1
  local IFS
  IFS=$'\t'
  # shellcheck disable=SC2086   # deliberate IFS split on TAB of a record we wrote ourselves
  set -- $record
  for tok in "$@"; do
    case "$tok" in
      "${field}="*)
        hits=$((hits + 1))
        if [ "$tok" = "${field}=${value}" ]; then matched=0; fi ;;
    esac
  done
  # Restore word-splitting BEFORE reporting: mi_warn joins its arguments with the first character of
  # IFS, so a message emitted while IFS is a TAB would come out tab-joined the day someone gives it a
  # second argument. Cheap here, invisible to find later.
  IFS=$' \t\n'
  if [ "$hits" -gt 1 ]; then
    mi_warn "prov: a ledger record carries '${field}' ${hits} times — it is ambiguous, so it matches"
    mi_warn "  nothing and grants nothing. Run 'mythical-ctl state repair'."
    return 1
  fi
  return "$matched"
}

# Replace (or insert) one record of <kind> whose <field> equals <value>, preserving every other
# record. Read-modify-write under the lock; mi_ledger_write proves lock ownership itself, and this
# function asserts it too so the refusal names the caller's operation rather than "write the ledger".
mi_led_put() {
  if [ "$#" -lt 4 ]; then mi_warn "prov: mi_led_put needs <kind> <key-field> <key-value> <field>..."; return 1; fi
  local kind="$1" kf="$2" kv="$3"; shift 3
  mi_lock_assert_held "record installer state"
  _mi_led_args_ok "$kind" "$kf" "$kv" || return 1
  local f rec="" records line out=""
  _mi_led_fields_ok "$@" || return 1
  for f in "$@"; do
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
  _mi_led_args_ok "$kind" "$kf" "$kv" || return 1
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
  _mi_led_args_ok "$kind" "$kf" "$kv" || return 1
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
  _mi_led_args_ok "$kind" || return 1
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

# A VALUE PARSED OUT OF A FILE IS NOT A NUMBER UNTIL IT HAS BEEN CHECKED, AND `$(( ))` IS NOT A
# PARSER — IT IS AN EVALUATOR.
#
# Bash evaluates a command substitution inside an arithmetic ARRAY SUBSCRIPT, so `n=$((v + 1))` with
# v='a[$(…)]' runs whatever is in the subscript. A value like that passes the field rule above
# untouched, because a field is only ever asked to hold no TAB and no newline — so a `gen=` written
# through this module's own public editor, or arriving in a ledger restored from a backup, executed
# arbitrary commands the next time anything recorded provenance for that object. The checksum on the
# ledger proves integrity, not provenance: it says the bytes were not altered after they were
# written, not that this installation wrote them.
#
# THE RULE, for whoever writes the next one: never let a value read from a file, a label, a manifest
# or a runtime answer reach `$(( ))`, `let`, an array subscript or `[ … -eq … ]` — all four evaluate
# arithmetic — until a check like this one has proved it is decimal digits and nothing else. This is
# the only arithmetic in the shipped tree operating on a parsed value; every other `$(( ))` in lib/
# and bin/ counts a loop or `$#`, both shell-controlled. If you add a second, bring this with you.
# (lib/ledger.sh keeps the schema number away from `[ -gt ]` for the neighbouring overflow reason.)
_mi_prov_gen_ok() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  # 18 digits is the widest value 64-bit signed arithmetic evaluates without wrapping. A bound also
  # keeps a megabyte of digits out of the evaluator.
  [ "${#1}" -le 18 ]
}

# The generation of the record currently held for <class>/<name>, or 0 when there is no record.
#
# A record that IS there and whose generation is not a number is refused, not reset: a silent reset to
# 0 is how a tampered record erases the generation history that would show it had been tampered with,
# and refusing is what this module does with every other fact it cannot read.
mi_prov_gen() {
  if [ "$#" -ne 2 ]; then mi_warn "prov: mi_prov_gen needs <class> <name>"; return 1; fi
  local rec g rc
  if rec="$(mi_prov_find "$1" "$2")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then printf '0\n'; return 0; fi
  [ "$rc" -eq 0 ] || return "$rc"
  g="$(mi_led_field "$rec" gen)" || g=""
  if ! _mi_prov_gen_ok "$g"; then
    mi_warn "prov: the record for '$2' carries a generation that is not a number ('$g') — refusing."
    mi_warn "  The ledger is checksummed, which proves it was not altered, not that this installation"
    mi_warn "  wrote it. Preserving it and reporting; run 'mythical-ctl state repair'."
    return 1
  fi
  printf '%s\n' "$g"
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
  # `gen` came out of the ledger, i.e. out of a FILE, and the line below EVALUATES it — see
  # _mi_prov_gen_ok, which is where that is proved to be digits. There is deliberately no second
  # check here: a guard whose removal changes nothing observable is a guard that gets removed.
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
  local class="$1" name="$2" rec nonce="" gen="0" records line out="" key trec
  _mi_prov_class_ok "$class" || return 1
  mi_lock_assert_held "tombstone an object"
  key="$(_mi_prov_key "$class" "$name")"

  # THIS FUNCTION IS THE THIRD WRITER, and it is the one that does NOT go through mi_led_put — it
  # serializes its own record below. So the field rule has to be applied here too, or <name> reaches
  # the serializer unchecked and a newline in it forges a whole record exactly as it would through
  # mi_led_put. `key=` is judged in its FIELD form because that is also its SELECTOR form: the two
  # are the same string, and a selector no record could ever equal supersedes nothing, silently.
  #
  # `class` is already closed by _mi_prov_class_ok. `nonce` and `gen` are NOT re-checked, and that is
  # a statement about the format rather than an omission: both come back out of mi_led_field, which
  # splits a single line on TAB, so neither can contain a TAB or a newline however the ledger got
  # written. The kind is this module's own constant. What remains variable is what is checked.
  _mi_led_fields_ok "key=${key}" "name=${name}" || return 1

  # WHERE THE IDENTITY COMES FROM, AND WHAT A REPEAT MUST NOT LOSE. The object record is
  # authoritative while it exists. Once it is gone, THE TOMBSTONE IS the surviving record of what was
  # there — so a second removal of the same object has to copy it forward. Reading only the object
  # record left the retry with nothing to read: it re-initialised nonce="" gen=0, dropped the
  # tombstone it had written a moment earlier and replaced it with an empty one. Retrying is safe
  # everywhere else in this module, and this is the one operation whose entire purpose is preserving
  # the identity of something removed, so a retry destroying exactly that inverted the supersession
  # rule below — "supersedes the earlier tombstone" has to mean "with equivalent content".
  if rec="$(mi_prov_find "$class" "$name")"; then :
  elif rec="$(mi_led_find "$MI_PROV_TOMB" key "$key")"; then :
  else rec=""
  fi
  # An unreadable ledger reaches this as an empty record and is caught by the read below, which
  # returns its status rather than writing — a tombstone is never written over a ledger we could not
  # read, so an empty record here cannot become an empty tombstone on disk.
  if [ -n "$rec" ]; then
    nonce="$(mi_led_field "$rec" nonce)" || nonce=""
    gen="$(mi_led_field "$rec" gen)" || gen=""
    # THE SAME RULE AS THE READER'S, because this is the module's second reader of `gen` and its only
    # writer of a gen it did not compute. Nothing here evaluates the value — but copying a generation
    # this module has just refused to read into the record that OUTLIVES the object would preserve it
    # for the next reader instead of reporting it, and a module that will not read a value must not
    # write it back either.
    if ! _mi_prov_gen_ok "$gen"; then
      mi_warn "prov: the record for '$name' carries a generation that is not a number ('$gen') —"
      mi_warn "  refusing to carry it into a tombstone. Run 'mythical-ctl state repair'."
      return 1
    fi
  fi
  trec=$'\t'"key=${key}"$'\t'"class=${class}"$'\t'"name=${name}"$'\t'"nonce=${nonce}"$'\t'"gen=${gen}"
  records="$(mi_ledger_read)" || {
    local rc=$?; [ "$rc" -eq 3 ] || return "$rc"; records="";
  }
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$MI_PROV_KIND"$'\t'*)
        # CLASS AND NAME, not name alone: a container and a volume can derive the same name (see
        # _mi_prov_key), and tombstoning one must not silently erase the other's provenance.
        if _mi_led_record_matches "${line#*$'\t'}" key "$key"; then continue; fi ;;
      "$MI_PROV_TOMB"$'\t'*)
        # A second removal of the same object supersedes the earlier tombstone rather than appending
        # beside it — otherwise a reinstall/uninstall cycle accumulates one tombstone per generation.
        if _mi_led_record_matches "${line#*$'\t'}" key "$key"; then continue; fi ;;
    esac
    out="${out}${line}"$'\n'
  done <<< "$records"
  out="${out}${MI_PROV_TOMB}${trec}"$'\n'
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

  # THE RECORD MUST BE ABOUT WHAT WAS ASKED ABOUT — the third door, and the one that stays shut when
  # the other two are walked around.
  #
  # A record is retrieved by its `key=` field, but `key`, `class` and `name` are three independent
  # fields: nothing made them agree. A record whose key says one object while its class and name
  # describe another answers the lookup for the first and then hands this function the SECOND
  # object's nonce, which is compared against the FIRST object's label — and if they happen to match,
  # deletion of an object this installer never created is authorized.
  #
  # Checked here rather than in mi_prov_find, in ONE place: this is the only function that turns a
  # record into permission to delete, and a check in both would be a check in neither — whichever ran
  # first would shadow the other, and the shadowed one could then be deleted with nothing observable
  # changing.
  local rclass rname
  rclass="$(mi_led_field "$rec" class)" || rclass=""
  rname="$(mi_led_field "$rec" name)" || rname=""
  if [ "$rclass" != "$class" ] || [ "$rname" != "$name" ]; then
    mi_warn "prov: the record found for ${class} '${name}' does not describe it — it describes"
    mi_warn "  ${rclass:-<no class>} '${rname:-<no name>}'. A record that is about something else is"
    mi_warn "  not authority over this, so it is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi

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
  local led="$h/.state/ledger"

  # PRESENCE IS THE EVIDENCE, NOT READABILITY — and `-f` asks the wrong question. A failed or partial
  # restore leaves `.state/ledger` as a DIRECTORY, or as a dangling symlink; `-f` is false for both,
  # so with no other trace beside it the machine was declared fresh, and a fresh machine is one this
  # installer initialises over. `-e` alone does not close it either: `-e` follows the link, so a
  # dangling symlink is invisible to it too. `-L` is what sees the link itself.
  if [ -f "$led" ]; then return 3; fi
  if [ -e "$led" ] || [ -L "$led" ]; then
    mi_warn "prov: the installer state ledger is present but is not a regular file — a directory, a"
    mi_warn "  dangling symlink or a device node, which is what a failed restore leaves behind."
    mi_warn "  Something is there, so this is not a first install; it is inconsistent, and it is"
    mi_warn "  reported rather than initialised over."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi

  # ONE SWEEP, ONE PRESENCE QUESTION, ASKED OF EVERY ENTRY. This was two loops over two globs, and
  # THE GLOB — not the test beside it — was what decided which entries got judged:
  #
  #   for p in "$h"/*/ ; do [ -d "$p" ] || continue
  #
  # bash expands a trailing-slash pattern by testing each candidate for DIRECTORY-ness, so
  # `$h/brokkr -> /gone` never became a candidate and the `[ -d ]` never ran on it. Patching that
  # test would have fixed nothing; measured, `[ -L "$h/link/" ]` is false even for a live link to a
  # directory, so a trailing slash defeats every test one could put next to it. `"$h"/*` offers
  # every entry — file, directory, live link and dangling link alike — and the tests below decide.
  local found=""
  local p b
  for p in "$h"/*; do
    b="${p##*/}"
    # PRESENCE, NOT READABILITY. `-e` follows a symlink, so it is false for a dangling one; `-L` is
    # the only test that sees the link itself. An unmatched glob expands to the literal pattern,
    # which is neither, so an empty home still falls through here.
    if [ -e "$p" ] || [ -L "$p" ]; then : ; else continue; fi
    case "$b" in
      # DELIBERATE EXEMPTIONS, and each for its own reason — not "these are not traces":
      #   mythical.conf         the family file is not evidence of any PRODUCT being installed.
      #   bin, .state           this installer's own scaffolding, created by mi_ensure_layout on
      #                         every run including the one asking the question, so counting them
      #                         would make no machine ever read as first use.
      #   transcripts, logs     user-data (§6c): they are MYTHICAL_HOME's original meaning and can
      #                         predate the installer entirely, so they are not evidence of a
      #                         previous INSTALLATION. They are still swept as data everywhere else.
      # Each is exempt whatever it is on disk — a dangling symlink named `bin` is exempt too, on
      # purpose, because the exemption is about what the NAME means, not about what is at the path.
      mythical.conf|bin|.state|transcripts|logs) continue ;;
      # A per-product config, readable or not: a dangling symlink named <product>.conf is as much a
      # trace of a previous installation as a readable file is.
      *.conf) found="${found} ${b}"; continue ;;
    esac
    # A per-product directory — or a link standing where one was. `-d` follows the link, so it is
    # true for a link to a live directory and false for a dangling one; `-L` catches what is left.
    if [ -d "$p" ]; then found="${found} ${b}/"; continue; fi
    if [ -L "$p" ]; then found="${found} ${b}"; continue; fi
    # Anything else here is a plain file at a name this installer never creates — not evidence.
  done

  # A STAGING ledger is its own third state (§6c/D59): an in-progress restore is not first use and not
  # inconsistent. Reported here so ordinary commands refuse and name it rather than proceeding.
  # Any presence at the path is the marker, for the same reason as the active ledger above — a
  # restore that failed while creating it is exactly the case this branch exists to catch.
  if [ -e "$h/.state/ledger.staging" ] || [ -L "$h/.state/ledger.staging" ]; then
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
  #
  # AND AN EMPTY ANSWER IS NOT THE SAME FACT AS NO ANSWER. The listings used to swallow every
  # failure, so a daemon that was down, absent from PATH, or refusing to answer produced three empty
  # listings and this function returned 0 — genuinely first use — off the strength of a question it
  # never got to ask. That is a fail-open on the single thing this function decides, and it inverts
  # the rule the whole module is built on: every other function here refuses when it cannot
  # establish a fact. Refuse here too, and say which listing failed.
  #
  # THIS IS THE FOURTH AND LAST TRACE QUESTION THIS FUNCTION ASKS, and the only one with no
  # filesystem path behind it — the other three (the ledger path, the staging marker, the home
  # sweep) are all `-e || -L` presence tests because a symlink can stand at any of them. There is no
  # symlink to see here, so that rule has no meaning for this one; its equivalent is the
  # answered-versus-could-not-be-asked distinction below, which is what makes the exemption safe
  # rather than merely true.
  local anyobj="" unasked="" kind names n
  for kind in container volume network; do
    if names="$(_mi_prov_list_all "$kind")"; then
      while IFS= read -r n; do
        [ -n "$n" ] || continue
        case "$n" in "${MI_NAME_PREFIX}-"*) anyobj="${anyobj} ${kind}:${n}" ;; esac
      done <<< "$names"
    else
      unasked="${unasked} ${kind}"
    fi
  done
  if [ -n "$unasked" ]; then
    mi_warn "prov: there is no installer state ledger, and the container runtime could not be asked"
    mi_warn "  what it holds (${unasked# })."
    mi_warn "  Labelled objects survive removing the home directory entirely, so 'no ledger' is only"
    mi_warn "  a first install once the runtime has ANSWERED that it holds none of ours."
    mi_warn "  Start the container runtime and run this again."
    return 1
  fi
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
#
# rc 0 the runtime ANSWERED and this is its listing, empty or not · non-zero it could not be asked.
# The `|| true` these arms used to carry reported "there is nothing there" for "I could not look",
# which is the one conclusion the caller must never reach by default. And the case statement had no
# default arm, so an unknown kind fell through to rc 0 with no output — the same fail-open one level
# down, from a typo rather than from a down daemon.
_mi_prov_list_all() {
  case "$1" in
    container) _mi_rt container ls -a --format '{{.Names}}' 2>/dev/null ;;
    network)   _mi_rt network   ls    --format '{{.Name}}'  2>/dev/null ;;
    volume)    _mi_rt volume    ls    --format '{{.Name}}'  2>/dev/null ;;
    *)         mi_warn "prov: '$1' is not a listable object kind"; return 1 ;;
  esac
}
