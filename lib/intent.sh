#!/usr/bin/env bash
# §6b — write-ahead intent, and §6b.2 — objects the ledger does not account for.
#
# The sequence every created object follows:
#
#   1. Record an INTENT — what is about to be created, with a fresh nonce — and commit the ledger.
#   2. Create the object, LABELLED with the installation identity and that nonce.
#   3. Record the CONFIRMATION, with the runtime's actual object ID, and commit.
#
# Recovery queries the runtime BY LABEL for the nonce, never by name (§6a rejects names as
# reassignable). But "not found ⇒ drop the intent" is wrong on its own: the daemon may have ACCEPTED
# the create and not finished it, so absence at the moment of the query proves nothing. Recovery
# reconciles rather than concludes.
#
# TWO RULES FROM lib/prov.sh RUN THROUGH EVERY FUNCTION HERE, because this module reads and writes the
# same ledger and a rule enforced at one module's inputs and not at the next module's is how each of
# that file's defects got in:
#
#   * A LOOKUP THAT DOES NOT RESOLVE TO EXACTLY ONE THING IS AMBIGUOUS, AND AMBIGUITY PRESERVES AND
#     REPORTS. mi_intent_confirm is the FOURTH writer that serializes its own record instead of going
#     through mi_led_put, so it asks that question — through _mi_led_select, the one place it is
#     asked — of all THREE record sets it consumes, and drops only the rows those resolved to.
#   * A VALUE PARSED OUT OF A FILE IS NOT A NUMBER UNTIL IT HAS BEEN CHECKED, AND `$(( ))` IS NOT A
#     PARSER. `created=` reaches arithmetic in mi_intent_abandonable, so it goes through the same
#     _mi_prov_gen_ok the generation counter does — which is what that function's own note asks the
#     next author to do rather than write a second one.
#
# And one rule of this module's own: ZERO MATCHES IS ONLY EVIDENCE WHEN THE RUNTIME ANSWERED. Every
# decision here that turns on "there are none" — reissue, adopt, abandon, gate — goes through a
# function that refuses to fold "could not ask" into "there are none".
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_INTENT_KIND=intent

# D39's grace period. NOT "quiescence": §6b.1 concedes the installer cannot observe whether Docker has
# finished a request it accepted, so there is no quiescent state to detect. This is a heuristic delay
# that makes a late arrival less likely, and nothing more. Five minutes — long enough that a daemon
# completing an accepted create has finished, short enough that an operator hitting the wedge is not
# told to come back tomorrow. A named constant so the number is arguable in one place, and so tests
# set it rather than sleeping.
MI_INTENT_GRACE=${MI_INTENT_GRACE:-300}

# A fresh nonce. Must be a safe label value, and must not repeat across calls within one run.
#
# THE SECOND PROPERTY CANNOT BE HELD BY STATE THIS FUNCTION KEEPS IN MEMORY, and this is the same
# mechanism that cost the multiple-match report its candidate list: every caller reads a PRINTED
# value — `n="$(mi_nonce_new)"` — and command substitution runs in a SUBSHELL, where every assignment
# the function makes to a global is discarded when it returns. A monotonic `_MI_NONCE_SEQ` stood here
# and was named as what guaranteed uniqueness; measured, it read 1 on every call and the caller's copy
# never moved. A guard that can be deleted with nothing observable changing is not a guard, and a
# comment naming the wrong mechanism costs the next author the round it cost this one.
#
# What actually distinguishes two calls is $RANDOM, because bash RESEEDS it per subshell: measured on
# this machine (bash 3.2.57), 500 sibling `$( … )` calls from one parent produced 500 distinct draws.
# `$$` does not help — inside `$( … )` it is still the PARENT's pid — and `date +%s` does not move
# within a second, so the random field carries this on its own and says so instead of being decorated
# with a counter that cannot. The property itself is pinned in tests/unit/intent.bats: 60 calls in the
# caller's own style, no repeat.
mi_nonce_new() {
  local h
  h="$(printf '%s|%s|%s' "$$" "$(date +%s 2>/dev/null || printf 0)" "${RANDOM}${RANDOM}${RANDOM}" \
       | mi_digest /dev/stdin)" || return 1
  [ -n "$h" ] || return 1
  printf 'n%s\n' "$(printf '%s' "$h" | cut -c1-16)"
}

_mi_intent_key() { printf '%s:%s\n' "$1" "$2"; }        # class:name — one live intent per object

# The runtime kind an intent's CLASS is asked about. `probe` is the only class whose runtime kind is
# not its own name — a probe IS a container to the runtime — and this is the one place that says so,
# rather than a `[ "$k" = probe ] && k=container` line beside every query. The vocabulary itself is
# not restated: it is lib/prov.sh's, so a class added there cannot silently mean nothing here.
_mi_intent_rtkind() {
  _mi_prov_class_ok "$1" || return 1
  if [ "$1" = probe ]; then printf 'container\n'; else printf '%s\n' "$1"; fi
}

# THE NONCE OUT OF AN INTENT RECORD — and PRESENCE is not the question, a VALUE is.
#
# mi_led_field returns 0 for a field spelled `nonce=` with nothing after it, because an empty value is
# a legal field and nothing in the format forbids one. So "the record answered" is not "there is a
# nonce", and an empty nonce is the single value that makes every label query below match nothing
# while looking exactly like a clean zero — after which reconciliation reissues and abandonment
# clears, both on the strength of a question that asked about nothing. Same shape as lib/prov.sh's
# "ONE RECORD, ZERO ANSWERS IS NOT ZERO RECORDS", one field along.
_mi_intent_nonce() {
  local rec="$1" name="$2" v
  if v="$(mi_led_field "$rec" nonce)"; then :; else
    mi_warn "intent: the intent for '$name' carries no nonce — it names nothing the runtime can be"
    mi_warn "  asked about, so it can be neither reconciled nor aged out. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  if [ -z "$v" ]; then
    mi_warn "intent: the intent for '$name' carries an EMPTY nonce — it says an object was about to be"
    mi_warn "  created without saying which one. A label query for it matches nothing, which is"
    mi_warn "  indistinguishable from 'it was never created'. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  printf '%s\n' "$v"
}

# --- whose is it, and is it the one -----------------------------------------------------------------
#
# ONE OBJECT'S INSTALLATION LABEL, or a REASON there is none. rc 0 the label is printed, and an EMPTY
# value means the object genuinely carries none · 3 the object is gone · 1 the question could not be
# answered (REPORTED).
#
# It replaces `mi_rt_inspect … || true` at three call sites, and that `|| true` was not a shortcut: it
# turned both failures into the empty string, which every reader here treats as a FACT — "this object
# carries no installation label". A down daemon therefore reported a foreign object as unlabelled, and
# an object that had already been removed reported the same. mi_rt_inspect splits 3 from 1 precisely
# so callers need not guess; this is the one place in this module that consumes the split.
_mi_intent_label() {
  local kind="$1" name="$2" ifield label rc
  case "$kind" in
    volume)    ifield=v.install ;;
    network)   ifield=n.install ;;
    container) ifield=c.install ;;
    *) mi_warn "intent: '$kind' has no installation label this adapter can read"; return 1 ;;
  esac
  if label="$(mi_rt_inspect "$kind" "$ifield" "$name")"; then rc=0; else rc=$?; fi
  [ "$rc" -ne 3 ] || return 3
  if [ "$rc" -ne 0 ]; then
    mi_warn "intent: the container runtime could not be asked which installation $kind '$name'"
    mi_warn "  belongs to. Nothing is adopted, aged out or accounted for on the strength of a"
    mi_warn "  question that was never answered."
    return 1
  fi
  # Docker's `index` on a label map with no such key prints `<no value>`, not the empty string, so the
  # unlabelled case arrives spelled two ways depending on whether the object has any labels at all.
  # The same normalization lib/prov.sh's authority check applies, for the same reason. It cannot
  # collide with a real identity: a minted one is `i` + 10 hex digits.
  case "$label" in '<no value>') label="" ;; esac
  printf '%s\n' "$label"
}

# IS THIS CANDIDATE THE OBJECT THIS INTENT DESCRIBES? — the ONE place a label match becomes "adopt it"
# or "it has appeared", and therefore the one place both halves of that question are asked.
#
# A NONCE SAYS WHICH OBJECT, NEVER WHOSE. It is misidentification protection, not authentication:
# labels are world-readable, and anyone who can put an object on this daemon can put our nonce on it.
# The evidence for "ours" is the object's own installation label — the same evidence, and the same two
# refusals, mi_prov_authority takes before it authorizes a removal. That check lived HERE too, but
# only on the path that reissues a volume and re-inspects it; the direct one-match path adopted
# whatever the nonce listing named. So with this installation iA and any object anywhere labelled
# `installation=iB, nonce=N`, an intent carrying N recorded THEIR object as this installation's
# provenance and dropped the intent — §4b.4's acceptance row is "two OS users, one daemon: no
# collision, no adoption", and a rule that decides adoption has to hold on every path that adopts.
#
# AND IT MUST BE THE OBJECT THE INTENT NAMED. The reissue path asks the runtime about `$name` and so
# could never adopt anything else; the direct path takes the name out of the listing, so an object of
# ours carrying this nonce under a DIFFERENT name was adopted as `class:name` — writing provenance,
# and later a deletion authority, for a name nothing holds. Everything downstream of this record
# looks an object up by name.
#
# rc 0 yes · 2 it is NOT ours: another installation's, or unlabelled (REPORTED) · 4 it IS ours but
# stands under another name (REPORTED) · 3 it is gone · 1 the question could not be answered
# (REPORTED). The five are five, not two: "gone" is a fact a later run can act on, "could not ask"
# authorizes nothing, and the two refusals differ in what an operator has to go and look at.
_mi_intent_ours() {
  local class="$1" name="$2" cand="$3" ident="$4" kind label rc
  kind="$(_mi_intent_rtkind "$class")" || return 1
  if label="$(_mi_intent_label "$kind" "$cand")"; then rc=0; else rc=$?; fi
  [ "$rc" -ne 3 ] || return 3
  [ "$rc" -eq 0 ] || return 1
  if [ -z "$label" ]; then
    mi_warn "intent: $kind '$cand' carries this intent's nonce but NO installation label, so nothing"
    mi_warn "  about the object itself says this installation created it. It is neither adopted nor"
    mi_warn "  removed: no label proves it is ours, and no provenance proves it is not someone else's."
    return 2
  fi
  if [ "$label" != "$ident" ]; then
    mi_warn "intent: $kind '$cand' carries this intent's nonce but is labelled for installation"
    mi_warn "  '$label'; this installation is '$ident'. A nonce says WHICH object, never WHOSE —"
    mi_warn "  anyone who can put an object on this daemon can put that label on it — so this is"
    mi_warn "  another installation's object. It is NOT adopted, NOT removed and NOT counted as ours."
    return 2
  fi
  if [ "$cand" != "$name" ]; then
    mi_warn "intent: $kind '$cand' carries this intent's nonce, but the intent is for '$name'."
    mi_warn "  Provenance, deletion authority and the unaccounted gate all look an object up by NAME,"
    mi_warn "  so recording this one under '$name' would record it for a name nothing holds. It is"
    mi_warn "  reported rather than adopted, and it is not removed."
    return 4
  fi
  return 0
}

# HOW MANY OBJECTS CARRY THIS NONCE — asked in ONE place, for both callers.
#
# `zero matches` is only evidence when the runtime ANSWERED. A find-by-label that could not be asked
# — the daemon is down, the kind is one the adapter will not list, the value is one it refuses —
# comes back empty, and folding that into "there are none" is what turns reconciliation into a
# reissue and abandonment into a clearance, on the strength of a question nobody got to ask. It is
# the same fail-open lib/prov.sh's mi_first_use closes for its own runtime listings.
#
# It was a check at one of the two call sites: mi_intent_abandonable pinged the daemon first and
# mi_intent_reconcile did not, so a reconcile against an unreachable daemon read as "zero" and
# reissued. One implementation, both callers — a copy at the second site is a guard that can be
# deleted with nothing observable changing.
#
# rc 0 the runtime answered · 1 it could not be asked, REPORTED. On success BOTH the count and the
# listing are left in MI_INTENT_COUNT and MI_INTENT_MATCH, valid until the next call, exactly as
# lib/prov.sh's MI_LED_TOK is — and, exactly as there, both callers copy them into locals on the
# following line.
#
# IT PRINTS NOTHING, AND THAT IS THE POINT. It used to print the count and publish the listing in a
# global, so it was called as `count="$(_mi_intent_matches …)"` — COMMAND SUBSTITUTION, which runs in
# a subshell, where the assignment to the global is made and then thrown away with the subshell.
# Measured: a global assigned inside `$( … )` is empty in the caller afterwards. The multiple-match
# branch therefore stopped correctly, printed "Candidates:", and named none of them — and the
# requirement it exists to satisfy is to report EVERY candidate. Publishing both values the same way
# is what makes the mistake loud if it is ever made again: a caller that wraps this in `$( … )` now
# gets an empty string, and `[ "" -gt 1 ]` is an error rather than a silent zero.
MI_INTENT_MATCH=""
MI_INTENT_COUNT=0

_mi_intent_matches() {
  local class="$1" nonce="$2" kind out line count=0
  MI_INTENT_MATCH=""; MI_INTENT_COUNT=0
  kind="$(_mi_intent_rtkind "$class")" || return 1
  if out="$(mi_rt_find_by_label "$kind" nonce "$nonce" 2>/dev/null)"; then :; else
    mi_warn "intent: the container runtime could not be asked which ${class}s carry nonce '$nonce'."
    mi_warn "  No answer and an empty answer are not the same fact, and every decision made from"
    mi_warn "  'there are none' — reissuing, adopting, abandoning — would be made from a question"
    mi_warn "  that was never answered."
    return 1
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    count=$((count + 1))          # a loop counter, not a value parsed out of a file
  done <<< "$out"
  MI_INTENT_MATCH="$out"
  MI_INTENT_COUNT="$count"
}

# Open an intent. Extra key=value fields ride along (product, role, id) so the confirmation and any
# report can name what was being built.
mi_intent_open() {
  if [ "$#" -lt 3 ]; then mi_warn "intent: mi_intent_open needs <class> <name> <nonce> [field...]"; return 1; fi
  local class="$1" name="$2" nonce="$3"; shift 3
  _mi_prov_class_ok "$class" || return 1
  # REFUSED ON THE WAY IN AS WELL AS ON THE WAY OUT. _mi_intent_nonce refuses an empty nonce when a
  # record is read, because a restored ledger can carry one; this refuses a caller that would write
  # one, because an intent that names no object can never be reconciled and would sit in the ledger
  # forever. The two are the same rule at the two ends the record travels between.
  if [ -z "$nonce" ]; then
    mi_warn "intent: refusing to record an intent with an empty nonce — the nonce is the only thing"
    mi_warn "  that lets recovery find the object this intent describes."
    return 1
  fi
  local now; now="$(date +%s 2>/dev/null || printf 0)"
  mi_led_put "$MI_INTENT_KIND" key "$(_mi_intent_key "$class" "$name")" \
    "key=$(_mi_intent_key "$class" "$name")" "class=${class}" "name=${name}" "nonce=${nonce}" \
    "created=${now}" "$@"
}

mi_intent_find() {
  if [ "$#" -ne 2 ]; then mi_warn "intent: mi_intent_find needs <class> <name>"; return 1; fi
  mi_led_find "$MI_INTENT_KIND" key "$(_mi_intent_key "$1" "$2")"
}

mi_intent_all() { mi_led_all "$MI_INTENT_KIND"; }

mi_intent_drop() {
  if [ "$#" -ne 2 ]; then mi_warn "intent: mi_intent_drop needs <class> <name>"; return 1; fi
  mi_led_del "$MI_INTENT_KIND" key "$(_mi_intent_key "$1" "$2")"
}

# Confirm: provenance in, intent out — ONE ledger write.
#
# Two writes would leave a window in which the object is both intended and recorded, and a crash there
# gives the next run two accounts of one object. The ledger is one atomic document (§6b) precisely so
# that related fields need not be written separately.
#
# It touches THREE record sets, and each one gets the cardinality question asked of it by the single
# function that asks it. An earlier draft filtered the ledger with its own loop — "drop every row
# whose key matches" — which is exactly the writer-side defect lib/prov.sh's _mi_led_select note
# describes: two contradicting intent rows, or two tombstones, would have been replaced by one
# confirmation, destroying the only evidence that the ledger needed repairing. That loop also dropped
# blank rows, which _mi_led_without preserves and reports for the same reason.
mi_intent_confirm() {
  if [ "$#" -lt 3 ]; then mi_warn "intent: mi_intent_confirm needs <class> <name> <nonce> [field...]"; return 1; fi
  local class="$1" name="$2" nonce="$3"; shift 3
  _mi_prov_class_ok "$class" || return 1
  mi_lock_assert_held "confirm a created object"

  local gen records rc ikey pkey oint="" oobj="" otomb="" rest
  # `gen` came out of the ledger, i.e. out of a FILE, and the line below EVALUATES it — mi_prov_gen is
  # where that is proved to be digits, and there is deliberately no second check here.
  gen="$(mi_prov_gen "$class" "$name")" || return 1
  gen=$((gen + 1))
  ikey="$(_mi_intent_key "$class" "$name")"
  pkey="$(_mi_prov_key "$class" "$name")"

  records="$(mi_ledger_read)" || { rc=$?; [ "$rc" -eq 3 ] || return "$rc"; records=""; }

  # The intent this confirmation consumes.
  if oint="$(_mi_led_select "$records" "$MI_INTENT_KIND" key "$ikey")"; then :; else
    rc=$?; [ "$rc" -eq 3 ] || return 1; oint=""
  fi
  # The provenance record it supersedes. mi_prov_gen has already refused an ambiguous set above; this
  # is not that check repeated, it is what decides WHICH row is dropped — the row the selector
  # resolved to, and no other.
  if oobj="$(_mi_led_select "$records" "$MI_PROV_KIND" key "$pkey")"; then :; else
    rc=$?; [ "$rc" -eq 3 ] || return 1; oobj=""
  fi
  # A tombstone for a name we are re-creating is stale by definition: the object exists again, with a
  # new nonce and a higher generation. Leaving it would make the same name both dead and live in one
  # ledger, and §6b.2's unrecorded-same-identity gate would then fire on our own freshly confirmed
  # object.
  if otomb="$(_mi_led_select "$records" "$MI_PROV_TOMB" key "$pkey")"; then :; else
    rc=$?; [ "$rc" -eq 3 ] || return 1; otomb=""
  fi

  # THE FIELD RULE, ON A WRITER THAT SERIALIZES ITS OWN RECORD. mi_led_put is not on this path, so
  # `name` and `nonce` would otherwise reach the serializer unchecked and a newline in either forges a
  # whole record — the same hole mi_prov_tombstone closes for the same reason. The list is built
  # ONCE and then both judged and written, so what was validated is what is serialized; and it is
  # judged as a LIST, so an extra field repeating a name the fixed part already uses is caught too.
  set -- "key=${pkey}" "class=${class}" "name=${name}" "nonce=${nonce}" "gen=${gen}" "$@"
  if ! _mi_led_fields_ok "$@"; then
    mi_warn "intent: refusing to write the confirmation record for ${class} '${name}'. Nothing was written."
    return 1
  fi
  local rec="${MI_PROV_KIND}" f
  for f in "$@"; do rec="${rec}"$'\t'"${f}"; done

  rest="$(_mi_led_without "$records" "$MI_INTENT_KIND" "$oint")"
  rest="$(_mi_led_without "$rest" "$MI_PROV_KIND" "$oobj")"
  rest="$(_mi_led_without "$rest" "$MI_PROV_TOMB" "$otomb")"
  # `$( )` strips the trailing newline, so the kept records are re-terminated here rather than fused
  # onto the record being appended; skipped entirely when nothing is kept.
  { [ -z "$rest" ] || printf '%s\n' "$rest"; printf '%s\n' "$rec"; } | mi_ledger_write
}

# --- reconciliation (§6b's recovery table) --------------------------------------------------------
#
#   exactly one match  ⇒ adopt it into the ledger — this IS the object the intent describes
#   zero matches       ⇒ containers and volumes: reissue the deterministic create, then RE-INSPECT and
#                        verify the labels. A conflict is not evidence — `docker volume create` against
#                        an existing name succeeds, returning whatever volume already holds it — so
#                        adopt only on an exact identity AND nonce match. Any ambiguous or unexpected
#                        error RETAINS the intent. NETWORKS: never reissue.
#   more than one       ⇒ STOP. Never delete to disambiguate. Report every candidate.
#
# and, before any of them, COULD NOT ASK ⇒ retain. That is not a fourth row of the table; it is the
# precondition the other three rest on, and it is asked by _mi_intent_matches.
#
# rc 0 reconciled · 1 stopped (reported) · 3 no such intent · 4 retained for a later run.
mi_intent_reconcile() {
  if [ "$#" -ne 2 ]; then mi_warn "intent: mi_intent_reconcile needs <class> <name>"; return 1; fi
  local class="$1" name="$2" rec nonce ident matches count rc
  _mi_prov_class_ok "$class" || return 1

  if rec="$(mi_intent_find "$class" "$name")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  nonce="$(_mi_intent_nonce "$rec" "$name")" || return 1
  ident="$(mi_ident_get)" || return 1

  # Called BARE, never through `$( … )` — see the note on _mi_intent_matches; a subshell would take
  # the listing with it and the report below would name nothing.
  if _mi_intent_matches "$class" "$nonce"; then :; else
    mi_warn "  The intent for $class '$name' is RETAINED and will be reconciled on a later run."
    return 4
  fi
  count="$MI_INTENT_COUNT"; matches="$MI_INTENT_MATCH"

  if [ "$count" -gt 1 ]; then
    mi_warn "intent: more than one $class carries nonce '$nonce' — stopping."
    mi_warn "  This can only come from a duplicate create and cannot be safely disambiguated."
    mi_warn "  Candidates:"
    local m
    while IFS= read -r m; do [ -n "$m" ] && mi_warn "    $m"; done <<< "$matches"
    mi_warn "  Remove the one you do not want with the container runtime directly, then re-run."
    return 1
  fi

  if [ "$count" -eq 1 ]; then
    local found id="" orc
    found="${matches%%$'\n'*}"

    # IS IT OURS, AND IS IT THE ONE — asked BEFORE anything is written, because this is an adoption
    # and this is the path that did not ask. Every answer but the first preserves both the object and
    # the intent.
    if _mi_intent_ours "$class" "$name" "$found" "$ident"; then orc=0; else orc=$?; fi
    case "$orc" in
      0) : ;;
      3) mi_warn "intent: the $class carrying nonce '$nonce' is already gone. Nothing is adopted; the"
         mi_warn "  intent is RETAINED and will be reconciled on a later run."
         return 4 ;;
      1) mi_warn "  The intent for $class '$name' is RETAINED and will be reconciled on a later run."
         return 4 ;;
      *) mi_warn "  The intent for $class '$name' is RETAINED, and nothing was recorded for it."
         return 1 ;;
    esac

    case "$class" in
      network)
        # THE ID IS READ HONESTLY OR NOT AT ALL. This was `… || true`, which turned a failed inspect
        # into an empty id and then confirmed anyway: "I could not ask about this object" became
        # provenance for an object that may not exist, and it dropped the intent — the only record
        # that would have let a later run recover. mi_rt_inspect's 3-vs-1 split is the whole point.
        if id="$(mi_rt_inspect network n.id "$found")"; then orc=0; else orc=$?; fi
        if [ "$orc" -eq 3 ]; then
          mi_warn "intent: network '$found' was listed and is already gone. Nothing is adopted; the"
          mi_warn "  intent is RETAINED and will be reconciled on a later run."
          return 4
        fi
        if [ "$orc" -ne 0 ]; then
          mi_warn "intent: the network carrying nonce '$nonce' could not be inspected, so this run"
          mi_warn "  cannot record what it is. The intent is RETAINED and nothing was written."
          return 4
        fi
        if [ -z "$id" ]; then
          mi_warn "intent: the runtime named no id for network '$found'. A network is recorded by its"
          mi_warn "  id (§6a rejects names as reassignable), so there is nothing to record. The intent"
          mi_warn "  is RETAINED."
          return 4
        fi ;;
      # D56: a volume has no ID at all — `docker volume inspect` returns Name, Driver, Labels,
      # Mountpoint and CreatedAt and nothing else — so name + nonce IS its identity.
      volume)           : ;;
      # A container's ID is read and recorded by the verb that launched it (Task 7), which holds the
      # rest of the launch facts worth recording alongside it.
      container|probe)  : ;;
      # Not reachable through the vocabulary above, and here for the same reason the reissue `case`
      # below has one: without it a class added to _mi_prov_class_ok later would be adopted with no
      # id and no thought, which is the silent half of the defect this arm's neighbour just fixed.
      *) mi_warn "intent: adopting a $class is not implemented — the intent is retained."
         return 4 ;;
    esac
    if [ -n "$id" ]; then
      mi_intent_confirm "$class" "$name" "$nonce" "id=${id}"
    else
      mi_intent_confirm "$class" "$name" "$nonce"
    fi
    return $?
  fi

  # Zero matches.
  if [ "$class" = network ]; then
    # D38: Docker does not guarantee name-conflict detection for networks, so a delayed original create
    # and a reissue can BOTH succeed, leaving two networks with the same name AND the same nonce —
    # and recovery could confirm the first and commit before the second appears, so the
    # multiple-match branch never runs and the duplicate is invisible to the ledger forever.
    mi_warn "intent: no network carries nonce '$nonce' yet, and a network is never reissued (D38)."
    mi_warn "  The intent is retained and will be reconciled on a later run."
    mi_warn "  If it never appears, 'mythical-ctl state abandon-intent network $name' offers a"
    mi_warn "  confirmed abandonment after a ${MI_INTENT_GRACE}s grace period."
    return 4
  fi

  case "$class" in
    volume)
      mi_rt_volume_create "$name" "$nonce" "$ident" >/dev/null || {
        mi_warn "intent: reissuing volume '$name' failed — retaining the intent for the next run"
        return 4; }
      ;;
    container|probe)
      # A container cannot be reissued from the intent alone: its image, mounts, ports and env are the
      # caller's to supply. The bring-up sequence owns that (Task 7); here we only report, so the
      # intent survives for the verb that knows how to rebuild it.
      mi_warn "intent: no $class carries nonce '$nonce'; rebuilding it needs the launch spec, so the"
      mi_warn "  intent is retained and the verb that opened it will re-create it."
      return 4
      ;;
    # Not reachable through the vocabulary above, and here anyway: without it a class added to
    # _mi_prov_class_ok later would fall through into the VOLUME re-inspection below and be judged
    # against a volume's labels. Retaining is the answer every other unknown gets here.
    *)
      mi_warn "intent: reissuing a $class is not implemented — the intent is retained."
      return 4
      ;;
  esac

  # RE-INSPECT. The create succeeding is not evidence of creation: against an existing name
  # `docker volume create` returns the existing volume WITHOUT applying our labels.
  #
  # Both halves go through the same two functions the direct one-match path above uses. They used to
  # be two `… || true` inspects compared in one condition, which was fail-CLOSED — an unanswerable
  # inspect became an empty string, which matched nothing, which refused — but it refused with the
  # wrong stated reason, telling an operator that an identity did not match when in fact nobody could
  # be asked. This module reports what actually happened everywhere else.
  local actual arc
  if _mi_intent_ours volume "$name" "$name" "$ident"; then arc=0; else arc=$?; fi
  case "$arc" in
    0) : ;;
    3) mi_warn "intent: the volume the reissue returned is already gone. The intent is RETAINED."
       return 4 ;;
    1) mi_warn "  The intent for volume '$name' is RETAINED and will be reconciled on a later run."
       return 4 ;;
    *) mi_warn "  The intent for volume '$name' is RETAINED, and nothing was recorded for it."
       return 1 ;;
  esac
  if actual="$(mi_rt_inspect volume v.nonce "$name")"; then arc=0; else arc=$?; fi
  if [ "$arc" -eq 3 ]; then
    mi_warn "intent: the volume the reissue returned is already gone. The intent is RETAINED."
    return 4
  fi
  if [ "$arc" -ne 0 ]; then
    mi_warn "intent: '$name' could not be inspected after the reissue, so nothing shows the volume"
    mi_warn "  standing there is the one this intent describes. The intent is RETAINED."
    return 4
  fi
  case "$actual" in '<no value>') actual="" ;; esac
  if [ "$actual" != "$nonce" ]; then
    mi_warn "intent: '$name' already existed and carries nonce '$actual', which does not match the"
    mi_warn "  '$nonce' this intent recorded — a create against an existing name succeeds and returns"
    mi_warn "  that volume without applying our labels."
    mi_warn "  It is NOT adopted — nothing proves it is ours — and NOT removed. The intent is retained."
    return 1
  fi
  mi_intent_confirm volume "$name" "$nonce"
}

# --- bounded retention (D39) ----------------------------------------------------------------------
# Retention without an exit is a wedge: if a network create never reached the daemon, every later run
# finds zero matches forever — never reissued because networks may not be, never cleared because zero
# is not proof of absence.
#
# rc 0 abandonable · 1 not yet (reported) · 3 no such intent.
mi_intent_abandonable() {
  if [ "$#" -ne 2 ]; then mi_warn "intent: mi_intent_abandonable needs <class> <name>"; return 1; fi
  local class="$1" name="$2" rec created now nonce count matches rc
  _mi_prov_class_ok "$class" || return 1

  if rec="$(mi_intent_find "$class" "$name")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"

  # The daemon must be REACHABLE. Zero matches against a daemon that is not answering is not evidence
  # of anything at all. (_mi_intent_matches refuses on a failed query too; this asks first so the
  # refusal names the daemon rather than the query.)
  if ! mi_rt_ping; then
    mi_warn "intent: the container runtime is not answering, so zero matches proves nothing."
    return 1
  fi

  nonce="$(_mi_intent_nonce "$rec" "$name")" || return 1
  # Bare, not `$( … )` — see the note on _mi_intent_matches.
  _mi_intent_matches "$class" "$nonce" || return 1
  count="$MI_INTENT_COUNT"; matches="$MI_INTENT_MATCH"

  # A MATCH IS ONLY EVIDENCE WHEN IT IS OURS, AND WHEN IT IS THE OBJECT THIS INTENT NAMED — the same
  # question the adoption path asks, asked by the same function, because "an object carrying this
  # nonce exists" was read here as "our object has appeared". Any object anywhere labelled with this
  # nonce then held the intent open forever: a network is never reissued (D38), a foreign object is
  # never adopted, and abandonment was refused — so the wedge D39's grace period exists to avoid was
  # reachable by another installation on the same daemon, or by anyone who copied a world-readable
  # label.
  if [ "$count" -ne 0 ]; then
    local ident m orc mine=0
    if ident="$(mi_ident_get)"; then :; else
      mi_warn "intent: this installation's own identity cannot be read, so nothing carrying this"
      mi_warn "  nonce can be shown to be ours or not ours. Refusing to age the intent out."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    while IFS= read -r m; do
      [ -n "$m" ] || continue
      if _mi_intent_ours "$class" "$name" "$m" "$ident"; then orc=0; else orc=$?; fi
      case "$orc" in
        0) mine=1 ;;
        # Reported by the call above. Another installation's object, or one that was listed and is
        # now gone: neither is evidence about the object this intent describes.
        2|3) : ;;
        # Ours, under another name. Abandoning would drop the only record tying this nonce to
        # anything, so it stops and an operator decides.
        4) mi_warn "  Refusing to age this intent out while an object of ours carries its nonce."
           return 1 ;;
        *) mi_warn "  Refusing to age an intent out on a question that was never answered."
           return 1 ;;
      esac
    done <<< "$matches"
    if [ "$mine" -eq 1 ]; then
      mi_warn "intent: the object for this intent has appeared — reconcile it instead of abandoning it."
      return 1
    fi
  fi

  # BOTH NUMBERS ARE CHECKED BEFORE EITHER REACHES ARITHMETIC, and by the SAME predicate the
  # generation counter uses — lib/prov.sh's note on _mi_prov_gen_ok asks the next author who puts a
  # parsed value into `$(( ))` to bring it along rather than write a second rule, and this is that
  # author. `created` comes out of the ledger, i.e. out of a file: measured on this machine, a
  # command substitution inside an arithmetic array subscript RUNS, so `created=a[$(…)]` — a
  # perfectly legal field, and a restored backup is the realistic source — would execute on the next
  # abandonment check.
  #
  # MI_INTENT_GRACE is checked for a different failure in the same line: `[ N -lt "$G" ]` with a
  # non-numeric G prints "integer expression expected" and returns 2, which an `if` reads as FALSE —
  # so a mistyped threshold would silently make EVERY intent immediately abandonable. Refusing is the
  # direction the rest of this module answers in.
  if created="$(mi_led_field "$rec" created)"; then :; else created=""; fi
  if ! _mi_prov_gen_ok "$created"; then
    mi_warn "intent: the intent for $class '$name' carries a creation time that is not a number"
    mi_warn "  ('${created}') — refusing to age it out. The ledger is checksummed, which proves it was"
    mi_warn "  not altered, not that this installation wrote it. Run 'mythical-ctl state repair'."
    return 1
  fi
  if ! _mi_prov_gen_ok "$MI_INTENT_GRACE"; then
    mi_warn "intent: MI_INTENT_GRACE is '${MI_INTENT_GRACE}', which is not a number of seconds."
    mi_warn "  An unreadable threshold does not fail the comparison, it fails it OPEN — every intent"
    mi_warn "  would read as older than the grace period. Refusing until it is a number."
    return 1
  fi
  now="$(date +%s 2>/dev/null || printf 0)"
  # Clock skew or a restored ledger can make created > now. Treat that as "not yet" rather than
  # computing a negative age that would pass every threshold.
  if [ "$created" -gt "$now" ]; then
    mi_warn "intent: this intent is dated in the future — refusing to age it out."
    return 1
  fi
  if [ $((now - created)) -lt "$MI_INTENT_GRACE" ]; then
    mi_warn "intent: this intent is $((now - created))s old; the grace period is ${MI_INTENT_GRACE}s."
    mi_warn "  Wait, then try again. The delay makes a late arrival from the daemon less likely — it is"
    mi_warn "  not a check that the daemon has finished, which cannot be observed."
    return 1
  fi
  return 0
}

# Clear a retained intent. ABANDONMENT IS AN OPERATOR DECISION, never automatic — the caller is
# responsible for the confirmation prompt (Task 9), and this function refuses unless the intent is
# actually abandonable.
mi_intent_abandon() {
  if [ "$#" -ne 2 ]; then mi_warn "intent: mi_intent_abandon needs <class> <name>"; return 1; fi
  mi_intent_abandonable "$1" "$2" || return 1
  mi_warn "intent: abandoning the recorded intent for $1 '$2'."
  mi_warn "  This does NOT guarantee convergence: the installer cannot distinguish 'never created'"
  mi_warn "  from 'not yet visible', so the object may still appear later. If it does, it is caught as"
  mi_warn "  an unrecorded same-identity object and the next operation will stop and report it."
  mi_intent_drop "$1" "$2"
}

# --- §6b.2: objects the ledger does not account for -----------------------------------------------
# An object can carry a mythicalOS label and be absent from this ledger for two entirely different
# reasons, and collapsing them into one word ("orphaned") is dangerous: on a shared daemon every OTHER
# user's healthy installation is also labelled for an identity this ledger does not account for.
# Calling those orphans invites removing someone else's working install.
#
#   FOREIGN-IDENTITY          labelled for a DIFFERENT installation. Report as unattributed. Never
#                             removed, never adopted, never proposed for removal. Not a cleanup queue.
#   UNRECORDED SAME-IDENTITY  labelled for THIS installation, absent from the ledger. STOP and report:
#                             this is ours and the ledger is wrong about it.
#   UNLABELLED, foreign name  ignored entirely.
#   UNLABELLED, OUR name      BLOCKS creation. Never adopted (no label proves it is ours) and never
#                             removed (no provenance proves it is not someone's).
#
# and a fifth line that is not a class of object but a class of ANSWER: COULD NOT ASK. See the note on
# mi_unaccounted_scan.
#
# mi_unaccounted_scan REPORTS all of them on stdout, one per line, and always succeeds.
# mi_unaccounted_gate returns nonzero for the three that must stop a mutating operation.

# Only the INSTALLATION label is read. The nonce says which object this is; the question here is only
# whose it is, and the nonce answer was computed and never used.
#
# THE THIRD SITE THAT SWALLOWED A FAILED INSPECT, and the one where doing so was fail-OPEN. `|| true`
# made an unanswerable question read as "this object carries no label", after which a name outside our
# scheme is ignored ENTIRELY — so a daemon that stopped between the listing and this question turned
# the objects the scan could not account for into objects the scan says nothing about, and the gate
# built on it reported clear. The two failures are now two answers, and both are the scan's to report:
# GONE (rc 3 — it is not there, so it accounts for nothing) and UNASKED (rc 1 — nothing here can be
# shown to be accounted for).
_mi_unacc_classify() {
  local kind="$1" name="$2" ident="$3" lident rc
  if lident="$(_mi_intent_label "$kind" "$name")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then printf 'gone\n'; return 0; fi
  if [ "$rc" -ne 0 ]; then printf 'unasked\n'; return 0; fi

  if [ -z "$lident" ]; then
    case "$name" in
      "${MI_NAME_PREFIX}-${ident}-"*|"${MI_NAME_PREFIX}-${ident}") printf 'colliding\n' ;;
      *) printf 'ignore\n' ;;
    esac
    return 0
  fi
  if [ "$lident" != "$ident" ]; then printf 'foreign\n'; return 0; fi

  # Same identity. Accounted for iff it has a live provenance record OR a live intent.
  if mi_prov_find "$kind" "$name" >/dev/null 2>&1; then printf 'recorded\n'; return 0; fi
  if mi_intent_find "$kind" "$name" >/dev/null 2>&1; then printf 'intended\n'; return 0; fi
  printf 'unrecorded\n'
}

# Print `CLASS<TAB>KIND<TAB>NAME` for every object that is not plainly accounted for. Always rc 0:
# this is a diagnostic, and `status` must be able to run it without being gated by its own findings.
#
# AN EMPTY ANSWER IS NOT THE SAME FACT AS NO ANSWER, and this function is the input to the gate that
# decides whether a mutating operation may proceed. A listing that could not be asked used to be
# swallowed, so a runtime that was down, absent from PATH, or refusing to answer produced three empty
# listings and the gate reported "clear" — a fail-open on the single thing the gate decides, and the
# same one lib/prov.sh's mi_first_use closes for its own sweep. The failure is REPORTED as a line
# rather than as a status, because rc 0 is this function's contract; the gate is where it stops
# anything. The identity is asked the same way: rc 3 is "there is none yet", which is first use and
# means nothing of ours can exist, but any other failure is a question that could not be asked.
mi_unaccounted_scan() {
  local ident kind name cls names rc
  if ident="$(mi_ident_get)"; then :; else
    rc=$?
    [ "$rc" -eq 3 ] || printf 'unasked\tinstallation identity\t-\n'
    return 0
  fi
  for kind in container volume network; do
    if names="$(_mi_prov_list_all "$kind")"; then :; else
      # An `unasked` row's second field is the SUBJECT that could not be answered for, not an object
      # kind — this row describes a question, not a thing.
      printf 'unasked\t%s listing\t-\n' "$kind"
      continue
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      cls="$(_mi_unacc_classify "$kind" "$name" "$ident")"
      case "$cls" in
        foreign)
          printf 'unattributed\t%s\t%s\n' "$kind" "$name" ;;
        unrecorded)
          printf 'unrecorded\t%s\t%s\n' "$kind" "$name" ;;
        colliding)
          printf 'colliding\t%s\t%s\n' "$kind" "$name" ;;
        # An object the listing named and this scan could not ask about. Reported as a row like every
        # other finding, with the object's own name in it — the listing-level `unasked` row above
        # cannot carry one, and "some volume somewhere" is not something an operator can go and look
        # at. `gone` and the accounted-for classes fall through: neither needs saying.
        unasked)
          printf 'unasked\t%s\t%s\n' "$kind" "$name" ;;
        *) : ;;
      esac
    done <<< "$names"
  done
  return 0
}

# The gate every MUTATING verb calls before it touches anything. rc 0 clear · 1 stop (reported).
#
# `status` deliberately does NOT call this — see the plan's Decisions item 9. A diagnostic that mutates
# nothing must not be blocked by what it found; a verb that mutates must be.
mi_unaccounted_gate() {
  local line cls kind name stop=0 report
  report="$(mi_unaccounted_scan)"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    cls="${line%%$'\t'*}"
    kind="$(printf '%s' "$line" | cut -f2)"
    name="$(printf '%s' "$line" | cut -f3)"
    case "$cls" in
      unattributed)
        # Another user's healthy installation, almost always (§4b.4). Report and carry on.
        mi_warn "note: $kind '$name' carries a mythicalOS installation label that is not this"
        mi_warn "  installation's. It may belong to another user on this daemon. It is left untouched."
        ;;
      unrecorded)
        mi_warn "stop: $kind '$name' is an unrecorded same-identity object: it is labelled for THIS"
        mi_warn "  installation, but the ledger has no record of it."
        mi_warn "  This is ours and the ledger is wrong about it — most often an abandoned intent's"
        mi_warn "  object that surfaced, a create confirmed after 'state repair' snapshotted, or a crash"
        mi_warn "  that lost the intent. It is never silently adopted and never automatically deleted."
        mi_warn "  Run 'mythical-ctl state repair', or remove it with the container runtime directly."
        stop=1
        ;;
      colliding)
        mi_warn "stop: $kind '$name' holds a name this installer would create, but is not labelled."
        mi_warn "  It is neither adopted nor removed: no label proves it is ours, and no provenance"
        mi_warn "  proves it is not someone else's. Rename or remove it, then re-run."
        stop=1
        ;;
      unasked)
        # Two subjects arrive here: a whole listing (name `-`), and one object the listing named.
        # Naming the object when there is one is the difference between a report an operator can act
        # on and one they cannot.
        if [ "$name" = "-" ]; then
          mi_warn "stop: the $kind could not be asked for, so nothing here can be shown to be"
          mi_warn "  accounted for."
        else
          mi_warn "stop: $kind '$name' could not be asked about, so it cannot be shown to be"
          mi_warn "  accounted for."
        fi
        mi_warn "  An empty answer and no answer are not the same fact, and this gate is what a"
        mi_warn "  verb asks before it changes anything. Start the container runtime — or, if the"
        mi_warn "  installer state is what could not be read, run 'mythical-ctl state repair' — then"
        mi_warn "  re-run."
        stop=1
        ;;
    esac
  done <<< "$report"
  return "$stop"
}
