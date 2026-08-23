#!/usr/bin/env bash
# D41/D44/D45/D47 — which network the family joins, and how it is ever changed.
#
# ATTACH BY ID, NEVER BY NAME (§6b.2). A rescan alone is a TOCTOU check — the delayed network can appear
# in the instant after it — so a scan can DETECT inconsistency but can never establish that none arises
# afterwards. What removes the ambiguity is not looking harder but not asking an ambiguous question:
# `docker network connect` accepts an ID, and an ID cannot resolve to a network that appeared later
# under the same name, however the race falls.
#
# TWO SOURCES OF A NETWORK ID, AND ONLY ONE OF THEM IS PROVENANCE (D41). An installer-created network's
# id comes from the ledger, and that record also carries deletion authority — the installer created it.
# An OPERATOR-SUPPLIED network (the D4 `MYTHICAL_NET` override) is configured by NAME, is deliberately
# unlabelled, and is NOT ours to remove: it gets a non-owned reference instead, resolved uniquely,
# persisted ATTACH-ONLY WITH NO DELETION AUTHORITY, and re-verified before use.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_NETREF_KIND=netref
MI_NETMIG_KIND=netmig

# --- the installer-owned network ------------------------------------------------------------------

# THE ONE READER of the owned network's provenance record, for both paths that hold one — the ordinary
# adopt and the one a reconciled intent produces. A second copy would be a second answer to "is the
# recorded network still there", and this is the answer that decides whether a SECOND network gets
# created beside the one already recorded.
#
# rc 0 prints the id · 1 refused (reported). There is deliberately no "recreate it" answer: recreating
# silently would strand every attached container on a network the ledger no longer names.
_mi_net_owned_adopt() {
  local rec="$1" id actual rc
  # ONE RECORD, ZERO ANSWERS IS NOT ZERO RECORDS. A record carrying no `id=` — or one carrying `id=`
  # with nothing after it, which is a legal field — used to fall through to the create path, so a
  # network this installation already has would have been stood up a second time beside it.
  if id="$(mi_led_field "$rec" id)"; then :; else
    mi_warn "netref: the recorded family network carries no id. A network is recorded BY its id (§6a"
    mi_warn "  rejects names as reassignable), so this record names nothing the runtime can be asked"
    mi_warn "  about — and creating one now would stand a second network beside whatever it describes."
    mi_warn "  It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  if [ -z "$id" ]; then
    mi_warn "netref: the recorded family network carries an EMPTY id — it says a network was created"
    mi_warn "  without saying which. It is PRESERVED and reported, never created over."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  # Re-verify: a recorded id that no longer resolves is not authority to create a second one.
  if actual="$(mi_rt_inspect network n.id "$id")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ] && [ "$actual" = "$id" ]; then
    printf '%s\n' "$id"
    return 0
  fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "netref: the recorded family network ($id) no longer exists."
  elif [ "$rc" -ne 0 ]; then
    mi_warn "netref: the recorded family network ($id) could not be inspected, so whether it is still"
    mi_warn "  there was never established."
  else
    mi_warn "netref: the recorded family network id ($id) is answered by '$actual'."
  fi
  mi_warn "  Run 'mythical-ctl state repair' — recreating it silently would strand every attached"
  mi_warn "  container on a network the ledger no longer names, with every product reporting healthy."
  return 1
}

# The installer's own network: created under write-ahead intent and labelled, like any other object.
# Its ledger record carries the id and DOES carry deletion authority.
#
# The D29 network preflight is NOT made here. It is made once, in mi_net_target, which is the door
# every source of a target id passes through — a check made on two of the three paths is a check the
# third one is missing.
mi_net_owned_ensure() {
  local ident name rec id nonce rc
  ident="$(mi_ident_get)" || return 1
  name="$(mi_name_network "$ident")" || return 1

  # THE RECORD, AND THE THREE ANSWERS IT CAN GIVE. Only rc 3 — "there is no record" — authorizes
  # creating a network. rc 1 is "the ledger could not be read, or two records answer", which
  # authorizes nothing: folding it into the first is how a second network gets created beside the one
  # already recorded, after which the ledger names one and the fleet is on the other.
  if rec="$(mi_prov_find network "$name")"; then rc=0; else rc=$?; fi
  case "$rc" in
    0) _mi_net_owned_adopt "$rec"; return $? ;;
    3) : ;;
    *) mi_warn "netref: whether this installation already has a family network could not be read from"
       mi_warn "  the ledger. Creating one now would stand a second network beside whatever is"
       mi_warn "  recorded. Nothing is created. Run 'mythical-ctl state repair'."
       return 1 ;;
  esac

  # A live intent from a previous crash governs, and networks are never reissued (D38). The same
  # three-way split: an unreadable ledger must not read as "no create was ever under way".
  if mi_intent_find network "$name" >/dev/null; then rc=0; else rc=$?; fi
  case "$rc" in
    3) : ;;
    0)
      # `return $?` after the `if` would read the IF STATEMENT's status — 0 when the condition was
      # false and there is no else-branch — so a RETAINED or stopped reconciliation reported SUCCESS
      # with no network id printed, and the caller then launched against an empty target.
      local rrc
      if mi_intent_reconcile network "$name"; then rrc=0; else rrc=$?; fi
      [ "$rrc" -eq 0 ] || return "$rrc"
      # It confirmed, so the provenance record is now the authority — read through the one reader that
      # judges it, rather than a second `mi_led_field` here that would answer differently.
      if rec="$(mi_prov_find network "$name")"; then :; else
        mi_warn "netref: the network intent reconciled, but no provenance record can be read for it."
        mi_warn "  Nothing is created over it. Run 'mythical-ctl state repair'."
        return 1
      fi
      _mi_net_owned_adopt "$rec"
      return $? ;;
    *) mi_warn "netref: whether a network create was already under way could not be read from the"
       mi_warn "  ledger. A network is never reissued (D38), and starting a second create here is"
       mi_warn "  exactly the duplicate that rule exists to prevent. Nothing is created."
       return 1 ;;
  esac

  nonce="$(mi_nonce_new)" || return 1
  mi_intent_open network "$name" "$nonce" || return 1
  if id="$(mi_rt_network_create "$name" "$ident" "$nonce")"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "netref: creating the family network failed. The intent is retained and reconciled later."
    return 1
  fi
  if [ -z "$id" ]; then
    mi_warn "netref: the runtime named no id for the network it created. A network is recorded BY its"
    mi_warn "  id, so there is nothing to confirm; the intent is RETAINED and reconciled later."
    return 1
  fi
  # RESCAN, as detection (§6b.2): having created a replacement, look for an extra same-identity network
  # and stop if one is there. That reports a state the operator needs to know about; it is the id that
  # makes the attach itself safe.
  #
  # The listing is CAPTURED AND CHECKED. `… 2>/dev/null || true` turned "the runtime could not be
  # asked" into an empty listing, which counts as one candidate and confirms — a duplicate ruled out
  # on the strength of a question that was never answered.
  local n line count=0
  if n="$(mi_rt_find_by_label network installation "$ident")"; then :; else
    mi_warn "netref: the runtime could not be asked which networks carry this installation's identity,"
    mi_warn "  so a duplicate create cannot be ruled out. The intent is RETAINED and nothing is"
    mi_warn "  confirmed."
    return 1
  fi
  # A loop counter, not a value parsed out of a file.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    count=$((count + 1))
  done <<< "$n"
  if [ "$count" -gt 1 ]; then
    mi_warn "netref: more than one network carries this installation's identity. Stopping."
    mi_warn "  This can only come from a duplicate create and cannot be safely disambiguated."
    mi_warn "$n"
    return 1
  fi
  mi_intent_confirm network "$name" "$nonce" "id=${id}" || return 1
  printf '%s\n' "$id"
}

# --- the non-owned reference (D41) ----------------------------------------------------------------

# rc 0 prints the recorded id · 3 no reference is recorded · 1 there is one and it cannot be read
# (REPORTED). The 3-vs-1 split is the whole of this reader: a record that is there but says nothing is
# not "no record", and treating it as one makes the next call RESOLVE AND WRITE OVER IT.
mi_net_ref_get() {
  local rec id rc
  if rec="$(mi_led_find "$MI_NETREF_KIND" key family)"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  if id="$(mi_led_field "$rec" id)"; then :; else
    mi_warn "netref: the recorded network reference carries no id — it says this installation was"
    mi_warn "  pointed at an operator's network without saying which one. It is PRESERVED and"
    mi_warn "  reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  if [ -z "$id" ]; then
    mi_warn "netref: the recorded network reference carries an EMPTY id, which names no network the"
    mi_warn "  runtime can be asked about. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  printf '%s\n' "$id"
}

# Resolve a configured NAME to an id, once, and it must resolve UNIQUELY: more than one match stops the
# operation rather than picking one.
#
# It lists by NAME rather than by label because an operator's network is deliberately unlabelled —
# mi_rt_find_by_label cannot answer this question at all — and it compares each listed name for
# equality rather than filtering, so no pattern, prefix or locale rule can widen the match.
mi_net_ref_resolve() {
  if [ "$#" -ne 1 ]; then mi_warn "netref: mi_net_ref_resolve needs a <name>"; return 1; fi
  local name="$1" all line count=0 id
  if [ -z "$name" ]; then
    mi_warn "netref: an empty network name names nothing, so nothing is resolved."
    return 1
  fi
  # CAPTURED AND CHECKED. A runtime that could not answer prints nothing, and reading that as "no such
  # network" is the fold this codebase refuses everywhere else: the operation would then stop with a
  # message sending the operator to look at a network that may well be there.
  if all="$(_mi_rt network ls --format '{{.Name}}')"; then :; else
    mi_warn "netref: the container runtime could not be asked which networks exist, so '$name' can be"
    mi_warn "  neither resolved nor shown to be absent. Nothing is resolved."
    return 1
  fi
  while IFS= read -r line; do
    [ "$line" = "$name" ] || continue
    count=$((count + 1))
  done <<< "$all"
  if [ "$count" -eq 0 ]; then
    mi_warn "netref: no network named '$name' exists."
    return 1
  fi
  if [ "$count" -gt 1 ]; then
    mi_warn "netref: more than one network is named '$name'. The reference is AMBIGUOUS, and the"
    mi_warn "  operation stops rather than picking one — attaching to whichever answered first is how"
    mi_warn "  a family joins a network the operator did not mean."
    return 1
  fi
  id="$(mi_rt_inspect network n.id "$name")" || return 1
  if [ -z "$id" ]; then
    mi_warn "netref: the runtime named no id for network '$name'. A network is referenced BY its id"
    mi_warn "  (§6a rejects names as reassignable), so there is nothing to record."
    return 1
  fi
  printf '%s\n' "$id"
}

# THE ONLY WRITER of the non-owned reference, and it will not write one that does not correspond to the
# configuration it came from.
#
# It exists as one function because THREE paths record this reference — a first resolution, a rebind
# with no containers to move, and D45 phase 6 — and each of them has to answer the same two questions
# before writing: is MYTHICAL_NET actually set, and does the name it holds resolve to the network the
# containers are on? A path that skipped either records a pair that does not correspond, and the very
# next mi_net_ref_verify then stops the installation over a mismatch this function created.
#
# It is deliberately NOT a provenance record: mi_prov_authority must never see it, so no uninstall path
# can ever read it as something to remove. `owned=no` says so in the record itself.
_mi_netref_commit() {
  local tgt="$1" name nowid rc
  if [ -z "$tgt" ]; then
    mi_warn "netref: refusing to record a network reference with no id."
    return 1
  fi
  if name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    mi_warn "netref: mythical.conf could not be read, so the network it names cannot be recorded."
    mi_warn "  Nothing was written."
    return 1
  fi
  if [ "$rc" -eq 3 ] || [ -z "$name" ]; then
    mi_warn "netref: MYTHICAL_NET is not set, so there is no operator network to record a reference to."
    mi_warn "  A reference recorded with no name is one nothing can ever re-verify. Nothing was"
    mi_warn "  written. Set MYTHICAL_NET, or use the installer's own network."
    return 1
  fi
  if nowid="$(mi_net_ref_resolve "$name")"; then :; else
    mi_warn "netref: MYTHICAL_NET names '$name', which does not resolve to exactly one network, so no"
    mi_warn "  reference is recorded. Fix the configuration and re-run."
    return 1
  fi
  if [ "$nowid" != "$tgt" ]; then
    mi_warn "netref: MYTHICAL_NET names '$name', which resolves to $nowid — but the network being"
    mi_warn "  recorded is $tgt. Refusing to record a reference that does not match where the"
    mi_warn "  containers actually are. Decide which network you want and re-run."
    return 1
  fi
  # ATTACH-ONLY, NO DELETION AUTHORITY.
  mi_led_put "$MI_NETREF_KIND" key family "key=family" "id=${tgt}" "name=${name}" "owned=no"
}

# Re-verify before use. A name that now resolves to a DIFFERENT id stops the operation and reports it,
# since the operator has replaced the network underneath us.
#
# AND THAT STOP HAS AN EXIT (D44). A changed or missing id is not always an attack: an operator edits
# MYTHICAL_NET, recreates a network, restores a backup, or runs `state repair`. Stopping forever on any
# of those is a wedge. So the report offers an EXPLICITLY CONFIRMED rebind — never automatic, because a
# silent rebind is precisely how a container gets joined to a network the operator did not intend.
mi_net_ref_verify() {
  local recorded name now rc
  recorded="$(mi_net_ref_get)" || return $?
  if name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    mi_warn "netref: mythical.conf could not be read, so the recorded network reference cannot be"
    mi_warn "  checked against it. Nothing is verified."
    return 1
  fi
  if [ "$rc" -eq 3 ] || [ -z "$name" ]; then
    mi_warn "netref: a non-owned network reference is recorded, but MYTHICAL_NET is no longer set."
    mi_warn "  Stopping. To adopt the installer's own network instead, remove the reference with a"
    mi_warn "  confirmed rebind: 'mythical-ctl net rebind'."
    return 1
  fi
  if now="$(mi_net_ref_resolve "$name")"; then :; else
    mi_warn "netref: MYTHICAL_NET names '$name', which does not resolve to exactly one network."
    mi_warn "  Stopping. 'mythical-ctl net rebind' offers an explicitly confirmed rebind once the"
    mi_warn "  network exists again."
    return 1
  fi
  if [ "$now" != "$recorded" ]; then
    mi_warn "netref: '$name' now resolves to a different network."
    mi_warn "    recorded: $recorded"
    mi_warn "    now:      $now"
    mi_warn "  The operator has replaced the network underneath this installation. Stopping."
    mi_warn "  'mythical-ctl net rebind' performs a confirmed rebind — which re-attaches EVERY existing"
    mi_warn "  container to the new id and verifies each, because recording the new id alone would"
    mi_warn "  leave the fleet on the old network with every product reporting healthy."
    return 1
  fi
  return 0
}

# The non-owned reference for <name>: the recorded one if there is one (re-verified), otherwise
# resolved once and recorded.
_mi_net_ref_ensure() {
  local name="$1" id rc oident oname oprc
  if id="$(mi_net_ref_get)"; then rc=0; else rc=$?; fi
  case "$rc" in
    0) mi_net_ref_verify || return 1
       # `$id` is the recorded value mi_net_ref_verify has just confirmed the name still resolves to,
       # so it is printed rather than read a second time: a second read is a second chance to discard
       # a failure, and the earlier revision of this function did exactly that.
       printf '%s\n' "$id"
       return 0 ;;
    3) : ;;
    *) return 1 ;;                 # there IS a reference and it could not be read; already reported
  esac
  # A FIRST non-owned reference is about to be recorded. If this installation ALREADY stood up its own
  # network, the fleet is on it — so silently recording a reference to the operator's network here would
  # leave every existing container on the owned network while new ones land on the operator's, the split
  # D45's phased rebind exists to prevent. Changing which network the family joins is the rebind's job,
  # never a side effect of resolving a target. So this is REFUSED, not recorded; 'net rebind' migrates.
  oident="$(mi_ident_get)" || return 1
  oname="$(mi_name_network "$oident")" || return 1
  if mi_prov_find network "$oname" >/dev/null; then oprc=0; else oprc=$?; fi
  case "$oprc" in
    3) : ;;                        # no owned network — a genuine first-time adoption of the operator's
    0) mi_warn "netref: MYTHICAL_NET names an operator network, but this installation already has its"
       mi_warn "  own family network with the fleet on it. Recording a reference now would split the"
       mi_warn "  family — new containers on the operator's network, the existing ones left behind."
       mi_warn "  Move the fleet with a confirmed rebind: 'mythical-ctl net rebind'."
       return 1 ;;
    *) mi_warn "netref: whether this installation already has its own family network could not be read,"
       mi_warn "  so recording a reference to the operator's network might split the fleet. Nothing is"
       mi_warn "  recorded. Run 'mythical-ctl state repair'."
       return 1 ;;
  esac
  id="$(mi_net_ref_resolve "$name")" || return 1
  _mi_netref_commit "$id" || return 1
  printf '%s\n' "$id"
}

# THE target network for this operation: the operator's if MYTHICAL_NET is set, ours otherwise.
#
# It takes the <index file> so every entry point a verb reaches into this module has one shape; nothing
# in this function needs it, and it is not read.
mi_net_target() {
  if [ "$#" -ne 1 ]; then mi_warn "netref: mi_net_target needs an <index file>"; return 1; fi
  local name id rc
  if name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    mi_warn "netref: mythical.conf could not be read, so which network this family joins cannot be"
    mi_warn "  established. Nothing is created and nothing is attached."
    return 1
  fi
  if [ "$rc" -eq 0 ] && [ -z "$name" ]; then
    # An operator who wrote the key meant something by it, and "" is not the installer's own network:
    # silently taking that branch would join the family to a network nobody named.
    mi_warn "netref: MYTHICAL_NET is set to an empty value. It names no network, and an empty override"
    mi_warn "  is not the same statement as no override at all. Remove the key to use the installer's"
    mi_warn "  own network, or name one."
    return 1
  fi
  if [ "$rc" -eq 3 ]; then
    # MYTHICAL_NET is not set — the installer's own network is the target. But if a non-owned reference
    # is RECORDED, the fleet is on an operator's network: MYTHICAL_NET was removed without moving it, and
    # creating or selecting the owned network now would strand every existing container on the operator's
    # network, the split D45 exists to prevent. That transition is the rebind's job, so it is REFUSED
    # here — mi_net_target resolves a steady-state target and must never flip which network the family is
    # on. (mi_net_owned_ensure's own path never calls verify, so this is the one place the check lands.)
    local rgrc
    if mi_net_ref_get >/dev/null; then rgrc=0; else rgrc=$?; fi
    case "$rgrc" in
      3) : ;;                       # no operator reference — the owned network is genuinely ours to use
      0) mi_warn "netref: MYTHICAL_NET is not set, but a reference to an operator network is recorded and"
         mi_warn "  the fleet is on it. Adopting the installer's own network now would split the family."
         mi_warn "  Remove the reference with a confirmed rebind: 'mythical-ctl net rebind'."
         return 1 ;;
      *) return 1 ;;                # a reference exists but could not be read; mi_net_ref_get reported it
    esac
    id="$(mi_net_owned_ensure)" || return $?
  else
    id="$(_mi_net_ref_ensure "$name")" || return $?
  fi
  if [ -z "$id" ]; then
    mi_warn "netref: no target network id was established, so there is nothing to attach to."
    return 1
  fi
  # THE D29 PREFLIGHT, ONCE, AT THE ONE PLACE THE TARGET IS ESTABLISHED. All three sources — a network
  # created now, one adopted from the ledger, and an operator's — reach this line, so none of them can
  # be the path that skipped it. It is re-asked on every call deliberately: `trusted_host_interfaces`
  # can be set on a network after this installation adopted it, and that re-exposes every
  # loopback-published port.
  mi_preflight_network "$id" || return 1
  printf '%s\n' "$id"
}

# --- D45: the phased fleet migration --------------------------------------------------------------
# "Refuse and roll back" is NOT implementable as an atomic operation, and an earlier revision promised
# it anyway: Docker has no transaction across N containers, the rebind can crash halfway with no record
# of what it had done, and rollback is impossible in the COMMONEST case — the old network having been
# deleted or recreated, so there is nothing to roll back onto.
#
# So it is a persisted phased migration, ordered so that NO PHASE LEAVES THE FAMILY PARTITIONED, with
# the phase recorded in the ledger BEFORE it is entered:
#
#   1  record the intent: SOURCE id, target id, and the container set
#   2  connect EVERY container to the new id with its alias, at a LOWER gateway priority than the source
#   3  verify via the probe: its own alias resolves, and every RUNNING sibling resolves AT ITS ENDPOINT
#      ADDRESS ON THE TARGET NETWORK. Stopped siblings are deferred, not demanded
#   4  detach each from the source network
#   5  verify final topology — every container exactly {target}, running siblings resolving at target
#      endpoints, egress working
#   6  commit the new reference, clear the intent
#
# THE INTENT RECORDS THE SOURCE, NOT ONLY THE TARGET. Phase 4 has to know what to detach, and after a
# crash the recovering process has no other way to learn it — the containers may by then be on two
# networks with nothing to say which was the old one.
#
# PHASE 5 EXISTS BECAUSE PHASE 6 DESTROYS THE ABILITY TO RESUME. Committing clears the intent, and the
# intent is what authorizes recovery — so if a single detach in phase 4 did not take effect, clearing
# first leaves a container on {source, target} with NO intent recorded, which §6b.3 classifies as a
# defect and which nothing can now resume.

# A PHASE OUT OF THE LEDGER IS NOT A NUMBER UNTIL IT HAS BEEN CHECKED. The resume loop compares and
# increments it, and `[ "$p" -le 6 ]` on a non-numeric prints "integer expression expected" and returns
# 2 — which an `if`/`while` reads as FALSE, so the loop never ran and recovery reported SUCCESS having
# migrated nothing. lib/prov.sh's _mi_prov_gen_ok is the digit rule (and the width bound that keeps a
# megabyte of digits out of the evaluator); it is reused rather than restated.
#
# One predicate, two readers — mi_netmig_phase and mi_netmig_resume — so neither shadows the other.
_mi_netmig_phase_ok() {
  if ! _mi_prov_gen_ok "$1"; then
    mi_warn "netref: the recorded migration phase '$1' is not a number, so there is no point to resume"
    mi_warn "  from. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  if [ "$1" -lt 1 ] || [ "$1" -gt 6 ]; then
    mi_warn "netref: the recorded migration phase '$1' is not one of the six phases. It is PRESERVED"
    mi_warn "  and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  return 0
}

# rc 0 prints the recorded phase · 3 no migration is recorded · 1 there is one and it cannot be read.
mi_netmig_phase() {
  local rec p rc
  if rec="$(mi_led_find "$MI_NETMIG_KIND" key family)"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  if p="$(mi_led_field "$rec" phase)"; then :; else
    mi_warn "netref: the recorded migration intent names no phase, so nothing can say how far it got."
    mi_warn "  It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  _mi_netmig_phase_ok "$p" || return 1
  printf '%s\n' "$p"
}

# Every container of this installation. By LABEL, never by name (§6a) — and `-a`, so a stopped one is
# in the set: a fleet operation that could not see a stopped product would declare the family migrated
# while leaving it on the old network.
_mi_netmig_containers() {
  local ident
  ident="$(mi_ident_get)" || return 1
  mi_rt_find_by_label container installation "$ident"
}

# THE FLEET THIS INVOCATION ACTS ON — FIXED AT INTENT-OPEN, never re-enumerated. §6a's rule that a
# name (or a set) can be reassigned while the RECORDED identity is the truth, applied to the fleet: once
# the intent records containers=<snapshot>, THAT snapshot is the migration's fleet and every later phase
# reads it back. Re-enumerating the live label set at phase 2/3/4/5 instead lets a container that
# appeared AFTER the intent opened — one phase 2 never connected and phase 3 never verified — be swept
# into phase 4's detach, stranding it on nothing while the ledger records the migration complete and its
# detach goes unprovenanced. A container that appears mid-migration is not part of THIS migration; it is
# §6b.2's unaccounted same-identity case the other paths already handle, not a member to move or detach.
#
# Only when NO intent is recorded yet does this OPEN one, snapshotting the live set — that is
# intent-open (phase 1, or a direct single-phase call that opens its own intent). An unreadable ledger
# is a THIRD answer and stops: it is not "no intent recorded", and enumerating past it would re-derive
# the very live set this exists to avoid.
#
# rc 0 prints the fleet (one container per line, possibly empty) · 1 refused (reported).
_mi_netmig_fleet() {
  local rec rc list
  if rec="$(mi_led_find "$MI_NETMIG_KIND" key family)"; then rc=0; else rc=$?; fi
  case "$rc" in
    0)
      if list="$(mi_led_field "$rec" containers)"; then :; else
        mi_warn "netref: the recorded migration names no container set, so the fleet it opened against"
        mi_warn "  is unknown. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
        return 1
      fi
      # _mi_netmig_record stores the set comma-joined; restore the newline form the phase loops read.
      # An empty value is legal (an intent opened against a fleet with no containers) and yields nothing.
      printf '%s' "$list" | tr ',' '\n'
      ;;
    3)
      _mi_netmig_containers || return 1
      ;;
    *)
      mi_warn "netref: whether a migration is already recorded could not be read from the ledger, so the"
      mi_warn "  fleet this phase must act on cannot be established. Re-enumerating the live set could"
      mi_warn "  sweep in a container this migration never connected. Nothing is done."
      return 1
      ;;
  esac
}

# THE ONE WRITER of the migration intent, so the three phases that record one cannot disagree about
# what it holds. The container list is built and CHECKED before it reaches the record: interpolating
# `$( … )` straight into the argument would publish an empty list on a failed `tr` and the recovering
# process would then think there was nothing to migrate.
_mi_netmig_record() {
  local phase="$1" src="$2" tgt="$3" cs="$4" list
  list="$(printf '%s' "$cs" | tr '\n' ',')" || {
    mi_warn "netref: the container set could not be serialized for the migration record."; return 1; }
  mi_led_put "$MI_NETMIG_KIND" key family "key=family" "phase=${phase}" "source=${src}" \
    "target=${tgt}" "containers=${list}"
}

# THE ALIAS A SIBLING ANSWERS TO, derived from its provenance record — asked in ONE place for the three
# phases that need it.
#
# A container carrying this installation's label but ABSENT from provenance must STOP the migration,
# not be skipped: skipping it leaves it on the source network while phase 5 declares the fleet
# migrated. It is §6b.2's unrecorded same-identity class, and that class stops every mutating
# operation — a migration is not an exception.
_mi_netmig_alias() {
  local c="$1" rec product rc
  if rec="$(mi_prov_find container "$c")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "netref: '$c' carries this installation's label but the ledger has no record of it."
    mi_warn "  Stopping the migration rather than migrating a fleet we cannot enumerate."
    return 1
  fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "netref: whether '$c' is recorded could not be read from the ledger, so the fleet cannot be"
    mi_warn "  enumerated. Stopping."
    return 1
  fi
  if product="$(mi_led_field "$rec" product)"; then :; else
    mi_warn "netref: the record for '$c' names no product, so its alias cannot be derived. Stopping."
    return 1
  fi
  if [ -z "$product" ]; then
    mi_warn "netref: the record for '$c' names an EMPTY product, so its alias cannot be derived."
    mi_warn "  Stopping. Run 'mythical-ctl state repair'."
    return 1
  fi
  mi_name_alias "$product"
}

# THE LIVE CHECK PHASE 5 MAKES, and why it is not mi_bringup_verify_live.
#
# That function re-asks the exact-set question itself, and WHILE THE MIGRATION INTENT IS RECORDED the
# permitted set it computes is {source, target} — the mid-move set, which is exactly right for phase 3
# and exactly wrong for phase 5. Phase 5's whole assertion is that the move is OVER, so every container
# is on the TARGET ALONE, which that function correctly refuses. The intent cannot be cleared first:
# clearing it IS phase 6, and phase 5 exists precisely because clearing before verifying leaves a
# half-detached container with no intent left to resume from.
#
# So phase 5 asks the exact-set question itself, MORE strictly (exactly {target}), and makes the live
# check out of the same two probe primitives bring-up uses: the DNS mechanism first — which separates
# "DNS on this network is broken" from "that product is not running" — and then the sibling's own alias
# compared AGAINST THE ENDPOINT ADDRESS taken from the very inspection the set was judged on. Nothing
# here re-implements a decision: the strict half is phase 5's own and the probe half is the probe
# module's.
#
# rc 0 verified · 1 not (reported).
_mi_netmig_live_ok() {
  local idx="$1" c="$2" netid="$3" alias="$4" expect="$5" resolved rc
  if [ -z "$expect" ]; then
    mi_warn "netref: '$c' is running but has no endpoint address on the target network, so its alias"
    mi_warn "  has nothing to answer with."
    return 1
  fi
  mi_probe_selfcheck "$idx" "$netid" || return 1
  if resolved="$(mi_probe_resolve "$idx" "$netid" "$alias")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "netref: the alias '$alias' does not resolve on the target network."
    return 1
  fi
  [ "$rc" -eq 0 ] || return 1
  # COMPARE ADDRESSES, not just resolution. Docker aliases are NETWORK-SCOPED, so a name can resolve
  # happily via another attachment and prove nothing about this one.
  if [ "$resolved" != "$expect" ]; then
    mi_warn "netref: '$alias' resolves to '$resolved', but '$c' is at '$expect' on the target network."
    mi_warn "  The name resolves — via something other than this network's endpoint for this container."
    return 1
  fi
  return 0
}

# PHASE 5'S PER-CONTAINER ASSERTION, factored so PHASE 3 can borrow it when the source network no
# longer resolves (a forward-only migration). It is the STRICT half — the container is on EXACTLY
# {target} — composed with the probe half (_mi_netmig_live_ok) for a running container. A stopped one
# has no endpoint, so only its attachment is asserted and the live check is deferred, exactly as D48
# requires. The attachment string is split by lib/bringup.sh's own walk (one separator at a time with
# parameter expansion), because an unquoted IFS split also GLOBS.
#
# rc 0 verified · 1 refused (reported).
_mi_netmig_target_only_ok() {
  local idx="$1" c="$2" tgt="$3" alias="$4" nets line tid expect="" cnt=0 obs
  nets="$(mi_rt_container_nets_resolved "$c")" || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    tid="${line%%$'\t'*}"
    cnt=$((cnt + 1))
    if [ "$tid" != "$tgt" ]; then
      mi_warn "netref: '$c' is still attached to '$tid' — its network set must be exactly {$tgt}."
      return 1
    fi
    expect="${line#*$'\t'}"
  done <<< "$(_mi_bringup_attachments "$nets")"
  if [ "$cnt" -ne 1 ]; then
    mi_warn "netref: '$c' has $cnt network attachments and must have exactly one — the target."
    return 1
  fi
  obs="$(mi_state_observed "$c")" || return 1
  if [ "$obs" = running ]; then
    _mi_netmig_live_ok "$idx" "$c" "$tgt" "$alias" "$expect" || return 1
  fi
  # A STOPPED container is not live-verified here (D48 — no endpoint to answer with). Its deferred alias
  # check stands and is performed at its next explicit start.
  return 0
}

# IS <c> STILL ATTACHED TO <tgt> RIGHT NOW? A MEMBERSHIP test — deliberately NOT the exact-set one.
# Phase 4 asks it the instant before it removes the source, while the container is meant to be on the
# full {source,target} set; a crash re-entry asks it of one already detached down to {target} alone.
# BOTH must answer "yes, the target is there", so the assertion is only "the target is present", which
# holds across the whole {source,target}→{target} window the detach walks. The set-shape assertion
# (exactly {target}) is phase 5's, made once the move is claimed complete; here it would refuse every
# not-yet-detached container and stall the phase.
#
# It exists so phase 4 MEASURES the target attachment rather than trusting the recorded phase: the
# admits gate proves phase 3 verified the fleet ONCE, not that an external `docker network disconnect`
# (or a stale/restored phase=3) has not removed a target attachment since. Detaching the source from a
# container no longer on the target leaves it on NEITHER network — the split the phase order exists to
# prevent, arrived at through a marker trusted past the moment it was true.
#
# rc 0 attached to <tgt> · non-zero not confirmed attached — either genuinely not on it, or the
# container could not be inspected at all (the inspect's rc is propagated). Both FAIL CLOSED at the
# caller: "could not ask" is not "still there", and neither authorizes a detach.
_mi_netmig_on_target() {
  local c="$1" tgt="$2" nets line
  nets="$(mi_rt_container_nets_resolved "$c")" || return $?
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [ "${line%%$'\t'*}" = "$tgt" ] && return 0
  done <<< "$(_mi_bringup_attachments "$nets")"
  return 1
}

# THE AUTHORITATIVE RECORD IS THE PROOF A DESTRUCTIVE PHASE MAY RUN. Phase 4 detaches and phase 6 clears
# the intent; both are irreversible, and both depend on the earlier phases having run — every container
# connected to the target (phase 2) and verified there (phases 3, 5). That proof is the recorded phase,
# and it is the RECORD that is consulted, never the caller's word: mi_netmig_run is a public entry
# point, and a bare `mi_netmig_run <idx> <src> <tgt> 4` against an ordinary attached fleet would
# otherwise detach the only network it is on in one call, with no proof the connects ever happened.
#
# It also pins the source and target to the ones the record documents, so a destructive phase acts only
# on the pair the intent names, never an arbitrary one handed in. The admissible recorded-phase window
# is <lo>..<hi>: phase 4 accepts {3,4} (phase 3 completed, or re-entry after a crash); phase 6 accepts
# {5} (phase 5 recorded its success — see there). A recorded phase below the window means the
# connect-and-verify phases have not completed.
#
# rc 0 admissible · 1 refused (reported).
_mi_netmig_admits() {
  local run="$1" src="$2" tgt="$3" lo="$4" hi="$5" rec rrc rphase rsrc rtgt
  if rec="$(mi_led_find "$MI_NETMIG_KIND" key family)"; then rrc=0; else rrc=$?; fi
  if [ "$rrc" -eq 3 ]; then
    mi_warn "netref: phase $run detaches or commits, and there is NO recorded migration to show the"
    mi_warn "  connect-and-verify phases ran. Refusing to act on proof it would have to invent — a bare"
    mi_warn "  phase against an ordinary attached fleet is how the family is split. Nothing is done."
    return 1
  fi
  if [ "$rrc" -ne 0 ]; then
    mi_warn "netref: whether a migration is recorded could not be read, so phase $run cannot establish"
    mi_warn "  that the earlier phases ran. Nothing is done."
    return 1
  fi
  if rphase="$(mi_led_field "$rec" phase)"; then :; else
    mi_warn "netref: the recorded migration names no phase, so phase $run cannot tell whether the"
    mi_warn "  earlier phases ran. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  _mi_netmig_phase_ok "$rphase" || return 1
  if rsrc="$(mi_led_field "$rec" source)"; then :; else rsrc=""; fi
  if rtgt="$(mi_led_field "$rec" target)"; then :; else rtgt=""; fi
  if [ "$rsrc" != "$src" ] || [ "$rtgt" != "$tgt" ]; then
    mi_warn "netref: phase $run was asked to act on source=$src target=$tgt, but the recorded migration"
    mi_warn "  documents source=$rsrc target=$rtgt. Refusing to detach or commit against a pair the"
    mi_warn "  record does not name."
    return 1
  fi
  if [ "$rphase" -lt "$lo" ] || [ "$rphase" -gt "$hi" ]; then
    mi_warn "netref: phase $run cannot run — the recorded migration is at phase $rphase, and phase $run"
    mi_warn "  requires it to have reached phase $lo. The connect-and-verify phases have not completed,"
    mi_warn "  and detaching or committing now is the split this ordering exists to prevent. Nothing is"
    mi_warn "  done."
    return 1
  fi
  return 0
}

# Run ONE phase. Split this way so recovery can enter at the recorded phase and so each phase's failure
# mode is a separate test.
mi_netmig_run() {
  if [ "$#" -ne 4 ]; then mi_warn "netref: mi_netmig_run needs <index> <source> <target> <phase>"; return 1; fi
  local idx="$1" src="$2" tgt="$3" phase="$4" cs c

  if [ -z "$src" ] || [ -z "$tgt" ]; then
    mi_warn "netref: a migration needs both a source and a target network id. Nothing is done."
    return 1
  fi
  # SOURCE AND TARGET MUST DIFFER, asked HERE because every phase and both entry points — a fresh
  # rebind and a resumed one — pass through this function. With them equal, phase 2 finds every
  # container already attached and does nothing, phase 5's exact-set check passes trivially, and phase
  # 4 detaches THE ONLY NETWORK THE FAMILY IS ON. The whole fleet ends up attached to nothing, and the
  # ledger records the migration as complete.
  if [ "$src" = "$tgt" ]; then
    mi_warn "netref: the migration source and target are the same network ($src). Phase 4 would detach"
    mi_warn "  the only network the family is on, leaving every container attached to nothing."
    mi_warn "  Nothing is done."
    return 1
  fi

  # THE FLEET IS THE RECORDED SNAPSHOT, not a live re-enumeration — see _mi_netmig_fleet. This is what
  # keeps phase 4 from detaching a container that appeared after the intent opened.
  cs="$(_mi_netmig_fleet)" || return 1

  case "$phase" in
    1)
      _mi_netmig_record 1 "$src" "$tgt" "$cs" || return 1
      ;;
    2)
      _mi_netmig_record 2 "$src" "$tgt" "$cs" || return 1
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        local alias2 nets2
        alias2="$(_mi_netmig_alias "$c")" || return 1
        nets2="$(mi_rt_container_nets_resolved "$c")" || return 1
        # Already attached? Re-running a phase must be idempotent, because recovery re-enters it.
        case ";${nets2}" in *";${tgt}="*) continue ;; esac
        # LOWER gateway priority than the source, so the SOURCE REMAINS THE PREFERRED ROUTE through
        # phases 2–3. Docker may otherwise select the newly attached network as the default gateway the
        # moment it is connected, and phase 3's egress check would fail with no action to take. The
        # source stays the route because it was MADE to, not because the runtime happened to leave it
        # alone. Detaching the source in phase 4 then performs the cutover by itself.
        mi_rt_network_connect "$tgt" "$c" "$alias2" -1 >/dev/null || {
          mi_warn "netref: could not connect '$c' to the target network. Stopping in phase 2 — every"
          mi_warn "  container must be on the new network before any leaves the old one."
          return 1; }
      done <<< "$cs"
      ;;
    3)
      # THE phase=3 MARKER IS WRITTEN AT THE END OF THIS PHASE, NOT ITS START — mirroring phase 5,
      # which records its success only after verifying. Phase 4's gate admits a recorded phase of {3,4}
      # and detaches the source; if phase 3 recorded `phase=3` on ENTRY, then any phase-3 failure left
      # that marker behind, and a subsequent bare `mi_netmig_run <idx> <src> <tgt> 4` would detach the
      # source on the strength of a phase 3 that never actually verified anything. "Phase 3 was entered"
      # is not "phase 3 succeeded". The snapshot phase 4 needs is written by phase 2's own record, so
      # deferring this one costs phase 4 nothing; a failed phase 3 simply leaves the marker at 2, which
      # phase 4 refuses. Phase 3 has no admits gate of its own precisely because it is non-destructive
      # and freely re-runnable, so nothing is lost by recording its completion rather than its entry.
      # IS THE SOURCE STILL PRESENT? A forward-only migration — the operator deleted the old network —
      # cannot be verified against {source,target}: the containers are on the target alone, and demanding
      # the source would wedge the migration forever (nothing could ever satisfy the check, the intent
      # could never clear). When the source is gone, the correct assertion is exactly {target}, which is
      # phase 5's check, borrowed here. When it is present, verification goes through bring-up's door,
      # where the permitted set during a recorded migration is {source,target}.
      local src3 s3rc
      # ONLY rc 3 IS ABSENT. mi_rt_inspect answers 3 when the daemon replied and the network is
      # genuinely gone (a forward-only migration), and 1 when the daemon could not be asked at all.
      # "COULD NOT ASK" IS NOT "ABSENT": folding 1 into absent drops the source-egress assertion below
      # and switches to the forward-only verifier on the strength of a question the runtime never
      # answered — the exact fail-open mi_netmig_resume already refuses at its own source inspect. So
      # the three answers are kept apart here too, and rc 1 STOPS without detaching.
      if mi_rt_inspect network n.id "$src" >/dev/null; then s3rc=0; else s3rc=$?; fi
      case "$s3rc" in
        0) src3=present ;;
        3) src3=absent ;;
        *) mi_warn "netref: phase 3 could not inspect the source network ($src), so whether this is a"
           mi_warn "  forward-only migration or a source that is genuinely gone cannot be told apart."
           mi_warn "  'Could not ask' is not 'absent' — stopping without detaching. Run 'mythical-ctl"
           mi_warn "  state repair'."
           return 1 ;;
      esac
      # The probe is the PRIMARY verifier for every container, not a fallback for stopped ones — it is
      # the one participant whose toolchain the core controls (D48). If it cannot be obtained,
      # verification CANNOT BE PERFORMED, so the migration STOPS HERE and does not detach.
      mi_probe_selfcheck "$idx" "$tgt" || {
        mi_warn "netref: stopping at phase 3. Nothing is detached — proceeding unverified because the"
        mi_warn "  checker was unavailable is the failure this phase exists to prevent."
        return 1; }
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        local alias3 obs3 want3 vrc out3 oline owant3
        alias3="$(_mi_netmig_alias "$c")" || return 1
        obs3="$(mi_state_observed "$c")" || return 1

        # AN OUTSTANDING ALIAS CHECK ON THE SOURCE CANNOT SURVIVE THIS MIGRATION. Phase 4 removes the
        # source network, after which a deferred `alias <source>` check — left from a bring-up whose live
        # verification never ran — can never be satisfied, and the container stays unreconciled forever.
        # It is NOT cleared here: clearing an outstanding check asserts it was VERIFIED, and nothing
        # verified this one. The migration is refused instead, so the source stays attached and the check
        # stays dischargeable; the operator starts the product (or runs state repair) to discharge it,
        # then re-runs the migration. There is no permanent unreconciled state left behind.
        if out3="$(mi_state_outstanding "$c")"; then :; else
          mi_warn "netref: could not read the outstanding checks for '$c', so whether this migration"
          mi_warn "  would strand one cannot be established. Stopping without detaching."
          return 1
        fi
        owant3="alias"$'\t'"$src"
        while IFS= read -r oline; do
          [ -n "$oline" ] || continue
          if [ "$oline" = "$owant3" ]; then
            mi_warn "netref: '$c' owes an alias check on the SOURCE network, which phase 4 removes — after"
            mi_warn "  which nothing could ever satisfy it and the container would stay unreconciled"
            mi_warn "  forever. Refusing to migrate it into that state. Start '$c' to discharge the check,"
            mi_warn "  or run 'mythical-ctl state repair', then re-run the migration."
            return 1
          fi
        done <<< "$out3"

        if [ "$obs3" != running ]; then
          # A STOPPED container has NO ADDRESS to verify — Docker releases it, so "confirm it answers at
          # its expected endpoint" has no endpoint in existence to compare against, and D43 forbids
          # starting one to find out. Its LIVE check is therefore deferred.
          #
          # BUT ITS ATTACHMENT TO THE TARGET IS ASSERTED HERE, never assumed. Phase 2's connect returns a
          # status, not a proof; a silently-failed connect would leave this container off the target
          # while phase 3 passed — and then phase 4 detaches the source and it is on nothing, the split
          # the phase order exists to make impossible. The attachment is inspectable whether or not the
          # container runs, so it is inspected. (Source present: the set is {source,target}, checked
          # through bring-up's door. Source gone: exactly {target}, phase 5's check.)
          if [ "$src3" = present ]; then
            mi_bringup_verify_attach "$c" "$tgt" "$alias3" || {
              mi_warn "netref: phase 3: '$c' is stopped and is NOT confirmed attached to the target"
              mi_warn "  network — a connect returned success but the attachment is not there. Stopping"
              mi_warn "  without detaching."
              return 1; }
          else
            _mi_netmig_target_only_ok "$idx" "$c" "$tgt" "$alias3" || {
              mi_warn "netref: phase 3: '$c' is stopped and is not on the target network alone (the source"
              mi_warn "  is gone, so this is a forward-only migration). Stopping without detaching."
              return 1; }
          fi
          # DEFERRING IS NOT SKIPPING: the check is recorded as outstanding on the TARGET and the next
          # explicit start performs it. The desired state is READ rather than assumed — `|| want=stopped`
          # would write `stopped` over a row this module could not read, D43's rule inverted by an
          # unreadable answer.
          if want3="$(mi_state_desired_get "$c")"; then :; else
            mi_warn "netref: '$c' is stopped and this installation has no readable record of what state"
            mi_warn "  it is meant to be in, so the deferred check cannot be recorded without inventing"
            mi_warn "  an intent for it. Stopping without detaching. Run 'mythical-ctl state repair'."
            return 1
          fi
          mi_state_commit "$c" "$want3" alias "$tgt" || return 1
          mi_warn "note: '$c' is stopped, so its alias has no endpoint to answer with. The check is"
          mi_warn "  recorded as outstanding and performed at its next explicit start."
          continue
        fi
        # RUNNING. Source present: verify through bring-up's own door — the container is on BOTH networks
        # here, exactly the {source,target} set _mi_bringup_attach_ok permits while this intent stands.
        # Source gone (forward-only): the container is on {target} alone, verified by phase 5's check.
        if [ "$src3" = present ]; then
          if mi_bringup_verify_live "$idx" "$c" "$tgt" "$alias3"; then vrc=0; else vrc=$?; fi
          if [ "$vrc" -eq 4 ]; then
            mi_warn "netref: phase 3 could not verify '$c' — the probe itself did not run, so nothing was"
            mi_warn "  established either way. Stopping without detaching."
            return 1
          fi
          if [ "$vrc" -ne 0 ]; then
            mi_warn "netref: phase 3 verification failed for '$c' on the target network."
            mi_warn "  Resolution is compared against the sibling's endpoint address on the TARGET"
            mi_warn "  NETWORK — during phase 2 every container is on BOTH networks and Docker aliases"
            mi_warn "  are network-scoped, so a name resolving via the OLD network proves nothing about"
            mi_warn "  the new one. Stopping without detaching."
            return 1
          fi
        else
          _mi_netmig_target_only_ok "$idx" "$c" "$tgt" "$alias3" || {
            mi_warn "netref: phase 3 verification failed for '$c' on the target network (forward-only —"
            mi_warn "  the source is gone, so the container must be on the target alone). Stopping without"
            mi_warn "  detaching."
            return 1; }
        fi
      done <<< "$cs"
      # Egress is verified UNCHANGED through phases 2–3 while the source exists — the containers are on
      # both networks precisely so that nothing changes yet. When the source is gone there is no route
      # through it to check; phase 5 verifies final egress on the target.
      if [ "$src3" = present ]; then
        mi_probe_egress "$idx" "$src" || {
          mi_warn "netref: egress through the SOURCE network is no longer working in phase 3, which means"
          mi_warn "  attaching the target moved the route despite the lower gateway priority. Stopping."
          return 1; }
      fi
      # ONLY NOW: every container is connected to the target and verified there, and egress is intact.
      # This is the proof phase 4 is admitted on. Written last, so a failure anywhere above leaves the
      # marker at phase 2 and phase 4 stays refused.
      _mi_netmig_record 3 "$src" "$tgt" "$cs" || return 1
      ;;
    4)
      # PROOF BEFORE DETACH. Phase 4 is the one destructive phase, and it may run only when the
      # authoritative record shows phases 2 and 3 completed — every container connected to the target
      # and verified there. Without this, a bare `mi_netmig_run <idx> <src> <tgt> 4` against an ordinary
      # attached fleet detaches the only network it is on in a single call. Admissible recorded phases
      # are {3, 4}: phase 3 completed, or this is a crash re-entry into phase 4.
      _mi_netmig_admits 4 "$src" "$tgt" 3 4 || return 1
      _mi_netmig_record 4 "$src" "$tgt" "$cs" || return 1
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        # MEASURE THE TARGET ATTACHMENT BEFORE REMOVING THE SOURCE, never act on the marker alone. The
        # admits gate above proves phase 3 verified this fleet ONCE; it does not prove '$c' is STILL on
        # the target now. An external disconnect (or a stale/restored phase=3) between the phases can
        # have taken the target attachment away — and detaching the source THEN leaves '$c' on neither
        # network, the split the phase order exists to prevent, which phase 5 would only notice
        # afterward with recovery stranded at phase 4. So re-inspect, and STOP without detaching if the
        # target is gone. (Re-entry finds already-detached containers on {target} alone — still on the
        # target, so this passes and the disconnect below is the no-op the comment describes.)
        _mi_netmig_on_target "$c" "$tgt" || {
          mi_warn "netref: phase 4: '$c' is not confirmed attached to the target network, so detaching"
          mi_warn "  it from the source would leave it on neither. Stopping without detaching — the"
          mi_warn "  intent stays at phase 4 and the migration resumes. Reconnect '$c' to the target, or"
          mi_warn "  run 'mythical-ctl state repair', then re-run."
          return 1; }
        # THE EXIT STATUS IS NOT THE RESULT, and here it must not be. Re-entering this phase after a
        # crash asks a runtime that has already detached some of them, where "it was never attached" is
        # an error — so a status-driven stop would make recovery impossible on exactly the path
        # recovery uses. What decides whether every detach took effect is phase 5, which ASKS the
        # runtime what each container is attached to. A status is a claim; that is a measurement.
        mi_rt_network_disconnect "$src" "$c" >/dev/null 2>&1 || true
      done <<< "$cs"
      ;;
    5)
      # DO NOT record phase 5 BEFORE verifying: a failure here must STAY IN PHASE 4 with the intent
      # intact, so recovery re-detaches rather than treating the verification as the thing to resume.
      # (The success record is written AFTER the checks, below.)
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        local alias5
        alias5="$(_mi_netmig_alias "$c")" || return 1
        # EXACTLY {target}, plus the live check for a running sibling — phase 5's own assertion, shared
        # with phase 3's forward-only path. The exact-set invariant is suspended only WHILE the intent is
        # recorded and only to {source,target}; at phase 5 the migration is asserting it is done, so the
        # strict check is made — see _mi_netmig_live_ok for why it cannot be borrowed from bring-up. A
        # stopped sibling has no endpoint, so its live check stays deferred (the outstanding entry phase
        # 3 recorded is performed at its next start); its attachment to {target} alone is still asserted.
        _mi_netmig_target_only_ok "$idx" "$c" "$tgt" "$alias5" || {
          mi_warn "netref: phase 5 verification failed for '$c'. STAYING IN PHASE 4 with the intent"
          mi_warn "  intact, so the migration resumes rather than committing over an unverified fleet —"
          mi_warn "  committing now would leave a container on {source,target} with no intent recorded,"
          mi_warn "  which nothing can resume."
          return 1; }
      done <<< "$cs"
      # Phase 4 is where the route deliberately MOVES, so "unchanged" is impossible across it —
      # detaching the source removes the very gateway being preserved. Phase 5 verifies FINAL egress on
      # the target.
      mi_probe_egress "$idx" "$tgt" || {
        mi_warn "netref: phase 5: egress on the target network does not work. Staying in phase 4."
        return 1; }
      # VERIFICATION IS COMPLETE — record phase 5, AFTER the checks and never before. This is the proof
      # phase 6's gate requires that the fleet was verified on the target ALONE before the intent is
      # cleared. A failure above returns without recording, so the record stays at phase 4 and recovery
      # re-detaches; a bare `mi_netmig_run <idx> <src> <tgt> 6` cannot commit-and-clear a migration that
      # was never verified here.
      _mi_netmig_record 5 "$src" "$tgt" "$cs" || return 1
      ;;
    6)
      # PROOF BEFORE CLEAR. Clearing the intent is irreversible — it is the only record of where the
      # fleet came from — so phase 6 runs only when the record shows phase 5 recorded its success
      # (admissible recorded phase is {5}). Without this, a bare `mi_netmig_run <idx> <src> <tgt> 6`
      # could commit a reference and delete an in-flight intent whose fleet was never verified on the
      # target, stranding a container on {source,target} with nothing left to resume it.
      _mi_netmig_admits 6 "$src" "$tgt" 5 5 || return 1
      # MEASURE THE FLEET AGAIN BEFORE THE IRREVERSIBLE CLEAR, never act on the marker alone. The admits
      # gate above proves phase 5 RECORDED its success once; it does not prove the fleet is STILL on the
      # target alone now. mi_netmig_run is public and re-runnable, so a container reattached to the OLD
      # network between phase 5 and this phase 6 (an external `docker network connect`, a restored
      # ledger) would sit on {source,target} — and clearing the intent now, the intent being the only
      # record of where the fleet came from, makes that split PERMANENT with nothing left to resume
      # from. So phase 5's exact-{target} verification is RE-RUN over the recorded fleet here, through
      # the very same verifier phase 5 uses, and any failure STOPS with the intent intact.
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        local alias6
        alias6="$(_mi_netmig_alias "$c")" || return 1
        _mi_netmig_target_only_ok "$idx" "$c" "$tgt" "$alias6" || {
          mi_warn "netref: phase 6: '$c' is no longer on the target network alone, so committing the"
          mi_warn "  reference and clearing the intent now would strand it mid-migration with nothing to"
          mi_warn "  resume from — the split phase 5 exists to prevent. STOPPING with the intent intact;"
          mi_warn "  the migration stays resumable. Run 'mythical-ctl state repair' if this persists."
          return 1; }
      done <<< "$cs"
      # COMMIT, then clear — and refuse to clear without committing. If MYTHICAL_NET has been removed
      # or edited since the migration started there is no correct reference to record, and clearing the
      # intent anyway would leave the fleet on the target while the ledger names something else: the
      # next operation would create or select a different network and the family would be split, with
      # no intent left to resume from. Stopping here is recoverable; clearing is not.
      _mi_netref_commit "$tgt" || {
        mi_warn "netref: phase 6 recorded nothing, so the migration intent is KEPT and this stays"
        mi_warn "  resumable. The containers are already on $tgt; clearing the intent without recording"
        mi_warn "  where they are would leave the fleet on a network the ledger does not name."
        mi_warn "  Decide which network you want and re-run 'mythical-ctl net rebind'."
        return 1; }
      mi_led_del "$MI_NETMIG_KIND" key family || return 1
      ;;
    *) mi_warn "netref: '$phase' is not a migration phase"; return 1 ;;
  esac
  return 0
}

# Resume from the recorded phase and CONTINUE FORWARD — it never unwinds, because being on both
# networks is a bounded, recorded intermediate state and being on neither is not. That is what makes an
# atomic rollback unnecessary rather than merely unavailable.
mi_netmig_resume() {
  if [ "$#" -ne 1 ]; then mi_warn "netref: mi_netmig_resume needs an <index file>"; return 1; fi
  local idx="$1" rec phase src tgt p irc
  rec="$(mi_led_find "$MI_NETMIG_KIND" key family)" || return $?
  if phase="$(mi_led_field "$rec" phase)"; then :; else
    mi_warn "netref: the recorded migration intent names no phase, so nothing can say where to resume."
    mi_warn "  It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  _mi_netmig_phase_ok "$phase" || return 1

  if src="$(mi_led_field "$rec" source)"; then :; else src=""; fi
  if [ -z "$src" ]; then
    mi_warn "netref: the recorded migration intent names no source network."
    mi_warn "  Phase 4 cannot know what to detach, and after a crash there is no other way to learn it:"
    mi_warn "  the containers may by then be on two networks with nothing to say which was the old one."
    mi_warn "  An intent naming only the target cannot complete its own migration. Manual recovery:"
    mi_warn "  inspect each container's attachments and detach the one that is not the target."
    return 1
  fi
  if tgt="$(mi_led_field "$rec" target)"; then :; else tgt=""; fi
  if [ -z "$tgt" ]; then
    mi_warn "netref: the recorded migration intent names no target network, so there is nothing to"
    mi_warn "  migrate onto. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
    return 1
  fi

  # OLD NETWORK MISSING IS ITS OWN STATE, not a failure of this one. When the recorded old id no longer
  # resolves there is nothing to detach and nothing to return to: the migration is FORWARD-ONLY and says
  # so. "Could not ask" is a third answer and stops — a migration must not be declared forward-only on
  # the strength of a question the runtime never answered.
  if mi_rt_inspect network n.id "$src" >/dev/null; then irc=0; else irc=$?; fi
  if [ "$irc" -eq 3 ]; then
    mi_warn "netref: the previous network ($src) no longer exists, so this migration is forward-only:"
    mi_warn "  there is nothing to detach and nothing to return to. Phases 3 and 5 verify each container"
    mi_warn "  against exactly {target} rather than {source,target}, so the migration completes FORWARD"
    mi_warn "  rather than wedging on a source that is gone. This is stated here rather than hidden"
    mi_warn "  behind a rollback promise that could not be kept."
  elif [ "$irc" -ne 0 ]; then
    mi_warn "netref: whether the previous network ($src) still exists could not be established, so"
    mi_warn "  nothing is resumed. A detach planned against a network we could not ask about is a"
    mi_warn "  detach planned in the dark."
    return 1
  fi

  p="$phase"
  while [ "$p" -le 6 ]; do
    mi_netmig_run "$idx" "$src" "$tgt" "$p" || return 1
    p=$((p + 1))
  done
  return 0
}

# The confirmed rebind (D44). The CONFIRMATION PROMPT is the verb's; this function is the mechanism and
# it refuses to run without a target the caller has already resolved.
mi_net_ref_rebind() {
  if [ "$#" -ne 2 ]; then mi_warn "netref: mi_net_ref_rebind needs an <index file> and a <new network id>"; return 1; fi
  local idx="$1" tgt="$2" src cs line count=0 rc srrc oident oname orec oprc
  if [ -z "$tgt" ]; then
    mi_warn "netref: mi_net_ref_rebind needs a resolved target network id, not an empty one."
    return 1
  fi
  mi_preflight_network "$tgt" || return 1
  # A migration already in flight owns the intent. Writing phase 1 over it would discard the recorded
  # SOURCE and container set while containers sit on {source, target} — destroying the only thing that
  # can finish them. Resume it instead. An unreadable answer stops for the same reason, one step
  # further back: an intent nobody could read is still the only record of where the fleet came from.
  if mi_led_find "$MI_NETMIG_KIND" key family >/dev/null; then rc=0; else rc=$?; fi
  case "$rc" in
    3) : ;;
    0) mi_warn "netref: a network migration is already recorded. Refusing to start a second one over"
       mi_warn "  it — its intent is the only record of where the fleet came from. Resume it with"
       mi_warn "  'mythical-ctl net rebind'."
       return 1 ;;
    *) mi_warn "netref: whether a migration is already under way could not be read from the ledger."
       mi_warn "  Starting one now would write over an intent nobody could read. Nothing is started."
       return 1 ;;
  esac

  cs="$(_mi_netmig_containers)" || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    count=$((count + 1))
  done <<< "$cs"
  if [ "$count" -eq 0 ]; then
    # No containers yet: there is nothing to migrate, so the reference is recorded directly — through
    # the same writer, held to the same rule.
    _mi_netref_commit "$tgt"
    return $?
  fi

  # WHERE THE FLEET IS NOW, which phase 4 detaches from. A recorded non-owned reference names it
  # directly. When there is NONE, the fleet is on the installer's OWN network — the "operator adopts
  # MYTHICAL_NET on an existing installation" migration — so the owned network is the source. It is read
  # from provenance WITHOUT creating one: a source to detach from must be where the fleet already is,
  # never a fresh empty network. An unreadable reference stops (an unreadable answer is not "there is
  # none"), and neither-reference-nor-owned-network-recorded with containers present is an inconsistent
  # state this cannot resolve blindly.
  if src="$(mi_net_ref_get)"; then srrc=0; else srrc=$?; fi
  case "$srrc" in
    0) : ;;
    3) oident="$(mi_ident_get)" || return 1
       oname="$(mi_name_network "$oident")" || return 1
       if orec="$(mi_prov_find network "$oname")"; then oprc=0; else oprc=$?; fi
       case "$oprc" in
         0) src="$(_mi_net_owned_adopt "$orec")" || return 1 ;;
         3) mi_warn "netref: there is no reference to migrate FROM and no installer-owned network is"
            mi_warn "  recorded, yet containers exist — where the fleet is cannot be established, so"
            mi_warn "  phase 4 would not know what to detach. Run 'mythical-ctl state repair'."
            return 1 ;;
         *) mi_warn "netref: whether this installation has its own network could not be read, so the"
            mi_warn "  migration source is unknown. Nothing is started."
            return 1 ;;
       esac ;;
    *) mi_warn "netref: the recorded network reference could not be read, so phase 4 would not know what"
       mi_warn "  to detach. Nothing is started."
       return 1 ;;
  esac
  mi_netmig_run "$idx" "$src" "$tgt" 1 || return 1
  mi_netmig_resume "$idx"
}
