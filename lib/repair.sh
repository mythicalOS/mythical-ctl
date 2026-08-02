#!/usr/bin/env bash
# §6b.1 — the schema version, and the way out of a corrupt ledger.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.
#
# LOCK DISCIPLINE: every mutating entry point here follows lib/verbs.sh's pattern — acquire via
# `_mi_with_lock`, never a `trap … RETURN`. A RETURN trap set in a verb-shaped function fires on
# EVERY NESTED function return when functrace (`set -T`) is on, which is exactly how this project's
# bats harness runs a test body (see the header of lib/verbs.sh) — so the trap releases the lock after
# the FIRST inner call and every later ledger write in the same repair run refuses for want of it.
# `_mi_with_lock` is acquire-run-release and is correct whether functrace is on or off.
#
# CONFIRMATION: `mi_confirm` is NOT redefined here. lib/verbs.sh already owns it (MI_CONFIRM=yes/no
# short-circuit; a bare prompt otherwise) — two implementations of a confirmation gate drift, and this
# module's own Interfaces line lists `MI_CONFIRM` (the env var), not `mi_confirm` (the function), for
# exactly that reason. Every confirm below calls the one lib/verbs.sh ships.

# --- schema migration (D35) -----------------------------------------------------------------------
# NEWER than this CLI understands ⇒ refuse, naming the required version. That gate is Plan 1's, in
# mi_ledger_read, and it must stay there: an older CLI that MISREADS a newer ledger deletes objects it
# misidentifies, so the refusal has to happen in the reader every caller goes through.
#
# OLDER ⇒ migrate forward, in one atomic replace, under the lock, with the prior copy retained until the
# migration commits.
#
# A MIGRATION MUST STATE A VALUE FOR EVERY FIELD THE OLDER SCHEMA LACKS — omitting that is how a
# "migrated" ledger becomes one that fails every read. At schema 1 there is nothing to migrate, so this
# is a no-op that exists to be the single place a future bump lands, with the three fields §6b.1
# enumerates already documented:
#
#   desired state    absent from any pre-D43 ledger. Initialized from OBSERVATION (running ⇒ running,
#                    stopped ⇒ stopped), reported as inferred rather than known, and listed.
#   outstanding      absent from any pre-D50 ledger, and a BOOLEAN in any pre-D52 one. A pre-D50 ledger
#                    initializes to {alias} for every container.
#   network ref      absent from any pre-D44 ledger. Re-resolved from mythical.conf — see
#                    _mi_repair_netref below, which every path that changes which network the ledger
#                    names must go through.
mi_schema_migrate() {
  mi_lock_assert_held "migrate the ledger schema"
  local records
  records="$(mi_ledger_read)" || { local rc=$?; [ "$rc" -eq 3 ] && return 0; return "$rc"; }
  # mi_ledger_read has already refused anything newer, and there is no older schema in existence yet.
  # A future bump adds its arm here, writes EVERY new field, and keeps the prior file until the atomic
  # replace commits (which mi_ledger_write's rename already gives us).
  : "$records"
  return 0
}

# --- state repair ---------------------------------------------------------------------------------
# IDENTITY MUST BE RE-ESTABLISHED FIRST, AND CANNOT COME FROM THE LEDGER. The ledger WAS the identity
# authority, so a corrupt one leaves "which of the labelled objects are mine?" unanswerable by the very
# record being repaired — and several installations may share the daemon.

# The distinct installation identities present in object labels, one per line.
#
# rc 0 the listing is complete (possibly empty) · 1 the runtime could not be asked about one of the
# three kinds — REFUSED rather than silently reporting a partial candidate set: a fewer-candidates
# answer here is how a repair adopts the wrong identity or offers reinitialization when a real
# candidate exists but could not be listed.
mi_repair_candidates() {
  local kind name id seen="" out="" names rc
  for kind in container volume network; do
    if names="$(_mi_prov_list_all "$kind")"; then rc=0; else rc=$?; fi
    if [ "$rc" -ne 0 ]; then
      mi_warn "repair: the container runtime could not be asked which ${kind}s exist, so the identities"
      mi_warn "  present on this daemon cannot be fully established. Refusing to report a partial list."
      return 1
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      case "$kind" in
        container) id="$(mi_rt_inspect container c.install "$name" 2>/dev/null || true)" ;;
        volume)    id="$(mi_rt_inspect volume    v.install "$name" 2>/dev/null || true)" ;;
        network)   id="$(mi_rt_inspect network    n.install "$name" 2>/dev/null || true)" ;;
      esac
      case "$id" in ''|'<no value>') continue ;; esac
      case " $seen " in *" $id "*) continue ;; esac
      seen="${seen} ${id}"
      out="${out}${id}"$'\n'
    done <<< "$names"
  done
  printf '%s' "$out"
}

# Show a candidate with its objects, ports and observed state, so the operator can tell which is theirs.
# Best-effort display: a listing failure for one kind is reported and skipped rather than aborting the
# whole report (the caller has already refused the operation itself via mi_repair_candidates).
_mi_repair_show() {
  local id="$1" kind name names rc
  mi_log "  identity $id"
  for kind in container volume network; do
    if names="$(_mi_prov_list_all "$kind")"; then rc=0; else rc=$?; fi
    if [ "$rc" -ne 0 ]; then
      mi_warn "repair: the container runtime could not be asked which ${kind}s exist; this identity's"
      mi_warn "  ${kind} objects are not listed."
      continue
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      local lid
      case "$kind" in
        container) lid="$(mi_rt_inspect container c.install "$name" 2>/dev/null || true)" ;;
        volume)    lid="$(mi_rt_inspect volume    v.install "$name" 2>/dev/null || true)" ;;
        network)   lid="$(mi_rt_inspect network    n.install "$name" 2>/dev/null || true)" ;;
      esac
      [ "$lid" = "$id" ] || continue
      if [ "$kind" = container ]; then
        mi_log "    $kind $name  ($(mi_state_observed "$name" 2>/dev/null || printf '?'), ports: $(mi_rt_inspect container c.ports "$name" 2>/dev/null || printf '?'))"
      else
        mi_log "    $kind $name"
      fi
    done <<< "$names"
  done
}

# D46: any path that changes which network the ledger names goes through D45's phased migration —
# rebind, repair, OR a schema migration. Re-resolving a name during a repair and recording it is a
# network change: if the name now identifies a DIFFERENT network, the ledger moves while the FLEET stays,
# which is precisely the silent DNS split D45 exists to prevent, entered through the repair path instead
# of the rebind path and with no confirmation anywhere on it.
#
# So it COMPARES BEFORE IT RECORDS: resolve the name, then observe the network the existing containers
# actually share.
#
# The <index file> is accepted (as $1) for the uniform call shape every entry point into this area
# takes; nothing in this function reads it — same as lib/netref.sh's mi_net_target.
_mi_repair_netref() {
  local ident="$2" name resolved common="" c nets pair ids first="" disagree=0 rc

  if name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 3 ] && return 0                    # no override: the installer's own network, nothing to rebuild
  [ "$rc" -eq 0 ] || return "$rc"

  resolved="$(mi_net_ref_resolve "$name")" || return 1

  local clist crc
  if clist="$(_mi_prov_list_all container)"; then crc=0; else crc=$?; fi
  if [ "$crc" -ne 0 ]; then
    mi_warn "repair: the container runtime could not be asked which containers exist, so whether the"
    mi_warn "  fleet agrees about its network cannot be established. Nothing recorded."
    return 1
  fi
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    local lid
    lid="$(mi_rt_inspect container c.install "$c" 2>/dev/null || true)"
    [ "$lid" = "$ident" ] || continue
    nets="$(mi_rt_inspect container c.nets "$c" 2>/dev/null || true)"
    ids=""
    local IFS=';'
    # shellcheck disable=SC2206
    for pair in $nets; do [ -n "$pair" ] && ids="${ids} ${pair%%=*}"; done
    unset IFS
    # One container's set may legitimately be {old,new} mid-migration; for this comparison take the
    # first, which is enough to detect disagreement between containers.
    # `grep -a .` exits 1 on empty input, and under the entrypoint's `pipefail` that becomes the
    # assignment's status — which aborts the CLI mid-repair, AFTER the ledger has been reset and only
    # partially rebuilt. A container with no attachments is ordinary here, not an error.
    local one
    one="$(printf '%s' "$ids" | tr ' ' '\n' | grep -a . | head -n1 || true)"
    [ -n "$one" ] || continue
    if [ -z "$first" ]; then first="$one"; common="$one"
    elif [ "$one" != "$first" ]; then disagree=1; fi
  done <<< "$clist"

  if [ "$disagree" -eq 1 ]; then
    mi_warn "repair: the containers do not agree about which network they are on. The fleet is already split"
    mi_warn "  and a migration cannot pick a side. Stopping."
    mi_warn "  Resolve it with the container runtime — attach them all to one network — then re-run."
    return 1
  fi

  if [ -z "$common" ]; then
    # No containers yet: record it; there is nothing to migrate.
    mi_led_put "$MI_NETREF_KIND" key family "key=family" "id=${resolved}" "name=${name}" "owned=no"
    return $?
  fi

  if [ "$common" = "$resolved" ]; then
    mi_led_put "$MI_NETREF_KIND" key family "key=family" "id=${resolved}" "name=${name}" "owned=no"
    return $?
  fi

  mi_warn "repair: MYTHICAL_NET names '$name', which resolves to $resolved — but the containers are"
  mi_warn "  actually on $common. That differs, so the reference is NOT simply recorded."
  mi_warn "  Recording the resolved ID alone would move the ledger while the fleet stayed put: every"
  mi_warn "  product would report healthy while no product resolved any sibling."
  mi_confirm "repair: enter the phased network migration ($common → $resolved)?" || {
    mi_warn "repair: not confirmed. Nothing recorded."; return 1; }

  # BOTH WRITES, IN ONE ATOMIC STEP is what §6b.1 requires — the reference set to the OBSERVED ID, and a
  # D45 intent naming that same ID as SOURCE and the resolved ID as target. Recording only the resolved
  # target would leave the ledger claiming a network the containers are not on, with no source recorded
  # to migrate them FROM. The repair's job is to reach a RESUMABLE state, not a finished one.
  local recs line out=""
  recs="$(mi_ledger_read)" || { local r2=$?; [ "$r2" -eq 3 ] || return "$r2"; recs=""; }
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$MI_NETREF_KIND"$'\t'*|"$MI_NETMIG_KIND"$'\t'*) continue ;;
    esac
    out="${out}${line}"$'\n'
  done <<< "$recs"
  out="${out}${MI_NETREF_KIND}"$'\t'"key=family"$'\t'"id=${common}"$'\t'"name=${name}"$'\t'"owned=no"$'\n'
  out="${out}${MI_NETMIG_KIND}"$'\t'"key=family"$'\t'"phase=1"$'\t'"source=${common}"$'\t'"target=${resolved}"$'\t'"containers="$'\n'
  printf '%s' "$out" | mi_ledger_write || return 1
  mi_warn "repair: recorded the observed network as the reference and a migration intent to move the"
  mi_warn "  fleet onto '$name'. Resume it with 'mythical-ctl net rebind'."
  return 0
}

# Rebuild what is reconstructible; be honest about what is not.
#
# Usage: mi_repair_run <index> [<identity> | --reinitialize]
mi_repair_run() {
  if [ "$#" -lt 1 ]; then mi_warn "repair: mi_repair_run needs an <index file> [identity|--reinitialize]"; return 1; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_repair_run_locked "$@"
}

_mi_repair_run_locked() {
  local idx="$1" choice="${2:-}" cands count

  cands="$(mi_repair_candidates)" || return 1
  count="$(printf '%s\n' "$cands" | grep -ac . || true)"
  count="${count:-0}"

  if [ "$count" -eq 0 ]; then
    # ZERO CANDIDATES IS NOT "NOTHING TO REPAIR": host state can exist with no labelled runtime objects
    # at all — a restore that carried ~/.mythical/ but no containers, or an operator who removed them.
    # Refusing here would deadlock the exact case §6b sends to repair.
    if [ "$choice" != "" ] && [ "$choice" != "--reinitialize" ]; then
      mi_warn "repair: no runtime object carries identity '$choice'."
      return 1
    fi
    mi_warn "repair: no runtime object carries a mythicalOS installation label."
    mi_warn "  A new identity will be minted and the ledger rebuilt from host state alone."
    mi_warn "  CONSEQUENCES, in plain terms:"
    mi_warn "    * EVERY TRUST FLOOR IS RESET. A withdrawn manifest could be replayed until new floors"
    mi_warn "      are established. This is a real rollback window you are accepting."
    mi_warn "    * Any pre-existing runtime objects will not be recognised as this installation's. They"
    mi_warn "      will be listed as unattributed and never touched."
    mi_confirm "repair: reinitialize this installation?" || { mi_warn "repair: not confirmed."; return 1; }
    _mi_repair_reset_ledger || return 1
    local nid
    nid="$(mi_ident_ensure)" || return 1
    mi_log "repair: reinitialized with identity $nid."
    _mi_repair_report_residual
    return 0
  fi

  if [ "$choice" = "--reinitialize" ]; then
    mi_warn "repair: refusing to reinitialize — $count installation identity/identities were found, so"
    mi_warn "  the right answer is to choose one rather than mint a new one and strand these objects:"
    printf '%s\n' "$cands" | while IFS= read -r c; do [ -n "$c" ] && _mi_repair_show "$c"; done
    return 1
  fi

  if [ -z "$choice" ]; then
    # EXACTLY ONE CANDIDATE IS STILL SHOWN AND STILL CONFIRMED — silently adopting the only one visible
    # is how a second user's containers get claimed on a shared daemon.
    mi_log "repair: found $count installation identity/identities on this daemon:"
    printf '%s\n' "$cands" | while IFS= read -r c; do [ -n "$c" ] && _mi_repair_show "$c"; done
    mi_warn "repair: choose one explicitly: 'mythical-ctl state repair <identity>'."
    mi_warn "  Nothing has been changed. The other identities' objects are untouched."
    return 1
  fi

  case $'\n'"$cands" in
    *$'\n'"$choice"$'\n'*|*$'\n'"$choice") : ;;
    *) mi_warn "repair: '$choice' is not one of the identities found on this daemon."; return 1 ;;
  esac

  # TRUST FLOORS ARE NOT RECONSTRUCTIBLE. They are a record of history, and history is not in the
  # runtime. Repair RESETS them, which is a rollback window the operator is explicitly accepting.
  mi_warn "repair: rebuilding installer state for identity '$choice'."
  mi_warn "  WHAT IS RECOVERED: provenance for containers, volumes and networks, from their labels."
  mi_warn "  WHAT IS NOT:"
  mi_warn "    * TRUST FLOORS. They record history, and history is not in the runtime. They are RESET,"
  mi_warn "      which reopens a rollback window: a withdrawn manifest becomes acceptable again until"
  mi_warn "      new floors are established."
  mi_warn "    * DESIRED STATE. It is set from what is observed now and reported as inferred, not"
  mi_warn "      recovered — repair cannot know whether a stopped container was stopped deliberately."
  mi_warn "    * IMAGE PROVENANCE. Images cannot carry the label, so repair neither rebuilds it nor"
  mi_warn "      enumerates the images — that list lived in the ledger being repaired."
  mi_confirm "repair: proceed, accepting the reset of every trust floor?" || {
    mi_warn "repair: not confirmed. Nothing has been changed."; return 1; }

  _mi_repair_reset_ledger || return 1
  mi_led_put "$MI_IDENT_KIND" id "$choice" "id=${choice}" || return 1

  local kind name inferred=""
  for kind in network volume container; do
    local names lrc
    if names="$(_mi_prov_list_all "$kind")"; then lrc=0; else lrc=$?; fi
    if [ "$lrc" -ne 0 ]; then
      mi_warn "repair: the container runtime could not be asked which ${kind}s exist, so provenance for"
      mi_warn "  identity '$choice' cannot be fully rebuilt. Stopping rather than reporting a repair that"
      mi_warn "  silently omitted some of its objects. The ledger already carries the new identity;"
      mi_warn "  re-run 'mythical-ctl state repair $choice' once the runtime answers."
      return 1
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      local lid lnonce
      case "$kind" in
        container) lid="$(mi_rt_inspect container c.install "$name" 2>/dev/null || true)"
                   lnonce="$(mi_rt_inspect container c.nonce "$name" 2>/dev/null || true)" ;;
        volume)    lid="$(mi_rt_inspect volume    v.install "$name" 2>/dev/null || true)"
                   lnonce="$(mi_rt_inspect volume    v.nonce "$name" 2>/dev/null || true)" ;;
        network)   lid="$(mi_rt_inspect network    n.install "$name" 2>/dev/null || true)"
                   lnonce="$(mi_rt_inspect network    n.nonce "$name" 2>/dev/null || true)" ;;
      esac
      [ "$lid" = "$choice" ] || continue
      local extra=""
      if [ "$kind" = network ]; then extra="id=$(mi_rt_inspect network n.id "$name" 2>/dev/null || true)"; fi
      if [ -n "$extra" ]; then mi_prov_record "$kind" "$name" "$lnonce" "$extra" || return 1
      else mi_prov_record "$kind" "$name" "$lnonce" || return 1; fi

      if [ "$kind" = container ]; then
        # OUTSTANDING CHECKS ARE INITIALIZED TO {alias} FOR EVERY RECOVERED CONTAINER — the same honest
        # default as a schema migration: a rebuilt ledger cannot know whether any container's alias was
        # ever verified on its current network, and defaulting to empty asserts a check that may never
        # have happened.
        #
        # DESIRED STATE IS SET FROM OBSERVATION. The conservative failure is a container that crashed
        # before the repair staying down; that is visible and fixable, where the opposite error silently
        # restarts something deliberately stopped.
        local obs want
        obs="$(mi_state_observed "$name")" || return 1
        case "$obs" in running) want=running ;; *) want=stopped ;; esac
        local netid=""
        netid="$(mi_rt_inspect container c.nets "$name" 2>/dev/null || true)"
        netid="${netid%%=*}"
        if [ -n "$netid" ]; then
          mi_state_commit "$name" "$want" alias "$netid" || return 1
        else
          # No network attachment at all — nothing this run can ever check, so nothing is declared owed.
          mi_state_commit "$name" "$want" +none || return 1
        fi
        inferred="${inferred}    $name → $want (observed)"$'\n'
      fi
    done <<< "$names"
  done

  # The non-owned reference, from HOST CONFIG rather than the corrupt ledger — the one piece of ledger
  # content that is genuinely rebuildable, precisely because it never carried provenance. It gains no
  # deletion authority in the process; the class has none to grant.
  _mi_repair_netref "$idx" "$choice" || return 1

  if [ -n "$inferred" ]; then
    mi_log "repair: desired state was inferred from observation, not recovered. Correct any that are wrong:"
    printf '%s' "$inferred"
  fi

  # CONTAINERS ALREADY RUNNING ARE VERIFIED IN THE SAME RECOVERY RUN — they have addresses, so there is
  # nothing to wait for; only stopped ones carry the entry forward to their next start.
  #
  # `mi_led_all` is CAPTURED AND ITS STATUS CHECKED BEFORE THE LOOP. `done <<< "$(mi_led_all X)"` takes
  # the WHILE's status, not the listing's, so a corrupt or partially unreadable ledger would read as an
  # empty listing and every running container's outstanding check would silently survive uncleared.
  local objs orc
  if objs="$(mi_led_all "$MI_PROV_KIND")"; then orc=0; else orc=$?; fi
  if [ "$orc" -ne 0 ]; then
    mi_warn "repair: the object records just written could not be read back, so running containers are"
    mi_warn "  not live-verified this run. Their outstanding alias checks remain and are retried at their"
    mi_warn "  next explicit start. Run 'mythical-ctl state repair $choice' again."
    return 1
  fi
  local rec c
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class container || continue
    c="$(mi_led_field "$rec" name)" || continue
    [ "$(mi_state_observed "$c")" = running ] || continue
    local alias netid2 product aliasesraw blob seg
    netid2="$(mi_state_outstanding "$c" | head -n1 | cut -f2)"
    [ -n "$netid2" ] || continue
    # Prefer the canonical family alias derived from the container's own product label (the value a
    # normal bring-up would have used); fall back to whatever alias the container actually carries on
    # this network — a repaired object may carry no product label at all (D37: images carry no
    # installation-specific label either, and this codebase does not require every recovered object to
    # be reachable through the manifest to be live-verified).
    product="$(mi_rt_inspect container c.product "$c" 2>/dev/null || true)"
    case "$product" in '<no value>') product="" ;; esac
    alias=""
    if [ -n "$product" ]; then alias="$(mi_name_alias "$product" 2>/dev/null || true)"; fi
    if [ -z "$alias" ]; then
      # Anchored on a LEADING ';' — same construction lib/bringup.sh's _mi_bringup_attach_ok uses — so a
      # netid that merely ENDS with the expected one cannot answer for it, and so the prefix strip below
      # actually removes the "<netid>:" it is meant to (without the leading ';' the pattern can only
      # match mid-string, never anchor at position 0, and the strip silently leaves the netid in place).
      aliasesraw="$(mi_rt_inspect container c.aliases "$c" 2>/dev/null || true)"
      blob=";${aliasesraw}"
      case "$blob" in
        *";${netid2}":*) : ;;
        *) continue ;;
      esac
      seg="${blob#*";${netid2}":}"; seg="${seg%%;*}"
      alias="${seg%%,*}"
    fi
    [ -n "$alias" ] || continue
    if mi_bringup_verify_live "$idx" "$c" "$netid2" "$alias"; then
      mi_state_outstanding_clear "$c" alias "$netid2" || return 1
    else
      mi_warn "repair: '$c' is running but its alias did not verify. Left running, still outstanding."
    fi
  done <<< "$objs"

  mi_log "repair: no image is deleted, and repair cannot say which images were this installer's —"
  mi_log "  that list lived in the ledger being repaired. Reporting it from a record just declared"
  mi_log "  untrustworthy would be inventing the answer."
  _mi_repair_report_residual
  return 0
}

# Re-scan immediately before committing, and STATE THE RESIDUAL. A dead client's lock is broken
# automatically (§4b.3a), but the DAEMON may still be completing a create that client had already issued
# — so an object can appear after repair's snapshot and be absent from the rebuilt ledger.
#
# THE ORDINARY RECONCILIATION CANNOT RESCUE A LATE ARRIVAL AFTER A REPAIR: rebuilding the ledger destroys
# the intent the object would have been matched against, and zero-candidate reinitialization mints a NEW
# identity, so an object labelled with the old one can never match. Such an object is STRANDED.
_mi_repair_report_residual() {
  mi_warn "repair: stated residual — repair cannot prove nothing is in flight."
  mi_warn "  The lock excludes other mythical-ctl processes, but the daemon may still be completing a"
  mi_warn "  create that a dead client already issued. Such an object appears after this snapshot and"
  mi_warn "  is absent from the rebuilt ledger — and ordinary reconciliation cannot rescue it, because"
  mi_warn "  the intent it would have matched is gone."
  mi_warn "  It shows up in 'status' as an unattributed or unrecorded object. Reattaching one is a"
  mi_warn "  distinct operation and is OUT OF SCOPE — adopting a different installation identity into a"
  mi_warn "  healthy ledger must not be improvised, because getting it wrong adopts another user's"
  mi_warn "  containers. Until it is designed, the remedy is the container runtime directly."
}

# Empty the ledger of everything EXCEPT the trust anchor, keeping the file valid. The prior file is
# retained until the atomic replace commits — which mi_ledger_write's rename already gives us — but a
# CORRUPT prior ledger must be moved aside first, or mi_ledger_write's own never-overwrite-what-we-
# cannot-read guard refuses the repair; a corrupt ledger's anchor cannot be salvaged either, since
# there is no readable record to salvage it FROM.
#
# THE ANCHOR SURVIVES; EVERYTHING ELSE DOES NOT — and that is not a smaller reset, it is the correct
# one. The anchor names the specific index digest this installation authenticated over TLS from a known
# origin (D21/§8.1); that fact is not runtime history the way the version FLOORS are, and the index file
# itself is untouched by a repair (repair only ever writes the ledger). Dropping the anchor here would
# force a fresh online bootstrap for no security benefit AND make live verification impossible for the
# rest of this same repair run, since mi_probe_image goes through mi_accept_index, which refuses outright
# with no anchor recorded (rc 4, "run once with network access"). The FLOORS genuinely cannot be
# reconstructed from anything outside the ledger being repaired — that is the real rollback window this
# repair opens, stated to the operator above — and dropping them does not touch what the anchor protects:
# an attacker still cannot swap the index itself for a different one without failing digest verification.
_mi_repair_reset_ledger() {
  local f; f="$(_mi_ledger_path)"
  if [ -f "$f" ] && ! ( mi_ledger_read >/dev/null 2>&1 ); then
    local aside="${f}.corrupt.$$"
    mv -f "$f" "$aside" || { mi_warn "repair: cannot move the corrupt ledger aside"; return 1; }
    mi_warn "repair: the corrupt ledger has been PRESERVED at $aside — it is evidence, not rubbish."
    mi_warn "  Its trust anchor could not be salvaged either — nothing here was readable to salvage it"
    mi_warn "  from — so this installation will need to be online once to re-establish it."
    printf '' | mi_ledger_write
    return $?
  fi
  local records rc kept="" line
  if records="$(mi_ledger_read)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      case "$line" in "${MI_TRUST_ANCHOR_KIND}"$'\t'*) kept="${kept}${line}"$'\n' ;; esac
    done <<< "$records"
  elif [ "$rc" -ne 3 ]; then
    # Unreachable in practice — the guard above already proved a present ledger reads clean — but a
    # library function refuses on an unrecognised code rather than assuming it means "empty".
    return "$rc"
  fi
  printf '%s' "$kept" | mi_ledger_write
}

# --- the verbs -------------------------------------------------------------------------------------
mi_verb_state_repair() {
  if [ "$#" -lt 1 ]; then mi_warn "verbs: state repair needs an <index>"; return 2; fi
  mi_repair_run "$@"
}

mi_verb_abandon_intent() {
  if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    mi_warn "verbs: state abandon-intent needs <class> <name>"; return 2
  fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_abandon_intent_locked "$1" "$2"
}
_mi_verb_abandon_intent_locked() {
  local class="$1" name="$2"
  mi_intent_abandonable "$class" "$name" || return 1
  mi_warn "verbs: abandoning the intent for $class '$name'."
  mi_warn "  The installer cannot distinguish 'never created' from 'not yet visible', so this does NOT"
  mi_warn "  guarantee the object will never appear. If it does, the next operation stops and reports it."
  mi_confirm "verbs: abandon this intent?" || { mi_warn "verbs: not confirmed."; return 1; }
  mi_intent_abandon "$class" "$name"
}

mi_verb_net_rebind() {
  if [ "$#" -ne 1 ]; then mi_warn "verbs: net rebind needs an <index>"; return 2; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_net_rebind_locked "$1"
}
_mi_verb_net_rebind_locked() {
  local idx="$1" name id

  # A recorded migration resumes rather than starting a new one.
  if mi_led_find "$MI_NETMIG_KIND" key family >/dev/null 2>&1; then
    mi_log "verbs: resuming the recorded network migration."
    mi_netmig_resume "$idx"
    return $?
  fi
  name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)" || {
    mi_warn "verbs: MYTHICAL_NET is not set, so there is no operator-supplied network to rebind onto."
    return 1; }
  id="$(mi_net_ref_resolve "$name")" || return 1
  mi_warn "verbs: rebinding this installation onto network '$name' ($id)."
  mi_warn "  Every existing container will be connected to it and verified BEFORE any is detached from"
  mi_warn "  the old one, so no step leaves the family partitioned. This is never automatic: a silent"
  mi_warn "  rebind is how a container gets joined to a network you did not intend."
  mi_confirm "verbs: rebind onto '$name'?" || { mi_warn "verbs: not confirmed."; return 1; }
  mi_net_ref_rebind "$idx" "$id"
}
