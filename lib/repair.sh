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

# THE ONE READER of an object's installation label, for every caller in this module that decides
# something from it (candidate discovery, the show listing, the post-reset rebuild loop). One
# implementation rather than the `2>/dev/null || true` idiom repeated at each site — that idiom folds
# rc 1 (the runtime could not answer) into an empty value indistinguishable from "no label", which is
# the exact silent-miss class this module exists to close: a second installation's object goes missing
# from candidate discovery instead of making discovery refuse to say "exactly one".
#
# rc 0 the label is printed — EMPTY is a real answer, an unlabelled object that is still present ·
# 3 the object is gone (a listing/inspect race — a later run, or this same run's next step, can act on
# it) · 1 the runtime could not answer. EVERY CALLER MUST FAIL CLOSED ON 1 — never read it as "no
# label", "a different identity", or "nothing to record".
_mi_repair_install_of() {
  if [ "$#" -ne 2 ]; then mi_warn "repair: _mi_repair_install_of needs <kind> <name>"; return 1; fi
  local kind="$1" name="$2" v rc
  case "$kind" in
    container) if v="$(mi_rt_inspect container c.install "$name")"; then rc=0; else rc=$?; fi ;;
    volume)    if v="$(mi_rt_inspect volume    v.install "$name")"; then rc=0; else rc=$?; fi ;;
    network)   if v="$(mi_rt_inspect network    n.install "$name")"; then rc=0; else rc=$?; fi ;;
    *) mi_warn "repair: '$kind' has no installation label this module reads"; return 1 ;;
  esac
  [ "$rc" -eq 3 ] && return 3
  [ "$rc" -eq 0 ] || return 1
  case "$v" in '<no value>') v="" ;; esac
  printf '%s\n' "$v"
}

# THE ONE READER of an object's nonce label — the other half of provenance, and the same rc split for
# the same reason: a nonce read that could not be answered must never be recorded as an empty or
# missing nonce, which is exactly the misidentification a nonce exists to prevent (§6a).
_mi_repair_nonce_of() {
  if [ "$#" -ne 2 ]; then mi_warn "repair: _mi_repair_nonce_of needs <kind> <name>"; return 1; fi
  local kind="$1" name="$2" v rc
  case "$kind" in
    container) if v="$(mi_rt_inspect container c.nonce "$name")"; then rc=0; else rc=$?; fi ;;
    volume)    if v="$(mi_rt_inspect volume    v.nonce "$name")"; then rc=0; else rc=$?; fi ;;
    network)   if v="$(mi_rt_inspect network    n.nonce "$name")"; then rc=0; else rc=$?; fi ;;
    *) mi_warn "repair: '$kind' has no nonce label this module reads"; return 1 ;;
  esac
  [ "$rc" -eq 3 ] && return 3
  [ "$rc" -eq 0 ] || return 1
  case "$v" in '<no value>') v="" ;; esac
  printf '%s\n' "$v"
}

# The distinct installation identities present in object labels, one per line.
#
# rc 0 the listing is complete (possibly empty) · 1 the runtime could not be asked about one of the
# three kinds, OR could not be asked for one particular object's installation label — REFUSED rather
# than silently reporting a partial candidate set: a fewer-candidates answer here is how a repair
# adopts the wrong identity, or offers reinitialization, when a real candidate exists but its label
# could not be read.
mi_repair_candidates() {
  local kind name id idrc seen=$'\n' out="" names rc
  for kind in container volume network; do
    if names="$(_mi_prov_list_all "$kind")"; then rc=0; else rc=$?; fi
    if [ "$rc" -ne 0 ]; then
      mi_warn "repair: the container runtime could not be asked which ${kind}s exist, so the identities"
      mi_warn "  present on this daemon cannot be fully established. Refusing to report a partial list."
      return 1
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      if id="$(_mi_repair_install_of "$kind" "$name")"; then idrc=0; else idrc=$?; fi
      if [ "$idrc" -eq 3 ]; then continue; fi   # gone since the listing was taken — nothing to count
      if [ "$idrc" -ne 0 ]; then
        mi_warn "repair: '$name' ($kind) could not be asked for its installation label, so candidate"
        mi_warn "  discovery cannot prove which identities are present on this daemon, or that there is"
        mi_warn "  only one. Refusing rather than silently omitting it — start the container runtime (or"
        mi_warn "  otherwise make it answer) and re-run."
        return 1
      fi
      [ -n "$id" ] || continue
      # NEWLINE-ANCHORED, NOT SPACE-PADDED. An installation identity read straight off a label is not
      # constrained to lib/doc.sh's `ident` charset the way a MINTED one always is (_mi_ident_mint is
      # always `i`+10 hex digits, but this reads whatever string is actually on the object) — so a
      # space-padded `case " $seen " in *" $id "*)` can match a PREFIX: seeing "A B" first and then
      # asking about "A" finds " A " inside " A B " and treats "A" as already counted, silently
      # collapsing two DISTINCT identities into one candidate. A newline can appear in neither $seen
      # nor $id (both are single values `_mi_repair_install_of` already split on TAB-delimited label
      # output, which has no embedded newline), so anchoring on it instead is exact.
      case "$seen" in *$'\n'"$id"$'\n'*) continue ;; esac
      seen="${seen}${id}"$'\n'
      out="${out}${id}"$'\n'
    done <<< "$names"
  done
  printf '%s' "$out"
}

# Show a candidate with its objects, ports and observed state, so the operator can tell which is theirs.
# Best-effort display: a listing or label-read failure for one kind/object is reported and skipped
# rather than aborting the whole report — the caller has already refused the operation itself via
# mi_repair_candidates, which applies the fail-closed rule this function does not need to repeat.
_mi_repair_show() {
  local id="$1" kind name names rc lid lidrc
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
      if lid="$(_mi_repair_install_of "$kind" "$name")"; then lidrc=0; else lidrc=$?; fi
      if [ "$lidrc" -eq 3 ]; then continue; fi
      if [ "$lidrc" -ne 0 ]; then
        mi_warn "repair: '$name' ($kind) could not be asked for its installation label; it may or may"
        mi_warn "  not belong to identity '$id' and is left out of this listing."
        continue
      fi
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
  local ident="$2" name resolved common="" c nets pair ids first="" disagree=0 rc fleet=""

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
    local lid lidrc netsrc
    if lid="$(_mi_repair_install_of container "$c")"; then lidrc=0; else lidrc=$?; fi
    if [ "$lidrc" -eq 3 ]; then continue; fi   # gone since the listing — not a vote either way
    if [ "$lidrc" -ne 0 ]; then
      mi_warn "repair: '$c' could not be asked for its installation label, so whether the fleet agrees"
      mi_warn "  about its network cannot be established. Recording a reference on an incomplete answer"
      mi_warn "  is how the ledger ends up naming a network a container may still be split from."
      mi_warn "  Nothing recorded."
      return 1
    fi
    [ "$lid" = "$ident" ] || continue
    # THE FLEET THIS RECONSTRUCTED MIGRATION WILL ACT ON — every container carrying this identity's
    # label, unconditionally, matching lib/netref.sh's _mi_netmig_containers exactly (by label, not
    # filtered by network attachment: a container with zero attachments still needs phase 2 to connect
    # it). Recorded BEFORE the network-agreement check below so a container with no attachments at all
    # (which `continue`s out of that check) is still part of the fleet a migration would move.
    fleet="${fleet}${c}"$'\n'
    if nets="$(mi_rt_inspect container c.nets "$c")"; then netsrc=0; else netsrc=$?; fi
    if [ "$netsrc" -eq 3 ]; then continue; fi   # gone since the label read a moment ago
    if [ "$netsrc" -ne 0 ]; then
      mi_warn "repair: '$c' carries this identity's label, but its network attachments could not be"
      mi_warn "  read. A container that may still be on a DIFFERENT network cannot be ruled out on an"
      mi_warn "  unanswered question. Nothing recorded."
      return 1
    fi
    ids=""
    local IFS=';'
    # shellcheck disable=SC2206
    for pair in $nets; do [ -n "$pair" ] && ids="${ids} ${pair%%=*}"; done
    unset IFS
    # One container's set may legitimately be {old,new} mid-migration; for this comparison take the
    # FIRST NON-EMPTY token, which is enough to detect disagreement between containers. A pure-shell
    # walk rather than `printf | tr | grep | head`: `head -n1` closes its stdin the instant it has its
    # line, and if `$ids` holds more than one token the upstream `printf` can be signalled SIGPIPE —
    # under THIS process's ambient options (this library sets none, but bin/mythical-ctl's caller-level
    # `set -euo pipefail` still governs, since sourced functions run in the SAME shell) that can fail
    # the assignment and abort mid-repair, AFTER the ledger has already been reset. `ids` always has a
    # single leading space and single-space separators by construction above, but the walk still skips
    # a blank token defensively (an empty `${pair%%=*}` from a malformed `nets` entry).
    local one="" rest="$ids" tok
    while [ -n "$rest" ]; do
      rest="${rest# }"
      tok="${rest%% *}"
      if [ "$tok" = "$rest" ]; then rest=""; else rest="${rest#* }"; fi
      if [ -n "$tok" ]; then one="$tok"; break; fi
    done
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
    # `$common` empty is NOT ONE FACT. It means "no containers carry this identity" ONLY when `$fleet`
    # is ALSO empty — `$fleet` is recorded unconditionally for every matching container, before the
    # per-container attachment check that sets `$common`, so a container that exists but is
    # UNATTACHED (or whose attachment could not be resolved to a single common network) leaves
    # `$fleet` non-empty while `$common` stays empty. Recording '$name' as a clean reference in THAT
    # case would make it the family network while the recovered containers are not attached to it at
    # all — the exact split state D46 exists to prevent, arrived at from the empty-fleet branch
    # instead of the disagreement branch a few lines above.
    if [ -n "$fleet" ]; then
      mi_warn "repair: identity '$ident' has containers, but none of them share a single attached"
      mi_warn "  network — each is either unattached, or its attachments could not be resolved to one."
      mi_warn "  Recording '$name' as a clean reference here would make it the family network while"
      mi_warn "  the recovered containers are not attached to it — a split state repair must not create."
      mi_warn "  Attach them to a network with the container runtime (or start them — bring-up attaches"
      mi_warn "  at creation) and re-run."
      return 1
    fi
    # Genuinely no containers carry this identity at all: record it; there is nothing to migrate.
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

  # THE MIGRATION MUST NOT CLAIM AN EMPTY FLEET, AND MUST NOT CLAIM A PARTIAL ONE EITHER. `$fleet` was
  # accumulated above from every container matching this identity, so it is structurally non-empty
  # whenever `$common` is (both come out of the same loop iteration) — but a migration record with
  # `containers=` empty, or holding only SOME of the fleet, is one lib/netref.sh's mi_netmig_resume can
  # never finish correctly: its own fleet is read straight back FROM this field (_mi_netmig_fleet),
  # never re-enumerated, so 'net rebind' would migrate only the containers this field happens to name
  # and leave the rest on the source network while still committing the new reference as if the move
  # were complete.
  #
  # PURE SHELL, NOT `printf | tr`. `tr` is an external process: a partial write before a signal or an
  # internal failure is captured by `$( … )` verbatim, and unless its own exit status is captured and
  # checked, a TRUNCATED `c1,` (only the first entry) is indistinguishable from the complete list. A
  # walk that never leaves this shell has no such window — there is no separate process whose failure
  # could truncate what was written, so "did every fleet line make it into $flist" does not need to be
  # asked at all, only answered by construction.
  local flist="" fline
  while IFS= read -r fline; do
    [ -n "$fline" ] || continue
    if [ -n "$flist" ]; then flist="${flist},${fline}"; else flist="$fline"; fi
  done <<< "$fleet"
  if [ -z "$flist" ]; then
    mi_warn "repair: the fleet for this migration could not be enumerated as non-empty, so recording a"
    mi_warn "  migration intent that claims one would leave 'net rebind' nothing to actually move."
    mi_warn "  Nothing recorded."
    return 1
  fi

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
  out="${out}${MI_NETMIG_KIND}"$'\t'"key=family"$'\t'"phase=1"$'\t'"source=${common}"$'\t'"target=${resolved}"$'\t'"containers=${flist}"$'\n'
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
  # PURE SHELL, NOT `grep -ac . || true`. `grep`'s own "no match" (rc 1) and an actual grep ERROR
  # (rc 2 — this project's own "grep here is ugrep with -I hard-coded, a NUL byte in the input skips
  # silently" hazard is exactly this class) are BOTH swallowed by `|| true` into the same outcome:
  # count stays unset, defaults to 0. `$cands` already succeeded above (mi_repair_candidates' own
  # contract is 0/1, no rc 3 to lose), so this is not a reader-failure question — but "zero" here is
  # the single most consequential answer in this function: with MI_CONFIRM=yes it takes the
  # reinitialize branch, resetting the ledger and minting a brand-new identity over whatever a REAL
  # candidate's objects were. A count that cannot silently misreport is worth having even though the
  # input is a local string, not a live read — counting non-empty lines with a bare loop has no
  # external process and no rc to lose in the first place.
  count=0
  local _cand_line
  while IFS= read -r _cand_line; do
    [ -n "$_cand_line" ] && count=$((count + 1))
  done <<< "$cands"

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
      local lid lidrc lnonce lnrc
      # THIS RUNS AFTER _mi_repair_reset_ledger. A read that cannot be answered here is more serious
      # than the same read failing during candidate discovery: the OLD ledger is already gone, so a
      # silent skip does not leave provenance stale, it leaves it MISSING — permanently, unless the
      # operator is told to re-run. FAIL CLOSED, always, never "skip this one and carry on".
      if lid="$(_mi_repair_install_of "$kind" "$name")"; then lidrc=0; else lidrc=$?; fi
      if [ "$lidrc" -eq 3 ]; then continue; fi   # gone since the listing was taken — nothing to rebuild
      if [ "$lidrc" -ne 0 ]; then
        mi_warn "repair: '$name' ($kind) could not be asked for its installation label. The ledger has"
        mi_warn "  already been reset for identity '$choice', and this object's provenance would be"
        mi_warn "  silently missing from the rebuild rather than merely stale. Stopping — re-run"
        mi_warn "  'mythical-ctl state repair $choice' once the runtime answers for it."
        return 1
      fi
      [ "$lid" = "$choice" ] || continue
      if lnonce="$(_mi_repair_nonce_of "$kind" "$name")"; then lnrc=0; else lnrc=$?; fi
      if [ "$lnrc" -eq 3 ]; then continue; fi
      if [ "$lnrc" -ne 0 ]; then
        mi_warn "repair: '$name' ($kind) carries identity '$choice', but its nonce could not be read."
        mi_warn "  Recording provenance with no nonce — or the wrong one — is exactly the"
        mi_warn "  misidentification a nonce exists to prevent (§6a). Stopping."
        return 1
      fi
      local extra=""
      if [ "$kind" = network ]; then
        local nid nidrc
        if nid="$(mi_rt_inspect network n.id "$name")"; then nidrc=0; else nidrc=$?; fi
        if [ "$nidrc" -eq 3 ]; then continue; fi
        if [ "$nidrc" -ne 0 ]; then
          mi_warn "repair: '$name' (network) carries identity '$choice', but its id could not be read."
          mi_warn "  A network is recorded BY its id (§6a), so there is nothing to record without one,"
          mi_warn "  and recording an empty one would name a network that does not exist. Stopping."
          return 1
        fi
        extra="id=${nid}"
      fi
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
        local netid="" netidrc
        # `+none` DECLARES NO LIVE VERIFICATION IS OWED. That is only true when the container genuinely
        # HAS no network attachment, which requires having actually read its attachments — never a
        # failed read defaulted to empty. Recording `+none` from a question that was never answered
        # would assert nothing needs verifying for a container that may well be attached and running.
        if netid="$(mi_rt_inspect container c.nets "$name")"; then netidrc=0; else netidrc=$?; fi
        if [ "$netidrc" -eq 3 ]; then continue; fi   # gone since the label read a moment ago
        if [ "$netidrc" -ne 0 ]; then
          mi_warn "repair: '$name' is recorded, but its network attachments could not be read, so whether"
          mi_warn "  it owes a live alias verification cannot be established."
          mi_warn "  Recording '+none' from an unread state would assert no check is owed when one may be. Stopping."
          return 1
        fi
        netid="${netid%%=*}"
        if [ -n "$netid" ]; then
          mi_state_commit "$name" "$want" alias "$netid" || return 1
        else
          # The attachment question WAS answered, and the answer was "none" — genuinely nothing to
          # check, unlike the failed-read case above.
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
    local obs2 obsrc2
    if obs2="$(mi_state_observed "$c")"; then obsrc2=0; else obsrc2=$?; fi
    if [ "$obsrc2" -ne 0 ]; then
      mi_warn "repair: '$c' could not be asked whether it is running, so this run cannot live-verify it."
      mi_warn "  Its outstanding alias check, if any, is left exactly as recorded — never cleared on an"
      mi_warn "  unread state."
      continue
    fi
    [ "$obs2" = running ] || continue
    local alias netid2 product prc aliasesraw alrc blob seg
    # THE PIPELINE'S STATUS IS THE LAST COMMAND'S (`cut`), which hides mi_state_outstanding's own rc —
    # without pipefail (this is a pure library; bin/mythical-ctl's pipefail does not reach here) a
    # failed reader piped into `head|cut` still prints nothing and the pipeline still exits 0. Captured
    # and checked BEFORE the transform, so "could not determine what is owed" is never read as "nothing
    # is owed" — the exact rc-3-vs-rc-1 conflation this module exists to close.
    local outst outstrc
    if outst="$(mi_state_outstanding "$c")"; then outstrc=0; else outstrc=$?; fi
    if [ "$outstrc" -ne 0 ]; then
      mi_warn "repair: '$c' is running, but its outstanding checks could not be read, so what it owes"
      mi_warn "  cannot be established. Left running; not live-verified this run."
      continue
    fi
    # PURE PARAMETER EXPANSION, NOT `head|cut`. `head -n1` closes its stdin the moment it has its line;
    # if `$outst` holds more than one row, the upstream `printf` can be signalled SIGPIPE, and under
    # THIS process's ambient shell options (this library sets none, but bin/mythical-ctl's caller-level
    # `set -euo pipefail` still governs — sourced functions run in the SAME shell, not a subshell) that
    # can fail the assignment and abort mid-repair, AFTER the ledger has already been reset. The FIRST
    # row is everything up to the first newline; its param is everything after the first tab.
    local firstrow="${outst%%$'\n'*}"
    netid2="${firstrow#*$'\t'}"
    [ -n "$netid2" ] && [ "$netid2" != "$firstrow" ] || continue
    # Prefer the canonical family alias derived from the container's own product label (the value a
    # normal bring-up would have used); fall back to whatever alias the container actually carries on
    # this network — a repaired object may carry no product label at all (D37: images carry no
    # installation-specific label either, and this codebase does not require every recovered object to
    # be reachable through the manifest to be live-verified).
    if product="$(mi_rt_inspect container c.product "$c")"; then prc=0; else prc=$?; fi
    if [ "$prc" -eq 3 ]; then continue; fi   # the container itself is gone
    if [ "$prc" -ne 0 ]; then
      # Could not ask. NOT read as "no product label" (that would still try mi_name_alias on empty and
      # then need to fall through anyway) — set it empty and fall straight to the aliases-based
      # reconstruction below, which is independently guarded on ITS OWN read a few lines down.
      product=""
    else
      case "$product" in '<no value>') product="" ;; esac
    fi
    alias=""
    if [ -n "$product" ]; then alias="$(mi_name_alias "$product" 2>/dev/null || true)"; fi
    if [ -z "$alias" ]; then
      # THE ALIAS READ ITSELF MUST FAIL CLOSED — a container whose network aliases could not be asked
      # about is not "carries no alias on this network" (which `continue`s harmlessly below, leaving
      # the check outstanding for a legitimate reason); it is "this run could not attempt live
      # verification at all", and the difference is worth saying so the operator does not read silence
      # as "nothing was owed".
      if aliasesraw="$(mi_rt_inspect container c.aliases "$c")"; then alrc=0; else alrc=$?; fi
      if [ "$alrc" -eq 3 ]; then continue; fi   # gone since the observation a moment ago
      if [ "$alrc" -ne 0 ]; then
        mi_warn "repair: '$c' is running, but its network aliases could not be read, so live"
        mi_warn "  verification cannot be attempted this run. Left running, still outstanding."
        continue
      fi
      # Anchored on a LEADING ';' — same construction lib/bringup.sh's _mi_bringup_attach_ok uses — so a
      # netid that merely ENDS with the expected one cannot answer for it, and so the prefix strip below
      # actually removes the "<netid>:" it is meant to (without the leading ';' the pattern can only
      # match mid-string, never anchor at position 0, and the strip silently leaves the netid in place).
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
#
# "mi_ledger_read failed" IS NOT ONE FACT. It calls mi_die for every non-absent failure — a checksum
# mismatch, a truncated file, a malformed header, AND a schema NEWER than this build understands — so a
# subshelled `! ( mi_ledger_read … )` reports the SAME exit status (the subshell's own `exit 1`) for all
# of them, with no way to tell "genuinely corrupt" from "this file is fine, this binary is old" from its
# rc alone. Reading the newer-schema case as corruption is the worst of the four: `mi_schema_migrate`'s
# own header already says the refusal there "must stay" a refusal — "an older CLI that MISREADS a newer
# ledger deletes objects it misidentifies" — and renaming a STILL-VALID, merely-newer ledger to
# `.corrupt.$$` and replacing it with an empty one is exactly that deletion, reached through the repair
# door instead of the read door. So the header is peeked at FIRST, without going through mi_ledger_read
# at all (it refuses before telling us the number), and a newer schema is refused outright — never
# repaired over.
_mi_repair_reset_ledger() {
  local f; f="$(_mi_ledger_path)"

  if [ -f "$f" ] && [ ! -r "$f" ]; then
    # A permissions problem is an OPERATIONAL fact about this process, not evidence about the ledger's
    # CONTENT — the bytes underneath may be perfectly valid. Refusing (never touching, never moving)
    # is the only honest answer to a question we structurally cannot ask.
    mi_warn "repair: the ledger exists but is not readable by this process. That is a permissions or"
    mi_warn "  ownership problem, not evidence the ledger's content is corrupt — nothing here has been"
    mi_warn "  touched or moved. Fix the permission (or re-run as the user that owns ~/.mythical) and"
    mi_warn "  re-run."
    return 1
  fi

  if [ -f "$f" ]; then
    local hschema hgt
    if hschema="$(_mi_repair_ledger_schema_of "$f")"; then
      if _mi_num_gt "$hschema" "$MI_LEDGER_SCHEMA"; then hgt=0; else hgt=1; fi
      if [ "$hgt" -eq 0 ]; then
        mi_warn "repair: this ledger's schema ($hschema) is newer than this build of mythical-ctl"
        mi_warn "  understands ($MI_LEDGER_SCHEMA). That is not corruption — it is D35's own gate doing"
        mi_warn "  its job — and repairing over it would rename a STILL-VALID ledger aside and replace"
        mi_warn "  it with an empty one, discarding everything a newer mythical-ctl already recorded."
        mi_warn "  Install the current mythical-ctl release and re-run. Nothing here has been touched."
        return 1
      fi
    fi
    # hschema unreadable as a header at all (empty file, no header line, non-numeric schema, …) falls
    # through to the ordinary corrupt-ledger path below, which is the right answer for those: none of
    # them is "valid, just newer".
  fi

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

# Peek at the ledger's header WITHOUT going through mi_ledger_read's fail-closed die — repair's whole
# point is to recover from files mi_ledger_read refuses, and the one thing it must not do is treat
# "refused because it is NEWER" the same as "refused because it is corrupt" (see the note above). This
# reads and validates ONLY the header line's schema number; it says nothing about the checksum or the
# body, and a caller MUST NOT treat its success as "the ledger is valid" — only mi_ledger_read decides
# that.
#
# rc 0 the schema number is printed (proven all-digit, safe for _mi_num_gt) · 1 the file has no header
# this function recognises as one (missing, empty, malformed, non-numeric schema) — the caller's cue to
# fall through to the ordinary corrupt-ledger handling, since none of those is "valid, merely newer".
_mi_repair_ledger_schema_of() {
  local f="$1" header schema
  [ -f "$f" ] || return 1
  header="$(head -n1 "$f" 2>/dev/null)" || return 1
  case "$header" in '#mythical-ctl-ledger schema='*) : ;; *) return 1 ;; esac
  schema="${header#\#mythical-ctl-ledger schema=}"
  case "$schema" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$schema"
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
  local idx="$1" name id migrc

  # A recorded migration resumes rather than starting a new one. `mi_led_find`'s rc split matters here:
  # 0 found · 3 absent (genuinely nothing to resume) · 1 unreadable/ambiguous. A bare `if cmd; then …;
  # fi` with no else treats 1 exactly like 3 and falls through to starting a FRESH rebind — writing
  # phase 1 over an in-flight migration record nobody could read, discarding the only account of where
  # the fleet came from. Mirrors lib/netref.sh's mi_net_ref_rebind, which makes this same check.
  if mi_led_find "$MI_NETMIG_KIND" key family >/dev/null 2>&1; then migrc=0; else migrc=$?; fi
  case "$migrc" in
    0) mi_log "verbs: resuming the recorded network migration."
       # NORMALIZE TO THE VERB CONTRACT (0/1/2 only leave this function — 3 has no meaning at this
       # verb, "not launched" is a manifest concept). mi_netmig_resume itself re-reads the migration
       # record it was just told exists; if it vanished in the window between OUR mi_led_find above and
       # its own internal mi_led_find (the daemon completing something under the lock is not the same
       # as another mythical-ctl process, which the lock DOES exclude), that inner read answers 3 —
       # "absent" — and a bare `return $?` would leak that unchanged. 3 here would mean an operational
       # race during an ALREADY-launched rebind, not "not launched"; mapped to 1.
       local mrc
       if mi_netmig_resume "$idx"; then mrc=0; else mrc=$?; fi
       case "$mrc" in 0|1|2) return "$mrc" ;; *) return 1 ;; esac ;;
    3) : ;;
    *) mi_warn "verbs: whether a network migration is already recorded could not be read from the"
       mi_warn "  ledger. Starting a fresh rebind now could write over an in-flight migration's intent"
       mi_warn "  — the only record of where the fleet came from. Nothing is started."
       return 1 ;;
  esac
  local nrc
  if name="$(mi_conf_get "$(mi_conf_family_path)" MYTHICAL_NET)"; then nrc=0; else nrc=$?; fi
  if [ "$nrc" -eq 3 ]; then
    mi_warn "verbs: MYTHICAL_NET is not set, so there is no operator-supplied network to rebind onto."
    return 1
  fi
  if [ "$nrc" -ne 0 ]; then
    mi_warn "verbs: mythical.conf could not be read, so whether MYTHICAL_NET is set cannot be"
    mi_warn "  established — this is not the same as it being unset. Nothing is started."
    return 1
  fi
  id="$(mi_net_ref_resolve "$name")" || return 1
  mi_warn "verbs: rebinding this installation onto network '$name' ($id)."
  mi_warn "  Every existing container will be connected to it and verified BEFORE any is detached from"
  mi_warn "  the old one, so no step leaves the family partitioned. This is never automatic: a silent"
  mi_warn "  rebind is how a container gets joined to a network you did not intend."
  mi_confirm "verbs: rebind onto '$name'?" || { mi_warn "verbs: not confirmed."; return 1; }
  mi_net_ref_rebind "$idx" "$id"
}
