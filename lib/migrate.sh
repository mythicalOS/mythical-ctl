#!/usr/bin/env bash
# §5/§5.1/§5.2 — `migrate-storage`, in nine durable phases (D51). This is the one place the installer
# itself reads attacker-controlled data (a container volume's contents) and writes it to host paths —
# both trees are untrusted, and every check below is written on that assumption.
#
# THE CONFINEMENT BOUNDARY IS THE DESTINATION PLUS ONE DERIVED STAGING PATH — stated, not assumed (D24,
# amended). §5.2's commit requires a same-filesystem sibling, which literally writes outside the
# destination. The authorization is deliberately narrow, and narrowness is what keeps it a boundary:
# exactly ONE additional path, `<parent-of-destination>/.mythical-staging-<nonce>`, DERIVED from the
# destination rather than configured, so nothing outside can name it; RECORDED IN THE INTENT BEFORE IT IS
# CREATED, so it is attributable rather than discovered; and confinement applies within it too.
#
# MI_MIG_KIND is declared in lib/state.sh, which loads first and needs it for the reconciler's
# suspension check. Do NOT redefine it here: two spellings of one ledger kind is how that check stops
# matching the records it guards.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

# mi_mig_precheck and mi_mig_run both call mi_accept_manifest/mi_accept_policy, which — unconditionally,
# for every caller — ADVANCE THE ANTI-ROLLBACK TRUST FLOOR as part of accepting an authentic document.
# That is a ledger write, so it requires the family lock (mi_lock_assert_held, several frames down).
# Both functions are called two ways: standalone, directly, by callers that have not taken the lock
# (every §10a check test, and mi_mig_resume's per-phase loop), and from inside the already-locked verb
# (_mi_verb_migrate_storage_locked, via _mi_with_lock). mi_lock_acquire is NOT reentrant — a second
# acquire from the SAME process reads its own pid back off the lock file and refuses as "another
# operation in progress" — so these two functions acquire the lock THEMSELVES, but only when it is not
# already held, and release it only if they were the ones who took it. Sets MI_MIG_LOCK_OWNED; must be
# called directly, never through `$( )`, or mi_lock_acquire's own `export` is lost to the subshell.
_mi_mig_lock_enter() {
  if [ -n "${MI_LOCK_TOKEN:-}" ]; then MI_MIG_LOCK_OWNED=0; return 0; fi
  mi_lock_acquire || return 1
  MI_MIG_LOCK_OWNED=1
  return 0
}
_mi_mig_lock_exit() {
  if [ "${MI_MIG_LOCK_OWNED:-0}" = 1 ]; then mi_lock_release; fi
  MI_MIG_LOCK_OWNED=0
  return 0
}

_mi_mig_key() { printf '%s:%s\n' "$1" "$2"; }

# STAGING IS A SIBLING OF THE DESTINATION, NEVER INSIDE IT. Putting staging inside the destination and
# then "atomically moving it into place" is renaming a directory onto its own parent, which the kernel
# refuses (ENOTEMPTY). A sibling on the same filesystem renames correctly onto a destination that does
# not exist OR is empty — the only two cases §5.1's non-empty-destination rule permits.
mi_mig_staging_path() {
  if [ "$#" -ne 2 ]; then mi_warn "migrate: mi_mig_staging_path needs <destination> <nonce>"; return 1; fi
  printf '%s/.mythical-staging-%s\n' "$(dirname -- "$1")" "$2"
}

# device:inode. `rename()` PRESERVES both, which is what makes the destination identifiable after a
# crash between the rename and the phase advance.
mi_mig_identity() {
  if [ "$#" -ne 1 ]; then mi_warn "migrate: mi_mig_identity needs a <path>"; return 1; fi
  _mi_ino "$1"
}

# CLOSE THE TOCTOU AT THE POINT OF USE, not at the point of the check. A device+inode captured once
# and trusted for everything that follows is only as good as the assumption that nothing changes in
# between — and both trees this module touches are untrusted (§5.1's own premise), so a parent
# directory an attacker can write to can replace a checked path with anything, including a symlink,
# between the check and whatever comes next. `_mi_ino` (via `stat`, no `-L`) reports the identity of
# the path ITSELF, not of a symlink's target — so a swap to a symlink changes the observed identity
# and is caught here, same as a swap to an ordinary different directory. This narrows the window to
# the gap between THIS call and the very next thing that touches the path, rather than eliminating it
# outright (a bash script hands a PATH STRING to whatever it invokes next, never a held-open handle,
# so no shell-level check can be perfectly atomic with an external process's own path resolution) — the
# same accepted narrowing this codebase already applies to mythical.conf's own read-to-rename window
# (lib/config.sh). Called immediately before each place that would otherwise re-resolve the path name
# after checking it once. rc 0 the identity still matches · 1 refused, nothing further attempted.
mi_mig_verify_identity() {
  if [ "$#" -ne 3 ]; then mi_warn "migrate: mi_mig_verify_identity needs <path> <expected identity> <what>"; return 1; fi
  local path="$1" want="$2" what="$3" cur
  cur="$(mi_mig_identity "$path" 2>/dev/null)" || cur=""
  if [ -z "$cur" ] || [ "$cur" != "$want" ]; then
    mi_warn "migrate: $what no longer carries the identity this process recorded for it (expected"
    mi_warn "  ${want}, found ${cur:-<unreadable>}). Between the check and this use, whatever is at"
    mi_warn "  '$path' changed. Refusing rather than operate on something this process never verified."
    return 1
  fi
  return 0
}

# Is <path> itself a MOUNT POINT? Detection must consult MOUNT-TABLE EVIDENCE.
#
# Comparing st_dev with the parent's does NOT detect this on its own: a bind mount of the same
# filesystem carries the same device number as its parent and is still unreplaceable, so a matching
# st_dev is not conclusive of "not a mount point" — only a DIFFERING st_dev is conclusive of the
# opposite. A differing st_dev below is therefore used only as a cheap first filter, never as the test
# on its own; a matching st_dev falls through to the mount table, which is authoritative either way.
mi_mig_is_mountpoint() {
  if [ "$#" -ne 1 ]; then mi_warn "migrate: mi_mig_is_mountpoint needs a <path>"; return 1; fi
  local p="$1" canon
  canon="$(mi_canon "$p" 2>/dev/null)" || return 1
  # Test hook: the harness cannot create real mounts. Each declared entry is canonicalized before the
  # comparison too — a fixture path built from a bare `mktemp -d` is not necessarily canonical itself
  # (measured: macOS's /var -> /private/var symlink means "$(mktemp -d)/x" and its own canonical form
  # are two different strings), and comparing raw against canonical would silently never match.
  local fm fmc
  for fm in ${FAKE_MOUNTPOINTS:-}; do
    fmc="$(mi_canon "$fm" 2>/dev/null)" || continue
    [ "$fmc" = "$canon" ] && return 0
  done
  [ -d "$canon" ] || return 1

  local d pd
  d="$(_mi_ino "$canon" 2>/dev/null)" || d=""
  d="${d%%:*}"
  pd="$(_mi_ino "$(dirname -- "$canon")" 2>/dev/null)" || pd=""
  pd="${pd%%:*}"
  if [ -n "$d" ] && [ -n "$pd" ] && [ "$d" != "$pd" ]; then return 0; fi

  # The real test: the mount table. Linux exposes a distinct mount ID in /proc/self/mountinfo, which is
  # authoritative; macOS has no such file, so the platform mount list is parsed instead — mount-table
  # evidence, never an st_dev comparison, a bind mount of the same filesystem shares its parent's device
  # number and would pass the cheap filter above.
  if [ -r /proc/self/mountinfo ]; then
    local line
    while IFS= read -r line; do
      # fields: id parent major:minor root mountpoint ...
      # shellcheck disable=SC2086   # deliberate field split of a mountinfo line we did not write
      set -- $line
      [ "${5:-}" = "$canon" ] && return 0
    done < /proc/self/mountinfo
    return 1
  fi
  # Plain `mount`, whose output is `<device> on <mountpoint> (<type>, …)` on macOS. There is
  # deliberately NO `mount -p` attempt: macOS rejects the flag (verified — "illegal option -- p"), so it
  # buys nothing there, and on a BSD where it IS supported it prints fstab format that the parser below
  # does not read — while SUCCEEDING, which would suppress the fallback and silently make this check
  # find nothing. A probe that quietly finds nothing is worse than one that is not attempted.
  local mp
  while IFS= read -r mp; do
    [ "$mp" = "$canon" ] && return 0
  done <<< "$( mount 2>/dev/null | sed -n 's/^.* on \([^(]*\) (.*$/\1/p' | sed 's/[[:space:]]*$//' )"
  return 1
}

# §5.2's phase-5 recovery. Decides on POSITIVE EVIDENCE ONLY, and stops when it has none.
#
#   identity at the DESTINATION  the rename completed  → advance to phase 6
#   identity at STAGING          the rename had not run → retry phase 5
#   NOWHERE                      unattributable — the rename may have succeeded and been replaced since
#                                → stop and report. Never touch either path again on its own.
#
# Acting again on the strength of an ABSENCE is the same error as removing on the strength of a NAME.
mi_mig_resolve_phase5() {
  if [ "$#" -ne 3 ]; then mi_warn "migrate: mi_mig_resolve_phase5 needs <destination> <staging> <recorded id>"; return 1; fi
  local dest="$1" stage="$2" want="$3" d s
  d="$(mi_mig_identity "$dest" 2>/dev/null)" || d=""
  s="$(mi_mig_identity "$stage" 2>/dev/null)" || s=""
  if [ -n "$d" ] && [ "$d" = "$want" ]; then printf 'destination\n'; return 0; fi
  if [ -n "$s" ] && [ "$s" = "$want" ]; then printf 'staging\n'; return 0; fi
  mi_warn "migrate: the recorded directory identity ($want) is at neither the destination nor the"
  mi_warn "  staging path. That is unattributable: the rename may already have completed and the"
  mi_warn "  destination may have been replaced since, in which case trying again would copy over"
  mi_warn "  whatever replaced it, and the original migrated data would already be gone. This stops"
  mi_warn "  here and reports. Nothing here is touched or taken away — inspect both paths and decide."
  return 1
}

# RESUME MUST VERIFY, NOT TRUST (§5.2). The recorded phase is a WRITE-AHEAD intent — written BEFORE
# the phase's own action runs, precisely so a crash mid-action still names the phase that was in
# progress. That same property means a recorded phase of 6 or later does NOT, by itself, prove phase
# 5's rename ever produced a destination: phases 1-5 are each the first place that establishes their
# own postcondition, so resuming AT any of them is always well-defined, but 6 (write the config)
# through 9 (restore desired state) all depend on phase 5's result already being on disk — phase 7's
# bind mount fails outright if the destination is not there.
#
# Verified the same way phase 5 itself verifies (mi_mig_resolve_phase5): the recorded device+inode,
# found or not, is the ONLY evidence trusted — never the destination's mere presence, and never its
# absence either. If it checks out, the recorded phase is trustworthy and resume proceeds from there
# unmodified. If it does not — no identity was ever recorded, or it is at neither candidate path, or
# the destination holds something else entirely — resume falls back to phase 5, where the SAME
# resolve-and-recover logic that already handles a genuine phase-5 crash (retry the rename from
# staging, or — when nothing was ever recorded because there was nothing yet to protect — proceed with
# an empty destination) re-derives the true state, and phases 6 on repeat over it. The source volume
# is untouched throughout, so redoing this tail is always well-defined.
mi_mig_resume_phase() {
  if [ "$#" -ne 3 ]; then
    mi_warn "migrate: mi_mig_resume_phase needs <recorded phase> <destination> <recorded stageid>"
    return 1
  fi
  local phase="$1" dest="$2" stageid="$3"
  case "$phase" in
    [1-5]) printf '%s\n' "$phase"; return 0 ;;
  esac
  if [ -n "$stageid" ]; then
    local curid
    if curid="$(mi_mig_identity "$dest" 2>/dev/null)" && [ "$curid" = "$stageid" ]; then
      printf '%s\n' "$phase"
      return 0
    fi
  fi
  printf '5\n'
  return 0
}

# A RECOGNISABLE STAGING NAME IS NOT AUTHORITY. The destination is untrusted by §5.1's own premise, so
# after a crash a directory bearing our staging name may be attacker-placed or may be replacement user
# data. Recovery verifies the NONCE recorded in the intent AND the directory's IMMUTABLE IDENTITY
# (device + inode) before removing anything, and PRESERVES AND REPORTS on any mismatch — the same rule
# §6a applies to runtime objects.
mi_mig_staging_reclaim() {
  if [ "$#" -ne 4 ]; then mi_warn "migrate: mi_mig_staging_reclaim needs <staging> <recorded nonce> <recorded id> <path nonce>"; return 1; fi
  local stage="$1" rnonce="$2" rid="$3" pnonce="$4" cur
  [ -d "$stage" ] || return 0
  cur="$(mi_mig_identity "$stage" 2>/dev/null)" || cur=""
  if [ "$pnonce" != "$rnonce" ] || [ -z "$cur" ] || [ "$cur" != "$rid" ]; then
    mi_warn "migrate: the staging directory $stage does not match the recorded intent"
    mi_warn "    recorded nonce=$rnonce identity=$rid"
    mi_warn "    found    nonce=$pnonce identity=${cur:-<unreadable>}"
    mi_warn "  it is preserved and reported. A name can be reassigned to something this installer never"
    mi_warn "  created, so the name alone is not authority to remove it. Whether to reclaim the space is"
    mi_warn "  your call; a retry proceeds beside it with a fresh nonce and a fresh path."
    return 1
  fi

  # ATOMIC RECLAIM, NOT check-then-rm. The check above named $stage by a PATH, and between it and an
  # `rm -rf` against that same path there is a window in which an attacker who still controls the
  # parent directory can replace whatever the name refers to — the recursive delete would then remove
  # the REPLACEMENT, which this process never verified, defeating the nonce+identity rule above
  # entirely. Renaming $stage away FIRST closes that: rename() is atomic and identity-preserving (by
  # inode), so the renamed handle is either exactly the object just checked, or the rename itself
  # raced and failed outright — nothing in between. The identity is re-verified on THAT handle,
  # immediately before the delete, with no further path-name lookup in between, and only ever removes
  # what was just renamed — never $stage by its original, still attacker-writable name.
  local tag priv vid
  tag="$(mi_nonce_new)" || { mi_warn "migrate: could not mint a reclaim path"; return 1; }
  priv="$(dirname -- "$stage")/.mythical-reclaim-${tag}"
  if [ -e "$priv" ]; then
    mi_warn "migrate: the private reclaim path $priv already exists. Refusing rather than risk 'mv'"
    mi_warn "  nesting the staging directory inside it instead of claiming it exclusively."
    return 1
  fi
  if ! mv -- "$stage" "$priv" 2>/dev/null; then
    mi_warn "migrate: could not rename the staging directory $stage to reclaim it. Nothing was removed."
    return 1
  fi
  vid="$(mi_mig_identity "$priv" 2>/dev/null)" || vid=""
  if [ -z "$vid" ] || [ "$vid" != "$rid" ]; then
    mi_warn "migrate: after renaming $stage to reclaim it, the renamed directory (now at $priv) no"
    mi_warn "  longer carries the identity just verified (expected $rid, found ${vid:-<unreadable>}) —"
    mi_warn "  something replaced it in the instant between the check and the rename. It is preserved"
    mi_warn "  at $priv, not deleted, and not renamed back onto a name that may already be reassigned."
    return 1
  fi
  rm -rf -- "$priv" || {
    mi_warn "migrate: could not remove the staging directory (renamed to $priv to reclaim it)"
    return 1
  }
  return 0
}

# --- preconditions (§5, D53/D55) -------------------------------------------------------------------
# THE ORDER IS: is there a LIVE INTENT matching this exact operation? — then the rest. A rule that
# refused "before anything else" on a present bind would refuse to RESUME, stranding the migration
# permanently at the phase that had just succeeded (phase 6 writes the bind while the intent is still
# live).
#
# rc 0 proceed — either a fresh migration, or a live intent for this exact (product, role,
# destination) that the caller is free to resume · 1 refused (reported). Whether a call that returned
# 0 is a fresh start or a resume is NOT signalled by this return code: the caller determines that
# independently, by asking mi_mig_phase whether a phase is already recorded — the same ledger record
# this function itself just consulted, so there is nothing this function could tell it that a second,
# ordinary read cannot.
mi_mig_precheck() {
  if [ "$#" -ne 6 ]; then mi_warn "migrate: mi_mig_precheck needs <index> <policy> <manifest> <product> <role> <destination>"; return 1; fi
  _mi_mig_lock_enter || return 1
  local _rc
  if _mi_mig_precheck_body "$@"; then _rc=0; else _rc=$?; fi
  _mi_mig_lock_exit
  return "$_rc"
}

_mi_mig_precheck_body() {
  local idx="$1" pol="$2" man="$3" product="$4" role="$5" dest="$6"
  local mrec prec rec rc ident

  ident="$(mi_ident_get)" || return 1
  mrec="$(mi_accept_manifest "$idx" "$pol" "$man" "$product")" || return 1
  prec="$(mi_accept_policy "$idx" "$pol")" || return 1

  # A live intent for (product, role) is resumed ONLY IF the requested destination matches the recorded
  # one — resuming on (product, role) alone would silently hijack a migration to a DIFFERENT path,
  # reporting success for a destination the operator did not name.
  if rec="$(mi_led_find "$MI_MIG_KIND" key "$(_mi_mig_key "$product" "$role")")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    local rdest rdrc
    if rdest="$(mi_led_field "$rec" dest)"; then rdrc=0; else rdrc=$?; fi
    if [ "$rdrc" -eq 3 ]; then rdest=""
    elif [ "$rdrc" -ne 0 ]; then return 1
    fi
    # A live intent for EXACTLY this destination is not a refusal — it is resumed, and skipping every
    # check below is deliberate: the destination may legitimately be non-empty by now (a completed
    # rename from an earlier phase), and re-running "is it empty" here would refuse a migration that
    # is correctly in progress.
    if [ -n "$rdest" ] && [ "$rdest" = "$dest" ]; then return 0; fi
    mi_warn "migrate: a migration of $product/$role is already in flight, to a different destination:"
    mi_warn "    in flight: ${rdest:-<unreadable>}"
    mi_warn "    requested: $dest"
    mi_warn "  Stopping. Finish or abandon the in-flight migration explicitly, then re-run."
    return 1
  fi
  [ "$rc" -eq 3 ] || return "$rc"

  # The role must EXIST in the manifest — which also gives the operator the list.
  local v roles="" found=0 mount=""
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    roles="${roles} ${v%%:*}"
    if [ "${v%%:*}" = "$role" ]; then found=1; mount="${v#*:}"; fi
  done <<< "$(mi_doc_values "$mrec" volume)"
  if [ "$found" -eq 0 ]; then
    mi_warn "migrate: '$product' has no volume role '$role'. Its roles are:${roles}"
    return 1
  fi

  # BUT RECOGNISING A ROLE IS NOT AUTHORIZING IT (D53). Rejecting only UNKNOWN roles makes every known
  # one migratable — including a product's secrets role. D5 puts runtime secrets in the product's own
  # store and §4.3 relies on that being a 0600 named volume; migrating it to a host bind moves every
  # model credential and webhook secret onto an operator-chosen path with whatever permissions and
  # backup exposure that path has. This command would have been a supported, one-line way to defeat the
  # secrets boundary — and nothing in "the role exists" would have stopped it.
  if ! mi_policy_bindable "$prec" "$product" "$role"; then
    mi_warn "migrate: the role '$role' is permitted for '$product' — the product mounts it — but it is"
    mi_warn "  not bindable. Bindability is a policy entitlement, declared in the family policy index,"
    mi_warn "  never by the product: a product must not be able to authorize widening its own storage"
    mi_warn "  boundary. A secrets role is deliberately kept off this list, because binding it would"
    mi_warn "  move every credential in it onto a host path with whatever exposure that path has."
    return 1
  fi

  # AND THE ROLE MUST CURRENTLY BE VOLUME-BACKED (D55) — proved by POSITIVE INSPECTION, not by an absent
  # config key. The source is always the DERIVED NAMED VOLUME, so after a role has been migrated to a
  # bind, running this again would copy that STALE volume — whose contents stopped changing at the first
  # migration — over the live bind and then rewrite mythical.conf to point at it. The operator would
  # lose everything written since. (Phase 9 only MAY remove the source volume, so the stale copy
  # generally still exists to be copied.)
  local up rup key cur crc
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')" || { mi_warn "migrate: could not derive the config key for '$product' — refusing rather than reading the wrong key."; return 1; }
  rup="$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')" || { mi_warn "migrate: could not derive the config key for role '$role' — refusing rather than reading the wrong key."; return 1; }
  key="MYTHICAL_${up}_${rup}_BIND"
  if cur="$(mi_conf_get "$(mi_conf_family_path)" "$key")"; then crc=0; else crc=$?; fi
  if [ "$crc" -eq 0 ]; then
    mi_warn "migrate: $product/$role is already bind-backed, at:"
    mi_warn "    $cur"
    mi_warn "  Refusing. The source of a migration is always the derived named volume, and that volume"
    mi_warn "  is now stale — its contents stopped changing when you first migrated. Copying it over"
    mi_warn "  the live bind would lose everything written since."
    mi_warn "  Bind-to-bind migration is a different operation and is not implemented: its source is a"
    mi_warn "  host path, it needs no copy container, and its failure modes differ."
    return 1
  elif [ "$crc" -ne 3 ]; then
    mi_warn "migrate: mythical.conf could not be read, so whether $product/$role is already bind-backed"
    mi_warn "  cannot be established. Refusing rather than guessing."
    return 1
  fi

  # POSITIVE INSPECTION: the current container must be observed mounting the recorded source volume,
  # identified by name (D56). An absent config key is weak evidence, since a bind could have been
  # configured without the config reflecting it.
  local srcvol c mounts
  srcvol="$(mi_name_volume "$ident" "$product" "$role")" || return 1
  c="$(mi_name_container "$ident" "$product")" || return 1
  mounts="$(mi_rt_inspect container c.mounts "$c" 2>/dev/null)" || mounts=""
  case ";${mounts}" in
    *"volume|${srcvol}|"*) : ;;
    *) mi_warn "migrate: the container for '$product' does not mount the volume this migration would read."
       mi_warn "    expected volume: $srcvol"
       mi_warn "    container mounts: ${mounts:-<none>}"
       mi_warn "  Refusing on positive inspection rather than assuming from an absent config key."
       return 1 ;;
  esac
  if ! mi_prov_authority volume "$srcvol" >/dev/null; then
    mi_warn "migrate: the source volume '$srcvol' does not match this installation's record (see above)."
    return 1
  fi

  # A NON-EMPTY DESTINATION IS A REFUSAL BY DEFAULT, not combined with the copy — combining an untrusted
  # tree with the copy is how the two become one. Our OWN staging does not count (otherwise a crashed
  # migration permanently blocks its own retry, the deadlock §5.2 exists to remove).
  local canon
  if [ -e "$dest" ]; then
    canon="$(mi_canon "$dest")" || return 1
    if [ ! -d "$canon" ]; then mi_warn "migrate: '$dest' exists and is not a directory"; return 1; fi
    local e
    for e in "$canon"/* "$canon"/.[!.]*; do
      # PRESENCE, NOT READABILITY. `-e` alone is false for a DANGLING symlink, so a destination
      # containing only one would read as empty — `-L` is what sees the link itself, the same
      # discipline this codebase applies everywhere a directory listing decides something (see
      # mi_first_use). An unmatched glob expands to the literal pattern, which is neither.
      if [ -e "$e" ] || [ -L "$e" ]; then : ; else continue; fi
      mi_warn "migrate: the destination '$canon' is not empty (found $(basename -- "$e"))."
      mi_warn "  Refusing rather than combining it with the copy: both trees here are untrusted, and"
      mi_warn "  combining an unproven tree into the copy is exactly how the two become one."
      return 1
    done
  fi

  # EXCEPT WHEN THE DESTINATION IS ITSELF A MOUNT POINT — then its sibling may be on the PARENT
  # filesystem, making the rename cross-device (EXDEV), and replacing a mount point fails regardless
  # (EBUSY).
  if mi_mig_is_mountpoint "$dest"; then
    mi_warn "migrate: '$dest' is itself a mount point, so the atomic commit cannot work: a sibling of it"
    mi_warn "  may be on the parent filesystem (EXDEV), and replacing a mount point fails anyway (EBUSY)."
    mi_warn "  The remedy is to migrate into a subdirectory of the mount instead — that restores a"
    mi_warn "  same-filesystem sibling and works normally. Refusing beats silently falling back to a"
    mi_warn "  non-atomic copy, which would give up the one property this phase exists to provide."
    return 1
  fi

  # The destination must not be inside the family home, and must not overlap another bind (§4.1a).
  mi_mount_check_overlap "$product" "$dest" || return 1
  return 0
}

# --- the nine phases ------------------------------------------------------------------------------
mi_mig_phase() {
  if [ "$#" -ne 2 ]; then mi_warn "migrate: mi_mig_phase needs <product> <role>"; return 1; fi
  local rec
  rec="$(mi_led_find "$MI_MIG_KIND" key "$(_mi_mig_key "$1" "$2")")" || return $?
  mi_led_field "$rec" phase
}

# The recorded phase-5 identity (device+inode) for <product>/<role>, one field over from
# mi_mig_phase — rc 0 prints it · 3 no migration is recorded, OR one is but has no stageid yet
# (legitimate before phase 3 has ever run) · 1 refused. Kept separate rather than folded into
# mi_mig_phase so a caller that only wants the phase never has to know this field exists.
mi_mig_stageid() {
  if [ "$#" -ne 2 ]; then mi_warn "migrate: mi_mig_stageid needs <product> <role>"; return 1; fi
  local rec
  rec="$(mi_led_find "$MI_MIG_KIND" key "$(_mi_mig_key "$1" "$2")")" || return $?
  mi_led_field "$rec" stageid
}

_mi_mig_set() {   # <product> <role> <phase> <field>...
  local product="$1" role="$2" phase="$3"; shift 3
  mi_led_put "$MI_MIG_KIND" key "$(_mi_mig_key "$product" "$role")" \
    "key=$(_mi_mig_key "$product" "$role")" "product=${product}" "role=${role}" "phase=${phase}" "$@"
}

# A field carried forward from the RECORD AS IT WAS WHEN THIS PHASE WAS ENTERED — never masking a real
# read failure as "there is nothing there". rc 3 (the field is legitimately absent) is the only status
# this may default; anything else propagates.
_mi_mig_carry() {
  local rec="$1" field="$2" dflt="${3:-}" v rc
  # NO PRIOR RECORD AT ALL (phase 1's own entry) is the other legitimate default, and it is NOT the
  # same rc as a real record missing this one field: mi_led_field's underlying gate treats an EMPTY
  # record string as MALFORMED (rc 1, "describes nothing") rather than rc 3, because a genuinely
  # malformed non-empty row and a deliberately empty "no record" string must not be read the same way
  # by every OTHER caller of mi_led_field. This function is the one place that draws the distinction
  # for its own callers: empty input defaults here; empty input everywhere else still refuses.
  if [ -z "$rec" ]; then printf '%s\n' "$dflt"; return 0; fi
  if v="$(mi_led_field "$rec" "$field")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then printf '%s\n' "$dflt"; return 0; fi
  [ "$rc" -eq 0 ] || return 1
  printf '%s\n' "$v"
}

# Run ONE phase. Phases are recorded BEFORE they are entered, which is what makes a crash resumable at
# the phase that was in progress rather than at the last one that finished.
#
# HELD FOR THE WHOLE PHASE, NOT JUST FOR mi_accept_manifest/mi_accept_policy: every phase body below
# also writes through mi_led_put/mi_conf_family_cas/mi_state_commit/mi_prov_tombstone, each of which
# asserts the lock itself (mi_lock_assert_held) rather than acquiring it — so the whole call must run
# under one continuous hold, exactly as every other mutating verb in this codebase does.
mi_mig_run() {
  if [ "$#" -ne 7 ]; then
    mi_warn "migrate: mi_mig_run needs <index> <policy> <manifest> <product> <role> <destination> <phase>"
    return 1
  fi
  _mi_mig_lock_enter || return 1
  local _rc
  if _mi_mig_run_body "$@"; then _rc=0; else _rc=$?; fi
  _mi_mig_lock_exit
  return "$_rc"
}

_mi_mig_run_body() {
  local idx="$1" pol="$2" man="$3" product="$4" role="$5" dest="$6" phase="$7"
  local rec ident mrec prec srcvol c up rup key stage nonce ruid ouid mount rc

  case "$phase" in [1-9]) : ;;
    *) mi_warn "migrate: '$phase' is not a migration phase"; return 1 ;;
  esac

  ident="$(mi_ident_get)" || return 1
  mrec="$(mi_accept_manifest "$idx" "$pol" "$man" "$product")" || return 1
  prec="$(mi_accept_policy "$idx" "$pol")" || return 1
  srcvol="$(mi_name_volume "$ident" "$product" "$role")" || return 1
  c="$(mi_name_container "$ident" "$product")" || return 1
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')" || { mi_warn "migrate: could not derive the config key for '$product' — refusing rather than reading the wrong key."; return 1; }
  rup="$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')" || { mi_warn "migrate: could not derive the config key for role '$role' — refusing rather than reading the wrong key."; return 1; }
  key="MYTHICAL_${up}_${rup}_BIND"
  ruid="$(mi_manifest_runtime_uid "$mrec")" || return 1
  ouid="$(id -u)"
  mount=""
  local v
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    [ "${v%%:*}" = "$role" ] && mount="${v#*:}"
  done <<< "$(mi_doc_values "$mrec" volume)"

  # THE RECORDED STATE, READ ONCE, AS IT WAS WHEN THIS CALL BEGAN. rc 3 (no record at all — this is
  # phase 1's own entry) is the only status that defaults to "nothing carried forward"; an unreadable or
  # ambiguous ledger must not be silently treated as an empty one, since every later phase's "carry
  # forward" reads would then write blanks over a migration this core simply failed to read.
  local rrc
  if rec="$(mi_led_find "$MI_MIG_KIND" key "$(_mi_mig_key "$product" "$role")")"; then rrc=0; else rrc=$?; fi
  if [ "$rrc" -eq 3 ]; then rec=""
  elif [ "$rrc" -ne 0 ]; then
    mi_warn "migrate: the recorded state for $product/$role could not be established. Refusing to act"
    mi_warn "  on this phase over a ledger this core cannot read. Run 'mythical-ctl state repair'."
    return 1
  fi
  nonce="$(_mi_mig_carry "$rec" nonce)" || return 1
  stage="$(_mi_mig_carry "$rec" staging)" || return 1

  case "$phase" in
    1)
      # EACH ATTEMPT ALLOCATES A FRESH NONCE AND A FRESH STAGING PATH. The identity cannot be captured
      # before the directory exists, so there is always a window — a crash between mkdir and the ledger
      # write — that leaves a directory we cannot prove is ours. Rather than removing on suspicion, an
      # unprovable leftover is preserved, reported once, and stepped around: the retry proceeds beside
      # it.
      nonce="$(mi_nonce_new)" || return 1
      stage="$(mi_mig_staging_path "$dest" "$nonce")" || return 1
      local prior desired prc dgrc
      if prior="$(mi_conf_get "$(mi_conf_family_path)" "$key")"; then prc=0; else prc=$?; fi
      if [ "$prc" -eq 3 ]; then prior=""
      elif [ "$prc" -ne 0 ]; then
        mi_warn "migrate: mythical.conf could not be read, so the prior value of $key cannot be"
        mi_warn "  established. Refusing to record an intent over configuration this core cannot read."
        return 1
      fi
      if desired="$(mi_state_desired_get "$c" 2>/dev/null)"; then dgrc=0; else dgrc=$?; fi
      if [ "$dgrc" -eq 3 ]; then desired=running
      elif [ "$dgrc" -ne 0 ]; then
        mi_warn "migrate: the recorded desired state for '$c' could not be read. Refusing to record an"
        mi_warn "  intent over a state this core cannot establish. Run 'mythical-ctl state repair'."
        return 1
      fi
      _mi_mig_set "$product" "$role" 1 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior}" "attempt=none" "desired=${desired}" \
        "mount=${mount}" "stageid=" || return 1
      ;;
    2)
      # DESIRED STATE IS PRESERVED — this stops the container as a MEANS, not as an intent. A verb that
      # stops a container as a means to an end must not overwrite what the operator wants.
      local prior2 attempt2 desired2 stageid2
      prior2="$(_mi_mig_carry "$rec" prior)" || return 1
      attempt2="$(_mi_mig_carry "$rec" attempt none)" || return 1
      desired2="$(_mi_mig_carry "$rec" desired running)" || return 1
      stageid2="$(_mi_mig_carry "$rec" stageid)" || return 1
      _mi_mig_set "$product" "$role" 2 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior2}" "attempt=${attempt2}" \
        "desired=${desired2}" "mount=${mount}" "stageid=${stageid2}" || return 1
      # STOP THE WRITER FIRST (§5.1), and a stop that FAILS must stop the migration. Copying a live tree
      # the product is still writing to is racing a process that gets to move the goalposts, and phase 4
      # would then verify a copy of a moment that never existed as a whole.
      if ! mi_rt_container_stop "$c" >/dev/null 2>&1; then
        local obs2 orc2
        if obs2="$(mi_state_observed "$c")"; then orc2=0; else orc2=$?; fi
        # A FAILURE TO ANSWER IS NOT EVIDENCE THAT IT STOPPED. `orc2 -ne 0` means the runtime could not
        # be asked at all — folding that into "not running" would let a copy proceed against a volume
        # that may still be live, on exactly the daemon-flaky moment this check exists to catch.
        if [ "$orc2" -ne 0 ] || [ "$obs2" = running ]; then
          mi_warn "migrate: '$c' could not be stopped, and whether it is still running could not be"
          mi_warn "  established either way. Refusing to copy a volume that may still be written to."
          mi_warn "  The intent stays at phase 2 and can be resumed."
          return 1
        fi
      fi
      ;;
    3)
      mi_copy_available "$idx" || return 1
      if mi_mig_is_mountpoint "$dest"; then mi_warn "migrate: '$dest' became a mount point"; return 1; fi
      local prior3 attempt3 desired3
      prior3="$(_mi_mig_carry "$rec" prior)" || return 1
      attempt3="$(_mi_mig_carry "$rec" attempt none)" || return 1
      desired3="$(_mi_mig_carry "$rec" desired running)" || return 1
      # `mkdir`, NOT `mkdir -p`: -p succeeds on an EXISTING directory, so after the documented crash
      # window (between the mkdir and the stageid write) a retry would adopt whatever sits at the
      # staging name, record ITS identity, and copy into it — the opposite of §5.2's rule that an
      # unprovable leftover is preserved, reported once, and stepped around with a fresh nonce.
      if ! mkdir -- "$stage" 2>/dev/null; then
        if [ -e "$stage" ]; then
          mi_warn "migrate: '$stage' already exists, so this attempt cannot prove the directory is its"
          mi_warn "  own. It is preserved and reported; re-run to proceed beside it with a fresh nonce"
          mi_warn "  and a fresh staging path. Reclaiming the space is your decision."
          _mi_mig_set "$product" "$role" 1 "dest=${dest}" "srcvol=${srcvol}" "staging=" "nonce=" \
            "confkey=${key}" "prior=${prior3}" "attempt=${attempt3}" "desired=${desired3}" \
            "mount=${mount}" "stageid=" || return 1
        else
          mi_warn "migrate: cannot create the staging directory $stage"
        fi
        return 1
      fi
      local sid
      sid="$(mi_mig_identity "$stage")" || { mi_warn "migrate: cannot read the staging identity"; return 1; }
      _mi_mig_set "$product" "$role" 3 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior3}" "attempt=${attempt3}" \
        "desired=${desired3}" "mount=${mount}" "stageid=${sid}" || return 1
      # RE-VERIFIED IMMEDIATELY BEFORE EACH POINT $stage IS HANDED TO THE COPY HELPER AS A WRITABLE
      # BIND SOURCE — never trusted on the strength of the identity captured above alone. The ledger
      # write between that capture and here (and, for the second check, the whole preflight round-trip)
      # is real wall-clock time in which an attacker who controls the destination's parent could replace
      # $stage with a symlink; the helper would then follow the raw path and write volume contents
      # outside the intended root. See mi_mig_verify_identity.
      mi_mig_verify_identity "$stage" "$sid" "the staging directory" || return 1
      mi_copy_preflight "$idx" "$stage" "$ruid" "$ouid" || return 1
      mi_mig_verify_identity "$stage" "$sid" "the staging directory" || return 1
      if [ -n "${MI_MIG_MAP_FOREIGN:-}" ]; then
        mi_copy_run "$idx" "$srcvol" "$stage" "$ruid" "$ouid" --map-foreign-to-operator || return 1
      else
        mi_copy_run "$idx" "$srcvol" "$stage" "$ruid" "$ouid" || return 1
      fi
      ;;
    4)
      # PHASE 4 IS NOT SEPARATELY RECORDED — as the phase table's own "crash here" column states, a
      # crash during verification is handled EXACTLY as one during phase 3: the ledger still names
      # phase 3, so a resumed process re-enters phase 3, and `mkdir` (no `-p`, see there) refuses to
      # adopt the unconfirmed copy — it is stepped around with a fresh nonce rather than salvaged.
      #
      # A resume that reaches this call directly with no staging directory on disk (never having run
      # phase 3 itself in this process) has nothing to verify. That can only happen from a corrective
      # ledger edit, never from a real crash — phase 3 always creates $stage before this phase can ever
      # be reached — so it is reported and treated as a no-op that still advances.
      if [ ! -d "$stage" ]; then
        mi_log "migrate: no staging directory at ${stage} to verify — nothing was copied in this"
        mi_log "  process to compare against. A genuine crash here re-enters phase 3, which redoes the"
        mi_log "  copy from scratch; this call has nothing to do."
      else
        local n
        n="${MI_COPY_ENTRIES:-}"
        case "$n" in
          ''|*[!0-9]*)
            mi_warn "migrate: no source-entry count is available to bind verification to the source"
            mi_warn "  (the copy step did not run in this process). Refusing to verify against a count"
            mi_warn "  no step derived."
            return 1 ;;
        esac
        mi_copy_verify "$idx" "$srcvol" "$stage" "$n" "$ruid" "$ouid" || return 1
        mi_copy_host_access_check "$stage" || return 1
        if [ "$ruid" != "$ouid" ]; then
          mi_copy_access_check "$idx" "$stage" "$ruid" || return 1
        fi
      fi
      ;;
    5)
      # Record BEFORE renaming, so a crash after rename() but before advancing is resolvable from the
      # identity rather than from the (now non-empty) destination.
      local prior5 attempt5 desired5 stageid5
      prior5="$(_mi_mig_carry "$rec" prior)" || return 1
      attempt5="$(_mi_mig_carry "$rec" attempt none)" || return 1
      desired5="$(_mi_mig_carry "$rec" desired running)" || return 1
      stageid5="$(_mi_mig_carry "$rec" stageid)" || return 1
      _mi_mig_set "$product" "$role" 5 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior5}" "attempt=${attempt5}" \
        "desired=${desired5}" "mount=${mount}" "stageid=${stageid5}" || return 1

      if [ -z "$stageid5" ]; then
        # NO IDENTITY, NO COMMIT — unless there is provably nothing to protect. A real crash always
        # leaves this identity recorded (phase 3 records it before the copy even starts), so reaching
        # phase 5 with none recorded, from a process that itself never ran phase 3 or 4, is a corrective
        # ledger edit, not a live migration. If something exists at either candidate path it cannot be
        # attributed to this attempt and is left alone; if NOTHING exists anywhere, there is nothing
        # that could be a hostile substitution and nothing legitimate to lose, so the destination is
        # simply put in place empty and the phase advances.
        if [ -e "$stage" ] || [ -e "$dest" ]; then
          mi_warn "migrate: phase 5 has no recorded staging identity, so this process cannot prove the"
          mi_warn "  directory at '$stage' is its own. Refusing to commit it onto '$dest'."
          mi_warn "  Nothing is removed. Re-run to proceed beside it with a fresh nonce."
          return 1
        fi
        mkdir -p -- "$dest" 2>/dev/null || { mi_warn "migrate: cannot create '$dest'"; return 1; }
      else
        local where
        where="$(mi_mig_resolve_phase5 "$dest" "$stage" "$stageid5")" || return 1
        if [ "$where" = staging ]; then
          # AN EMPTY DESTINATION IS RENAMED ONTO; A MISSING ONE TOO — but the rmdir's OWN result
          # decides which of those this is, never an assumption. precheck accepted $dest empty or
          # absent, which an attacker who controls its parent can undo afterward by creating a
          # NON-EMPTY directory (or a symlink to one) there before this phase runs. Discarding rmdir's
          # failure and moving on regardless used to let `mv` silently reinterpret the operation: `mv`
          # treats an EXISTING destination directory as a place to move INTO, not one to replace, so a
          # non-empty $dest would have nested the whole copy one level down (as
          # $dest/<staging's basename>) beside whatever the attacker put there — non-atomic, and wrong
          # in a way nothing afterward would notice. If $dest still exists after rmdir, it is not the
          # empty/absent leaf this migration verified, and this fails closed rather than hand it to
          # `mv`.
          if [ -e "$dest" ]; then
            rmdir -- "$dest" 2>/dev/null
            if [ -e "$dest" ]; then
              mi_warn "migrate: '$dest' is no longer the empty or absent directory this migration"
              mi_warn "  verified — something exists there now that 'rmdir' could not remove (it is not"
              mi_warn "  empty, or is not a directory at all). Refusing to move the copy onto it: doing"
              mi_warn "  so would let 'mv' move it INSIDE whatever is there instead of atomically"
              mi_warn "  replacing it. Nothing was moved; the copy is intact at $stage."
              return 1
            fi
          fi
          mv -- "$stage" "$dest" || {
            mi_warn "migrate: the atomic commit (rename) failed. The copy is intact at $stage; nothing"
            mi_warn "  was destroyed. If the destination is on a different filesystem or is a mount"
            mi_warn "  point, migrate into a subdirectory instead."
            return 1; }
          # AND AFTER THE RENAME, THE RESULT IS VERIFIED TOO — not assumed from `mv`'s own exit status
          # alone. A rename this process just performed should leave $dest carrying exactly the identity
          # that just moved there; if it does not, something about the destination is not what this
          # process believes it just put in place, and continuing to phase 6 (which writes this very
          # path into mythical.conf) over that would commit to it anyway.
          mi_mig_verify_identity "$dest" "$stageid5" "the destination" || return 1
        fi
      fi
      ;;
    6)
      # THE BIND IS WRITTEN BEFORE THE CONTAINER IS REPLACED, not after. D42 builds a container from
      # mythical.conf — so with the write ordered last, the replacement would have recreated the product
      # ON THE NAMED VOLUME IT WAS MIGRATING AWAY FROM, and only then recorded the bind. Configuration
      # precedes the object built from it.
      #
      # THIS PARTICULAR RECORD'S OWN `attempt` FIELD IS READ FROM THE STALE `$rec` — the record as it
      # was BEFORE this call — deliberately: on a fresh entry to phase 6 it still reads "none" (nothing
      # here has touched it yet), and on a RESUMED entry (a crash after this phase's own write below,
      # before the compare-and-set completed) it reads "started" from that crashed attempt's own write.
      # That is exactly the distinction mi_conf_family_cas's third argument needs.
      local prior6 attempt6 desired6 stageid6
      prior6="$(_mi_mig_carry "$rec" prior)" || return 1
      attempt6="$(_mi_mig_carry "$rec" attempt none)" || return 1
      desired6="$(_mi_mig_carry "$rec" desired running)" || return 1
      stageid6="$(_mi_mig_carry "$rec" stageid)" || return 1
      _mi_mig_set "$product" "$role" 6 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior6}" "attempt=started" \
        "desired=${desired6}" "mount=${mount}" "stageid=${stageid6}" || return 1
      mi_conf_family_cas "$key" "$dest" "$prior6" "$attempt6" || return 1
      ;;
    7)
      # PHASE 7 IS A CONTAINER REPLACEMENT, because "switch the mount" is not an operation. Docker
      # mounts are fixed at creation — `docker update` exposes no mount, volume or bind option — so the
      # new container is built by D42's bring-up, the old one is removed and tombstoned, and both are
      # provenance-recorded like any other object.
      local prior7 attempt7 desired7 stageid7
      prior7="$(_mi_mig_carry "$rec" prior)" || return 1
      attempt7="$(_mi_mig_carry "$rec" attempt started)" || return 1
      desired7="$(_mi_mig_carry "$rec" desired running)" || return 1
      stageid7="$(_mi_mig_carry "$rec" stageid)" || return 1
      _mi_mig_set "$product" "$role" 7 "dest=${dest}" "srcvol=${srcvol}" "staging=${stage}" \
        "nonce=${nonce}" "confkey=${key}" "prior=${prior7}" "attempt=${attempt7}" \
        "desired=${desired7}" "mount=${mount}" "stageid=${stageid7}" || return 1
      local netid alias image envfile
      netid="$(mi_net_target "$idx")" || return 1
      alias="$(mi_name_alias "$product")" || return 1
      image="$(mi_manifest_image "$mrec")" || return 1
      # Line by line, never `specs=($(...))`: word-splitting and glob-expanding a bind path is exactly
      # the escape this module exists to prevent.
      local -a specs; specs=()
      local _line _specs
      _specs="$(mi_bringup_specs "$product" "$mrec" "$prec")" || return 1
      while IFS= read -r _line; do
        [ -n "$_line" ] || continue
        specs+=("$_line")
      done <<< "$_specs"
      specs+=("label=product=${product}")
      local -a wanted; wanted=()
      while IFS= read -r v; do [ -n "$v" ] && wanted+=("$v"); done <<< "$(mi_doc_values "$mrec" secret)"
      if [ "${#wanted[@]}" -gt 0 ]; then
        envfile="$(mi_secrets_envfile "$product" "${wanted[@]}")" || return 1
      else
        envfile="-"
      fi
      # §6a: the phase-7 replacement removes the old container, so it must prove ownership first.
      local arc
      if mi_prov_authority container "$c"; then arc=0; else arc=$?; fi
      if [ "$arc" -eq 0 ]; then
        # Tombstone only what was actually removed. A transient removal failure followed by a
        # tombstone strips the old container's authority record while it is still there: recovery then
        # reads it as absent, skips the removal, and cannot create the replacement under the same
        # name — phase 7 stranded, with nothing left that can remove the blocker.
        if ! mi_rt_container_rm "$c" >/dev/null 2>&1; then
          [ "$envfile" = "-" ] || rm -f "$envfile"
          mi_warn "migrate: could not remove the old container '$c'. Its record is kept so it stays"
          mi_warn "  removable; the migration stays at phase 7 and can be resumed."
          return 1
        fi
      elif [ "$arc" -ne 3 ]; then
        [ "$envfile" = "-" ] || rm -f "$envfile"
        mi_warn "migrate: refusing to replace '$c' at phase 7 (see above). The migration stays at"
        mi_warn "  phase 7 with its intent intact and can be resumed once the container is resolved."
        return 1
      fi
      if ! mi_prov_tombstone container "$c"; then
        [ "$envfile" = "-" ] || rm -f "$envfile"
        mi_warn "migrate: could not tombstone the removed container '$c'. The migration stays at phase"
        mi_warn "  7 and can be resumed; run 'mythical-ctl state repair' if a later step reports the"
        mi_warn "  object as already accounted for."
        return 1
      fi
      # `preserve` reads the DESIRED STATE ALREADY RECORDED — the migration must not express intent.
      local brc
      if mi_bringup "$idx" "$c" "$image" "$netid" "$alias" preserve "$envfile" "${specs[@]}"; then brc=0; else brc=$?; fi
      [ "$envfile" = "-" ] || rm -f "$envfile"
      [ "$brc" -eq 0 ] || return 1
      ;;
    8)
      # PHASE 8 CANNOT ASK THE CONTAINER ANYTHING. D42's bring-up leaves a replacement STOPPED when
      # desired state is `stopped`, and D43 forbids starting a product whose desired state is stopped —
      # so "verify the container sees the migrated data" was unreachable for exactly the products most
      # likely to be migrated.
      #
      # Split by what is provable without running: THE DATA was verified host-side at phase 4; THE
      # MOUNT CONFIGURATION is verified by inspection here; and the CONTAINER-SIDE VIEW is not verified
      # at all — the check that would have carried it was removed as unimplementable, because it needs
      # tooling no product image is required to ship. Not deferred, not outstanding, not claimed.
      local mounts canon
      canon="$(mi_canon "$dest")" || return 1
      mounts="$(mi_rt_inspect container c.mounts "$c")" || return 1
      case ";${mounts}" in
        *"|${canon}|${mount}|"*) : ;;
        *) mi_warn "migrate: the replacement container does not mount '$canon' at '$mount'."
           mi_warn "    inspected mounts: $mounts"
           return 1 ;;
      esac
      mi_log "migrate: verified by inspection that $c mounts $canon at $mount."
      mi_log "  The data was verified host-side at phase 4. The container-side read is not verified at all"
      mi_log "  and is not claimed — it would need tooling no product image is required to ship."
      ;;
    9)
      # Clear the intent, reconcile toward the RECORDED desired state, and only NOW may the source
      # volume be removed. Removing it is never automatic: it is the operator's data and the copy is
      # what was just verified, not a substitute for their decision.
      #
      # RESTORE THE DESIRED STATE FIRST, EXPLICITLY, then clear the intent — not because phase 7's own
      # bring-up leaves it wrong (it does not), but because the family lock is released the instant this
      # process crashes, and a crash between phase 7 and phase 9 leaves the migration SUSPENDED (§6b's
      # suspension check) while still letting an operator's plain `stop`/`start` write straight over the
      # desired-state row with no reconciliation to catch it. Restoring from the copy this phase itself
      # captured at phase 1 — rather than trusting whatever the row currently says — is what makes that
      # window safe. And the intent is cleared only after the last thing it authorizes has succeeded: an
      # intent cleared first, followed by a failed restore, would leave nothing recording that the
      # container should still reach its prior state.
      local desired9 netid2 alias2
      desired9="$(_mi_mig_carry "$rec" desired running)" || return 1
      netid2="$(mi_net_target "$idx")" || return 1
      alias2="$(mi_name_alias "$product")" || return 1
      case "$desired9" in
        running) mi_state_commit "$c" running alias "$netid2" || return 1 ;;
        stopped) mi_state_commit "$c" stopped || return 1 ;;
        *) mi_warn "migrate: the recorded desired state '$desired9' for '$c' is neither running nor"
           mi_warn "  stopped — refusing to restore it blindly. Run 'mythical-ctl state repair'."
           return 1 ;;
      esac
      mi_led_del "$MI_MIG_KIND" key "$(_mi_mig_key "$product" "$role")" || return 1
      # Report a failed reconciliation rather than swallowing it: the data has moved and the config
      # names it, so the migration itself succeeded — but a replacement that is not in its recorded
      # desired state is not a finished job.
      if ! mi_bringup_reconcile "$idx" "$c" "$netid2" "$alias2"; then
        mi_warn "migrate: the data has moved and $key names it, but '$c' did not reach its recorded"
        mi_warn "  desired state ($desired9). The migration is complete; the container is not settled."
        mi_warn "  'mythical-ctl status $product' shows what is outstanding."
      fi
      mi_log "migrate: $product/$role now uses the host directory $dest."
      mi_log "  The source volume '$srcvol' is retained. It holds the data as it was before the copy,"
      mi_log "  and removing it is your decision: 'docker volume rm $srcvol' once you are satisfied."
      ;;
  esac
  return 0
}

# Resume every live storage migration from its recorded phase.
mi_mig_resume() {
  if [ "$#" -ne 3 ]; then mi_warn "migrate: mi_mig_resume needs <index> <policy> <manifest-dir-or-file>"; return 1; fi
  local idx="$1" pol="$2" man="$3" recs rc rec product role dest phase p mf stageid srrc

  # CAPTURE AND CHECK FIRST. `done <<< "$(mi_led_all X)"` takes the WHILE loop's status, not the
  # listing's, so a corrupt or ambiguous ledger (rc 1) would be silently read as an EMPTY listing and
  # this would report success having resumed nothing at all.
  if recs="$(mi_led_all "$MI_MIG_KIND")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 0; fi        # no ledger at all: nothing to resume
  if [ "$rc" -ne 0 ]; then
    mi_warn "migrate: the recorded storage migrations could not be fully read, so this cannot see every"
    mi_warn "  migration it must resume. Refusing rather than resuming a partial view of the ledger."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi

  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    # A record that passed the ledger's format/checksum gate can still be missing a SEMANTIC field this
    # verb needs. Fail closed on it rather than silently skipping the migration it describes.
    if ! product="$(mi_led_field "$rec" product)"; then
      mi_warn "migrate: a recorded storage migration does not name a product. Refusing to guess which"
      mi_warn "  one it is. Run 'mythical-ctl state repair'."
      return 1
    fi
    if ! role="$(mi_led_field "$rec" role)"; then
      mi_warn "migrate: the recorded migration for '$product' does not name a role. Run 'mythical-ctl"
      mi_warn "  state repair'."
      return 1
    fi
    if ! dest="$(mi_led_field "$rec" dest)"; then
      mi_warn "migrate: the recorded migration for $product/$role does not name a destination. Run"
      mi_warn "  'mythical-ctl state repair'."
      return 1
    fi
    if ! phase="$(mi_led_field "$rec" phase)"; then
      mi_warn "migrate: the recorded migration for $product/$role does not name a phase. Run"
      mi_warn "  'mythical-ctl state repair'."
      return 1
    fi
    case "$phase" in [1-9]) : ;;
      *) mi_warn "migrate: the recorded migration for $product/$role names phase '$phase', which is not"
         mi_warn "  one this core defines. Run 'mythical-ctl state repair'."
         return 1 ;;
    esac
    # OPTIONAL: absent (rc 3) is legitimate — either no migration has reached phase 3 yet, or (as
    # here) the resume itself has not decided the destination is trustworthy. Anything else is a real
    # read failure and must not be silently treated as "nothing recorded".
    if stageid="$(mi_led_field "$rec" stageid)"; then srrc=0; else srrc=$?; fi
    if [ "$srrc" -eq 3 ]; then stageid=""
    elif [ "$srrc" -ne 0 ]; then
      mi_warn "migrate: the recorded migration for $product/$role could not be fully read (stageid)."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    p="$(mi_mig_resume_phase "$phase" "$dest" "$stageid")" || return 1

    mf="$man"
    [ -d "$man" ] && mf="${man}/${product}.manifest"
    if [ "$p" = "$phase" ]; then
      mi_log "migrate: resuming $product/$role at phase $phase."
    else
      mi_log "migrate: $product/$role recorded phase $phase, but the destination does not verifiably"
      mi_log "  carry phase 5's result. Re-deriving from observable state: resuming at phase $p instead."
    fi
    # A RESUME IS NEVER AUTOMATIC (§5), exactly like the fresh path. Every phase from here to 9 can
    # stop the container, copy data, write mythical.conf or replace the container — the SAME
    # destructive steps a fresh migrate-storage confirms before touching anything — and arriving here
    # through the resume door (a reconciliation sweep, not an operator's own `migrate-storage`
    # invocation) must not skip asking. `mi_confirm` reads MI_CONFIRM the same way every other caller
    # in this codebase does, so a scripted `MI_CONFIRM=yes` still resumes unattended on purpose; what
    # it must not do is resume destructively with NO confirmation input at all.
    mi_warn "migrate: $product/$role is recorded at phase $p and will be resumed — depending on the"
    mi_warn "  phase this stops the container, copies data, writes mythical.conf, or replaces the"
    mi_warn "  container. Never automatic."
    mi_confirm "migrate: resume $product/$role from phase $p?" || {
      mi_warn "migrate: not confirmed. $product/$role stays recorded at phase $phase; nothing was done."
      return 1
    }
    while [ "$p" -le 9 ]; do
      mi_mig_run "$idx" "$pol" "$mf" "$product" "$role" "$dest" "$p" || return 1
      p=$((p + 1))
    done
  done <<< "$recs"
  return 0
}

# --- the verb --------------------------------------------------------------------------------------
mi_verb_migrate_storage() {
  if [ "$#" -lt 5 ]; then
    mi_warn "verbs: migrate-storage needs <index> <policy> <manifest> <product> <role> --to-bind <path>"
    return 2
  fi
  local idx="$1" pol="$2" man="$3" product="$4" role="$5"; shift 5
  local dest="" mapforeign=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --to-bind)
        [ "$#" -ge 2 ] || { mi_warn "verbs: migrate-storage option '--to-bind' requires a value"; return 2; }
        dest="$2"; shift 2 ;;
      --map-foreign-to-operator) mapforeign=1; shift ;;
      *) mi_warn "verbs: unknown migrate-storage option '$1'"; return 2 ;;
    esac
  done
  [ -n "$dest" ] || { mi_warn "verbs: migrate-storage needs --to-bind <path>"; return 2; }
  case "$dest" in /*) : ;; *) mi_warn "verbs: --to-bind needs an absolute path"; return 2 ;; esac

  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_migrate_storage_locked "$idx" "$pol" "$man" "$product" "$role" "$dest" "$mapforeign"
}

_mi_verb_migrate_storage_locked() {
  local idx="$1" pol="$2" man="$3" product="$4" role="$5" dest="$6" mapforeign="$7"
  _mi_verb_prepare || return 1

  if [ "$mapforeign" -eq 1 ]; then MI_MIG_MAP_FOREIGN=1; else unset MI_MIG_MAP_FOREIGN 2>/dev/null || true; fi

  mi_mig_precheck "$idx" "$pol" "$man" "$product" "$role" "$dest" || return 1

  # RESUME-VS-FRESH IS NOT PRECHECK'S TO SIGNAL. It already consulted the one ledger record this
  # decision rests on (to know whether to skip its own emptiness/mountpoint checks for an in-flight
  # destination); asking mi_mig_phase is an ordinary second read of that same record, not a second
  # decision — and it keeps precheck's own contract to one question ("may this proceed at all").
  local p prc
  if p="$(mi_mig_phase "$product" "$role")"; then prc=0; else prc=$?; fi
  case "$prc" in
    3)
      mi_warn "verbs: migrating $product/$role to the host directory '$dest'. This stops the"
      mi_warn "  container, copies the data, writes mythical.conf, and replaces the container to mount"
      mi_warn "  the new location. Never automatic."
      mi_confirm "verbs: migrate $product/$role storage to '$dest'?" || { mi_warn "verbs: not confirmed."; return 1; }
      p=1 ;;
    0)
      case "$p" in [1-9]) : ;;
        *) mi_warn "verbs: the recorded migration phase '$p' for $product/$role is not one this core"
           mi_warn "  defines — refusing to resume it blindly. Run 'mythical-ctl state repair'."
           return 1 ;;
      esac
      # THE RECORDED PHASE IS A WRITE-AHEAD INTENT, VERIFIED BEFORE IT IS TRUSTED — see
      # mi_mig_resume_phase. A phase of 6 or later is only resumed there directly when the destination
      # verifiably carries phase 5's result; otherwise this re-derives the true starting phase (5, where
      # the existing resolve-and-recover logic takes it from there) so the operator is told, and this
      # proceeds from, the phase that will actually run.
      local stageid strc
      if stageid="$(mi_mig_stageid "$product" "$role")"; then strc=0; else strc=$?; fi
      if [ "$strc" -eq 3 ]; then stageid=""
      elif [ "$strc" -ne 0 ]; then
        mi_warn "verbs: the recorded migration for $product/$role could not be fully read (stageid)."
        mi_warn "  Refusing to resume over a ledger this core cannot read. Run 'mythical-ctl state"
        mi_warn "  repair'."
        return 1
      fi
      p="$(mi_mig_resume_phase "$p" "$dest" "$stageid")" || return 1
      # CONFIRMATION COVERS RESUME TOO, NOT ONLY A FRESH START. Depending on the recorded phase,
      # resuming can stop the container, copy data, write mythical.conf, and replace the container —
      # the same destructive steps a fresh migration performs, picked up partway through.
      mi_warn "verbs: a migration of $product/$role to '$dest' is already recorded and will be resumed"
      mi_warn "  from phase $p. This is never automatic."
      mi_confirm "verbs: resume the recorded migration?" || { mi_warn "verbs: not confirmed."; return 1; }
      mi_log "verbs: resuming the in-flight migration of $product/$role at phase $p." ;;
    *) mi_warn "verbs: could not tell whether a migration of $product/$role is already recorded."
       mi_warn "  Refusing rather than guessing. Run 'mythical-ctl state repair'."
       return 1 ;;
  esac
  while [ "$p" -le 9 ]; do
    mi_mig_run "$idx" "$pol" "$man" "$product" "$role" "$dest" "$p" || return 1
    p=$((p + 1))
  done
  return 0
}
