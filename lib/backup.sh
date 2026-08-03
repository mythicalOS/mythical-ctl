#!/usr/bin/env bash
# §6c/D59 — backup and the staging-ledger restore.
#
# COPYING THE DIRECTORY IS NOT A BACKUP (§3a). The named volumes and the product's runtime secrets are
# not in `~/.mythical` at all, and `rm -rf ~/.mythical` leaves every container running. A backup is: the
# tree, the installer state LEDGER, and per volume a contents archive plus its per-entry MANIFEST and its
# recorded NONCE. Refusing to write one without the ledger is the point — a tree-only "backup" is a
# data-loss trap dressed as a feature: it restores a machine that has silently discarded every rollback
# floor and no longer recognizes its own containers.
#
# VOLUME BACKUPS CARRY IDENTITY METADATA, NOT JUST BYTES (D59). Restoring volume *contents* into freshly
# created volumes produces volumes whose nonce labels are absent — so the restored ledger, faithfully
# carried by the same backup, would reject the very volumes the restore just created: every identity
# check fails, every operation preserves-and-stops, and the "restored" installation is wedged by its own
# consistency rules working correctly on inconsistent inputs. Carrying the nonce (and re-labelling on
# create) is what keeps that from happening.
#
# THE STAGING LEDGER IS NON-AUTHORITATIVE (§6c/D59, lib/ledger.sh). A restore writes the incoming ledger
# plus its own intent to `.state/ledger.staging` — same format, same checksum discipline, a distinct
# well-known path beside the real ledger — BEFORE anything is created. D28 permits exactly one
# authoritative ledger; nothing here launches, deletes or reconciles from the staging one, and every
# ordinary command that finds it (with no active ledger) refuses and names it as an in-progress restore,
# never as first use (see mi_first_use, lib/prov.sh — that classification already existed before this
# file; this module is what actually produces and clears the marker it recognises).
#
# PURE library — no side effects at source time; no `set -euo pipefail`.
#
# ARRAY-TYPED LOCALS DECLARED HERE: none. If you add one, see the reserved-name list in lib/copy.sh's own
# header (`args`, `pk`, `pv`, `placed`, `fields`, `triples`, `rtargv`/`rtpost`, `hspecs`, `pairs`, `srcs`,
# `modes`, `bspecs`, `broles`, `ids`, `permitted`, `cspecs`) before picking a new array name.

MI_RESTORE_KIND=restore

# --- shared: a safe location for the operator-named directory ------------------------------------------
# BOTH the backup's OUTPUT directory and the restore's INPUT directory are named by the operator on the
# command line, and both sit on the untrusted side of the SAME TOCTOU class Task 12 (migrate-storage)
# already closed for its own destination: an attacker-writable parent could otherwise be swapped for a
# symlink between this process naming the path and it ever being written to or read from. Bash has no
# fd-relative filesystem operation that would let it re-verify atomically, so — exactly as §5.1's own
# residual note says — the fix is REQUIRING a safe (operator- or root-owned, not group/other-writable)
# location, never trying to out-race a hostile parent with more re-checks.
#
# THIS IS ALSO THE ONLY AUTHENTICATION A BACKUP GETS (codex gate round 1, HIGH). There is no secret to
# sign the tree with, and the ledger's plain sha256 is exactly as recomputable by whoever can write the
# tree as it is by this code — an attacker who can write volumes/V.data can write a mutually consistent
# volumes/V.manifest beside it, and the ledger's own checksum, right along with it. So the checksums
# authenticate INTERNAL CONSISTENCY (the bytes were not damaged after being written), never PROVENANCE
# (that this installer's own backup wrote them) — the same distinction lib/prov.sh draws for the ledger
# itself. What stands in for a signature is LOCATION: if no other party can write anywhere in the
# backup root, no other party can forge the manifest or the data underneath it either, mutually
# consistent or not. See docs/RECOVERY.md's "Trusting a backup" section for the boundary stated in the
# operator's own terms.
#
# REUSED, NOT RE-DERIVED: mi_canon (lib/bringup.sh) and _mi_mig_verify_chain_owner_safe (lib/migrate.sh)
# are migrate-storage's own hardened primitives for exactly this class of problem — a second,
# hand-written copy of either is exactly the kind of drift this codebase's "one implementation of a
# security check" rule exists to prevent.
#
# THE WHOLE CANONICAL PATH IS RESOLVED, LEAF INCLUDED, WHEN IT ALREADY EXISTS. An earlier version of
# this function canonicalized only the PARENT (via migrate's own _mi_mig_canon_dest, built for a
# migration DESTINATION that is expected not to exist yet) and kept the raw leaf name verbatim — so an
# EXISTING backup-directory symlink was never followed, and everything below trusted the alias rather
# than what it actually named. mi_canon on an existing path resolves it fully, following a symlink leaf
# exactly as it already follows one mid-chain; on a leaf that does not exist yet it falls back to
# canonical-parent-plus-name on its own, so one call is correct for both a backup being read and one
# about to be created. Which ANCESTOR CHAIN gets the ownership check then depends on whether anything is
# there yet: a leaf that already exists is checked WHOLE, itself included — an existing backup root that
# is group/other-writable is exactly as forgeable as an unsafe parent, per the note above. A leaf that
# does not exist cannot be stat'd at all, so only its (already-canonical) parent is checked; the leaf
# itself is safe by construction the instant THIS process creates it under a parent nothing else can
# write into.
#
# rc 0 prints the canonical, safety-verified path · 1 refused (reported).
_mi_backup_safe_dir() {
  if [ "$#" -ne 2 ]; then mi_warn "backup: _mi_backup_safe_dir needs a <directory> and <what>"; return 1; fi
  local raw="$1" what="$2" canon
  canon="$(mi_canon "$raw" 2>/dev/null)" || {
    mi_warn "backup: '$raw' does not resolve. Refusing to use it for $what."
    return 1
  }
  if [ -e "$canon" ] || [ -L "$canon" ]; then
    _mi_mig_verify_chain_owner_safe "$canon" "$what" || {
      mi_warn "backup: refusing to use an unsafe location for $what."
      return 1
    }
  else
    _mi_mig_verify_chain_owner_safe "$(dirname -- "$canon")" "the parent of $what" || {
      mi_warn "backup: refusing to use an unsafe location for $what."
      return 1
    }
  fi
  printf '%s\n' "$canon"
}

# Canonicalize <path> AT THE POINT OF USE, refusing unless it resolves to something still inside
# <root> (which must already be canonical — _mi_backup_safe_dir's own output). This is what closes the
# gap between an early existence/type check on a path and the moment it is actually read or bound into
# the copy container (codex gate round 1, HIGH): checking `-L` once and then using the RAW path later
# leaves a window in which a writable-by-nobody-else-but-still-swappable-by-us-in-theory root could, in
# principle, have an entry replaced between the two — canonicalizing immediately before use collapses
# that window to this call itself, the same discipline _mi_backup_safe_dir already applies to the root,
# and the containment check catches a symlink that escapes the root outright rather than trusting
# wherever it leads.
_mi_backup_canon_under() {
  if [ "$#" -ne 3 ]; then mi_warn "backup: _mi_backup_canon_under needs a <path> <root> <what>"; return 1; fi
  local p="$1" root="$2" what="$3" canon
  canon="$(mi_canon "$p" 2>/dev/null)" || {
    mi_warn "restore: $what does not resolve. Refusing to use it."
    return 1
  }
  case "$canon" in
    "$root"|"$root"/*) : ;;
    *)
      mi_warn "restore: $what resolves to '$canon', which is OUTSIDE the verified backup root ('$root')."
      mi_warn "  Refusing — a symlink escaping the root cannot be trusted."
      return 1 ;;
  esac
  printf '%s\n' "$canon"
}

# EACH VOLUME'S REAL, DECLARED runtime_uid — resolved the SAME way lib/migrate.sh's own
# _mi_mig_run_body does (mi_accept_manifest, then mi_manifest_runtime_uid), never a fixed stand-in
# (codex gate round 1, HIGH). A product declaring `runtime_uid=900` owns its files as uid 900:
# treating every volume as if it belonged to uid 0 made backup refuse files genuinely owned by the
# product (foreign to the assumed (0, operator) pair) and made restore grant ownership to uid 0 —
# leaving the product unable to read the data it was just given back. That is D59 restated at the
# ownership layer, not a simplification.
#
# The manifest is loaded through the FULL authenticated chain — index, policy and trust, exactly like
# every other mi_accept_manifest caller — never a bare parse: runtime_uid decides who owns copied
# files, so it has to come from a document this installation actually vouches for, not merely one that
# happens to parse. rc 0 prints the uid · 1 refused (reported) — a volume whose product cannot be
# authenticated, or whose manifest declares no runtime_uid, refuses rather than guessing 0.
_mi_backup_runtime_uid() {
  if [ "$#" -ne 5 ]; then
    mi_warn "backup: _mi_backup_runtime_uid needs <index> <policy> <manifest-dir> <product> <volume>"
    return 1
  fi
  local idx="$1" pol="$2" mdir="$3" product="$4" vol="$5" manfile mrec ruid
  manfile="${mdir}/${product}.manifest"
  mrec="$(mi_accept_manifest "$idx" "$pol" "$manfile" "$product")" || {
    mi_warn "backup: could not authenticate the manifest for product '$product' (volume '$vol') —"
    mi_warn "  refusing to guess its runtime uid."
    return 1
  }
  ruid="$(mi_manifest_runtime_uid "$mrec")" || {
    mi_warn "backup: the manifest for product '$product' (volume '$vol') declares no runtime_uid —"
    mi_warn "  refusing to guess it."
    return 1
  }
  printf '%s\n' "$ruid"
}

# --- backup manifest --------------------------------------------------------------------------------
# THE BACKUP MANIFEST AUTHENTICATES THE CONTRACT, NOT JUST THE BYTES. Per-file digests alone let a
# restore verify "success" while silently losing everything D57/D58 promise: a symlink re-created as a
# file has no bytes to mismatch, flattened hardlinks digest identically, and dropped modes or ownership
# are invisible to a content hash alone.
#
# So the manifest records, per entry: TYPE, and per type — content digest (regular files), the verbatim
# link target (symlinks, length-delimited exactly like lib/copy.sh's own linktarget=, and read back the
# same way — one definition, reused), hardlink grouping, mode, ownership and mtime. It is produced by the
# SAME pinned copy container that reads the volume for the backup's contents archive (the host cannot
# read a named volume at all — D54), through a new `verify --manifest` mode of the existing closed
# command word (new command ARGUMENTS, per D49 — never a new command).
mi_backup_manifest_write() {
  if [ "$#" -ne 3 ]; then mi_warn "backup: mi_backup_manifest_write needs <index> <volume> <out>"; return 1; fi
  local idx="$1" vol="$2" out="$3" transcript rc tmp doneval
  mi_copy_available "$idx" || return 1
  if transcript="$(_mi_copy_helper "$idx" verify "arg=/src" "arg=--manifest" "srcvol=${vol}" 2>/dev/null)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "backup: could not enumerate volume '$vol' for its manifest — the backup is NOT written."
    return 1
  fi
  _mi_copy_grammar_ok "$transcript" manifest digest linktarget mode owner mtime hardlink "done" || {
    mi_warn "backup: the manifest transcript for volume '$vol' is not well-formed — the backup is NOT"
    mi_warn "  written."
    return 1
  }
  doneval="$(_mi_copy_stated "$transcript" "done" "backup manifest" "completion")" || return 1
  if [ "$doneval" != ok ]; then
    mi_warn "backup: the manifest helper for volume '$vol' did not report completion (done=${doneval:-<empty>})."
    mi_warn "  The backup is NOT written."
    return 1
  fi
  tmp="$(mktemp "${out}.XXXXXX")" || return 1
  if ! printf '%s\n' "$transcript" > "$tmp"; then
    rm -f "$tmp"
    mi_warn "backup: cannot write the manifest for volume '$vol'"
    return 1
  fi
  mv -f "$tmp" "$out" || { rm -f "$tmp"; mi_warn "backup: cannot install the manifest for volume '$vol'"; return 1; }
}

# --- backup -----------------------------------------------------------------------------------------
mi_backup_run() {
  if [ "$#" -ne 4 ]; then
    mi_warn "backup: mi_backup_run needs an <index file>, a <policy file>, a <manifest dir> and an"
    mi_warn "  <output directory>"
    return 1
  fi
  local idx="$1" pol="$2" mdir="$3" rawdir="$4" dir lf

  dir="$(_mi_backup_safe_dir "$rawdir" "the backup output directory")" || return 1

  lf="$(_mi_ledger_path)"
  if [ ! -f "$lf" ]; then
    mi_warn "backup: there is no installer state ledger to back up."
    mi_warn "  Refusing to write a backup without it: restoring the tree alone would give you a machine"
    mi_warn "  that has silently discarded every rollback floor and no longer recognizes its own"
    mi_warn "  containers."
    return 1
  fi
  mi_ledger_read >/dev/null || {
    mi_warn "backup: the ledger does not validate. Refusing to capture state we cannot read."; return 1; }

  mkdir -p -- "$dir/volumes" || { mi_warn "backup: cannot create '$dir'"; return 1; }
  cp -- "$lf" "$dir/ledger" || { mi_warn "backup: cannot capture the ledger"; return 1; }

  # --- the tree, excluding the ephemeral lock and the ledger (captured separately, above) -----------
  # RESTORING A STALE LOCK WEDGES THE FIRST OPERATION AFTER A RESTORE, and the lock is not ledger
  # content: it is ephemeral, lives beside the ledger, and is never backed up. The ledger and any
  # staging ledger are excluded here too — they are captured through their own authoritative paths
  # (`$dir/ledger` above; a staging one is never legitimate to carry forward at all, see mi_restore_run's
  # `active`/`staging-*` refusals), so a second, generic copy under `tree/.state/` would just be a
  # confusing duplicate for a future restore to reason about.
  #
  # NUL-DELIMITED, READ FROM A FILE, RC CHECKED EXPLICITLY (the same discipline lib/migrate.sh's own
  # escaping-symlink re-walk uses, for the identical reason): `find | while read` without `pipefail`
  # reports the WHILE loop's status, so a `find` that failed partway through an unreadable subdirectory
  # would silently look like "walked the whole tree and found nothing else" rather than "did not finish".
  local h tmp frc
  h="$(mi_home)" || return 1
  tmp="$(mktemp "$dir/.tree-list.XXXXXX")" || { mi_warn "backup: cannot list the installer home"; return 1; }
  ( cd "$h" && find . -mindepth 1 \
        \( -path './.state/lock' -o -path './.state/lock.*' \
           -o -path './.state/ledger' -o -path './.state/ledger.staging' \) -prune \
        -o -print0 ) > "$tmp"
  frc=$?
  if [ "$frc" -ne 0 ]; then
    rm -f "$tmp"
    mi_warn "backup: could not fully walk the installer home ($h) — refusing a partial tree."
    return 1
  fi
  # The temp file is removed ONCE, after this loop fully exits — never from inside it, while the
  # redirect below still has it open for reading (the same discipline lib/migrate.sh's own
  # escaping-symlink re-walk uses; see mi_mig_verify_no_escaping_symlinks). A failure sets $failed and
  # `break`s instead of returning directly.
  #
  # EVERY TEST AND READ IS AGAINST THE ABSOLUTE PATH ("$h/$rel"), NEVER THE RELATIVE ONE `find` PRINTED
  # ("./x"). `find` ran inside a `( cd "$h" && … )` subshell so its OWN cwd was $h — that `cd` does not
  # survive past the subshell, so testing the bare relative path here (in THIS function's own cwd,
  # whatever it happens to be) answered every `-L`/`-d`/`-f` question about the WRONG location. `$rel`
  # is kept only to name the destination under `$dir/tree/`.
  local p rel abs tgt failed=0
  while IFS= read -r -d '' p; do
    [ -n "$p" ] || continue
    rel="${p#./}"
    [ -n "$rel" ] || continue
    abs="$h/$rel"
    if [ -L "$abs" ]; then
      if ! tgt="$(readlink -- "$abs")"; then
        mi_warn "backup: cannot read symlink target for '$rel'"; failed=1; break
      fi
      if ! mkdir -p -- "$(dirname -- "$dir/tree/$rel")"; then failed=1; break; fi
      if ! ln -s -- "$tgt" "$dir/tree/$rel"; then
        mi_warn "backup: cannot recreate symlink '$rel'"; failed=1; break
      fi
    elif [ -d "$abs" ]; then
      if ! mkdir -p -- "$dir/tree/$rel"; then failed=1; break; fi
    elif [ -f "$abs" ]; then
      if ! mkdir -p -- "$(dirname -- "$dir/tree/$rel")"; then failed=1; break; fi
      if ! cp -p -- "$abs" "$dir/tree/$rel"; then
        mi_warn "backup: cannot copy '$rel'"; failed=1; break
      fi
    else
      mi_warn "backup: '$rel' is not a regular file, directory or symlink — skipped (not product data)."
    fi
  done < "$tmp"
  rm -f "$tmp"
  [ "$failed" -eq 0 ] || return 1

  # --- every named volume: contents, per-entry manifest, and its recorded nonce ----------------------
  local records lrc rec name nonce product ruid
  if records="$(mi_led_all object)"; then lrc=0; else lrc=$?; fi
  if [ "$lrc" -ne 0 ]; then
    mi_warn "backup: the installer state ledger's object records could not be listed in full — refusing"
    mi_warn "  a backup that would silently omit some of them."
    return 1
  fi
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class volume || continue
    # FAIL CLOSED ON A MISSING REQUIRED FIELD, NEVER SKIP PAST IT (codex gate round 1, MEDIUM). A
    # record can pass the checksum and _mi_led_record_matches's own well-formedness gate — every
    # token is a valid key=value field — and still be semantically incomplete: `object` with
    # `class=volume` but no `name=` or no `nonce=`. `|| continue` treated that the same as "this
    # record is not a volume" and moved on, so a backup could OMIT a ledger-declared volume with no
    # trace that anything was skipped — a silent partial backup. The record itself is named in the
    # refusal because there is no volume name to name it by.
    name="$(mi_led_field "$rec" name)" || {
      mi_warn "backup: a 'volume' object record carries no name — refusing rather than silently"
      mi_warn "  omitting a ledger-declared volume from the backup. Record: ${rec:-<empty>}"
      return 1
    }
    nonce="$(mi_led_field "$rec" nonce)" || {
      mi_warn "backup: the record for volume '$name' carries no nonce — refusing rather than silently"
      mi_warn "  omitting it from the backup."
      return 1
    }
    product="$(mi_led_field "$rec" product)" || {
      mi_warn "backup: the record for volume '$name' carries no product — refusing rather than"
      mi_warn "  guessing which manifest declares its runtime uid."
      return 1
    }
    ruid="$(_mi_backup_runtime_uid "$idx" "$pol" "$mdir" "$product" "$name")" || return 1
    printf '%s\n' "$nonce" > "$dir/volumes/${name}.nonce" || return 1
    mi_backup_manifest_write "$idx" "$name" "$dir/volumes/${name}.manifest" || return 1
    mkdir -p -- "$dir/volumes/${name}.data" || return 1
    mi_copy_run "$idx" "$name" "$dir/volumes/${name}.data" "$ruid" "$(id -u)" || return 1
    mi_log "backup: captured volume $name (contents, per-entry manifest, and its nonce)."
  done <<< "$records"

  mi_log "backup: written to $dir."
  mi_log "  It contains the ledger, the tree, and every named volume's contents WITH its identity"
  mi_log "  metadata. Restoring contents alone would create volumes with no nonce labels, which the"
  mi_log "  restored ledger would then reject — the installation would be wedged by its own consistency"
  mi_log "  rules working correctly on inconsistent inputs."
  return 0
}

# --- restore ----------------------------------------------------------------------------------------
# §6b's first-use rule gains a THIRD column (lib/prov.sh's mi_first_use already implements the read side
# of this): no active ledger BUT a staging one present is neither first use nor inconsistent — it is an
# in-progress restore. This function classifies it for the restore verb itself.
#
# Prints: none | staging-with-intent | staging-no-intent | staging-corrupt | active
mi_restore_state() {
  local lf sf
  lf="$(_mi_ledger_path)"; sf="$(_mi_ledger_staging_path)"
  if [ -f "$lf" ]; then printf 'active\n'; return 0; fi
  [ -f "$sf" ] || { printf 'none\n'; return 0; }
  if ! mi_ledger_staging_read >/dev/null 2>&1; then printf 'staging-corrupt\n'; return 0; fi
  if _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_find "$MI_RESTORE_KIND" key restore >/dev/null 2>&1; then
    printf 'staging-with-intent\n'
  else
    printf 'staging-no-intent\n'
  fi
}

# The six phases (§6c):
#
#   1  write the staging ledger, restore intent inside it (host-side, before anything is created)
#   2  per volume: create WITH the recorded nonce label — then RE-INSPECT: the nonce must be present and
#      the volume EMPTY. `docker volume create` against an existing name returns the existing volume
#      WITHOUT applying the label (verified), so a same-name survivor fails one of the two checks and the
#      restore REFUSES, naming it — never fills a volume it cannot prove it just created
#   3  fill, via the pinned copy container — the REVERSE of an ordinary copy's direction (host backup
#      data, read-only, into the volume being filled): mi_copy_fill, not mi_copy_run
#   4  verify contents against the PER-ENTRY manifest the backup carries, not bytes alone
#   5  only when EVERY volume verifies: atomically rewrite the staging ledger to its final, intent-free
#      form — this is the ready-to-activate state
#   6  ACTIVATE — atomically rename the staging ledger into the ledger path. Until this step the machine
#      has no ACTIVE ledger claiming these volumes, so nothing launches them
#
# PHASE 5 EXISTS BECAUSE THE INTENT LIVES INSIDE THE FILE BEING ACTIVATED. Renaming the staging ledger
# unchanged would activate a ledger that still says a restore is in progress — every subsequent command
# meeting a live intent on a completed restore. So the intent is removed by an atomic rewrite FIRST, and
# the two staging states are recovery's dispatch: staging WITH an intent ⇒ resume the phases; staging
# WITHOUT one (and checksum-valid) ⇒ phase 5 completed, activate.
#
# LABEL-FIRST ALONE creates the opposite hazard from contents-only: a crash DURING filling leaves a
# volume that passes every identity check while holding PARTIAL contents, and a restored ledger would let
# ordinary reconciliation launch the product on half its data. Identity must not authenticate contents
# that are not there yet — which is why activation is last.
mi_restore_run() {
  if [ "$#" -ne 4 ]; then
    mi_warn "restore: mi_restore_run needs an <index file>, a <policy file>, a <manifest dir> and a"
    mi_warn "  <backup directory>"
    return 1
  fi
  local idx="$1" pol="$2" mdir="$3" rawdir="$4" st sf

  sf="$(_mi_ledger_staging_path)"
  st="$(mi_restore_state)"

  case "$st" in
    active)
      # RESTORE REQUIRES THAT NO ACTIVE LEDGER EXISTS — it is a RECOVERY operation, not a replacement.
      # On a machine with a live installation, restore would create its volumes beside the running
      # ones and phase 5 would atomically replace the live ledger — ORPHANING EVERY RUNNING CONTAINER
      # of the current installation in one rename, with its provenance gone.
      mi_warn "restore: an active installer state ledger is present:"
      mi_warn "    $(_mi_ledger_path)"
      mi_warn "  Refusing. Activating a restored ledger would orphan every running container of the"
      mi_warn "  installation that is here now — their provenance would be gone in one rename."
      mi_warn "  Replacing a live installation with a backup is a deliberately destructive operation that"
      mi_warn "  must be designed as one. Uninstall first, or wait for an explicit 'restore --replace'"
      mi_warn "  with its own safeguards. It is NOT a side effect a recovery verb may have."
      return 1 ;;
    staging-corrupt)
      # A CORRUPT STAGING LEDGER CANNOT AUTHORIZE CLEANUP — its contents are exactly what the checksum
      # says not to trust.
      local aside="${sf}.corrupt.$$"
      mv -f "$sf" "$aside" || { mi_warn "restore: cannot preserve the corrupt staging ledger"; return 1; }
      mi_warn "restore: the staging ledger does not validate. It has been PRESERVED at $aside."
      mi_warn "  It authorizes nothing: the record of which partial volumes a previous attempt created is"
      mi_warn "  exactly what the checksum says not to trust."
      mi_warn "  Any partial volumes from that attempt are PRESERVED and are BLOCKING a fresh restore."
      mi_warn "  Removing them is your explicit call — the installer cannot prove they are its own."
      _mi_restore_report_blocking
      return 1 ;;
  esac

  # EVERY REMAINING BRANCH DOES SOMETHING DESTRUCTIVE — creates and fills volumes, or activates the
  # incoming ledger in place of the (absent) active one — so it is gated HERE, ONCE, covering all
  # three (a fresh start, a resume, and the activate-only "staging-no-intent" case) before any of them
  # runs, exactly as migrate-storage and uninstall gate their own destructive verbs (codex gate round
  # 1, HIGH: `MI_CONFIRM=no mythical-ctl restore BACKUP` used to create, fill and activate with no
  # confirmation at all — mi_confirm was called only by abandon). `active`/`staging-corrupt` above are
  # pure refusals — nothing is touched — so they return before this gate, never through it.
  case "$st" in
    none)
      mi_confirm "restore: restore from '${rawdir}' — creates and fills named volumes under their recorded identity, then activates the incoming ledger?" \
        || { mi_warn "restore: not confirmed."; return 1; } ;;
    *)
      mi_confirm "restore: resume the in-progress restore and activate it once every volume verifies?" \
        || { mi_warn "restore: not confirmed."; return 1; } ;;
  esac

  case "$st" in
    staging-no-intent)
      mi_log "restore: a completed restore is ready to activate. Activating."
      mi_ledger_staging_activate
      return $? ;;
    staging-with-intent)
      mi_log "restore: resuming the in-progress restore." ;;
    none)
      local dir ledgercanon
      dir="$(_mi_backup_safe_dir "$rawdir" "the backup directory")" || return 1
      [ -d "$dir" ] || { mi_warn "restore: '$dir' is not a backup directory"; return 1; }
      # Canonicalized AT THE POINT OF USE, immediately before the read that trusts it — not checked
      # once here and read via the raw path later, which is exactly the window a writable-by-nobody-
      # else root still leaves between a `-L` check and the `cp` that follows it.
      ledgercanon="$(_mi_backup_canon_under "$dir/ledger" "$dir" "the backup's ledger")" || return 1
      if [ ! -f "$ledgercanon" ]; then
        mi_warn "restore: '$dir' carries no ledger (or it is not a plain file). A backup without one"
        mi_warn "  cannot support a verified restore — it would rebuild a machine with no rollback"
        mi_warn "  floors and no provenance."
        return 1
      fi
      # Phase 1: the staging ledger IS the incoming ledger, with the intent written inside it.
      cp -- "$ledgercanon" "$sf" || { mi_warn "restore: cannot stage the incoming ledger"; return 1; }
      mi_ledger_staging_read >/dev/null || {
        mi_warn "restore: the incoming ledger does not validate — refusing to stage it."
        rm -f "$sf"
        return 1
      }
      _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_put "$MI_RESTORE_KIND" key restore \
        "key=restore" "phase=2" "source=${dir}" "volumes=" || return 1 ;;
  esac

  # From here on, EVERY path (a fresh 'none' start and a resumed 'staging-with-intent') reads its
  # source directory back OUT OF THE STAGING LEDGER'S OWN INTENT RECORD, never re-trusts the raw
  # operand a second time — a resume is not handed $rawdir/$dir at all (mi_verb_restore's dispatch does
  # not even require one), and using the CLI argument here (were it present) rather than the recorded
  # value would let a resume silently read a DIFFERENT directory than the one phase 1 committed to.
  local irec dir
  irec="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_find "$MI_RESTORE_KIND" key restore)" || {
    mi_warn "restore: the staging ledger carries no restore intent to resume."
    return 1
  }
  dir="$(mi_led_field "$irec" source)" || {
    mi_warn "restore: the staging ledger's restore intent names no source directory."
    return 1
  }

  # RE-AUTHENTICATE THE BACKUP ROOT AT THE POINT OF USE, on EVERY entry INCLUDING RESUME (codex gate
  # round 2, HIGH). Phase 1 checked this location, but a crash-and-resume can span an attacker making
  # the backup root group-writable and swapping its in-root V.data/V.manifest in between; the
  # fresh-restore path's own safety comes from this same _mi_backup_safe_dir call, so a resume must
  # re-run it now rather than trust the phase-1 result over the location's state at this instant. The
  # re-verified CANONICAL path is what every read and mount below uses.
  dir="$(_mi_backup_safe_dir "$dir" "the backup directory being restored")" || return 1

  # The staging ledger's OWN installation identity — the original installation's, carried faithfully
  # by the backup — is what every volume this restore creates must be labelled with. Read ONCE, before
  # the per-volume loop, from the staged ledger, never from mi_ident_get (which answers for whatever
  # ACTIVE ledger this machine has — none, by construction, while a restore is in progress).
  local ident irc
  if ident="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_ident_get)"; then irc=0; else irc=$?; fi
  if [ "$irc" -ne 0 ]; then
    mi_warn "restore: the staging ledger's own installation identity cannot be read — refusing to"
    mi_warn "  create volumes under an identity this process cannot establish."
    return 1
  fi

  # Phases 2–4, per volume, driven by the staging ledger's own volume records — read ONCE, rc checked:
  # `done <<< "$(...)"` swallows a failed listing as an EMPTY one, which would silently skip every
  # volume rather than refuse.
  local recs lrc rec name nonce actual arc empty src datacanon mancanon product ruid
  if recs="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_all object)"; then lrc=0; else lrc=$?; fi
  if [ "$lrc" -ne 0 ]; then
    mi_warn "restore: the staging ledger's object records could not be listed in full — refusing to"
    mi_warn "  proceed on a partial view of which volumes this restore is responsible for."
    return 1
  fi
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class volume || continue
    name="$(mi_led_field "$rec" name)" || {
      mi_warn "restore: a 'volume' object record in the staging ledger carries no name — refusing rather"
      mi_warn "  than silently skipping past a ledger-declared volume this restore would otherwise omit."
      mi_warn "  Record: ${rec:-<empty>}"
      return 1
    }
    nonce="$(mi_led_field "$rec" nonce)" || {
      mi_warn "restore: the record for volume '$name' carries no nonce — refusing rather than silently"
      mi_warn "  skipping past a ledger-declared volume this restore would otherwise omit."
      return 1
    }
    product="$(mi_led_field "$rec" product)" || {
      mi_warn "restore: the record for volume '$name' carries no product — refusing rather than"
      mi_warn "  guessing which manifest declares its runtime uid."
      return 1
    }
    # Same authenticated-manifest resolution as backup's own loop, and under the SAME staging-ledger
    # override as every other trust-chain read during a restore (see the note a few lines below on
    # mi_copy_available/mi_accept_index) — mi_accept_manifest reaches mi_accept_index/mi_accept_policy
    # too, and the anchor those check lives in the ledger.
    ruid="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" _mi_backup_runtime_uid "$idx" "$pol" "$mdir" "$product" "$name")" || return 1
    src="${dir}/volumes/${name}"
    # CANONICALIZED AT THE POINT OF USE, immediately before the fill/verify calls below that trust
    # them — never checked once here and read via the raw path later. See _mi_backup_canon_under's own
    # header for why that gap matters even inside an already-verified-safe root.
    datacanon="$(_mi_backup_canon_under "${src}.data" "$dir" "the backup's contents for volume '$name'")" || return 1
    if [ ! -d "$datacanon" ]; then
      mi_warn "restore: the backup has no contents directory for volume '$name' (or it is not a plain"
      mi_warn "  directory)."
      return 1
    fi
    mancanon="$(_mi_backup_canon_under "${src}.manifest" "$dir" "the backup's manifest for volume '$name'")" || return 1
    if [ ! -f "$mancanon" ]; then
      mi_warn "restore: the backup has no per-entry manifest for volume '$name'."
      mi_warn "  A backup without one cannot support verified restore — this backup was not written by"
      mi_warn "  a version that captures one."
      return 1
    fi

    # Phase 2, then RE-INSPECT.
    mi_rt_volume_create "$name" "$nonce" "$ident" >/dev/null || return 1
    if actual="$(mi_rt_inspect volume v.nonce "$name" 2>/dev/null)"; then arc=0; else arc=$?; fi
    if [ "$arc" -eq 1 ]; then
      mi_warn "restore: could not verify volume '$name' — the container runtime did not answer. The"
      mi_warn "  intent is retained so a re-run converges once the runtime is reachable."
      return 1
    fi
    if [ "$actual" != "$nonce" ]; then
      mi_warn "restore: a volume named '$name' already exists and does not carry the recorded nonce."
      mi_warn "    recorded: $nonce"
      mi_warn "    found:    ${actual:-<none>}"
      mi_warn "  Refusing. 'volume create' against an existing name succeeds and does NOT apply the"
      mi_warn "  new label, so this is a SURVIVOR, not the volume we just created — and the restore"
      mi_warn "  never fills a volume it cannot prove it created."
      return 1
    fi
    # EVERY CALL BELOW THAT MAY REACH mi_copy_available/mi_accept_index IS MADE UNDER THE STAGING
    # LEDGER, NOT THE (ABSENT) ACTIVE ONE. mi_accept_index authenticates the family index against the
    # recorded trust anchor (mi_trust_anchor_get) — and that anchor lives IN THE LEDGER (mi_ledger_get),
    # exactly like every other trust fact. A restore runs with NO active ledger by definition (mi_restore_
    # state's `active` case already refuses otherwise), so without this override every one of these calls
    # would fail "no family-index anchor has been recorded" on precisely the machine a restore is
    # rebuilding — even though the anchor the backup's OWN installation established is sitting right here,
    # in the ledger this restore just staged. Verifying the index against THAT anchor (carried faithfully
    # by the backup, exactly like every other trust fact) is correct: it is the same trust history the
    # original installation already had, not a fresh one this machine has to re-earn. Any trust-floor
    # ADVANCE mi_accept_index performs as a side effect (mi_trust_commit) lands in the staging ledger too,
    # which is exactly where it belongs until activation carries it forward.
    empty="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" _mi_restore_volume_empty "$idx" "$name")" || return 1
    if [ "$empty" = yes ]; then
      # Phase 3: fill, via the pinned copy container — HOST BACKUP DATA (read-only) into the VOLUME
      # (writable). The reverse of mi_copy_run's direction (see lib/copy.sh's mi_copy_fill). $datacanon,
      # never ${src}.data: the raw path was only ever good for the existence/type check above.
      _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_copy_fill "$idx" "$datacanon" "$name" "$ruid" "$(id -u)" || return 1
      # Phase 4: against THE MANIFEST'S contract, not bytes alone.
      _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" _mi_restore_verify "$idx" "$name" "$mancanon" || return 1
      mi_log "restore: volume $name filled and verified against the backup's per-entry manifest."
    else
      # NOT EMPTY is not automatically a survivor to refuse: RESUME IS STATE-VERIFYING, NOT
      # PHASE-TRUSTING (the same discipline lib/migrate.sh's own resume applies). Re-running these
      # phases from the top on every resume — the simplest correct thing to do, since phases 2-4 have
      # no other durable per-volume marker — means a crash while filling volume B, with volume A
      # already filled and verified in this SAME attempt, must find A non-empty and NOT treat that as
      # a foreign survivor. The distinguishing fact is whether it verifies against OUR manifest: if it
      # does, this volume is already done and the loop moves on; if it does not, it genuinely holds
      # partial contents from an interrupted fill (or is a real survivor), and there is no safe way to
      # tell those apart except refusing and pointing at abandonment.
      if _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" _mi_restore_verify "$idx" "$name" "$mancanon"; then
        mi_log "restore: volume $name already filled and verified (resumed)."
      else
        mi_warn "restore: volume '$name' carries our nonce but is NOT EMPTY and does not verify against"
        mi_warn "  the backup's manifest — it holds partial contents from an interrupted attempt."
        mi_warn "  Resuming would fill over them blindly. Abandon the restore ('restore --abandon') so"
        mi_warn "  the partial volumes are removed under their recorded identity, then start again."
        return 1
      fi
    fi
  done <<< "$recs"

  # Phase 5: the intent-free rewrite, atomically.
  _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_del "$MI_RESTORE_KIND" key restore || return 1
  mi_log "restore: every volume verified. The staging ledger is now intent-free and ready to activate."

  # Phase 6.
  mi_ledger_staging_activate
}

# Activate: ONE atomic rename. Until this instant the machine has no active ledger claiming these
# volumes, so nothing can start the product on them.
mi_ledger_staging_activate() {
  local sf lf
  sf="$(_mi_ledger_staging_path)"; lf="$(_mi_ledger_path)"
  mi_ledger_staging_read >/dev/null || {
    mi_warn "restore: the staging ledger does not validate — refusing to activate it."; return 1; }
  # rc 0 = a live restore intent is still recorded (restore not finished) → refuse. rc 3 = the intent
  # is genuinely GONE (the restore cleared it) → the only case that may activate. Any other rc = the
  # intent read FAILED (rc 1, ambiguous/unreadable) — FAIL CLOSED, never fold a reader failure into
  # "absent" and atomically activate a ledger that may still record an unfinished restore (codex gate
  # round 2, HIGH; the rc-3-vs-rc-1 rule this codebase applies everywhere).
  local frc
  if _MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_find "$MI_RESTORE_KIND" key restore >/dev/null 2>&1; then frc=0; else frc=$?; fi
  if [ "$frc" -eq 0 ]; then
    mi_warn "restore: the staging ledger still carries a live restore intent — refusing to activate."
    mi_warn "  Activating it would leave every later command meeting an in-progress restore that has"
    mi_warn "  finished."
    return 1
  elif [ "$frc" -ne 3 ]; then
    mi_warn "restore: whether the staging ledger still carries a live restore intent could not be"
    mi_warn "  established — the intent read failed. Refusing to activate rather than risk activating a"
    mi_warn "  ledger that still records an unfinished restore."
    return 1
  fi
  [ ! -f "$lf" ] || { mi_warn "restore: an active ledger appeared — refusing to overwrite it"; return 1; }
  mv -f "$sf" "$lf" || { mi_warn "restore: activation failed"; return 1; }
  mi_log "restore: activated. The installation is live again."
  return 0
}

# ABANDONMENT CLEANS UP BEFORE DESTROYING ITS OWN AUTHORITY. The staging ledger is the only record
# proving which partial volumes the restore created — deleting it first leaves nonce-labelled,
# non-empty volumes that a restarted restore then meets as same-name survivors and REFUSES, with no
# authoritative record left to remove them: a wedge built from two correct rules.
mi_restore_abandon() {
  local sf st recs lrc rec name nonce actual
  sf="$(_mi_ledger_staging_path)"
  st="$(mi_restore_state)"
  case "$st" in
    none) mi_warn "restore: there is no in-progress restore to abandon."; return 1 ;;
    active) mi_warn "restore: this machine has an active ledger; there is no restore in progress."; return 1 ;;
    staging-corrupt)
      # THE SAME PRESERVE-ASIDE mi_restore_run's OWN staging-corrupt branch performs — one behaviour
      # for one fact, whichever verb the operator reached it through. Leaving the corrupt file in
      # place here (as an earlier version of this function did) while mi_restore_run moved it aside
      # would mean the SAME corrupt ledger is preserved as forensic evidence on one path and left
      # sitting at the well-known name on the other, for no reason tied to what actually happened.
      local aside="${sf}.corrupt.$$"
      mv -f "$sf" "$aside" || { mi_warn "restore: cannot preserve the corrupt staging ledger"; return 1; }
      mi_warn "restore: the staging ledger does not validate. It has been PRESERVED at $aside."
      mi_warn "  It authorizes no cleanup: the record of which partial volumes a previous attempt"
      mi_warn "  created is exactly what the checksum says not to trust."
      _mi_restore_report_blocking
      return 1 ;;
  esac
  mi_warn "restore: abandoning the in-progress restore."
  mi_warn "  Volumes this restore created — matching the EXACT name and nonce it recorded — are removed"
  mi_warn "  first. Anything that does not match is preserved and reported."
  mi_confirm "restore: abandon it?" || { mi_warn "restore: not confirmed."; return 1; }

  if recs="$(_MI_LEDGER_STAGING_INTERNAL=1 MI_LEDGER_PATH_OVERRIDE="$sf" mi_led_all object)"; then lrc=0; else lrc=$?; fi
  if [ "$lrc" -ne 0 ]; then
    mi_warn "restore: the staging ledger's object records could not be listed in full — refusing to"
    mi_warn "  abandon on a partial view of which volumes this restore created."
    return 1
  fi
  local irc failed=0
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class volume || continue
    # FAIL CLOSED, not `|| continue`: a volume record missing its own name/nonce is exactly the same
    # semantically-incomplete-but-checksum-valid case backup and restore's fill loops refuse — see the
    # note in mi_backup_run. Abandoning on a partial view could leave a ledger-declared volume neither
    # removed nor reported as preserved.
    name="$(mi_led_field "$rec" name)" || {
      mi_warn "restore: a 'volume' object record in the staging ledger carries no name — refusing to"
      mi_warn "  abandon on a partial view of it. Record: ${rec:-<empty>}"
      return 1
    }
    nonce="$(mi_led_field "$rec" nonce)" || {
      mi_warn "restore: the record for volume '$name' carries no nonce — refusing to abandon on a"
      mi_warn "  partial view of it."
      return 1
    }
    # rc 3 (absent) and rc 1 (daemon could not be asked) are NOT the same fact: absence means nothing
    # to remove; an unreachable daemon means this loop cannot tell whether the volume is ours at all,
    # and treating it as "gone" would silently skip a real one. Capture and distinguish, as everywhere
    # else in this module.
    if actual="$(mi_rt_inspect volume v.nonce "$name" 2>/dev/null)"; then irc=0; else irc=$?; fi
    if [ "$irc" -eq 1 ]; then
      mi_warn "  could not determine whether '$name' still carries our nonce — the container runtime"
      mi_warn "  did not answer. Refusing to guess; the staging ledger is kept so a re-run can finish."
      failed=1
      continue
    fi
    if [ "$actual" = "$nonce" ]; then
      # THE REMOVAL'S OWN STATUS IS CHECKED, NEVER MASKED WITH `|| true`. A volume this daemon refuses
      # to remove (still mounted by a container, most often) must not be reported as removed — that is
      # exactly the silent-miss this module's own header warns every other reader off of, and reporting
      # success here is worse than a bare failure: an operator reading "removed" has no reason to look
      # again, while the volume — and its record, about to be destroyed below — are both still live.
      if mi_rt_volume_rm "$name" >/dev/null 2>&1; then
        mi_log "  removed partial volume $name."
      else
        mi_warn "  COULD NOT remove partial volume $name (it may still be in use) — the staging ledger"
        mi_warn "  is kept: deleting it while this volume is still labelled with our nonce would leave"
        mi_warn "  it as an unrecorded survivor no future restore could prove is its own."
        failed=1
      fi
    elif [ -n "$actual" ]; then
      mi_warn "  PRESERVED $name — it carries nonce '$actual', not the recorded '$nonce'."
    fi
  done <<< "$recs"
  [ "$failed" -eq 0 ] || return 1

  rm -f "$sf" || { mi_warn "restore: could not remove the staging ledger"; return 1; }
  mi_warn "restore: abandoned. The machine has no active and no staging ledger."
  return 0
}

_mi_restore_report_blocking() {
  mi_warn "restore: partial volumes that may belong to the abandoned attempt:"
  local names n
  if names="$(_mi_prov_list_all volume)"; then
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      case "$n" in "${MI_NAME_PREFIX}-"*) mi_warn "    volume $n" ;; esac
    done <<< "$names"
  else
    mi_warn "  (the container runtime could not be asked which volumes exist)"
  fi
  mi_warn "  The installer cannot prove these are its own — the record that would have said so is the"
  mi_warn "  file whose checksum just failed. They BLOCK a fresh restore, and removing them is your"
  mi_warn "  explicit call: docker volume rm <name>"
}

# Emptiness must be observed THROUGH the daemon — the host cannot read a named volume (D54).
_mi_restore_volume_empty() {
  if [ "$#" -ne 2 ]; then mi_warn "restore: _mi_restore_volume_empty needs <index> <volume>"; return 1; fi
  local idx="$1" vol="$2" out rc v
  mi_copy_available "$idx" || return 1
  if out="$(_mi_copy_helper "$idx" verify "arg=/src" "arg=--count" "srcvol=${vol}" 2>/dev/null)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "restore: cannot determine whether volume '$vol' is empty — refusing rather than assuming."
    return 1
  fi
  v="$(_mi_copy_stated "$out" checked "restore emptiness check" "the entry count")" || return 1
  case "$v" in
    0) printf 'yes\n' ;;
    ''|*[!0-9]*)
      mi_warn "restore: the emptiness check's count for '$vol' is not a number ('$v')."
      return 1 ;;
    *) printf 'no\n' ;;
  esac
  return 0
}

# Phase 4's verification, against the manifest's per-entry contract — never bytes alone. The manifest is
# handed to the helper on STDIN (lib/runtime.sh's `stdin=1` spec), never mounted as a third host path.
_mi_restore_verify() {
  if [ "$#" -ne 3 ]; then mi_warn "restore: _mi_restore_verify needs <index> <volume> <manifest file>"; return 1; fi
  local idx="$1" vol="$2" man="$3" out rc bad=0 v mcount checkedval doneval
  mi_copy_available "$idx" || return 1
  if [ -L "$man" ] || [ ! -f "$man" ]; then
    mi_warn "restore: the manifest for volume '$vol' is missing or not a plain file — refusing to"
    mi_warn "  verify without it."
    return 1
  fi
  if out="$(_mi_copy_helper "$idx" verify "arg=/src" "arg=--against-stdin" "srcvol=${vol}" "stdin=1" \
             < "$man" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  _mi_copy_grammar_ok "$out" mismatch checked "done" || return 1

  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_warn "restore: VERIFICATION MISMATCH in $vol: $v"
    mi_warn "  The manifest authenticates type, link targets, hardlink topology, mode, ownership and"
    mi_warn "  mtime — not bytes alone. A symlink re-created as a file has no bytes to mismatch, and"
    mi_warn "  flattened hardlinks digest identically."
    bad=1
  done <<< "$(_mi_copy_fields "$out" mismatch)"
  if _mi_copy_has_key "$out" mismatch && [ "$bad" -eq 0 ]; then
    mi_warn "restore: the verifier reported a mismatch that names nothing — treated as a mismatch."
    bad=1
  fi
  if [ "$rc" -ne 0 ] && [ "$bad" -eq 0 ]; then
    mi_warn "restore: verification of volume '$vol' did not complete."
    bad=1
  fi

  doneval="$(_mi_copy_stated "$out" "done" "restore verification" completion)" || bad=1
  if [ "$bad" -eq 0 ] && [ "$doneval" != ok ]; then
    mi_warn "restore: the verifier for '$vol' reported 'done=${doneval:-<empty>}' rather than completion."
    bad=1
  fi

  # THE COUNT BINDS VERIFICATION TO THE MANIFEST ITSELF, the same discipline lib/copy.sh's own
  # copy->verify already applies to the source's own enumeration: a verifier that "checked" fewer (or
  # more) entries than the manifest actually names cannot be trusted as a verification of THAT manifest.
  # `grep -c` exits 1 on a genuine zero-match count (not a failure — an empty manifest is legal), so
  # the count is read from stdout regardless of that; a REAL read failure (permission, an I/O error)
  # prints nothing, and the numeric-format check right below is what turns that into a refusal rather
  # than an empty pattern that would otherwise only coincidentally fail closed against a non-empty
  # checkedval.
  mcount="$(grep -ac '^manifest=' "$man")"
  case "$mcount" in
    ''|*[!0-9]*)
      mi_warn "restore: could not count the manifest's own entries in '$man' — refusing to bind"
      mi_warn "  verification to a count this process could not establish."
      bad=1 ;;
  esac
  checkedval="$(_mi_copy_stated "$out" checked "restore verification" "the checked count")" || bad=1
  if [ "$bad" -eq 0 ]; then
    case "$checkedval" in
      "$mcount") : ;;
      ''|*[!0-9]*)
        mi_warn "restore: the verifier's checked count for '$vol' is not a number ('$checkedval')."
        bad=1 ;;
      *)
        mi_warn "restore: the verifier for '$vol' checked ${checkedval} entries, but the manifest names"
        mi_warn "  ${mcount}. A count that does not match the manifest cannot bind verification to it —"
        mi_warn "  refusing rather than trusting a partial or padded check."
        bad=1 ;;
    esac
  fi

  [ "$bad" -eq 0 ]
}

# --- verbs -------------------------------------------------------------------------------------------

mi_verb_backup() {
  if [ "$#" -ne 4 ]; then
    mi_warn "verbs: backup needs an <index>, a <policy>, a <manifest-dir> and an <output directory>"
    return 2
  fi
  mi_preflight_daemon || return 1
  mi_ensure_layout || return 1
  _mi_with_lock mi_backup_run "$@"
}

mi_verb_restore() {
  if [ "$#" -lt 3 ]; then
    mi_warn "verbs: restore needs an <index>, a <policy>, a <manifest-dir> and a <backup directory>,"
    mi_warn "  or --abandon in place of the directory"
    return 2
  fi
  if [ "$#" -eq 4 ] && [ "$4" = --abandon ]; then
    mi_preflight_daemon || return 1
    mi_ensure_layout || return 1
    _mi_with_lock mi_restore_abandon
    return $?
  fi
  [ "$#" -eq 4 ] || {
    mi_warn "verbs: restore needs an <index>, a <policy>, a <manifest-dir> and a <backup directory>,"
    mi_warn "  or --abandon in place of the directory"
    return 2
  }
  mi_preflight_daemon || return 1
  mi_ensure_layout || return 1
  _mi_with_lock mi_restore_run "$@"
}
