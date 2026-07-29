#!/usr/bin/env bash
# Family-scoped operation lock (D31/§4b.3a). Serializes every mutating operation so read-modify-
# write on the ledger and mythical.conf cannot interleave. The lock is a FILE, published atomically
# via ln so it is never seen existing-but-empty. A dead holder's lock is broken UNDER A SERIALIZING
# RECOVERY GATE — never by moving the live pathname aside on a stale liveness reading, which can
# relocate and orphan a fresh holder's lock (the one unsafe move: it yields two live holders).
# Release and the break are ownership/liveness-checked so no live lock is ever destroyed.

_mi_lock_file()        { printf '%s/.state/lock\n' "$(mi_home)"; }

# rc 0 iff the file is EXACTLY ONE newline-terminated line. `sed`'s ^…$ anchors match every LINE, not
# the whole file, so a file with two individually well-formed records would let the parsers below
# emit a newline-joined value (e.g. two PIDs); `kill -0` on that fails, the break would treat it as
# dead, and it could delete a lock naming a LIVE holder — splitting the family lock. Gating every
# parse on "one clean line" closes that: a multi-line, non-terminated, or empty file is unreadable.
_mi_lock_one_line() {
  [ -z "$(tail -c1 "$1" 2>/dev/null)" ] || return 1              # newline-terminated (or empty file)
  [ "$(awk 'END{print NR}' "$1" 2>/dev/null)" = 1 ]             # exactly one line
}

# Parse a field ONLY from a single clean line that fully matches the record — anchored `^…$`, exact
# field order — so a malformed/garbage/prefix (`pid=123garbage`) or doubled `token=` record yields
# nothing and is treated as unreadable → refuse, never confidently broken or authorized (fail closed).
# The main lock is `pid=<digits> start=<digits> token=<non-space>`; the recovery gate is `pid=<digits>`
# alone, which needs its OWN exact parser (the full-record parser would reject it).
_mi_lock_owner_pid()   { _mi_lock_one_line "$1" || return 0; sed -n 's/^pid=\([0-9][0-9]*\) start=[0-9][0-9]* token=[^ ]*$/\1/p' "$1" 2>/dev/null; }
_mi_lock_owner_token() { _mi_lock_one_line "$1" || return 0; sed -n 's/^pid=[0-9][0-9]* start=[0-9][0-9]* token=\([^ ]*\)$/\1/p' "$1" 2>/dev/null; }
_mi_gate_owner_pid()   { _mi_lock_one_line "$1" || return 0; sed -n 's/^pid=\([0-9][0-9]*\)$/\1/p' "$1" 2>/dev/null; }

# Try once: publish a fully-formed lock file atomically. 0 on success, 1 if already held.
_mi_lock_try() {
  local lf="$1" tmp
  MI_LOCK_TOKEN="$$.${RANDOM}.${RANDOM}"
  tmp="$(mktemp "${lf}.new.XXXXXX")" || { unset MI_LOCK_TOKEN; return 1; }
  # A FAILED write must not proceed to ln — that would publish an empty/partial lock that wedges
  # every later acquire as "acquiring". errexit is suppressed here (the function runs in an && / if
  # context), so check the write explicitly rather than trusting `set -e`.
  if ! printf 'pid=%s start=%s token=%s\n' "$$" "$(date +%s 2>/dev/null || echo 0)" "$MI_LOCK_TOKEN" > "$tmp"; then
    rm -f "$tmp"; unset MI_LOCK_TOKEN; return 1
  fi
  # ln fails if the target exists; on success $lf points at the already-written inode — no empty
  # window. Then drop the temp name (the inode survives as $lf).
  if ln "$tmp" "$lf" 2>/dev/null; then
    rm -f "$tmp"
    export MI_LOCK_TOKEN MI_LOCK_HELD=1
    return 0
  fi
  rm -f "$tmp"; unset MI_LOCK_TOKEN
  return 1
}

# Serialized recovery gate — a SECOND, short-lived lock that lets at most one process break a stale
# lock at a time. Returns 0 holding it (caller MUST call _mi_recovery_exit), 1 if busy.
#
# The gate is NEVER force-cleared by racing. Force-clearing it means removing/renaming a file we
# only observed stale, and with ln/rename/rm there is no compare-and-swap: between the observation
# and the act, a fresh holder can take the pathname, so a "steal" can relocate a LIVE gate and — if
# the restore then loses the pathname — orphan it, yielding two overlapping breakers and re-opening
# the two-live-holders main-lock race. There is no safe auto-clear at ANY level (it is turtles all
# the way down), so we stop the regress here: the gate is taken only by an atomic `ln`, released
# only by its own holder, and a gate orphaned by a crash inside this ~ms window is reported for a
# one-time manual clear (see mi_lock_acquire), not stolen. The COMMON crash — during the actual
# operation, holding the MAIN lock — is still broken automatically; only a crash in this window is
# manual, which is astronomically rarer and never risks two live holders.
_mi_recovery_enter() {
  local rlf="$1" rtmp
  rtmp="$(mktemp "${rlf}.XXXXXX")" || return 1
  if ! printf 'pid=%s\n' "$$" > "$rtmp"; then rm -f "$rtmp"; return 1; fi   # failed write ⇒ no ln
  if ln "$rtmp" "$rlf" 2>/dev/null; then rm -f "$rtmp"; return 0; fi
  rm -f "$rtmp"; return 1
}
_mi_recovery_exit() { rm -f "$1"; }

mi_lock_acquire() {
  local lf; lf="$(_mi_lock_file)"
  _mi_lock_try "$lf" && return 0

  # Held. Read the owner. If the holder RELEASED $lf between the failed try and this read, sed
  # fails on the vanished file; `|| holder=""` keeps the entrypoint's `set -e` from aborting the
  # CLI. An empty PID (holder mid-publish OR just-released) then refuses safely and the caller
  # retries — we never break a lock we could not read.
  local holder; holder="$(_mi_lock_owner_pid "$lf")" || holder=""
  if [ -z "$holder" ]; then
    mi_warn "another mythical-ctl operation is acquiring the lock — try again shortly"
    return 1
  fi
  if kill -0 "$holder" 2>/dev/null; then
    mi_warn "another mythical-ctl operation is in progress (pid $holder) — try again when it finishes"
    return 1
  fi

  # Holder looks dead. Break it UNDER THE RECOVERY GATE. While we hold the gate the lock pathname is
  # identity-stable — plain acquirers cannot create it (it still exists) or remove it, and no other
  # breaker holds the gate — so we re-read liveness on the SAME file and rm it ONLY if still dead.
  # We never move a live lock aside, so a break can never split one lock into two live holders.
  local rlf="${lf}.recovery" cur rgpid
  if _mi_recovery_enter "$rlf"; then
    cur="$(_mi_lock_owner_pid "$lf")" || cur=""
    if [ -n "$cur" ] && ! kill -0 "$cur" 2>/dev/null; then
      rm -f "$lf"
      mi_warn "broke a stale lock left by a dead process (pid $cur)"
    fi
    # cur empty (released) or now-alive (a fresh holder won the race first): touch nothing; retry.
    _mi_recovery_exit "$rlf"
    _mi_lock_try "$lf" && return 0
    mi_warn "another mythical-ctl operation acquired the lock first — try again"
    return 1
  fi
  # Could NOT enter the recovery gate, and we never steal it (see _mi_recovery_enter). Read its owner
  # for the message only (a pure read — no mutation, no race): a live owner is another operation mid-
  # break (transient, retry); a dead owner is a crash inside the ~ms recovery window (needs a
  # one-time manual clear, named exactly).
  rgpid="$(_mi_gate_owner_pid "$rlf")" || rgpid=""   # gate record is pid=<digits> only
  if [ -n "$rgpid" ] && ! kill -0 "$rgpid" 2>/dev/null; then
    mi_warn "a previous operation was interrupted while recovering the lock; if no mythical-ctl is running, remove ${rlf} and retry"
  else
    mi_warn "another mythical-ctl operation is recovering the lock — try again shortly"
  fi
  return 1
}

# Remove the lock ONLY if it is ours (token match). Never delete another holder's lock.
mi_lock_release() {
  local lf; lf="$(_mi_lock_file)"
  if [ -f "$lf" ] && [ -n "${MI_LOCK_TOKEN:-}" ] && [ "$(_mi_lock_owner_token "$lf")" = "$MI_LOCK_TOKEN" ]; then
    rm -f "$lf"
  fi
  unset MI_LOCK_HELD MI_LOCK_TOKEN || true
  return 0
}

# Prove this process holds the family lock, or die. The ONLY authorization for a mutating write.
#
# Proof is a token match against the lock file on disk — never a bare environment flag, which any
# caller could set. `_mi_lock_owner_token` already gates on the record being exactly one clean,
# newline-terminated, fully-matching line, so a malformed or doubled record yields nothing and we
# refuse (fail closed).
#
# <what> completes the sentence "refusing to <what> without holding the family lock", so callers
# name their own operation and the message stays specific.
mi_lock_assert_held() {
  # Arity BEFORE any positional expansion, the same discipline every public function in this codebase
  # applies — and it matters most here, in the function this comment calls the ONLY authorization for
  # a mutating write. Under the entrypoint's `set -u`, `local what="$1"` on a no-argument call aborts
  # with bash's raw "unbound variable"; without errexit it produces "refusing to  without holding the
  # family lock", a garbled message from a security primitive. It fails closed either way — what is
  # lost is the diagnostic, and this is shared code a future caller will get wrong.
  #
  # `mi_die`, not `mi_warn` + `return 1`: this function's contract is that it never returns when
  # authorization is absent. A caller that neglected to check a returned status would carry on and
  # write unauthorized, so a refusal that can be ignored would be a real regression.
  if [ "$#" -ne 1 ]; then
    mi_die "mi_lock_assert_held needs a <what> naming the operation it is guarding"
  fi
  local what="$1" lf ltok=""
  lf="$(_mi_lock_file)"
  if [ -f "$lf" ]; then
    ltok="$(_mi_lock_owner_token "$lf")" || ltok=""
  fi
  if [ -n "${MI_LOCK_TOKEN:-}" ] && [ -n "$ltok" ] && [ "$ltok" = "$MI_LOCK_TOKEN" ]; then
    return 0
  fi
  mi_die "refusing to $what without holding the family lock (D28/§4b.3a)"
}
