#!/usr/bin/env bash
# The single atomic state ledger (D28): one checksummed file, replaced by atomic rename under the
# family lock (D36/§4b.3a), fail-closed on any corruption (D28), schema-versioned (D35).

MI_LEDGER_SCHEMA=1

# The real ledger path, UNLESS a caller has asked for the staging one instead (§6c/D59). The override
# is read from the environment, which looks exactly like the kind of configurable path this codebase
# refuses everywhere else — the difference here is that it selects between TWO PATHS THIS CODE OWNS,
# both under `~/.mythical/.state/`, never an arbitrary file: an env-settable ledger path with no such
# guard would let any caller point the atomic writer (mi_ledger_write, which still proves lock
# ownership itself) at a file of its choosing.
_mi_ledger_path() {
  if [ -n "${MI_LEDGER_PATH_OVERRIDE:-}" ]; then
    case "$MI_LEDGER_PATH_OVERRIDE" in
      "$(mi_home)/.state/ledger"|"$(mi_home)/.state/ledger.staging") : ;;
      *) mi_die "ledger: refusing an out-of-tree ledger path override" ;;
    esac
    printf '%s\n' "$MI_LEDGER_PATH_OVERRIDE"
    return 0
  fi
  printf '%s/.state/ledger\n' "$(mi_home)"
}

# §6c/D59 — the STAGING ledger. Same format, same checksum, a distinct well-known name beside the real
# ledger path, and explicitly NOT AUTHORITATIVE: no operation launches, deletes or reconciles from it
# (D28 permits exactly one authoritative ledger). It exists because a restore needs somewhere to put an
# incoming ledger plus its own intent before either is trusted.
_mi_ledger_staging_path() { printf '%s/.state/ledger.staging\n' "$(mi_home)"; }

# Read/write the staging ledger with the SAME integrity discipline as the real one — implemented by
# pointing the one shared validator/writer at the staging path via the override above, so a future fix
# to the read or write path cannot land on only one of the two files.
mi_ledger_staging_read()  { MI_LEDGER_PATH_OVERRIDE="$(_mi_ledger_staging_path)" mi_ledger_read; }
mi_ledger_staging_write() { MI_LEDGER_PATH_OVERRIDE="$(_mi_ledger_staging_path)" mi_ledger_write; }

# Decimal-string greater-than: 0 (true) if $1 > $2. Both are already validated all-digit strings.
# Avoids shell integer conversion so an arbitrarily long schema cannot overflow `[ -gt ]`.
_mi_num_gt() {
  local a="$1" b="$2"
  local LC_ALL=C   # force byte collation; `[[ > ]]` otherwise uses locale rules, not byte order
  while [ "${#a}" -gt 1 ] && [ "${a:0:1}" = 0 ]; do a="${a:1}"; done   # strip leading zeros
  while [ "${#b}" -gt 1 ] && [ "${b:0:1}" = 0 ]; do b="${b:1}"; done   # (${#x} is length, not value)
  if [ "${#a}" -ne "${#b}" ]; then [ "${#a}" -gt "${#b}" ]; return; fi
  [[ "$a" > "$b" ]]   # equal length ⇒ byte order equals numeric order for digits (under LC_ALL=C)
}

# THE SHARED IMPLEMENTATION. Print body records (everything between the header and the checksum),
# validating first. INTERNAL — every ordinary caller goes through the public `mi_ledger_read` wrapper
# below, which normalizes this function's finer-grained rc to the PUBLIC 0/1/3 contract every existing
# caller (and every existing test of every module) already depends on. This function alone carries the
# extra distinction repair's destroy gate needs, via `mi_ledger_confirmed_corrupt` further below — the
# ONE caller allowed to see it.
#
# rc 0 ok · 3 missing · 1 refused for a reason that does NOT positively confirm the ledger's CONTENT
# is bad (a permissions/path-shape problem before we ever open it, unable to even snapshot or read the
# bytes, the digest tool itself failed, or the schema is merely NEWER than this build understands —
# D35's own gate, not corruption) · 4 the content itself is POSITIVELY CONFIRMED corrupt: this function
# already holds a complete, faithful private copy of the bytes on disk (the snapshot below succeeded)
# and either they fail to parse as a ledger or their own checksum disagrees with what they claim.
#
# THE 1-vs-4 SPLIT EXISTS FOR REPAIR (round 8 cross-model gate). `state repair`'s reset path renames an
# existing ledger aside and replaces it with an empty one — a real destructive action only corruption
# justifies. Before this split every non-absent failure here reported the SAME rc 1 (mi_die always
# `exit 1`), so a failure with NO bearing on the ledger's actual content — a runtime I/O error while
# THIS call was copying or hashing it, an out-of-space mktemp, a momentarily broken sha256 tool — was
# indistinguishable from a genuinely corrupt file, and the reset path could not tell them apart: it
# reset a perfectly good ledger, discarding the trust anchor and every rollback floor, because reading
# it once happened to fail for a reason that said nothing about its bytes. rc 4 is reported ONLY once
# `cat "$f" > "$snap"` below has already succeeded — from that point on, "these exact bytes do not
# check out" is genuine, positive evidence, not a guess. Everything before that point — unable to even
# take the snapshot, unable to read it — stays rc 1: nothing about the content was ever established.
#
# rc 4 MUST NOT leak past the public wrapper (round 8-refined: the FIRST cut of this split gave rc 4
# directly to `mi_ledger_read`, which every general caller — `mi_ledger_get`/`mi_led_all` and the
# direct callers in prov.sh/trust.sh/state.sh/intent.sh — propagates unexamined; a corrupt ledger then
# surfaced as rc 4 instead of rc 1 through ALL of them, and `tests/unit/prov.bats`'s "a corrupt ledger
# fails CLOSED for identity" test, which asserts rc 1 specifically, broke. Those modules' rc-1 contract
# for a corrupt ledger is the CORRECT, load-bearing one and must stay byte-for-byte; only repair may
# ever see the finer distinction, and only through the dedicated helper below, never through this
# function's own name).
_mi_ledger_read_impl() {
  local f; f="$(_mi_ledger_path)"
  # ABSENT is rc 3 — a legitimate first write. PRESENT-BUT-NOT-A-REGULAR-FILE is not absent, and
  # conflating the two was silent data loss. `[ -f ]` alone is false for a directory and for a
  # dangling symlink, so both reported "no ledger", the writer's never-destroy-evidence check below
  # was skipped as a result, and `mv -f "$tmp" "$f"` then either moved the temp file INTO the
  # directory (returning 0, writing nothing, leaving a stray .ledger.XXXXXX behind on every call) or
  # replaced the dangling symlink and destroyed the trace it pointed at. Measured consequence:
  # mi_ident_ensure minted a DIFFERENT installation identity on every invocation, because each write
  # reported success and each read still said "absent".
  if [ ! -f "$f" ]; then
    if [ -e "$f" ] || [ -L "$f" ]; then
      mi_die "ledger: '$f' exists but is not a regular file — refusing (fail closed). Run 'state repair'."
    fi
    return 3
  fi

  # Snapshot the ledger to a PRIVATE inode, then validate AND parse the SAME bytes. Reopening $f for
  # each step (tail/head/sed) is a TOCTOU: reads do not hold the lock, so a concurrent atomic replace
  # (mi_ledger_write's `mv -f`) between the checksum validation and the final body read would let us
  # validate one file yet return another — e.g. a checksum-valid but NEWER-schema file whose schema
  # gate we never ran (silently defeating D35). Reading a copy we own closes the window: once cat has
  # opened $f, a later rename cannot change these bytes. Named `.ledger.*` so the fs snapshot excludes it.
  local snap; snap="$(mktemp "$(dirname "$f")/.ledger.read.XXXXXX")" || mi_die "ledger: cannot create read buffer — refusing (fail closed)"
  if ! cat "$f" > "$snap" 2>/dev/null; then rm -f "$snap"; mi_die "ledger: cannot read — refusing (fail closed)"; fi

  # The file MUST end in a newline. Truncating just the final byte leaves the header/body byte range
  # identical, so `sed '$d'` would hash the same bytes and accept a truncated write. A trailing
  # newline makes `tail -c1` yield empty; anything else is truncation → fail closed.
  #
  # rc 4 from here down: $snap is a proven, complete, private copy of the bytes on disk (the `cat`
  # above already succeeded), so every refusal below is POSITIVE evidence about THOSE bytes — not
  # about this process's ability to read them.
  if [ -n "$(tail -c1 "$snap")" ]; then
    rm -f "$snap"; mi_warn "ledger is not newline-terminated (truncated?) — refusing (fail closed)"; return 4
  fi

  # Split: header (line 1), checksum (last line), body (the rest).
  local header checkline
  header="$(head -n1 "$snap")"
  checkline="$(tail -n1 "$snap")"
  case "$checkline" in
    '#sha256='*) : ;;
    *) rm -f "$snap"; mi_warn "ledger checksum line missing or malformed — refusing (fail closed)"; return 4 ;;
  esac

  # Recompute the checksum over everything except the last line. A FAILURE to compute it (the digest
  # tool itself misbehaving) is an operational fact about this process, not evidence about the ledger's
  # bytes — stays rc 1 via mi_die. A computed-but-DISAGREEING checksum is the opposite: definitive,
  # positive proof the bytes do not check out.
  local recomputed expected
  expected="${checkline#\#sha256=}"
  recomputed="$(sed '$d' "$snap" | mi_digest /dev/stdin)" || { rm -f "$snap"; mi_die "ledger: failed to compute checksum — refusing (fail closed)"; }
  [ -n "$recomputed" ] || { rm -f "$snap"; mi_die "ledger: empty computed checksum — refusing (fail closed)"; }
  if [ "$recomputed" != "$expected" ]; then
    rm -f "$snap"; mi_warn "ledger checksum mismatch — refusing (fail closed)"; return 4
  fi

  # Schema gate (after integrity, so a torn header is caught as corruption first).
  case "$header" in
    '#mythical-ctl-ledger schema='*) : ;;
    *) rm -f "$snap"; mi_warn "ledger header malformed — refusing (fail closed)"; return 4 ;;
  esac
  local schema="${header#\#mythical-ctl-ledger schema=}"
  # Must be plain decimal digits BEFORE any comparison — a non-numeric schema is corruption.
  case "$schema" in
    ''|*[!0-9]*)
      rm -f "$snap"; mi_warn "ledger schema '$schema' is not a number — refusing (fail closed)"; return 4 ;;
  esac
  # Compare as decimal STRINGS, never via `[ -gt ]` (overflow → parse). Digit-count then lexical.
  #
  # NEWER-than-understood is deliberately NOT rc 4. It is the one case in this function where the
  # checksum has already validated AND the header parses cleanly, yet the ledger must still be
  # refused — and unlike every rc-4 case above, refusing it is not because anything is wrong with
  # these bytes: D35 says a newer mythical-ctl legitimately wrote a schema this build does not
  # understand yet. Reporting rc 4 here would tell a caller "destroy this", and repair's reset path
  # (lib/repair.sh) would rename a STILL-VALID, merely-newer ledger aside and replace it with an
  # empty one — deleting everything a newer mythical-ctl already recorded through the repair door
  # instead of the read door. Stays rc 1: refused, but never mistaken for corruption.
  if _mi_num_gt "$schema" "$MI_LEDGER_SCHEMA"; then
    rm -f "$snap"; mi_die "ledger schema $schema is newer than this mythical-ctl understands ($MI_LEDGER_SCHEMA) — refusing"
  fi

  # Body = everything except line 1 and the last line — from the SAME snapshot we validated.
  sed -e '1d' -e '$d' "$snap"
  rm -f "$snap"
}

# THE PUBLIC READER. Every ordinary caller's contract, UNCHANGED from before round 8: rc 0 ok · 3
# missing · 1 refused — corrupt, newer-schema, and a transient read/IO failure ALL report this same rc,
# exactly as they always did. `mi_ledger_get`/`mi_led_all` and the direct callers in prov.sh/trust.sh/
# state.sh/intent.sh all propagate whatever this returns unexamined beyond `-eq 3`; none of them, or
# their tests, may observe rc 4 — only `_mi_ledger_read_impl` produces it, and only
# `mi_ledger_confirmed_corrupt` below ever looks for it.
mi_ledger_read() {
  _mi_ledger_read_impl
  local rc=$?
  case "$rc" in
    4) return 1 ;;
    *) return "$rc" ;;
  esac
}

# THE ONE CALLER ALLOWED TO SEE THE DISTINCTION. Whether the ledger, if present, is POSITIVELY
# CONFIRMED corrupt — a checksum computed over a complete, faithfully-read copy of its bytes
# disagreeing with what they claim, or those same proven bytes failing to parse as a ledger at all.
# This exists ONLY for `state repair`'s destroy-and-rebuild gate (lib/repair.sh), which may act only on
# this, never on "could not be read" in general — see `_mi_ledger_read_impl`'s own rc-4 note for why.
#
# rc 0 positively confirmed corrupt (destroy-eligible) · 1 NOT confirmed corrupt — covers a valid
# ledger, an absent ledger, AND an unreadable-for-an-unproven-reason ledger alike; the caller must treat
# all three the same way: do not destroy.
#
# Subshelled: `_mi_ledger_read_impl` still routes its OWN operational-failure branches through
# `mi_die`, which calls `exit`. Called bare (as this function's caller does — `if
# mi_ledger_confirmed_corrupt; then`, not through `$( )`), an unguarded `exit` there would terminate the
# CALLER's process, not just this function. `( … )` contains it to a boolean answer, the same way
# `mi_ledger_write` and repair's own destroy-probe already contain `mi_ledger_read` for the same reason.
mi_ledger_confirmed_corrupt() {
  ( _mi_ledger_read_impl >/dev/null 2>&1 )
  [ "$?" -eq 4 ]
}

# Replace the ledger atomically from records on stdin. Requires the caller to actually HOLD the
# family lock — proven by our token matching the on-disk lock file, not merely by an env flag a
# caller could set. Fails closed rather than clobbering an existing ledger that does not validate.
mi_ledger_write() {
  # Prove we hold the lock. Single implementation, in lib/lock.sh — this check used to be inlined
  # here and is now shared with the config writer; two copies of a security check drift.
  mi_lock_assert_held "write the ledger"
  local f dir tmp
  f="$(_mi_ledger_path)"; dir="$(dirname "$f")"

  # Never destroy evidence: if a ledger exists it must be valid before we replace it. A missing
  # ledger is fine to create; a valid one is fine to replace; a corrupt one is refused.
  # Run the validation read in a SUBSHELL: on corruption mi_ledger_read calls mi_die (exit), which
  # would otherwise terminate this writer before it could report. Containing it keeps the writer's
  # own diagnostic reachable.
  # Anything present that is not a regular file is refused before the validation read, for the same
  # reason the reader refuses it: `[ -f ]` is false for a directory and for a dangling symlink, so
  # this guard used to be skipped on exactly the inputs that make the `mv -f` below destructive.
  if [ ! -f "$f" ] && { [ -e "$f" ] || [ -L "$f" ]; }; then
    mi_die "ledger: '$f' exists but is not a regular file — refusing to write over it; run 'state repair'"
  fi
  if [ -f "$f" ] && ! ( mi_ledger_read >/dev/null 2>&1 ); then
    mi_die "existing ledger does not validate — refusing to overwrite it; run 'state repair'"
  fi

  tmp="$(mktemp "$dir/.ledger.XXXXXX")" || mi_die "ledger: cannot create a temp file in $dir — refusing (fail closed)"
  # Buffer the whole body, then guarantee it ends in exactly one newline before the checksum line,
  # so a final record lacking its own newline cannot fuse onto '#sha256='. An empty body is legal.
  local body
  body="$(cat)" || { rm -f "$tmp"; mi_die "ledger: cannot read the records to write — refusing (fail closed)"; }

  # EVERY construction write is checked, and each one separately. This module is a PURE library that
  # must be correct WITHOUT ambient errexit — the entrypoint's `set -e` masks the problem, but nothing
  # else does. Unchecked, a failed write here (a full disk, a read-only temp, an ENOSPC mid-record)
  # falls straight through to the `mv -f` below and ATOMICALLY REPLACES A VALID LEDGER WITH A
  # TRUNCATED ONE — the precise inverse of the never-destroy-evidence guarantee asserted twenty lines
  # above. Reproduced with a `mktemp` shim handing back a 0444 file: the old code wrote nothing,
  # digested the empty file happily, appended nothing, and renamed the empty temp over a good ledger,
  # returning 0.
  #
  # The header and the body are written as two checked statements rather than one `{ … } > "$tmp"`
  # group, because a group's status is only its LAST command's: with an empty body the group ends on a
  # false `if` test, which is status 0, so a failed header write would have been reported as success.
  if ! printf '#mythical-ctl-ledger schema=%s\n' "$MI_LEDGER_SCHEMA" > "$tmp"; then
    rm -f "$tmp"; mi_die "ledger: cannot write the header — refusing (fail closed)"
  fi
  if [ -n "$body" ]; then
    if ! printf '%s\n' "$body" >> "$tmp"; then
      rm -f "$tmp"; mi_die "ledger: cannot write the records — refusing (fail closed)"
    fi
  fi

  local sum
  sum="$(mi_digest "$tmp")" || { rm -f "$tmp"; mi_die "ledger: failed to compute checksum — refusing (fail closed)"; }
  [ -n "$sum" ] || { rm -f "$tmp"; mi_die "ledger: empty checksum — refusing (fail closed)"; }
  if ! printf '#sha256=%s\n' "$sum" >> "$tmp"; then
    rm -f "$tmp"; mi_die "ledger: cannot write the checksum line — refusing (fail closed)"
  fi

  # Atomic replace: same directory, so rename() cannot cross filesystems. Checked too — an unchecked
  # `mv` leaves the temp behind on failure and reports whatever status the caller's shell options
  # happen to produce.
  mv -f "$tmp" "$f" || { rm -f "$tmp"; mi_die "ledger: cannot replace $f — refusing (fail closed)"; }
}

# Convenience: print records of <kind>, or the value of <key> within them.
mi_ledger_get() {
  # `fields`, not `f`: this is the only ARRAY-typed local in the shipped libraries, and the release
  # bundler concatenates every module into one file in MODULES order — after which shellcheck's
  # array tracking is no longer per-function. A later module's ordinary `local f="$1"` for a file
  # path then draws SC2178 ("used as an array but is now assigned a string") plus an SC2128 on every
  # use, so the repo tree lints clean while `shellcheck dist/mythical-ctl` fails. `f` for a filename
  # is the obvious name in five of the modules here; the array is the one that gives way.
  local kind="$1" key="${2:-}" records line fields tok
  # Capture and PROPAGATE first. A bare `mi_ledger_read | while` returns the while's status, so
  # without ambient pipefail a corrupt/torn ledger exits only the pipeline subshell and the while
  # reports success with no records — silently defeating fail-closed for this PUBLIC reader (and
  # letting a test pass for the wrong reason). Capturing makes the failure hard regardless of the
  # caller's shell options; iterate the captured records via a here-string.
  records="$(mi_ledger_read)" || return $?
  while IFS= read -r line; do
    case "$line" in
      "$kind"$'\t'*) : ;; *) continue ;;
    esac
    if [ -z "$key" ]; then printf '%s\n' "$line"; continue; fi
    # emit the value of key= within the tab fields
    IFS=$'\t' read -r -a fields <<<"$line"
    for tok in "${fields[@]}"; do
      case "$tok" in "$key"=*) printf '%s\n' "${tok#*=}" ;; esac
    done
  done <<< "$records"
}
