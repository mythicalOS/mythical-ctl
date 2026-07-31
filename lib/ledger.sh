#!/usr/bin/env bash
# The single atomic state ledger (D28): one checksummed file, replaced by atomic rename under the
# family lock (D36/§4b.3a), fail-closed on any corruption (D28), schema-versioned (D35).

MI_LEDGER_SCHEMA=1

_mi_ledger_path() { printf '%s/.state/ledger\n' "$(mi_home)"; }

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

# Print body records (everything between the header and the checksum). Validates first.
# Exit: 0 ok · 3 missing · 1 corrupt/newer-schema (fail closed).
mi_ledger_read() {
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
  [ -z "$(tail -c1 "$snap")" ] || { rm -f "$snap"; mi_die "ledger is not newline-terminated (truncated?) — refusing (fail closed)"; }

  # Split: header (line 1), checksum (last line), body (the rest).
  local header checkline
  header="$(head -n1 "$snap")"
  checkline="$(tail -n1 "$snap")"
  case "$checkline" in
    '#sha256='*) : ;;
    *) rm -f "$snap"; mi_die "ledger checksum line missing or malformed — refusing (fail closed)" ;;
  esac

  # Recompute the checksum over everything except the last line.
  local recomputed expected
  expected="${checkline#\#sha256=}"
  recomputed="$(sed '$d' "$snap" | mi_digest /dev/stdin)" || { rm -f "$snap"; mi_die "ledger: failed to compute checksum — refusing (fail closed)"; }
  [ -n "$recomputed" ] || { rm -f "$snap"; mi_die "ledger: empty computed checksum — refusing (fail closed)"; }
  [ "$recomputed" = "$expected" ] || { rm -f "$snap"; mi_die "ledger checksum mismatch — refusing (fail closed)"; }

  # Schema gate (after integrity, so a torn header is caught as corruption first).
  case "$header" in
    '#mythical-ctl-ledger schema='*) : ;;
    *) rm -f "$snap"; mi_die "ledger header malformed — refusing (fail closed)" ;;
  esac
  local schema="${header#\#mythical-ctl-ledger schema=}"
  # Must be plain decimal digits BEFORE any comparison — a non-numeric schema is corruption.
  case "$schema" in
    ''|*[!0-9]*) rm -f "$snap"; mi_die "ledger schema '$schema' is not a number — refusing (fail closed)" ;;
  esac
  # Compare as decimal STRINGS, never via `[ -gt ]` (overflow → parse). Digit-count then lexical.
  if _mi_num_gt "$schema" "$MI_LEDGER_SCHEMA"; then
    rm -f "$snap"; mi_die "ledger schema $schema is newer than this mythical-ctl understands ($MI_LEDGER_SCHEMA) — refusing"
  fi

  # Body = everything except line 1 and the last line — from the SAME snapshot we validated.
  sed -e '1d' -e '$d' "$snap"
  rm -f "$snap"
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
