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
  [ -f "$f" ] || return 3

  # The file MUST end in a newline. Truncating just the final byte leaves the header/body byte
  # range identical, so `sed '$d'` would hash the same bytes and accept a truncated write. A
  # trailing newline makes `tail -c1` yield empty; anything else is truncation → fail closed.
  [ -z "$(tail -c1 "$f")" ] || mi_die "ledger is not newline-terminated (truncated?) — refusing (fail closed)"

  # Split: header (line 1), checksum (last line), body (the rest).
  local header checkline
  header="$(head -n1 "$f")"
  checkline="$(tail -n1 "$f")"
  case "$checkline" in
    '#sha256='*) : ;;
    *) mi_die "ledger checksum line missing or malformed — refusing (fail closed)" ;;
  esac

  # Recompute the checksum over everything except the last line.
  local recomputed expected
  expected="${checkline#\#sha256=}"
  recomputed="$(sed '$d' "$f" | mi_digest /dev/stdin)"
  [ "$recomputed" = "$expected" ] || mi_die "ledger checksum mismatch — refusing (fail closed)"

  # Schema gate (after integrity, so a torn header is caught as corruption first).
  case "$header" in
    '#mythical-ctl-ledger schema='*) : ;;
    *) mi_die "ledger header malformed — refusing (fail closed)" ;;
  esac
  local schema="${header#\#mythical-ctl-ledger schema=}"
  # Must be plain decimal digits BEFORE any comparison — a non-numeric schema is corruption.
  case "$schema" in
    ''|*[!0-9]*) mi_die "ledger schema '$schema' is not a number — refusing (fail closed)" ;;
  esac
  # Compare as decimal STRINGS, never via `[ -gt ]`: a large all-digit schema overflows shell
  # integers, `[ -gt ]` then errors, the `if` sees false, and the body would be parsed. Compare
  # by digit-count (after stripping leading zeros), then lexically at equal length.
  if _mi_num_gt "$schema" "$MI_LEDGER_SCHEMA"; then
    mi_die "ledger schema $schema is newer than this mythical-ctl understands ($MI_LEDGER_SCHEMA) — refusing"
  fi

  # Body = everything except line 1 and the last line.
  sed -e '1d' -e '$d' "$f"
}

# Replace the ledger atomically from records on stdin. Requires the caller to actually HOLD the
# family lock — proven by our token matching the on-disk lock file, not merely by an env flag a
# caller could set. Fails closed rather than clobbering an existing ledger that does not validate.
mi_ledger_write() {
  # Prove we hold the lock: nonempty MI_LOCK_TOKEN that matches the lock file's token on disk.
  # Read inline (no dependency on lock.sh being sourced at this call site).
  local lf ltok=""
  lf="$(mi_home)/.state/lock"
  # Guard the token read behind the file test. Under the entrypoint's `set -e`, `sed` on an ABSENT
  # lock file exits nonzero and the assignment would abort the CLI *before* the refusal below ever
  # runs — a silent exit with sed's code, not our contract exit. (A bare `bash -c` test shell has no
  # `set -e`, which is why the refusal test must opt into it or it passes for the wrong reason.)
  # Read only when the file exists AND is exactly one newline-terminated line; then strict whole-record
  # match (same shape as lib/lock.sh's parser, kept inline so this guard needs no lock.sh sourced): a
  # multi-line / malformed / garbage / doubled-token record yields nothing → refuse (fail closed).
  if [ -f "$lf" ] && [ -z "$(tail -c1 "$lf" 2>/dev/null)" ] && [ "$(awk 'END{print NR}' "$lf" 2>/dev/null)" = 1 ]; then
    ltok="$(sed -n 's/^pid=[0-9][0-9]* start=[0-9][0-9]* token=\([^ ]*\)$/\1/p' "$lf" 2>/dev/null)" || ltok=""
  fi
  { [ -n "${MI_LOCK_TOKEN:-}" ] && [ -n "$ltok" ] && [ "$ltok" = "$MI_LOCK_TOKEN" ]; } \
    || mi_die "refusing to write the ledger without holding the family lock (D28/§4b.3a)"
  local f dir tmp
  f="$(_mi_ledger_path)"; dir="$(dirname "$f")"

  # Never destroy evidence: if a ledger exists it must be valid before we replace it. A missing
  # ledger is fine to create; a valid one is fine to replace; a corrupt one is refused.
  # Run the validation read in a SUBSHELL: on corruption mi_ledger_read calls mi_die (exit), which
  # would otherwise terminate this writer before it could report. Containing it keeps the writer's
  # own diagnostic reachable.
  if [ -f "$f" ] && ! ( mi_ledger_read >/dev/null 2>&1 ); then
    mi_die "existing ledger does not validate — refusing to overwrite it; run 'state repair'"
  fi

  tmp="$(mktemp "$dir/.ledger.XXXXXX")"
  # Buffer the whole body, then guarantee it ends in exactly one newline before the checksum line,
  # so a final record lacking its own newline cannot fuse onto '#sha256='. An empty body is legal.
  local body; body="$(cat)"
  {
    printf '#mythical-ctl-ledger schema=%s\n' "$MI_LEDGER_SCHEMA"
    if [ -n "$body" ]; then printf '%s\n' "$body"; fi
  } > "$tmp"
  local sum; sum="$(mi_digest "$tmp")"
  printf '#sha256=%s\n' "$sum" >> "$tmp"
  # Atomic replace: same directory, so rename() cannot cross filesystems.
  mv -f "$tmp" "$f"
}

# Convenience: print records of <kind>, or the value of <key> within them.
mi_ledger_get() {
  local kind="$1" key="${2:-}" records line f tok
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
    IFS=$'\t' read -r -a f <<<"$line"
    for tok in "${f[@]}"; do
      case "$tok" in "$key"=*) printf '%s\n' "${tok#*=}" ;; esac
    done
  done <<< "$records"
}
