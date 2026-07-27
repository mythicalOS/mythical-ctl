#!/usr/bin/env bash
# Snapshot + diff helpers for §10a acceptance assertions (test-only).
# snap_fs / snap_runtime write stable sorted descriptions; snap_assert_unchanged diffs them.
# Self-contained: does not depend on lib/ being sourced (snap_runtime tests do not load it).

_snap_digest() {
  # Hash via STDIN, not `sha256sum "$1"` — the latter echoes the filename in its output, and for a
  # name containing a newline/backslash sha256sum escapes and line-wraps it, poisoning the digest.
  # `< "$1"` makes the reported name `-`. Take the first field with `${out%% *}` (no `| cut`, which
  # would mask a hasher failure); if the hasher runs but the read fails, emit UNREADABLE, never a
  # silent empty — so an unreadable file is visible in the snapshot, not indistinguishable from ''.
  local out
  if   command -v sha256sum >/dev/null 2>&1; then out="$(sha256sum < "$1" 2>/dev/null)" && { printf '%s\n' "${out%% *}"; return 0; }
  elif command -v shasum    >/dev/null 2>&1; then out="$(shasum -a 256 < "$1" 2>/dev/null)" && { printf '%s\n' "${out%% *}"; return 0; }
  else echo NODIGEST; return 0; fi
  echo UNREADABLE
}

# Escape backslash, tab, and newline so a pathname or link target is ALWAYS one clean tab-delimited
# field. Version-independent (no `printf %q`, whose newline handling differs across bash 3.2/4/5).
# Deterministic and reversible, so snapshots still sort, diff, and detect changes exactly.
_snap_enc() {
  local s="$1"
  s="${s//\\/\\\\}"        # backslash first (so escapes we add below are not re-escaped)
  s="${s//$'\t'/\\t}"      # tab  -> \t
  s="${s//$'\n'/\\n}"      # newline -> \n
  printf '%s' "$s"
}

snap_fs() {
  local out="$1" home="${MYTHICAL_HOME:?}"
  # Exclude the volatile lock file, its recovery gate, and every mktemp publish leftover
  # (`lock.*` covers lock.new.*, lock.recovery, and lock.recovery.* mktemp temps) so snapshots
  # are deterministic. The exclusion is path-anchored to `.state/`, so identically-named user data
  # elsewhere is still captured.
  # Content hash (files) / link target (symlinks) catches an in-place overwrite at the same mode.
  # NUL-delimited traversal (`-print0` / `read -d ''`) so a filename containing a NEWLINE is one
  # item, not two false paths. The mode comes from `awk 'NR==1'` because `ls -ld` echoes the name
  # (and a symlink's `-> target`), which line-wraps on a newline and would otherwise splice a stray
  # field into `$m`. Path and link target go through `_snap_enc`, so a tab/newline never breaks the
  # tab-delimited, one-line-per-entry format. Result: a reliable full-tree D9 seam for ANY filename.
  ( cd "$home" && find . \
      -path './.state/lock' -prune -o \
      -path './.state/lock.*' -prune -o \
      -path './.state/.ledger.*' -prune -o \
      -print0 \
      | while IFS= read -r -d '' p; do
          local t m extra
          # Classify explicitly. Only a real regular file (`-f`) is hashed — a FIFO passed to a
          # reader would BLOCK the whole snapshot forever, and sockets/devices are not file content.
          # They are recorded by type (never read), so the seam completes on any tree.
          if   [ -L "$p" ]; then t="link";    extra="$(readlink "$p")"
          elif [ -d "$p" ]; then t="dir";     extra="-"
          elif [ -f "$p" ]; then t="file";    extra="$(_snap_digest "$p")"
          else                   t="special"; extra="-"; fi
          # ls is the portable way to read the mode string: `find -printf %M` is GNU-only and `stat`
          # differs GNU/BSD; `NR==1` already handles a name ls line-wraps.
          # shellcheck disable=SC2012
          m="$(ls -ld "$p" | awk 'NR==1{print $1}')"
          printf '%s\t%s\t%s\t%s\n' "$(_snap_enc "$p")" "$t" "$m" "$(_snap_enc "$extra")"
        done ) | LC_ALL=C sort > "$out"
}

snap_runtime() {
  local out="$1" state="${FAKE_DOCKER_STATE:-${MYTHICAL_HOME}/.fake-docker}"
  if [ -d "$state/volumes" ]; then
    ( cd "$state/volumes" && for v in *; do
        [ -e "$v" ] || continue
        printf 'volume\t%s\t%s\n' "$v" "$(cat "$v")"
      done ) | LC_ALL=C sort > "$out"
  else
    : > "$out"
  fi
}

# Diff two snapshots. Prints the diff and returns 1 on any difference (or diff error); 0 if same.
# No temp file — a shared /tmp path would collide across parallel bats jobs.
snap_assert_unchanged() {
  local d
  if ! d="$(diff -u "$1" "$2")"; then
    printf '%s\n' "$d"
    return 1
  fi
  return 0
}
