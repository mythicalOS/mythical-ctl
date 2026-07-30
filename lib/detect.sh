#!/usr/bin/env bash
# The /detect version contract (D10, §9) — CONSUMER side only.
#
# /detect is JSON and is not ours to change; §9 defines it for the products. The core needs exactly
# three flat string fields from it — product, version, ui_url — and §7.5's dependency floor has no
# JSON parser.
#
# THIS IS NOT A JSON PARSER, and it must not grow into one. It extracts a flat string field with an
# anchored pattern and REFUSES anything it cannot read unambiguously: an escaped character, a
# non-string value, a nested object, a repeated key. A partial JSON parser that guesses is worse
# than none, because the guess is invisible.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_DETECT_UNKNOWN=unknown

# Whole-response byte ceiling, checked in the SHELL by mi_detect_field BEFORE a single byte reaches
# _mi_detect_toplevel's awk scanner.
#
# The scanner accumulates the current string token one character at a time (`tok = tok c`, in the
# string-state branch below). Under GNU awk that append is amortised O(1) and the whole scan is O(n)
# in the length of the response. Under BSD awk — /usr/bin/awk on macOS, a first-class target for this
# installer, not a fallback — string concatenation re-copies the whole accumulated token on every
# character, so the SAME scan is O(n^2). Measured on this worktree, under
# `env -i PATH=/usr/bin:/bin HOME="$HOME" /bin/bash --noprofile --norc -c '…'` (BSD awk):
#
#   value length  25000 ->    66 ms
#   value length  50000 ->   182 ms   (2.8x for 2x input)
#   value length 100000 ->   614 ms   (3.4x)
#   value length 200000 ->  2496 ms   (3.8x)
#
# — roughly quadrupling per doubling, so an unbounded ~1 MiB response costs on the order of a minute.
# The SAME measurement under GNU awk (the default on this machine's ordinary PATH) is flat: 55 ms at
# 25000, 114 ms at 200000. That gap is exactly why this must be bounded here rather than left as a
# per-token cap inside the awk program: a cap inside awk would only hide the defect on whichever awk
# happens to be on PATH, and this installer ships to both. A length check in the calling shell, before
# awk ever starts, bounds the work regardless of which awk is present.
#
# /detect's response is a live HTTP reply from a product container: three short flat strings
# (`product`, `version`, `ui_url`) plus whatever else a product chooses to include. 32768 (32 KiB) is
# generous enough that no real response comes close, and cheap even at the cap itself — a response
# exactly this size measured 92 ms under the same BSD-awk harness above, indistinguishable from any
# other bounded local computation. The input is an HTTP response from a product container, so without
# this bound a misbehaving or hostile product could stall the installer for as long as it liked.
MI_DETECT_MAXBYTES=32768

# Emit one record per DEPTH-1 member: `key<TAB>flag<TAB>value`, where flag is
#   s = a plain string value we can read       e = a string we cannot read verbatim (any escape,
#   x = a value that is not a plain string          or a raw control byte)
#
# A REGEX CANNOT DO THIS. `"version"` matches identically whether it sits at the top level or inside
# `components`, so a pattern-based extractor reports {"components":{"version":"evil"}} as the
# product version. This is a bounded state machine — string state, brace/bracket depth, and nothing
# else. It does not decode escapes, parse numbers, or validate JSON; it locates depth-1 members and
# says honestly which values it cannot read. That is the smallest thing that is correct, and it must
# not be grown into a parser.
_mi_detect_toplevel() {
  printf '%s' "$1" | awk '
    BEGIN { stack = ""; instr = 0; esc = 0; ux = 0; st = 0; key = ""; tok = ""; lit = ""
            bad = 0; keybad = 0; err = 0; closed = 0 }
    function depth() { return length(stack) }
    function litok(v) {
      return (v == "true" || v == "false" || v == "null" ||
              v ~ /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?$/)
    }
    {
      if (NR > 1 && instr) { err = 1 }        # a raw LF inside a string
      n = length($0)
      for (i = 1; i <= n; i++) {
        c = substr($0, i, 1)

        if (instr) {
          if (ux > 0) {                        # inside a \uXXXX escape
            if (c !~ /^[0-9a-fA-F]$/) { err = 1 }
            ux--; bad = 1; continue
          }
          if (esc) {
            esc = 0; bad = 1                   # the value is unreadable verbatim either way
            if (c == "u") { ux = 4; continue }
            if (c !~ /^["\\\/bfnrt]$/) { err = 1 }   # an invalid escape is malformed JSON
            continue
          }
          if (c == "\\") { esc = 1; continue }
          if (c == "\"") {
            instr = 0
            if (depth() == 1 && (st == 0 || st == 5)) { key = tok; keybad = bad; st = 1 }
            else if (depth() == 1 && st == 2) {
              if (bad || keybad) print key "\te\t"
              else               print key "\ts\t" tok
              st = 3
            }
            tok = ""; bad = 0
            continue
          }
          if (c < " ") { err = 1; continue }   # a raw control byte inside a string
          tok = tok c
          continue
        }

        if (c == " " || c == "\t" || c == "\r") {
          if (st == 4) { if (!litok(lit)) err = 1; lit = ""; st = 3 }   # whitespace ends a literal
          continue
        }

        if (depth() == 0) {
          if (closed || c != "{") { err = 1; continue }
          stack = "}"; st = 0; continue
        }

        if (depth() == 1) {
          if (st == 4) {                       # consuming a bare literal
            if (c == "," || c == "}") { if (!litok(lit)) err = 1; lit = ""; st = 3 }
            else { lit = lit c; continue }
          }
          if (st == 0 || st == 5) {            # a key; after `,` (st 5) it is REQUIRED
            if (c == "}" && st == 0) { stack = ""; closed = 1; continue }
            if (c == "\"") { instr = 1; tok = ""; bad = 0; continue }
            err = 1; continue
          }
          if (st == 1) { if (c == ":") { st = 2; continue } err = 1; continue }
          if (st == 2) {
            if (c == "\"")            { instr = 1; tok = ""; bad = 0; continue }
            if (c == "{")             { print key "\tx\t"; stack = stack "}"; continue }
            if (c == "[")             { print key "\tx\t"; stack = stack "]"; continue }
            print key "\tx\t"; lit = c; st = 4; continue
          }
          # st == 3: a value has been consumed; ONLY a comma or the closing brace may follow
          if (c == ",") { st = 5; continue }
          if (c == "}") { stack = ""; closed = 1; continue }
          err = 1; continue
        }

        # depth >= 2: a value we deliberately do not interpret. DELIMITERS ARE STILL MATCHED — an
        # unbalanced or mismatched nesting ([ closed by }) would desynchronise the depth counter and
        # let a nested key be reported as top-level, which is the one way malformed input elsewhere
        # can make THIS function return a wrong answer.
        if (c == "{") { stack = stack "}"; continue }
        if (c == "[") { stack = stack "]"; continue }
        if (c == "}" || c == "]") {
          if (substr(stack, length(stack), 1) != c) { err = 1; continue }
          stack = substr(stack, 1, length(stack) - 1)
          if (depth() == 1) st = 3
          if (depth() == 0) closed = 1
          continue
        }
        if (c == "\"") { instr = 1; tok = ""; bad = 0; continue }
      }
    }
    END {
      if (st == 4 && !litok(lit)) err = 1
      if (instr || depth() != 0 || err || !closed) print "\t!\t"
    }'
}

# Extract a flat, top-level string field. rc 0 ok · 1 unreadable (reported) · 3 absent.
mi_detect_field() {
  if [ "$#" -ne 2 ]; then mi_warn "detect: mi_detect_field needs <json> and a <field>"; return 1; fi
  local json="$1" field="$2" recs hits flag val
  local LC_ALL=C
  case "$field" in ''|*[!a-z0-9_]*) mi_warn "detect: '$field' is not a field name"; return 1 ;; esac

  # Bounded HERE, before a single byte reaches the awk scanner — see MI_DETECT_MAXBYTES above for
  # why the scan itself cannot be trusted to stay cheap regardless of size.
  if [ "${#json}" -gt "$MI_DETECT_MAXBYTES" ]; then
    mi_warn "detect: the response is ${#json} bytes, more than $MI_DETECT_MAXBYTES — refusing to parse it"
    return 1
  fi

  recs="$(_mi_detect_toplevel "$json")" || { mi_warn "detect: cannot read the response"; return 1; }

  # The state machine emits a bare `!` flag when the document as a whole is unreadable — an
  # unterminated string, unbalanced braces, or trailing garbage. Any field lookup against such a
  # response is unreadable, never absent.
  if printf '%s\n' "$recs" | grep -q '^	!	$'; then
    mi_warn "detect: the response is not well-formed enough to read (unterminated string, unbalanced braces or trailing content)"
    return 1
  fi

  hits="$(printf '%s\n' "$recs" | awk -F'\t' -v k="$field" '$1==k' | wc -l | tr -d ' ')"
  case "$hits" in
    0) return 3 ;;
    1) : ;;
    *) mi_warn "detect: '$field' appears $hits times at the top level — refusing an ambiguous response"; return 1 ;;
  esac

  flag="$(printf '%s\n' "$recs" | awk -F'\t' -v k="$field" '$1==k{print $2}')"
  val="$( printf '%s\n' "$recs" | awk -F'\t' -v k="$field" '$1==k{print $3}')"
  if [ "$flag" != "s" ]; then
    mi_warn "detect: the value of '$field' is not a plain string this reader can extract"
    mi_warn "  (escapes, numbers, null and nested objects are refused rather than guessed at)"
    return 1
  fi
  printf '%s\n' "$val"
}

# D10: `version` is the product version; `image_version` is a DEPRECATED ALIAS retained for one
# release cycle. An image with no stamp reports an explicit unknown marker — it never fabricates a
# value and never inherits a sibling's, because unmeasured is not measured-clean (§9).
#
# `version` can come back three ways, and the alias is consulted for exactly two of them:
#   - ABSENT (rc 3)                     — no version was reported at all → fall back.
#   - present but EMPTY (rc 0, "")      — `""` is a syntactically valid flat string, but a product
#                                          reporting `"version":""` has no version to report, which
#                                          is exactly what the fallback is for → fall back.
#   - present but UNREADABLE (rc 1)     — an escape, a number, `null`, a nested object: something WAS
#                                          reported and this reader failed to read it. The alias must
#                                          NOT mask that: reporting `image_version` here would answer
#                                          a question about a field we failed to read with the value
#                                          of a different one, so this case alone never falls back.
mi_detect_version() {
  if [ "$#" -ne 1 ]; then mi_warn "detect: mi_detect_version needs <json>"; return 1; fi
  local v rc
  if v="$(mi_detect_field "$1" version)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ] && [ -n "$v" ]; then printf '%s\n' "$v"; return 0; fi
  # rc 1 (present but unreadable) is the ONLY case that must not fall back — see the three-way note
  # above. Both remaining cases reaching this line — rc 3 (absent) and rc 0 with an empty value —
  # are treated alike: `version` carries nothing usable, so the deprecated alias is consulted.
  if [ "$rc" -eq 1 ]; then
    printf '%s\n' "$MI_DETECT_UNKNOWN"; return 0
  fi
  if v="$(mi_detect_field "$1" image_version)" && [ -n "$v" ]; then
    printf '%s\n' "$v"; return 0
  fi
  printf '%s\n' "$MI_DETECT_UNKNOWN"
}
