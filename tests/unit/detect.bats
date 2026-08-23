#!/usr/bin/env bats
load '../lib/test_helper'

setup() { setup_test_env; load_mctl; }

J='{"product":"brokkr","version":"0.1.13","ui_url":"http://localhost:7480/","components":{"ui":"0.1.12","daemon":"0.1.13"},"image_version":"0.1.13"}'

@test "the three required flat fields are extracted" {
  [ "$(mi_detect_field "$J" product)" = "brokkr" ]
  [ "$(mi_detect_field "$J" version)" = "0.1.13" ]
  [ "$(mi_detect_field "$J" ui_url)"  = "http://localhost:7480/" ]
}

@test "whitespace around the colon is tolerated" {
  [ "$(mi_detect_field '{ "product" : "brokkr" }' product)" = "brokkr" ]
}

# Space, tab and CR outside the root object are valid JSON whitespace and must not be refused — a
# product's HTTP response carrying insignificant leading/trailing whitespace is still a well-formed
# response. (A leading/trailing LF is not tested here: awk's default line splitting drops it before
# the scanner's character loop ever sees it, which is a different mechanism from the explicit
# space/tab/CR handling this test pins.) Written with printf so the whitespace bytes are exact —
# a shell literal for tab/CR would not survive quoting.
@test "leading and trailing JSON whitespace (space, tab, CR) outside the root object is accepted" {
  local f="$BATS_TEST_TMPDIR/j" ws
  for ws in ' ' "$(printf '\t')" "$(printf '\r')"; do
    printf '%s{"version":"1"}' "$ws" > "$f"
    run mi_detect_field "$(cat "$f")" version
    [ "$status" -eq 0 ] && [ "$output" = "1" ] \
      || { echo "leading whitespace rejected: status=$status output=$output" >&2; return 1; }

    printf '{"version":"1"}%s' "$ws" > "$f"
    run mi_detect_field "$(cat "$f")" version
    [ "$status" -eq 0 ] && [ "$output" = "1" ] \
      || { echo "trailing whitespace rejected: status=$status output=$output" >&2; return 1; }
  done
}

# Non-whitespace content outside the root object must still be refused. The two-object case is
# already pinned in "malformed JSON is refused" below; this adds the single-character case so the
# accept-whitespace fix above cannot be read as having widened acceptance beyond whitespace itself.
@test "non-whitespace content after the root object is still refused" {
  run mi_detect_field '{"version":"1"} x' version
  [ "$status" -eq 1 ] \
    || { echo "accepted trailing garbage: status=$status output=$output" >&2; return 1; }
}

@test "an absent field reports rc 3, distinct from unreadable" {
  run mi_detect_field "$J" nothing
  [ "$status" -eq 3 ]
}

# The nested object must not be mistaken for a flat field.
@test "a nested field is reported unreadable, never guessed at" {
  run mi_detect_field "$J" components
  [ "$status" -eq 1 ]
}

@test "a value containing an escape is refused rather than mis-decoded" {
  local j
  for j in '{"product":"a\"b"}' '{"product":"a\\b"}' '{"product":"a\nb"}'; do
    run mi_detect_field "$j" product
    [ "$status" -eq 1 ] || { echo "accepted escaped value: $j" >&2; return 1; }
  done
}

@test "a non-string value is refused" {
  run mi_detect_field '{"product":123}' product
  [ "$status" -eq 1 ]
  run mi_detect_field '{"product":null}' product
  [ "$status" -eq 1 ]
}

@test "a field name is matched whole, not as a substring" {
  [ "$(mi_detect_field '{"ui_url":"u","url":"v"}' url)" = "v" ]
}

# T4: this used to assert only `[ "$status" -eq 1 ]`, which passes even with the ambiguity gate
# itself (the `*)` arm on the hits-count case) deleted — with two hits, `flag` and `val` each
# capture TWO lines via command substitution, `[ "$flag" != "s" ]` is still true (a two-line string
# can never equal the one-char "s"), and the function returns 1 anyway from that unrelated
# downstream check. The message pins WHICH refusal actually fired.
@test "a repeated field is refused as ambiguous, not merely refused for some other reason" {
  run mi_detect_field '{"product":"a","product":"b"}' product
  [ "$status" -eq 1 ]
  [[ "$output" == *ambiguous* ]] \
    || { echo "output missing the ambiguity-gate's own message: $output" >&2; return 1; }
}

# docs/DOCUMENT-FORMAT.md's malformed-structure table used to say a repeated key is refused "at the
# top level" without qualification. In fact mi_detect_field only rejects a repeat of the field it was
# ASKED for — it checks whether its own answer is ambiguous, not whether the response contains any
# duplicate key. Pin both halves: querying the field that IS repeated is refused (already covered
# above for the single-field case); querying a DIFFERENT field succeeds even though some other
# top-level key is repeated.
@test "only a repeat of the requested field is refused; a repeat of a different top-level key is not inspected" {
  [ "$(mi_detect_field '{"x":"a","x":"b","version":"1"}' version)" = "1" ]
  run mi_detect_field '{"x":"a","x":"b","version":"1"}' x
  [ "$status" -eq 1 ] \
    || { echo "querying the repeated field itself was not refused: status=$status output=$output" >&2; return 1; }
}

# T3: the scanner's raw-control-byte gate (`if (c < " ") { err = 1; continue }`, inside a string) is
# the only thing stopping a raw TAB byte embedded in a JSON string from forging the internal
# `key<TAB>flag<TAB>value` record format that mi_detect_field splits on. Without it, a key string
# containing embedded TABs shaped like `<field><TAB>s<TAB><forged value>` bleeds straight into the
# emitted record, and the downstream `awk -F'\t' '$1==k'` lookup matches field 1 exactly — reporting
# the forged value with rc 0. The input is a product container's own HTTP response, so this is a
# record-forgery gate, not a formatting nicety. Written with `printf` so the TAB bytes are exact —
# passing `\t` as a shell string literal would write a backslash and a `t` and prove nothing (see
# the escaped-key tests below for the same discipline).
@test "T3: a raw control byte inside a JSON string cannot forge a field via the TAB-delimited record format" {
  local f="$BATS_TEST_TMPDIR/j"
  printf '{"version\ts\t9.9.9-PWNED":"x"}' > "$f"
  run mi_detect_field "$(cat "$f")" version
  [ "$status" -eq 1 ] \
    || { echo "a raw control byte forged a version field: status=$status output=$output" >&2; return 1; }
}

# --- the escaped-key asymmetry (docs/DOCUMENT-FORMAT.md: "one asymmetry worth stating plainly") ---
# Escapes are never decoded anywhere in this reader -- including in KEYS. Every escape test above
# escapes a VALUE; these two escape a KEY, which no other test in this file does. Written with
# printf so the escape bytes are exact, not eaten by shell quoting.
#
# Verified by hand against a modified copy of the scanner that decodes \uXXXX in keys (the exact
# "later improvement" this asymmetry warns about): it turns the first case's rc 3 into rc 0, and
# turns the second case's clean single-hit lookup into a false "ambiguous" refusal -- so both tests
# below would fail, silently, under that regression.

@test "a key spelled only with an escape is reported absent, never matched by its decoded spelling" {
  local f="$BATS_TEST_TMPDIR/j"
  printf '{"pro\\u0064uct":"x"}' > "$f"
  run mi_detect_field "$(cat "$f")" product
  [ "$status" -eq 3 ]
}

@test "an escaped-spelling key never masks or collides with the literal key of the same name" {
  local f="$BATS_TEST_TMPDIR/j"
  printf '{"pro\\u0064uct":"x","product":"y"}' > "$f"
  [ "$(mi_detect_field "$(cat "$f")" product)" = "y" ]
}

# Malformed SEQUENCING is refused too, not only malformed values. An earlier version reacted to the
# tokens it recognised and ignored the rest, so {"a":"1" "b":"2"} — no comma — parsed happily.
@test "malformed JSON is refused, including bad member sequencing" {
  local j
  for j in '{"product":"brokkr" "ignored":"v"}' \
           '{"product""brokkr"}' \
           '{,"product":"a"}' \
           '{"product":"a",}' \
           '{"product":"a":"b"}' \
           '{"product":}' \
           '{:"a"}' \
           '{"a":123 "product":"x"}' \
           '{"a":{"b":"c"} "product":"x"}' \
           '["product","a"]' \
           '{"product":"a"} {"product":"b"}' \
           '{"product":"a"' \
           'product' \
           ''; do
    run mi_detect_field "$j" product
    [ "$status" -eq 1 ] || { echo "accepted malformed JSON: $j" >&2; return 1; }
  done
}

# Grammar, not just character sets. Delimiters are MATCHED (an `[` closed by `}` would
# desynchronise the depth counter and let a nested key be reported as top-level — the one way
# malformed input elsewhere can make this function return a WRONG answer, as opposed to no answer);
# bare literals must be exactly true/false/null or a JSON number; escapes must be valid.
@test "malformed literals, delimiters and escapes are refused" {
  local j
  for j in '{"product":"ok","x":tru}' \
           '{"product":"ok","x":TRUE}' \
           '{"product":"ok","x":01}' \
           '{"product":"ok","x":1.}' \
           '{"product":"ok","x":+1}' \
           '{"product":"ok","x":[}}' \
           '{"product":"ok","x":[1,2}' \
           '{"product":"ok","x":{"a":1]}' \
           '{"product":"ok"}}'; do
    run mi_detect_field "$j" product
    [ "$status" -eq 1 ] || { echo "accepted malformed: $j" >&2; return 1; }
  done
  # invalid escapes, written through printf so the bytes are exact
  local f="$BATS_TEST_TMPDIR/j"
  printf '{"product":"ok","x":"\\q"}'      > "$f"; run mi_detect_field "$(cat "$f")" product; [ "$status" -eq 1 ]
  printf '{"product":"ok","x":"\\u12"}'    > "$f"; run mi_detect_field "$(cat "$f")" product; [ "$status" -eq 1 ]
  printf '{"product":"ok","x":"\\uZZZZ"}'  > "$f"; run mi_detect_field "$(cat "$f")" product; [ "$status" -eq 1 ]
}

@test "valid literals, numbers and escapes still read" {
  [ "$(mi_detect_field '{"product":"ok","x":true}'      product)" = "ok" ]
  [ "$(mi_detect_field '{"product":"ok","x":null}'      product)" = "ok" ]
  [ "$(mi_detect_field '{"product":"ok","x":-12.5e-3}'  product)" = "ok" ]
  [ "$(mi_detect_field '{"a":{},"b":[],"product":"ok"}' product)" = "ok" ]
  local f="$BATS_TEST_TMPDIR/j"
  printf '{"a":"\\u0041\\n\\t","product":"ok"}' > "$f"
  [ "$(mi_detect_field "$(cat "$f")" product)" = "ok" ]
}

# The scanner accumulates a bare literal one character at a time and only checks for its terminator
# (a comma or the closing brace) WITHIN the current awk record (line). A raw LF inside
# `true`/`false`/`null`/a number is invalid JSON -- whitespace may only separate tokens, never sit
# inside one -- so each pair below is the SAME bytes as an already-refused case in "malformed
# literals, delimiters and escapes are refused" above, just with a newline dropped into the middle
# of the literal. Before this scanner terminated an in-progress literal at a record boundary, the
# fragment before the newline and the fragment after it were validated together as though the
# newline had never happened, so these were wrongly ACCEPTED. The equivalent case for a STRING value
# is already refused (see "a raw LF inside a string" a few lines above `litok` in the scanner).
@test "a raw LF inside a bare literal is refused, matching the same bytes refused on one line" {
  local f="$BATS_TEST_TMPDIR/j"

  printf '{"product":"ok","x":tru\ne}' > "$f"          # "tru"+"e" -> "true" if joined blind
  run mi_detect_field "$(cat "$f")" product
  [ "$status" -eq 1 ] \
    || { echo "accepted a literal split tru|e by a raw LF: status=$status output=$output" >&2; return 1; }

  printf '{"product":"ok","x":1\ne2}' > "$f"           # "1"+"e2" -> "1e2" if joined blind
  run mi_detect_field "$(cat "$f")" product
  [ "$status" -eq 1 ] \
    || { echo "accepted a number split 1|e2 by a raw LF: status=$status output=$output" >&2; return 1; }

  printf '{"product":"ok","x":1\n.2}' > "$f"           # "1"+".2" -> "1.2" if joined blind
  run mi_detect_field "$(cat "$f")" product
  [ "$status" -eq 1 ] \
    || { echo "accepted a number split 1|.2 by a raw LF: status=$status output=$output" >&2; return 1; }

  printf '{"product":"ok","x":tr\nue}' > "$f"          # "tr"+"ue" -> "true" if joined blind
  run mi_detect_field "$(cat "$f")" product
  [ "$status" -eq 1 ] \
    || { echo "accepted a literal split tr|ue by a raw LF: status=$status output=$output" >&2; return 1; }
}

# The regression the fix above most plausibly causes: a bare literal is legitimately followed by
# whitespace INCLUDING a newline in ordinary pretty-printed JSON, most commonly when it is the last
# member of the object and the closing brace sits on the next line with no trailing comma. That
# newline must still terminate and VALIDATE the literal (exactly like the in-record space/tab/CR
# case just above it in the scanner), not refuse the document outright -- refusing here would be
# strictly more broken than the defect this fix closes. Every field is read to prove the whole
# document parsed cleanly: if the fix wrongly refused the response, `product`/`version`/`ui_url`
# would fail too, not just the literal-valued fields.
@test "a pretty-printed response ending each member, including bare literals, on its own line still reads" {
  local resp
  resp="$(printf '{\n  "product": "ok",\n  "version": "1.0",\n  "ui_url": "http://x",\n  "n": 3,\n  "b": true,\n  "z": null\n}')"
  [ "$(mi_detect_field "$resp" product)" = "ok" ]
  [ "$(mi_detect_field "$resp" version)" = "1.0" ]
  [ "$(mi_detect_field "$resp" ui_url)" = "http://x" ]
}

@test "well-formed responses with every value kind still read" {
  [ "$(mi_detect_field '{"product":"a","n":123,"o":{"k":"v"},"arr":[1,2],"b":true,"z":null}' product)" = "a" ]
  [ "$(mi_detect_field '{"a":{"product":"nested"},"product":"top"}' product)" = "top" ]
  [ "$(mi_detect_field '{"a":[{"product":"in-array"}],"product":"top"}' product)" = "top" ]
  [ "$(mi_detect_field "$(printf '{\n  "product" : "a" ,\n  "n" : 1\n}')" product)" = "a" ]
}

# MI_DETECT_MAXBYTES bounds the response in the SHELL, before a single byte reaches the awk scanner
# — see the constant's own comment in lib/detect.sh for why: under BSD awk (macOS's /usr/bin/awk,
# a first-class target), the scanner's per-character token accumulation is quadratic in the length of
# the value being read, so an unbounded response lets a misbehaving or hostile product stall the
# installer. Built with the bash `printf '%*s'` builtin plus `tr`, not brace expansion or `seq` —
# both are external-tool-free, portable, and the size tracks the constant rather than a hardcoded
# literal that could silently stop being "one over the cap" if the constant ever changes.
@test "a response over the byte cap is refused before parsing, and the message names the cap" {
  local n=$((MI_DETECT_MAXBYTES + 1))
  local big; big="$(printf '%*s' "$n" '' | tr ' ' 'a')"
  local j="{\"product\":\"x\",\"version\":\"${big}\"}"
  [ "${#j}" -gt "$MI_DETECT_MAXBYTES" ]   # the fixture itself must be over the cap, or this proves nothing
  run mi_detect_field "$j" version
  [ "$status" -eq 1 ] || { echo "an over-cap response was not refused: status=$status output=$output" >&2; return 1; }
  [[ "$output" == *"$MI_DETECT_MAXBYTES"* ]] \
    || { echo "output does not name the cap $MI_DETECT_MAXBYTES: $output" >&2; return 1; }
}

@test "a response exactly at the byte cap is still read" {
  local j0='{"product":""}'
  local overhead=${#j0}   # the fixed bytes around the value, measured rather than hand-counted
  local pad=$((MI_DETECT_MAXBYTES - overhead))
  local val; val="$(printf '%*s' "$pad" '' | tr ' ' 'a')"
  local j="{\"product\":\"${val}\"}"
  [ "${#j}" -eq "$MI_DETECT_MAXBYTES" ] \
    || { echo "fixture is ${#j} bytes, not exactly the $MI_DETECT_MAXBYTES cap" >&2; return 1; }
  [ "$(mi_detect_field "$j" product)" = "$val" ]
}

# --- D10: the deprecated alias ---

@test "version is preferred, and image_version is the fallback" {
  [ "$(mi_detect_version "$J")" = "0.1.13" ]
  [ "$(mi_detect_version '{"product":"x","image_version":"9.9"}')" = "9.9" ]
}

@test "a response with neither version field reports the unknown marker, never a fabricated value" {
  [ "$(mi_detect_version '{"product":"x"}')" = "unknown" ]
}

@test "a version is never inherited from a sibling field" {
  run mi_detect_version '{"product":"x","components":{"ui":"1.2.3"}}'
  [ "$output" = "unknown" ]
}

@test "an empty version string falls back to the deprecated alias, exactly like an absent one" {
  [ "$(mi_detect_version '{"product":"x","version":"","image_version":"9.9"}')" = "9.9" ]
}

@test "a present-but-unreadable version is reported unknown and never falls back to the alias" {
  [ "$(mi_detect_version '{"product":"x","version":123,"image_version":"9.9"}')" = "unknown" ]
}
