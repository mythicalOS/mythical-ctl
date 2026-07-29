#!/usr/bin/env bats
load '../lib/test_helper'

# setup_test_env FIRST. Defining setup() here REPLACES the helper's hook — bats does not chain —
# so without it MYTHICAL_HOME is unset and the suite writes into the engineer's real home.
setup() {
  setup_test_env
  load_mctl
  SPEC="$(printf 'MYTHICAL_A\tstr:16\nMYTHICAL_N\tint:1:100\nMYTHICAL_E\tenum:red|green\nMYTHICAL_B\tbool\nMYTHICAL_P\tpath:64\nMYTHICAL_NET\tnetname')"
  F="$MYTHICAL_HOME/t.conf"
}

@test "an unknown key is REJECTED, not ignored" {
  printf 'MYTHICAL_A=ok\nMYTHICAL_UNKNOWN=x\n' > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *MYTHICAL_UNKNOWN* ]]
}

@test "a valid file emits validated records" {
  printf 'MYTHICAL_A=hello\nMYTHICAL_N=42\n' > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "$(printf 'MYTHICAL_A\thello')" ]
  [ "${lines[1]}" = "$(printf 'MYTHICAL_N\t42')" ]
}

@test "str rejects an over-length value" {
  printf 'MYTHICAL_A=%s\n' "01234567890123456789" > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 1 ]
}

@test "int rejects out-of-range, non-numeric, and empty" {
  local v
  for v in 0 101 abc 1x '' ' 5' +5; do
    printf 'MYTHICAL_N=%s\n' "$v" > "$F"
    run mi_conf_load "$F" "$SPEC"
    [ "$status" -eq 1 ] || { echo "int accepted '$v'" >&2; return 1; }
  done
}

@test "int accepts the inclusive bounds" {
  local v
  for v in 1 100 50; do
    printf 'MYTHICAL_N=%s\n' "$v" > "$F"
    run mi_conf_load "$F" "$SPEC"
    [ "$status" -eq 0 ] || { echo "int rejected '$v'" >&2; return 1; }
  done
}

@test "int does not overflow on an absurdly long number" {
  printf 'MYTHICAL_N=999999999999999999999999999999\n' > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 1 ]
}

@test "int rejects a leading zero — [ -ge ] would re-read it as octal" {
  local v
  for v in 010 007 00 0100; do
    printf 'MYTHICAL_N=%s\n' "$v" > "$F"
    run mi_conf_load "$F" "$SPEC"
    [ "$status" -eq 1 ] || { echo "int accepted leading-zero '$v'" >&2; return 1; }
  done
}

# The enum test puts an attacker-controlled value into a `case` PATTERN. It is written as
# *"|${v}|"* — the QUOTES are load-bearing: a quoted expansion inside a pattern matches literally,
# so glob metacharacters in the value are inert. Unquoted, `d*` would match `dark` and the whole
# enum check would be bypassable. Verified on bash 3.2.57. This test exists so that a future edit
# dropping the quotes fails loudly instead of silently opening the hole.
@test "a glob metacharacter in a value does not match an enum member" {
  local v
  for v in 'r*' '*' '?' 're?' '[rg]reen' 'gre*'; do
    printf 'MYTHICAL_E=%s\n' "$v" > "$F"
    run mi_conf_load "$F" "$SPEC"
    [ "$status" -eq 1 ] || { echo "enum matched glob value '$v'" >&2; return 1; }
  done
}

# Quoting makes glob metacharacters inert, but the DELIMITER is a separate hole: 'red|green'
# matches the joined list "|red|green|" exactly, so it would be accepted as a member.
@test "a value containing the enum delimiter is rejected" {
  local v
  for v in 'red|green' 'red|' '|green' 'red|blue'; do
    printf 'MYTHICAL_E=%s\n' "$v" > "$F"
    run mi_conf_load "$F" "$SPEC"
    [ "$status" -eq 1 ] || { echo "enum accepted delimiter value '$v'" >&2; return 1; }
  done
}

@test "enum accepts only listed values, and is not a substring match" {
  printf 'MYTHICAL_E=red\n'   > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_E=green\n' > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_E=blue\n'  > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_E=re\n'    > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_E=redgreen\n' > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_E=\n'      > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
}

@test "bool accepts exactly true and false" {
  printf 'MYTHICAL_B=true\n'  > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_B=false\n' > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_B=1\n'     > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_B=True\n'  > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
}

@test "path requires absolute and refuses a .. component" {
  printf 'MYTHICAL_P=/srv/data\n'      > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_P=relative/x\n'     > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_P=/srv/../etc\n'    > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_P=/srv/..hidden\n'  > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_P=\n'               > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
}

# §4b.2 / §10a: network mode host and container:<name> are rejected from mythical.conf.
@test "netname refuses host and container: modes" {
  printf 'MYTHICAL_NET=mythical-net\n'   > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 0 ]
  printf 'MYTHICAL_NET=host\n'           > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_NET=container:brokkr\n' > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_NET=none\n'           > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_NET=-leading-dash\n'  > "$F"; run mi_conf_load "$F" "$SPEC"; [ "$status" -eq 1 ]
}

# Rejection must emit NOTHING. Printing valid records as they are found would hand a consumer a
# PREFIX of attacker-influenced configuration whenever a later record is rejected — the file
# "fails", but its first keys are already on stdout for anyone piping this or mishandling status.
@test "a valid record followed by an invalid one emits nothing at all" {
  printf 'MYTHICAL_A=fine\nMYTHICAL_UNKNOWN=x\n' > "$F"
  local out; out="$(mi_conf_load "$F" "$SPEC" 2>/dev/null || true)"
  [ -z "$out" ]
}

@test "a malformed file fails validation without reaching the spec" {
  printf 'MYTHICAL_A=$(id)\n' > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 1 ]
}

@test "a missing file reports rc 3" {
  run mi_conf_load "$MYTHICAL_HOME/absent.conf" "$SPEC"
  [ "$status" -eq 3 ]
}

@test "an absent key in a present file is not an error — defaults are the caller's business" {
  printf 'MYTHICAL_A=x\n' > "$F"
  run mi_conf_load "$F" "$SPEC"
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 1 ]
}

@test "mi_conf_get returns one value, rc 3 when absent" {
  printf 'MYTHICAL_A=x\nMYTHICAL_N=7\n' > "$F"
  run mi_conf_get "$F" MYTHICAL_N
  [ "$status" -eq 0 ]
  [ "$output" = "7" ]
  run mi_conf_get "$F" MYTHICAL_MISSING
  [ "$status" -eq 3 ]
}

@test "mi_conf_get propagates a parse failure instead of reporting absent" {
  printf 'MYTHICAL_A=`id`\n' > "$F"
  run mi_conf_get "$F" MYTHICAL_A
  [ "$status" -eq 1 ]
}
