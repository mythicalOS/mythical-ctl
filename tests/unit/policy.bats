#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env
  load_mctl
  F="$MYTHICAL_HOME/policy"
}

# family_gid is REQUIRED (D60), so every fixture that is meant to be otherwise valid carries it.
pol() { { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'; printf '%s\n' "$1"; } > "$F"; }

VALID='brokkr.permitted_role=state
brokkr.permitted_role=secrets
brokkr.bindable_role=state
brokkr.permitted_secret=MYTHICAL_TELEMETRY_KEY
brokkr.permitted_mount=transcripts
skuld.permitted_role=state
skuld.bindable_role=state'

@test "a valid policy index loads" {
  pol "$VALID"
  run mi_policy_load "$F"
  [ "$status" -eq 0 ]
}

# D53 / §10a: "policy index collapsing permitted and bindable | rejected as malformed — a secrets
# role must be permitted AND non-bindable, which one list cannot express".
@test "a bindable role that is not permitted is rejected" {
  pol "$(printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=logs')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *logs* ]] || { echo "output missing logs: $output" >&2; return 1; }
  [[ "$output" == *permitted* ]]
}

@test "a bindable SECRETS role is rejected outright" {
  pol "$(printf 'brokkr.permitted_role=secrets\nbrokkr.bindable_role=secrets')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *secrets* ]]
}

@test "a permitted secrets role that is NOT bindable is fine — that is the point of two lists" {
  pol "$(printf 'brokkr.permitted_role=secrets\nbrokkr.permitted_role=state\nbrokkr.bindable_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 0 ]
}

@test "entitlements do not bleed between products" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" brokkr role secrets;  [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  role secrets;  [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr secret MYTHICAL_TELEMETRY_KEY; [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  secret MYTHICAL_TELEMETRY_KEY; [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr mount transcripts; [ "$status" -eq 0 ]
  run mi_policy_permits "$p" skuld  mount transcripts; [ "$status" -ne 0 ]
}

@test "an unknown product is entitled to nothing" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" ghost role state
  [ "$status" -ne 0 ]
}

@test "bindable is queried separately from permitted" {
  pol "$VALID"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_bindable "$p" brokkr state;   [ "$status" -eq 0 ]
  run mi_policy_bindable "$p" brokkr secrets; [ "$status" -ne 0 ]
  run mi_policy_permits  "$p" brokkr role secrets; [ "$status" -eq 0 ]
}

@test "a value substring does not satisfy an entitlement" {
  pol "$(printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state')"
  local p; p="$(mi_policy_load "$F")"
  run mi_policy_permits "$p" brokkr role stat;    [ "$status" -ne 0 ]
  run mi_policy_permits "$p" brokkr role states;  [ "$status" -ne 0 ]
}

@test "a product name that is not an identifier is rejected" {
  pol "$(printf 'Brokkr.permitted_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

# A product-prefixed document key is meaningless; an unprefixed entitlement grants nobody anything.
# Both used to validate, which on the authorization document is a silent misconfiguration.
# D60's gid is what makes the amended Plan 2 signature answerable. Declared `one` in the spec and
# required by nothing, a policy would authenticate, load, and then answer "absent" to it.
@test "a policy without family_gid is rejected" {
  { printf 'mythical-policy 1\nversion=1\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *family_gid* ]]
}

@test "a repeated document key is rejected — freshness must not be ambiguous" {
  pol "$(printf 'brokkr.permitted_role=state')"
  # two version lines: the header already supplies one
  { printf 'mythical-policy 1\nversion=1\nversion=2\nfamily_gid=60748\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *version* ]] || { echo "output missing version: $output" >&2; return 1; }
  { printf 'mythical-policy 1\nversion=1\nfamily_gid=60748\nexpires=1\nexpires=2\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "document keys may not be product-prefixed" {
  pol "$(printf 'brokkr.version=99')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  pol "$(printf 'brokkr.expires=5')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "entitlement keys must be product-prefixed" {
  pol "$(printf 'permitted_role=state')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *permitted_role* ]]
}

@test "an unknown entitlement key is rejected, not ignored" {
  pol "$(printf 'brokkr.permitted_everything=yes')"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "the wrong document type is rejected" {
  { printf 'mythical-manifest 1\nversion=1\nfamily_gid=60748\nbrokkr.permitted_role=state\n'; } > "$F"
  run mi_policy_load "$F"
  [ "$status" -eq 1 ]
}

@test "the query functions refuse bad arity instead of aborting under set -u" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger doc trust policy; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_policy_permits "" brokkr; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]] || { echo "continued past UNREACHABLE (arity guard did not abort): $output" >&2; return 1; }
  [[ "$output" != *"unbound variable"* ]]
}
