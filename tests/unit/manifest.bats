#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env
  load_mctl
  # The cross-chain tests below write the ledger (anchors and version floors), and every ledger
  # write proves lock ownership — so the layout and the lock are part of this suite's setup, not an
  # optional extra. Without them those tests fail before they reach the chain.
  mi_ensure_layout
  mi_lock_acquire
  F="$MYTHICAL_HOME/manifest"
  P="$MYTHICAL_HOME/policy"
  DIG="sha256:$(printf 'a%.0s' {1..64})"
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.permitted_role=secrets\n'
    printf 'brokkr.bindable_role=state\n'
    printf 'brokkr.permitted_secret=MYTHICAL_TELEMETRY_KEY\n'
    printf 'brokkr.permitted_mount=transcripts\n'; } > "$P"
  POL="$(mi_policy_load "$P")"
}

man() { { printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\n'
          printf 'image=ghcr.io/example/brokkr@%s\n' "$DIG"
          printf '%s\n' "$1"; } > "$F"; }

@test "a valid manifest loads" {
  man "$(printf 'volume=state:/data\nsecret=MYTHICAL_TELEMETRY_KEY\nmount=transcripts\nport=7480')"
  run mi_manifest_load "$F"
  [ "$status" -eq 0 ]
}

# --- D22: image-reference policy ---

@test "a digest-pinned image is required; a tag is refused" {
  local ref
  for ref in 'ghcr.io/example/brokkr:latest' 'ghcr.io/example/brokkr' 'brokkr:1.2.3' \
             'ghcr.io/example/brokkr@sha256:short' 'ghcr.io/example/brokkr@md5:abc'; do
    { printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=%s\n' "$ref"; } > "$F"
    run mi_manifest_load "$F"
    [ "$status" -eq 1 ] || { echo "accepted unpinned reference '$ref'" >&2; return 1; }
  done
}

@test "mi_manifest_image returns the pinned reference" {
  man ''
  local m; m="$(mi_manifest_load "$F")"
  [ "$(mi_manifest_image "$m")" = "ghcr.io/example/brokkr@$DIG" ]
}

# --- §7.3: launch state is declared, not inferred ---

@test "launched=false reports rc 3 — the not-launched contract code" {
  { printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=false\nmin_core=0.1.0\n'
    printf 'image=ghcr.io/example/brokkr@%s\n' "$DIG"; } > "$F"
  local m; m="$(mi_manifest_load "$F")"
  run mi_manifest_launched "$m"
  [ "$status" -eq 3 ]
}

@test "launched=true reports rc 0" {
  man ''
  run mi_manifest_launched "$(mi_manifest_load "$F")"
  [ "$status" -eq 0 ]
}

@test "a missing launched field is refused — launch state is never inferred" {
  { printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nmin_core=0.1.0\n'
    printf 'image=ghcr.io/example/brokkr@%s\n' "$DIG"; } > "$F"
  run mi_manifest_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *launched* ]]
}

# --- §8.1: entitlement enforcement ---

@test "a manifest selecting only entitled things passes the check" {
  man "$(printf 'volume=state:/data\nvolume=secrets:/run/secrets\nsecret=MYTHICAL_TELEMETRY_KEY\nmount=transcripts')"
  run mi_manifest_check "$(mi_manifest_load "$F")" "$POL"
  [ "$status" -eq 0 ]
}

@test "a manifest asking for a role it is not entitled to is rejected" {
  man "$(printf 'volume=siblings:/data')"
  run mi_manifest_check "$(mi_manifest_load "$F")" "$POL"
  [ "$status" -eq 1 ]
  [[ "$output" == *siblings* ]]
}

@test "a manifest asking for a secret outside its namespace is rejected" {
  man "$(printf 'secret=MYTHICAL_SKULD_SECRET')"
  run mi_manifest_check "$(mi_manifest_load "$F")" "$POL"
  [ "$status" -eq 1 ]
  [[ "$output" == *MYTHICAL_SKULD_SECRET* ]]
}

@test "a manifest asking for a mount it is not entitled to is rejected" {
  man "$(printf 'mount=logs')"
  run mi_manifest_check "$(mi_manifest_load "$F")" "$POL"
  [ "$status" -eq 1 ]
}

@test "a manifest for a product the policy index does not know is rejected" {
  { printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=ghost\nlaunched=true\n'
    printf 'min_core=0.1.0\nimage=ghcr.io/example/ghost@%s\nvolume=state:/data\n' "$DIG"; } > "$F"
  run mi_manifest_check "$(mi_manifest_load "$F")" "$POL"
  [ "$status" -eq 1 ]
}

# Decisions item 5: the manifest grammar has no bindable key, so claiming one is a rejection.
@test "a manifest declaring bindability is rejected" {
  man "$(printf 'bindable_role=secrets')"
  run mi_manifest_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *bindable_role* ]]
}

# §4b.2 / §10a: network mode host and container:<name> are rejected from the manifest as well as
# from mythical.conf.
@test "a manifest cannot choose a network at all" {
  man "$(printf 'network=host')"
  run mi_manifest_load "$F"
  [ "$status" -eq 1 ]
}

# §8: every manifest declares the minimum core it needs, and the core refuses a product that needs
# a newer one. Authentic is not the same as compatible.
@test "a manifest requiring a newer core is refused, even when fully authentic" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=99.0.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\n' "$(mi_digest "$d/mb")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *99.0.0* ]]
}

@test "a manifest with no min_core is refused — unstated must not mean any core will do" {
  local dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nimage=r@%s\n' "$dig" > "$F"
  run mi_manifest_load "$F"
  [ "$status" -eq 1 ]
  [[ "$output" == *min_core* ]]
}

@test "the version comparator orders components numerically, not lexically" {
  _mi_version_ge 0.1.0 0.1.0
  _mi_version_ge 0.1.0 0.0.9
  _mi_version_ge 10.0.0 9.9.9
  _mi_version_ge 1 0.9.9
  _mi_version_ge 0.1 0.1.0
  ! _mi_version_ge 0.1.0 0.1.1
  ! _mi_version_ge 2.0.0 10.0.0
  ! _mi_version_ge 0.1.0 99999999999999999999
}

@test "the core version tracks the entrypoint's VERSION" {
  local v; v="$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "${_MCTL_ROOT}/bin/mythical-ctl")"
  [ -n "$v" ]
  [ "$MI_CORE_VERSION" = "$v" ]
}

@test "coreversion accepts MAJOR[.MINOR[.PATCH]] and nothing else" {
  local v
  for v in 1 1.2 1.2.3 0 10.20.30; do
    _mi_doc_type_ok coreversion "$v" || { echo "rejected valid version '$v'" >&2; return 1; }
  done
  for v in '' '.' '1.' '.1' '1..2' '1.2.3.4' 'v1' '1.2.3-rc1' '1 2' '1.a'; do
    ! _mi_doc_type_ok coreversion "$v" || { echo "accepted invalid version '$v'" >&2; return 1; }
  done
}

# --- core-derived naming (D32) ---

@test "names are derived from the installation identity plus the product" {
  [ "$(mi_name_volume inst1 brokkr state)"  = "mythical-inst1-brokkr-state" ]
  [ "$(mi_name_container inst1 brokkr)"     = "mythical-inst1-brokkr" ]
  [ "$(mi_name_network inst1)"              = "mythical-inst1-net" ]
}

@test "two installations derive different names for the same product and role" {
  [ "$(mi_name_volume inst1 brokkr state)" != "$(mi_name_volume inst2 brokkr state)" ]
}

# §8/§4b.4: the network ALIAS stays the bare product name so family discovery keeps working.
@test "the network alias is the bare product name, not the derived one" {
  # `mythical-brokkr`, NOT `brokkr` — the name every sibling actually resolves (see the function's
  # own comment). The bare form here is what a reader "fixes" it back to, so the assertion is
  # explicit about which of the family's two names this is.
  [ "$(mi_name_alias brokkr)" = "mythical-brokkr" ]
  [ "$(mi_name_alias saga)" = "mythical-saga" ]
}

@test "name derivation refuses inputs that are not identifiers" {
  local bad
  for bad in 'Inst' 'in st' '../x' '' 'x/y' '-lead'; do
    run mi_name_volume "$bad" brokkr state
    [ "$status" -ne 0 ] || { echo "accepted identity '$bad'" >&2; return 1; }
    run mi_name_volume inst1 "$bad" state
    [ "$status" -ne 0 ] || { echo "accepted product '$bad'" >&2; return 1; }
  done
}

# The cross-chain tests live HERE, not in the trust suite: they exercise mi_accept_policy and
# mi_accept_manifest, which do not exist until Tasks 3 and 4. A suite that calls a later task's
# functions cannot pass at its own task's Step 4.
mkindex() {   # writes $MYTHICAL_HOME/{policy,mb,ms,index}
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.bindable_role=state\n'
    printf 'skuld.permitted_role=state\n'; } > "$d/policy"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=skuld\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/ms"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb")" "$(mi_digest "$d/ms")"; } > "$d/index"
}

@test "every acceptance path verifies and parses one snapshot, never the live file twice" {
  local src="${_MCTL_ROOT}/lib" pair mod fn body
  for pair in "trust.sh:mi_accept_index" "policy.sh:mi_accept_policy" "manifest.sh:mi_accept_manifest"; do
    mod="${pair%%:*}"; fn="${pair#*:}"
    body="$(awk -v f="${fn}() {" 'index($0,f)==1,/^\}/' "$src/$mod")"
    [ -n "$body" ] || { echo "range for $fn matched nothing — the check would pass vacuously" >&2; return 1; }
    printf '%s' "$body" | grep -qF '_mi_conf_snap "$f"' \
      || { echo "$fn does not snapshot the document" >&2; return 1; }
    printf '%s' "$body" | grep -qF 'mi_trust_verify_digest "$snap"' \
      || { echo "$fn verifies something other than the snapshot" >&2; return 1; }
    if printf '%s' "$body" | grep -qE 'mi_(index|policy|manifest)_load "\$f"'; then
      echo "$fn parses the live file after verifying" >&2; return 1
    fi
  done
}

@test "a forged record blob passed where a file belongs is refused" {
  mkindex
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  # a blob that, if it were believed, would vouch for anything
  local forged; forged="$(printf 'policy_digest\t%s\nmanifest\tbrokkr:%s\n' \
                          "$(mi_digest "$MYTHICAL_HOME/policy")" "$(mi_digest "$MYTHICAL_HOME/mb")")"
  run mi_accept_manifest "$forged" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mb" brokkr
  [ "$status" -ne 0 ]
  run mi_accept_policy "$forged" "$MYTHICAL_HOME/policy"
  [ "$status" -ne 0 ]
}

# Authentication is RE-DERIVED on every call, not carried over from an earlier one. Changing the
# anchor must invalidate the very same files that were accepted a moment ago.
@test "the anchor is consulted on every acceptance, not cached from a previous one" {
  mkindex
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  run mi_accept_manifest "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mb" brokkr
  [ "$status" -eq 0 ]

  mi_trust_anchor_set "$(printf 'b%.0s' {1..64})"      # a different, legitimate-looking anchor
  run mi_accept_manifest "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mb" brokkr
  [ "$status" -ne 0 ]
  [[ "$output" == *digest* ]]
}

@test "the chain accepts an untampered index, policy and manifest" {
  mkindex
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  local pol
  run mi_accept_index "$MYTHICAL_HOME/index"
  [ "$status" -eq 0 ]
  pol="$(mi_accept_policy "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy")"
  [ "$(mi_policy_family_gid "$pol")" = "60748" ]
  run mi_accept_manifest "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mb" brokkr
  [ "$status" -eq 0 ]
}

# §10a: "manifest for a different product". A perfectly valid, correctly-digested SIBLING manifest
# is still the wrong answer to a request for brokkr.
# The index must VOUCH for the file under brokkr's name, or the digest check refuses first and this
# test passes without ever reaching the identity comparison. Verified by mutation: disabling the
# product check leaves the naive version green and this one red.
@test "a manifest the index vouches for, but which declares another product, is refused" {
  mkindex
  local d="$MYTHICAL_HOME"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\n' "$(mi_digest "$d/ms")"; } > "$d/index"   # brokkr → the SKULD file
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/ms" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *skuld* ]] || { echo "output missing skuld: $output" >&2; return 1; }
  [[ "$output" == *requested* ]]
}

@test "tampering at any level of the chain is refused" {
  mkindex
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  printf 'mythical-manifest 1\nversion=9\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@sha256:%s\n' "$(printf 'a%.0s' {1..64})" > "$MYTHICAL_HOME/mb"
  run mi_accept_manifest "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mb" brokkr
  [ "$status" -eq 1 ]

  printf 'mythical-policy 1\nversion=1\nfamily_gid=1\nbrokkr.permitted_role=secrets\n' > "$MYTHICAL_HOME/policy"
  run mi_accept_policy "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy"
  [ "$status" -eq 1 ]

  printf 'mythical-index 1\nversion=99\nexpires=4102444800\npolicy_digest=%s\n' "$(printf 'a%.0s' {1..64})" > "$MYTHICAL_HOME/index"
  run mi_accept_index "$MYTHICAL_HOME/index"
  [ "$status" -eq 1 ]
}

# An index that does not list a product is a REFUSAL, not silence.
@test "a product the index does not vouch for is refused" {
  mkindex
  mi_trust_anchor_set "$(mi_digest "$MYTHICAL_HOME/index")"
  local dig; dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=saga\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\n' "$dig" > "$MYTHICAL_HOME/mg"
  run mi_accept_manifest "$MYTHICAL_HOME/index" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/mg" saga
  [ "$status" -eq 1 ]
  [[ "$output" == *vouch* ]]
}

# §7.3's contract code, carried through the door: authentic, but declares it has not launched.
@test "an authentic not-launched manifest reports rc 3, not 0" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=false\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\n' "$(mi_digest "$d/mb")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr
  [ "$status" -eq 3 ]
}

@test "the manifest cannot supply a name — only a role" {
  man "$(printf 'volume_name=mythical-skuld-state')"
  run mi_manifest_load "$F"
  [ "$status" -eq 1 ]
}

# An authentic, correctly-attributed manifest can still ask for more than the policy index grants
# it. Every other refusal in this suite is caught closer to its own cause (mi_manifest_check has
# direct tests above), but THE DOOR is the thing that promises to walk every step — so it needs its
# own witness that entitlement enforcement is actually wired into mi_accept_manifest, not only into
# the function it calls. Verified by mutation: deleting the `mi_manifest_check` call from
# mi_accept_manifest leaves every other test in this file green, and only this one goes red.
@test "an entitlement violation is refused by the door itself, not only by mi_manifest_check" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  # mkindex's policy grants brokkr only the 'state' role — 'secrets' is not among its entitlements.
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=secrets:/run/secrets\n' "$dig" > "$d/mb"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *secrets* ]]
}
