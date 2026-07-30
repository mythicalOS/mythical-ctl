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

# T5: through mi_manifest_load, the `launched` key is typed `bool` (lib/doc.sh's _mi_doc_type_ok
# refuses anything but true/false at PARSE time), so mi_manifest_launched's own non-boolean arm can
# never be reached through the normal door — it only guards a caller (public, on the roster) that
# hands it hand-built records directly, the same way this file already pins mi_manifest_core_ok and
# policy.bats pins mi_policy_family_gid on hand-built records rather than only through the loader.
@test "T5: mi_manifest_launched refuses a non-boolean launch state rather than reporting it launched" {
  local records; records="$(printf 'launched\tmaybe\n')"
  run mi_manifest_launched "$records"
  [ "$status" -eq 1 ] \
    || { echo "a non-boolean launch state was not refused with rc 1: status=$status output=$output" >&2; return 1; }
  [[ "$output" == *"not true or false"* ]] \
    || { echo "output missing the malformed-value message: $output" >&2; return 1; }
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

# T5: mi_accept_manifest's OWN step 1 (`idx="$(mi_accept_index "$ixf")"`) authenticates the family
# index — as distinct from merely parsing it. Nothing above isolates this specific call: step 2
# (mi_accept_policy) re-derives its own authentication of the SAME "$ixf" from the SAME anchor, so on
# every unmutated path here a broken step 1 is silently backstopped by step 2 re-checking the
# identical file — swapping step 1's mi_accept_index for mi_index_load changes no test's outcome
# above, because mi_accept_policy still refuses. (A "no anchor at all" fixture does not isolate it
# either: mi_trust_check_only, reached later for the MANIFEST's own freshness, independently refuses
# on anchor absence too.) This test removes both backstops: the anchor IS recorded (so the later
# freshness gate's anchor-presence check is satisfied), the cached index is tampered so its real
# bytes no longer match that anchor, and mi_accept_policy is stubbed to succeed unconditionally (the
# same function-shadowing technique tests/unit/trust.bats already uses on mi_trust_anchor_get) so it
# cannot independently re-catch the tampering by re-deriving from the same file. Only step 1's own
# digest check stands between this forged index and full acceptance.
@test "T5: mi_accept_manifest's own index authentication cannot be bypassed even when the policy step is stubbed" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  mi_trust_anchor_set "$(mi_digest "$d/index")"     # anchors the REAL, untampered index

  # A forged manifest an attacker with local write access (but not the anchor) wants accepted.
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/forged-mb"

  # The cached index is rewritten to vouch for it, without ever touching the recorded anchor.
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\n' "$(mi_digest "$d/forged-mb")"; } > "$d/index"

  # Grants exactly what the forged manifest asks for, so nothing downstream of step 1 can
  # independently refuse — entitlement, min_core and launch state would all otherwise pass too.
  mi_accept_policy() {
    printf 'family_gid\t60748\n'
    printf 'brokkr.permitted_role\tstate\n'
    return 0
  }
  run mi_accept_manifest "$d/index" "$d/policy" "$d/forged-mb" brokkr
  [ "$status" -eq 1 ] \
    || { echo "a forged index was accepted through step 1 alone: status=$status output=$output" >&2; return 1; }
  [[ "$output" == *digest* ]] \
    || { echo "output missing a digest-mismatch message: $output" >&2; return 1; }
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

# --- Fix 1: mi_accept_manifest must not advance the floor before its later gates ---
#
# Before the fix, this door called mi_trust_check (check-then-commit) ahead of entitlement/min_core,
# so a manifest refused for either reason had already raised the persisted version floor — a
# publisher's typo would permanently block every future manifest at or below the refused version,
# including a perfectly good earlier one. The fix splits the door into mi_trust_check_only (here)
# and a later mi_trust_commit, placed after entitlement and min_core but before the launch-state
# check (rc 3 is still an acceptance).

@test "Fix 1: an entitlement violation leaves the version floor unchanged" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  # version=7, asking for the 'secrets' role — NOT entitled under mkindex's policy (brokkr only has
  # 'state' there). A pre-fix door would have committed floor=7 for manifest:brokkr before reaching
  # this refusal.
  printf 'mythical-manifest 1\nversion=7\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=secrets:/run/secrets\n' "$dig" > "$d/mb7"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb7")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb7" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *secrets* ]] || { echo "output missing 'secrets': $output" >&2; return 1; }
  # rc 3 = "no floor was ever recorded" (mi_trust_floor_get's own contract) — the refusal above must
  # not have written one.
  run mi_trust_floor_get "manifest:brokkr"
  [ "$status" -eq 3 ] || { echo "expected no floor recorded for manifest:brokkr, got status $status: $output" >&2; return 1; }
}

@test "Fix 1: an accepted-but-not-launched manifest still advances the version floor" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=5\nexpires=4102444800\nproduct=brokkr\nlaunched=false\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb5"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb5")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb5" brokkr
  [ "$status" -eq 3 ]
  run mi_trust_floor_get "manifest:brokkr"
  [ "$status" -eq 0 ]
  [ "$output" = "5" ] || { echo "expected floor=5 for manifest:brokkr, got: $output" >&2; return 1; }
}

# --- Fix 2: the door's freshness gate cannot be silently deleted -------------------------------------

@test "Fix 2: an expired manifest is refused through the door" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  printf 'mythical-manifest 1\nversion=1\nexpires=1\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mbx"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mbx")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mbx" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *expired* ]] || { echo "output missing 'expired': $output" >&2; return 1; }
}

@test "Fix 2: a version rollback is refused through the door" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr    # mkindex's mb is version=1
  [ "$status" -eq 0 ]

  printf 'mythical-manifest 1\nversion=2\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb2"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb2")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb2" brokkr   # floor advances to 2
  [ "$status" -eq 0 ]

  # Roll back to the original version=1 file/index — must be refused as a replay, and no floor
  # should ever have been written if freshness were skipped entirely.
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\nmanifest=skuld:%s\n' "$(mi_digest "$d/mb")" "$(mi_digest "$d/ms")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr
  [ "$status" -eq 1 ]
  [[ "$output" == *replay* ]] || { echo "output missing 'replay': $output" >&2; return 1; }
}

# --- Fix 3: the door's authentication of the policy index cannot be silently deleted -----------------
# Replacing mi_accept_policy with mi_policy_load at the door's call site would leave a locally
# tampered policy file honoured, because mi_policy_load only PARSES — it never checks the file
# against the digest the family index vouches for.

@test "Fix 3: a policy tampered with locally after the chain was built is refused, naming the digest mismatch" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  # A manifest asking for the 'secrets' role — NOT entitled under mkindex's real (untampered)
  # policy, where brokkr has only 'state'.
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=secrets:/run/secrets\n' "$dig" > "$d/mbs"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\npolicy_digest=%s\n' "$(mi_digest "$d/policy")"
    printf 'manifest=brokkr:%s\n' "$(mi_digest "$d/mbs")"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"

  # An attacker with local write access rewrites the policy file to grant the role the manifest
  # wants, WITHOUT touching the index or its already-recorded policy_digest.
  { printf 'mythical-policy 1\nversion=1\nexpires=4102444800\nfamily_gid=60748\n'
    printf 'brokkr.permitted_role=state\nbrokkr.permitted_role=secrets\nbrokkr.bindable_role=state\n'
    printf 'skuld.permitted_role=state\n'; } > "$d/policy"

  run mi_accept_manifest "$d/index" "$d/policy" "$d/mbs" brokkr
  [ "$status" -ne 0 ]
  [[ "$output" == *digest* ]] || { echo "output missing 'digest': $output" >&2; return 1; }
}

# --- Fix 5: mi_manifest_core_ok is public and must type-check min_core itself ------------------------
# Through the door, min_core is already bounded by mi_manifest_spec's `coreversion` type and
# mi_manifest_load's 3-component cap. Called directly against a hand-built records string, no such
# gate has run, and _mi_version_ge compares only the first 3 dot-components — silently ignoring a
# 4th rather than refusing it.

@test "Fix 5: mi_manifest_core_ok refuses a min_core value with a stray 4th component" {
  local records; records="$(printf 'min_core\t0.1.0.9\n')"
  run mi_manifest_core_ok "$records"
  [ "$status" -eq 1 ] || { echo "accepted an invalid min_core '0.1.0.9': $output" >&2; return 1; }
  [[ "$output" == *"0.1.0.9"* ]] || { echo "output missing the rejected value: $output" >&2; return 1; }
}

# --- Fix 6: MI_CORE_VERSION, the comparator's left operand, must itself be a valid coreversion -------
# _mi_version_ge is not called through mi_manifest_core_ok's new type gate for its OWN left operand —
# that gate only validates the manifest's min_core. MI_CORE_VERSION's validity currently rests on a
# coupling between this assertion and the smoke-test regex in tests/smoke.sh, which never reference
# each other; this test localizes the invariant so a bad MI_CORE_VERSION fails here, at its source.

@test "Fix 6: MI_CORE_VERSION is itself a valid coreversion" {
  _mi_doc_type_ok coreversion "$MI_CORE_VERSION" \
    || { echo "MI_CORE_VERSION '$MI_CORE_VERSION' is not a valid coreversion" >&2; return 1; }
}

# --- Fix 7: digest-mismatch diagnostics must name the operator's file, not the private snapshot ------

@test "Fix 7: a digest mismatch through the door names the operator's manifest path, not the temp snapshot" {
  mkindex
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' {1..64})"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  # Tamper with the manifest bytes AFTER the index has already recorded a digest for the untampered
  # ones — the door must refuse on the mismatch and name $d/mb, not the private snapshot it read.
  printf 'mythical-manifest 1\nversion=2\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\nvolume=state:/data\n' "$dig" > "$d/mb"
  run mi_accept_manifest "$d/index" "$d/policy" "$d/mb" brokkr
  [ "$status" -ne 0 ]
  [[ "$output" == *"$d/mb"* ]] || { echo "output missing the operator's path $d/mb: $output" >&2; return 1; }
  [[ "$output" != *mctl-conf.* ]] || { echo "output leaked the temp snapshot path: $output" >&2; return 1; }
}
