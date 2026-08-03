# Test-only helpers. Never sourced by shipped code.
# Each test gets a private MYTHICAL_HOME and a PATH with tests/harness/ first,
# so the fake `docker` (added in Task 5) shadows any real one.

_MCTL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The isolation itself, callable by name. A suite that needs its own setup() MUST call this first —
# bats does not chain setup(), so defining one in a suite REPLACES the hook below.
setup_test_env() {
  MYTHICAL_HOME="$(mktemp -d)"
  export MYTHICAL_HOME
  # Fake-runtime state lives OUTSIDE MYTHICAL_HOME, or its bookkeeping (calls.log, volume
  # records) would show up in every filesystem snapshot and break non-destructive assertions
  # for the wrong reason. snap_runtime reads the same var, so they stay consistent.
  FAKE_DOCKER_STATE="$(mktemp -d)"
  export FAKE_DOCKER_STATE
  # harness dir first so the fake docker (Task 5) wins; real tools still reachable after.
  PATH="${_MCTL_ROOT}/tests/harness:${PATH}"
  export PATH
}

teardown_test_env() {
  [ -n "${MYTHICAL_HOME:-}" ] && rm -rf "$MYTHICAL_HOME"
  [ -n "${FAKE_DOCKER_STATE:-}" ] && rm -rf "$FAKE_DOCKER_STATE"
  return 0
}

setup()    { setup_test_env; }
teardown() { teardown_test_env; }

# Run the CLI under test, capturing status+output into bats' $status/$output.
run_mctl() { run "${_MCTL_ROOT}/bin/mythical-ctl" "$@"; }

# Source whichever shipped modules exist, in dependency order. Skipping absent ones lets a task's
# tests run before later tasks have created their modules (e.g. Task 2 has no lock.sh yet).
load_mctl() {
  local m f
  for m in common layout config lock ledger doc trust policy manifest detect runtime preflight exit prov intent state probe bringup netref verbs repair copy migrate; do
    f="${_MCTL_ROOT}/lib/${m}.sh"
    # shellcheck disable=SC1090
    [ -f "$f" ] && source "$f"
  done
  return 0
}

assert_ok()       { [ "$status" -eq 0 ]  || { echo "expected exit 0, got $status: $output" >&2; return 1; }; }
assert_fail()     { [ "$status" -eq "$1" ] || { echo "expected exit $1, got $status: $output" >&2; return 1; }; }
assert_contains() { case "$output" in *"$1"*) : ;; *) echo "output missing '$1': $output" >&2; return 1;; esac; }

# The fixture helper image's entrypoint. The probe and the copy tasks install real scripts here;
# until then a test that needs a helper sets FAKE_HELPER_BIN itself.
fake_helper() {
  local body="$1" p
  p="$(mktemp "${BATS_TEST_TMPDIR}/helper.XXXXXX")"
  printf '#!/usr/bin/env bash\n%s\n' "$body" > "$p"
  chmod 755 "$p"
  FAKE_HELPER_BIN="$p"; export FAKE_HELPER_BIN
}

# A digest-pinned image reference, for fixtures that need a valid `digestref`.
a_digestref() { printf 'ghcr.io/mythicalos/%s@sha256:%s\n' "${1:-fixture}" "$(printf 'a%.0s' $(seq 1 64))"; }

# The two pinned helper images every family index MUST name (mi_index_spec: `probe_image` and
# `copy_image`, both `digestref`, both cardinality `one`). Emitted from ONE place, and called by every
# index fixture in this suite, so that adding or renaming a required index key is a single edit rather
# than twenty — and so no fixture can drift into spelling one of them differently from the rest.
index_helper_images() {
  printf 'probe_image=%s\n' "$(a_digestref probe)"
  printf 'copy_image=%s\n' "$(a_digestref copy)"
}

# Install the fixture helper image's entrypoint as the thing the fake `docker container run` executes.
#
# THE FIXTURE ENTRYPOINT IS THE SPECIFICATION for the real pinned helper images (D49's probe and D54's
# copy container), which are built outside this repository: it defines the command grammar those images
# must answer. See tests/harness/helperimg for the grammar itself.
install_helper_img() {
  FAKE_HELPER_BIN="${_MCTL_ROOT}/tests/harness/helperimg"
  # Loud here rather than as "fake docker: FAKE_HELPER_BIN is not set to an executable fixture
  # entrypoint" ten frames down inside the runtime adapter: a fixture that lost its executable bit is
  # a harness problem and must not read as a probe failure.
  [ -x "$FAKE_HELPER_BIN" ] \
    || { echo "install_helper_img: $FAKE_HELPER_BIN is missing or not executable" >&2; return 1; }
  export FAKE_HELPER_BIN
}

# A VERIFIED family index at <file>: a complete `mythical-index 1` document plus the trust anchor
# recorded for it, so `mi_accept_index <file>` returns 0.
#
# Defaults emitted, in this order: version=1, expires=<now+1 day>, policy_digest, probe_image,
# copy_image. Any extra `key=value` argument is emitted verbatim AFTER them — and an argument whose KEY
# names one of those defaults REPLACES that default rather than being appended beside it.
#
# THE REPLACEMENT IS NOT A CONVENIENCE. Every default above is cardinality `one`, and mi_doc_load
# refuses a `one` key that appears twice — so a naive append would make `write_index_fixture … \
# "expires=1"` fail as a MALFORMED document rather than as the expired document the caller meant to
# build, and the test would pass or fail for the wrong reason. Keys that are not defaults (notably
# `manifest=<product>:<digest>`, cardinality `many`) are simply appended, repeats included.
#
# It writes the ledger (the anchor), so the family lock must already be held.
write_index_fixture() {
  local f="$1"; shift
  local kv key over=""
  for kv in "$@"; do over="${over}|${kv%%=*}|"; done
  {
    printf 'mythical-index 1\n'
    for kv in "version=1" \
              "expires=$(( $(date +%s) + 86400 ))" \
              "policy_digest=$(printf 'b%.0s' $(seq 1 64))" \
              "probe_image=$(a_digestref probe)" \
              "copy_image=$(a_digestref copy)"; do
      key="${kv%%=*}"
      case "$over" in *"|${key}|"*) continue ;; esac
      printf '%s\n' "$kv"
    done
    for kv in "$@"; do printf '%s\n' "$kv"; done
  } > "$f"
  mi_trust_anchor_set "$(mi_digest "$f")"
}

# A guaranteed-dead PID for stale-lock fixtures. A literal like 999999 is NOT reliably dead — Linux
# pid_max can exceed it — so spawn a child, reap it, and reuse its PID: reaped, and not reallocatable
# until the OS wraps the whole PID space (millions of spawns away), so kill -0 always reports it dead.
a_dead_pid() { local p; sh -c 'exit 0' & p=$!; wait "$p" 2>/dev/null || true; printf '%s\n' "$p"; }

# Write a complete, VERIFIED document set for a fixture product: family index, policy index and
# manifest, with the index's digests actually matching the files. Overrides are `key=value` pairs that
# REPLACE the corresponding manifest default (never append a duplicate — mi_doc_load rejects a
# `one`-cardinality key that appears twice).
write_fixture_product() {
  local p="$1"; shift
  local pol="$MYTHICAL_HOME/policy" man="$MYTHICAL_HOME/${p}.manifest" idx="$MYTHICAL_HOME/index"
  local gid=2000

  # The policy index accumulates across products, so re-read what is there and add this product's rows.
  if [ ! -f "$pol" ]; then
    { printf 'mythical-policy 1\n'; printf 'version=1\n'
      printf 'expires=%s\n' "$(( $(date +%s) + 86400 ))"
      printf 'family_gid=%s\n' "$gid"; } > "$pol"
  fi
  { printf '%s.permitted_role=state\n' "$p"
    printf '%s.permitted_role=secrets\n' "$p"
    printf '%s.bindable_role=state\n' "$p"
    printf '%s.permitted_secret=MYTHICAL_TELEMETRY_KEY\n' "$p"
    printf '%s.permitted_mount=transcripts\n' "$p"; } >> "$pol"

  # Manifest defaults, then overrides applied by key.
  local -a keys vals
  keys=(version expires product launched image min_core runtime_uid); vals=(1 "$(( $(date +%s) + 86400 ))" "$p" true "$(a_digestref "$p")" 0.1.0 900)
  local kv k v i
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"; i=0
    while [ "$i" -lt "${#keys[@]}" ]; do
      if [ "${keys[$i]}" = "$k" ]; then vals[$i]="$v"; k=""; break; fi
      i=$((i + 1))
    done
    [ -z "$k" ] || { keys+=("$k"); vals+=("$v"); }
  done
  { printf 'mythical-manifest 1\n'
    i=0; while [ "$i" -lt "${#keys[@]}" ]; do printf '%s=%s\n' "${keys[$i]}" "${vals[$i]}"; i=$((i+1)); done
    printf 'volume=state:/data\n'
    printf 'volume=secrets:/secrets\n'
    printf 'secret=MYTHICAL_TELEMETRY_KEY\n'
    printf 'mount=transcripts\n'
    printf 'port=7480\n'; } > "$man"

  # The index vouches for both, so its digests must be computed AFTER the files are final.
  { printf 'mythical-index 1\n'; printf 'version=1\n'
    printf 'expires=%s\n' "$(( $(date +%s) + 86400 ))"
    printf 'policy_digest=%s\n' "$(mi_digest "$pol")"
    printf 'probe_image=%s\n' "$(a_digestref probe)"
    printf 'copy_image=%s\n' "$(a_digestref copy)"
    local m
    for m in "$MYTHICAL_HOME"/*.manifest; do
      [ -e "$m" ] || continue
      printf 'manifest=%s:%s\n' "$(basename "$m" .manifest)" "$(mi_digest "$m")"
    done; } > "$idx"
  # The anchor and the telemetry key are BOTH ledger/config writes under the family lock. The naive
  # `printf … >> mythical.conf` the brief showed writes MYTHICAL_TELEMETRY_KEY twice on the second
  # product, which Plan 2's scanner rejects as a duplicate — so it is written through the additive,
  # idempotent sanctioned writer instead. Acquire the lock only if the caller has not.
  if [ -z "${MI_LOCK_TOKEN:-}" ]; then
    mi_lock_acquire
    mi_trust_anchor_set "$(mi_digest "$idx")"
    mi_conf_family_add MYTHICAL_TELEMETRY_KEY tk
    mi_lock_release
  else
    mi_trust_anchor_set "$(mi_digest "$idx")"
    mi_conf_family_add MYTHICAL_TELEMETRY_KEY tk
  fi
}
