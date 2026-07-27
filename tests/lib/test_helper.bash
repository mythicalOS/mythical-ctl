# Test-only helpers. Never sourced by shipped code.
# Each test gets a private MYTHICAL_HOME and a PATH with tests/harness/ first,
# so the fake `docker` (added in Task 5) shadows any real one.

_MCTL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

setup() {
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

teardown() {
  [ -n "${MYTHICAL_HOME:-}" ] && rm -rf "$MYTHICAL_HOME"
  [ -n "${FAKE_DOCKER_STATE:-}" ] && rm -rf "$FAKE_DOCKER_STATE"
}

# Run the CLI under test, capturing status+output into bats' $status/$output.
run_mctl() { run "${_MCTL_ROOT}/bin/mythical-ctl" "$@"; }

# Source whichever shipped modules exist, in dependency order. Skipping absent ones lets a task's
# tests run before later tasks have created their modules (e.g. Task 2 has no lock.sh yet).
load_mctl() {
  local m f
  for m in common layout lock ledger; do
    f="${_MCTL_ROOT}/lib/${m}.sh"
    # shellcheck disable=SC1090
    [ -f "$f" ] && source "$f"
  done
  return 0
}

assert_ok()       { [ "$status" -eq 0 ]  || { echo "expected exit 0, got $status: $output" >&2; return 1; }; }
assert_fail()     { [ "$status" -eq "$1" ] || { echo "expected exit $1, got $status: $output" >&2; return 1; }; }
assert_contains() { case "$output" in *"$1"*) : ;; *) echo "output missing '$1': $output" >&2; return 1;; esac; }

# A guaranteed-dead PID for stale-lock fixtures. A literal like 999999 is NOT reliably dead — Linux
# pid_max can exceed it — so spawn a child, reap it, and reuse its PID: reaped, and not reallocatable
# until the OS wraps the whole PID space (millions of spawns away), so kill -0 always reports it dead.
a_dead_pid() { local p; sh -c 'exit 0' & p=$!; wait "$p" 2>/dev/null || true; printf '%s\n' "$p"; }
