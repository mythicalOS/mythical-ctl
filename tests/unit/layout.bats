load '../lib/test_helper'

@test "harness runs and MYTHICAL_HOME is isolated" {
  [ -d "$MYTHICAL_HOME" ]
  run_mctl --version
  assert_ok
  assert_contains "mythical-ctl"
}

@test "__selftest sources whatever modules exist without aborting" {
  # Runs the entrypoint (under its own `set -euo pipefail`). At Task 1 no lib/ module exists yet,
  # so the guarded loop sources nothing and still prints ok — proving the dispatch and the [ -f ]
  # guard hold. As later tasks add modules, this same test proves each one sources cleanly.
  run_mctl __selftest
  assert_ok
  assert_contains "ok"
}
