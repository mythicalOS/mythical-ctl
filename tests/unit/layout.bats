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

@test "mi_ensure_layout creates the managed subtree, idempotently" {
  load_mctl
  mi_ensure_layout
  [ -d "$MYTHICAL_HOME/bin" ]
  [ -d "$MYTHICAL_HOME/.state" ]
  # second run must not error and must not change what exists
  local before; before="$(cd "$MYTHICAL_HOME" && find . | sort)"
  mi_ensure_layout
  local after;  after="$(cd "$MYTHICAL_HOME" && find . | sort)"
  [ "$before" = "$after" ]
}

@test "mi_ensure_layout never touches transcripts or logs" {
  load_mctl
  mkdir -p "$MYTHICAL_HOME/transcripts"
  echo secret > "$MYTHICAL_HOME/transcripts/keep"
  mi_ensure_layout
  [ "$(cat "$MYTHICAL_HOME/transcripts/keep")" = secret ]
}

@test "mi_zone classifies paths by ownership class" {
  load_mctl
  [ "$(mi_zone bin/mythical-ctl)"        = installer-managed ]
  [ "$(mi_zone .state/ledger)"           = installer-state ]
  [ "$(mi_zone brokkr.conf)"             = user-owned ]
  [ "$(mi_zone mythical.conf)"           = user-owned ]
  [ "$(mi_zone transcripts/x.jsonl)"     = user-data ]
  [ "$(mi_zone logs/sessions/y)"         = user-data ]
  [ "$(mi_zone brokkr/compose.yaml)"     = installer-managed ]
  [ "$(mi_zone brokkr/generated.conf)"   = installer-managed ]   # nested .conf is NOT user-owned
  [ "$(mi_zone something-else)"          = unknown ]
}

@test "mi_digest matches a known sha256" {
  load_mctl
  printf 'abc' > "$MYTHICAL_HOME/f"
  # sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  [ "$(mi_digest "$MYTHICAL_HOME/f")" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]
}

@test "mi_ensure_layout fails loudly when it cannot create the subtree" {
  load_mctl
  # A regular FILE as the parent makes mkdir -p under it fail deterministically (no chmod needed).
  local blocker="$BATS_TEST_TMPDIR/blocker"; : > "$blocker"
  run env MYTHICAL_HOME="$blocker/home" bash -c \
    'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; mi_ensure_layout'
  [ "$status" -ne 0 ]
  assert_contains "cannot create"
}
