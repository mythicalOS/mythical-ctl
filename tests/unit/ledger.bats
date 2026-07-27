load '../lib/test_helper'

# Simulate genuinely holding the family lock: publish a lock file and match its token. The ledger
# writer's guard checks the token against this file, so this is what a real mi_lock_acquire (Task 4)
# produces — proving the guard, not bypassing it with an env flag. MI_LOCK_TOKEN is exported so a
# `bash -c` subshell in a test inherits it (alongside MYTHICAL_HOME).
hold_lock() {
  printf 'pid=%s start=0 token=testtok\n' "$$" > "$MYTHICAL_HOME/.state/lock"
  export MI_LOCK_TOKEN=testtok
}
setup_ledger() { load_mctl; mi_ensure_layout; hold_lock; }

@test "missing ledger returns 3 and prints nothing" {
  load_mctl; mi_ensure_layout
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; mi_ledger_read'
  [ "$status" -eq 3 ]
  [ -z "$output" ]
}

@test "write then read round-trips records" {
  setup_ledger
  printf 'identity\tid=abc123\ninitialized\tproduct=brokkr\n' | mi_ledger_write
  run mi_ledger_read
  assert_ok
  assert_contains "id=abc123"
  assert_contains "product=brokkr"
}

@test "write is refused without the lock held (no token, no lock file)" {
  load_mctl; mi_ensure_layout
  # `set -euo pipefail` mirrors the shipped entrypoint: without it the writer's token-read `sed`
  # on the absent lock file would abort silently and this test would pass for the wrong reason.
  run bash -c 'set -euo pipefail; unset MI_LOCK_TOKEN; source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; printf "x\ty=1\n" | mi_ledger_write'
  [ "$status" -ne 0 ]
  assert_contains "lock"
}

@test "write is refused when the token does not match the lock file" {
  setup_ledger                            # lock file token=testtok, MI_LOCK_TOKEN=testtok
  export MI_LOCK_TOKEN=wrong-token        # now our token no longer matches the file on disk
  run bash -c 'set -euo pipefail; source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; printf "x\ty=1\n" | mi_ledger_write'
  [ "$status" -ne 0 ]
  assert_contains "lock"
}

@test "a ledger truncated by its final newline fails closed" {
  setup_ledger
  printf 'identity\tid=abc\n' | mi_ledger_write
  local f="$MYTHICAL_HOME/.state/ledger" nm1
  nm1=$(( $(wc -c < "$f") - 1 ))
  dd if="$f" of="$f.trunc" bs=1 count="$nm1" 2>/dev/null
  mv "$f.trunc" "$f"                       # file no longer ends in a newline
  run mi_ledger_read
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "newline"
}

@test "a torn ledger fails closed" {
  setup_ledger
  printf 'identity\tid=abc123\n' | mi_ledger_write
  # corrupt the body after the checksum was written
  printf 'tampered\tx=1\n' >> "$MYTHICAL_HOME/.state/ledger"
  run mi_ledger_read
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "checksum"
}

@test "a newer schema is refused, not parsed" {
  setup_ledger
  # Build a checksum-valid ledger by hand with a bumped schema, so the ONLY thing wrong is the
  # schema number. Construct header+body first, checksum that exact byte range, append the sum —
  # exactly what the writer does, so read and write agree by construction.
  local f="$MYTHICAL_HOME/.state/ledger"
  printf '#mythical-ctl-ledger schema=9999\nidentity\tid=abc\n' > "$f"
  local sum; sum="$(mi_digest "$f")"
  printf '#sha256=%s\n' "$sum" >> "$f"
  run mi_ledger_read
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "schema"
}

@test "a non-numeric schema is refused (fail closed, not parsed)" {
  setup_ledger
  local f="$MYTHICAL_HOME/.state/ledger"
  printf '#mythical-ctl-ledger schema=garbage\nidentity\tid=abc\n' > "$f"
  local sum; sum="$(mi_digest "$f")"
  printf '#sha256=%s\n' "$sum" >> "$f"
  run mi_ledger_read
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "schema"
}

@test "a HUGE numeric schema (past integer range) is still refused" {
  setup_ledger
  local f="$MYTHICAL_HOME/.state/ledger"
  # far beyond any shell integer — a naive [ -gt ] would error and fall through to parsing
  printf '#mythical-ctl-ledger schema=99999999999999999999999999\nidentity\tid=abc\n' > "$f"
  local sum; sum="$(mi_digest "$f")"
  printf '#sha256=%s\n' "$sum" >> "$f"
  run mi_ledger_read
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "schema"
}

@test "the writer refuses to clobber an existing corrupt ledger" {
  setup_ledger
  printf 'identity\tid=abc\n' | mi_ledger_write        # valid ledger exists
  printf 'garbage-appended\n' >> "$MYTHICAL_HOME/.state/ledger"  # now corrupt
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; printf "x\ty=1\n" | mi_ledger_write'
  [ "$status" -ne 0 ]
  assert_contains "validate"
  # the corrupt file must still be there — the writer preserved the evidence
  grep -q 'garbage-appended' "$MYTHICAL_HOME/.state/ledger"
}

@test "input records without a trailing newline still produce a readable ledger" {
  setup_ledger
  printf 'identity\tid=abc' | mi_ledger_write          # NOTE: no trailing newline
  run mi_ledger_read
  assert_ok
  assert_contains "id=abc"
}

@test "mi_ledger_get selects by kind and key" {
  setup_ledger
  printf 'initialized\tproduct=brokkr\ninitialized\tproduct=skuld\n' | mi_ledger_write
  run mi_ledger_get initialized product
  assert_ok
  assert_contains "brokkr"
  assert_contains "skuld"
}

@test "mi_ledger_get fails closed on a corrupt ledger (no ambient pipefail)" {
  setup_ledger
  printf 'initialized\tproduct=brokkr\n' | mi_ledger_write
  printf 'tampered\tx=1\n' >> "$MYTHICAL_HOME/.state/ledger"   # body changed after the checksum
  # The test shell has no `set -o pipefail`; a bare `mi_ledger_read | while` would swallow the
  # reader's failure and report success with no records. The captured reader must propagate instead.
  run bash -c 'set +o pipefail; source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; mi_ledger_get initialized'
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
  assert_contains "checksum"
}

@test "mi_ledger_read leaves no read-snapshot temp behind" {
  setup_ledger
  printf 'identity\tid=abc\n' | mi_ledger_write
  run mi_ledger_read
  assert_ok
  # the read path snapshots to a private .state/.ledger.read.* temp and MUST remove it
  [ -z "$(find "$MYTHICAL_HOME/.state" -name '.ledger.*' -print -quit)" ]
}

@test "ledger write fails closed when the hasher itself fails (no checksum-empty ledger)" {
  setup_ledger
  local badbin="$BATS_TEST_TMPDIR/badbin"; mkdir -p "$badbin"
  printf '#!/usr/bin/env bash\nexit 3\n' > "$badbin/sha256sum"; chmod +x "$badbin/sha256sum"
  printf '#!/usr/bin/env bash\nexit 3\n' > "$badbin/shasum";    chmod +x "$badbin/shasum"
  run env PATH="$badbin:$PATH" bash -c \
    'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; printf "identity\tid=abc\n" | mi_ledger_write'
  [ "$status" -ne 0 ]
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]     # nothing (esp. no checksum-empty ledger) was published
}

@test "ledger read fails closed when the hasher itself fails" {
  setup_ledger
  printf 'identity\tid=abc\n' | mi_ledger_write        # written with a WORKING hasher
  local badbin="$BATS_TEST_TMPDIR/badbin2"; mkdir -p "$badbin"
  printf '#!/usr/bin/env bash\nexit 3\n' > "$badbin/sha256sum"; chmod +x "$badbin/sha256sum"
  printf '#!/usr/bin/env bash\nexit 3\n' > "$badbin/shasum";    chmod +x "$badbin/shasum"
  run env PATH="$badbin:$PATH" bash -c \
    'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/ledger.sh; mi_ledger_read'
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]
}
