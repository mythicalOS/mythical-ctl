load '../lib/test_helper'

@test "acquire then release round-trips and sets the token" {
  load_mctl; mi_ensure_layout
  mi_lock_acquire
  [ "$MI_LOCK_HELD" = 1 ]
  [ -n "$MI_LOCK_TOKEN" ]
  [ -f "$MYTHICAL_HOME/.state/lock" ]
  mi_lock_release
  [ ! -e "$MYTHICAL_HOME/.state/lock" ]
}

@test "a live holder blocks a second acquire and names the holder" {
  load_mctl; mi_ensure_layout
  # plant a live holder as a lock FILE (our own PID is alive)
  printf 'pid=%s start=0 token=other\n' "$$" > "$MYTHICAL_HOME/.state/lock"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "$$"
}

@test "a dead holder's lock is broken and acquired" {
  load_mctl; mi_ensure_layout
  printf 'pid=%s start=0 token=dead\n' "$(a_dead_pid)" > "$MYTHICAL_HOME/.state/lock"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire && echo ACQUIRED'
  assert_ok
  assert_contains "ACQUIRED"
  assert_contains "stale"
}

@test "an unreadable-PID lock is treated as in-progress, not broken" {
  load_mctl; mi_ensure_layout
  # a holder mid-publish would leave no readable pid= — must NOT be broken as stale
  printf 'garbage-no-pid\n' > "$MYTHICAL_HOME/.state/lock"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "acquiring"
  # the planted lock must still be there — we refused rather than broke it
  [ -f "$MYTHICAL_HOME/.state/lock" ]
}

@test "a malformed lock record fails closed — unreadable, not parsed or broken" {
  load_mctl; mi_ensure_layout
  # A prefix-matching / garbage record must NOT be read as a real owner PID (the strict parser
  # rejects `pid=123garbage...`), so it is treated as in-progress and refused, never broken.
  printf 'pid=123garbage start=0 token=x\n' > "$MYTHICAL_HOME/.state/lock"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "acquiring"
  [ -f "$MYTHICAL_HOME/.state/lock" ]
}

@test "a multi-record lock file fails closed — refused, never broken (one record is LIVE)" {
  load_mctl; mi_ensure_layout
  # sed's ^…$ anchor per LINE, so a two-record file could otherwise yield a newline-joined PID that
  # kill -0 rejects → mis-read as dead → broken, deleting a lock naming a LIVE holder. The one-line
  # gate makes the whole file unreadable instead: line 1 names US (alive), so a break here would be a
  # split. Assert refusal WITHOUT deletion.
  printf 'pid=%s start=0 token=A\npid=%s start=0 token=B\n' "$$" "$(a_dead_pid)" > "$MYTHICAL_HOME/.state/lock"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "acquiring"
  [ -f "$MYTHICAL_HOME/.state/lock" ]              # the live holder's lock is untouched
}

@test "a recovery gate left by a crash is NOT stolen — refuse and name it for manual clear" {
  load_mctl; mi_ensure_layout
  # a stale main lock AND a recovery gate both left by dead processes (a break that crashed midway).
  # The gate is never force-cleared by racing (that IS the two-live-holders race), so acquisition
  # must refuse WITHOUT touching either file and name the gate for a one-time manual removal.
  local dp; dp="$(a_dead_pid)"
  printf 'pid=%s start=0 token=dead\n' "$dp" > "$MYTHICAL_HOME/.state/lock"
  printf 'pid=%s\n'                    "$dp" > "$MYTHICAL_HOME/.state/lock.recovery"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "lock.recovery"                  # the message names the exact file to remove
  [ -f "$MYTHICAL_HOME/.state/lock" ]              # main lock untouched (we did not break under a crashed gate)
  [ -f "$MYTHICAL_HOME/.state/lock.recovery" ]     # gate left in place (never stolen)
}

@test "a LIVE recovery gate blocks the break — another operation is already recovering" {
  load_mctl; mi_ensure_layout
  printf 'pid=%s start=0 token=dead\n' "$(a_dead_pid)" > "$MYTHICAL_HOME/.state/lock"
  # the recovery gate is held by a LIVE process (this bats pid; the subshell below is a child, so $$
  # is alive throughout) — i.e. someone else is mid-break. We must NOT steal the gate or break.
  printf 'pid=%s\n' "$$" > "$MYTHICAL_HOME/.state/lock.recovery"
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_acquire'
  [ "$status" -eq 1 ]
  assert_contains "recovering"                     # transient: another operation is mid-break
  [ -f "$MYTHICAL_HOME/.state/lock" ]              # left the stale lock for the active breaker
  [ -f "$MYTHICAL_HOME/.state/lock.recovery" ]     # left the live gate untouched
}

@test "release will NOT delete a lock it does not own" {
  load_mctl; mi_ensure_layout
  mi_lock_acquire                     # we hold it, MI_LOCK_TOKEN is ours
  # simulate the lock having been re-taken by someone else (different token on disk)
  printf 'pid=1 start=0 token=someone-else\n' > "$MYTHICAL_HOME/.state/lock"
  mi_lock_release
  # our release must have left the foreign lock in place
  [ -f "$MYTHICAL_HOME/.state/lock" ]
  rm -f "$MYTHICAL_HOME/.state/lock"  # tidy up the planted lock
}

@test "release is a safe no-op when not held" {
  load_mctl; mi_ensure_layout
  run bash -c 'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; source '"$_MCTL_ROOT"'/lib/lock.sh; mi_lock_release && echo OK'
  assert_ok
  assert_contains "OK"
}
