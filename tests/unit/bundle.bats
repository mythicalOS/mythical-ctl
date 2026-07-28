load '../lib/test_helper'

# The release ships ONE file. Every test here exists because a bundler that "looks right" can still
# publish an artifact that is subtly not the thing the repository tests — the sentinels could drift,
# a module could be dropped, an inlined function could behave differently from its repo original.
# So the bundle is built for real and then held to the same contract as the repo entrypoint.

BUNDLE=""

setup() {
  # test_helper's setup gives us the isolated MYTHICAL_HOME + PATH; keep it.
  _MCTL_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  MYTHICAL_HOME="$(mktemp -d)"
  export MYTHICAL_HOME
  BUNDLE="$BATS_TEST_TMPDIR/mythical-ctl"
  run "${_MCTL_ROOT}/tools/bundle.sh" "$BUNDLE"
  [ "$status" -eq 0 ] || { echo "bundle build failed: $output" >&2; return 1; }
}

teardown() {
  [ -n "${MYTHICAL_HOME:-}" ] && rm -rf "$MYTHICAL_HOME"
  return 0
}

# Same lock fixture as ledger.bats: publish a lock file and match its token, so the ledger writer's
# guard is PROVED rather than bypassed. Exported for the `bash -c` subshells below.
hold_lock() {
  printf 'pid=%s start=0 token=testtok\n' "$$" > "$MYTHICAL_HOME/.state/lock"
  export MI_LOCK_TOKEN=testtok
}

@test "the bundle is reproducible — same inputs, byte-identical output" {
  # A published digest is only meaningful if anyone can rebuild the same bytes. A timestamp, a
  # hostname or a build counter anywhere in the generator would break this and nothing else.
  local a="$BATS_TEST_TMPDIR/a" b="$BATS_TEST_TMPDIR/b"
  run "${_MCTL_ROOT}/tools/bundle.sh" "$a"; [ "$status" -eq 0 ]
  run "${_MCTL_ROOT}/tools/bundle.sh" "$b"; [ "$status" -eq 0 ]
  cmp "$a" "$b"
}

@test "the bundle is self-contained — no sentinels, no sourcing of lib/" {
  # The published artifact has no ../lib beside it. Either leftover would mean the release either
  # tries to source a directory that is not there, or could be re-bundled into itself.
  run grep -n 'mctl:modules' "$BUNDLE"
  [ "$status" -ne 0 ] || { echo "module sentinel survived into the bundle: $output" >&2; return 1; }

  run grep -nE '(^|[^[:alnum:]_])(source|\.)[[:space:]]+[^[:space:]]*lib/' "$BUNDLE"
  [ "$status" -ne 0 ] || { echo "bundle still sources a lib/ path: $output" >&2; return 1; }
}

@test "the bundle's library surface is complete (__selftest)" {
  run bash "$BUNDLE" __selftest
  assert_ok
  assert_contains "ok"
}

@test "entrypoint parity: --version is byte-identical to the repo entrypoint" {
  # The release workflow derives the published version from the artifact. If the bundle could report
  # anything other than what the repo entrypoint reports, the tag check would be checking the wrong file.
  local repo_v bundle_v
  repo_v="$("${_MCTL_ROOT}/bin/mythical-ctl" --version)"
  bundle_v="$(bash "$BUNDLE" --version)"
  [ "$repo_v" = "$bundle_v" ] || { echo "version drift: repo=$repo_v bundle=$bundle_v" >&2; return 1; }
}

@test "entrypoint parity: --help exits 0 and an unknown command exits 2" {
  run bash "$BUNDLE" --help
  assert_ok

  # 2 is the usage-error code the smoke suite and callers pin. Inlining must not disturb dispatch.
  run bash "$BUNDLE" not-a-real-command
  assert_fail 2
}

@test "the INLINED ledger really works — write/read round-trip through the bundle" {
  # The point of the whole exercise: not "does the file parse" but "do the inlined libraries behave
  # exactly as the repo modules do". Sourcing the artifact loads its functions without running main,
  # so they can be exercised the same way ledger.bats exercises lib/*.sh.
  run bash -c 'source '"$BUNDLE"'; mi_ensure_layout'
  assert_ok
  hold_lock

  run bash -c 'source '"$BUNDLE"'; printf "identity\tid=abc123\ninitialized\tproduct=brokkr\n" | mi_ledger_write'
  assert_ok

  run bash -c 'source '"$BUNDLE"'; mi_ledger_read'
  assert_ok
  assert_contains "id=abc123"
  assert_contains "product=brokkr"

  run bash -c 'source '"$BUNDLE"'; mi_ledger_get initialized product'
  assert_ok
  assert_contains "brokkr"
}

@test "fail-closed behaviour survives bundling — a corrupt ledger is refused, not parsed" {
  # Silently degrading to "parse what you can" is the failure mode that matters here, and it is
  # exactly the kind of thing a transcription bug in a bundler could introduce.
  run bash -c 'source '"$BUNDLE"'; mi_ensure_layout'
  assert_ok
  hold_lock

  run bash -c 'source '"$BUNDLE"'; printf "identity\tid=abc123\n" | mi_ledger_write'
  assert_ok
  printf 'tampered\tx=1\n' >> "$MYTHICAL_HOME/.state/ledger"    # body changed after the checksum

  run bash -c 'source '"$BUNDLE"'; mi_ledger_read'
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]        # 3 means "no ledger"; a corrupt one must be louder than absent
  assert_contains "checksum"
}

@test "the completeness gate refuses a lib/ module missing from MODULES" {
  # The regression this guards: a future module is added to lib/ and wired into the dev loader, but
  # nobody updates MODULES — and the release quietly ships without it. Proved on a COPY of the repo,
  # so the real lib/ is never mutated by a test.
  local copy="$BATS_TEST_TMPDIR/repo"
  mkdir -p "$copy"
  cp -R "${_MCTL_ROOT}/bin" "${_MCTL_ROOT}/lib" "${_MCTL_ROOT}/tools" "$copy/"
  printf '#!/usr/bin/env bash\nmi_zzz_extra() { :; }\n' > "$copy/lib/zzz_extra.sh"

  run "$copy/tools/bundle.sh" "$copy/out"
  [ "$status" -ne 0 ] || { echo "bundler built despite an unlisted module" >&2; return 1; }
  assert_contains "zzz_extra"
  [ ! -f "$copy/out" ]       # and it published nothing
}
