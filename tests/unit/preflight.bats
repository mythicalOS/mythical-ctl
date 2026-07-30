#!/usr/bin/env bats
load '../lib/test_helper'

# `unset DOCKER_HOST` is hermeticity, not tidiness. mi_preflight_daemon reads DOCKER_HOST BEFORE the
# context (a set DOCKER_HOST overrides the context, so checking the context first would pass a remote
# daemon standing beside a local context), and the harness never unsets it. On any machine whose shell
# exports DOCKER_HOST — common with remote contexts, colima, rootless setups and CI runners — the
# Docker-Desktop and npipe cases below would be decided by the ambient environment rather than by the
# code. The tests that WANT a DOCKER_HOST set it themselves, as a command prefix.
setup() { setup_test_env; unset DOCKER_HOST; load_mctl; }
teardown() { teardown_test_env; }

@test "a healthy local rootful Engine 28 daemon passes" {
  run mi_preflight_daemon
  [ "$status" -eq 0 ]
}

@test "Engine 27 is refused, naming the version and the reason" {
  FAKE_DOCKER_SERVER_VERSION=27.5.1 run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "Engine 28"
  assert_contains "27.5.1"
}

@test "a version we cannot parse is refused, never treated as new enough" {
  FAKE_DOCKER_SERVER_VERSION=dev run mi_preflight_daemon
  [ "$status" -ne 0 ]
}

@test "a 100-major engine is accepted — the comparison is numeric, not lexical" {
  FAKE_DOCKER_SERVER_VERSION=100.0.0 run mi_preflight_daemon
  [ "$status" -eq 0 ]
}

@test "a rootless daemon is refused with the reason" {
  FAKE_DOCKER_ROOTLESS=1 run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "rootless"
}

@test "a remote DOCKER_HOST is refused" {
  DOCKER_HOST=tcp://10.0.0.5:2376 run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "local"
}

@test "an ssh:// context is refused" {
  FAKE_DOCKER_CONTEXT_HOST=ssh://build@10.0.0.5 run mi_preflight_daemon
  [ "$status" -ne 0 ]
}

@test "Docker Desktop's managed VM socket is ACCEPTED" {
  FAKE_DOCKER_CONTEXT_HOST="unix://$HOME/.docker/run/docker.sock" run mi_preflight_daemon
  [ "$status" -eq 0 ]
  DOCKER_HOST="unix:///var/run/docker.sock" run mi_preflight_daemon
  [ "$status" -eq 0 ]
}

@test "an npipe:// endpoint is accepted (Docker Desktop on Windows) but tcp:// is not" {
  FAKE_DOCKER_CONTEXT_HOST='npipe:////./pipe/dockerDesktopLinuxEngine' run mi_preflight_daemon
  [ "$status" -eq 0 ]
  FAKE_DOCKER_CONTEXT_HOST='tcp://127.0.0.1:2375' run mi_preflight_daemon
  [ "$status" -ne 0 ]
}

@test "a REMOTE named pipe is refused — the scheme alone is not the locality" {
  # A Windows named pipe is `\\<server>\pipe\<name>`, spelled `//<server>/pipe/<name>` in the endpoint
  # URL, and the server component `.` means THIS machine. `npipe:////remote-host/pipe/docker_engine`
  # is therefore a perfectly valid REMOTE daemon. Accepting every `npipe://*` failed open on exactly
  # the invariant this check exists to enforce, and it failed open silently: the accept-test above
  # passes either way, because the local form is a member of both sets.
  FAKE_DOCKER_CONTEXT_HOST='npipe:////remote-host/pipe/docker_engine' run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "not local"

  # Only the exact `.` component is the local machine. Anything else is refused rather than reasoned
  # about — this is a locality gate, and a server component we have to interpret is one we cannot
  # place on either side of it.
  FAKE_DOCKER_CONTEXT_HOST='npipe:////../pipe/docker_engine' run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "not local"

  DOCKER_HOST='npipe:////remote-host/pipe/docker_engine' run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "not local"
}

@test "an absent daemon is refused, distinctly from a policy refusal" {
  FAKE_DOCKER_DOWN=1 run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "did not answer"
}

@test "a daemon we cannot ask about rootlessness is refused, not assumed rootful" {
  # mi_rt_rootless returns 2 for "could not ask", which is neither 0 (rootless) nor 1 (rootful), and
  # the refusal for it was UNREACHABLE until the harness grew a knob narrow enough to produce it: the
  # only other way to make `info` fail was FAKE_DOCKER_DOWN, which fails `version` too and therefore
  # trips the ping refusal several lines earlier. So the arm could be replaced by `*) : ;;` with the
  # whole suite green — an unknown daemon silently treated as rootful, which is the same error as
  # treating an unmeasured thing as measured-clean.
  #
  # The assertion names the rootless message specifically: refusing for the WRONG reason (a ping
  # failure, an unreadable context) would satisfy a bare non-zero check.
  FAKE_DOCKER_INFO_FAIL=1 run mi_preflight_daemon
  [ "$status" -ne 0 ]
  assert_contains "cannot determine whether the daemon is rootless"
}

@test "a bridge network with no trusted_host_interfaces passes" {
  net="$(mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_network "$net"
  [ "$status" -eq 0 ]
}

@test "a macvlan network is refused" {
  net="$(FAKE_DOCKER_NET_DRIVER=macvlan mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_network "$net"
  [ "$status" -ne 0 ]
  assert_contains "macvlan"
}

@test "an ipvlan network is refused" {
  net="$(FAKE_DOCKER_NET_DRIVER=ipvlan mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_network "$net"
  [ "$status" -ne 0 ]
}

@test "trusted_host_interfaces set to ANY value is refused, naming the setting" {
  net="$(FAKE_DOCKER_NET_THI=eth0 mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_network "$net"
  [ "$status" -ne 0 ]
  assert_contains "trusted_host_interfaces"
}

@test "trusted_host_interfaces rendered as Go's '<no value>' is ABSENT, not set" {
  # Go templates render a MISSING map key as the literal string `<no value>`, not as empty. Reading
  # that as "set" would refuse every correctly-configured network — the refusal firing on the healthy
  # case, which is worse than not checking. Pinned here because the empty-string case alone cannot
  # tell the two acceptances apart, so the `<no value>` arm could be deleted with the suite green.
  net="$(FAKE_DOCKER_NET_THI='<no value>' mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_network "$net"
  [ "$status" -eq 0 ]
}

@test "a network that does not exist is refused, not silently skipped" {
  run mi_preflight_network 0000000000000000000000000000000000000000000000000000000000009999
  [ "$status" -ne 0 ]
}

@test "no docker command at all is refused before anything else is asked" {
  # PATH is emptied for the duration of ONE function call. `run` is not used here: it would have to
  # survive a PATH with no external commands in it, and what is under test needs no subprocess at all.
  local st out
  mkdir -p "$MYTHICAL_HOME/nopath"
  if out="$(PATH="$MYTHICAL_HOME/nopath" mi_preflight_daemon 2>&1)"; then st=0; else st=$?; fi
  [ "$st" -ne 0 ] || { echo "expected a refusal with no docker on PATH, got rc 0: $out" >&2; return 1; }
  case "$out" in
    *"no 'docker' command found"*) : ;;
    *) echo "refused, but not for the missing runtime: $out" >&2; return 1 ;;
  esac
}

@test "mi_preflight_all runs the daemon half even when no network is named" {
  run mi_preflight_all
  [ "$status" -eq 0 ]
  FAKE_DOCKER_ROOTLESS=1 run mi_preflight_all
  [ "$status" -ne 0 ]
  assert_contains "rootless"
}

@test "mi_preflight_all refuses when the network half refuses" {
  net="$(FAKE_DOCKER_NET_DRIVER=macvlan mi_rt_network_create mythical-i1-net i1 n1)"
  run mi_preflight_all "$net"
  [ "$status" -ne 0 ]
  assert_contains "macvlan"

  # And it does NOT refuse a good one — a network half that always said no would pass the assertion
  # above and break every real install.
  good="$(mi_rt_network_create mythical-i2-net i2 n2)"
  run mi_preflight_all "$good"
  [ "$status" -eq 0 ]
}

@test "allow-direct-routing is documented as undetectable and no check claims to detect it" {
  # -A3 is REQUIRED, not decoration. `grep` prints only the MATCHING line, and in lib/preflight.sh
  # the phrase "not detectable" sits two lines below the line naming `allow-direct-routing`. Without
  # the context flag $output is the match line alone and the assertion fails against correct code.
  run grep -a -A3 'allow-direct-routing' "${_MCTL_ROOT}/lib/preflight.sh"
  [ "$status" -eq 0 ]
  assert_contains "not detectable"
}

@test "the engine-version grammar refuses every malformed shape, not just the reported one" {
  # Pinned as a CLASS, deliberately. Three review rounds each produced the next malformed string that
  # slipped past a prefix check — `28.`, then `28..`, then `28.0..`/`28.0-`/`28.0__`/`28.0.0--` — so
  # the table below is every shape raised across all of them plus the degenerate ones. Testing one
  # instance is what let this recur twice.
  #
  # Scope: none of these was ever exploitable. Each accepted value had a major at or above the floor
  # and `27.` was refused throughout, so no malformed version ever admitted an engine older than the
  # floor. This pins the module's stated rule, it does not close a bypass.
  local v
  for v in '28.' '28..' '28.0..' '28.0-' '28.0__' '28.0.0--' '28.0.0-' '.28' '-28.0' '+28' \
           'dev' '28x' '1e9' '9999999999999.0' '..' '-' '+'; do
    if _mi_pf_engine_major_ok "$v"; then
      echo "malformed version '$v' was ACCEPTED" >&2; return 1
    fi
  done
  # and the floor still holds for a well-formed old version
  if _mi_pf_engine_major_ok '27.9.9'; then echo "27.9.9 accepted" >&2; return 1; fi
}

@test "every real Docker version shape is still accepted — the grammar must not over-refuse" {
  # The counterpart, and the reason the suffix's CONTENT is deliberately not parsed: a false refusal
  # strands every install on a supported daemon, which is the more expensive error when only the
  # major decides the gate.
  local v
  for v in '28' '28.0' '28.1.4' '2025.1' '100.0.0' '0028.0' \
           '28.0.0-beta.1' '28.0.0-rc.1' '28.0.0-dev' '28.0.0+build.7'; do
    if ! _mi_pf_engine_major_ok "$v"; then
      echo "real version '$v' was REFUSED" >&2; return 1
    fi
  done
}

@test "a malformed version is refused through the public preflight path, not only the helper" {
  FAKE_DOCKER_SERVER_VERSION=28. run mi_preflight_daemon
  [ "$status" -ne 0 ]
  FAKE_DOCKER_SERVER_VERSION=28.0.0-beta.1 run mi_preflight_daemon
  [ "$status" -eq 0 ]
}
