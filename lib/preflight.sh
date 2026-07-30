#!/usr/bin/env bash
# §4b — the preconditions that make the rest of this design's guarantees true.
#
# RECONSTRUCTED: the design of record references §4b.1–§4b.4 from D26, D29, D30, D31 and D32 and from
# twelve §10a rows, but the section itself was never written (verified 2026-07-28). The requirements
# below come from those decisions and rows, and the plan's "Decisions" item 2 carries the mapping. If
# §4b is written later and disagrees, §4b wins.
#
# Every check REFUSES rather than degrading. D29's whole point is that `-p 127.0.0.1:…` is necessary
# and insufficient: on macvlan/ipvlan the container sits on the physical network, and Engine <28 lets
# the same L2 segment reach localhost-published ports. Publishing anyway and calling it loopback
# would be the design claiming a wall it does not have.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

# Compare the engine's MAJOR against MI_RT_MIN_ENGINE numerically. Docker versions are `28.1.4`,
# sometimes with a suffix (`28.0.0-beta.1`); only the leading integer matters here.
#
# An UNPARSEABLE version is a REFUSAL, not a pass. A daemon reporting `dev` or an empty string is one
# we cannot place on either side of the gate, and treating unknown as new-enough is the same error as
# treating an unmeasured thing as measured-clean.
#
# MI_RT_MIN_ENGINE is defined in lib/runtime.sh, deliberately NOT here: two definitions of a version
# floor drift, and the one that drifts is always the copy. CI lints each lib/*.sh on its own, so this
# is a cross-file reference the linter cannot resolve — measured with shellcheck 0.11.0, SC2154 does
# NOT fire on it, because an ALL-CAPS name is assumed to be an environment variable. The directive
# below is therefore a no-op today and is kept only so a linter that drops that assumption cannot
# turn a correct cross-module reference into a red build. It is scoped to this function, whose only
# other variables are locals.
# shellcheck disable=SC2154
_mi_pf_engine_major_ok() {
  local v="$1" major="${1%%.*}"
  case "$v" in
    ''|*[!0-9.a-zA-Z+_-]*) return 1 ;;
  esac
  case "$major" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#major}" -le 9 ] || return 1
  [ "$major" -ge "$MI_RT_MIN_ENGINE" ]
}

# Is this daemon endpoint LOCAL (D30)? Bind sources resolve on the DAEMON's host, so a remote daemon
# makes every path check in §4.1a and §5.1 validate the wrong filesystem.
#
# Accepted: a unix socket (including Docker Desktop's per-user socket under $HOME) and a Windows named
# pipe — Docker Desktop's managed VM is explicitly fine, because the daemon shares the host's view of
# the paths we bind.
#
# Refused: everything else, INCLUDING `tcp://127.0.0.1`. A loopback TCP daemon looks local and is not
# necessarily so — it can be an SSH-forwarded port or a socket-activated proxy to another machine, and
# the endpoint string cannot tell us which. Refusing a rare-but-ambiguous configuration is cheaper
# than validating paths against a filesystem that is not the one the container will see.
_mi_pf_endpoint_local() {
  case "${1:-}" in
    unix://*|npipe://*) return 0 ;;
    *) return 1 ;;
  esac
}

# rc 0 the daemon is usable · 1 refused (reported).
mi_preflight_daemon() {
  if ! mi_rt_available; then
    mi_warn "preflight: no 'docker' command found."
    mi_warn "  mythical-ctl needs rootful Docker Engine 28+ or Docker Desktop, with a LOCAL daemon."
    return 1
  fi
  if ! mi_rt_ping; then
    mi_warn "preflight: the container runtime did not answer."
    mi_warn "  Start Docker (or Docker Desktop) and try again."
    return 1
  fi

  # Locality (D30/§4b.3). DOCKER_HOST overrides the context when set, so check it FIRST and check the
  # context only when it is unset — otherwise a remote DOCKER_HOST beside a local context passes.
  local ep
  if [ -n "${DOCKER_HOST:-}" ]; then
    ep="$DOCKER_HOST"
  else
    ep="$(mi_rt_context_host)" || return 1
  fi
  if ! _mi_pf_endpoint_local "$ep"; then
    mi_warn "preflight: the docker daemon at '$ep' is not local, and mythical-ctl requires a local one."
    mi_warn "  Host paths you bind are resolved on the DAEMON's filesystem, so a remote daemon would"
    mi_warn "  validate one machine's paths and mount another's. Docker Desktop's managed VM is fine."
    return 1
  fi

  # Rootless (D29/§4b.2). rc 2 means we could not ask, which is not "rootful".
  #
  # `mi_rt_rootless; rl=$?` would ABORT the CLI: bin/mythical-ctl runs `set -euo pipefail`, and a
  # simple command whose status is not consumed by if/while/&&/||/! trips errexit — so the HEALTHY
  # path (rc 1, not rootless) would kill the process before this case statement ran. Every nonzero
  # return in this codebase is a normal outcome, so every capture goes through an if/else.
  local rl
  if mi_rt_rootless; then rl=0; else rl=$?; fi
  case "$rl" in
    0) mi_warn "preflight: this is a ROOTLESS docker daemon, which mythical-ctl refuses."
       mi_warn "  The loopback publishing guarantee (D26) depends on rootful port publishing, so on a"
       mi_warn "  rootless daemon this installation would be claiming a wall it does not have."
       return 1 ;;
    1) : ;;
    *) mi_warn "preflight: cannot determine whether the daemon is rootless — refusing rather than assuming."
       return 1 ;;
  esac

  local v
  v="$(mi_rt_engine_version)" || return 1
  if ! _mi_pf_engine_major_ok "$v"; then
    mi_warn "preflight: docker Engine $v is not supported — mythical-ctl requires Engine ${MI_RT_MIN_ENGINE} or newer."
    mi_warn "  Before Engine ${MI_RT_MIN_ENGINE}, a port published to 127.0.0.1 is still reachable from the same"
    mi_warn "  L2 segment. Publishing anyway and calling it loopback would be a false claim."
    return 1
  fi
  return 0
}

# The topology half (D29/§4b.2), for ONE network — by ID or name.
#
# `allow-direct-routing` is a DAEMON setting that re-exposes published ports, and it is deliberately
# absent from this function: it is **not detectable** from any API the CLI can reach. It is a stated
# precondition, not an enforced check. Only a POSITIVE active probe could refuse on it, and a negative
# probe proves nothing — so nothing here claims to have looked. Saying "verified" about a setting we
# cannot read would be the one thing worse than not checking it.
mi_preflight_network() {
  if [ "$#" -ne 1 ]; then mi_warn "preflight: mi_preflight_network needs a <network id or name>"; return 1; fi
  local net="$1" driver thi rc

  if driver="$(mi_rt_inspect network n.driver "$net")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "preflight: network '$net' does not exist."
    return 1
  fi
  [ "$rc" -eq 0 ] || return 1

  case "$driver" in
    bridge) : ;;
    macvlan|ipvlan)
      mi_warn "preflight: network '$net' uses the $driver driver, which mythical-ctl refuses."
      mi_warn "  $driver places the container directly on the physical network, so publishing to"
      mi_warn "  127.0.0.1 constrains nothing. Use a NAT-mode user-defined bridge."
      return 1 ;;
    *)
      # An unknown driver is refused for the same reason an unparseable engine version is: we cannot
      # place it on either side of D29's guarantee.
      mi_warn "preflight: network '$net' uses the '$driver' driver; mythical-ctl requires a NAT-mode bridge."
      return 1 ;;
  esac

  # `trusted_host_interfaces` (Engine 28+) re-exposes loopback-published ports on the named
  # interfaces. ANY non-empty value is a refusal — there is no safe subset, and enumerating
  # "acceptable" interfaces would be this installer deciding which of the operator's networks are
  # trustworthy.
  if thi="$(mi_rt_inspect network n.thi "$net")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return 1
  case "$thi" in
    ''|'<no value>') : ;;
    *)
      mi_warn "preflight: network '$net' has trusted_host_interfaces set to '$thi'."
      mi_warn "  That re-exposes 127.0.0.1-published ports on those interfaces, defeating D26's wall."
      mi_warn "  Recreate the network without the option, or point MYTHICAL_NET at one that has it unset."
      return 1 ;;
  esac
  return 0
}

# Both halves, for the family network this installation will use. Called by every mutating verb before
# it touches anything — the network argument may be absent on a first install, in which case only the
# daemon half runs and the network is checked immediately after it is created.
mi_preflight_all() {
  mi_preflight_daemon || return 1
  if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
    mi_preflight_network "$1" || return 1
  fi
  return 0
}
