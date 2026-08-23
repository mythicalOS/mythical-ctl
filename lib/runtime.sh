#!/usr/bin/env bash
# The ONLY place mythical-ctl executes the container runtime.
#
# Two invariants live here rather than at the call sites, because a rule every caller must remember
# is a rule that gets forgotten once:
#
#   * NO CALLER CAN EXPRESS AN UNSAFE LAUNCH. The publish flag is assembled here, always with the
#     127.0.0.1 host IP (D26/§4b.1); the network mode is checked against `host`/`none`/`container:`
#     (D26/§4b.2, D42); mounts arrive as typed specs, never as raw flags. A caller that wanted
#     `-p 0.0.0.0:…` has no way to say it.
#   * NO CALLER CAN SUPPLY A GO TEMPLATE. Runtime state is read with `docker … inspect --format`,
#     which keeps §7.5's floor free of a JSON parser — but a template is code that can reach any
#     field of the inspect document, including .Config.Env. Callers name a symbolic field; the
#     mapping below is closed and every template in it is a constant.
#
# The binary is `docker`, resolved through PATH, and is deliberately NOT configurable: an env
# override would be a way to make the CLI execute an arbitrary program with the arguments it builds.
# The tests shadow it by putting tests/harness/ first in PATH.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_RT_NS=mythicalos          # label namespace; also spelled literally inside the templates below
# shellcheck disable=SC2034   # read by the preflight module; CI lints each lib/*.sh alone and cannot see it
MI_RT_MIN_ENGINE=28          # D29: Engine 28+ is what makes the loopback publish a wall

# --- argument hygiene -----------------------------------------------------------------------------
# Every argument that reaches the runtime passes this first. A control byte in an argument is either
# a bug or an injection attempt: it cannot be quoted safely into a log line, it can forge a field in
# a label, and no legitimate name, path, digest or port contains one.
_mi_rt_arg_ok() {
  local v="$1"
  local LC_ALL=C            # [[:cntrl:]] must mean bytes, not the operator's locale
  [ -n "$v" ] || return 1
  case "$v" in *[[:cntrl:]]*) return 1 ;; esac
  [ "${#v}" -le 4096 ]
}

# Strip leading zeros from an all-digit string, leaving at least one digit, so a port is canonical in
# the argv and its digit count means what it says.
_mi_rt_strip_zeros() {
  local n="$1"
  while [ "${#n}" -gt 1 ] && [ "${n:0:1}" = 0 ]; do n="${n:1}"; done
  printf '%s' "$n"
}

# --- mount components -----------------------------------------------------------------------------
# A mount reaches the runtime as `--mount type=bind,source=…,target=…` — a COMMA-separated key=value
# list, not the colon-separated triple the spec grammar above it uses. So a comma inside a component
# does not stay inside that component. MEASURED here, with the spec taken verbatim from the caller:
#
#   bind=/host:/container,bind-propagation=rshared:rw
#     → --mount type=bind,source=/host,target=/container,bind-propagation=rshared
#   volume=v,volume-opt=o=bind,volume-opt=device=/etc:/d:rw
#     → --mount type=volume,source=v,volume-opt=o=bind,volume-opt=device=/etc,target=/d
#
# The second is the serious one: it turns a NAMED VOLUME into a host bind mount, i.e. a container
# escape expressed through the one API whose whole purpose is to make an unsafe launch inexpressible.
# Splitting on `:` and checking "starts with /" cannot see either, because both components are
# well-formed paths as far as that check is concerned.
#
# No volume name and no path this code constructs ever contains a comma, so refusing one closes
# Docker's option grammar at no cost to any legitimate caller. There is ONE implementation of each
# rule, used by both the container arm and the helper arm — two copies of a security check drift.

# A bind SOURCE or a mount TARGET: comma-free, absolute, `..`-free. <what> only names the field in
# the refusal, so the operator is told which component of which spec was rejected.
_mi_rt_bind_path_ok() {
  local p="$1" what="$2"
  case "$p" in *,*) mi_warn "runtime: $what '$p' contains a comma, which would open Docker's mount option list"; return 1 ;; esac
  _mi_rt_arg_ok "$p" || { mi_warn "runtime: $what is empty, over-long, or contains a control byte"; return 1; }
  case "$p" in /*) : ;; *) mi_warn "runtime: $what '$p' is not absolute"; return 1 ;; esac
  case "/${p}/" in */../*) mi_warn "runtime: $what '$p' contains a .. component"; return 1 ;; esac
  return 0
}

# A volume SOURCE is a NAME, not a path. Absolute is refused as well as comma-bearing: a `/`-leading
# "name" is a bind mount wearing the volume spec's clothes, and the whole point of the two spec kinds
# is that the caller cannot choose which one it gets.
_mi_rt_volume_name_ok() {
  local n="$1"
  case "$n" in *,*) mi_warn "runtime: volume name '$n' contains a comma, which would open Docker's mount option list"; return 1 ;; esac
  case "$n" in /*) mi_warn "runtime: '$n' is an absolute path, not a volume name"; return 1 ;; esac
  _mi_rt_arg_ok "$n" || { mi_warn "runtime: volume name is empty, over-long, or contains a control byte"; return 1; }
  return 0
}

# Exec the runtime with pre-validated arguments. Every public function funnels through this.
_mi_rt() {
  local a
  for a in "$@"; do
    if ! _mi_rt_arg_ok "$a"; then
      mi_warn "runtime: refusing to pass an argument containing a control byte or over 4096 bytes"
      return 1
    fi
  done
  command docker "$@"
}

mi_rt_available() { command -v docker >/dev/null 2>&1; }

# Does the daemon answer at all? Used to disambiguate an inspect failure, so it must not itself
# depend on any object existing.
mi_rt_ping() { _mi_rt version --format '{{.Server.Version}}' >/dev/null 2>&1; }

# --- the closed template map ----------------------------------------------------------------------
# Naming: <kind-initial>.<field>. Every template is a literal. Where a real implementation would want
# a lookup key — (index .NetworkSettings.Networks "<name>") — the template RANGES over everything and
# emits delimited pairs the shell filters, so no value is ever interpolated into a template.
# shellcheck disable=SC2016   # every $ below belongs to the Go template, not to the shell
_mi_rt_tmpl() {
  case "$1" in
    c.running)  printf '{{.State.Running}}' ;;
    c.status)   printf '{{.State.Status}}' ;;
    c.image)    printf '{{.Image}}' ;;
    c.nonce)    printf '{{index .Config.Labels "mythicalos.nonce"}}' ;;
    c.install)  printf '{{index .Config.Labels "mythicalos.installation"}}' ;;
    c.product)  printf '{{index .Config.Labels "mythicalos.product"}}' ;;
    # "<netid>=<addr>;" per attachment. A STOPPED container yields "<netid>=;" — Docker releases the
    # address, and the fake runtime reproduces that, so D48's "a stopped container has no endpoint"
    # is a property the tests observe rather than a claim they assume.
    c.nets)     printf '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' ;;
    c.aliases)  printf '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}:{{range $v.Aliases}}{{.}},{{end}};{{end}}' ;;
    # NAME-CARRYING variants, for the PRE-START attach check only (§6b.3 step 2). A container that has
    # NEVER started reports an EMPTY NetworkID for every endpoint — the runtime assigns the endpoint id
    # at first start, and it then PERSISTS across stop (measured: `docker create --network X` leaves
    # NetworkID empty; `start` fills it; a later `stop` keeps it). Step 2 inspects a created-but-not-yet
    # -started container, so it cannot identify a network by id at all. The inspect map KEY ($k) is the
    # network NAME, present from creation, so these emit it and the caller resolves name->id. The two
    # above are UNCHANGED for every running-container caller (verify_live, repair, netref), where the id
    # is populated and no resolution is needed.
    c.netpairs)   printf '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.NetworkID}}={{$v.IPAddress}};{{end}}' ;;
    c.aliaspairs) printf '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.NetworkID}}:{{range $v.Aliases}}{{.}},{{end}};{{end}}' ;;
    c.mounts)   printf '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}|{{.RW}};{{end}}' ;;
    c.ports)    printf '{{range $p,$bs := .NetworkSettings.Ports}}{{range $bs}}{{$p}}={{.HostIp}}:{{.HostPort}};{{end}}{{end}}' ;;
    n.id)       printf '{{.Id}}' ;;
    n.driver)   printf '{{.Driver}}' ;;
    n.install)  printf '{{index .Labels "mythicalos.installation"}}' ;;
    n.nonce)    printf '{{index .Labels "mythicalos.nonce"}}' ;;
    # §4b.2/§10a: `trusted_host_interfaces` re-exposes a loopback publish. Read it as a network
    # OPTION, which is where Docker keeps it, and refuse on any non-empty value.
    n.thi)      printf '{{index .Options "com.docker.network.bridge.trusted_host_interfaces"}}' ;;
    v.nonce)    printf '{{index .Labels "mythicalos.nonce"}}' ;;
    v.install)  printf '{{index .Labels "mythicalos.installation"}}' ;;
    v.driver)   printf '{{.Driver}}' ;;
    i.digest)   printf '{{index .RepoDigests 0}}' ;;
    *) return 1 ;;
  esac
}

# Read one field of one object. rc 0 value printed · 3 object not present · 1 the runtime could not
# answer.
#
# The 3-vs-1 split matters everywhere in §6b: "the object is gone" authorizes reconciliation, while
# "the daemon is down" authorizes nothing. `docker inspect` exits 1 for both, and its stderr wording
# is not a contract — so instead of matching on a message, we ask a question that does not depend on
# the object: if the daemon answers `version`, the object is genuinely absent.
mi_rt_inspect() {
  if [ "$#" -ne 3 ]; then mi_warn "runtime: mi_rt_inspect needs <kind> <field> <name>"; return 1; fi
  local kind="$1" field="$2" name="$3" tmpl out
  case "$kind" in container|network|volume|image) : ;;
    *) mi_warn "runtime: '$kind' is not an inspectable kind"; return 1 ;;
  esac
  if ! tmpl="$(_mi_rt_tmpl "$field")"; then
    mi_warn "runtime: '$field' is not a field this adapter exposes"
    return 1
  fi
  _mi_rt_arg_ok "$name" || { mi_warn "runtime: refusing to inspect a name containing a control byte"; return 1; }
  if out="$(_mi_rt "$kind" inspect --format "$tmpl" -- "$name" 2>/dev/null)"; then
    printf '%s\n' "$out"
    return 0
  fi
  if mi_rt_ping; then return 3; fi
  mi_warn "runtime: the container runtime did not answer"
  return 1
}

# --- attachment sets, with NEVER-STARTED endpoints resolved ---------------------------------------
# Read a container's network attachments in the id-keyed form every caller compares — "<id>=<addr>;…"
# for nets, "<id>:<aliases>;…" for aliases — RESOLVING the empty NetworkID a never-started container
# reports (the runtime assigns the endpoint id at first start; before that only the network NAME, the
# inspect map key, is present). `c.nets`/`c.aliases` alone return an EMPTY id for such a container, so
# a bare read on a created-but-not-started container mis-identifies every network as ''. These are the
# readers install/recreate (step 2), state repair, and network migration use in its place.
#
# FAIL CLOSED, and it is not a name-substitution fallback: a network may LEGALLY be named a 64-hex
# string — the exact spelling of an expected id — so emitting the name when resolution fails would let
# a stray attachment named the expected id pass an exact-set check on a transient inspect hiccup. If an
# endpoint reports no id AND its name cannot be resolved to one, the whole read fails (rc 1) and the
# caller refuses rather than guessing. rc 0 value printed · 3 the container is gone · 1 unreadable or
# unresolvable.
mi_rt_container_nets_resolved()    { _mi_rt_container_pairs_resolved "$1" c.netpairs '=' ; }
mi_rt_container_aliases_resolved() { _mi_rt_container_pairs_resolved "$1" c.aliaspairs ':' ; }
_mi_rt_container_pairs_resolved() {
  if [ "$#" -ne 3 ]; then mi_warn "runtime: _mi_rt_container_pairs_resolved needs <container> <field> <sep>"; return 1; fi
  local c="$1" field="$2" sep="$3" pairs rc rest f name tail nid val out="" resolved rrc
  if pairs="$(mi_rt_inspect container "$field" "$c")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"    # 3 (gone) / 1 (unreadable) propagated verbatim
  rest="$pairs"
  # Walk "<name>=<id><sep><value>;" one ';'-field at a time with parameter expansion — an unquoted IFS
  # split also GLOBS. The name is split off on the FIRST `=`; names and ids never contain `=`/`:`/`;`.
  while [ -n "$rest" ]; do
    f="${rest%%;*}"
    if [ "$rest" = "$f" ]; then rest=""; else rest="${rest#*;}"; fi
    [ -n "$f" ] || continue
    name="${f%%=*}"
    tail="${f#*=}"
    nid="${tail%%"${sep}"*}"
    val="${tail#*"${sep}"}"
    if [ -z "$nid" ]; then
      if resolved="$(mi_rt_inspect network n.id "$name" 2>/dev/null)"; then rrc=0; else rrc=$?; fi
      if [ "$rrc" -ne 0 ] || [ -z "$resolved" ]; then
        mi_warn "runtime: an attachment ('$name') on '$c' reports no id and its name could not be"
        mi_warn "  resolved to one, so the container's exact network set cannot be established. Refusing"
        mi_warn "  rather than guessing — a guessed id could match an expected network it is not on."
        return 1
      fi
      nid="$resolved"
    fi
    out="${out}${nid}${sep}${val};"
  done
  printf '%s\n' "$out"
}

# --- identity queries -----------------------------------------------------------------------------

mi_rt_engine_version() {
  local v
  v="$(_mi_rt version --format '{{.Server.Version}}' 2>/dev/null)" || {
    mi_warn "runtime: cannot read the engine version — is the daemon running?"; return 1; }
  [ -n "$v" ] || { mi_warn "runtime: the engine reported an empty version"; return 1; }
  printf '%s\n' "$v"
}

# rc 0 iff the daemon is ROOTLESS (which §4b.2 refuses). Reported by `docker info` in
# SecurityOptions as `name=rootless`; a daemon that cannot be asked is an error, not "rootful".
mi_rt_rootless() {
  local s
  s="$(_mi_rt info --format '{{range .SecurityOptions}}{{.}} {{end}}' 2>/dev/null)" || return 2
  case "$s" in *rootless*) return 0 ;; esac
  return 1
}

# The active context's daemon endpoint. D30 needs this to refuse a REMOTE daemon: bind sources
# resolve on the daemon's host, so a remote one validates the wrong filesystem.
mi_rt_context_host() {
  local h
  h="$(_mi_rt context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" || {
    mi_warn "runtime: cannot read the active docker context"; return 1; }
  printf '%s\n' "$h"
}

# --- discovery by label, NEVER by name (§6a) ------------------------------------------------------
# `-a` for containers is load-bearing: without it a STOPPED container is invisible, recovery finds
# zero matches, reissues, and collides with the container it could not see.
mi_rt_find_by_label() {
  if [ "$#" -ne 3 ]; then mi_warn "runtime: mi_rt_find_by_label needs <kind> <label-key> <value>"; return 1; fi
  local kind="$1" k="$2" v="$3"
  case "$k" in installation|nonce|product|role) : ;;
    *) mi_warn "runtime: '$k' is not a label this installer sets"; return 1 ;;
  esac
  _mi_rt_arg_ok "$v" || { mi_warn "runtime: refusing a label filter containing a control byte"; return 1; }
  case "$kind" in
    container) _mi_rt container ls -a --filter "label=${MI_RT_NS}.${k}=${v}" --format '{{.Names}}' ;;
    network)   _mi_rt network   ls    --filter "label=${MI_RT_NS}.${k}=${v}" --format '{{.Name}}'  ;;
    volume)    _mi_rt volume    ls    --filter "label=${MI_RT_NS}.${k}=${v}" --format '{{.Name}}'  ;;
    *) mi_warn "runtime: '$kind' cannot be listed by label"; return 1 ;;
  esac
}

# --- images ---------------------------------------------------------------------------------------
# Images carry no installation label (D37) — Docker fixes image labels at BUILD time — so there is no
# find_by_label for them and no automatic removal anywhere in this module.

mi_rt_image_present() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_image_present needs <ref>"; return 1; fi
  _mi_rt image inspect --format '{{.Id}}' -- "$1" >/dev/null 2>&1
}

# Pull, keeping every failure LOUD and distinguishable (§7.3). The stderr is passed through
# deliberately: an operator debugging a broken publication needs the registry's own words, and §10a
# requires auth and network failures never to be folded into the pre-launch message.
mi_rt_image_pull() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_image_pull needs <ref>"; return 1; fi
  _mi_rt image pull -- "$1"
}

# --- networks -------------------------------------------------------------------------------------
# Created with the NAT-mode bridge driver explicitly (D29): the default is already `bridge`, but
# relying on a default for a security property means a daemon-level default change silently removes
# the wall.
mi_rt_network_create() {
  if [ "$#" -ne 3 ]; then mi_warn "runtime: mi_rt_network_create needs <name> <identity> <nonce>"; return 1; fi
  local name="$1" ident="$2" nonce="$3"
  _mi_rt network create --driver bridge \
    --label "${MI_RT_NS}.installation=${ident}" \
    --label "${MI_RT_NS}.nonce=${nonce}" \
    -- "$name"
}

mi_rt_network_rm() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_network_rm needs <name-or-id>"; return 1; fi
  _mi_rt network rm -- "$1"
}

# Attach by ID, with the alias passed EXPLICITLY (§6b.2): `docker network connect` infers no alias,
# and without one the container joins under its own installation-scoped name, which no sibling can
# guess — family DNS then fails silently, indistinguishable from an absent peer (§9).
#
# <gw-priority> is required, not defaulted: D45 phase 2 depends on the target being attached at a
# LOWER priority than the source so the route does not move before phase 4.
mi_rt_network_connect() {
  if [ "$#" -ne 4 ]; then mi_warn "runtime: mi_rt_network_connect needs <netid> <container> <alias> <gw-priority>"; return 1; fi
  local netid="$1" c="$2" alias="$3" gw="$4" gwd
  _mi_rt_netmode_ok "$netid" || return 1
  # A character-SET test (`*[!0-9-]*`) constrains which bytes may appear and nothing about their
  # arrangement, so `1-2`, `-` and `--` all satisfy it and reach Docker. The priority is an
  # optionally-negative integer: strip at most one leading `-`, then require digits and only digits.
  gwd="$gw"
  case "$gwd" in -*) gwd="${gwd#-}" ;; esac
  case "$gwd" in ''|*[!0-9]*) mi_warn "runtime: gateway priority '$gw' is not an integer"; return 1 ;; esac
  _mi_rt network connect --alias "$alias" --gw-priority "$gw" -- "$netid" "$c"
}

mi_rt_network_disconnect() {
  if [ "$#" -ne 2 ]; then mi_warn "runtime: mi_rt_network_disconnect needs <netid> <container>"; return 1; fi
  _mi_rt network disconnect -- "$1" "$2"
}

# The three modes no product container may ever use (D26/§4b.2, D42). Checked here, so no call site
# can omit it: `host` shares the host's network namespace outright, `container:<name>` joins another
# container's, and `none` cannot later be connected to any network at all — verified: the daemon
# refuses with "container cannot be connected to multiple networks with one of the networks in
# private (none) mode", so a container created that way can never join the family network.
_mi_rt_netmode_ok() {
  case "$1" in
    host|none|container:*)
      mi_warn "runtime: network mode '$1' is rejected by design (D26/D42) — the family network is a user-defined bridge"
      return 1 ;;
  esac
  _mi_rt_arg_ok "$1"
}

# --- volumes --------------------------------------------------------------------------------------
# NOTE the real semantics this preserves (verified, and reproduced by the fake): `docker volume
# create` against an EXISTING name SUCCEEDS and returns that volume WITHOUT applying the new labels.
# So a create is never evidence of creation — every caller must re-inspect the nonce (D56/§6b).
mi_rt_volume_create() {
  if [ "$#" -ne 3 ]; then mi_warn "runtime: mi_rt_volume_create needs <name> <nonce> <identity>"; return 1; fi
  _mi_rt volume create \
    --label "${MI_RT_NS}.installation=${3}" \
    --label "${MI_RT_NS}.nonce=${2}" \
    -- "$1"
}

mi_rt_volume_rm() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_volume_rm needs <name>"; return 1; fi
  _mi_rt volume rm -- "$1"
}

# --- container creation ---------------------------------------------------------------------------
# Created STOPPED and attached to the target network AT CREATION (D42 step 1). Not a bare create:
# Docker attaches the default bridge when no network is named, and connecting the family network
# afterwards leaves the container on BOTH — quietly breaking the isolation §4b.4 depends on while
# every check asking "is it attached to our network?" still passes.
#
# Specs are TYPED, one per argument, and are the only way to express a mount, a port or a label:
#
#   volume=<name>:<container-path>:<ro|rw>
#   bind=<canonical-host-path>:<container-path>:<ro|rw>
#   publish=<host-port>:<container-port>       ← the 127.0.0.1 host IP is added HERE, not by callers
#   label=<key>=<value>                        ← key from the closed set
#
# `env=<KEY>` is NOT one of them. It is named here only to say so: the parser below rejects it, and
# it is deliberately absent because <envfile> already carries every declared key as a 0600 file. A
# later task that reads a spec list promising `env=` and finds "unknown container spec" is losing a
# debugging round to a comment, so the comment states the boundary instead of implying the feature.
#
# There is deliberately no `arg=` or `flag=` spec. A generic escape hatch would return every
# invariant above to the call sites.
mi_rt_container_create() {
  if [ "$#" -lt 5 ]; then
    mi_warn "runtime: mi_rt_container_create needs <name> <image> <netid> <alias> <envfile|-> [spec...]"
    return 1
  fi
  local name="$1" image="$2" netid="$3" alias="$4" envfile="$5"
  shift 5
  _mi_rt_netmode_ok "$netid" || return 1
  _mi_rt_arg_ok "$name"  || { mi_warn "runtime: invalid container name"; return 1; }
  _mi_rt_arg_ok "$image" || { mi_warn "runtime: invalid image reference"; return 1; }
  _mi_rt_arg_ok "$alias" || { mi_warn "runtime: invalid network alias"; return 1; }

  local -a rtargv
  rtargv=(container create --name "$name" --network "$netid" --network-alias "$alias")

  # §4.3: bootstrap secrets go in a per-container 0600 env file, NEVER in argv — argv is
  # world-readable through `ps` on the host. The file holds only this product's declared keys and the
  # caller removes it after the run.
  if [ "$envfile" != "-" ]; then
    [ -f "$envfile" ] || { mi_warn "runtime: env file '$envfile' does not exist"; return 1; }
    rtargv+=(--env-file "$envfile")
  fi

  local s kind body p1 p2 p3 ro
  for s in "$@"; do
    kind="${s%%=*}"; body="${s#*=}"
    case "$kind" in
      volume|bind)
        p1="${body%%:*}"; body="${body#*:}"
        p2="${body%%:*}"; p3="${body#*:}"
        case "$p3" in ro|rw) : ;; *) mi_warn "runtime: mount spec '$s' must end in :ro or :rw"; return 1 ;; esac
        _mi_rt_bind_path_ok "$p2" "mount target" || { mi_warn "runtime: refusing mount spec '$s'"; return 1; }
        # An `if`, not `$( [ "$p3" = ro ] && printf ',readonly' )`. MEASURED on this machine: a
        # command substitution whose last command FAILS makes the enclosing ASSIGNMENT fail, and an
        # array append is an assignment — so under the entrypoint's ambient `set -e` the whole CLI
        # exited, silently, on every read-WRITE mount. The rw path is the common one, so the bug
        # would have fired on essentially every real launch while the tests (which reach this line
        # only through bats' `run`, where errexit is off) stayed green.
        ro=""
        if [ "$p3" = ro ]; then ro=",readonly"; fi
        if [ "$kind" = bind ]; then
          _mi_rt_bind_path_ok "$p1" "bind source" || { mi_warn "runtime: refusing mount spec '$s'"; return 1; }
          # `type=bind` explicitly: the --mount form refuses to create a missing source, where -v
          # silently creates a DIRECTORY. A missing single-file bind silently becoming a directory is
          # how <product>.conf stops being the file the product writes (§4.1a).
          rtargv+=(--mount "type=bind,source=${p1},target=${p2}${ro}")
        else
          _mi_rt_volume_name_ok "$p1" || { mi_warn "runtime: refusing mount spec '$s'"; return 1; }
          rtargv+=(--mount "type=volume,source=${p1},target=${p2}${ro}")
        fi
        ;;
      publish)
        p1="${body%%:*}"; p2="${body#*:}"
        case "$p1" in ''|*[!0-9]*) mi_warn "runtime: publish host port '$p1' is not a port"; return 1 ;; esac
        case "$p2" in ''|*[!0-9]*) mi_warn "runtime: publish container port '$p2' is not a port"; return 1 ;; esac
        # `if`, not `A && B || C`: the Global Constraints forbid that idiom outright, and the newer
        # linter in CI reports SC2015 on it. (Do NOT begin a wrapped comment line with the word
        # "shellcheck" — measured: `# shellcheck reports SC2015 on it.` is parsed as a DIRECTIVE and
        # fails the file with SC1072/SC1073 rather than reading as prose.)
        #
        # The LENGTH bound is not decoration. MEASURED on bash 3.2 here: `[` parses base 10, so a
        # leading zero is NOT octal to it (unlike `[[ … ]]` and `(( … ))`, where `010 -eq 8` is
        # true) — but a digit string too long for a machine integer makes `[` print "integer
        # expression expected" and return 2, and an `if` reads 2 as FALSE. Without the bound, a
        # 20-digit "port" would therefore pass BOTH range comparisons and be handed to docker.
        # Zeros are stripped first so the bound counts real digits and the argv is canonical.
        p1="$(_mi_rt_strip_zeros "$p1")"; p2="$(_mi_rt_strip_zeros "$p2")"
        if [ "${#p1}" -gt 5 ] || [ "$p1" -lt 1 ] || [ "$p1" -gt 65535 ]; then
          mi_warn "runtime: host port $p1 out of range"; return 1
        fi
        if [ "${#p2}" -gt 5 ] || [ "$p2" -lt 1 ] || [ "$p2" -gt 65535 ]; then
          mi_warn "runtime: container port $p2 out of range"; return 1
        fi
        # THE loopback wall (D26/§4b.1). The host IP is a constant here. A caller that wanted
        # 0.0.0.0 would have had to smuggle it through $p1, which the digit check above refuses.
        rtargv+=(-p "127.0.0.1:${p1}:${p2}")
        ;;
      label)
        p1="${body%%=*}"; p2="${body#*=}"
        case "$p1" in installation|nonce|product|role|generation) : ;;
          *) mi_warn "runtime: '$p1' is not a label this installer sets"; return 1 ;;
        esac
        rtargv+=(--label "${MI_RT_NS}.${p1}=${p2}")
        ;;
      *) mi_warn "runtime: unknown container spec '$s'"; return 1 ;;
    esac
  done

  rtargv+=(-- "$image")
  _mi_rt "${rtargv[@]}"
}

mi_rt_container_start() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_container_start needs <name>"; return 1; fi
  _mi_rt container start -- "$1"
}

mi_rt_container_stop() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_container_stop needs <name>"; return 1; fi
  _mi_rt container stop -- "$1"
}

mi_rt_container_rm() {
  if [ "$#" -ne 1 ]; then mi_warn "runtime: mi_rt_container_rm needs <name>"; return 1; fi
  _mi_rt container rm -f -- "$1"
}

# --- the helper container (D49/D54) ---------------------------------------------------------------
# One entry point for BOTH pinned helpers — the probe and the copy container — because they share
# every property that makes them safe: a digest-pinned image from the family index, a CLOSED command
# set, no product involvement, and `--rm`. A helper that took instructions would be an execution
# primitive (D49), so the command is chosen by the caller from a fixed vocabulary and the adapter
# passes nothing else.
#
# <netspec> is either `none` (the copy container — D54 requires it, and this is the one legitimate
# use of `none` in the design, since the copy never joins a network) or a network ID (the probe).
# <runas> is `-` or a numeric uid (D58's effective-access check runs AS the product's runtime uid).
#
# `--rm` IS THE HALF OF THE CONTRACT THAT SAYS NO HELPER OUTLIVES ITS OWN INVOCATION. The other half is
# that while it DOES live it is an object like any other (§6a/§6b): named, and labelled with both the
# nonce and the installation, through the `name=` and `install=` specs below. A helper carrying only a
# nonce is anonymous — a nonce says WHICH object, never WHOSE — so a leaked one could never be shown to
# be ours, nothing would be authorized to remove it, and §6b.2's classifier would read a
# daemon-assigned name as a stranger's object and ignore it entirely.
mi_rt_run_helper() {
  if [ "$#" -lt 5 ]; then
    mi_warn "runtime: mi_rt_run_helper needs <image> <netspec> <runas> <label-nonce> <cmd> [args...]"
    return 1
  fi
  local image="$1" netspec="$2" runas="$3" nonce="$4" cmd="$5"
  shift 5
  case "$cmd" in
    resolve|selfcheck|egress|preflight|copy|verify|acl|access) : ;;
    *) mi_warn "runtime: '$cmd' is not a helper command"; return 1 ;;
  esac
  # TWO argument positions, and confusing them is a SILENT failure rather than an error: everything
  # before `-- <image>` is a flag DOCKER reads, everything after `<cmd>` is an argument OUR entrypoint
  # reads. An earlier draft appended every extra argument to the pre-image array, so the probe's alias
  # was handed to docker as a flag and the helper ran with no alias at all — `resolve` then answered
  # about nothing, every live verification failed, and D42 step 5 could never pass. Found by executing
  # a bring-up end to end, not by reading it.
  local -a rtargv rtpost
  rtargv=(container run --rm --label "${MI_RT_NS}.nonce=${nonce}")
  rtpost=()
  if [ "$netspec" = none ]; then
    rtargv+=(--network none)
  else
    _mi_rt_netmode_ok "$netspec" || return 1
    rtargv+=(--network "$netspec")
  fi
  if [ "$runas" != "-" ]; then
    case "$runas" in ''|*[!0-9]*) mi_warn "runtime: --user must be a numeric uid"; return 1 ;; esac
    rtargv+=(--user "$runas")
  fi
  # TYPED specs only. There is deliberately no verbatim pass-through: a generic escape hatch here
  # would return every launch invariant in this module to the call sites.
  local s
  for s in "$@"; do
    case "$s" in
      # Every one of the three below is VALIDATED, not interpolated. The callers are this codebase's
      # own code today, but the guarantee this module documents is STRUCTURAL — "no caller can express
      # an unsafe launch" — and a later task passes an operator-influenced destination through
      # `staging=`. Unvalidated, `staging=/host,bind-propagation=rshared` becomes a real
      # bind-propagation option on the one writable mount the helper has.
      #
      # The SOURCE volume is mounted READ-ONLY: the copy has no reason to write to what it is
      # preserving, and a bug or a hostile payload that mutates the source destroys the original
      # before the copy is verified (D54).
      srcvol=*)  _mi_rt_volume_name_ok "${s#srcvol=}" || { mi_warn "runtime: refusing helper spec '$s'"; return 1; }
                 rtargv+=(--mount "type=volume,source=${s#srcvol=},target=/src,readonly") ;;
      # STAGING IS THE ONLY WRITABLE MOUNT, and nothing else from the host is mounted at all.
      staging=*) _mi_rt_bind_path_ok "${s#staging=}" "helper staging source" || return 1
                 rtargv+=(--mount "type=bind,source=${s#staging=},target=/dst") ;;
      dstro=*)   _mi_rt_bind_path_ok "${s#dstro=}" "helper read-only source" || return 1
                 rtargv+=(--mount "type=bind,source=${s#dstro=},target=/dst,readonly") ;;
      # THE REVERSE PAIR (Task 13, §6c/D59 restore): filling a freshly created volume from a backup's
      # host tree needs mount roles exactly opposite srcvol=/staging= above — a read-only BIND at /src
      # (the backup's untrusted tree is a host directory, not a volume) and a WRITABLE VOLUME at /dst
      # (the destination being filled). The copy container's own command word and transcript grammar do
      # not change: "copy /src /dst <ruid> <ouid>" reads whatever backs /src and writes whatever backs
      # /dst, so no new closed command word is needed — only these two new mount specs (lib/copy.sh's
      # mi_copy_fill assembles them; mi_copy_run/mi_copy_available's existing callers never use them).
      srcbind=*) _mi_rt_bind_path_ok "${s#srcbind=}" "helper read-only bind source" || return 1
                 rtargv+=(--mount "type=bind,source=${s#srcbind=},target=/src,readonly") ;;
      dstvol=*)  _mi_rt_volume_name_ok "${s#dstvol=}" || { mi_warn "runtime: refusing helper spec '$s'"; return 1; }
                 rtargv+=(--mount "type=volume,source=${s#dstvol=},target=/dst") ;;
      # Keep the container's stdin open. The ONLY use today is restore's per-entry manifest verify
      # (Task 13): the manifest is handed to the helper on stdin rather than as a THIRD host mount, so
      # a restore never has to mount an extra untrusted path just to authenticate against it. `docker
      # run` detaches stdin by default; without this a caller piping data into `_mi_copy_helper` would
      # silently reach nothing.
      stdin=1)   rtargv+=(-i) ;;
      # The name the caller's own record names it by, and the installation it belongs to — the same
      # two facts every other create in this module records. See the note above the function.
      name=*)    _mi_rt_arg_ok "${s#name=}" || { mi_warn "runtime: invalid helper container name"; return 1; }
                 rtargv+=(--name "${s#name=}") ;;
      # A per-run DNS name for this container on the network it is joining (D49's selfcheck asks the
      # probe to resolve the name it was registered under). It is a NETWORK alias, so it is refused
      # outright when there is no network: a container in private (`none`) mode has no resolver for a
      # name to be registered with, and a daemon asked for both answers with an error rather than a
      # container. Refusing here means no caller can build that call at all.
      netalias=*) if [ "$netspec" = none ]; then
                    mi_warn "runtime: a network alias cannot be registered on a helper with no network"
                    return 1
                  fi
                  _mi_rt_arg_ok "${s#netalias=}" || { mi_warn "runtime: invalid helper network alias"; return 1; }
                  rtargv+=(--network-alias "${s#netalias=}") ;;
      install=*) _mi_rt_arg_ok "${s#install=}" || { mi_warn "runtime: invalid installation identity"; return 1; }
                 rtargv+=(--label "${MI_RT_NS}.installation=${s#install=}") ;;
      # An argument to the CLOSED command word, INSIDE the container — never a docker flag. Every
      # value passed this way is a container-internal path or an alias this code computed.
      arg=*)     rtpost+=("${s#arg=}") ;;
      *) mi_warn "runtime: unknown helper spec '$s'"; return 1 ;;
    esac
  done
  # `${rtpost[@]+"${rtpost[@]}"}` — under `set -u`, bash 3.2 errors on "${rtpost[@]}" for an EMPTY
  # array, which is the ordinary case for selfcheck and egress.
  _mi_rt "${rtargv[@]}" -- "$image" "$cmd" ${rtpost[@]+"${rtpost[@]}"}
}
