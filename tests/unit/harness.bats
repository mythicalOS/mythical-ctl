load '../lib/test_helper'

@test "fake docker records and inspects a labelled volume, with no Id" {
  docker volume create --label mythical.nonce=n1 vol-a
  run docker volume inspect vol-a
  assert_ok
  assert_contains '"Name": "vol-a"'
  assert_contains 'mythical.nonce=n1'
  case "$output" in *'"Id"'*) echo "volumes must not report an Id"; return 1;; esac
}

@test "creating an existing volume does not overwrite labels (real semantics)" {
  docker volume create --label mythical.nonce=n1 vol-b
  docker volume create --label mythical.nonce=n2 vol-b   # must NOT change the label
  run docker volume inspect vol-b
  assert_contains 'mythical.nonce=n1'
  case "$output" in *n2*) echo "existing volume label was overwritten"; return 1;; esac
}

@test "pull outcome is programmable" {
  FAKE_DOCKER_PULL=notfound run docker image pull ghcr.io/x/y@sha256:deadbeef
  [ "$status" -ne 0 ]
  assert_contains "not found"
  FAKE_DOCKER_PULL=ok run docker image pull ghcr.io/x/y@sha256:deadbeef
  assert_ok
}

@test "every call is logged" {
  docker volume create vol-c
  docker volume rm vol-c
  grep -q 'volume create' "$FAKE_DOCKER_STATE/calls.log"
  grep -q 'volume rm'     "$FAKE_DOCKER_STATE/calls.log"
}

@test "info reports a programmable server version" {
  FAKE_DOCKER_SERVER_VERSION=27.1.0 run docker info --format '{{.ServerVersion}}'
  assert_contains "27.1.0"
}

@test "fs snapshot is stable across a no-op and detects a new file" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  snap_fs "$BATS_TEST_TMPDIR/a"
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  assert_ok
  echo hello > "$MYTHICAL_HOME/brokkr.conf"
  snap_fs "$BATS_TEST_TMPDIR/c"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/c"
  [ "$status" -eq 1 ]
  assert_contains "brokkr.conf"
}

@test "fs snapshot detects an in-place content change with the SAME mode" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  echo one > "$MYTHICAL_HOME/brokkr.conf"; chmod 600 "$MYTHICAL_HOME/brokkr.conf"
  snap_fs "$BATS_TEST_TMPDIR/a"
  echo two > "$MYTHICAL_HOME/brokkr.conf"; chmod 600 "$MYTHICAL_HOME/brokkr.conf"  # same mode, new bytes
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  [ "$status" -eq 1 ]
  assert_contains "brokkr.conf"
}

@test "fs snapshot is robust to a filename containing a newline and a tab" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  # A user-data file whose name contains a newline AND a tab must not split or corrupt the snapshot:
  # exactly one line per entry, stable across a no-op, and its content change is still detected.
  printf 'x' > "$MYTHICAL_HOME/weird"$'\n'"na"$'\t'"me"
  snap_fs "$BATS_TEST_TMPDIR/a"
  # the weird name must appear on EXACTLY ONE line, escaped (no split into false paths). -F: the
  # pattern is the literal escaped form `weird\nna\tme` (backslash-n, backslash-t) that _snap_enc writes.
  [ "$(grep -Fc 'weird\nna\tme' "$BATS_TEST_TMPDIR/a")" -eq 1 ]
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  assert_ok
  printf 'CHANGED' > "$MYTHICAL_HOME/weird"$'\n'"na"$'\t'"me"
  snap_fs "$BATS_TEST_TMPDIR/c"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/c"
  [ "$status" -eq 1 ]
}

@test "fs snapshot does not hang on a FIFO — special files are recorded, never read" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  # A named pipe in user data must not be hashed (a reader would block forever). It is recorded by
  # type instead, so the snapshot completes. `run` fails the test if snap_fs hangs (bats times out).
  mkfifo "$MYTHICAL_HOME/apipe"
  run snap_fs "$BATS_TEST_TMPDIR/a"
  assert_ok
  grep -qE '/apipe	special	' "$BATS_TEST_TMPDIR/a"
}

@test "runtime snapshot captures volumes and their labels" {
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  docker volume create --label mythical.nonce=n1 vol-x
  snap_runtime "$BATS_TEST_TMPDIR/r"
  grep -q 'vol-x' "$BATS_TEST_TMPDIR/r"
  grep -q 'mythical.nonce=n1' "$BATS_TEST_TMPDIR/r"
}

# --- resource names are path components, so they are the fake's own attack surface ----------------
# Re-point the fake's state INSIDE bats' per-test tmpdir, so a `../../` escape lands in a tree bats
# removes after the test and the assertions can name the exact escaped path. $STATE/<kind>/../../x
# resolves to the state directory's PARENT, which is $ESC below.
# The original mktemp state dir is removed first, so nothing leaks even if the test fails early.
relocate_fake_state() {
  rm -rf "$FAKE_DOCKER_STATE"
  FAKE_DOCKER_STATE="$BATS_TEST_TMPDIR/fake/state"
  export FAKE_DOCKER_STATE
  mkdir -p "$FAKE_DOCKER_STATE"
  ESC="$BATS_TEST_TMPDIR/fake"
}

@test "a name that traverses out of the state directory is refused for every resource kind" {
  # MEASURED against the pre-fix fake: `docker network create ../../x` resolved to
  # $FAKE_DOCKER_STATE/networks/../../x and CREATED a file outside the fake's own state directory —
  # test isolation gone, and the fake materially MORE PERMISSIVE than the real daemon, which refuses
  # such names outright. That is the one thing this file must never be.
  local before after
  relocate_fake_state
  # The container attempt must be one that would otherwise SUCCEED, so its refusal can only be the
  # name rule: the image is pulled and the network exists first.
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  before="$(ls -a "$ESC")"

  run docker network create ../../escapee-network
  [ "$status" -ne 0 ] || { echo "network create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker volume create ../../escapee-volume
  [ "$status" -ne 0 ] || { echo "volume create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker container create --name ../../escapee-container --network "$net" -- demo/img:tag
  [ "$status" -ne 0 ] || { echo "container create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'

  # Per kind, and then over the whole directory: an escape under ANY other name is caught too.
  [ ! -e "$ESC/escapee-network" ]   || { echo "network create wrote outside the state dir" >&2; return 1; }
  [ ! -e "$ESC/escapee-volume" ]    || { echo "volume create wrote outside the state dir" >&2; return 1; }
  [ ! -e "$ESC/escapee-container" ] || { echo "container create wrote outside the state dir" >&2; return 1; }
  after="$(ls -a "$ESC")"
  [ "$before" = "$after" ] \
    || { echo "the state directory's parent changed:"; diff <(echo "$before") <(echo "$after"); return 1; }
}

@test "a traversing name cannot read or rewrite a file that already exists outside the state dir" {
  # The other half of the escape, and the more alarming one: a name that resolves onto an EXISTING
  # file makes the fake treat that file as one of its own records. All three MEASURED against the
  # pre-fix fake, with the file holding 'IMPORTANT DATA':
  #
  #   docker volume create  ../../canary → rc 0   ("existing volume" — the outside file is adopted)
  #   docker volume inspect ../../canary → rc 0   ({ "Name": "../../canary", … } — outside file read)
  #   docker container start ../../canary → rc 0  and rec_set's `mv -f` REWROTE the file, which then
  #                                               read: IMPORTANT DATA / state=running / nets=
  local body
  relocate_fake_state
  printf 'IMPORTANT DATA\n' > "$ESC/canary"

  run docker volume create ../../canary
  [ "$status" -ne 0 ] || { echo "volume create adopted a file outside the state dir" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker volume inspect ../../canary
  [ "$status" -ne 0 ] || { echo "volume inspect read a file outside the state dir: $output" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker container start ../../canary
  [ "$status" -ne 0 ] || { echo "container start acted on a file outside the state dir" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'

  body="$(cat "$ESC/canary")"
  [ "$body" = "IMPORTANT DATA" ] \
    || { echo "a file outside the state directory was rewritten: $body" >&2; return 1; }
  # And no mktemp publish temp was left there either — rec_set builds its temp beside its target.
  [ "$(ls -A "$ESC" | grep -ac .)" = 2 ] \
    || { echo "unexpected entries beside the state dir: $(ls -A "$ESC")" >&2; return 1; }
}

@test "every subcommand that takes a name validates it, not only create" {
  # A rule applied only at create is a rule with a door beside it: inspect, rm, start, stop, connect
  # and disconnect all spell their argument into the same directory.
  local sub
  relocate_fake_state
  for sub in "volume inspect" "volume rm" "network inspect" "network rm" \
             "container inspect" "container rm" "container start" "container stop"; do
    # Deliberate word split: $sub is a two-word subcommand.
    run docker $sub ../../escapee
    [ "$status" -ne 0 ] || { echo "docker $sub accepted a traversing name" >&2; return 1; }
    assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  done
  run docker network connect --alias a --gw-priority 0 -- ../../escapee c1
  [ "$status" -ne 0 ] || { echo "network connect accepted a traversing network" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker network disconnect -- n1 ../../escapee
  [ "$status" -ne 0 ] || { echo "network disconnect accepted a traversing container" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  [ ! -e "$ESC/escapee" ] || { echo "a lookup wrote outside the state dir" >&2; return 1; }
  # The EMPTY name is the same defect wearing nothing: `$STATE/containers/` is the containers
  # DIRECTORY, `[ -e ]` accepts it, and the pre-fix fake rendered a field from it and exited 0.
  run docker container inspect --format '{{.Id}}' -- ""
  [ "$status" -ne 0 ] || { echo "container inspect accepted an empty name (output: '$output')" >&2; return 1; }
}

@test "image records are keyed by the exact reference, not a character-folded one" {
  # `tr -c 'A-Za-z0-9._-' '_'` folded `foo/bar:tag` and `foo_bar:tag` to the SAME key `foo_bar_tag`,
  # so pulling one satisfied the create/run image gate for the other and that gate stopped meaning
  # "this image was pulled". Real Docker treats them as different repositories.
  local net
  net="$(docker network create n1)"
  docker image pull foo/bar:tag >/dev/null

  run docker image inspect --format '{{index .RepoDigests 0}}' -- foo_bar:tag
  [ "$status" -ne 0 ] || { echo "an unpulled reference inspected as present: $output" >&2; return 1; }
  assert_contains "No such image: foo_bar:tag"
  run docker container create --name c1 --network "$net" -- foo_bar:tag
  [ "$status" -ne 0 ] || { echo "create accepted an image that was never pulled" >&2; return 1; }
  assert_contains "Unable to find image 'foo_bar:tag' locally"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  run docker container run --rm --network none -- foo_bar:tag selfcheck
  [ "$status" -ne 0 ] || { echo "run accepted an image that was never pulled" >&2; return 1; }
  assert_contains "Unable to find image 'foo_bar:tag' locally"
  # The reference that WAS pulled still resolves, so the new key did not simply break every lookup.
  run docker container create --name c2 --network "$net" -- foo/bar:tag
  assert_ok
}

# --- a network the daemon does not have ------------------------------------------------------------
# `--network` and `network connect`'s first argument are RESOLVED by a real daemon, against the
# networks it actually has. This fake required only a non-empty string, so a container could be
# created on, and connected to, a network that exists nowhere — accepted here, refused there.

@test "a container cannot be created on a network that does not exist" {
  # MEASURED against the pre-fix fake: `container create --network nonexistent` exited 0 and recorded
  # an attachment to a network no `network create` ever made. Two costs. The fake was more permissive
  # than the daemon, which is the one thing it must never be; and bring-up's step 2 — "the container
  # is attached to exactly the EXPECTED network ID" — had nothing that could fail it, so a missing or
  # broken ID-propagation guard in a later task would read as green.
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"

  run docker container create --name c1 --network nonexistent -- demo/img:tag
  [ "$status" -ne 0 ] || { echo "create accepted a network that does not exist" >&2; return 1; }
  assert_contains "network nonexistent not found"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }

  # The positive controls: a real daemon resolves the network by ID *and* by name, so both must work
  # here or the refusal above would be indistinguishable from a create that simply stopped working.
  run docker container create --name c1 --network "$net" -- demo/img:tag
  assert_ok
  run docker container create --name c2 --network n1 -- demo/img:tag
  assert_ok
  # And the attachment is recorded under the network's ID, never under the name it was reached by.
  # That ID is precisely what bring-up compares against; a fake that echoed the name back would make
  # the comparison pass for the wrong reason.
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c2
  [ "$output" = "${net}=;" ] \
    || { echo "attached as '$output', expected the network ID '${net}=;'" >&2; return 1; }

  # `container run` — the helper arm, which is how the probe joins the family network (D42 step 5) —
  # resolves the same way. A fake that is faithful in one arm and permissive in the other is a guard
  # with a door beside it. The MESSAGE is pinned because this arm dies for a second reason anyway
  # (no fixture entrypoint), and a status-only assertion would pass on that instead.
  run docker container run --rm --network nonexistent -- demo/img:tag selfcheck
  [ "$status" -ne 0 ] || { echo "run accepted a network that does not exist" >&2; return 1; }
  assert_contains "network nonexistent not found"
}

@test "network connect refuses a network that does not exist, and attaches by ID" {
  # The other half of the same gap: `network connect` validated only the SPELLING of its arguments
  # (wave 2's traversal rule), never whether the network was there. Pre-fix this succeeded and left
  # the container attached to a fabricated id.
  local net net2
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  net2="$(docker network create n2)"
  docker container create --name c1 --network "$net" -- demo/img:tag >/dev/null

  run docker network connect --alias a --gw-priority 0 -- nonexistent c1
  [ "$status" -ne 0 ] || { echo "connect accepted a network that does not exist" >&2; return 1; }
  assert_contains "network nonexistent not found"
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c1
  [ "$output" = "${net}=;" ] \
    || { echo "the refused connect changed the attachments: $output" >&2; return 1; }

  # Positive control, by NAME, recorded under the ID — same rule as create.
  run docker network connect --alias a --gw-priority 0 -- n2 c1
  assert_ok
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c1
  [ "$output" = "${net}=;${net2}=;" ] \
    || { echo "attached as '$output', expected '${net}=;${net2}=;'" >&2; return 1; }
}

@test "network create records the driver it was ASKED for, not an assumed one" {
  # `--driver` was consumed and thrown away, and the record was written as
  # `${FAKE_DOCKER_NET_DRIVER:-bridge}` regardless. The consequence is not cosmetic: `--driver bridge`
  # could be DELETED from the adapter with the whole suite green, and that flag is the D29 NAT wall
  # (the default is already `bridge`; it is passed explicitly so a daemon-level default change cannot
  # silently remove it). A knob that answers `bridge` no matter what was asked cannot tell the two
  # apart, so it made the guard untestable.
  local d
  docker network create --driver macvlan m1 >/dev/null
  run docker network inspect --format '{{.Driver}}' -- m1
  [ "$output" = "macvlan" ] || { echo "driver recorded as '$output', asked for macvlan" >&2; return 1; }
  # The `--driver=<value>` spelling is the same flag.
  docker network create --driver=ipvlan i1 >/dev/null
  run docker network inspect --format '{{.Driver}}' -- i1
  [ "$output" = "ipvlan" ] || { echo "driver recorded as '$output', asked for ipvlan" >&2; return 1; }
  # No --driver at all is `bridge`, exactly as a real daemon's default is.
  docker network create d1 >/dev/null
  run docker network inspect --format '{{.Driver}}' -- d1
  [ "$output" = "bridge" ] || { echo "the default driver is '$output', not bridge" >&2; return 1; }

  # A driver the daemon has no plugin for is refused, and nothing is recorded.
  run docker network create --driver bogus b1
  [ "$status" -ne 0 ] || { echo "an unknown driver was accepted" >&2; return 1; }
  assert_contains "bogus"
  [ ! -e "$FAKE_DOCKER_STATE/networks/b1" ] \
    || { echo "the refused create still recorded a network" >&2; return 1; }
  # `host` and `none` are PRE-DEFINED networks; a real daemon refuses to create another.
  for d in host none; do
    run docker network create --driver "$d" "x-$d"
    [ "$status" -ne 0 ] || { echo "network create --driver $d was accepted" >&2; return 1; }
  done

  # FAKE_DOCKER_NET_DRIVER still OVERRIDES the requested driver, and must keep doing so: it is how a
  # test fabricates a macvlan/ipvlan network the adapter cannot legitimately create, which is what
  # the preflight refusals are tested against. Honouring `--driver` must not cost that.
  export FAKE_DOCKER_NET_DRIVER=macvlan
  docker network create --driver bridge k1 >/dev/null
  unset FAKE_DOCKER_NET_DRIVER
  run docker network inspect --format '{{.Driver}}' -- k1
  [ "$output" = "macvlan" ] \
    || { echo "FAKE_DOCKER_NET_DRIVER no longer wins: got '$output'" >&2; return 1; }
}

# --- the closed surface: flags, positionals and templates -------------------------------------------
# Three review rounds each found the same defect one arm at a time — the fake accepting what a real
# daemon refuses. The rounds below sweep the whole surface instead: every arm was asked whether it
# takes an input Docker rejects. These four tests cover the argument layer, which was uniformly
# permissive: unknown flags swallowed, extra positionals discarded, templates answered regardless.

@test "an unimplemented flag is refused by every arm, never silently ignored" {
  # The one that decides the question is `container run -v /:/hostroot`: MEASURED against the pre-fix
  # fake it exited 0 with the flag DROPPED, so a whole-host bind mount was reported as a clean run.
  # A fake that ignores a flag is worse than one that lacks it — the ignored case is a container
  # escape a test calls green.
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  fake_helper 'exit 0'

  run docker container run --rm --network none -v /:/hostroot -- demo/img:tag selfcheck
  [ "$status" -ne 0 ] || { echo "container run ignored -v /:/hostroot" >&2; return 1; }
  assert_contains "does not implement the flag -v"
  run docker container create --name c1 --network "$net" --user 1000 -- demo/img:tag
  [ "$status" -ne 0 ] || { echo "container create ignored --user" >&2; return 1; }
  assert_contains "does not implement the flag --user"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  run docker volume create --driver local v1
  [ "$status" -ne 0 ] || { echo "volume create ignored --driver" >&2; return 1; }
  [ ! -e "$FAKE_DOCKER_STATE/volumes/v1" ] \
    || { echo "the refused create still recorded a volume" >&2; return 1; }
  run docker network create --subnet 10.0.0.0/24 n2
  [ "$status" -ne 0 ] || { echo "network create ignored --subnet" >&2; return 1; }
  run docker container ls -q
  [ "$status" -ne 0 ] || { echo "container ls ignored -q" >&2; return 1; }
  run docker image pull -q other/img:tag
  [ "$status" -ne 0 ] || { echo "image pull ignored -q" >&2; return 1; }
  # And the flags the adapter really does emit still work, so the rule refuses the unimplemented
  # rather than the unfamiliar.
  run docker container create --name c2 --network "$net" --network-alias p1 --label mythicalos.nonce=n \
      -p 127.0.0.1:7480:7480 -- demo/img:tag
  assert_ok
}

@test "a subcommand that acts on one object refuses a second one" {
  # Docker's CLI errors on the extra argument; this fake kept the LAST and discarded the rest, so
  # `volume create v2 v3` created v3 alone and reported success, and a container create with a
  # COMMAND resolved the command word as the image ("Unable to find image 'infinity' locally").
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"

  run docker volume create v2 v3
  [ "$status" -ne 0 ] || { echo "volume create accepted two names" >&2; return 1; }
  [ ! -e "$FAKE_DOCKER_STATE/volumes/v3" ] && [ ! -e "$FAKE_DOCKER_STATE/volumes/v2" ] \
    || { echo "a refused two-name create still recorded a volume" >&2; return 1; }
  run docker volume inspect --format '{{.Driver}}' va vb
  [ "$status" -ne 0 ] || { echo "volume inspect accepted two names" >&2; return 1; }
  run docker network rm n1 n2
  [ "$status" -ne 0 ] || { echo "network rm accepted two names" >&2; return 1; }
  [ -e "$FAKE_DOCKER_STATE/networks/n1" ] \
    || { echo "the refused rm removed the network anyway" >&2; return 1; }
  run docker image pull demo/img:tag other/img:tag
  [ "$status" -ne 0 ] || { echo "image pull accepted two references" >&2; return 1; }
  run docker container create --name c1 --network "$net" -- demo/img:tag sleep infinity
  [ "$status" -ne 0 ] || { echo "container create accepted a command" >&2; return 1; }
  assert_contains "command is not implemented"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
}

@test "version, info and context answer only the templates they implement" {
  # Every one of these arms printed ONE answer for ANY template. `version --format
  # '{{.Client.Version}}'` returned the SERVER version, so the preflight engine gate (D29, engine
  # 28+) could have been comparing the CLI's own version with the suite green; `info --format
  # '{{.OSType}}'` returned the SecurityOptions string, so the rootless gate could have been reading
  # any field at all. The two versions differ here precisely so the fields are distinguishable.
  run docker version --format '{{.Server.Version}}'
  [ "$output" = "28.0.0" ] || { echo "server version is '$output'" >&2; return 1; }
  run docker version --format '{{.Client.Version}}'
  [ "$output" = "99.0.0" ] || { echo "client version is '$output', not a distinct field" >&2; return 1; }
  run docker version --format '{{.Nope}}'
  [ "$status" -ne 0 ] || { echo "version answered an unimplemented template: $output" >&2; return 1; }
  assert_contains "unsupported version template"

  run docker info --format '{{range .SecurityOptions}}{{.}} {{end}}'
  assert_contains "seccomp"
  run docker info --format '{{.OSType}}'
  [ "$status" -ne 0 ] || { echo "info answered an unimplemented template: $output" >&2; return 1; }
  assert_contains "unsupported info template"

  run docker context inspect --format '{{.Endpoints.docker.Host}}'
  [ "$output" = "unix:///var/run/docker.sock" ] || { echo "context host is '$output'" >&2; return 1; }
  run docker context inspect --format '{{.Name}}'
  [ "$status" -ne 0 ] || { echo "context answered an unimplemented template: $output" >&2; return 1; }
  # A NAMED context is not the active one, and answering as if it were is how a test about the wrong
  # daemon passes.
  run docker context inspect --format '{{.Endpoints.docker.Host}}' some-other-context
  [ "$status" -ne 0 ] || { echo "context inspect answered for a named context: $output" >&2; return 1; }
}

@test "ls answers only the templates and filters it implements" {
  # `--format` was parsed off and thrown away, so every template printed the NAME: an adapter asking
  # for the driver, the id or the image would have been handed names and its lookup would have
  # "worked". A non-label `--filter` matched nothing and reported success — the emptiest possible
  # wrong answer — and a second `--filter` silently replaced the first, where a real daemon ANDs them.
  docker volume create --label mythicalos.nonce=n1 v1 >/dev/null
  run docker volume ls --format '{{.Name}}'
  [ "$output" = "v1" ] || { echo "volume ls --format '{{.Name}}' gave '$output'" >&2; return 1; }
  run docker volume ls --format '{{.Driver}}'
  [ "$status" -ne 0 ] || { echo "volume ls answered an unimplemented template: $output" >&2; return 1; }
  assert_contains "unsupported volume ls template"
  run docker container ls -a --format '{{.ID}}'
  [ "$status" -ne 0 ] || { echo "container ls answered an unimplemented template: $output" >&2; return 1; }
  run docker volume ls --filter dangling=true
  [ "$status" -ne 0 ] || { echo "volume ls accepted a filter it cannot apply: '$output'" >&2; return 1; }
  assert_contains "only label= filters"
  run docker volume ls --filter label=mythicalos.nonce=n1 --filter label=mythicalos.nonce=n2
  [ "$status" -ne 0 ] || { echo "volume ls accepted two filters and applied one: '$output'" >&2; return 1; }
  run docker network ls n1
  [ "$status" -ne 0 ] || { echo "network ls accepted a positional argument" >&2; return 1; }
}

# --- referenced resources, conflicting state, and arguments that were accepted but ignored ---------

@test "a resource that is still referenced cannot be removed" {
  # §6b's teardown ordering is detach-then-remove, and the daemon is what enforces it. This fake
  # removed a network with a container attached, a volume a container mounts, and a RUNNING container
  # without `-f` — so the ordering was a convention no test could fail on, and `container rm -f`
  # could have been reduced to `container rm` with the suite green.
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  docker volume create vv >/dev/null
  docker container create --name c1 --network "$net" --mount type=volume,source=vv,target=/d -- demo/img:tag >/dev/null

  run docker network rm n1
  [ "$status" -ne 0 ] || { echo "removed a network with an attached container" >&2; return 1; }
  assert_contains "has active endpoints"
  run docker volume rm vv
  [ "$status" -ne 0 ] || { echo "removed a volume a container mounts" >&2; return 1; }
  assert_contains "volume is in use"

  docker container start c1 >/dev/null
  run docker container rm c1
  [ "$status" -ne 0 ] || { echo "removed a RUNNING container without -f" >&2; return 1; }
  assert_contains "You cannot remove a running container"
  [ -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused rm removed the container anyway" >&2; return 1; }
  # -f is what makes it possible, and once the container is gone both removals are allowed.
  run docker container rm -f c1
  assert_ok
  run docker volume rm vv
  assert_ok
  run docker network rm n1
  assert_ok
}

@test "network connect refuses a duplicate endpoint and a private-mode container, and the container name is always an alias" {
  # Three gaps in one arm. Connecting the SAME network twice appended a second attachment (a real
  # daemon: "endpoint with name … already exists"), a container in `none` mode was attached happily
  # (the daemon refusal lib/runtime.sh's D26/D42 comment CITES as its reason), and an omitted
  # `--alias` recorded an EMPTY alias list — so §6b.2's explicit alias was unobservable.
  local net net2 nets
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  net2="$(docker network create n2)"
  docker container create --name c1 --network "$net" -- demo/img:tag >/dev/null

  run docker network connect --alias a --gw-priority 0 -- n1 c1
  [ "$status" -ne 0 ] || { echo "connected the same network twice" >&2; return 1; }
  assert_contains "already exists in network"
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c1
  [ "$output" = "${net}=;" ] \
    || { echo "the refused connect changed the attachments: $output" >&2; return 1; }

  docker container create --name c2 --network none -- demo/img:tag >/dev/null
  run docker network connect --alias a --gw-priority 0 -- n2 c2
  [ "$status" -ne 0 ] || { echo "connected a container in private (none) mode" >&2; return 1; }
  assert_contains "private (none) mode"

  # The automatic alias: a real daemon makes the container reachable under its own NAME, so an
  # attachment made WITHOUT --alias is not aliasless — it carries the name and nothing else, which is
  # exactly §9's "no sibling can guess it" failure and is now visible in the record.
  run docker network connect -- n2 c1
  assert_ok
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}:{{range $v.Aliases}}{{.}},{{end}};{{end}}' -- c1
  nets="$output"
  case "$nets" in *"${net2}:c1,"*) : ;; *) echo "no automatic name alias: $nets" >&2; return 1 ;; esac
  # And an EXPLICIT alias is recorded alongside it, so the two cases are distinguishable.
  docker container create --name c3 --network "$net" --network-alias p1 -- demo/img:tag >/dev/null
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}:{{range $v.Aliases}}{{.}},{{end}};{{end}}' -- c3
  [ "$output" = "${net}:p1,c3,;" ] \
    || { echo "explicit + automatic alias came out as '$output'" >&2; return 1; }
}

@test "network disconnect resolves its network and refuses a container that is not attached" {
  # The arm took its argument as a literal id and filtered attachments by prefix, so: a detach from a
  # network that does not exist reported SUCCESS, a detach naming the network by NAME matched nothing
  # and reported success, and a detach of a container that was never attached reported success. Three
  # different "it worked" answers for three calls that detached nothing.
  local net net2
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  net2="$(docker network create n2)"
  docker container create --name c1 --network "$net" -- demo/img:tag >/dev/null

  run docker network disconnect -- nonexistent c1
  [ "$status" -ne 0 ] || { echo "disconnect accepted a network that does not exist" >&2; return 1; }
  assert_contains "network nonexistent not found"
  run docker network disconnect -- n2 c1
  [ "$status" -ne 0 ] || { echo "disconnect accepted a network the container is not on" >&2; return 1; }
  assert_contains "is not connected to network"

  # By NAME, the attachment is found and removed — the pre-fix arm silently matched nothing here.
  run docker network disconnect -- n1 c1
  assert_ok
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c1
  [ -z "$output" ] || { echo "the attachment survived a detach by name: $output" >&2; return 1; }

  # FAKE_DOCKER_DISCONNECT_SILENT still fabricates §10a's silent detach failure, on a REAL
  # attachment: success reported, attachment intact.
  docker network connect --alias a --gw-priority 0 -- n1 c1
  export FAKE_DOCKER_DISCONNECT_SILENT=1
  run docker network disconnect -- n1 c1
  unset FAKE_DOCKER_DISCONNECT_SILENT
  assert_ok
  run docker container inspect \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}={{$v.IPAddress}};{{end}}' -- c1
  [ "$output" = "${net}=;" ] \
    || { echo "the silent-detach knob no longer keeps the attachment: '$output'" >&2; return 1; }
}

@test "a missing --env-file is refused, and a two-field publish records the address the daemon binds" {
  # `--env-file` was accepted and IGNORED, which left lib/runtime.sh's own existence check as the
  # only thing refusing it — a guard whose deletion changes nothing observable. §4.3 puts bootstrap
  # secrets in that file.
  #
  # `-p` assumed the three-field form and read the HOST PORT as the host IP, so `-p 7480:7480` was
  # recorded as the nonsense `7480/tcp=7480:7480`. Its real meaning is a bind on ALL addresses, which
  # the daemon reports as 0.0.0.0 — the very thing D26/§4b.1 exists to prevent, and the fake could
  # not have shown it.
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"

  run docker container create --name c1 --network "$net" --env-file "$BATS_TEST_TMPDIR/absent.env" -- demo/img:tag
  [ "$status" -ne 0 ] || { echo "create accepted an env file that does not exist" >&2; return 1; }
  assert_contains "no such file or directory"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  : > "$BATS_TEST_TMPDIR/present.env"
  run docker container create --name c1 --network "$net" --env-file "$BATS_TEST_TMPDIR/present.env" -- demo/img:tag
  assert_ok

  docker container create --name c2 --network "$net" -p 7480:7480 -- demo/img:tag >/dev/null
  run docker container inspect \
    --format '{{range $p,$bs := .NetworkSettings.Ports}}{{range $bs}}{{$p}}={{.HostIp}}:{{.HostPort}};{{end}}{{end}}' -- c2
  [ "$output" = "7480/tcp=0.0.0.0:7480;" ] \
    || { echo "a two-field publish recorded '$output', not the 0.0.0.0 bind it is" >&2; return 1; }
  docker container create --name c3 --network "$net" -p 127.0.0.1:7480:7480 -- demo/img:tag >/dev/null
  run docker container inspect \
    --format '{{range $p,$bs := .NetworkSettings.Ports}}{{range $bs}}{{$p}}={{.HostIp}}:{{.HostPort}};{{end}}{{end}}' -- c3
  [ "$output" = "7480/tcp=127.0.0.1:7480;" ] \
    || { echo "a three-field publish recorded '$output'" >&2; return 1; }
}

@test "container run without --rm leaves the container behind, as a real daemon does" {
  # `--rm` was parsed and discarded, and no container was ever recorded for a `run` — so the flag
  # that guarantees no pinned helper outlives its own invocation (D49/D54) could be deleted from the
  # adapter with nothing anywhere for a test to find.
  docker image pull demo/img:tag >/dev/null
  fake_helper 'exit 0'

  docker container run --rm --network none -- demo/img:tag selfcheck
  run docker container ls -a --format '{{.Names}}'
  [ -z "$output" ] || { echo "--rm left a container behind: $output" >&2; return 1; }

  docker container run --network none -- demo/img:tag selfcheck
  run docker container ls -a --format '{{.Names}}'
  [ -n "$output" ] || { echo "a run WITHOUT --rm left nothing behind" >&2; return 1; }
  run docker container inspect --format '{{.State.Status}}' -- "$output"
  [ "$output" = "exited" ] || { echo "the leftover container is '$output', not exited" >&2; return 1; }
}

@test "a named volume a container mounts is auto-created, as the daemon does" {
  # The permissiveness question read from the other side: not "what does the fake accept that Docker
  # refuses" but "what does the fake FAIL TO CREATE that Docker creates". A missing named volume is
  # auto-created by the daemon (the deliberate asymmetry with bind mounts, which are refused). This
  # fake recorded the mount and created nothing, so the runtime world it showed had fewer objects in
  # it than a real one — and a §10a "nothing partial survives" assertion would have passed over an
  # orphan volume that really would be left behind. It carries no labels, exactly as the daemon's
  # does, which is what makes it invisible to every find-by-label sweep in §6a.
  local net
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  [ ! -e "$FAKE_DOCKER_STATE/volumes/orphan" ] || { echo "fixture is not clean" >&2; return 1; }
  docker container create --name c1 --network "$net" \
    --mount type=volume,source=orphan,target=/d -- demo/img:tag >/dev/null
  run docker volume ls
  case "$output" in *orphan*) : ;; *) echo "the mounted volume was not created: '$output'" >&2; return 1 ;; esac
  run docker volume inspect --format '{{index .Labels "mythicalos.nonce"}}' -- orphan
  assert_ok
  [ -z "$output" ] || { echo "an auto-created volume must carry no labels, got '$output'" >&2; return 1; }
}

@test "an image id is stable across inspects" {
  # The id was minted per inspect, so two reads of the SAME image reported different ids — an image
  # that appears to change identity between two calls, which is the opposite of what a digest-pinned
  # reference means.
  local first second other
  docker image pull demo/img:tag >/dev/null
  docker image pull other/img:tag >/dev/null
  first="$(docker image inspect --format '{{.Id}}' -- demo/img:tag)"
  second="$(docker image inspect --format '{{.Id}}' -- demo/img:tag)"
  [ "$first" = "$second" ] \
    || { echo "the same image reported two ids: '$first' then '$second'" >&2; return 1; }
  other="$(docker image inspect --format '{{.Id}}' -- other/img:tag)"
  [ "$other" != "$first" ] || { echo "two different images share an id" >&2; return 1; }
}

@test "the lock file and its temps (incl. the recovery gate) are excluded from the fs snapshot" {
  load_mctl; mi_ensure_layout; mi_lock_acquire
  # A normal acquire creates no recovery/temp files, so plant the transient artifacts a stale-break
  # leaves mid-flight — the recovery gate, its mktemp publish temp, and the lock's publish temp.
  # None may appear in a snapshot.
  : > "$MYTHICAL_HOME/.state/lock.recovery"
  : > "$MYTHICAL_HOME/.state/lock.recovery.AbC123"
  : > "$MYTHICAL_HOME/.state/lock.new.abc123"
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  snap_fs "$BATS_TEST_TMPDIR/s"
  ! grep -q '\.state/lock' "$BATS_TEST_TMPDIR/s"
  rm -f "$MYTHICAL_HOME"/.state/lock.recovery* "$MYTHICAL_HOME"/.state/lock.new.*
  mi_lock_release
}
