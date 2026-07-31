#!/usr/bin/env bats
# §4.1a — what may be mounted into a product container, decided at the launch site.
#
# Two rule sets, and they are not the same rule: the CORE-FIXED mounts are a closed allowlist the core
# computes itself and checks for identity, type and link count, while the OPERATOR-CONFIGURABLE binds
# are checked for overlap — against the family home, against the core-fixed set, and against each
# other. Every comparison is on CANONICAL paths, because the string a user typed and the file a launch
# opens are not the same thing.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire
  printf 'X=1\n' > "$MYTHICAL_HOME/mythical.conf"
  printf 'PEER=x\n#mythical-conf-sha256=deadbeef\n' > "$MYTHICAL_HOME/brokkr.conf"
  mkdir -p "$MYTHICAL_HOME/transcripts" "$MYTHICAL_HOME/logs"
  OUT="$(mktemp -d)"
}
teardown() { rm -rf "$OUT"; mi_lock_release; teardown_test_env; }

@test "canonicalization resolves symlinks and works on macOS and Linux alike" {
  mkdir -p "$OUT/real"; ln -s "$OUT/real" "$OUT/link"
  run mi_canon "$OUT/link"
  [ "$output" = "$(cd "$OUT/real" && pwd -P)" ]
}

@test "canonicalization of a non-existent leaf still resolves its parent" {
  mkdir -p "$OUT/real"; ln -s "$OUT/real" "$OUT/link"
  run mi_canon "$OUT/link/newfile"
  [ "$output" = "$(cd "$OUT/real" && pwd -P)/newfile" ]
}

@test "canonicalization refuses a relative path — every comparison must be on absolute paths" {
  run mi_canon "relative/path"
  [ "$status" -ne 0 ]
}

# A path that resolves to itself for ever must REFUSE, not hang. Following links is unbounded by
# nature, and an installer that spins on an operator's symlink loop is a hang with no message.
@test "a symlink LOOP is refused rather than followed for ever" {
  ln -s "$OUT/b" "$OUT/a"; ln -s "$OUT/a" "$OUT/b"
  run mi_canon "$OUT/a"
  [ "$status" -ne 0 ]
  assert_contains "symbolic links"
}

@test "the three core-fixed mounts pass on a healthy home" {
  run mi_mount_check_fixed brokkr
  [ "$status" -eq 0 ]
}

@test "they pass when MYTHICAL_HOME sits under a SYMLINKED component — /var on macOS" {
  # The expected paths must be built from the canonical home, or every install under /var (macOS) or
  # any symlinked mount point is refused as "resolves elsewhere". This is the case that broke.
  local real="$OUT/realhome" link="$OUT/linkhome"
  mkdir -p "$real"; ln -s "$real" "$link"
  MYTHICAL_HOME="$link" mi_ensure_layout
  printf 'PEER=x\n' > "$link/brokkr.conf"; mkdir -p "$link/transcripts" "$link/logs"
  MYTHICAL_HOME="$link" run mi_mount_check_fixed brokkr
  [ "$status" -eq 0 ]
}

@test "a <product>.conf that is a SYMLINK is refused" {
  rm "$MYTHICAL_HOME/brokkr.conf"
  ln -s "$HOME/.ssh/id_ed25519" "$MYTHICAL_HOME/brokkr.conf"
  run mi_mount_check_fixed brokkr
  [ "$status" -ne 0 ]
  assert_contains "symlink"
}

@test "a <product>.conf HARDLINKED to mythical.conf is refused — symlink tests alone pass this" {
  rm "$MYTHICAL_HOME/brokkr.conf"
  ln "$MYTHICAL_HOME/mythical.conf" "$MYTHICAL_HOME/brokkr.conf"
  run mi_mount_check_fixed brokkr
  [ "$status" -ne 0 ]
  assert_contains "link count"
}

@test "a <product>.conf HARDLINKED to bin/mythical-ctl is refused" {
  printf '#!/bin/sh\n' > "$MYTHICAL_HOME/bin/mythical-ctl"
  rm "$MYTHICAL_HOME/brokkr.conf"
  ln "$MYTHICAL_HOME/bin/mythical-ctl" "$MYTHICAL_HOME/brokkr.conf"
  run mi_mount_check_fixed brokkr
  [ "$status" -ne 0 ]
}

# A family home that has never been configured has no mythical.conf, and that is not a refusal — the
# protected set simply has one fewer member. The opposite reading would refuse every first install.
@test "a home with no mythical.conf yet still passes — absence is not a failed identity read" {
  rm -f "$MYTHICAL_HOME/mythical.conf"
  run mi_mount_check_fixed brokkr
  [ "$status" -eq 0 ]
}

@test "a core-fixed mount of the wrong TYPE is refused" {
  rm "$MYTHICAL_HOME/brokkr.conf"; mkdir "$MYTHICAL_HOME/brokkr.conf"
  run mi_mount_check_fixed brokkr
  [ "$status" -ne 0 ]
  assert_contains "not a regular file"
}

# The core-fixed set could not be computed, so nothing about these mounts was checked — which must
# not read as "there was nothing to check". Both checkers walk that set through a here-string, and a
# here-string built from a failed command is empty: the loop runs zero times and the checker returns
# success. A product name that is not an `ident` is the reachable way to make the set fail.
@test "a product name that cannot make a path REFUSES, never checks nothing and passes" {
  run mi_mount_check_fixed "../evil"
  [ "$status" -ne 0 ]
  assert_contains "not a usable product name"
}

@test "the overlap check refuses the same way rather than comparing against an empty set" {
  mkdir -p "$OUT/work"
  run mi_mount_check_overlap "../evil" "$OUT/work"
  [ "$status" -ne 0 ]
  assert_contains "not a usable product name"
}

@test "a bind naming the family home is rejected" {
  run mi_mount_check_overlap brokkr "$MYTHICAL_HOME"
  [ "$status" -ne 0 ]
}

@test "a bind naming ~/.mythical/bin directly is rejected" {
  run mi_mount_check_overlap brokkr "$MYTHICAL_HOME/bin"
  [ "$status" -ne 0 ]
  assert_contains "family home"
}

@test "a bind naming ~/.mythical/<product>/ is rejected" {
  mkdir -p "$MYTHICAL_HOME/brokkr"
  run mi_mount_check_overlap brokkr "$MYTHICAL_HOME/brokkr"
  [ "$status" -ne 0 ]
}

@test "a SYMLINK whose target resolves inside the family home is rejected" {
  ln -s "$MYTHICAL_HOME/bin" "$OUT/sneaky"
  run mi_mount_check_overlap brokkr "$OUT/sneaky"
  [ "$status" -ne 0 ]
}

# The family home's own PARENT, not $HOME: the test home is a private temporary directory, so $HOME
# does not contain it and the assertion would have passed for the wrong reason on every platform.
@test "an ANCESTOR path containing the family home is rejected — containment is symmetric" {
  run mi_mount_check_overlap brokkr "$(dirname "$MYTHICAL_HOME")"
  [ "$status" -ne 0 ]
  assert_contains "contains"
}

@test "a bind that is genuinely outside is accepted" {
  mkdir -p "$OUT/work"
  run mi_mount_check_overlap brokkr "$OUT/work"
  [ "$status" -eq 0 ]
}

@test "two WRITABLE binds where one is an ancestor of the other are rejected" {
  mkdir -p "$OUT/work/project"
  run mi_mount_binds_check_pairwise "bind=$OUT/work:/work:rw" "bind=$OUT/work/project:/project:rw"
  [ "$status" -ne 0 ]
  assert_contains "overlap"
}

@test "two overlapping binds are rejected when EITHER is writable" {
  mkdir -p "$OUT/work/project"
  run mi_mount_binds_check_pairwise "bind=$OUT/work:/work:ro" "bind=$OUT/work/project:/project:rw"
  [ "$status" -ne 0 ]
  run mi_mount_binds_check_pairwise "bind=$OUT/work:/work:rw" "bind=$OUT/work/project:/project:ro"
  [ "$status" -ne 0 ]
}

@test "two read-only overlapping binds are permitted" {
  mkdir -p "$OUT/work/project"
  run mi_mount_binds_check_pairwise "bind=$OUT/work:/work:ro" "bind=$OUT/work/project:/project:ro"
  [ "$status" -eq 0 ]
}

@test "two non-overlapping writable binds are permitted" {
  mkdir -p "$OUT/a" "$OUT/b"
  run mi_mount_binds_check_pairwise "bind=$OUT/a:/a:rw" "bind=$OUT/b:/b:rw"
  [ "$status" -eq 0 ]
}

@test "identical canonical sources are rejected, however they were spelled" {
  mkdir -p "$OUT/a"; ln -s "$OUT/a" "$OUT/alias"
  run mi_mount_binds_check_pairwise "bind=$OUT/a:/a:rw" "bind=$OUT/alias:/b:rw"
  [ "$status" -ne 0 ]
}

# A mode outside {ro,rw} must REFUSE. Read as "not rw" it would make the overlap rule permissive for
# exactly the specs nobody wrote on purpose — a fail-open reached by a typo.
@test "a bind spec whose mode is neither ro nor rw is refused, never read as read-only" {
  mkdir -p "$OUT/work/project"
  run mi_mount_binds_check_pairwise "bind=$OUT/work:/work:readonly" "bind=$OUT/work/project:/project:ro"
  [ "$status" -ne 0 ]
  assert_contains ":ro or :rw"
}

@test "the VALIDATED canonical path is what reaches the spec — never the operator's string" {
  mkdir -p "$OUT/real"; ln -s "$OUT/real" "$OUT/link"
  printf 'MYTHICAL_BROKKR_WORK_BIND=%s\n' "$OUT/link" > "$MYTHICAL_HOME/mythical.conf"
  run mi_mount_binds brokkr work
  [ "$status" -eq 0 ]
  assert_contains "$(cd "$OUT/real" && pwd -P)"
  run grep -a "$OUT/link" <<<"$output"
  [ "$status" -ne 0 ]
}

# The pairwise rule has to be applied to the set the launch actually gets, not merely offered as a
# function a caller may remember to call. Two roles bound to overlapping writable paths is the
# combination §4.1a refuses, and mi_mount_binds is the only place the whole set exists at once.
@test "mi_mount_binds applies the pairwise rule to the whole set it emits" {
  mkdir -p "$OUT/work/project"
  { printf 'MYTHICAL_BROKKR_WORK_BIND=%s\n' "$OUT/work"
    printf 'MYTHICAL_BROKKR_PROJECT_BIND=%s\n' "$OUT/work/project"; } > "$MYTHICAL_HOME/mythical.conf"
  run mi_mount_binds brokkr work project
  [ "$status" -ne 0 ]
  assert_contains "overlap"

  # And it still emits BOTH when they do not overlap — a check that refused everything would pass the
  # assertion above while making the function useless.
  mkdir -p "$OUT/a" "$OUT/b"
  { printf 'MYTHICAL_BROKKR_WORK_BIND=%s\n' "$OUT/a"
    printf 'MYTHICAL_BROKKR_PROJECT_BIND=%s\n' "$OUT/b"; } > "$MYTHICAL_HOME/mythical.conf"
  run mi_mount_binds brokkr work project
  [ "$status" -eq 0 ]
  assert_contains "$(cd "$OUT/a" && pwd -P)"
  assert_contains "$(cd "$OUT/b" && pwd -P)"
}

@test "a role with no bind key falls through to a named volume rather than failing" {
  printf 'MYTHICAL_NET=n\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_mount_binds brokkr work
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# --- the product-scoped mythical.conf vocabulary (D53) --------------------------------------------

@test "the product key spec names the port and every BINDABLE role, and nothing else" {
  local mrec prec
  mrec="$(printf 'volume\tstate:/var/lib/p1\nvolume\tsecrets:/run/secrets\n')"
  prec="$(printf 'p1.bindable_role\tstate\n')"
  run mi_conf_product_keys p1 "$mrec" "$prec"
  [ "$status" -eq 0 ]
  assert_contains "MYTHICAL_P1_PORT"
  assert_contains "MYTHICAL_P1_STATE_BIND"
  case "$output" in
    *MYTHICAL_P1_SECRETS_BIND*)
      echo "a role the policy index does not make bindable became a bind key: $output" >&2
      return 1 ;;
  esac
}

# Recognising a role is not authorizing it. With the entitlement check gone, EVERY declared role
# becomes bindable — including the one whose whole protection is that it is a named volume.
@test "no bindable_role entitlement means no bind key at all" {
  local mrec
  mrec="$(printf 'volume\tstate:/var/lib/p1\n')"
  run mi_conf_product_keys p1 "$mrec" ""
  [ "$status" -eq 0 ]
  assert_contains "MYTHICAL_P1_PORT"
  case "$output" in
    *_BIND*) echo "an unentitled role became bindable: $output" >&2; return 1 ;;
  esac
}

@test "the operation's spec is the core vocabulary PLUS this product's" {
  local mrec prec
  mrec="$(printf 'volume\tstate:/var/lib/p1\n')"
  prec="$(printf 'p1.bindable_role\tstate\n')"
  run mi_conf_spec_for p1 "$mrec" "$prec"
  [ "$status" -eq 0 ]
  assert_contains "MYTHICAL_TELEMETRY_KEY"
  assert_contains "MYTHICAL_NET"
  assert_contains "MYTHICAL_P1_STATE_BIND"
}
