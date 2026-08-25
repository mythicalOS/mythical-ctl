#!/usr/bin/env bats
# The closed `volatile_mount` wire, installer half (lib/volatile.sh). The manifest names ONE bounded
# absolute container path; every hardening property of the mount is fixed by the wire and cannot be
# declared. These tests pin the path grammar, the canonical production root, the fixed security-option
# set, and the typed spec the runtime adapter consumes — the accept/reject cases the wire enumerates.
load '../lib/test_helper'

setup() { setup_test_env; load_mctl; }
teardown() { teardown_test_env; }

@test "the canonical root and the fixed security options are the wire's exact literals" {
  run mi_volatile_root
  [ "$output" = "/run/mythical/credential-homes" ]
  # The three flags, in the wire's canonical order — byte-comparable with a Compose tmpfs option
  # string. A reordering here would silently break that parity, so the WHOLE string is asserted.
  run mi_volatile_tmpfs_secopts
  [ "$output" = "nodev,nosuid,noexec" ]
}

@test "a bounded absolute path of safe segments is accepted" {
  local v
  for v in /run/mythical/credential-homes /a /srv/x.y_z-1 /a/b/c /tmp/inject-root; do
    run mi_volatile_path_ok "$v"
    [ "$status" -eq 0 ] || { echo "rejected a valid container path '$v'" >&2; return 1; }
  done
}

@test "every path the wire's grammar rejects is rejected" {
  local v
  # relative, bare root, trailing slash, empty segment, . / .. traversal, and a too-short value.
  for v in relative/path / /a/ /a//b /a/./b /a/../b /. /.. /a/.. .; do
    run mi_volatile_path_ok "$v"
    [ "$status" -eq 1 ] || { echo "accepted an invalid container path '$v'" >&2; return 1; }
  done
}

# The grammar is also the CLOSURE: because a segment is only [A-Za-z0-9._-], the field can carry no
# second token and no options sub-grammar. A space, a comma, a colon or an `=` is how a publisher
# would try to smuggle `nodev=false` or a bind `source=` past the field; each must be refused.
@test "a value carrying a second token or an option is rejected — the field cannot widen the mount" {
  local v
  for v in \
    '/run/mythical/credential-homes exec' \
    '/run/mythical/credential-homes,nodev=false' \
    '/run/mythical/credential-homes:rw' \
    '/path=exec' \
    '/path*' \
    '/path;other'; do
    run mi_volatile_path_ok "$v"
    [ "$status" -eq 1 ] || { echo "accepted a mount-widening value '$v'" >&2; return 1; }
  done
}

@test "a whitespace or control byte in the path is rejected" {
  # A literal tab and a leading space — neither is in the safe-segment charset.
  run mi_volatile_path_ok "$(printf '/a/\tb')"
  [ "$status" -eq 1 ]
  run mi_volatile_path_ok " /a"
  [ "$status" -eq 1 ]
}

@test "the length bound is enforced at both ends" {
  # 512 bytes accepted, 513 rejected. Built as /<510 chars> and /<511 chars>.
  local ok over
  ok="/$(printf 'a%.0s' $(seq 1 511))"      # 512 bytes total
  over="/$(printf 'a%.0s' $(seq 1 512))"    # 513 bytes total
  [ "${#ok}" -eq 512 ]
  [ "${#over}" -eq 513 ]
  run mi_volatile_path_ok "$ok"
  [ "$status" -eq 0 ] || { echo "rejected a 512-byte path" >&2; return 1; }
  run mi_volatile_path_ok "$over"
  [ "$status" -eq 1 ] || { echo "accepted a 513-byte path" >&2; return 1; }
}

@test "the canonical-root predicate is true only for the fixed root" {
  run mi_volatile_is_canonical_root /run/mythical/credential-homes
  [ "$status" -eq 0 ]
  run mi_volatile_is_canonical_root /tmp/credential-homes
  [ "$status" -ne 0 ]
}

@test "the production guard accepts the canonical root and refuses every other, even valid, path" {
  run mi_volatile_assert_production_root /run/mythical/credential-homes
  [ "$status" -eq 0 ]
  # A perfectly valid path that is not the canonical root — production may not fall back to it.
  run mi_volatile_assert_production_root /tmp/credential-homes
  [ "$status" -eq 1 ]
  assert_contains "must be rooted at /run/mythical/credential-homes"
  # An outright invalid path fails the same guard, not silently.
  run mi_volatile_assert_production_root /a/../b
  [ "$status" -eq 1 ]
}

# The security-option check is fail-closed: only the exact frozen set, in order, is the hardened
# mount. A missing flag, a reordering, or an added option is a DIFFERENT, weaker mount and is refused.
@test "the security-option check accepts only the exact frozen set" {
  run mi_volatile_secopts_ok "nodev,nosuid,noexec"
  [ "$status" -eq 0 ]
  local bad
  for bad in "nodev,nosuid" "nosuid,noexec,nodev" "nodev,nosuid,noexec,exec" "" "rw,nodev,nosuid,noexec"; do
    run mi_volatile_secopts_ok "$bad"
    [ "$status" -ne 0 ] || { echo "accepted a weakened option set '$bad'" >&2; return 1; }
  done
}

# The disjointness predicate keeps the credential-home root isolated from every other mount. Overlap
# is symmetric — equal, a subpath either way — because a durable mount at, under, OR over the root all
# put credential bytes on persistent storage inside the tmpfs tree.
@test "path disjointness catches equal, child, and ancestor overlaps but allows a sibling" {
  local root=/run/mythical/credential-homes
  # Overlapping (rc 1): identical, a child, and an ancestor.
  local bad
  for bad in /run/mythical/credential-homes /run/mythical/credential-homes/session /run/mythical /run; do
    run mi_volatile_path_disjoint "$root" "$bad"
    [ "$status" -ne 0 ] || { echo "missed an overlap with '$bad'" >&2; return 1; }
  done
  # Disjoint (rc 0): a sibling and an unrelated tree — and a name that only shares a prefix STRING but
  # not a path boundary (…-homes-2 is not under …-homes).
  local ok
  for ok in /run/mythical/other /data /run/mythical/credential-homes-2; do
    run mi_volatile_path_disjoint "$root" "$ok"
    [ "$status" -eq 0 ] || { echo "wrongly flagged '$ok' as overlapping" >&2; return 1; }
  done
}

# Overlap is judged on NORMALIZED paths, so a different SPELLING of a child cannot slip a durable mount
# under the root. The looser mount-target grammar accepts `.` segments, `//`, and a trailing slash, and
# a bare lexical prefix check would miss every one of these.
@test "path normalization defeats equivalent spellings of an overlapping path" {
  local n
  n="$(mi_volatile_path_norm /run/mythical/./credential-homes//session/)"
  [ "$n" = "/run/mythical/credential-homes/session" ] \
    || { echo "unexpected normalization: '$n'" >&2; return 1; }
  # All of these RESOLVE beneath the root and must be caught as overlapping despite the spelling.
  local root=/run/mythical/credential-homes bad
  for bad in \
    '/run/mythical/./credential-homes/session' \
    '/run/mythical/credential-homes//session' \
    '/run/mythical/credential-homes/session/' \
    '/run/mythical/credential-homes/.'; do
    run mi_volatile_path_disjoint "$root" "$bad"
    [ "$status" -ne 0 ] || { echo "an equivalent spelling '$bad' slipped past the overlap check" >&2; return 1; }
  done
}

@test "the typed launch spec is emitted for a valid path and refused for an invalid one" {
  run mi_volatile_mount_spec /run/mythical/credential-homes
  [ "$status" -eq 0 ]
  [ "$output" = "volatile=/run/mythical/credential-homes" ]
  run mi_volatile_mount_spec /a/../b
  [ "$status" -ne 0 ]
  case "$output" in *volatile=*) echo "a spec was emitted for an invalid path: $output" >&2; return 1 ;; esac
}
