#!/usr/bin/env bash
# The closed authenticated-manifest `volatile_mount` wire, implemented for the installer.
#
# One manifest field names the credential-bearing isolated-home mount: a bounded absolute container
# path, and nothing else. Every hardening property of the mount is FIXED here and is not declarable —
# the manifest carries only the path, so a publisher cannot widen the mount into a generic escape
# hatch. That closure is the whole point of the field being a bare path with no options sub-grammar.
#
# This module is the bash half of a two-surface contract: one surface provisions the volatile root,
# the other (this installer) reads the manifest path and renders the tmpfs mount. Both render the
# SAME root and the SAME hardening. This module owns the manifest-side rules — the path grammar, the
# canonical production root, and the fixed security-option set. The actual container `--tmpfs`
# rendering lives at the one launch site in lib/runtime.sh (no caller may express a mount any other
# way); the rendered mount is a NON-PERSISTENT tmpfs carrying nodev,nosuid,noexec, daemon-owned, with
# 0700 homes and 0600 credential files beneath the root, excluded from backup and restore.
#
# PURE library — no side effects at source time, no filesystem access, no secret bytes; it validates
# and maps metadata only. Correct with or without ambient errexit (see lib/common.sh).

# The one production credential-home root. Supported deployments mount THIS path as the volatile
# tmpfs; production may not fall back to a state directory, a bind mount, a named volume, or the
# container writable layer. A test runner may inject a private temporary root at the lower layers,
# but the production bring-up path enforces this one (see mi_volatile_assert_production_root).
mi_volatile_root() { printf '%s\n' '/run/mythical/credential-homes'; }

# The three tmpfs security flags, in the wire's canonical order, so a Compose tmpfs option string and
# this installer's mount invocation render the SAME token sequence and can be byte-compared. This is
# the ONE place the set and its order are written; every other surface asks for it here.
mi_volatile_tmpfs_secopts() { printf '%s\n' 'nodev,nosuid,noexec'; }

# Accept a bounded absolute container path, and nothing else. This is the closed value validator for
# the `volatile_mount` field: because the accepted charset is only [A-Za-z0-9._-] per segment plus the
# separator, it also rejects every attempt to smuggle a second token or an options sub-grammar past
# it (a space, a comma, a colon, an `=`), which is what keeps a manifest from widening the mount.
#
# Accepted: begins with `/`; each segment is [A-Za-z0-9._-]+; no trailing slash; the bare root `/` is
# refused; no empty segment (`//`); no `.` or `..` traversal segment; no whitespace or control byte;
# length 2..512 bytes. rc 0 accepted, 1 rejected.
mi_volatile_path_ok() {
  local v="$1"
  # Byte semantics, not the operator's locale: the class checks below must mean bytes.
  local LC_ALL=C
  # Length bound first, in bytes.
  if [ "${#v}" -lt 2 ] || [ "${#v}" -gt 512 ]; then return 1; fi   # an `if`, not A && B || C
  # Absolute, and no trailing slash — which also refuses the bare root `/`.
  case "$v" in /*) : ;; *) return 1 ;; esac
  case "$v" in */) return 1 ;; esac
  # The safe-segment charset over the WHOLE string, done BEFORE the segment walk below. One class
  # rejects whitespace, control bytes, `:` `,` `=` `*` and every other byte outside the grammar in a
  # single pass — and, run first, it leaves no glob metacharacter for the walk's expansions to act on.
  case "$v" in *[!A-Za-z0-9._/-]*) return 1 ;; esac
  # No empty (`//`) or `.`/`..` traversal segment. Walk by parameter expansion rather than an IFS
  # split: the leading `/` is dropped once, then each segment is taken from the front, so no leading
  # empty field and no word-splitting subtlety can change the answer.
  local rest="${v#/}" seg
  while [ -n "$rest" ]; do
    seg="${rest%%/*}"
    case "$rest" in */*) rest="${rest#*/}" ;; *) rest="" ;; esac
    [ -n "$seg" ] || return 1
    case "$seg" in .|..) return 1 ;; esac
  done
  return 0
}

# True only for the canonical production credential-home root.
mi_volatile_is_canonical_root() { [ "$1" = "$(mi_volatile_root)" ]; }

# Fail-closed guard for the production path: the declared mount must be a valid path AND rooted at the
# canonical root. Reported, rc 1 on any mismatch — a test runner injecting a private root does not
# call this, but the installer's real bring-up does, so a manifest cannot point file-auth homes
# anywhere but the fixed root, nor fall back to durable storage.
mi_volatile_assert_production_root() {
  local v="$1"
  if ! mi_volatile_path_ok "$v"; then
    mi_warn "volatile: '$v' is not a bounded absolute container path"
    return 1
  fi
  if [ "$v" != "$(mi_volatile_root)" ]; then
    mi_warn "volatile: a production credential-home mount must be rooted at $(mi_volatile_root), not '$v'."
    mi_warn "  Production may not fall back to a state directory, a bind mount, a named volume, or the"
    mi_warn "  container writable layer — the mount must be the fixed non-persistent tmpfs root."
    return 1
  fi
  return 0
}

# True (rc 0) only when two absolute container paths are DISJOINT — neither equal, nor one a subpath
# of the other. Used to keep the volatile credential-home root isolated from every other mount: a
# durable mount (a named volume or a bind) at, under, or over the volatile root would place credential
# bytes on persistent, backed-up storage inside the tmpfs tree, defeating the non-persistence and
# backup exclusion the mount exists to guarantee. rc 1 on any overlap. Both inputs are validated
# safe-segment paths (or fixed literals) with no glob metacharacter, so the prefix patterns are literal.
mi_volatile_path_disjoint() {
  local a="$1" b="$2"
  [ "$a" != "$b" ] || return 1                       # identical mount points
  case "${b}/" in "${a}/"*) return 1 ;; esac         # b is at or under a
  case "${a}/" in "${b}/"*) return 1 ;; esac         # a is at or under b
  return 0
}

# True only when a security-option string is EXACTLY the fixed set, in the canonical order. Reject a
# weakened set (a missing flag, a reordering, or an added one). This is the fail-closed check for a
# rendered mount's hardening: any string that is not the frozen one is refused rather than downgraded.
mi_volatile_secopts_ok() { [ "$1" = "$(mi_volatile_tmpfs_secopts)" ]; }

# Map a declared manifest path to the TYPED launch spec the runtime adapter consumes: `volatile=<path>`.
# Validated first, so nothing that reaches the launch site can be an unbounded or traversal path; the
# fixed hardening is applied by the adapter, never spelled here. rc 0 with the spec printed, 1 rejected.
mi_volatile_mount_spec() {
  local v="$1"
  if ! mi_volatile_path_ok "$v"; then
    mi_warn "volatile: refusing to build a mount spec for '$v' — not a bounded absolute container path"
    return 1
  fi
  printf 'volatile=%s\n' "$v"
}
