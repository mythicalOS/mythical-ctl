#!/usr/bin/env bash
# §6b.3 container bring-up, §4.1a mount validation at the launch site, §4.3 secret injection.
#
# THE ORDER IS FIXED AND CONFIRMATION COMES LAST, so "confirmed" always means "attached correctly, and
# to nothing else":
#
#   1 create, NOT started, attached to the target network ID AT CREATION — behind a write-ahead intent
#     that records the DESIRED STATE and the check this bring-up owes, not merely the nonce
#   2 verify by inspection — the COMPLETE network set, exactly {expected}, with the expected alias
#   3 record desired state and the outstanding check, then confirm
#   4 start
#   5 verify live — re-inspect, re-apply step 2's complete-set rule to THAT inspection, resolve the
#     alias against the address it actually has, compare, and only then clear
#
# STEP 5 REPEATS STEP 2 BECAUSE STEP 5 IS THE STEP THAT CLEARS. Everything "confirmed" claims has to
# be true at the moment the check is retired, and the second half of the claim — attached to NOTHING
# ELSE — is the half a network attached after step 2 falsifies without disturbing anything step 5
# used to look at.
#
# THE INTENT CARRIES THE DECISION BECAUSE THE WINDOW BEFORE THE FIRST STATE WRITE CANNOT BE CLOSED BY
# ORDERING. Steps 1–2 can complete and the process die before step 3 writes anything, and a recovering
# process cannot re-derive what the dead one decided. So it is written down before the object exists.
#
# CONSEQUENCE FOR CALLERS: a container intent opened here is finished by mi_bringup_recover and by
# nothing else. lib/intent.sh's generic mi_intent_reconcile confirms a matched object directly — right
# for a volume, whose existence is its whole state, and wrong for a container, which also owes a
# desired state and a live verification. That is no longer left to callers to observe: the generic
# reconciler REFUSES class container outright, because a comment here is not a boundary while the
# function over there still accepts the call.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.
#
# ARRAY-TYPED LOCALS DECLARED HERE: `srcs`, `modes`, `bspecs`, `broles`, `ids`, `permitted`. tools/bundle.sh
# flattens every module into one file, after which shellcheck's array tracking is no longer
# per-function — so a later module using one of these names for an ordinary scalar draws SC2178 plus
# an SC2128 per use, with the tree clean and only `shellcheck dist/mythical-ctl` red. The names
# already spoken for elsewhere are `args`, `pk`, `pv`, `placed` (lib/config.sh), `fields`
# (lib/ledger.sh), `triples` (lib/trust.sh), `rtargv`/`rtpost` (lib/runtime.sh), `hspecs`
# (lib/probe.sh) and `pairs` (lib/state.sh).

# --- canonicalization -----------------------------------------------------------------------------
# `readlink -f` is GNU-only and `realpath` is not on macOS's floor, so canonicalization is done here
# with `cd`+`pwd -P`, which is POSIX and identical on both platforms. §10a: "canonicalization + confined
# copy, on macOS AND Linux — identical behaviour; a portability gap here is a security bug."
#
# The leaf may not exist (a bind source is often created by the container), so the DIRECTORY is
# resolved and the basename appended. `pwd -P` resolves every symlink in the directory chain, which is
# the property §4.1a needs: "Compare canonical paths, never the strings a user typed."
#
# IT ITERATES RATHER THAN RECURSING, and the bound is the reason. Following a symlink leaf yields
# another path that may itself be a symlink, and `a -> b`, `b -> a` is a pair an operator can create
# by accident — a recursive follow spins on it until the process dies, which is a hang with no
# message on the one code path an operator reaches through their own configuration. The limit is
# stated and refused out loud instead.
mi_canon() {
  if [ "$#" -ne 1 ]; then mi_warn "bringup: mi_canon needs a <path>"; return 1; fi
  local orig="$1" p="$1" d b rd t hops=0
  case "$p" in
    /*) : ;;
    *) mi_warn "bringup: '$p' is not an absolute path — every path comparison is on absolute paths"; return 1 ;;
  esac
  while :; do
    # Strip trailing slashes so `/a/b/` and `/a/b` canonicalize identically; keep a bare `/`.
    while [ "${#p}" -gt 1 ] && [ "${p%/}" != "$p" ]; do p="${p%/}"; done
    if [ -d "$p" ]; then
      ( cd -P -- "$p" 2>/dev/null && pwd -P ) || { mi_warn "bringup: cannot resolve '$orig'"; return 1; }
      return 0
    fi
    # Parameter expansion, not `dirname`/`basename`: two forks per component, and the expansions are
    # exact here because the trailing slashes are already gone and the path is absolute.
    d="${p%/*}"; [ -n "$d" ] || d=/
    b="${p##*/}"
    rd="$( cd -P -- "$d" 2>/dev/null && pwd -P )" || { mi_warn "bringup: cannot resolve the parent of '$orig'"; return 1; }
    # A SYMLINK leaf must be followed too — that is the "symlink whose target resolves inside" defeat.
    if [ -L "$rd/$b" ]; then
      hops=$((hops + 1))
      if [ "$hops" -gt 40 ]; then
        mi_warn "bringup: '$orig' passes through more than 40 symbolic links. That is a loop or a chain"
        mi_warn "  no legitimate path needs, and following it further would never terminate. Refusing."
        return 1
      fi
      t="$(readlink -- "$rd/$b")" || { mi_warn "bringup: cannot read the link at '$orig'"; return 1; }
      case "$t" in
        /*) p="$t" ;;
        *)  p="${rd}/${t}" ;;
      esac
      continue
    fi
    if [ "$rd" = / ]; then printf '/%s\n' "$b"; else printf '%s/%s\n' "$rd" "$b"; fi
    return 0
  done
}

# Is <a> equal to, inside, or containing <b>? Both must already be canonical.
# CONTAINMENT IS SYMMETRIC: checking one direction only lets an ancestor through, and an ancestor
# contains everything below it.
_mi_path_overlaps() {
  local a="$1" b="$2"
  [ "$a" = "$b" ] && return 0
  case "$a/" in "$b"/*) return 0 ;; esac
  case "$b/" in "$a"/*) return 0 ;; esac
  return 1
}

# A product or role name, before it is joined into a PATH or a configuration KEY. Both joins below are
# string concatenation, so a `/` or a `..` here is a path escape and anything outside the lowercase
# `ident` grammar makes the `tr`-based upper-casing ambiguous. It is the SAME document type every
# runtime name in this installer is checked against (lib/manifest.sh's mi_name_* helpers), asked in
# one place here rather than at each of the four entry points that take one.
_mi_bringup_name_ok() {
  if _mi_doc_type_ok ident "$2"; then return 0; fi
  mi_warn "bringup: '$2' is not a usable $1 name"
  return 1
}

# --- core-fixed mounts (§4.1a) ---------------------------------------------------------------------
# A CLOSED, EXACT allowlist the core computes itself: ~/.mythical/<product>.conf, ~/.mythical/
# transcripts, ~/.mythical/logs. Never derived from configuration, never extended by a manifest.
#
# ~/.mythical/ ITSELF is never mounted, because it contains mythical.conf — and a directory mount would
# hand every secret in it to everything inside, which is the exact failure this design exists to
# prevent. This is stated because it is the most natural implementation mistake available: binding one
# directory is simpler than binding N files, and it silently defeats D2 and D4 without any visible
# symptom.
#
# The family home, CANONICALIZED. Every core-fixed path is built from this and every comparison is
# canonical-to-canonical. Comparing a canonical path against a raw $MYTHICAL_HOME refuses any install
# whose home sits under a symlinked component — which on macOS is every home under /var or /tmp, since
# /var is a symlink to /private/var. §10a requires identical behaviour on macOS and Linux, so this is
# not a cosmetic difference. (Found by executing mi_mount_check_fixed on macOS, not by reading it.)
mi_home_canon() { mi_canon "$(mi_home)"; }

mi_mount_core_fixed() {
  if [ "$#" -ne 1 ]; then mi_warn "bringup: mi_mount_core_fixed needs <product>"; return 1; fi
  _mi_bringup_name_ok product "$1" || return 1
  local h; h="$(mi_home_canon)" || return 1
  printf 'file\t%s/%s.conf\t/etc/mythical/%s.conf\trw\n' "$h" "$1" "$1"
  printf 'dir\t%s/transcripts\t/home/mythical/transcripts\trw\n' "$h"
  printf 'dir\t%s/logs\t/home/mythical/logs\trw\n' "$h"
}

# THE SET, OR A REFUSAL — never an empty listing. Both checkers below walk this through a here-string,
# and a here-string built from a FAILED command is empty: the loop then runs zero times and the
# checker returns success having examined nothing. That is "I could not ask" becoming "there is
# nothing there", on the two functions whose whole job is to refuse.
_mi_mount_core_fixed_set() {
  local out
  out="$(mi_mount_core_fixed "$1")" || return 1
  if [ -z "$out" ]; then
    mi_warn "bringup: the core-fixed mount set for '$1' came back empty. It is a fixed list of three;"
    mi_warn "  an empty one means it could not be computed, not that there is nothing to check."
    return 1
  fi
  printf '%s\n' "$out"
}

# Identity of a path as `device:inode`, or a failure. `stat` differs between GNU and BSD, so both
# spellings are tried — and a FAILURE to read the identity is reported as one, never as "no conflict".
_mi_ino() {
  local p="$1" out
  out="$(stat -f '%d:%i' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }   # BSD/macOS
  out="$(stat -c '%d:%i' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }   # GNU
  return 1
}

# Link count, GNU/BSD portable.
_mi_nlink() {
  local p="$1" out
  out="$(stat -f '%l' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }
  out="$(stat -c '%h' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }
  return 1
}

# Numeric OWNER uid, GNU/BSD portable.
_mi_owner_uid() {
  local p="$1" out
  out="$(stat -f '%u' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }
  out="$(stat -c '%u' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }
  return 1
}

# Permission bits as OCTAL DIGITS (no leading `0`, no file-type prefix), GNU/BSD portable — `%Lp` on
# BSD and `%a` on GNU both print the low bits only (never the `S_IFDIR`-family type bits `%p`/`%f`
# carry). May be 3 or 4 digits (a 4th, leading digit appears only when setuid/setgid/sticky is set);
# callers that want the group/other write bits take the LAST TWO characters (`${m#"${m%??}"}`) rather
# than assume a fixed width, since bash 3.2 (this codebase's floor) has no negative substring offset.
_mi_mode_octal() {
  local p="$1" out
  out="$(stat -f '%Lp' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }   # BSD/macOS
  out="$(stat -c '%a' -- "$p" 2>/dev/null)" && { printf '%s\n' "$out"; return 0; }    # GNU
  return 1
}

# The identities NOTHING mounted into a container may share: mythical.conf, and everything under
# bin/. Printed one per line; a path that EXISTS and whose identity cannot be read is a refusal, not
# one fewer member — a protected file silently dropped from this set is a comparison that passes by
# having asked nothing.
#
# An ABSENT mythical.conf is not that case. A family home that has never been configured has no such
# file, so there is no identity for anything to collide with, and refusing here would refuse every
# first install.
_mi_mount_protected() {
  local h="$1" p ino
  if [ -e "$h/mythical.conf" ] || [ -L "$h/mythical.conf" ]; then
    if ! ino="$(_mi_ino "$h/mythical.conf")"; then
      mi_warn "bringup: the family configuration file exists but its identity cannot be read. Nothing"
      mi_warn "  can then be shown NOT to be it, so this refuses rather than assuming."
      return 1
    fi
    printf '%s\n' "$ino"
  fi
  for p in "$h"/bin/*; do
    [ -e "$p" ] || [ -L "$p" ] || continue
    if ! ino="$(_mi_ino "$p")"; then
      mi_warn "bringup: '$p' is under the installer-managed bin/ directory and its identity cannot be"
      mi_warn "  read. This refuses rather than leaving it out of the protected set."
      return 1
    fi
    printf '%s\n' "$ino"
  done
  return 0
}

# Check every core-fixed mount for a product. rc 0 ok · 1 refused (reported).
#
# Each is checked for exact canonical-path equality with the expected location, for being the expected
# TYPE, for not being a SYMLINK, and — because symlink checks are not sufficient — for DISTINCT
# IDENTITY against mythical.conf, against anything under bin/, and against every other core-fixed
# mount.
#
# A hardlink is not a link at the path level: it is a second name for the same inode, and every symlink
# test passes. If brokkr.conf is hardlinked to mythical.conf, mounting it read-write hands the container
# the host-only file that §4.1 depends on being unreachable; hardlinked to bin/mythical-ctl, it hands
# over the CLI. The entire two-file split is bypassed without a single symlink existing.
#
# THE IDENTITY CHECK IS NOT THE LINK-COUNT CHECK REPEATED, and the difference is why both are here. A
# hardlink to a regular file always raises its link count, so for the `file` mount the count catches
# it first. A BIND MOUNT does not: `mount --bind ~/.mythical/bin ~/.mythical/transcripts` gives two
# paths the same device and inode with a link count of 1 apiece, and it is available for DIRECTORIES,
# which cannot be hardlinked at all. The count answers "how many names does this file have"; the
# identity answers "is this the same object as that one", and only the second one covers the
# directory mounts.
mi_mount_check_fixed() {
  if [ "$#" -ne 1 ]; then mi_warn "bringup: mi_mount_check_fixed needs <product>"; return 1; fi
  local product="$1" h type src dst mode rc=0
  h="$(mi_home_canon)" || return 1

  local fixed protected
  fixed="$(_mi_mount_core_fixed_set "$product")" || return 1
  protected="$(_mi_mount_protected "$h")" || return 1

  local seen=""
  # shellcheck disable=SC2034   # dst/mode are read to CONSUME the record's remaining fields — without
  # them, `mode` would be appended to `dst`. The container target is validated at the launch site.
  while IFS=$'\t' read -r type src dst mode; do
    [ -n "$type" ] || continue
    local canon ino
    # The SYMLINK test comes FIRST, before canonical equality. A symlinked <product>.conf fails both,
    # but "this path is a symlink" is the actionable message and "it resolves elsewhere" is not — and a
    # reviewer reading the generic message would not know which defeat had been attempted.
    if [ -L "$src" ]; then
      mi_warn "bringup: '$src' is a symlink. Core-fixed mounts are never followed — a <product>.conf"
      mi_warn "  that has become a symlink to a private key is an attack, not a configuration."
      rc=1; continue
    fi
    if ! canon="$(mi_canon "$src")"; then rc=1; continue; fi
    if [ "$canon" != "$src" ]; then
      mi_warn "bringup: core-fixed mount '$src' resolves to '$canon' — it must be exactly where the"
      mi_warn "  core expects it. A core-fixed path that resolves elsewhere is an attack, not a"
      mi_warn "  configuration."
      rc=1; continue
    fi
    case "$type" in
      file)
        if [ ! -f "$src" ]; then mi_warn "bringup: '$src' is not a regular file"; rc=1; continue; fi
        local n
        if ! n="$(_mi_nlink "$src")"; then
          mi_warn "bringup: cannot read the link count of '$src' — refusing rather than assuming"
          rc=1; continue
        fi
        # The count came out of `stat`, and the comparison below EVALUATES it. Digits or nothing.
        case "$n" in ''|*[!0-9]*)
          mi_warn "bringup: the link count of '$src' came back as '$n', which is not a number"
          rc=1; continue ;;
        esac
        if [ "$n" -gt 1 ]; then
          mi_warn "bringup: '$src' has a link count of $n. The installer created this file and nothing"
          mi_warn "  legitimate shares its inode, so a second name for it is unexplainable. Refusing."
          rc=1; continue
        fi ;;
      dir)
        if [ ! -d "$src" ]; then mi_warn "bringup: '$src' is not a directory"; rc=1; continue; fi ;;
      *)
        mi_warn "bringup: '$type' is not a core-fixed mount type"; rc=1; continue ;;
    esac
    if ! ino="$(_mi_ino "$src")"; then
      mi_warn "bringup: cannot read the identity of '$src' — refusing rather than assuming"
      rc=1; continue
    fi
    case $'\n'"${protected}"$'\n' in
      *$'\n'"${ino}"$'\n'*)
        mi_warn "bringup: '$src' is the same object as mythical.conf or a file under bin/. That would"
        mi_warn "  mount the host-only file, or the CLI itself, into the container. Refusing."
        rc=1; continue ;;
    esac
    case $'\n'"${seen}"$'\n' in
      *$'\n'"${ino}"$'\n'*)
        mi_warn "bringup: '$src' is the same object as another core-fixed mount. Refusing."
        rc=1; continue ;;
    esac
    seen="${seen}${ino}"$'\n'
  done <<< "$fixed"
  return "$rc"
}

# --- operator-configurable binds (§4.1a) ----------------------------------------------------------
# Everything else, and here the overlap rule applies in full.

# rc 0 the bind source is acceptable · 1 refused (reported).
mi_mount_check_overlap() {
  if [ "$#" -ne 2 ]; then mi_warn "bringup: mi_mount_check_overlap needs <product> <source>"; return 1; fi
  local product="$1" src="$2" h canon type fsrc rest fixed
  h="$(mi_home_canon)" || return 1
  canon="$(mi_canon "$src")" || return 1

  if _mi_path_overlaps "$canon" "$h"; then
    mi_warn "bringup: bind source '$src' resolves to '$canon', which is, is inside, or contains the"
    mi_warn "  family home '$h'. Refusing: that would hand the container write access to the CLI it"
    mi_warn "  will later be launched by, or to the generated artifacts that inform that launch."
    if [ "$canon" != "$h" ]; then
      case "$h/" in "$canon"/*) mi_warn "  ('$canon' CONTAINS the family home — containment is checked in both directions.)" ;; esac
    fi
    return 1
  fi

  fixed="$(_mi_mount_core_fixed_set "$product")" || return 1
  while IFS=$'\t' read -r type fsrc rest; do
    [ -n "$fsrc" ] || continue
    local fc
    # `|| return 1`, not `|| continue`. A core-fixed path this module cannot canonicalize is one the
    # overlap comparison would then silently skip, and every bind naming it would be accepted.
    if ! fc="$(mi_canon "$fsrc")"; then
      mi_warn "bringup: the core-fixed mount '$fsrc' cannot be canonicalized, so no bind can be shown"
      mi_warn "  not to overlap it. Refusing rather than skipping the comparison."
      return 1
    fi
    if _mi_path_overlaps "$canon" "$fc"; then
      mi_warn "bringup: bind source '$canon' overlaps the core-fixed mount '$fc'. Refusing."
      return 1
    fi
  done <<< "$fixed"
  # shellcheck disable=SC2034   # `type`/`rest` consume the record's remaining fields; only fsrc is read
  return 0
}

# Binds must also be checked AGAINST EACH OTHER, not only against protected paths. With /work bound
# read-write, the container replaces /work/project — the source of a second bind — with a symlink into
# ~/.mythical/, and the NEXT launch follows it. Every individual bind passed validation; the
# combination did not.
#
# Two binds may not overlap when EITHER is writable. Two read-only binds may.
#
# IT SPLITS THE SPEC THE WAY THE RUNTIME DOES, field by field from the left, and that is not a style
# choice. Taking the mode as "everything after the last colon" (`${body##*:}`) while lib/runtime.sh
# takes it as "everything after the second" makes the two disagree about any spec with a fourth field:
# `bind=/a:/b:x:rw` reads as mode `rw` here — accepted — and as mode `x:rw` there, where it is refused.
# So this rule would have judged a combination on a mode the launch never saw. One split, both readers,
# and a spec that is not exactly three fields is refused rather than silently re-cut.
mi_mount_binds_check_pairwise() {
  local -a srcs modes
  srcs=(); modes=()
  local s body p1 p3 c rest
  for s in "$@"; do
    case "$s" in bind=*) : ;; *) continue ;; esac
    body="${s#bind=}"
    p1="${body%%:*}"; rest="${body#*:}"; p3="${rest#*:}"
    if [ "$rest" = "$body" ] || [ "$p3" = "$rest" ]; then
      mi_warn "bringup: bind spec '$s' is not <source>:<target>:<mode>. A spec this function has to"
      mi_warn "  re-cut to read is one whose source it cannot be sure of, and the source is what the"
      mi_warn "  overlap rule is about."
      return 1
    fi
    # A MODE OUTSIDE {ro,rw} IS REFUSED, never read as "not writable". The rule below turns on
    # `= rw`, so an unrecognised third field would make the pair read-only to this function and
    # permit exactly the overlap it exists to refuse — a fail-open reached by a typo.
    case "$p3" in
      ro|rw) : ;;
      *) mi_warn "bringup: bind spec '$s' must end in :ro or :rw. A mode this function does not"
         mi_warn "  recognise would be treated as read-only, which permits the overlap it must refuse."
         return 1 ;;
    esac
    c="$(mi_canon "$p1")" || return 1
    srcs+=("$c"); modes+=("$p3")
  done
  local i j
  i=0
  while [ "$i" -lt "${#srcs[@]}" ]; do
    j=$((i + 1))
    while [ "$j" -lt "${#srcs[@]}" ]; do
      if _mi_path_overlaps "${srcs[$i]}" "${srcs[$j]}"; then
        if [ "${modes[$i]}" = rw ] || [ "${modes[$j]}" = rw ]; then
          mi_warn "bringup: binds '${srcs[$i]}' and '${srcs[$j]}' overlap and at least one is writable."
          mi_warn "  A writable ancestor lets the container replace the other bind's source with a"
          mi_warn "  symlink, which the next launch would follow. Refusing."
          return 1
        fi
      fi
      j=$((j + 1))
    done
    i=$((i + 1))
  done
  return 0
}

# --- product-scoped mythical.conf keys ------------------------------------------------------------
# Plan 2 owns mythical.conf's ENGINE and its core vocabulary (MYTHICAL_NET, MYTHICAL_TELEMETRY_KEY).
# The product-scoped keys are per-product BY CONSTRUCTION — they name a role or a port the manifest
# declares — so they cannot be a static list, and Plan 2 deliberately left them out.
#
# The spec is DERIVED FROM THE AUTHENTICATED MANIFEST, which is what keeps a hostile mythical.conf from
# introducing a key: an operator can type MYTHICAL_BROKKR_SECRETS_BIND, and if the policy index does
# not make `secrets` bindable it is not in the spec and the file is rejected (D53).
#
#   MYTHICAL_<PRODUCT>_<ROLE>_BIND   path:4096   for every BINDABLE role (policy, not manifest)
#   MYTHICAL_<PRODUCT>_PORT          int:1:65535 the published host port
#
# <PRODUCT> and <ROLE> are upper-cased with `tr`, not `${x^^}` — bash 3.2 has no case modification.
mi_conf_product_keys() {
  if [ "$#" -ne 3 ]; then mi_warn "bringup: mi_conf_product_keys needs <product> <manifest-records> <policy-records>"; return 1; fi
  local product="$1" mrec="$2" prec="$3" up rup v role
  _mi_bringup_name_ok product "$product" || return 1
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')"
  printf 'MYTHICAL_%s_PORT\tint:1:65535\n' "$up"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    role="${v%%:*}"
    _mi_bringup_name_ok role "$role" || return 1
    # BINDABILITY IS A POLICY ENTITLEMENT (D53). Recognising a role is not authorizing it: rejecting
    # only UNKNOWN roles would make every known one bindable — including a product's SECRETS role,
    # whose 0600 named volume D5 and §4.3 depend on. `migrate-storage` would have been a supported
    # one-liner for moving every model credential onto an operator-chosen host path.
    mi_policy_bindable "$prec" "$product" "$role" || continue
    rup="$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')"
    printf 'MYTHICAL_%s_%s_BIND\tpath:4096\n' "$up" "$rup"
  done <<< "$(mi_doc_values "$mrec" volume)"
}

# The full mythical.conf spec for this operation: Plan 2's core keys plus this product's.
mi_conf_spec_for() {
  if [ "$#" -ne 3 ]; then mi_warn "bringup: mi_conf_spec_for needs <product> <manifest-records> <policy-records>"; return 1; fi
  mi_conf_family_spec
  mi_conf_product_keys "$@"
}

# WHERE THIS ROLE IS MOUNTED INSIDE THE CONTAINER, out of the AUTHENTICATED manifest — the only
# document that says. A manifest declares `volume  <role>:<absolute path>` (lib/doc.sh's `rolemount`),
# which is precisely the role→target mapping a launchable bind spec needs, and it is authenticated by
# the same door that vouched for the product.
#
# rc 0 the target is printed · 1 refused (reported).
#
# A ROLE THE MANIFEST DOES NOT PLACE HAS NO TARGET, and that is a refusal rather than a guess. There is
# nowhere else the container path could come from: the core derives NAMES (D32), never mount points,
# and inventing one would mount an operator's directory somewhere the product does not read.
#
# AND A ROLE IT PLACES TWICE IS AMBIGUOUS. Two records for one role are two answers to a question that
# has one, and picking the first would decide by file order which of an operator's directories is
# exposed at which path. Same rule the ledger applies to a lookup that resolves to more than one thing.
_mi_bringup_role_target() {
  local mrec="$1" role="$2" v r p found="" n=0
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in *:*) : ;; *) continue ;; esac   # not a rolemount at all; it places nothing
    r="${v%%:*}"; p="${v#*:}"
    [ "$r" = "$role" ] || continue
    n=$((n + 1))
    found="$p"
  done <<< "$(mi_doc_values "$mrec" volume)"
  if [ "$n" -eq 0 ]; then
    mi_warn "bringup: the manifest declares no mount point for the '$role' volume, so there is nowhere"
    mi_warn "  inside the container to bind it to. A container path is never invented here — the core"
    mi_warn "  derives names, not mount points. Refusing."
    return 1
  fi
  if [ "$n" -gt 1 ]; then
    mi_warn "bringup: the manifest places the '$role' volume at $n different paths. That is two answers"
    mi_warn "  to a question with one, and taking the first would let record order decide where an"
    mi_warn "  operator's directory is exposed. Refusing."
    return 1
  fi
  printf '%s\n' "$found"
}

# A COMPONENT OF A `bind=<source>:<target>:<mode>` SPEC, judged by the rule the CONSUMER applies and by
# the one the GRAMMAR needs — asked HERE, by the producer, so that no value this module emits can look
# launchable without being launchable.
#
# _mi_rt_bind_path_ok is lib/runtime.sh's own rule (absolute, comma-free, no `..`, no control bytes),
# called rather than copied: it is what mi_rt_container_create will apply, and a second implementation
# of the same check is one that drifts until the producer accepts what the consumer refuses.
#
# THE COLON IS THIS FUNCTION'S OWN ADDITION, and it is the one the runtime's rule cannot make. The spec
# is colon-separated, so a colon INSIDE a component moves every field boundary after it: the runtime
# reads `bind=/x:/y:/t:rw` as source `/x`, target `/y`, mode `/t:rw` and refuses — but
# `bind=/x:/y:rw`, where the source genuinely is `/x:/y`, is read as source `/x` mounted at `/y` and
# LAUNCHES, mounting a path nobody named. Refusing at the producer is the only place that distinction
# still exists; by the time the spec is a string, the information is gone.
_mi_bringup_spec_field_ok() {
  local v="$1" what="$2"
  _mi_rt_bind_path_ok "$v" "$what" || return 1
  case "$v" in
    *:*)
      mi_warn "bringup: $what '$v' contains a ':'. A bind spec is <source>:<target>:<mode>, so a colon"
      mi_warn "  inside a component moves the field boundaries and the launch mounts a different pair"
      mi_warn "  of paths from the one written down. Refusing rather than emitting a spec that cannot"
      mi_warn "  mean what it says."
      return 1 ;;
  esac
  return 0
}

# Emit `<role><TAB>bind=<canonical source>:<manifest target>:rw` for every role the operator has bound,
# having validated it. Roles with no bind key fall through to a named volume (D6: storage defaults to
# named volumes, and a fresh install requires the user to decide no paths).
#
# THE SECOND FIELD IS THE CONTAINER PATH THE MANIFEST DECLARES, and this is a correction. It used to be
# the ROLE — so every spec this function emitted was refused by mi_rt_container_create, whose target
# must be absolute, and the operator-bind feature could not work at all as emitted. It was defended as
# a seam for a later task to convert; it is not one. The output is documented as a `bind=` runtime spec
# and shaped exactly like one, so nothing stops a caller passing it straight to the runtime, which is
# what a later task would naturally do. The manifest already holds the mapping, so the conversion has
# an authenticated source and belongs here, at the one place that has both halves.
#
# THE LINE IS A RECORD, NOT AN ARGV FRAGMENT — TAB-separated, role first, exactly as mi_mount_core_fixed
# emits its mounts. A caller needs the pairing (the roles that got no bind are the ones that fall
# through to named volumes) and cannot recover it from the spec, where nothing distinguishes a target
# from any other path. Role first so that a caller who splats the whole listing into the runtime fails
# on the FIRST token, loudly, with "unknown container spec", before anything is created — rather than
# accepting a spec and then failing on the annotation beside it.
#
# THE VALIDATED CANONICAL SOURCE is what is emitted — never the operator's original string. §4.1a:
# "Validate and launch against the same resolved path. Canonicalize once, then pass the validated
# canonical source to the runtime."
#
# THE PAIRWISE RULE IS APPLIED HERE, TO THE WHOLE SET, and that is the point of the buffering below.
# mi_mount_check_overlap answers "is this one bind acceptable"; the pairwise rule is about the
# COMBINATION, and this is the only place the combination exists. Left to each caller to remember, it
# would be a rule applied to some of its inputs and not others — and the set a launch actually
# receives is the set that matters. Buffering also means a refused combination emits nothing at all,
# rather than handing a caller a PREFIX of a launch spec it may act on.
mi_mount_binds() {
  if [ "$#" -lt 4 ]; then
    mi_warn "bringup: mi_mount_binds needs <product> <manifest-records> <policy-records> <role>..."
    return 1
  fi
  local product="$1" mrec="$2" prec="$3"; shift 3
  _mi_bringup_name_ok product "$product" || return 1
  local up role rup key val f rc pspec
  # Two parallel arrays rather than one, and the role is CARRIED rather than parsed back out of the
  # spec: neither of the spec's path components is distinguishable from the other once it is a string,
  # and re-splitting one on `:` to recover an annotation is exactly the re-cut this module refuses to
  # make anywhere else.
  local -a bspecs broles
  bspecs=(); broles=()
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')"
  f="$(mi_conf_family_path)"
  # D53's gate, ASKED WHERE THE MOUNT IS ACTUALLY PRODUCED. mi_conf_get reads a key straight out of the
  # file with no spec, so reading MYTHICAL_<P>_<R>_BIND directly honoured whatever an operator had
  # typed — the entitlement lived only in the spec a caller may or may not have validated the file
  # against. `migrate-storage` would then have been a supported one-liner for moving every model
  # credential onto an operator-chosen host path, which is the exact scenario D53 names. The spec is
  # the SAME one mi_conf_product_keys builds, not a second reading of the policy index.
  pspec="$(mi_conf_product_keys "$product" "$mrec" "$prec")" || return 1
  for role in "$@"; do
    _mi_bringup_name_ok role "$role" || return 1
    rup="$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')"
    key="MYTHICAL_${up}_${rup}_BIND"
    if val="$(mi_conf_get "$f" "$key")"; then rc=0; else rc=$?; fi
    if ! _mi_conf_spec_type "$pspec" "$key" >/dev/null; then
      # Not bindable. Falling through to the named volume is right when the operator said nothing — but
      # SILENTLY, while the file names the key, would leave them believing a bind is in effect when the
      # role's whole protection is that it is not one.
      if [ "$rc" -eq 0 ]; then
        mi_warn "bringup: $f sets '$key', but the authenticated policy index does not make '$role'"
        mi_warn "  bindable for '$product'. Recognising a role is not authorizing it: a role kept on a"
        mi_warn "  named volume is kept there deliberately. Refusing rather than ignoring the setting."
        return 1
      fi
      [ "$rc" -eq 3 ] || return "$rc"
      continue
    fi
    [ "$rc" -eq 3 ] && continue                        # not bound: the named volume is used instead
    [ "$rc" -eq 0 ] || return "$rc"
    local canon target
    canon="$(mi_canon "$val")" || return 1
    mi_mount_check_overlap "$product" "$canon" || return 1
    target="$(_mi_bringup_role_target "$mrec" "$role")" || return 1
    # BOTH components, by the consumer's own rule plus the grammar's — so what is emitted is launchable
    # or nothing is emitted at all.
    _mi_bringup_spec_field_ok "$canon" "bind source for role '$role'" || return 1
    _mi_bringup_spec_field_ok "$target" "container target for role '$role'" || return 1
    bspecs+=("bind=${canon}:${target}:rw"); broles+=("$role")
  done
  [ "${#bspecs[@]}" -gt 0 ] || return 0
  mi_mount_binds_check_pairwise ${bspecs[@]+"${bspecs[@]}"} || return 1
  local i=0
  while [ "$i" -lt "${#bspecs[@]}" ]; do
    printf '%s\t%s\n' "${broles[$i]}" "${bspecs[$i]}"
    i=$((i + 1))
  done
  return 0
}

# --- §4.3 secret injection ------------------------------------------------------------------------
# Three classes, not two, and only ONE of them enters a container:
#
#   host-consumed        registry credentials, anything only the installer uses — NEVER enters.
#   container-bootstrap  a telemetry key, a future enrollment token — enters DELIBERATELY, and is
#                        visible in `docker inspect`. That exposure is accepted and documented: it is a
#                        local-first product and the operator already has the daemon socket.
#   product-runtime      model keys, webhook secrets — already inside, in the product's own store.
#
# Requirements this implements:
#   * INJECTION IS PER-KEY AND EXPLICIT. A product receives exactly the bootstrap secrets its manifest
#     declares, from what the POLICY INDEX already grants it. Passing the whole file, or the whole
#     environment, is forbidden — the point of the host-only file is that one product's compromise does
#     not disclose another's credentials, and a bulk --env-file of mythical.conf surrenders exactly that.
#   * NEVER IN `docker run` ARGV. Argv is world-readable via `ps` on the host. A per-container 0600 env
#     file holding ONLY that product's declared keys, removed after the run.
#
# Prints the path of the env file. THE CALLER REMOVES IT, on every exit path including failure —
# mi_bringup does NOT, and an earlier version of this comment said it did, which is exactly how a
# 0600 file of bootstrap secrets ends up outliving the run that needed it. The three callers are
# mi_verb_install, mi_verb_recreate and migrate-storage phase 7; each removes it in one place that
# every return path passes through.
mi_secrets_envfile() {
  if [ "$#" -lt 1 ]; then mi_warn "bringup: mi_secrets_envfile needs <product> [key...]"; return 1; fi
  local product="$1"; shift
  local f tmp key val rc spec
  # The product name is joined into the temp file's NAME below, so it is judged before it becomes a
  # path component.
  _mi_bringup_name_ok product "$product" || return 1
  f="$(mi_conf_family_path)"
  spec="$(mi_conf_family_spec)"
  # Created 0600 BEFORE any content lands. mktemp is already 0600, but stating it means a future edit
  # that stops using mktemp does not silently widen it. Under MYTHICAL_HOME/.state so it never appears
  # in a filesystem snapshot of the user-visible tree and is never inside a bind.
  tmp="$(mktemp "$(mi_home)/.state/.env.${product}.XXXXXX")" || {
    mi_warn "bringup: cannot create the secret env file"; return 1; }
  chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
  for key in "$@"; do
    # The key must be one mythical.conf ACCEPTS — an unknown key here would mean the manifest asked for
    # something outside the family vocabulary, which is a manifest error, not a missing value.
    if ! _mi_conf_spec_type "$spec" "$key" >/dev/null; then
      rm -f "$tmp"
      mi_warn "bringup: '$product' asked for bootstrap secret '$key', which mythical.conf does not define."
      mi_warn "  A product selects from what the policy index grants it; it cannot name arbitrary keys."
      return 1
    fi
    if val="$(mi_conf_get "$f" "$key")"; then rc=0; else rc=$?; fi
    if [ "$rc" -eq 3 ]; then
      rm -f "$tmp"
      mi_warn "bringup: '$product' requires bootstrap secret '$key', which is not set in $f."
      return 1
    fi
    [ "$rc" -eq 0 ] || { rm -f "$tmp"; return "$rc"; }
    printf '%s=%s\n' "$key" "$val" >> "$tmp" || { rm -f "$tmp"; return 1; }
  done
  printf '%s\n' "$tmp"
}

# --- §6b.3 step 1: create ------------------------------------------------------------------------
# THE INTENT RECORDS WHAT THIS RUN WAS IN THE MIDDLE OF *DOING*, not merely which object it was in the
# middle of creating — and that is the whole of the fix for the window this sequence could not close.
#
# The window is BEFORE the first state write, and no ordering closes it. Create succeeds, step 2's
# inspection succeeds, the process dies before mi_state_commit. Recovery re-inspects and confirms — but
# with nothing to say what the desired state was or what check was owed, it wrote neither, and
# mi_state_plan then answered `none` for ever: for an intended `running` container, never started,
# never live-verified, and no outstanding entry for any later start to schedule a verification from.
# Reordering the two writes does not help (the gap is earlier than both) and neither would a combined
# writer: it cannot close a gap that opens before it is called. The durable record has to carry the
# decision, because the process that made it is the one that died.
#
# So the write-ahead record carries the DESIRED STATE this bring-up resolved (`preserve` is resolved by
# mi_bringup before this is called, so what lands here is always a concrete `running`/`stopped`) and
# the CHECK the sequence owes. mi_bringup_recover reads all three back, establishes state through the
# ordinary atomic writer, and only then confirms.
mi_bringup_create() {
  if [ "$#" -lt 6 ]; then
    mi_warn "bringup: mi_bringup_create needs <container> <image> <netid> <alias> <running|stopped> <envfile|-> [spec...]"
    return 1
  fi
  local c="$1" image="$2" netid="$3" alias="$4" desired="$5" envfile="$6"; shift 6
  local ident nonce
  # Judged HERE, before the intent is written, by the vocabulary lib/state.sh owns — a value this
  # module invented would be one mi_state_commit refuses at recovery time, which is the worst moment to
  # discover it: the container exists, the intent names an unusable state, and nothing can act on it.
  _mi_state_desired_ok "$desired" || return 1
  ident="$(mi_ident_get)" || return 1
  nonce="$(mi_nonce_new)" || return 1
  # Write-ahead: the intent, with the nonce AND the decision, BEFORE the object.
  mi_intent_open container "$c" "$nonce" \
    "desired=${desired}" "check=alias" "check_param=${netid}" || return 1
  mi_rt_container_create "$c" "$image" "$netid" "$alias" "$envfile" \
    "$@" "label=installation=${ident}" "label=nonce=${nonce}" >/dev/null || return 1
  printf '%s\n' "$nonce"
}

# --- §6b.3 step 2: verify by inspection ----------------------------------------------------------

# Every attachment `c.nets` reports, as `<netid><TAB><address>` lines.
#
# ONE walk, for BOTH readers below: step 2 needs the complete set of IDs and step 5 needs the address
# on one of them, and two splits of one string is how the two stop agreeing about what an attachment
# is. It walks the string one separator at a time with parameter expansion rather than setting
# `IFS=';'` and letting word splitting do it, because unquoted word splitting also GLOBS — a field
# whose value happened to be a pattern would be replaced by matching filenames in the working
# directory — and because an IFS split has to be undone afterwards.
_mi_bringup_attachments() {
  local rest="$1" pair
  while [ -n "$rest" ]; do
    pair="${rest%%;*}"
    if [ "$rest" = "$pair" ]; then rest=""; else rest="${rest#*;}"; fi
    [ -n "$pair" ] || continue
    case "$pair" in
      *=*) printf '%s\t%s\n' "${pair%%=*}" "${pair#*=}" ;;
      *)   printf '%s\t\n' "$pair" ;;
    esac
  done
}

# THE COMPLETE NETWORK SET, not merely presence. Asking "is our network among them?" is what lets a
# stray default bridge survive. Not "the connect command returned zero".
#
# The one exception is a recorded D45 migration, during which the permitted set is exactly {old, new} —
# bounded, recorded, and resumed the moment it commits. A two-network container with NO migration
# intent recorded is a DEFECT, and is caught here rather than tolerated.
#
# THE JUDGEMENT IS SEPARATED FROM THE INSPECTION, and it is separated because TWO steps make it. Step 2
# asks it of a stopped container; step 5 asks it again of a running one — and step 5 is the step that
# CLEARS the outstanding check, so it is the step at which getting this wrong is unrecoverable.
#
# Step 5 used to pull the target network's address out of the attachment set and never re-ask. A second
# network attached AFTER step 2 — before or during running — therefore changed nothing it looked at:
# DNS still resolved the alias to the target network's address, live verification returned success, and
# the caller retired the only outstanding entry. The result is a container this CLI reports as verified
# and reconciled while attached to an extra network, which is exactly the state step 2 exists to make
# unreachable, arriving through the door step 5 left open. "Confirmed" means attached correctly AND TO
# NOTHING ELSE, and that second half has to be true at the moment the check is retired, not only at the
# moment it was written.
#
# It takes the inspection RESULTS rather than performing them, so step 5 can judge and measure ONE
# observation. Inspecting twice would compare an address against a topology established a moment
# earlier — a check that passes for the wrong reason, which is the same defect class one layer down.
#
# rc 0 the set is exactly what is permitted, and the alias is on the expected network · 1 refused
# (reported).
_mi_bringup_attach_ok() {
  if [ "$#" -ne 5 ]; then mi_warn "bringup: _mi_bringup_attach_ok needs <container> <netid> <alias> <nets> <aliases>"; return 1; fi
  local c="$1" want="$2" alias="$3" nets="$4" aliases="$5" id line

  local -a ids
  ids=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ids+=("${line%%$'\t'*}")
  done <<< "$(_mi_bringup_attachments "$nets")"
  # A container with NO attachments yields an empty array, and under `set -u` bash 3.2 errors on
  # "${ids[@]}" for an empty array (verified) — so the loops below use the `${ids[@]+...}` guard. An
  # unattached container is not hypothetical: it is what a half-built bring-up leaves behind, which is
  # exactly the state this function exists to catch.
  if [ "${#ids[@]}" -eq 0 ]; then
    mi_warn "bringup: '$c' is attached to NO network at all."
    mi_warn "  Its network set must be exactly {$want}."
    return 1
  fi

  # The permitted set. Exactly one ID normally; exactly {source,target} during a recorded migration.
  local -a permitted
  permitted=("$want")
  local mig src tgt migrc
  # THE MIGRATION LOOKUP FAILS CLOSED, in both of its failure directions.
  #
  # `mi_led_find` answers rc 0 found · 3 absent · 1 could not answer — the last covering an unreadable
  # ledger and an AMBIGUOUS one (two `netmig key=family` rows). Only rc 3 means "there is no
  # migration"; treating rc 1 as absent is the same fold this codebase has closed five times, and here
  # it is a fail-open with a specific consequence: the permitted set silently narrows back to the
  # singleton `{want}`, a container standing on the target alone then satisfies every direction below,
  # live verification succeeds, and the caller RETIRES the outstanding check — leaving a half-migrated
  # container recorded as verified and never looked at again.
  #
  # A record that IS present must yield both fields. A missing or empty `source`/`target` was coerced
  # to empty and fell through to the same singleton, so a truncated record produced the identical
  # wrong answer by a second route.
  if mig="$(mi_led_find netmig key family 2>/dev/null)"; then migrc=0; else migrc=$?; fi
  case "$migrc" in
    3) : ;;                       # genuinely no migration recorded — the singleton is correct
    0) src="$(mi_led_field "$mig" source)" || src=""
       tgt="$(mi_led_field "$mig" target)" || tgt=""
       if [ -z "$src" ] || [ -z "$tgt" ]; then
         mi_warn "bringup: a network migration is recorded but does not name both networks."
         mi_warn "  Refusing to verify '$c' against a narrower set than the record implies — that is"
         mi_warn "  how a half-migrated container gets recorded as verified. Run 'mythical-ctl state repair'."
         return 1
       fi
       permitted=("$src" "$tgt") ;;
    *) mi_warn "bringup: cannot read whether a network migration is in progress."
       mi_warn "  Refusing rather than assuming there is none — assuming would narrow the permitted"
       mi_warn "  set and accept a container standing half-way through one."
       return 1 ;;
  esac

  # EXACTLY THE PERMITTED SET, WHICH IS "EVERY PERMITTED ID EXACTLY ONCE" — not "every attachment is
  # permitted, and the wanted one is among them". That weaker pair accepts a strict SUBSET, and the
  # subset it accepts is the mid-migration one. With a recorded migration the permitted set is
  # {source,target}, so a container attached to the TARGET alone satisfies both halves when it is
  # verified for the target (nothing unexpected is attached; the wanted network is), and a container
  # on the SOURCE alone satisfies them both when the wanted network is the source. Neither is
  # attached to the set the migration record documents, and success here is what makes every caller
  # of mi_bringup_verify_live retire the outstanding check — so a container standing half-way through
  # a migration would be recorded as verified and never looked at again.
  local i ok n
  # Direction 1 — nothing beyond the permitted set. This is what catches a stray default bridge.
  for id in ${ids[@]+"${ids[@]}"}; do
    ok=0
    for i in ${permitted[@]+"${permitted[@]}"}; do [ "$id" = "$i" ] && ok=1; done
    if [ "$ok" -eq 0 ]; then
      mi_warn "bringup: '$c' is attached to network '$id', which is not permitted."
      mi_warn "  Its network set must be exactly {${permitted[*]}} — 'is ours among them' is what lets a"
      mi_warn "  stray default bridge survive."
      return 1
    fi
  done
  # Direction 2 — the network THIS call is about. Asked separately, and before direction 3, because
  # direction 3 does not imply it: a migration recorded between two OTHER networks bounds `permitted`
  # to a pair the wanted network is not in, and a container attached to exactly that pair would
  # satisfy direction 3 while having no attachment to the network being verified at all.
  ok=0
  for id in ${ids[@]+"${ids[@]}"}; do [ "$id" = "$want" ] && ok=1; done
  if [ "$ok" -eq 0 ]; then
    mi_warn "bringup: '$c' is not attached to the expected network '$want'."
    return 1
  fi
  # Direction 3 — every permitted ID present, exactly once. Zero is the subset above. More than one
  # is a second endpoint on a single network: a real daemon refuses the duplicate connect outright,
  # so seeing it means something other than this CLI built the attachment, and a comparison that
  # counted only distinct ids would call that set equal to one it does not match.
  for i in ${permitted[@]+"${permitted[@]}"}; do
    n=0
    for id in ${ids[@]+"${ids[@]}"}; do
      if [ "$id" = "$i" ]; then n=$((n + 1)); fi
    done
    if [ "$n" -eq 1 ]; then continue; fi
    if [ "$n" -eq 0 ]; then
      mi_warn "bringup: '$c' is NOT attached to network '$i'."
      mi_warn "  Its network set must be exactly {${permitted[*]}}; it is attached to {${ids[*]}}."
      mi_warn "  A subset is not the set: during a recorded migration a container standing on only one"
      mi_warn "  of the two is mid-move, not reconciled, and this is the check whose success retires"
      mi_warn "  the outstanding verification."
    else
      mi_warn "bringup: '$c' is attached to network '$i' $n times."
      mi_warn "  Its network set must be exactly {${permitted[*]}} — one endpoint per network."
    fi
    return 1
  done

  # The alias, on the expected network. `docker network connect` infers none, and without it the
  # container joins under its own installation-scoped name — which no sibling can guess, so family DNS
  # fails SILENTLY and a rejected peer is indistinguishable from an absent one (§9).
  #
  # Both the presence test and the extraction below are anchored on the leading `;`, so a network id
  # that merely ENDS with the expected one cannot answer for it.
  local blob=";${aliases}" seg
  case "$blob" in
    *";${want}:"*) : ;;
    *) mi_warn "bringup: '$c' has no alias recorded on network '$want'"; return 1 ;;
  esac
  seg="${blob#*";${want}":}"; seg="${seg%%;*}"
  case ",${seg}" in
    *",${alias},"*) : ;;
    *) mi_warn "bringup: '$c' does not carry the alias '$alias' on network '$want' (has: ${seg%,})"
       mi_warn "  Siblings resolve a product by its alias; without it, family DNS fails silently."
       return 1 ;;
  esac
  return 0
}

# Step 2's entry point: inspect, then judge. The judgement itself is the predicate above, which step 5
# calls on its own inspection. This step runs on a container that has NEVER started, whose endpoints
# carry no NetworkID yet — so it reads the RESOLVED attachment views (lib/runtime.sh
# mi_rt_container_{nets,aliases}_resolved), which identify each network by its NAME and resolve it to
# the id the predicate compares, failing closed if a name cannot be resolved. Step 5 (verify_live)
# inspects a RUNNING container, where the id is populated, and reads c.nets/c.aliases directly.
mi_bringup_verify_attach() {
  if [ "$#" -ne 3 ]; then mi_warn "bringup: mi_bringup_verify_attach needs <container> <expected netid> <alias>"; return 1; fi
  local c="$1" want="$2" alias="$3" nets aliases
  nets="$(mi_rt_container_nets_resolved "$c")" || return 1
  aliases="$(mi_rt_container_aliases_resolved "$c")" || return 1
  _mi_bringup_attach_ok "$c" "$want" "$alias" "$nets" "$aliases"
}

# --- §6b.3 step 5: verify live -------------------------------------------------------------------
# RE-INSPECT the container now that it is running to learn the endpoint address it actually has, then
# have the probe resolve its alias and confirm the answer matches THAT address.
#
# The re-inspection is not redundant: the only earlier inspection happened at step 2, while the
# container was STOPPED and had no address at all. Comparing DNS against "the address inspection
# reports" would have compared it against nothing.
#
# rc 0 verified · 1 verification FAILED (reported; the caller keeps the outstanding entry and leaves
# the product running) · 4 the probe could not run at all.
mi_bringup_verify_live() {
  if [ "$#" -ne 4 ]; then mi_warn "bringup: mi_bringup_verify_live needs <index> <container> <netid> <alias>"; return 1; fi
  local idx="$1" c="$2" netid="$3" alias="$4" nets aliases line expect="" resolved rc

  nets="$(mi_rt_inspect container c.nets "$c")" || return 1
  aliases="$(mi_rt_inspect container c.aliases "$c")" || return 1
  # THE COMPLETE-SET CHECK, AGAIN, BEFORE ANYTHING THIS FUNCTION SAYS CAN RETIRE A CHECK. Success here
  # is what makes the caller clear the outstanding entry, so every property "confirmed" claims has to
  # hold NOW — including the one about what the container is NOT attached to. The topology can change
  # between step 2 and this moment, and a resolving alias is no evidence about it: aliases are
  # network-scoped, so the target network answers correctly no matter what else the container joined.
  #
  # Judged on THIS inspection, and the address below is taken from the same one, so the address
  # compared belongs to the topology just proved complete.
  _mi_bringup_attach_ok "$c" "$netid" "$alias" "$nets" "$aliases" || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "${line%%$'\t'*}" = "$netid" ]; then expect="${line#*$'\t'}"; fi
  done <<< "$(_mi_bringup_attachments "$nets")"
  if [ -z "$expect" ]; then
    mi_warn "bringup: '$c' has no endpoint address on '$netid' — it is not running, so its alias has"
    mi_warn "  no endpoint to answer with. Deferring the check to its next explicit start."
    return 1
  fi

  # The DNS MECHANISM first: the probe's own alias. This separates "DNS on this network is broken" from
  # "that product is not running", and it is testable regardless of what the fleet is doing.
  mi_probe_selfcheck "$idx" "$netid" || return 4

  if resolved="$(mi_probe_resolve "$idx" "$netid" "$alias")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 4 ] || [ "$rc" -eq 1 ]; then return 4; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "bringup: the alias '$alias' does not resolve on network '$netid'."
    return 1
  fi
  # COMPARE ADDRESSES, not just resolution. Docker aliases are NETWORK-SCOPED, so during a migration a
  # name resolves happily via the OLD network and proves nothing about the new one. A check that passes
  # for the wrong reason is the same defect class as asking "is our network among them?".
  if [ "$resolved" != "$expect" ]; then
    mi_warn "bringup: '$alias' resolves to '$resolved' on network '$netid', but '$c' is at '$expect'."
    mi_warn "  The name resolves — via something other than this network's endpoint for this container."
    return 1
  fi
  return 0
}

# --- the whole sequence --------------------------------------------------------------------------
# <desired> is `running`, `stopped`, or `preserve`.
#
# DESIRED STATE IS A PARAMETER OF THE CALLER, NOT A CONSTANT. `install` and `start` pass `running`; a
# container REPLACEMENT (a `recreate`, or D51 phase 7) passes `preserve`, because those verbs preserve
# intent rather than express it. An earlier revision hardcoded `running` here, so every replacement
# silently restarted a product the operator had stopped — defeating D43 through the one path D43 did
# not name.
#
# EVERY path that ends with a container running walks steps 3–5: set the outstanding entry → start →
# verify live → clear it. An earlier revision left that tail on `install` alone.
mi_bringup() {
  if [ "$#" -lt 7 ]; then
    mi_warn "bringup: mi_bringup needs <index> <container> <image> <netid> <alias> <running|stopped|preserve> <envfile|-> [spec...]"
    return 1
  fi
  local idx="$1" c="$2" image="$3" netid="$4" alias="$5" desired="$6" envfile="$7"; shift 7
  local nonce want rc

  case "$desired" in
    running|stopped) want="$desired" ;;
    preserve)
      if want="$(mi_state_desired_get "$c")"; then rc=0; else rc=$?; fi
      if [ "$rc" -eq 3 ]; then
        mi_warn "bringup: asked to preserve the desired state of '$c', but there is no desired state"
        mi_warn "  recorded for it. Refusing to guess: 'running' would start something nobody asked"
        mi_warn "  for, and 'stopped' would take a working install down."
        return 1
      fi
      [ "$rc" -eq 0 ] || return 1 ;;
    *) mi_warn "bringup: '$desired' is not running, stopped or preserve"; return 1 ;;
  esac

  # `$want`, never `$desired`: `preserve` is resolved above, and the intent must record the state this
  # run actually decided on. Writing `preserve` into it would leave recovery re-deriving a decision
  # from a ledger this run may already have changed.
  nonce="$(mi_bringup_create "$c" "$image" "$netid" "$alias" "$want" "$envfile" "$@")" || return 1

  # Step 2. A container that does not verify is REMOVED and the intent retained — leaving it would be a
  # confirmed-but-detached container, the state §6b.3 exists to make unreachable.
  if ! mi_bringup_verify_attach "$c" "$netid" "$alias"; then
    # We created this container microseconds ago under our own nonce — but §6a's rule has NO
    # exceptions, and re-reading one label is cheaper than an exception a later reader must reason
    # about. If it no longer carries our nonce, something else holds that name: leave it.
    if [ "$(mi_rt_inspect container c.nonce "$c" 2>/dev/null || true)" = "$nonce" ]; then
      mi_rt_container_rm "$c" >/dev/null 2>&1 || true
      mi_warn "bringup: removed '$c' because it did not verify. Nothing was confirmed."
    else
      mi_warn "bringup: '$c' did not verify AND no longer carries the nonce we created it with —"
      mi_warn "  something else holds that name. It is left alone. Nothing was confirmed."
    fi
    return 1
  fi

  # Step 3. Desired state AND the outstanding check first — mi_state_commit writes both in ONE atomic
  # ledger write — and the confirmation second.
  #
  # THE ORDER OF THE TWO WRITES IS THE CRASH WINDOW, and only one direction is recoverable. Crash
  # between them as written and the intent is still open, so mi_state_plan answers `suspended` and
  # mi_bringup_recover finishes the job. Confirm FIRST and the same crash leaves provenance with no
  # desired state at all: mi_state_plan answers `none`, the container is running, and nothing is ever
  # scheduled to verify it.
  #
  # The outstanding entry is set BEFORE the start, so a crash anywhere between the start and the clear
  # leaves it set and the work repeats. Setting it after the start would leave a window in which a
  # started container is considered fully reconciled without live verification.
  local id
  mi_state_commit "$c" "$want" alias "$netid" || return 1
  id="$(mi_rt_inspect container c.image "$c" 2>/dev/null || true)"
  mi_intent_confirm container "$c" "$nonce" "id=${id}" || return 1

  if [ "$want" = stopped ]; then
    # Nothing is running, so there is nothing to live-verify. The entry stays: it will be performed at
    # the container's next explicit start (D48 — a stopped container has no address, so its alias has
    # no endpoint to answer with). Deferring is not skipping.
    return 0
  fi

  # Step 4.
  mi_rt_container_start "$c" >/dev/null || {
    mi_warn "bringup: '$c' was created and confirmed, but did not start."
    return 1; }

  # Step 5. The status is captured in the ELSE branch: `rc=$?` after the `fi` would read the `if`
  # statement's own status (0 when the condition was false and there is no else), so the probe-failure
  # branch below could never be reached.
  if mi_bringup_verify_live "$idx" "$c" "$netid" "$alias"; then
    # `|| return 1`: a bare call is a simple command, so a failed ledger write would abort the CLI
    # under `set -e` AFTER the container is running and verified — the worst moment to exit silently.
    # The PARAMETER is named as well as the kind: this container may owe an alias check on more than
    # one network, and only the one just verified may be retired.
    mi_state_outstanding_clear "$c" alias "$netid" || return 1
    return 0
  else
    rc=$?
  fi
  # FAILURE IS A STATE, NOT AN EXCEPTION (D50). The container keeps the outstanding entry, the failure
  # is recorded and reported, and the product is LEFT RUNNING. It is not stopped — the operator asked
  # for it — and not silently accepted. An installer that stops a working product because a DNS check
  # failed is worse than one that keeps saying the check failed.
  if [ "$rc" -eq 4 ]; then
    mi_warn "bringup: '$c' is running, but the probe could not run, so its alias was not verified."
  else
    mi_warn "bringup: '$c' is running, but its alias did not verify. It is left running and the check"
    mi_warn "  remains outstanding; it will be retried on the next operation."
  fi
  return 1
}

# --- recovery (§6b.3's table) --------------------------------------------------------------------
# RECOVERY RE-INSPECTS; IT NEVER TRUSTS THAT AN INSPECTION HAPPENED. An earlier revision gave
# crashes-after-inspection their own row that confirmed the container directly — but "inspection
# succeeded" existed only in the process that died, and is nowhere in the ledger. A recovering process
# cannot distinguish "inspected and correct" from "never inspected", and in the gap the topology may
# have changed: a network detached, a second one attached. So the unconfirmed states collapse into one
# row and always re-inspect. Steps that leave no durable record are not steps recovery can reason about.
#
# AND IT ESTABLISHES STATE BEFORE IT CONFIRMS. Confirming alone was the defect: it consumed the intent
# — the only durable record of what was being built — and wrote provenance in its place, leaving a
# container with no desired state and no outstanding check. mi_state_plan then answered `none`, so the
# container was never started, never live-verified, and nothing existed for a later start to schedule a
# verification from. The order here mirrors mi_bringup's for the same reason: state first, confirmation
# second, so a crash between them leaves the intent open and the next run repeats this function.
#
# rc 0 confirmed · 4 removed and the intent retained for the verb to rebuild · 1 stopped (reported).
mi_bringup_recover() {
  if [ "$#" -ne 4 ]; then mi_warn "bringup: mi_bringup_recover needs <index> <container> <netid> <alias>"; return 1; fi
  # shellcheck disable=SC2034   # <index> is part of the recovery signature every caller passes; the
  # live verification it feeds is the reconciler's step, not this one's — see mi_bringup_reconcile.
  local idx="$1" c="$2" netid="$3" alias="$4" rec nonce rc

  if rec="$(mi_intent_find container "$c")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  nonce="$(mi_led_field "$rec" nonce)" || return 1

  # WHAT THE DYING RUN WAS IN THE MIDDLE OF DOING — read BEFORE anything is inspected, removed or
  # written. An intent this function cannot fully read is one it cannot finish, and it must not remove
  # a container on the strength of a record it could not act on either way.
  #
  # A MISSING FIELD IS A REFUSAL, NOT A DEFAULT. lib/state.sh has no default desired state for exactly
  # this reason: `running` would start something nobody asked for and `stopped` would take a working
  # install down. Confirming without one is the third wrong answer and the quietest — it produces a
  # container that is accounted for, never started, and never checked. Every intent this module opens
  # carries all three fields; one that does not came from a restored, foreign or older ledger, or from
  # a caller that is not this sequence.
  local want check param
  if want="$(mi_led_field "$rec" desired)"; then :; else
    mi_warn "bringup: the intent for '$c' does not say which desired state this bring-up was recording."
    mi_warn "  Confirming it would consume the only record of what was being built and leave the"
    mi_warn "  container accounted for, never started and never verified. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  if ! _mi_state_desired_ok "$want"; then
    mi_warn "  — and that value is on DISK, in the intent, not in this call. The container and the"
    mi_warn "  intent are both PRESERVED. Run 'mythical-ctl state repair'."
    return 1
  fi
  if check="$(mi_led_field "$rec" check)"; then :; else
    mi_warn "bringup: the intent for '$c' does not say what check this bring-up owed. An intent that"
    mi_warn "  records a start without recording what proving it costs is the state D50 refuses to let"
    mi_warn "  an empty outstanding set mean. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  _mi_state_kind_ok "$check" || return 1
  if param="$(mi_led_field "$rec" check_param)"; then :; else param=""; fi
  if [ -z "$param" ]; then
    mi_warn "bringup: the intent for '$c' records a '${check}' check that names nothing to verify."
    mi_warn "  An 'alias' check carries the network the alias must resolve on, and one carrying nothing"
    mi_warn "  can never be matched and so can never be cleared. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  # THE INTENT AND THE CALLER MUST BE TALKING ABOUT THE SAME NETWORK. The topology is verified below
  # against the caller's <netid>, and the check is recorded from the intent's — so a disagreement would
  # commit a check for a network nothing here has looked at, on the evidence of a network nobody
  # recorded. There is no safe way to pick one: the intent is the durable record and the argument is
  # what was actually proved. Both are preserved and an operator decides.
  if [ "$param" != "$netid" ]; then
    mi_warn "bringup: the intent for '$c' was opened for network '$param', and this recovery was asked"
    mi_warn "  about '$netid'. Those are two different bring-ups. Nothing is confirmed, nothing is"
    mi_warn "  removed, and nothing is recorded."
    return 1
  fi

  local obs
  obs="$(mi_state_observed "$c")" || return 1
  if [ "$obs" = absent ]; then
    mi_warn "bringup: the intent for '$c' names a container that does not exist; retaining the intent"
    mi_warn "  so the verb that opened it can re-create it from the launch spec."
    return 4
  fi

  # Prove it is ours before touching it: name + nonce label, never the name alone (§6a).
  local actual
  actual="$(mi_rt_inspect container c.nonce "$c" 2>/dev/null || true)"
  if [ "$actual" != "$nonce" ]; then
    mi_warn "bringup: '$c' exists but carries nonce '$actual', not the recorded '$nonce'."
    mi_warn "  It is NOT adopted and NOT removed. Resolve it with the container runtime, then re-run."
    return 1
  fi

  if ! mi_bringup_verify_attach "$c" "$netid" "$alias"; then
    mi_rt_container_rm "$c" >/dev/null 2>&1 || true
    mi_warn "bringup: removed '$c' — it was created but its topology does not verify, and a"
    mi_warn "  confirmed-but-detached container is a state this sequence must never produce."
    return 4
  fi

  # STATE FIRST, CONFIRMATION SECOND — mi_bringup's step 3, performed here from the record rather than
  # from a decision this process never made. mi_state_commit writes the desired row and the outstanding
  # entry in ONE atomic ledger write, so the container can never be confirmed with one and not the
  # other; and because the intent is still open until the line below, a crash in between simply brings
  # the next run back to this function.
  mi_state_commit "$c" "$want" "$check" "$param" || return 1
  local id
  id="$(mi_rt_inspect container c.image "$c" 2>/dev/null || true)"
  mi_intent_confirm container "$c" "$nonce" "id=${id}" || return 1
  return 0
}

# Act on mi_state_plan for one container. A RESUME IS ATTEMPTED ONCE PER RUN AND REPORTED, never
# retried in a loop: a container that exits immediately because its image is broken must surface as a
# failure, not become an invisible restart cycle.
#
# rc 0 converged (or nothing to do) · 1 attempted and failed (reported) · 4 needs a rebuild only the
# verb can perform.
mi_bringup_reconcile() {
  if [ "$#" -ne 4 ]; then mi_warn "bringup: mi_bringup_reconcile needs <index> <container> <netid> <alias>"; return 1; fi
  local idx="$1" c="$2" netid="$3" alias="$4" plan
  plan="$(mi_state_plan "$c")" || return 1
  case "$plan" in
    none)      return 0 ;;
    suspended)
      mi_warn "note: reconciliation of '$c' is suspended — a migration intent is recorded for it and"
      mi_warn "  carries the desired state to restore. The reconciler must not restart a container a"
      mi_warn "  migration deliberately stopped."
      return 0 ;;
    defer)
      mi_warn "note: '$c' is stopped with a verification outstanding. A stopped container has no"
      mi_warn "  address, so there is nothing to resolve; the check is performed at its next start."
      return 0 ;;
    exited)
      mi_warn "bringup: '$c' should be running and is not, and this installer has ALREADY resumed it"
      mi_warn "  once under the intent currently recorded. It does not stay up. Reported rather than"
      mi_warn "  started again — restarting on every pass is the loop the attempt record exists to"
      mi_warn "  stop. Re-stating the intent grants a fresh attempt."
      return 1 ;;
    rebuild)   return 4 ;;
    stop)
      mi_rt_container_stop "$c" >/dev/null || {
        mi_warn "bringup: '$c' should be stopped but stopping it failed. Reported once, not retried."
        return 1; }
      return 0 ;;
    verify)
      if mi_bringup_verify_live "$idx" "$c" "$netid" "$alias"; then
        mi_state_outstanding_clear "$c" alias "$netid" || return 1
        return 0
      fi
      mi_warn "bringup: the outstanding verification for '$c' failed again. Left running, still"
      mi_warn "  outstanding, reported once."
      return 1 ;;
    "start verify")
      # THE ATTEMPT IS RECORDED BEFORE THE START, and this call is not optional. lib/state.sh cannot
      # enforce it — a verb that omits it silently restores an infinite restart loop with the whole
      # suite green — and it is what makes the SECOND plan (`exited`) differ from this one. Before,
      # not after: a crash between the start and the record would leave a container nobody knows was
      # tried, and a start that does not survive is still an attempt.
      mi_state_resume_record "$c" || return 1
      if ! mi_rt_container_start "$c" >/dev/null 2>&1; then
        mi_warn "bringup: '$c' should be running but did not start. Attempted ONCE this run and"
        mi_warn "  reported as a failure — never retried in a loop, because a container that exits"
        mi_warn "  immediately on a broken image would become an invisible restart cycle."
        return 1
      fi
      if mi_bringup_verify_live "$idx" "$c" "$netid" "$alias"; then
        mi_state_outstanding_clear "$c" alias "$netid" || return 1
        return 0
      fi
      mi_warn "bringup: '$c' started but its alias did not verify. Left running, still outstanding."
      return 1 ;;
    *) mi_warn "bringup: internal error — unknown plan '$plan'"; return 1 ;;
  esac
}
