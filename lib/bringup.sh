#!/usr/bin/env bash
# §6b.3 container bring-up, §4.1a mount validation at the launch site, §4.3 secret injection.
#
# THE ORDER IS FIXED AND CONFIRMATION COMES LAST, so "confirmed" always means "attached correctly, and
# to nothing else":
#
#   1 create, NOT started, attached to the target network ID AT CREATION
#   2 verify by inspection — the COMPLETE network set, exactly {expected}, with the expected alias
#   3 record desired state and the outstanding check, then confirm
#   4 start
#   5 verify live — re-inspect for the address it actually has, resolve its alias, compare, then clear
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
mi_mount_binds_check_pairwise() {
  local -a srcs modes
  srcs=(); modes=()
  local s body p1 p3 c
  for s in "$@"; do
    case "$s" in bind=*) : ;; *) continue ;; esac
    body="${s#bind=}"
    p1="${body%%:*}"; p3="${body##*:}"
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

# Emit `bind=<canonical>:<container-path>:<rw>` for every role the operator has bound, having validated
# it. Roles with no bind key fall through to a named volume (D6: storage defaults to named volumes, and
# a fresh install requires the user to decide no paths).
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
  if [ "$#" -lt 2 ]; then mi_warn "bringup: mi_mount_binds needs <product> <role>..."; return 1; fi
  local product="$1"; shift
  _mi_bringup_name_ok product "$product" || return 1
  local up role rup key val f rc
  # Two parallel arrays rather than one, and the role is CARRIED rather than parsed back out of the
  # spec: recovering it with `${b%:*}`/`${b##*:}` would re-split a string on a `:` that a canonical
  # host path is free to contain, so the annotation could name a fragment of the path instead.
  local -a bspecs broles
  bspecs=(); broles=()
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')"
  f="$(mi_conf_family_path)"
  for role in "$@"; do
    _mi_bringup_name_ok role "$role" || return 1
    rup="$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')"
    key="MYTHICAL_${up}_${rup}_BIND"
    if val="$(mi_conf_get "$f" "$key")"; then rc=0; else rc=$?; fi
    [ "$rc" -eq 3 ] && continue                        # not bound: the named volume is used instead
    [ "$rc" -eq 0 ] || return "$rc"
    local canon
    canon="$(mi_canon "$val")" || return 1
    mi_mount_check_overlap "$product" "$canon" || return 1
    bspecs+=("bind=${canon}:${role}:rw"); broles+=("$role")
  done
  [ "${#bspecs[@]}" -gt 0 ] || return 0
  mi_mount_binds_check_pairwise ${bspecs[@]+"${bspecs[@]}"} || return 1
  local i=0
  while [ "$i" -lt "${#bspecs[@]}" ]; do
    printf '%s\t%s\n' "${bspecs[$i]}" "${broles[$i]}"
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
mi_bringup_create() {
  if [ "$#" -lt 5 ]; then
    mi_warn "bringup: mi_bringup_create needs <container> <image> <netid> <alias> <envfile|-> [spec...]"
    return 1
  fi
  local c="$1" image="$2" netid="$3" alias="$4" envfile="$5"; shift 5
  local ident nonce
  ident="$(mi_ident_get)" || return 1
  nonce="$(mi_nonce_new)" || return 1
  # Write-ahead: the intent, with the nonce, BEFORE the object.
  mi_intent_open container "$c" "$nonce" || return 1
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
mi_bringup_verify_attach() {
  if [ "$#" -ne 3 ]; then mi_warn "bringup: mi_bringup_verify_attach needs <container> <expected netid> <alias>"; return 1; fi
  local c="$1" want="$2" alias="$3" nets aliases id line
  nets="$(mi_rt_inspect container c.nets "$c")" || return 1
  aliases="$(mi_rt_inspect container c.aliases "$c")" || return 1

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
  local mig src tgt
  if mig="$(mi_led_find netmig key family 2>/dev/null)"; then
    src="$(mi_led_field "$mig" source)" || src=""
    tgt="$(mi_led_field "$mig" target)" || tgt=""
    if [ -n "$src" ] && [ -n "$tgt" ]; then permitted=("$src" "$tgt"); fi
  fi

  # Every attachment must be permitted, AND the expected one must be present. Both directions: the
  # first catches a stray bridge, the second catches a container that is on the migration's source
  # only.
  local i ok
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
  ok=0
  for id in ${ids[@]+"${ids[@]}"}; do [ "$id" = "$want" ] && ok=1; done
  if [ "$ok" -eq 0 ]; then
    mi_warn "bringup: '$c' is not attached to the expected network '$want'."
    return 1
  fi

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
  local idx="$1" c="$2" netid="$3" alias="$4" nets line expect="" resolved rc

  nets="$(mi_rt_inspect container c.nets "$c")" || return 1
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

  nonce="$(mi_bringup_create "$c" "$image" "$netid" "$alias" "$envfile" "$@")" || return 1

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
# rc 0 confirmed · 4 removed and the intent retained for the verb to rebuild · 1 stopped (reported).
mi_bringup_recover() {
  if [ "$#" -ne 4 ]; then mi_warn "bringup: mi_bringup_recover needs <index> <container> <netid> <alias>"; return 1; fi
  # shellcheck disable=SC2034   # <index> is part of the recovery signature every caller passes; the
  # live verification it feeds is the reconciler's step, not this one's — see mi_bringup_reconcile.
  local idx="$1" c="$2" netid="$3" alias="$4" rec nonce rc

  if rec="$(mi_intent_find container "$c")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  nonce="$(mi_led_field "$rec" nonce)" || return 1

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
