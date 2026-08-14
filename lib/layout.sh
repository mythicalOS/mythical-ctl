#!/usr/bin/env bash
# The ~/.mythical/ family home (D1) and its ownership zones (§6c). Non-destructive (D9).

mi_home() { printf '%s\n' "${MYTHICAL_HOME:-$HOME/.mythical}"; }

# Create only what is missing. Never touch user data. Idempotent.
mi_ensure_layout() {
  local h; h="$(mi_home)"
  local d
  for d in bin .state; do
    [ -d "$h/$d" ] || mkdir -p "$h/$d" || mi_die "cannot create $h/$d"
  done
  # transcripts/ and logs/ are user-data (MYTHICAL_HOME's original meaning): never created here,
  # never removed here. They appear when a product binds them.
  return 0
}

# Classify a home-relative path into its §6c ownership class. Deletion/backup rules key on this.
# Order matters: bash `case` globs match slashes, so every NESTED path must be decided before the
# top-level `*.conf` rule — otherwise `brokkr/generated.conf` would fall into `*.conf` (user-owned)
# and cross the flat/nested boundary. The `*/*` arm therefore sits above `*.conf`.
#
# THE HOST-TOOL SLOT (docs/CONFIG-FORMAT.md, "Amendment: the host-tool slot") is the one leaf carved
# out of the installer-managed product directory: `<product>/cli.toml` is where a product's HOST-SIDE
# tool keeps its own configuration, including host-only credentials, and it is `user-owned` — the
# installer never creates, reads, writes or removes it. It is not `<product>.conf`, because that file
# is bind-mounted into the product's container read-write, which is the last place a host-only bearer
# token may live.
#
# THREE ARMS, NOT ONE, AND THE FIRST TWO ARE GUARDS. `case` globs match slashes, so a lone
# `*/cli.toml` would also capture `brokkr/generated/cli.toml` (a generated artifact) and
# `../cli.toml` (not even inside the home) — both of them landing in the one class the installer
# promises never to touch. `*/*/*` therefore decides everything two or more separators deep FIRST,
# leaving the slot arm reachable only by a path with exactly one separator; `mythical/cli.toml` is
# refused by name; and `[a-z]` on the leading component rejects `.`, `..`, `/`, and every component
# that could not begin a legal product name. All three keep the class every pre-existing path
# already had, which is why they can sit above `*/*` safely.
#
# The classifier answers about a path's SHAPE, and it stops SHORT of the full product-name grammar
# on purpose: it refuses a leading component that could not begin a legal name, and it refuses the
# RESERVED name outright, but it does not re-implement the rest. A path classifier holding a second,
# drifting copy of what a product is would be worse than one that admits its limit;
# `_mi_conf_product_name_ok` in lib/config.sh is the authority, and a caller deciding about a real
# directory calls it (lib/prov.sh's first-use sweep does). What survives is a small overmatch in the
# safe direction — `fooBAR/cli.toml` reads as user-owned — and preserving one file too many is the
# error this installer is built to make.
#
# `LC_ALL=C` IS LOAD-BEARING ON THE ONE RANGE BELOW, and it is not decoration. Under a non-C
# collation `[a-z]` matches uppercase: measured here on bash 3.2 under da_DK.UTF-8, `case Brokkr in
# [a-z]*)` MATCHES, so without this the same path classifies differently on an operator's laptop
# than in CI. Scoped `local` so nothing else in the process is affected.
mi_zone() {
  local p="$1"
  local LC_ALL=C
  case "$p" in
    .state/*)                              printf 'installer-state\n'   ;;
    bin|bin/*)                             printf 'installer-managed\n' ;;
    transcripts|transcripts/*|logs|logs/*) printf 'user-data\n'        ;;
    */*/*)                                 printf 'installer-managed\n' ;;  # 2+ separators: never the slot, always generated
    mythical/cli.toml)                     printf 'installer-managed\n' ;;  # `mythical` is RESERVED — never a product directory
    [a-z]*/cli.toml)                       printf 'user-owned\n'        ;;  # the host-tool slot, one level down, under a name that could begin a legal product
    */*)                                   printf 'installer-managed\n' ;;  # any other nested path = generated artifacts (brokkr/compose.yaml, brokkr/generated.conf)
    mythical.conf|*.conf)                  printf 'user-owned\n'        ;;  # top-level confs only (no slash reaches here)
    *)                                     printf 'unknown\n'           ;;
  esac
}
