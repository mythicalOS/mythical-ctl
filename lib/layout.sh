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
mi_zone() {
  local p="$1"
  case "$p" in
    .state/*)                              printf 'installer-state\n'   ;;
    bin|bin/*)                             printf 'installer-managed\n' ;;
    transcripts|transcripts/*|logs|logs/*) printf 'user-data\n'        ;;
    */*)                                   printf 'installer-managed\n' ;;  # any other nested path = generated artifacts (brokkr/compose.yaml, brokkr/generated.conf)
    mythical.conf|*.conf)                  printf 'user-owned\n'        ;;  # top-level confs only (no slash reaches here)
    *)                                     printf 'unknown\n'           ;;
  esac
}
