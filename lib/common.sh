#!/usr/bin/env bash
# Shared leaf: logging and the digest primitive. Sourced by every module.
# PURE library — no side effects at source time beyond function definitions. In particular it does
# NOT run `set -euo pipefail`: that would flip the sourcing shell (tests, bats, any consumer) into
# strict mode. Strict mode is the ENTRYPOINT's job (bin/mythical-ctl sets it once); every function
# here is written to be correct with or without ambient errexit.

mi_log()  { printf '%s\n' "$*"; }
mi_warn() { printf '%s\n' "$*" >&2; }
mi_die()  { printf '%s\n' "$*" >&2; exit 1; }

# Print the sha256 hex of a file. Floor: sha256sum (Linux) or shasum -a 256 (macOS).
mi_digest() {
  local f="$1" out
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum "$f")"    || mi_die "mi_digest: sha256sum failed for '$f'"
  elif command -v shasum >/dev/null 2>&1; then
    out="$(shasum -a 256 "$f")" || mi_die "mi_digest: shasum failed for '$f'"
  else
    mi_die "no sha256 implementation found (need sha256sum or shasum)"
  fi
  printf '%s\n' "${out%% *}"
}
