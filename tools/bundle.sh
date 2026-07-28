#!/usr/bin/env bash
# Build the RELEASE artifact: a single self-contained mythical-ctl.
#
# The installed layout is exactly one file — ~/.mythical/bin/mythical-ctl. There is deliberately no
# installed lib/ directory: one artifact means one digest means one attestation, and an entrypoint
# that sources from a directory on disk is an arbitrary-code-execution surface at every later run.
# So the modules are inlined here, at release time, into the entrypoint's sentinel-delimited region.
#
# Deterministic by construction: same inputs, byte-identical output. No timestamps, no hostnames,
# no build counters, no randomness — a reproducible artifact is what makes a published digest
# checkable by someone who was not there when it was built.
#
# Usage: tools/bundle.sh [OUTFILE]          (default: dist/mythical-ctl)

set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${_HERE}/.." && pwd)"

SRC="${ROOT}/bin/mythical-ctl"
LIBDIR="${ROOT}/lib"
OUT="${1:-${ROOT}/dist/mythical-ctl}"

BEGIN='# >>> mctl:modules >>>'
END='# <<< mctl:modules <<<'

# Explicit, ordered dependency list. Order is load order — `common` defines the primitives the rest
# call, so alphabetical or glob order would be a latent bug the day a module runs code at load time.
MODULES=(common layout lock ledger)

die() { printf 'bundle: %s\n' "$*" >&2; exit 1; }

# Same probe as the CLI itself: sha256sum (Linux) or shasum -a 256 (macOS).
digest() {
  local f="$1" out
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum "$f")"     || die "sha256sum failed for '$f'"
  elif command -v shasum >/dev/null 2>&1; then
    out="$(shasum -a 256 "$f")" || die "shasum failed for '$f'"
  else
    die "no sha256 implementation found (need sha256sum or shasum)"
  fi
  printf '%s\n' "${out%% *}"
}

[ -f "$SRC" ]  || die "entrypoint not found: $SRC"
[ -d "$LIBDIR" ] || die "library directory not found: $LIBDIR"

# --- completeness gate -------------------------------------------------------------------------
# The failure this exists to prevent: someone adds lib/foo.sh, wires it into the entrypoint's dev
# loop, ships a release — and the bundler silently drops it, because MODULES was never updated. The
# artifact then breaks in a way no repo-mode test can see. So the declared list and the actual
# lib/*.sh set must agree EXACTLY, in both directions, or the build stops here.
declared="$(printf '%s\n' "${MODULES[@]}" | LC_ALL=C sort)"

actual=""
for f in "$LIBDIR"/*.sh; do
  # An unmatched glob leaves the pattern itself; anything else is a REAL directory entry — including
  # a DANGLING SYMLINK, for which `-e` is false because it follows the link. Skipping on `-e` alone
  # (and worse, `break`ing) abandoned the rest of the scan, so every module sorting after the broken
  # entry vanished from `actual`, the lists compared equal, and the build silently dropped real code:
  # exactly the failure this gate exists to prevent. Detect the unmatched glob explicitly, and treat
  # anything that is not a readable regular file as a hard error rather than a skip.
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then
    continue                     # unmatched glob: no modules on disk at all
  fi
  [ -f "$f" ] && [ -r "$f" ] || die "lib entry is not a readable regular file (dangling symlink?): $f"
  b="$(basename "$f")"
  actual="${actual}${b%.sh}"$'\n'
done
actual="$(printf '%s' "$actual" | LC_ALL=C sort)"

if [ "$declared" != "$actual" ]; then
  # Name the offenders explicitly — "lists differ" sends the reader back to diffing by hand.
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    case $'\n'"${declared}"$'\n' in
      *$'\n'"${m}"$'\n'*) ;;
      *) printf 'bundle: lib/%s.sh exists but is NOT listed in MODULES — add it (in dependency order) or delete it\n' "$m" >&2 ;;
    esac
  done <<< "$actual"
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    case $'\n'"${actual}"$'\n' in
      *$'\n'"${m}"$'\n'*) ;;
      *) printf 'bundle: MODULES lists "%s" but lib/%s.sh does not exist\n' "$m" "$m" >&2 ;;
    esac
  done <<< "$declared"
  die "module list is incomplete — refusing to build a release artifact that would silently drop code"
fi

# --- sentinel gate -----------------------------------------------------------------------------
# Exactly one of each, or the replacement below would be ambiguous: two BEGINs and we would not know
# which region is the real one; zero and we would ship the dev loader with no ../lib beside it.
n_begin="$(grep -c -F -x -- "$BEGIN" "$SRC" || true)"
n_end="$(grep -c -F -x -- "$END" "$SRC" || true)"
[ "$n_begin" = "1" ] || die "expected exactly 1 '${BEGIN}' line in ${SRC}, found ${n_begin}"
[ "$n_end" = "1" ]   || die "expected exactly 1 '${END}' line in ${SRC}, found ${n_end}"

begin_ln="$(grep -n -F -x -- "$BEGIN" "$SRC" | cut -d: -f1)"
end_ln="$(grep -n -F -x -- "$END" "$SRC" | cut -d: -f1)"
[ "$begin_ln" -lt "$end_ln" ] || die "module sentinels are out of order in ${SRC} (begin=${begin_ln} end=${end_ln})"

# --- build -------------------------------------------------------------------------------------
mkdir -p "$(dirname "$OUT")" || die "cannot create output directory for '$OUT'"

tmp="${OUT}.tmp.$$"
# shellcheck disable=SC2064   # expand $tmp now: the trap must name this build's temp, not a later one
trap 'rm -f "$tmp"' EXIT

{
  # everything before the region
  sed -n "1,$((begin_ln - 1))p" "$SRC"

  # the region, replaced: provenance first, then the modules inlined verbatim
  printf '# --- inlined libraries (built by tools/bundle.sh) ---------------------------------\n'
  printf '# This file is GENERATED. Edit bin/mythical-ctl and lib/*.sh in the repository, then\n'
  printf '# rebuild — changes made here are lost on the next release build.\n'
  printf '#\n'
  printf '# Inlined modules, in load order, with the sha256 of each source file:\n'
  for m in "${MODULES[@]}"; do
    f="${LIBDIR}/${m}.sh"
    [ -f "$f" ] || die "module '${m}' listed in MODULES but lib/${m}.sh does not exist"
    printf '#   lib/%s.sh  sha256=%s\n' "$m" "$(digest "$f")"
  done
  printf '# ---------------------------------------------------------------------------------\n'

  for m in "${MODULES[@]}"; do
    f="${LIBDIR}/${m}.sh"
    printf '\n# ===== lib/%s.sh =====\n' "$m"
    # Verbatim, minus the module's own `#!/usr/bin/env bash` — a shebang mid-file is just a comment,
    # but leaving four of them in would invite the reader to think this file has four entry points.
    if IFS= read -r first < "$f" && [ "$first" = "#!/usr/bin/env bash" ]; then
      tail -n +2 "$f"
    else
      cat "$f"
    fi
  done
  printf '\n'

  # everything after the region
  sed -n "$((end_ln + 1)),\$p" "$SRC"
} > "$tmp"

chmod 755 "$tmp"
mv "$tmp" "$OUT"
trap - EXIT

printf '%s\n' "$OUT"
printf 'sha256=%s\n' "$(digest "$OUT")"
