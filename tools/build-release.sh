#!/usr/bin/env bash
#
# build-release.sh — build the published artifacts, deterministically, and refuse to hand back
# anything that cannot be shown to be what it claims.
#
# Usage: tools/build-release.sh [--repro] <version> [OUTDIR]
#
#   <version>   the version to stamp, WITHOUT a leading "v" (e.g. 0.2.1, 0.2.1-rc1)
#   OUTDIR      where the artifacts land (default: <repo>/dist)
#   --repro     also build the whole matrix a SECOND time, from a copy of the source at a
#               different absolute path and with an empty build cache, and require every
#               artifact to be byte-identical
#
# WHAT REPRODUCIBLE MEANS HERE, AND WHY IT IS CHECKED RATHER THAN CLAIMED. The same source at
# the same commit must produce the same bytes on a different machine, so that a published
# SHA-256 is something a stranger can re-derive rather than something they have to trust. Every
# ingredient of that is a flag below, and every flag below is asserted afterwards from the
# artifact itself — a release process whose reproducibility is asserted in a comment and never
# exercised is indistinguishable from one that does not have the property, right up until
# somebody tries to reproduce a build and cannot.
#
#   CGO_ENABLED=0   no host toolchain, no host libc, no linker-dependent bytes; also what makes
#                   the artifact a single static file with no runtime to install
#   -trimpath       source paths become module-relative, so the builder's home directory,
#                   checkout location and module cache do not travel inside the binary
#   -buildvcs=false no commit hash, no commit time, no dirty flag — a VCS stamp is a timestamp
#                   with extra steps, and it makes a build from an exported tree differ from a
#                   build from a checkout of the same source. MEASURED: removing this flag makes
#                   all four targets differ between the two builds of the --repro check — but
#                   only in a checkout whose .git is a real directory. Where .git is a FILE (a
#                   linked worktree, a submodule) the go command recognises no VCS at all and
#                   stamps nothing even under -buildvcs=true, so that flavour of checkout cannot
#                   demonstrate the flag either way. CI clones normally, and does.
#   -ldflags -s -w  strip the symbol table and DWARF; smaller, and nothing in them is contract
#   -X ...Version=  the version stamp — see the note on the linker's silence below
#   GOTOOLCHAIN     pinned: two Go releases do not emit the same bytes, so "same source" is only
#                   half of "same output"
#
# THE LINKER IS SILENT ABOUT A -X THAT DOES NOTHING. `-X some/wrong/path.Version=1.2.3` builds
# without a word and ships the compiled-in default (measured). That is the same shape of
# accident as a build argument that resolves to the empty string, which this family has already
# shipped once: the gate goes green, the artifact reports the wrong thing, and nothing says so.
# So the stamp is never assumed to have worked — release-verify executes the host artifact and
# requires the exact line, and requires the version string to be physically present in the
# artifacts it cannot execute.
#
# The grading is deliberately a SEPARATE program (tools/release-verify), reading the files
# rather than the commands that made them, and it owns the platform list this script loops
# over. See its header.

set -euo pipefail

_HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(CDPATH='' cd -- "${_HERE}/.." && pwd)"

# The pinned toolchain. It is duplicated in .github/workflows/ci.yml's go job, which is the
# only other place that pins one, so a drift between them is refused below rather than left to
# produce two different "reproducible" answers.
PIN_GOTOOLCHAIN='go1.26.5'

VERSION_SYMBOL='mythicalos.ai/ctl/internal/version.Version'
VERIFIER='./tools/release-verify'

die() {
  printf 'build-release: ERROR: %s\n' "$*" >&2
  exit 1
}
step() { printf '\n=== %s ===\n' "$*"; }

REPRO=0
if [ "${1:-}" = '--repro' ]; then
  REPRO=1
  shift
fi

# An ARGUMENT, not an environment variable. A stamp read from the environment is exactly the
# thing that goes empty without anybody noticing; a missing argument cannot.
[ "$#" -ge 1 ] || die "usage: tools/build-release.sh [--repro] <version> [OUTDIR]"
[ "$#" -le 2 ] || die "too many arguments; usage: tools/build-release.sh [--repro] <version> [OUTDIR]"
VERSION="$1"
OUT="${2:-${ROOT}/dist}"

[ -n "$VERSION" ] || die "the version argument is empty — refusing to stamp an artifact with nothing"

if [ -n "${GOTOOLCHAIN:-}" ] && [ "${GOTOOLCHAIN}" != "$PIN_GOTOOLCHAIN" ]; then
  die "GOTOOLCHAIN is ${GOTOOLCHAIN}, but the release pin is ${PIN_GOTOOLCHAIN}.
   Two toolchains do not produce the same bytes, so this would publish an artifact nobody else
   can reproduce. Change the pin here and in the CI go job together, in one commit."
fi

# GOFLAGS/GOENV are owned by this invocation: an inherited -tags or -mod selection would change
# what gets compiled into a published artifact without appearing anywhere in this script.
export GOTOOLCHAIN="$PIN_GOTOOLCHAIN"
export GOFLAGS=''
export GOENV=off
export CGO_ENABLED=0

cd "$ROOT"

step "toolchain"
go version

step "targets"
# release-verify owns the matrix; this loop consumes it. An empty list would build nothing and
# say nothing, so it is refused here rather than diagnosed three steps later.
TARGETS="$(go run "$VERIFIER" targets)"
[ -n "$TARGETS" ] || die "release-verify listed no targets"
printf '%s\n' "$TARGETS"

build_matrix() { # build_matrix <outdir>
  local outdir="$1" target goos goarch artifact
  mkdir -p "$outdir"
  while read -r target; do
    [ -n "$target" ] || continue
    goos="${target%/*}"
    goarch="${target#*/}"
    artifact="${outdir}/mythical-ctl_${goos}_${goarch}"
    # Remove first. If a build fails, `set -e` stops us — but a file left over from an earlier
    # run would otherwise be graded as if this run had produced it.
    rm -f "$artifact"
    printf '  %s\n' "$target"
    GOOS="$goos" GOARCH="$goarch" go build \
      -trimpath \
      -buildvcs=false \
      -ldflags "-s -w -X ${VERSION_SYMBOL}=${VERSION}" \
      -o "$artifact" \
      ./cmd/mythical-ctl
  done <<< "$TARGETS"
}

write_sums() { # write_sums <outdir>
  local outdir="$1" target
  local names=()
  # The names come from the SAME target list the build loop used, never from a glob of the
  # directory: a glob would happily checksum a stray file, and would silently shrink if a
  # target were missing -- which is the one thing the checksum file must not be able to do.
  while read -r target; do
    [ -n "$target" ] || continue
    names+=( "mythical-ctl_${target%/*}_${target#*/}" )
  done <<< "$TARGETS"
  [ "${#names[@]}" -gt 0 ] || die "no artifacts to checksum in ${outdir}"
  # Written by the standard tool, in the standard format, so `sha256sum -c SHA256SUMS` in the
  # download directory is the verification a consumer actually runs. release-verify then
  # recomputes every digest with crypto/sha256 - two independent implementations, which is the
  # only arrangement in which comparing them means anything.
  if command -v sha256sum > /dev/null 2>&1; then
    ( cd "$outdir" && rm -f SHA256SUMS && sha256sum "${names[@]}" > SHA256SUMS )
  elif command -v shasum > /dev/null 2>&1; then
    ( cd "$outdir" && rm -f SHA256SUMS && shasum -a 256 "${names[@]}" > SHA256SUMS )
  else
    die "neither sha256sum nor shasum is available; the checksum file cannot be written by an implementation independent of the verifier"
  fi
}


step "build"
rm -f "${OUT}/SHA256SUMS"
build_matrix "$OUT"
write_sums "$OUT"

step "verify"
# The forbidden set is the build environment itself: if any of these strings survives into an
# artifact, the binary is not path-independent and two machines cannot agree on its digest.
# ROOT is always present, so the list can never end up empty -- release-verify refuses an empty
# --forbid set outright, because a scan with nothing to look for passes without reading a byte.
FORBID=( --forbid "$ROOT" )
for value in "${HOME:-}" "$(go env GOMODCACHE)" "$(go env GOCACHE)" "$(go env GOROOT)"; do
  # An unset HOME or an empty `go env` answer must not become an empty --forbid entry: that
  # would match everything and turn a targeted scan into an unconditional refusal.
  if [ -n "$value" ] && [ "$value" != '/' ]; then
    FORBID+=( --forbid "$value" )
  fi
done
go run "$VERIFIER" verify --dir "$OUT" --version "$VERSION" "${FORBID[@]}"
printf '\nartifacts: %s\n' "$OUT"
cat "${OUT}/SHA256SUMS"

if [ "$REPRO" -eq 0 ]; then
  exit 0
fi

step "reproducibility (second build, different source path, cold cache)"
# The second build is moved on the two axes that actually break reproducibility in Go: the
# absolute path of the source tree (what -trimpath exists to neutralise — without it these two
# builds differ, measured) and the build cache (empty, so every object is recompiled rather
# than read back from the first build's cache; a comparison that a warm cache could satisfy
# would prove nothing about the compiler).
TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/mctl-repro.XXXXXX")"
# shellcheck disable=SC2317  # invoked via trap
cleanup() { [ -n "${TMPROOT:-}" ] && rm -rf "$TMPROOT"; }
trap cleanup EXIT

ALTSRC="${TMPROOT}/an-alternate-and-differently-named-source-root"
ALTOUT="${TMPROOT}/out"
mkdir -p "$ALTSRC" "$ALTOUT"
# Only what ./cmd/mythical-ctl needs to compile. Copied, not symlinked: a symlink would leave
# the compiler reading the original path and defeat the whole point of moving it.
tar -cf - go.mod go.sum cmd internal | ( cd "$ALTSRC" && tar -xf - )

(
  cd "$ALTSRC"
  export GOCACHE="${TMPROOT}/gocache"
  build_matrix "$ALTOUT"
)

go run "$VERIFIER" compare "$OUT" "$ALTOUT"
printf '\nreproducible: every target is byte-identical across two independent builds\n'
