#!/usr/bin/env bash
#
# parity-audit.sh — prove that deleting the frozen bash tree loses nothing.
#
# Usage: tools/parity-audit.sh [--write-manifest]
#
# THE CLAIM UNDER AUDIT. Every @test in tests/unit/*.bats and tests/acceptance/*.bats is accounted
# for EXACTLY ONCE by a `// PORTED:` or `// N/A:` inventory line somewhere in the Go tree, and every
# PORTED line names a Go test that actually exists. Not "at least once": a test claimed twice
# usually means one of the two claims is wrong, and the wrong one hides behind the right one.
#
# THIS SCRIPT DRIVES THE TOOLCHAIN; tools/parity-audit GRADES. Same split as build-release.sh and
# release-verify, for the same reason: the grader reads FILES rather than the commands that made
# them, so it can be unit-tested against fixtures and its guards can be mutation-verified. All this
# half does is produce the two `go test -list` streams the grader resolves PORTED targets against —
# one per build-tag lane, because the acceptance lane's tests do not exist without its tag and a
# claim on one of them would otherwise look dangling.
#
# IT IS A check.sh STAGE, NOT A SCRIPT SOMEBODY REMEMBERS TO RUN. `bash check.sh parity`, in CI. An
# uninvoked audit protects nothing; this one is re-proved on every change.
#
# IT OUTLIVES WHAT IT AUDITS. The cutover deletes the bats trees. tests/parity-manifest.tsv is the
# corpus in committed form: while the trees exist it is regenerated and byte-compared against them,
# and once they are gone it IS the corpus. So the parity gate keeps running AFTER the deletion it
# precedes — which is the only way to know the deletion did not quietly take the evidence with it.
set -euo pipefail

cd "$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# THE GO ENVIRONMENT IS OWNED BY THIS SCRIPT, PROCESS-WIDE — NOT INVOCATION BY INVOCATION, WHICH
# IS HOW THIS AUDIT WAS ONCE DISARMED IN ONE ENVIRONMENT VARIABLE.
#
# The four witness commands below used to carry `GOFLAGS='' GOENV=off` and the `go run` that
# GRADED did not. `go run` honours GOFLAGS and GOFLAGS carries `-exec`, so
# `GOFLAGS=-exec=/usr/bin/true bash check.sh parity` built the auditor, ran /usr/bin/true instead
# of it, printed `check.sh: OK` and exited 0 — with a genuine unclaimed corpus row present, which
# the same command without that variable exits 1 on. Every missing, duplicate, malformed or
# dangling record passed that way. GOFLAGS carries `-ldflags` too, so
# `-ldflags=-X=main.manifestSHA256=<digest>` replaces the pin the auditor compares the committed
# manifest against: an edited manifest plus its new digest would have passed without the source
# pin changing. Both measured on this tree.
#
# An inherited -run or -tags is the milder version of the same thing and the original reason the
# witnesses were guarded: it changes which tests are listed, and a SHORTER list makes PORTED
# targets look dangling — a red for a reason that has nothing to do with the port.
#
# GOFLAGS='' IS NOT ENOUGH ON ITS OWN. Go treats an EMPTY environment variable as UNSET and falls
# back to the go env FILE (measured: with GOFLAGS='' exported and a file setting GOFLAGS,
# `go env GOFLAGS` reports the FILE's value), so GOENV=off is the half that closes the file
# channel. GOWORK=off is the same shape again — a `go.work` in an ancestor directory is picked up
# without being asked, and its `replace` directives choose which copy of a dependency ends up
# inside the grader. `bash check.sh selfcheck` probes both channels against this script.
export GOFLAGS=''
export GOENV=off
export GOWORK=off

if [ "${1:-}" = "--write-manifest" ]; then
  # Guarded by the export block above, like every other `go` invocation in this file.
  exec go run ./tools/parity-audit --write-manifest
fi

if [ $# -gt 0 ]; then
  printf 'parity-audit.sh: unknown argument: %s (want nothing, or --write-manifest)\n' "$1" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/mctl-parity.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

go test -list '.*' ./... > "$TMP/list-default.txt"
go test -tags acceptance -list '.*' ./... > "$TMP/list-acceptance.txt"

# THE SECOND WITNESS, PER LANE, AND IT IS THE TOOLCHAIN'S OWN FILE SELECTION.
#
# The grader used to build its source witness by WALKING every *_test.go on disk with build
# constraints deliberately not applied. Paired with a list witness that reads unstructured stdout,
# the two could agree about a test no lane runs: a file tagged out of every lane declaring
# TestClaimed, and an active init() that merely PRINTS "TestClaimed". TestGoFiles/XTestGoFiles are
# the files go itself compiles for THIS lane after applying its tags, so the source half can no
# longer testify about a file the lane does not build.
#
# GoFiles RIDES ALONG FOR A SECOND REASON, and it is the one the grader cares about more: this same
# stream is what tells it WHICH FILES MAY CARRY A CLAIM. Claim discovery used to be a filesystem
# walk that read bytes, so a claim moved into a testdata directory — or behind a build constraint no
# lane satisfies — was credited to a row while describing nothing that runs. Demonstrated end to end
# with a file that was not even valid Go. The claim-bearing set is now exactly what go compiles:
# GoFiles + TestGoFiles + XTestGoFiles, unioned across the lanes.
FILE_TMPL='{{.ImportPath}}	{{.Dir}}	{{join .GoFiles " "}}	{{join .TestGoFiles " "}}	{{join .XTestGoFiles " "}}'
go list -f "$FILE_TMPL" ./... > "$TMP/files-default.txt"
go list -tags acceptance -f "$FILE_TMPL" ./... > "$TMP/files-acceptance.txt"

# PAIRED, AND IN THE SAME ORDER. The grader refuses a mismatched count rather than pairing by luck.
go run ./tools/parity-audit \
  --go-list "$TMP/list-default.txt" --go-files "$TMP/files-default.txt" \
  --go-list "$TMP/list-acceptance.txt" --go-files "$TMP/files-acceptance.txt"
