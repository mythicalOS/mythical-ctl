#!/usr/bin/env bash
# §7.3's exit-code contract. Four codes, and an aggregate for a multi-product batch.
#
# This is a PUBLIC contract: automation branches on these numbers, and §10a asserts each branch and
# each mixed batch outcome. "A non-alarming exit" is not implementable — exit 0 tells a script the
# install SUCCEEDED and the product is now running, which is false for a pre-launch product and will
# be acted on; exit 1 makes a normal pre-launch state indistinguishable from a real failure, so a
# wrapper cannot tell "not yet released" from "your registry is down".
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_EX_OK=0            # the requested operation completed
MI_EX_FAIL=1          # operational failure — it was attempted and did not succeed
# shellcheck disable=SC2034   # read by bin/mythical-ctl; CI lints each lib/*.sh alone and cannot see it
MI_EX_USAGE=2         # the invocation was wrong; NOTHING was attempted
MI_EX_NOTLAUNCHED=3   # a recognised, expected state; no product runtime or config objects created

mi_ex_name() {
  case "${1:-}" in
    0) printf 'completed\n' ;;
    1) printf 'failed\n' ;;
    2) printf 'usage error\n' ;;
    3) printf 'not launched yet\n' ;;
    *) printf 'unknown exit code %s\n' "${1:-}" ;;
  esac
}

# Aggregate per-product outcomes, WORST WINS (§7.3):
#
#   every product succeeded                        → 0
#   some succeeded, some not-launched, no failures → 3
#   any product failed operationally               → 1
#
# So 0 means EVERYTHING you asked for is running — a caller can branch on it without inspecting
# anything else. 3 means nothing went wrong but you did not get everything. 1 means something
# genuinely failed even if other products installed fine.
#
# Usage (2) is deliberately NOT aggregatable, and that is not pedantry: usage means nothing was
# attempted, so it cannot be one product's outcome inside a batch that attempted others. A caller
# passing it has a bug, and mapping it silently onto 1 would hide the bug and misreport the batch.
#
# EVERY argument is validated before anything is aggregated, and the loop below therefore never
# returns early on a `1`. An earlier version did — `1` is the worst code, so there was nothing left
# to learn — and the shortcut made both refusals above depend on POSITION:
#
#   mi_ex_worst 2 1  → refused, as intended
#   mi_ex_worst 1 2  → printed 1, exit 0        the forbidden code never looked at
#   mi_ex_worst 1 7  → printed 1, exit 0        the undefined code never looked at
#
# Which is the precise failure the refusals were written to prevent, arriving through the door they
# were meant to close: a caller's bug answered with a plausible-looking batch result instead of a
# complaint. Scanning the whole list costs one pass over a handful of integers; agreeing with a
# malformed call costs the caller the bug.
mi_ex_worst() {
  if [ "$#" -eq 0 ]; then
    mi_warn "exit: mi_ex_worst needs at least one per-product outcome"
    return 1
  fi
  local c saw1=0 saw3=0
  for c in "$@"; do
    case "$c" in
      0) : ;;
      1) saw1=1 ;;
      3) saw3=1 ;;
      2) mi_warn "exit: usage errors are not batch outcomes — nothing was attempted for one product"
         return 1 ;;
      *) mi_warn "exit: '$c' is not an exit code this contract defines"
         return 1 ;;
    esac
  done
  if [ "$saw1" -eq 1 ]; then printf '%s\n' "$MI_EX_FAIL"
  elif [ "$saw3" -eq 1 ]; then printf '%s\n' "$MI_EX_NOTLAUNCHED"
  else printf '%s\n' "$MI_EX_OK"; fi
}
