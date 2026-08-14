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
# THE SLOT ARM IS A CANDIDATE FILTER, NOT THE DECISION. `case` globs match slashes, so `*/cli.toml`
# also catches `brokkr/generated/cli.toml` (a generated artifact) and `../cli.toml` (not even inside
# the home). Neither may end up in the one class the installer promises never to touch, and neither
# does: the arm's body re-checks the leaf exactly and puts the leading component to the product-name
# grammar, and anything that fails either falls out as `installer-managed` — the class it carried
# before this carve-out existed. The arm sits above `*/*` only to be given the chance to ask.
#
# THE SLOT'S LEADING COMPONENT IS A LEGAL PRODUCT NAME OR IT IS NOT THE SLOT, and the grammar is
# ASKED OF ITS ONE AUTHORITY rather than re-implemented here. An earlier revision stopped at the
# first character (`[a-z]`) and documented the rest as an accepted overmatch; `fooBAR/cli.toml`,
# `foo bar/cli.toml` and an over-long name all read as user-owned, which is a class no path outside
# the carve-out is entitled to. Copying the grammar into this file instead would leave the layout
# holding a second version of it to drift against, which is why the call is made rather than the
# rules restated.
#
# IT FAILS CLOSED WHEN THE AUTHORITY IS NOT LOADED. `mi_zone` lives in a module that is sourced
# before lib/config.sh, and a caller may have sourced this file alone; if the validator is absent the
# answer is `installer-managed` — exactly the class the path carried before the carve-out existed —
# so an unanswerable question yields the unprivileged class instead of silently granting the
# privileged one.
#
# THERE IS NO `LC_ALL=C` HERE, AND NO `[a-z]` PRE-FILTER, DELIBERATELY. Both were here and both were
# measured to be MASKED: with the grammar behind them, loosening the glob to `[!.]*` or dropping the
# locale pin changed no answer this function gives, so nothing would have caught either being lost.
# The one character range that decides anything lives in `_mi_conf_product_name_ok`, which pins its
# own `LC_ALL=C` — a range under a dictionary collation matches uppercase, and that is where the
# guard belongs and where a test can still kill it. A guard no input reaches is not defence in
# depth; it is a line that looks like protection and is not.
#
# `nocasematch` IS REACHABLE FROM THE ENVIRONMENT, and an earlier revision of this comment said it
# was not. MEASURED: `BASHOPTS=nocasematch` does NOT arm it, which is what that claim was based on —
# but `BASH_ENV=<file>` naming a file that runs `shopt -s nocasematch` DOES, for every
# non-interactive bash, this CLI included. Both halves of this arm are defended against it: the leaf
# by a string comparison, the name by unsetting the option around the validator call.
#
# THAT IS THIS ARM ONLY. The option still changes how every other `case` in the CLI matches — the
# ledger's field parsing, the config scanner, the document readers — which is a pre-existing,
# codebase-wide exposure this amendment neither introduces nor closes. Recorded here because the
# measurement was made here.
#
# `LC_ALL=C` IS LOAD-BEARING ON THE ONE RANGE BELOW, and it is not decoration. Under a non-C
# collation `[a-z]` matches uppercase: measured here on bash 3.2 under da_DK.UTF-8, `case Brokkr in
# [a-z]*)` MATCHES, so without this the same path classifies differently on an operator's laptop
# than in CI. Scoped `local` so nothing else in the process is affected.
mi_zone() {
  local p="$1"
  case "$p" in
    .state/*)                              printf 'installer-state\n'   ;;
    bin|bin/*)                             printf 'installer-managed\n' ;;
    transcripts|transcripts/*|logs|logs/*) printf 'user-data\n'        ;;
    */cli.toml)                                                             # candidate slot — the LEAF is re-checked exactly, then the NAME decides
      # THE LEAF IS COMPARED WITH `=`, NOT LEFT TO THE GLOB THAT GOT US HERE, and that one comparison
      # carries two rules at once.
      #
      # CASE. `case` honours `nocasematch`, so with a caller having enabled it `brokkr/CLI.TOML`
      # reaches this arm — and a generated artifact would take the one class that says the installer
      # does not own it. Measured: a string comparison is unaffected by the option, a `case` glob is.
      #
      # DEPTH. `${p#*/}` strips only as far as the FIRST separator, so for anything deeper than one
      # level the remainder still contains a `/` and can never equal the reserved name:
      # `brokkr/generated/cli.toml` yields `generated/cli.toml` and is refused here. A separate
      # `*/*/*` arm used to sit above this and say the same thing; it was measured to be MASKED once
      # this comparison existed — no input reached a different answer through it — so it is gone
      # rather than left looking like the thing that enforces depth. This is that thing.
      # THE VALIDATOR IS CALLED WITH `nocasematch` OFF, in a subshell, because the option changes how
      # ITS `case` matches too: measured, `_mi_conf_product_name_ok Brokkr` SUCCEEDS under it, so the
      # leaf comparison alone would still let `BROKKR/cli.toml` through. The subshell is what makes
      # this arm's answer independent of a caller's shell options without reaching into a published
      # grammar the rest of the CLI depends on.
      if [ "${p#*/}" = cli.toml ] \
         && declare -F _mi_conf_product_name_ok >/dev/null 2>&1 \
         && ( shopt -u nocasematch; _mi_conf_product_name_ok "${p%%/*}" ); then
        printf 'user-owned\n'
      else
        printf 'installer-managed\n'
      fi ;;
    */*)                                   printf 'installer-managed\n' ;;  # any other nested path = generated artifacts (brokkr/compose.yaml, brokkr/generated.conf)
    mythical.conf|*.conf)                  printf 'user-owned\n'        ;;  # top-level confs only (no slash reaches here)
    *)                                     printf 'unknown\n'           ;;
  esac
}
