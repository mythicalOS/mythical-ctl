load '../lib/test_helper'

@test "harness runs and MYTHICAL_HOME is isolated" {
  [ -d "$MYTHICAL_HOME" ]
  run_mctl --version
  assert_ok
  assert_contains "mythical-ctl"
}

@test "__selftest asserts the whole library surface is present" {
  # Runs the entrypoint (under its own `set -euo pipefail`) and checks that every shipped library
  # function is actually defined after the module-load region ran. The same assertion holds for the
  # release bundle, where the modules are inlined and "did it source" has no answer.
  run_mctl __selftest
  assert_ok
  assert_contains "ok"
}

@test "mi_ensure_layout creates the managed subtree, idempotently" {
  load_mctl
  mi_ensure_layout
  [ -d "$MYTHICAL_HOME/bin" ]
  [ -d "$MYTHICAL_HOME/.state" ]
  # second run must not error and must not change what exists
  local before; before="$(cd "$MYTHICAL_HOME" && find . | sort)"
  mi_ensure_layout
  local after;  after="$(cd "$MYTHICAL_HOME" && find . | sort)"
  [ "$before" = "$after" ]
}

@test "mi_ensure_layout never touches transcripts or logs" {
  load_mctl
  mkdir -p "$MYTHICAL_HOME/transcripts"
  echo secret > "$MYTHICAL_HOME/transcripts/keep"
  mi_ensure_layout
  [ "$(cat "$MYTHICAL_HOME/transcripts/keep")" = secret ]
}

@test "mi_zone classifies paths by ownership class" {
  load_mctl
  [ "$(mi_zone bin/mythical-ctl)"        = installer-managed ]
  [ "$(mi_zone .state/ledger)"           = installer-state ]
  [ "$(mi_zone brokkr.conf)"             = user-owned ]
  [ "$(mi_zone mythical.conf)"           = user-owned ]
  [ "$(mi_zone transcripts/x.jsonl)"     = user-data ]
  [ "$(mi_zone logs/sessions/y)"         = user-data ]
  [ "$(mi_zone brokkr/compose.yaml)"     = installer-managed ]
  [ "$(mi_zone brokkr/generated.conf)"   = installer-managed ]   # nested .conf is NOT user-owned
  [ "$(mi_zone something-else)"          = unknown ]
}

# --- the host-tool slot (docs/CONFIG-FORMAT.md, "Amendment: the host-tool slot") -------------------

@test "the host-tool slot is user-owned, at exactly one level under a product directory" {
  load_mctl
  [ "$(mi_zone brokkr/cli.toml)"         = user-owned ]
  [ "$(mi_zone saga/cli.toml)"           = user-owned ]
  [ "$(mi_zone a/cli.toml)"              = user-owned ]
  # DEPTH. `case` globs match slashes, so the candidate arm catches these too; what refuses them is
  # the exact leaf comparison in its body — the remainder after the FIRST separator is
  # `nested/cli.toml`, which is not the reserved name. A generated artifact must not be promoted
  # into the one class the installer promises never to touch.
  [ "$(mi_zone brokkr/nested/cli.toml)"  = installer-managed ]
  [ "$(mi_zone brokkr/a/b/cli.toml)"     = installer-managed ]
  # THE NAME IS RESERVED EXACTLY, not by prefix, suffix or extension.
  [ "$(mi_zone brokkr/cli.yaml)"         = installer-managed ]
  [ "$(mi_zone brokkr/mycli.toml)"       = installer-managed ]
  [ "$(mi_zone brokkr/cli.toml.bak)"     = installer-managed ]
  [ "$(mi_zone brokkr/cli.toml/)"        = installer-managed ]
  # Top level is not a product directory, so a bare `cli.toml` is still unclassified.
  [ "$(mi_zone cli.toml)"                = unknown ]
}

@test "a traversal spelling is not the host-tool slot, and neither is a dot-leading directory" {
  load_mctl
  # `../cli.toml` is not inside the home at all. Classifying it user-owned would put a path OUTSIDE
  # ~/.mythical/ into the class that means "the installer never touches this" — a claim about a file
  # this layout does not own. `..`, `.` and `.hidden` are refused because they are not legal product
  # names; `a/../cli.toml` and the two-slash spellings are refused by the exact leaf comparison,
  # whose remainder after the first separator still carries a `/`.
  [ "$(mi_zone ../cli.toml)"             = installer-managed ]
  [ "$(mi_zone a/../cli.toml)"           = installer-managed ]
  [ "$(mi_zone ./cli.toml)"              = installer-managed ]
  [ "$(mi_zone .hidden/cli.toml)"        = installer-managed ]
  [ "$(mi_zone /cli.toml)"               = installer-managed ]
  [ "$(mi_zone //cli.toml)"              = installer-managed ]
}

@test "the installer's own zones keep the slot's name — the carve-out is only in a product directory" {
  load_mctl
  # Each of these arms sits ABOVE the slot arm, and each must still win. If the slot arm were moved
  # up, `bin/cli.toml` would become a file the installer may not replace — inside the directory it
  # installs itself into.
  [ "$(mi_zone bin/cli.toml)"            = installer-managed ]
  [ "$(mi_zone .state/cli.toml)"         = installer-state ]
  [ "$(mi_zone transcripts/cli.toml)"    = user-data ]
  [ "$(mi_zone logs/cli.toml)"           = user-data ]
}

@test "the three product names that CANNOT carry a slot are pinned as a known limit" {
  load_mctl
  # `bin`, `logs` and `transcripts` are legal product names, yet those directories already mean
  # something else directly under the home — so their `cli.toml` is decided by the arm above and a
  # product so named gets no slot. That is documented as a limit rather than fixed here: fixing it
  # would mean changing what is a legal product NAME, which is a different contract with its own
  # published grammar and its own tests. Pinned so the limit stays a decision, and so anyone who
  # later narrows the grammar finds the two halves named in one place.
  local n
  for n in bin logs transcripts; do
    run _mi_conf_product_name_ok "$n"
    [ "$status" -eq 0 ]                     # a legal product name...
  done
  [ "$(mi_zone bin/cli.toml)"         = installer-managed ]   # ...with no slot
  [ "$(mi_zone logs/cli.toml)"        = user-data ]
  [ "$(mi_zone transcripts/cli.toml)" = user-data ]
  # Two of the three are worse than "no slot": logs/ and transcripts/ ARE core-fixed mounts, so a
  # host-side tool that followed the general rule for a product named `logs` would put its bearer
  # token inside a directory the container reads and writes — the exact outcome the slot exists to
  # prevent, reached by obeying the contract. Pinned against the mount set rather than asserted.
  run mi_mount_core_fixed brokkr
  [ "$status" -eq 0 ]
  local d
  for d in logs transcripts; do
    case "$output" in
      *"/$d"*) : ;;
      *) echo "'$d' is not a core-fixed mount any more — this test's premise is stale: $output" >&2
         return 1 ;;
    esac
  done
  # The document says all of it in as many words, so the limit is published and not merely true.
  grep -Faq 'Three product names cannot carry a slot' "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
  grep -Faq 'are bind-mounted into product containers' "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
  grep -Faq 'must not invent one' "${_MCTL_ROOT}/README.md"
}

@test "a component that could not BEGIN a legal product name is not the slot" {
  load_mctl
  # The leading component decides, and these are the ones that fail at the FIRST character.
  # `mythical` is in the list because it is RESERVED — ~/.mythical/mythical.conf is the host-only
  # family file — and the grammar refuses it by name, not by shape.
  [ "$(mi_zone mythical/cli.toml)"       = installer-managed ]
  [ "$(mi_zone Brokkr/cli.toml)"         = installer-managed ]
  [ "$(mi_zone 1foo/cli.toml)"           = installer-managed ]
  [ "$(mi_zone -foo/cli.toml)"           = installer-managed ]
  [ "$(mi_zone _foo/cli.toml)"           = installer-managed ]
  # ...and a legal-shaped one still is.
  [ "$(mi_zone brokkr/cli.toml)"         = user-owned ]
  [ "$(mi_zone a1/cli.toml)"             = user-owned ]
  [ "$(mi_zone my-product/cli.toml)"     = user-owned ]
}

@test "the slot's uppercase refusal survives a non-C collation, end to end" {
  # MEASURED on bash 3.2: under a dictionary-collating locale, `case Brokkr in [a-z]*)` MATCHES, so
  # without a pinned `LC_ALL=C` this path classifies one way on an operator's laptop and another in
  # CI — and the laptop is the one that gets it wrong. The pin lives in `_mi_conf_product_name_ok`,
  # the grammar's authority and the only place a character range still decides anything; mi_zone
  # deliberately does not carry a second one, because a copy there would be masked by this and so
  # could be lost with nothing going red. This asserts the END-TO-END property either way.
  #
  # THE LOCALE HAS TO REACH THE SHELL AT STARTUP. A prefix assignment on the function call
  # (`LC_ALL=xx mi_zone …`) does NOT re-arm collation for a `case` glob in the running shell —
  # written that way first, and the test then passed with the guard REMOVED: it could not fail. Only
  # a shell that inherits the locale in its environment exercises it, which is what this runs.
  #
  # AND THE HAZARD IS PROVEN PRESENT BEFORE THE GUARD IS ASSERTED AGAINST IT. If no installed locale
  # collates that way (a stock CI image may generate none), there is nothing here to defeat and this
  # SKIPS loudly rather than passing over a guard it never tested.
  local loc="" cand
  for cand in en_US.UTF-8 en_US.utf8 da_DK.UTF-8 da_DK.utf8 en_GB.UTF-8 de_DE.UTF-8; do
    if LC_ALL="$cand" bash -c 'case Brokkr in [a-z]*) exit 0 ;; *) exit 1 ;; esac' 2>/dev/null; then
      loc="$cand"; break
    fi
  done
  if [ -z "$loc" ]; then
    skip "no installed locale collates [a-z] over uppercase — the guard cannot be exercised here"
  fi

  run env LC_ALL="$loc" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; source "$1/lib/config.sh"; mi_zone Brokkr/cli.toml' _ "$_MCTL_ROOT"
  [ "$status" -eq 0 ]
  [ "$output" = installer-managed ] || { echo "under $loc: got '$output'" >&2; return 1; }
  # The positive case is unaffected by locale either way, asserted so a guard that simply refused
  # everything would not pass this test.
  run env LC_ALL="$loc" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; source "$1/lib/config.sh"; mi_zone brokkr/cli.toml' _ "$_MCTL_ROOT"
  [ "$output" = user-owned ] || { echo "under $loc: got '$output'" >&2; return 1; }
}

@test "the slot's leading component must satisfy the FULL product-name grammar, not just its start" {
  load_mctl
  # The cases that separate "checked the first character" from "asked the grammar's authority".
  # Every one of these was `user-owned` while the classifier stopped at `[a-z]`, and every one of
  # them is a path outside the documented carve-out.
  [ "$(mi_zone fooBAR/cli.toml)"                = installer-managed ]
  [ "$(mi_zone foo.conf/cli.toml)"              = installer-managed ]
  [ "$(mi_zone "foo bar/cli.toml")"             = installer-managed ]
  [ "$(mi_zone "foo_bar/cli.toml")"             = installer-managed ]
  [ "$(mi_zone "$(printf 'x%.0s' $(seq 1 65))/cli.toml")" = installer-managed ]
  # ...while every legal name still is the slot. Asserted so a validator that refused EVERYTHING
  # would not pass this test.
  [ "$(mi_zone brokkr/cli.toml)"                = user-owned ]
  [ "$(mi_zone a/cli.toml)"                     = user-owned ]
  [ "$(mi_zone my-product2/cli.toml)"           = user-owned ]
  [ "$(mi_zone "$(printf 'x%.0s' $(seq 1 64))/cli.toml")" = user-owned ]
  # And the classifier and the authority agree, rather than the test asserting the grammar twice.
  local n
  for n in fooBAR foo.conf foo_bar; do
    run _mi_conf_product_name_ok "$n"
    [ "$status" -ne 0 ]
  done
}

@test "the reserved leaf is exact even under nocasematch — a case glob would not be" {
  load_mctl
  # `case` honours `shopt -s nocasematch`, so with a caller having enabled it `*/cli.toml` matches
  # `brokkr/CLI.TOML` and a generated artifact takes the one class that says the installer does not
  # own it. The leaf is therefore compared with `=`, which the option does not affect. Nothing in
  # this tree sets nocasematch and it cannot be set from the environment, so a test that did not
  # enable it explicitly would never reach this.
  shopt -s nocasematch
  local got_upper got_mixed got_lower
  got_upper="$(mi_zone brokkr/CLI.TOML)"
  got_mixed="$(mi_zone brokkr/Cli.Toml)"
  got_lower="$(mi_zone brokkr/cli.toml)"
  shopt -u nocasematch
  [ "$got_upper" = installer-managed ] || { echo "CLI.TOML classified '$got_upper'" >&2; return 1; }
  [ "$got_mixed" = installer-managed ] || { echo "Cli.Toml classified '$got_mixed'" >&2; return 1; }
  # ...and the real leaf is still the slot with the option on, so this is about the NAME of the leaf
  # and not about nocasematch having broken the arm outright.
  [ "$got_lower" = user-owned ] || { echo "cli.toml classified '$got_lower'" >&2; return 1; }
}

@test "an uppercase product NAME is refused under nocasematch too — the validator is called with it off" {
  load_mctl
  # The leaf comparison above does not cover this half: `BROKKR/cli.toml` has the exact leaf, and
  # under nocasematch the grammar's own `case` accepts `BROKKR` — measured. So the validator is
  # invoked with the option unset, and this is the test that says so.
  shopt -s nocasematch
  local got authority
  got="$(mi_zone BROKKR/cli.toml)"
  # ...and the hazard is proven present rather than assumed: the bare validator DOES accept it here.
  if _mi_conf_product_name_ok BROKKR; then authority=accepts; else authority=refuses; fi
  shopt -u nocasematch
  [ "$authority" = accepts ] || skip "this bash does not case-fold the grammar under nocasematch"
  [ "$got" = installer-managed ] || { echo "BROKKR/cli.toml classified '$got'" >&2; return 1; }
}

@test "nocasematch reaching the CLI through BASH_ENV does not promote a path to the slot" {
  # The environment vector, end to end, in a shell started the way the CLI is. BASHOPTS does NOT arm
  # the option; BASH_ENV naming a file that sets it DOES, which is why the contract says so.
  printf 'shopt -s nocasematch\n' > "$BATS_TEST_TMPDIR/nc.sh"
  run env BASH_ENV="$BATS_TEST_TMPDIR/nc.sh" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; source "$1/lib/config.sh"
     shopt -q nocasematch || { echo NOT-ARMED; exit 0; }
     printf "%s %s\n" "$(mi_zone BROKKR/cli.toml)" "$(mi_zone brokkr/CLI.TOML)"' _ "$_MCTL_ROOT"
  [ "$status" -eq 0 ]
  case "$output" in
    NOT-ARMED) skip "BASH_ENV does not arm nocasematch on this bash" ;;
    "installer-managed installer-managed") : ;;
    *) echo "BASH_ENV-armed nocasematch gave: $output" >&2; return 1 ;;
  esac
}

@test "mi_zone fails CLOSED for the slot when the name authority is not loaded" {
  # mi_zone lives in a module sourced BEFORE lib/config.sh, and a caller may source this file alone.
  # An unanswerable question must yield the class the path carried before the carve-out existed,
  # never the privileged one — otherwise a partial load silently promotes a generated artifact.
  # stderr is discarded so this asserts the CLASS and not a diagnostic: the class is the contract.
  run env MYTHICAL_HOME="$MYTHICAL_HOME" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; mi_zone brokkr/cli.toml 2>/dev/null' _ "$_MCTL_ROOT"
  [ "$status" -eq 0 ]
  [ "$output" = installer-managed ] || { echo "unloaded authority gave '$output'" >&2; return 1; }
  # ...and with the authority present the very same call is the slot, so the test above is about the
  # missing module and not about the path.
  run env MYTHICAL_HOME="$MYTHICAL_HOME" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; source "$1/lib/config.sh"; mi_zone brokkr/cli.toml 2>/dev/null' _ "$_MCTL_ROOT"
  [ "$output" = user-owned ] || { echo "loaded authority gave '$output'" >&2; return 1; }
}

@test "only a shell FUNCTION may answer the name question — a program on PATH may not" {
  # This is what `declare -F` buys, and it is not the fail-closed class above: with the guard gone
  # the class is still right, because a failed call fails the `&&` chain. What changes is WHO may
  # answer. A bare call resolves through PATH, so an executable of that name — a stray build
  # artifact, a directory an operator put on PATH, anything writable and earlier — could exit 0 and
  # promote any nested `cli.toml` to the one class the installer never touches. `declare -F` asks
  # for a function and nothing else.
  local fake="$BATS_TEST_TMPDIR/fakebin"
  mkdir -p "$fake"
  printf '#!/bin/sh\nexit 0\n' > "$fake/_mi_conf_product_name_ok"
  chmod 755 "$fake/_mi_conf_product_name_ok"
  # `fooBAR` is refused by the real grammar, so a `user-owned` answer here could only have come from
  # the impostor. lib/config.sh is deliberately NOT sourced: PATH is the only candidate answerer.
  run env MYTHICAL_HOME="$MYTHICAL_HOME" PATH="$fake:$PATH" bash -c \
    'source "$1/lib/common.sh"; source "$1/lib/layout.sh"; mi_zone fooBAR/cli.toml 2>/dev/null' _ "$_MCTL_ROOT"
  [ "$output" = installer-managed ] || { echo "a program on PATH answered: '$output'" >&2; return 1; }
  # And the impostor really is reachable, or the assertion above would hold for the wrong reason.
  run env PATH="$fake:$PATH" bash -c '_mi_conf_product_name_ok anything'
  [ "$status" -eq 0 ]
}

@test "the host-tool amendment changed NO pre-existing classification" {
  load_mctl
  # Every path the zone map classified before the slot existed, asserted again where a reviewer will
  # see it. `case` matches top-down and its globs match slashes, so a new arm is precisely how a
  # pre-existing path changes class with nothing noticing.
  [ "$(mi_zone bin)"                     = installer-managed ]
  [ "$(mi_zone bin/mythical-ctl)"        = installer-managed ]
  [ "$(mi_zone bin/a/b/c)"               = installer-managed ]
  [ "$(mi_zone .state/ledger)"           = installer-state ]
  [ "$(mi_zone .state/a/b)"              = installer-state ]
  [ "$(mi_zone transcripts)"             = user-data ]
  [ "$(mi_zone transcripts/x.jsonl)"     = user-data ]
  [ "$(mi_zone logs)"                    = user-data ]
  [ "$(mi_zone logs/sessions/y)"         = user-data ]
  [ "$(mi_zone mythical.conf)"           = user-owned ]
  [ "$(mi_zone brokkr.conf)"             = user-owned ]
  [ "$(mi_zone brokkr/compose.yaml)"     = installer-managed ]
  [ "$(mi_zone brokkr/generated.conf)"   = installer-managed ]
  [ "$(mi_zone brokkr/a/b/c)"            = installer-managed ]
  [ "$(mi_zone something-else)"          = unknown ]
  [ "$(mi_zone "")"                      = unknown ]
}

@test "the host-tool slot the document publishes is the one the classifier implements" {
  load_mctl
  # The slot's spelling is a PUBLISHED contract that a host-side tool implements without reading this
  # source. A rename on one side only is silent both ways: the tool writes where the document said,
  # and the classifier calls that a generated artifact the installer may remove.
  grep -Faq '~/.mythical/<product>/cli.toml' "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
  [ "$(mi_zone brokkr/cli.toml)" = user-owned ]
}

@test "mi_ensure_layout neither creates nor disturbs a host-tool slot" {
  load_mctl
  mkdir -p "$MYTHICAL_HOME/brokkr"
  printf 'token = "host-only"\n' > "$MYTHICAL_HOME/brokkr/cli.toml"
  local before; before="$(mi_digest "$MYTHICAL_HOME/brokkr/cli.toml")"
  mi_ensure_layout
  [ "$before" = "$(mi_digest "$MYTHICAL_HOME/brokkr/cli.toml")" ]
  # And it does not invent one for a product that has no host-side tool. `-e` alone is not the test:
  # it follows a symlink and is therefore FALSE for a dangling one, so a regression that planted a
  # dangling slot would satisfy it while having created the path this asserts nothing creates.
  mi_ensure_layout
  [ ! -e "$MYTHICAL_HOME/saga/cli.toml" ]
  [ ! -L "$MYTHICAL_HOME/saga/cli.toml" ]
}

@test "mi_digest matches a known sha256" {
  load_mctl
  printf 'abc' > "$MYTHICAL_HOME/f"
  # sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  [ "$(mi_digest "$MYTHICAL_HOME/f")" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]
}

@test "mi_ensure_layout fails loudly when it cannot create the subtree" {
  load_mctl
  # A regular FILE as the parent makes mkdir -p under it fail deterministically (no chmod needed).
  local blocker="$BATS_TEST_TMPDIR/blocker"; : > "$blocker"
  run env MYTHICAL_HOME="$blocker/home" bash -c \
    'source '"$_MCTL_ROOT"'/lib/common.sh; source '"$_MCTL_ROOT"'/lib/layout.sh; mi_ensure_layout'
  [ "$status" -ne 0 ]
  assert_contains "cannot create"
}
