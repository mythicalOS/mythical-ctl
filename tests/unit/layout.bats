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
  # DEPTH. `case` globs match slashes, so without the `*/*/*` guard above it a lone `*/cli.toml`
  # would swallow every one of these — a generated artifact promoted into the one class the
  # installer promises never to touch.
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
  # this layout does not own. The leading `[!.]` is what refuses it; the depth guard refuses the rest.
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
  # The document says so in as many words, so the limit is published and not merely true.
  grep -Faq 'Three product names cannot carry a slot' "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
}

@test "mi_zone classifies path SHAPE and does not validate the product name" {
  load_mctl
  # A documented non-guarantee, pinned so it stays a decision rather than becoming an accident. No
  # arm of mi_zone validates a product name; `_mi_conf_product_name_ok` is the single authority, and
  # giving the path classifier a second, disagreeing opinion would be worse than having none.
  # Nothing creates these paths, and no caller reads a zone as permission to create one.
  [ "$(mi_zone Brokkr/cli.toml)"         = user-owned ]
  [ "$(mi_zone mythical/cli.toml)"       = user-owned ]
  run _mi_conf_product_name_ok Brokkr
  [ "$status" -ne 0 ]
  run _mi_conf_product_name_ok mythical
  [ "$status" -ne 0 ]
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
  # And it does not invent one for a product that has no host-side tool.
  mi_ensure_layout
  [ ! -e "$MYTHICAL_HOME/saga/cli.toml" ]
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
