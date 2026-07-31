#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire
  IDENT="$(mi_ident_ensure)"
}
teardown() { mi_lock_release; teardown_test_env; }

# Append a row to the ledger verbatim, keeping every row already there. The editors refuse to WRITE
# two records answering for one key, so a duplicate can only arrive from a restored or foreign
# ledger — which is the state the reads below have to survive, and the only way to build it.
put_raw() { { mi_ledger_read; printf '%s\n' "$1"; } | mi_ledger_write; }

@test "a nonce is unique across calls and is a safe label value" {
  a="$(mi_nonce_new)"; b="$(mi_nonce_new)"
  [ "$a" != "$b" ]
  case "$a" in *[!a-z0-9]*) false ;; *) true ;; esac
}

@test "an intent is recorded BEFORE the object and carries its creation time" {
  n="$(mi_nonce_new)"
  mi_intent_open volume mythical-i1-p1-state "$n"
  run mi_intent_find volume mythical-i1-p1-state
  assert_contains "nonce=$n"
  assert_contains "created="
}

@test "confirm records provenance and drops the intent, in ONE ledger write" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  mi_rt_volume_create v1 "$n" "$IDENT"
  mi_intent_confirm volume v1 "$n"
  run mi_intent_find volume v1
  [ "$status" -eq 3 ]
  run mi_prov_find volume v1
  [ "$status" -eq 0 ]
  assert_contains "nonce=$n"
}

@test "reconcile adopts EXACTLY ONE label match" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  mi_rt_volume_create v1 "$n" "$IDENT"
  run mi_intent_reconcile volume v1
  [ "$status" -eq 0 ]
  run mi_prov_find volume v1
  [ "$status" -eq 0 ]
}

@test "reconcile with ZERO matches REISSUES a volume, then re-inspects the nonce" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  run mi_intent_reconcile volume v1
  [ "$status" -eq 0 ]
  run mi_rt_inspect volume v.nonce v1
  [ "$output" = "$n" ]
}

@test "a reissue that meets an EXISTING same-name volume is NOT adopted — the nonce differs" {
  mi_rt_volume_create v1 someone-elses "$IDENT"
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  run mi_intent_reconcile volume v1
  [ "$status" -ne 0 ]
  assert_contains "does not match"
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
}

@test "reconcile NEVER reissues a network (D38) — the intent is retained" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  run mi_intent_reconcile network mythical-i1-net
  [ "$status" -eq 4 ]
  assert_contains "never reissued"
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
  run mi_rt_inspect network n.id mythical-i1-net
  [ "$status" -eq 3 ]
}

@test "MORE THAN ONE match stops and reports every candidate — never deletes to disambiguate" {
  n="$(mi_nonce_new)"
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  FAKE_DOCKER_NET_DUPLICATE=1 mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  mi_intent_open network mythical-i1-net "$n"
  run mi_intent_reconcile network mythical-i1-net
  [ "$status" -ne 0 ]
  assert_contains "more than one"
  run mi_rt_find_by_label network nonce "$n"
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
}

@test "a retained network intent is not abandonable before the grace period" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  run mi_intent_abandonable network mythical-i1-net
  [ "$status" -ne 0 ]
  assert_contains "grace"
}

@test "after the grace period with still zero matches it becomes abandonable" {
  n="$(mi_nonce_new)"
  MI_INTENT_GRACE=0 mi_intent_open network mythical-i1-net "$n"
  MI_INTENT_GRACE=0 run mi_intent_abandonable network mythical-i1-net
  [ "$status" -eq 0 ]
}

@test "abandonment is not possible while the daemon is unreachable" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  MI_INTENT_GRACE=0 FAKE_DOCKER_DOWN=1 run mi_intent_abandonable network mythical-i1-net
  [ "$status" -ne 0 ]
}

@test "abandonment clears the intent and says it does NOT guarantee convergence" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  MI_INTENT_GRACE=0 run mi_intent_abandon network mythical-i1-net
  [ "$status" -eq 0 ]
  assert_contains "may still appear"
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 3 ]
}

@test "an abandoned intent's object surfacing later is UNRECORDED SAME-IDENTITY, and stops" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  MI_INTENT_GRACE=0 mi_intent_abandon network mythical-i1-net
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains "unrecorded"
  assert_contains "mythical-i1-net"
}

@test "a FOREIGN-identity object is reported as unattributed and never stops an operation" {
  mi_rt_volume_create other-vol nonce-x someoneelse
  run mi_unaccounted_scan
  [ "$status" -eq 0 ]
  assert_contains "unattributed"
  assert_contains "other-vol"
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
}

@test "the unattributed listing NEVER proposes removal" {
  mi_rt_volume_create other-vol nonce-x someoneelse
  run mi_unaccounted_scan
  # POSITIVE CONTROL FIRST. The assertion below is an ABSENCE, and an absence proves nothing about a
  # function that printed nothing at all: a broken scan gives an empty $output, grep finds no verb,
  # and the test passes while asserting only that silence contains no verbs. So prove the listing
  # actually ran and actually named the object before asking what it does NOT say about it.
  assert_contains "unattributed"
  assert_contains "other-vol"
  run grep -aiE 'remove|delete|prune' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "an UNLABELLED object holding a name we would create BLOCKS creation" {
  # No labels at all: created outside this installer, which is a state `docker volume create` cannot
  # produce — the adapter always labels — so the record is written straight into the fake's state.
  # The fake creates its own directories on its first invocation, and nothing has invoked it yet.
  mkdir -p "$FAKE_DOCKER_STATE/volumes"
  printf 'labels=\ndriver=local\n' > "$FAKE_DOCKER_STATE/volumes/mythical-${IDENT}-p1-state"
  run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains "not labelled"
  assert_contains "neither adopted nor removed"
}

@test "an unlabelled object NOT holding one of our names is ignored entirely" {
  # The foreign-identity volume is the POSITIVE CONTROL: it guarantees the listing is non-empty, so
  # the absence assertion below is about what the scan says rather than about whether it said
  # anything. Without it, a scan that printed nothing would pass this test.
  mi_rt_volume_create other-vol nonce-x someoneelse
  printf 'labels=\ndriver=local\n' > "$FAKE_DOCKER_STATE/volumes/postgres-data"
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
  run mi_unaccounted_scan
  assert_contains "other-vol"
  run grep -a 'postgres-data' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "a confirmed object is NOT unrecorded — the gate passes once provenance exists" {
  n="$(mi_nonce_new)"
  mi_intent_open volume "mythical-${IDENT}-p1-state" "$n"
  mi_rt_volume_create "mythical-${IDENT}-p1-state" "$n" "$IDENT"
  mi_intent_confirm volume "mythical-${IDENT}-p1-state" "$n"
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
}

@test "an object with a LIVE intent is not unrecorded — the intent accounts for it" {
  n="$(mi_nonce_new)"
  mi_intent_open volume "mythical-${IDENT}-p1-state" "$n"
  mi_rt_volume_create "mythical-${IDENT}-p1-state" "$n" "$IDENT"
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
}

@test "a TOMBSTONED object that still exists is unrecorded, and stops" {
  n="$(mi_nonce_new)"
  mi_rt_volume_create "mythical-${IDENT}-p1-state" "$n" "$IDENT"
  mi_prov_record volume "mythical-${IDENT}-p1-state" "$n"
  mi_prov_tombstone volume "mythical-${IDENT}-p1-state"
  run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains "unrecorded"
}

# --- the rules this module adds, each pinned where it is decided ------------------------------------

@test "an intent with no nonce is refused — it could never be reconciled" {
  run mi_intent_open volume v1 ""
  [ "$status" -ne 0 ]
  run mi_intent_find volume v1
  [ "$status" -eq 3 ]
}

@test "confirm PRESERVES two intents answering for one key rather than collapsing them" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  put_raw "$(printf 'intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=other\tcreated=1')"
  mi_rt_volume_create v1 "$n" "$IDENT"
  run mi_intent_confirm volume v1 "$n"
  [ "$status" -ne 0 ]
  # Both rows are still there, and no provenance was written on the strength of a ledger that
  # contradicts itself.
  run mi_led_all intent
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
}

@test "confirm PRESERVES a second tombstone for the name it is re-creating" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  put_raw "$(printf 'tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=a\tgen=1')"
  put_raw "$(printf 'tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=b\tgen=2')"
  mi_rt_volume_create v1 "$n" "$IDENT"
  run mi_intent_confirm volume v1 "$n"
  [ "$status" -ne 0 ]
  run mi_led_all tombstone
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
}

@test "reconcile RETAINS the intent when the runtime cannot be asked — zero is not an answer" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  FAKE_DOCKER_DOWN=1 run mi_intent_reconcile volume v1
  [ "$status" -eq 4 ]
  assert_contains "could not be asked"
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
}

@test "an intent whose creation time is not a number is never aged out" {
  # `created` reaches `$(( ))`, which EVALUATES rather than parses — measured on this machine: a
  # command substitution inside an array subscript runs. So a restored ledger's `created` is a value
  # out of a file reaching an evaluator, which is the one hazard lib/prov.sh's generation check
  # exists for and asks the next author to bring along.
  put_raw "$(printf 'intent\tkey=network:mythical-i1-net\tclass=network\tname=mythical-i1-net\tnonce=n1\tcreated=a[9]')"
  MI_INTENT_GRACE=0 run mi_intent_abandonable network mythical-i1-net
  [ "$status" -ne 0 ]
  assert_contains "not a number"
}

@test "a grace period that is not a number refuses rather than ageing everything out" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  MI_INTENT_GRACE=xxx run mi_intent_abandonable network mythical-i1-net
  [ "$status" -ne 0 ]
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
}

@test "the gate STOPS when the runtime cannot be listed — an empty answer is not no answer" {
  FAKE_DOCKER_DOWN=1 run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains "could not be asked"
}
