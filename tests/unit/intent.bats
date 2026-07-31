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
  # STOPPING AND REPORTING ARE TWO CLAIMS, and only the first was pinned here. The requirement is
  # "report every candidate", so the candidate has to appear in what the operator is shown — nothing
  # else in this message names it.
  assert_contains "mythical-i1-net"
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

# --- a nonce says WHICH object, never WHOSE (§4b.4) -------------------------------------------------

@test "reconcile does NOT adopt an object labelled for ANOTHER installation" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  # Another installation's volume, standing at the name we were about to use, carrying OUR nonce.
  # Labels are world-readable and world-writable by anyone the daemon authorizes, so a matching nonce
  # is not evidence of ownership — the object's own installation label is.
  mi_rt_volume_create v1 "$n" someoneelse
  run mi_intent_reconcile volume v1
  [ "$status" -ne 0 ]
  assert_contains "someoneelse"
  # Nothing was recorded, and the intent — the only record that our own object may never have been
  # created — survives.
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
  # AND THE FOREIGN OBJECT IS UNTOUCHED: still there, still theirs, still carrying its labels.
  run mi_rt_inspect volume v.install v1
  [ "$status" -eq 0 ]
  [ "$output" = someoneelse ]
  run mi_rt_inspect volume v.nonce v1
  [ "$output" = "$n" ]
}

@test "reconcile does NOT adopt an object of ours standing under a DIFFERENT name" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  # Ours by label, but not the object this intent describes: everything downstream — provenance,
  # deletion authority, the unaccounted gate — looks an object up BY NAME, so recording `volume:v1`
  # here would record provenance for a name nothing holds.
  mi_rt_volume_create v-other "$n" "$IDENT"
  run mi_intent_reconcile volume v1
  [ "$status" -ne 0 ]
  assert_contains "v-other"
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
  run mi_rt_inspect volume v.nonce v-other
  [ "$output" = "$n" ]
}

@test "a FOREIGN object carrying our nonce is not our object appearing, and does not wedge abandonment" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  mi_rt_network_create othernet someoneelse "$n" >/dev/null
  # "Something carries this nonce" was read as "our object has appeared", so another installation's
  # object — or anyone who copied the label — held this intent open forever: never reissued (D38),
  # never reconcilable (it is not ours), never abandonable.
  MI_INTENT_GRACE=0 run mi_intent_abandonable network mythical-i1-net
  [ "$status" -eq 0 ]
}

@test "an object of OURS carrying this nonce under another name refuses abandonment" {
  n="$(mi_nonce_new)"
  mi_intent_open network mythical-i1-net "$n"
  mi_rt_network_create mythical-i1-other "$IDENT" "$n" >/dev/null
  MI_INTENT_GRACE=0 run mi_intent_abandonable network mythical-i1-net
  [ "$status" -ne 0 ]
  assert_contains "mythical-i1-other"
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
}

# --- could not ask is not an answer, on the inspect paths too ---------------------------------------

@test "an inspect that could not be answered is NOT an adoption" {
  n="$(mi_nonce_new)"
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  mi_intent_open network mythical-i1-net "$n"
  # The listing answers and names one network; the daemon then stops before the inspect of what it
  # named. Swallowing that produced provenance with no id for an object nobody could confirm, and
  # dropped the intent that was the only record left of it.
  FAKE_DOCKER_DOWN_AFTER=1 run mi_intent_reconcile network mythical-i1-net
  [ "$status" -eq 4 ]
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
  run mi_prov_find network mythical-i1-net
  [ "$status" -eq 3 ]
}

@test "an object listed and then removed is retained, not adopted" {
  n="$(mi_nonce_new)"
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  mi_intent_open network mythical-i1-net "$n"
  # rc 3, not rc 1: the daemon answers, and its answer is that the object is gone. That is a fact a
  # later run can act on — but it is still not an adoption, and the intent is what carries it forward.
  FAKE_DOCKER_INSPECT_MISSING=mythical-i1-net run mi_intent_reconcile network mythical-i1-net
  [ "$status" -eq 4 ]
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
  run mi_prov_find network mythical-i1-net
  [ "$status" -eq 3 ]
}

@test "an object whose label could not be read STOPS the gate instead of being ignored" {
  mi_rt_volume_create postgres-data nonce-x someoneelse
  # Call 1 lists containers, call 2 lists volumes and names this one, call 3 asks whose it is — and
  # never gets an answer. Swallowing that read as "it carries no label", after which a name outside
  # our scheme is ignored ENTIRELY: the one object the scan could not account for is the one it says
  # nothing about.
  #
  # ASSERTED ON THE ROWS, WITH STDERR DISCARDED. `run` merges stderr into $output, and the warning
  # this failure prints NAMES THE OBJECT — so asserting `postgres-data` on the merged output passed
  # against a scan that classified it as `ignore` and reported nothing at all. Found by mutation:
  # replacing the `unasked` classification with `ignore` left the whole suite green. The scan's
  # contract is its rows, so the rows are what this reads.
  rows="$(FAKE_DOCKER_DOWN_AFTER=2 mi_unaccounted_scan 2>/dev/null)"
  case "$rows" in
    *unasked*postgres-data*) : ;;
    *) echo "no unasked row for the object; rows were: [$rows]" >&2; return 1 ;;
  esac
  # And the gate stops. It would stop on the failed network listing alone — rc 1 from mi_rt_inspect
  # IS "the daemon is down", so no fixture can make one object unanswerable while the listings still
  # answer — which is exactly why the row above, and not this, is what pins the classification.
  rm -f "$FAKE_DOCKER_STATE/down-after.count"
  FAKE_DOCKER_DOWN_AFTER=2 run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains "could not be asked"
}

@test "an id that could not be read after the labels answered is not an adoption" {
  n="$(mi_nonce_new)"
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  mi_intent_open network mythical-i1-net "$n"
  # The listing answers (1), the installation label answers (2), and the daemon stops before the id
  # (3). EVERY inspect on this path is its own question and every one of them has to be able to fail:
  # found by mutation, the identity read added above shadowed this arm, so restoring the `|| true`
  # on the id read left the suite green. The empty-id guard below it reaches the same rc, so what
  # this asserts is the REASON — an operator sent to look for a network the runtime "named no id"
  # for, when in fact nobody could be asked, is being sent to the wrong place.
  FAKE_DOCKER_DOWN_AFTER=2 run mi_intent_reconcile network mythical-i1-net
  [ "$status" -eq 4 ]
  assert_contains "could not be inspected"
  run mi_prov_find network mythical-i1-net
  [ "$status" -eq 3 ]
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
}

@test "an object removed between the listing and the question about it is not reported as unlabelled" {
  n="$(mi_nonce_new)"
  mi_rt_volume_create "mythical-${IDENT}-p1-state" "$n" "$IDENT"
  # The daemon answers: it is gone. Nothing that is not there can be unaccounted for — and calling it
  # unlabelled would report an object holding one of our names, which is a stop.
  FAKE_DOCKER_INSPECT_MISSING="mythical-${IDENT}-p1-state" run mi_unaccounted_gate
  [ "$status" -eq 0 ]
}

# --- the report names every candidate, which needs the list to survive the call ---------------------

@test "the multiple-match report NAMES every candidate" {
  n="$(mi_nonce_new)"
  mi_rt_volume_create v-alpha "$n" "$IDENT"
  mi_rt_volume_create v-beta "$n" "$IDENT"
  mi_intent_open volume v-alpha "$n"
  run mi_intent_reconcile volume v-alpha
  [ "$status" -ne 0 ]
  assert_contains "more than one"
  assert_contains "v-alpha"
  assert_contains "v-beta"
  # Never deleted to disambiguate: both are still there, with their labels.
  run mi_rt_inspect volume v.nonce v-alpha
  [ "$output" = "$n" ]
  run mi_rt_inspect volume v.nonce v-beta
  [ "$output" = "$n" ]
}

@test "nonces do not repeat across many calls in one run" {
  # Called the way every caller calls it — `n=\$(mi_nonce_new)` — which is a SUBSHELL, so any
  # in-memory counter the function keeps is discarded before the next call sees it. Two calls could
  # not show that; this asks the question the module's own comment claims an answer to.
  seen=""; i=0
  while [ "$i" -lt 60 ]; do
    v="$(mi_nonce_new)"
    [ -n "$v" ] || { echo "empty nonce at call $i" >&2; return 1; }
    case "$seen" in *" ${v} "*) echo "nonce repeated at call $i: $v" >&2; return 1 ;; esac
    seen="${seen} ${v} "
    i=$((i + 1))
  done
}

@test "reconcile does NOT adopt an object carrying our nonce and NO installation label" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  # A nonce label and nothing else — a state the adapter cannot produce, because it always writes
  # both labels, so it is written straight into the fake's state. Nothing about the object says whose
  # it is, which is the same answer §6b.2 gives an unlabelled object standing at one of our names:
  # neither adopted nor removed.
  mkdir -p "$FAKE_DOCKER_STATE/volumes"
  printf 'labels=mythicalos.nonce=%s\ndriver=local\n' "$n" > "$FAKE_DOCKER_STATE/volumes/v1"
  run mi_intent_reconcile volume v1
  [ "$status" -ne 0 ]
  assert_contains "NO installation label"
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
}

@test "a network that vanishes between the label and the id is retained, not adopted" {
  n="$(mi_nonce_new)"
  mi_rt_network_create mythical-i1-net "$IDENT" "$n" >/dev/null
  mi_intent_open network mythical-i1-net "$n"
  # Inspect 1 answers whose it is; it is removed before inspect 2 asks what it is. rc 3, not rc 1:
  # the daemon answered, and its answer is that the object is gone — which is a fact a later run can
  # act on, and is reported as such rather than as a question nobody could ask.
  FAKE_DOCKER_INSPECT_MISSING=mythical-i1-net FAKE_DOCKER_INSPECT_MISSING_AFTER=1 \
    run mi_intent_reconcile network mythical-i1-net
  [ "$status" -eq 4 ]
  assert_contains "already gone"
  run mi_prov_find network mythical-i1-net
  [ "$status" -eq 3 ]
  run mi_intent_find network mythical-i1-net
  [ "$status" -eq 0 ]
}

@test "a reissued volume that vanishes before its nonce is read is retained, not refused" {
  n="$(mi_nonce_new)"
  mi_intent_open volume v1 "$n"
  # Zero matches, so the volume is reissued; inspect 1 answers whose it is, and it is gone before
  # inspect 2 reads its nonce. Retained for a later run (4), not stopped (1) — and not reported as a
  # nonce that did not match, which is what an empty answer read as a value looks like.
  FAKE_DOCKER_INSPECT_MISSING=v1 FAKE_DOCKER_INSPECT_MISSING_AFTER=1 \
    run mi_intent_reconcile volume v1
  [ "$status" -eq 4 ]
  assert_contains "already gone"
  run mi_intent_find volume v1
  [ "$status" -eq 0 ]
}
