#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire
  IDENT="$(mi_ident_ensure)"
  NET="$(mi_rt_network_create "mythical-${IDENT}-net" "$IDENT" nnet)"
  C="mythical-${IDENT}-p1"
  # The fake runtime refuses `container create` from an image it was never asked to pull, because that
  # is what a real daemon does — so the fixture pulls first, exactly as tests/unit/runtime.bats does.
  IMG="$(a_digestref p1)"
  mi_rt_image_pull "$IMG" >/dev/null
  mi_rt_container_create "$C" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce=cn >/dev/null
}
teardown() { mi_lock_release; teardown_test_env; }

@test "desired state and the outstanding set commit in ONE ledger write" {
  before="$(mi_digest "$MYTHICAL_HOME/.state/ledger")"
  mi_state_commit "$C" running alias "$NET"
  run mi_state_desired_get "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  assert_contains "alias"
  assert_contains "$NET"
  [ "$before" != "$(mi_digest "$MYTHICAL_HOME/.state/ledger")" ]
}

@test "desired state defaults to NOTHING, not to running" {
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
  [ -z "$output" ]
}

@test "clearing an outstanding kind clears ONLY that kind" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C"
  [ -z "$output" ]
  run mi_state_desired_get "$C"
  [ "$output" = running ]
}

@test "clearing a kind this core does not define is REFUSED, not a silent no-op" {
  mi_state_commit "$C" running alias "$NET"
  run mi_state_outstanding_clear "$C" storage "$NET"
  [ "$status" -ne 0 ]
  assert_contains "not a check kind"
}

@test "observed state is read from the runtime, never from the ledger" {
  run mi_state_observed "$C"
  [ "$output" = stopped ]
  mi_rt_container_start "$C"
  run mi_state_observed "$C"
  [ "$output" = running ]
}

@test "observed state reports absent for a container that is gone" {
  mi_rt_container_rm "$C"
  run mi_state_observed "$C"
  [ "$output" = absent ]
}

@test "an outstanding flag makes a container NOT reconciled even when actual==desired==running" {
  mi_state_commit "$C" running alias "$NET"
  mi_rt_container_start "$C"
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_reconciled "$C"
  [ "$status" -eq 0 ]
}

@test "desired=stopped with the container stopped IS reconciled" {
  mi_state_commit "$C" stopped
  run mi_state_reconciled "$C"
  [ "$status" -eq 0 ]
}

@test "the plan for desired=running, stopped, no outstanding, is start-then-verify" {
  mi_state_commit "$C" running
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
}

@test "the plan for desired=running, RUNNING, outstanding alias, is verify NOW — not at a future start" {
  mi_state_commit "$C" running alias "$NET"
  mi_rt_container_start "$C"
  run mi_state_plan "$C"
  [ "$output" = "verify" ]
}

@test "the plan for desired=stopped, still running, is stop — reconciliation runs BOTH ways" {
  mi_state_commit "$C" stopped
  mi_rt_container_start "$C"
  run mi_state_plan "$C"
  [ "$output" = "stop" ]
}

@test "the plan for desired=stopped, not running, is nothing — a completed stop is not a crash" {
  mi_state_commit "$C" stopped
  run mi_state_plan "$C"
  [ "$output" = "none" ]
}

@test "a STOPPED container with an outstanding alias check DEFERS — it has no address to verify" {
  mi_state_commit "$C" stopped alias "$NET"
  run mi_state_plan "$C"
  [ "$output" = "defer" ]
}

@test "a recorded storage-migration intent SUSPENDS reconciliation for that container" {
  # The REAL record shape: kind `storagemig`, keyed <product>:<role>. Using a container `intent` here
  # would pass for the wrong reason — that is a different suspension path, and it is tested below.
  mi_prov_record container "$C" cn "product=p1"
  mi_state_commit "$C" running
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" "dest=/d"
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an unconfirmed CONTAINER intent also suspends — a half-built container is not reconcilable" {
  mi_state_commit "$C" running
  mi_intent_open container "$C" cn
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an absent container with desired=running plans a rebuild, never a bare start" {
  mi_state_commit "$C" running
  mi_rt_container_rm "$C"
  run mi_state_plan "$C"
  [ "$output" = "rebuild" ]
}

@test "forget removes both records, for a family uninstall" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_forget "$C"
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}

@test "desired state accepts only running or stopped" {
  run mi_state_commit "$C" paused
  [ "$status" -ne 0 ]
  assert_contains "running or stopped"
}

# --- the refusals, each pinned so the guard cannot be deleted with the suite green ----------------
#
# Everything below this line refuses. They are here because a guard whose removal changes nothing
# observable is a guard that gets removed: each of these fails against the shape this module was
# written to replace, and the shape is named in the test's own comment.

# Append a row verbatim, keeping every row already there. The editors refuse to WRITE two records
# answering for one key, so a contradiction can only arrive from a restored or foreign ledger — which
# is the state these reads have to survive, and the only way to build it.
put_raw() { { mi_ledger_read; printf '%s\n' "$1"; } | mi_ledger_write; }

@test "a ledger that cannot be READ refuses the outstanding set — it never reports an empty one" {
  # An empty set is what makes a container reconciled and what makes the plan `none`, so folding
  # "could not read the ledger" into it declares a fleet settled on an unanswered question. The shape
  # that does this is `while … done <<< "$(mi_led_all …)"` followed by `return 0`: the reader's status
  # is discarded by the command substitution and the loop simply sees nothing.
  mi_state_commit "$C" running alias "$NET"
  printf 'tampered\n' >> "$MYTHICAL_HOME/.state/ledger"
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
}

@test "an outstanding entry that does not say what check is owed refuses the whole set" {
  # Skipping it would retire an owed verification by leaving it out of the set, and an empty set means
  # reconciled — so the one entry that cannot be interpreted would be the one that silently clears.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"param=x"
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
}

@test "an intent lookup that cannot answer refuses the plan — that is not 'there is no intent'" {
  # mi_led_find returns 1 for an unreadable ledger AND for a key more than one record answers for.
  # `if mi_intent_find …; then suspended; fi` folds both into "proceed", and proceeding on a container
  # whose half-built state nobody could read is the direction that acts.
  mi_state_commit "$C" running
  mi_intent_open container "$C" cn
  put_raw "intent"$'\t'"key=container:${C}"$'\t'"class=container"$'\t'"name=${C}"$'\t'"nonce=other"$'\t'"created=1"
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
  assert_contains "unconfirmed intent governs"
}

@test "a storage-migration lookup that cannot answer refuses the plan" {
  # `rec="$(mi_prov_find …)" || return 1` reports "no migration governs" for an unreadable or
  # ambiguous ledger, which is "proceed" — and proceeding restarts a container a migration
  # deliberately stopped.
  mi_state_commit "$C" running
  mi_prov_find() { return 1; }
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
  assert_contains "storage migration governs"
}

@test "a runtime answer that is neither true nor false is refused, never read as stopped" {
  # `if [ "$v" = true ]; then running; else stopped; fi` manufactures `stopped` out of anything it does
  # not recognise — and desired=running plus a manufactured `stopped` plans a start against a
  # container whose state was never established.
  mi_rt_inspect() { printf 'maybe\n'; }
  run mi_state_observed "$C"
  [ "$status" -ne 0 ]
}

@test "a desired state the reconciler has no row for is refused on READ, not planned around" {
  # The vocabulary is closed on the way in; closing it only there let a restored `state=paused` reach
  # the reconciler's table, fall through every arm, print nothing and return SUCCESS — which reads to
  # a caller as "no work to do".
  put_raw "desired"$'\t'"container=${C}"$'\t'"state=paused"
  run mi_state_desired_get "$C"
  [ "$status" -eq 1 ]
  assert_contains "running or stopped"
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
}

@test "a container name that would forge a record is refused, never serialized" {
  # mi_state_commit writes two kinds in one write, so mi_led_put — which applies the field rule — is
  # not on this path. Unchecked, a TAB forges a field boundary and a newline forges a whole record.
  run mi_state_commit "forged"$'\n'"desired"$'\t'"container=elsewhere" running
  [ "$status" -ne 0 ]
  run mi_state_commit "$C" running alias "net"$'\t'"kind=alias"
  [ "$status" -ne 0 ]
}

@test "an outstanding check with no parameter is refused — that is the boolean D52 replaced" {
  # An `alias` entry carries the network its alias must resolve on, and the clear matches on it. An
  # entry carrying nothing can never be matched, so it keeps its container unreconciled forever.
  run mi_state_commit "$C" running alias ""
  [ "$status" -ne 0 ]
  run mi_state_commit "$C" running alias
  [ "$status" -ne 0 ]
}

@test "two contradicting desired rows are PRESERVED, not replaced by one" {
  # Dropping every matching row and appending one destroys the only evidence that the ledger needs
  # repairing, at the first ordinary operation that touches this container.
  mi_state_commit "$C" running
  put_raw "desired"$'\t'"container=${C}"$'\t'"state=stopped"
  run mi_state_commit "$C" running
  [ "$status" -ne 0 ]
  run mi_state_desired_get "$C"
  [ "$status" -eq 1 ]
}

@test "forget removes the outstanding SET, not just the one row a selector resolves to" {
  # Two mi_led_del calls are two writes AND two single-row deletes: on a container with two entries
  # the second call refuses outright, leaving the set half-forgotten behind a deleted desired row.
  mi_state_commit "$C" running alias "$NET" alias "${NET}x"
  mi_state_forget "$C"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "a blank row survives a commit and a clear, rather than being tidied away by them" {
  # `[ -n "$line" ] || continue` in a rewriting loop reads as harmless and is not: the row is silently
  # absent from the output, so a foreign or restored ledger quietly loses a row at the first operation
  # that touches this container.
  mi_state_commit "$C" running alias "$NET"
  body="$(mi_ledger_read)"
  { printf '\n'; printf '%s\n' "$body"; } | mi_ledger_write
  [ "$(mi_ledger_read | grep -ac '^$' || true)" -eq 1 ]
  mi_state_commit "$C" stopped alias "$NET"
  [ "$(mi_ledger_read | grep -ac '^$' || true)" -eq 1 ]
  mi_state_outstanding_clear "$C" alias "$NET"
  [ "$(mi_ledger_read | grep -ac '^$' || true)" -eq 1 ]
}

# --- fix wave 1: AN OUTSTANDING CHECK MAY ONLY DISAPPEAR WHEN THE THING IT NAMES WAS VERIFIED -------
#
# Four faces of one rule, so four ways an owed verification could stop being owed with nobody having
# performed it. Each test names the shape it replaces, as the block above does.

@test "an outstanding check SURVIVES a commit that does not mention it" {
  # A desired-state write is not a verification of anything. `mi_state_commit "$C" stopped` used to
  # rewrite this container's whole state and drop the alias entry with it — nothing was checked, and
  # the check simply vanished, leaving the container reconciled on an unanswered question.
  mi_state_commit "$C" running alias "$NET"
  mi_state_commit "$C" stopped
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  assert_contains "alias"
  assert_contains "$NET"
  run mi_state_plan "$C"
  [ "$output" = "defer" ]
}

@test "a later commit ADDS to the outstanding set rather than replacing it" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_commit "$C" running alias "${NET}x"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  case $'\n'"$output"$'\n' in
    *$'\n'"alias"$'\t'"${NET}"$'\n'*) : ;;
    *) echo "the first check was replaced rather than added to: $output" >&2; return 1 ;;
  esac
  case $'\n'"$output"$'\n' in
    *$'\n'"alias"$'\t'"${NET}x"$'\n'*) : ;;
    *) echo "the second check was not recorded: $output" >&2; return 1 ;;
  esac
}

@test "clearing names the PARAMETER — a same-kind check nobody verified survives" {
  # `mi_state_outstanding_clear "$C" alias` filtered on the KIND alone, while mi_state_commit accepts
  # several entries of one kind with different parameters — so verifying the alias on ONE network
  # retired the check owed on every other. Test 28 builds two same-kind entries but exercises
  # `forget`; this one exercises the clear, which is the function the defect is in.
  mi_state_commit "$C" running alias "$NET" alias "${NET}x"
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  case $'\n'"$output"$'\n' in
    *$'\n'"alias"$'\t'"${NET}x"$'\n'*) : ;;
    *) echo "a check nobody verified was cleared too: $output" >&2; return 1 ;;
  esac
  case $'\n'"$output"$'\n' in
    *$'\n'"alias"$'\t'"${NET}"$'\n'*) echo "the verified check survived its own clear: $output" >&2; return 1 ;;
  esac
  # and one unverified entry still keeps the container off the reconciled list
  mi_rt_container_start "$C"
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
}

@test "a clear that does not name WHICH check was verified is refused" {
  # The clear is the only place an owed check disappears, so it has to name the exact thing that was
  # verified. A parameterless clear names a kind and nothing else — the by-kind clear this replaced,
  # one call earlier.
  mi_state_commit "$C" running alias "$NET"
  run mi_state_outstanding_clear "$C" alias
  [ "$status" -ne 0 ]
  run mi_state_outstanding_clear "$C" alias ""
  [ "$status" -ne 0 ]
  run mi_state_outstanding "$C"
  assert_contains "$NET"
}

@test "an outstanding entry that does not say WHAT to verify refuses the whole set" {
  # A missing `param` became `p=""`, so a restored `container=C kind=alias` row was listed as an
  # ordinary entry: it schedules a `verify` that names nothing to verify, and the by-kind clear then
  # deleted it. Fail closed, exactly as the missing-`kind` case already does.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"kind=alias"
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
}

@test "an outstanding entry whose parameter is EMPTY refuses the set too" {
  # `param=` is a legal field carrying no value, so it reaches the listing as `p=""` — the same entry
  # naming nothing, one byte later, and the same reason to refuse it.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"kind=alias"$'\t'"param="
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
}

@test "the desired row has exactly ONE writer, and it is the atomic one" {
  # mi_state_desired_set wrote `desired` alone: it neither preserved the recorded value nor wrote an
  # outstanding check atomically with it. A caller that recorded `running`, started the container and
  # crashed left observed = desired = running with nothing outstanding — plan `none`, and the live
  # verification lost. It is REMOVED rather than documented against; with the set now preserved,
  # `mi_state_commit <container> <state>` is the intent-preserving write it existed for, obtained
  # through the atomic path.
  run type mi_state_desired_set
  [ "$status" -ne 0 ]
  mi_state_commit "$C" running alias "$NET"
  want="$(mi_state_desired_get "$C")"
  mi_state_commit "$C" "$want"
  run mi_state_outstanding "$C"
  assert_contains "$NET"
}

@test "recording the same check twice records it once, and ONE clear retires it" {
  # commit ADDS to the set now, so a check already owed must not be written a second time: two rows
  # naming one verification are not two obligations, and the second would outlive the clear that
  # performed it if the clear dropped only one row.
  mi_state_commit "$C" running alias "$NET"
  mi_state_commit "$C" running alias "$NET" alias "$NET"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  n=0
  while IFS= read -r l; do if [ -n "$l" ]; then n=$((n + 1)); fi; done <<< "$output"
  [ "$n" -eq 1 ] || { echo "expected one entry, got ${n}: $output" >&2; return 1; }
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}
