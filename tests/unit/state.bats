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
  mi_state_commit "$C" running +none
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
  mi_state_commit "$C" running +none
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" "dest=/d"
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an unconfirmed CONTAINER intent also suspends — a half-built container is not reconcilable" {
  mi_state_commit "$C" running +none
  mi_intent_open container "$C" cn
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an absent container with desired=running plans a rebuild, never a bare start" {
  mi_state_commit "$C" running +none
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
  mi_state_commit "$C" running +none
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
  mi_state_commit "$C" running +none
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
  run mi_state_commit "forged"$'\n'"desired"$'\t'"container=elsewhere" running +none
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
  mi_state_commit "$C" running +none
  put_raw "desired"$'\t'"container=${C}"$'\t'"state=stopped"
  run mi_state_commit "$C" running +none
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
  # THE MESSAGE IS ASSERTED, NOT JUST THE STATUS, and that is not decoration. A record with no `param=`
  # field and one carrying `param=` with nothing after it both arrive at the listing as an empty
  # value, so either guard alone refuses both — and a test that checked only the status stayed green
  # with the missing-field branch deleted, because the empty-value branch below caught it. The two are
  # kept apart for the reason lib/prov.sh keeps "carries no fields at all" apart from "this token is
  # not a field": they are different facts about a ledger someone has to repair. Asserting which fact
  # is reported is what makes each branch independently observable.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"kind=alias"
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
  assert_contains "does not say WHAT it must verify"
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
}

@test "an outstanding entry whose parameter is EMPTY refuses the set too" {
  # `param=` is a legal field carrying no value, so it reaches the listing as an empty value — the same
  # entry naming nothing, one byte later, and the same reason to refuse it. The record DOES carry the
  # field, so it is the other fact, and the other message.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"kind=alias"$'\t'"param="
  run mi_state_outstanding "$C"
  [ "$status" -ne 0 ]
  assert_contains "carries an EMPTY parameter"
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
  #
  # BOTH DIRECTIONS, and the first one is the one a weaker fixture misses. Asking only whether the
  # kept rows already carry the check answers the ACROSS-CALLS case correctly and still writes two
  # rows for a pair repeated WITHIN one call — so the duplicate below is committed first, with nothing
  # recorded before it, where only the rows this same call has appended can answer.
  mi_state_commit "$C" running alias "$NET" alias "$NET"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  n=0
  while IFS= read -r l; do if [ -n "$l" ]; then n=$((n + 1)); fi; done <<< "$output"
  [ "$n" -eq 1 ] || { echo "one call, one check, expected one entry, got ${n}: $output" >&2; return 1; }
  # and across calls, where the kept rows are what answers
  mi_state_commit "$C" running alias "$NET"
  run mi_state_outstanding "$C"
  n=0
  while IFS= read -r l; do if [ -n "$l" ]; then n=$((n + 1)); fi; done <<< "$output"
  [ "$n" -eq 1 ] || { echo "a later commit re-recorded the same check, got ${n}: $output" >&2; return 1; }
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}

@test "a clear whose parameter could not be a field is refused, not a silent no-op" {
  # The entry was serialized from these three fields, so the clear is judged by the writer's own list
  # rule. Without it a selector no field could ever equal matches nothing, clears nothing, and reports
  # success — a caller believing it retired a check that is still owed.
  mi_state_commit "$C" running alias "$NET"
  run mi_state_outstanding_clear "$C" alias "net"$'\t'"kind=alias"
  [ "$status" -ne 0 ]
  run mi_state_outstanding "$C"
  assert_contains "$NET"
}

@test "forget and clear touch only the container they name" {
  # The container half of the match is what keeps one container's uninstall, or one container's
  # verified alias, from retiring the checks every other container owes.
  local C2="${C}-two"
  mi_rt_container_create "$C2" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce=cn2 >/dev/null
  mi_state_commit "$C" running alias "$NET"
  mi_state_commit "$C2" running alias "$NET"
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C2"
  assert_contains "$NET"
  mi_state_forget "$C"
  run mi_state_outstanding "$C2"
  assert_contains "$NET"
  run mi_state_desired_get "$C2"
  [ "$output" = running ]
}

@test "a check of a kind this core does not know is not retired by clearing another" {
  # A newer version's kind, arriving in a restored ledger. This core lists it — it says what is owed
  # and what it names, which is all the listing needs — and an `alias` clear must leave it exactly
  # where it is. It is also the only shape available today for pinning the KIND half of the match,
  # since `alias` is the one kind this core defines.
  mi_state_commit "$C" running alias "$NET"
  put_raw "outstanding"$'\t'"container=${C}"$'\t'"kind=storage"$'\t'"param=${NET}"
  mi_state_outstanding_clear "$C" alias "$NET"
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  case $'\n'"$output"$'\n' in
    *$'\n'"storage"$'\t'"${NET}"$'\n'*) : ;;
    *) echo "a check of another kind was retired by an alias clear: $output" >&2; return 1 ;;
  esac
  case $'\n'"$output"$'\n' in
    *$'\n'"alias"$'\t'"${NET}"$'\n'*) echo "the verified alias check survived: $output" >&2; return 1 ;;
  esac
}

# --- fix wave 3: EVERY TRANSITION THAT LEAVES A CONTAINER RUNNING ENDS IN A LIVE VERIFICATION ------
#
# Two rules, and both turn on a fact that has to be WRITTEN DOWN rather than inferred from an empty
# set — what this intent owes, and whether this installer has already tried to start the container.
# An absence cannot carry either fact, which is precisely what made both defects invisible.

@test "a running intent that owes NO live verification must SAY so — silence is refused" {
  # `mi_state_commit "$C" running` wrote an empty outstanding set and said nothing about it. Start the
  # container, crash before anything else is recorded, and the ledger reads running/running with
  # nothing outstanding — plan `none`, fully reconciled, and the live verification never happened.
  # That is byte for byte the state a COMPLETED verification leaves, so nothing downstream can tell
  # the two apart. "It started" is not evidence that its alias resolves.
  run mi_state_commit "$C" running
  [ "$status" -ne 0 ]
  assert_contains "owes no live verification"
  # and nothing was written — the refusal is not a warning printed beside a completed write
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
}

@test "an intent that owes nothing RECORDS that it owes nothing" {
  mi_state_commit "$C" running +none
  run mi_state_desired_get "$C"
  [ "$status" -eq 0 ]
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  # THE POINT OF THE WHOLE FIX: the answer is ON THE ROW, not implied by the empty set beside it.
  rec="$(mi_led_find desired container "$C")"
  run mi_led_field "$rec" verify
  [ "$status" -eq 0 ]
  [ "$output" = none ]
  # and it still plans the verification step — D42 walks it on every path that leaves it running
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
}

@test "a running row that does not say what it owes is refused on READ" {
  # The crash shape, arriving from disk: an intent recorded, nothing outstanding, and nothing saying
  # whether anything ever was. This core can no longer write it; a restored or older ledger still
  # can, and reading it as "there is no work to do" is the entire defect.
  put_raw "desired"$'\t'"container=${C}"$'\t'"state=running"
  run mi_state_desired_get "$C"
  [ "$status" -eq 1 ]
  assert_contains "does not say whether a live verification is"
  assert_contains "indistinguishable from a crash"
  mi_rt_container_start "$C"
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
}

@test "a verify value this core has no meaning for is refused, not planned around" {
  # The same closed-vocabulary rule the desired state itself gets, and for the same reason: a value
  # nothing has a row for must not reach the reconciler and be silently treated as one that does.
  put_raw "desired"$'\t'"container=${C}"$'\t'"state=running"$'\t'"verify=later"
  run mi_state_desired_get "$C"
  [ "$status" -eq 1 ]
  assert_contains "'owed' or 'none'"
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
}

@test "declaring nothing is owed while a check IS owed is a contradiction, and refused" {
  # The declaration is a claim about the state this write LEAVES BEHIND, not about its own argument
  # list — a commit preserves the outstanding set, so a commit that carries no pairs is not a commit
  # that owes nothing.
  mi_state_commit "$C" running alias "$NET"
  run mi_state_commit "$C" running +none
  [ "$status" -ne 0 ]
  assert_contains "still owes"
  # nor can it be smuggled in beside a pair, which would be one call saying both things at once
  run mi_state_commit "$C" running alias "${NET}x" +none
  [ "$status" -ne 0 ]
  assert_contains "owes NO live verification"
  run mi_state_outstanding "$C"
  assert_contains "$NET"
}

@test "a container that does not stay up is resumed ONCE, then reported" {
  # For desired=running every observed `stopped` yielded `start verify`. Starting a container that
  # exits immediately changes neither the desired state nor the outstanding set, so the next
  # reconciliation produced the IDENTICAL action, for ever — nothing recorded said an attempt had
  # already been made, so "has not been resumed" and "was resumed and exited" were the same state.
  mi_state_commit "$C" running alias "$NET"
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
  # the verb performs that plan: it records the attempt, then starts...
  mi_state_resume_record "$C"
  mi_rt_container_start "$C"
  # ...and the container exits immediately
  mi_rt_container_stop "$C"
  # ASK AGAIN — the whole finding is that the second plan used to equal the first.
  run mi_state_plan "$C"
  [ "$status" -eq 0 ]
  [ "$output" = "exited" ] || { echo "the second plan is still '$output' — it is resumed for ever" >&2; return 1; }
}

@test "a fresh statement of intent grants a fresh attempt" {
  # Otherwise a container reported once could never be started again by any ordinary operation.
  mi_state_commit "$C" running alias "$NET"
  mi_state_resume_record "$C"
  run mi_state_plan "$C"
  [ "$output" = "exited" ]
  mi_state_commit "$C" running alias "$NET"
  run mi_state_plan "$C"
  [ "$output" = "start verify" ] || { echo "a re-stated intent did not grant a fresh attempt: $output" >&2; return 1; }
}

@test "the attempt record is retired by the verification that proves the container came up" {
  # A container that started perfectly well, was verified, and is later stopped out of band — by a
  # reboot, or by hand — must be startable again. The clear is the one call that reports a live
  # verification, and a live verification is evidence the container had an address to verify.
  mi_state_commit "$C" running alias "$NET"
  mi_state_resume_record "$C"
  mi_rt_container_start "$C"
  mi_state_outstanding_clear "$C" alias "$NET"
  mi_rt_container_stop "$C"
  run mi_state_plan "$C"
  [ "$output" = "start verify" ] || { echo "a container that came up and was verified is not resumed again: $output" >&2; return 1; }
}

@test "an attempt record that cannot be read refuses the plan, never reads as 'not tried yet'" {
  # Folding "could not answer" into "no attempt recorded" is the direction that starts the container
  # again, which is the loop this record exists to stop. Same split as every other reader here.
  mi_state_commit "$C" running alias "$NET"
  mi_state_resume_record "$C"
  put_raw "resumed"$'\t'"container=${C}"$'\t'"notafield"
  run mi_state_plan "$C"
  [ "$status" -ne 0 ]
  assert_contains "already resumed"
}

@test "recording the same attempt twice records it once" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_resume_record "$C"
  mi_state_resume_record "$C"
  n=0
  while IFS= read -r l; do
    case "$l" in "resumed"$'\t'*) n=$((n + 1)) ;; esac
  done <<< "$(mi_ledger_read)"
  [ "$n" -eq 1 ] || { echo "one attempt, expected one row, got ${n}" >&2; return 1; }
  run mi_state_plan "$C"
  [ "$output" = "exited" ]
}

@test "forget drops the attempt record too, and only for the container it names" {
  local C2="${C}-two"
  mi_rt_container_create "$C2" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce=cn2 >/dev/null
  mi_state_commit "$C" running alias "$NET"
  mi_state_commit "$C2" running alias "$NET"
  mi_state_resume_record "$C"
  mi_state_resume_record "$C2"
  mi_state_forget "$C"
  n=0
  while IFS= read -r l; do
    case "$l" in "resumed"$'\t'*) n=$((n + 1)) ;; esac
  done <<< "$(mi_ledger_read)"
  [ "$n" -eq 1 ] || { echo "expected only the other container's attempt to survive, got ${n} row(s)" >&2; return 1; }
  run mi_state_plan "$C2"
  [ "$output" = "exited" ] || { echo "one container's forget retired another's attempt: $output" >&2; return 1; }
}

@test "the row says WHICH of the two answers this intent gave" {
  # Both values are load-bearing and they are different facts: `owed` says a live verification is
  # outstanding, `none` says the caller declared there is none to perform. A writer that recorded one
  # of them for both cases would put the row back to carrying no information — an absence with a
  # field name in front of it.
  mi_state_commit "$C" running alias "$NET"
  rec="$(mi_led_find desired container "$C")"
  run mi_led_field "$rec" verify
  [ "$status" -eq 0 ]
  [ "$output" = owed ] || { echo "a commit that owes a check recorded verify='$output'" >&2; return 1; }
  mi_state_outstanding_clear "$C" alias "$NET"
  mi_state_commit "$C" running +none
  rec="$(mi_led_find desired container "$C")"
  run mi_led_field "$rec" verify
  [ "$status" -eq 0 ]
  [ "$output" = none ] || { echo "a declared-nothing commit recorded verify='$output'" >&2; return 1; }
}
