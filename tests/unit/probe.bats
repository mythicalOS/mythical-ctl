#!/usr/bin/env bats
# D49 — the probe. "A temporary container with DNS tools" is not a specification; these are the
# properties that make it one: the image comes from the verified family index, the command set is
# closed, an unobtainable probe STOPS rather than falls back, and every run is recorded under
# write-ahead intent and accounted for afterwards.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire
  IDENT="$(mi_ident_ensure)"
  NET="$(mi_rt_network_create "mythical-${IDENT}-net" "$IDENT" nnet)"
  # A verified index naming the probe image.
  PROBE_REF="$(a_digestref probe)"
  write_index_fixture "$MYTHICAL_HOME/index" "probe_image=$PROBE_REF"
  install_helper_img
}
teardown() { mi_lock_release; teardown_test_env; }

# Append a row to the ledger verbatim, keeping every row already there — the only way to build the
# state a restored or foreign ledger produces, which the reads below have to survive.
put_raw() { { mi_ledger_read; printf '%s\n' "$1"; } | mi_ledger_write; }

@test "the probe image comes from the family index, not from a constant" {
  run mi_probe_image "$MYTHICAL_HOME/index"
  [ "$status" -eq 0 ]
  [ "$output" = "$PROBE_REF" ]
}

@test "an index that does not verify yields no probe image" {
  printf 'tampered\n' >> "$MYTHICAL_HOME/index"
  run mi_probe_image "$MYTHICAL_HOME/index"
  [ "$status" -ne 0 ]
}

# The amendment this task makes to mi_index_spec, asserted at the door that depends on it. `opt`
# instead of `one` for either key passes every other test in this file: the fixtures all carry both.
@test "an index that names neither pinned helper image is refused — the keys are REQUIRED" {
  local d="$MYTHICAL_HOME" pol
  pol="$(printf 'b%.0s' $(seq 1 64))"
  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\n'
    printf 'policy_digest=%s\n' "$pol"
    printf 'copy_image=%s\n' "$(a_digestref copy)"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_probe_image "$d/index"
  [ "$status" -ne 0 ]
  assert_contains "probe_image"

  { printf 'mythical-index 1\nversion=1\nexpires=4102444800\n'
    printf 'policy_digest=%s\n' "$pol"
    printf 'probe_image=%s\n' "$(a_digestref probe)"; } > "$d/index"
  mi_trust_anchor_set "$(mi_digest "$d/index")"
  run mi_probe_image "$d/index"
  [ "$status" -ne 0 ]
  assert_contains "copy_image"
}

# D22: a tag is not a digest. `digestref` refuses one by construction, which is why the probe image
# cannot be `latest` even if someone publishes an index saying so.
@test "an index naming a FLOATING tag for the probe image is refused" {
  write_index_fixture "$MYTHICAL_HOME/index" "probe_image=ghcr.io/mythicalos/probe:latest"
  run mi_probe_image "$MYTHICAL_HOME/index"
  [ "$status" -ne 0 ]
  assert_contains "probe_image"
}

@test "an UNOBTAINABLE probe image reports unavailable — it never falls back" {
  FAKE_DOCKER_PULL=notfound run mi_probe_available "$MYTHICAL_HOME/index"
  [ "$status" -ne 0 ]
  assert_contains "cannot be obtained"
  run grep -aiE 'busybox|alpine|fallback' <<<"$output"
  [ "$status" -ne 0 ]
}

# §7.3/§10a: the registry's own words reach the operator. Folding an auth failure into a generic
# "cannot be obtained" sends someone debugging a broken publication to look at their network.
@test "a pull refusal keeps the registry's own wording" {
  FAKE_DOCKER_PULL=auth run mi_probe_available "$MYTHICAL_HOME/index"
  [ "$status" -ne 0 ]
  assert_contains "denied"
}

@test "an already-present probe image needs no pull" {
  mi_rt_image_pull "$PROBE_REF" >/dev/null
  FAKE_DOCKER_PULL=neterr run mi_probe_available "$MYTHICAL_HOME/index"
  [ "$status" -eq 0 ]
}

@test "selfcheck resolves the probe's OWN alias on the target network" {
  run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -eq 0 ]
}

@test "selfcheck FAILING is distinguishable from a product not running" {
  HELPER_SELFCHECK=fail run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ]
  assert_contains "DNS on this network"
}

# AN EXIT STATUS IS NOT A RESULT. The helper interface STATES its answer (`selfcheck=ok`), so that is
# what has to be present — a pinned image that regressed to exiting 0 while saying nothing, or while
# saying `selfcheck=fail`, would otherwise be read as a verified network by the one function whose
# whole purpose is to decide whether DNS works. This is the rule mi_probe_resolve already applies to
# `alias=`, at the two doors that did not have it.
@test "selfcheck refuses a zero-exit helper that does not STATE selfcheck=ok" {
  fake_helper 'exit 0'
  run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "a silent zero-exit helper was accepted as a verified network" >&2; return 1; }
  assert_contains "selfcheck"

  fake_helper 'printf "selfcheck=fail\n"; exit 0'
  run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "'selfcheck=fail' with exit 0 was accepted as a verified network" >&2; return 1; }
}

# The helper's contract is 0/1/2. An OUT-OF-CONTRACT status is a failed check like any other, and it
# is SAID so — what it must never become is this module's own "the container could not be accounted
# for", which sends an operator to 'state repair' over an object that was reaped normally and no
# longer exists.
#
# The middle assertion is the one that matters and the one a first draft of this test did not have:
# asserting only the two ABSENCES passes just as well when an out-of-contract status collides with
# this module's own rc 4, and the failure is then reported by nobody at all — no verdict, no warning,
# a silent non-zero. Measured: that draft survived the mutation that removes the normalisation.
@test "an out-of-contract helper status is a REPORTED failed check, not an unaccounted-for container" {
  fake_helper 'exit 4'
  run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "an out-of-contract helper status was accepted as a verified network" >&2; return 1; }
  assert_contains "not a status the helper contract defines"
  assert_contains "DNS on this network"
  case "$output" in
    *"could not be accounted for"*)
      echo "a reaped container was reported as outstanding: $output" >&2; return 1 ;;
  esac
}

@test "resolve returns the address for an alias" {
  HELPER_RESOLVE_ADDR=10.88.1.7 run mi_probe_resolve "$MYTHICAL_HOME/index" "$NET" p1
  [ "$status" -eq 0 ]
  [ "$output" = "10.88.1.7" ]
}

@test "resolve reports 3 when the alias does not resolve, distinctly from a probe failure" {
  HELPER_RESOLVE_ADDR= run mi_probe_resolve "$MYTHICAL_HOME/index" "$NET" p1
  [ "$status" -eq 3 ]
}

# An answer is only an answer to the question that was asked. A reply about another alias is a
# malfunctioning probe, not this alias's address — and returning it would hand D42/D48's rebind an
# address belonging to a different container.
@test "an answer about a DIFFERENT alias is refused, never returned as this one's address" {
  fake_helper 'printf "alias=other\naddress=10.88.1.9\n"'
  run mi_probe_resolve "$MYTHICAL_HOME/index" "$NET" p1
  [ "$status" -eq 1 ]
  assert_contains "answered about"
}

# A missing address FIELD is a broken probe; an EMPTY address is the documented "did not resolve".
# Folding the first into the second reports a working probe that found nothing, and D48 then treats
# a malfunctioning verifier as a verification result.
@test "an answer carrying no address field at all is a probe failure, not a non-resolving alias" {
  fake_helper 'printf "alias=p1\n"'
  run mi_probe_resolve "$MYTHICAL_HOME/index" "$NET" p1
  [ "$status" -eq 1 ]
}

@test "the probe command set is CLOSED — nothing manifest-supplied reaches it" {
  run mi_rt_run_helper "$PROBE_REF" "$NET" - n1 'sh -c id'
  [ "$status" -ne 0 ]
  assert_contains "not a helper command"
}

@test "a probe run is recorded under write-ahead intent and cleaned up when it completes" {
  before="$(mi_intent_all | grep -ac 'class=probe' || true)"
  mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  after="$(mi_intent_all | grep -ac 'class=probe' || true)"
  [ "$before" = "$after" ]
}

# `--rm` is half of what makes the pinned helper safe to run at all (D49): no helper may outlive its
# own invocation. Dropping it from the runtime adapter leaves the container behind — which the reap
# below would then remove, so "no container survives" alone would not notice. The second assertion is
# what pins the flag: on the ordinary path nothing has to be swept up, because there is nothing there.
@test "a completed probe removes ITSELF — no container survives and nothing sweeps one up" {
  mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  run ls "$FAKE_DOCKER_STATE/containers"
  [ -z "$output" ] || { echo "a probe container survived its own run: $output" >&2; return 1; }
  run grep -a 'container rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ] || { echo "the probe had to be swept up rather than removing itself: $output" >&2; return 1; }
}

# The same rule on the run's OWN path, not only in the sweep. The intent is the only thing that
# accounts for a container that survived, so it may go only once the runtime has SAID the container is
# gone. Here the daemon stops answering between the run and that question: the container's fate is
# unknown, so the record stays.
#
# AND THE CALL ITSELF FAILS. Keeping the intent while returning 0 tells the caller both "there is
# nothing outstanding" (rc 0) and "there might be" (the record) at once, and the caller acts on the
# rc: it proceeds, believing a probe container nobody can account for was cleaned up. The status
# assertion is not decoration — without it this test passes with that defect installed.
@test "a run whose container could not be accounted for afterwards KEEPS its intent AND FAILS" {
  mi_rt_image_pull "$PROBE_REF" >/dev/null     # so the call count below is the run's own
  # Calls made while the knob is set: 1 image inspect (present), 2 container run. The reap's inspect
  # is the third, and its ping the fourth — both die, so mi_rt_inspect reports "could not ask".
  FAKE_DOCKER_DOWN_AFTER=2 run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "a run whose container could not be accounted for reported success" >&2; return 1; }
  run mi_intent_all
  assert_contains "class=probe"
}

# ...and it fails as the fact it IS. The probe answered here — the daemon died afterwards — so
# claiming DNS is broken would send an operator to debug a network that was never shown to be at
# fault. The two facts are reported separately or one of them is a lie.
@test "an unaccountable probe container is not reported as a DNS verdict" {
  mi_rt_image_pull "$PROBE_REF" >/dev/null
  FAKE_DOCKER_DOWN_AFTER=2 run mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  case "$output" in
    *"DNS on this network"*)
      echo "an unaccounted-for container was reported as broken DNS: $output" >&2; return 1 ;;
  esac
  assert_contains "could not be accounted for"
}

# §6a/§6b: a probe container is an object like any other while it exists. Without the installation
# label a leaked one is anonymous — a nonce says WHICH object, never WHOSE — so nothing could ever
# show it to be ours, and without the derived name §6b.2's classifier reads it as a stranger's.
@test "the probe container is NAMED and LABELLED for this installation, like any other object" {
  mi_probe_selfcheck "$MYTHICAL_HOME/index" "$NET"
  run grep -a 'container run' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  assert_contains "--label mythicalos.installation=${IDENT}"
  assert_contains "--name mythical-${IDENT}-probe-"
}

@test "a leftover probe from an earlier crash is recognised by its label and cleaned up" {
  n="$(mi_nonce_new)"
  mi_intent_open probe "mythical-${IDENT}-probe-${n}" "$n"
  printf 'labels=mythicalos.installation=%s;mythicalos.nonce=%s;\nstate=exited\nnets=\naliases=\n' \
    "$IDENT" "$n" > "$FAKE_DOCKER_STATE/containers/mythical-${IDENT}-probe-${n}"
  run mi_probe_cleanup
  [ "$status" -eq 0 ]
  run mi_intent_find probe "mythical-${IDENT}-probe-${n}"
  [ "$status" -eq 3 ]
  [ ! -e "$FAKE_DOCKER_STATE/containers/mythical-${IDENT}-probe-${n}" ]
}

@test "cleanup never touches a probe belonging to another installation" {
  printf 'labels=mythicalos.installation=other;mythicalos.nonce=zz;\nstate=exited\n' \
    > "$FAKE_DOCKER_STATE/containers/mythical-other-probe-zz"
  mi_probe_cleanup
  [ -e "$FAKE_DOCKER_STATE/containers/mythical-other-probe-zz" ]
}

# The same rule at the name our OWN record points at. A name can be reassigned (§6a), so a container
# standing there is not evidence that it is ours — and dropping the record would be forgetting an
# object on the strength of a label that says someone else's.
@test "cleanup refuses a container at OUR recorded name that is labelled for another installation" {
  n="$(mi_nonce_new)"
  name="mythical-${IDENT}-probe-${n}"
  mi_intent_open probe "$name" "$n"
  printf 'labels=mythicalos.installation=other;mythicalos.nonce=%s;\nstate=exited\n' "$n" \
    > "$FAKE_DOCKER_STATE/containers/${name}"
  run mi_probe_cleanup
  [ "$status" -ne 0 ]
  [ -e "$FAKE_DOCKER_STATE/containers/${name}" ] \
    || { echo "another installation's container was removed" >&2; return 1; }
  run mi_intent_find probe "$name"
  [ "$status" -eq 0 ] \
    || { echo "the intent was dropped for an object that was never removed" >&2; return 1; }
}

# "I could not ask" is never "there is nothing there". A daemon that cannot answer leaves the
# container where it is AND leaves the record that accounts for it where it is.
@test "a leftover the runtime could not be asked about is PRESERVED, never forgotten" {
  n="$(mi_nonce_new)"
  name="mythical-${IDENT}-probe-${n}"
  mi_intent_open probe "$name" "$n"
  printf 'labels=mythicalos.installation=%s;mythicalos.nonce=%s;\nstate=exited\n' "$IDENT" "$n" \
    > "$FAKE_DOCKER_STATE/containers/${name}"
  FAKE_DOCKER_DOWN=1 run mi_probe_cleanup
  [ "$status" -ne 0 ]
  [ -e "$FAKE_DOCKER_STATE/containers/${name}" ]
  run mi_intent_find probe "$name"
  [ "$status" -eq 0 ] \
    || { echo "an intent was dropped on the strength of a question nobody answered" >&2; return 1; }
}

# Every removal below is scoped by the installation identity. A ledger that cannot say which
# installation this is cannot say which objects are ours, so it cannot say that none of them are.
@test "cleanup refuses when the installation identity cannot be read" {
  put_raw "identity"$'\t'"id=iotherone"
  run mi_probe_cleanup
  [ "$status" -ne 0 ]
}

@test "egress is reported as a distinct check" {
  run mi_probe_egress "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -eq 0 ]
  HELPER_EGRESS=fail run mi_probe_egress "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ]
}

# The same door, the same rule: `egress=ok` is the stated result and nothing else is one. An answer
# to ANOTHER check is not an answer to this one either — the third case below exits 0 and states a
# perfectly good `selfcheck=ok`, which says nothing whatever about egress.
@test "egress refuses a zero-exit helper that does not STATE egress=ok" {
  fake_helper 'exit 0'
  run mi_probe_egress "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "a silent zero-exit helper was accepted as working egress" >&2; return 1; }
  assert_contains "egress"

  fake_helper 'printf "egress=fail\n"; exit 0'
  run mi_probe_egress "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "'egress=fail' with exit 0 was accepted as working egress" >&2; return 1; }

  fake_helper 'printf "selfcheck=ok\n"; exit 0'
  run mi_probe_egress "$MYTHICAL_HOME/index" "$NET"
  [ "$status" -ne 0 ] \
    || { echo "an answer about another check was accepted as working egress" >&2; return 1; }
}
