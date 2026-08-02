#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"
  MI_CONFIRM=yes; export MI_CONFIRM     # non-interactive confirmation, tests only
}
teardown() { teardown_test_env; }

@test "a NEWER ledger schema is refused, naming the required version (already Plan 1; asserted here)" {
  mi_lock_acquire; mi_ident_ensure >/dev/null; mi_lock_release
  sed 's/schema=1/schema=99/' "$MYTHICAL_HOME/.state/ledger" > "$MYTHICAL_HOME/.state/l2"
  mv "$MYTHICAL_HOME/.state/l2" "$MYTHICAL_HOME/.state/ledger"
  run mi_ident_get
  [ "$status" -eq 1 ]
}

@test "a schema migration is a no-op at schema 1 and does not rewrite the ledger" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  h="$(mi_digest "$MYTHICAL_HOME/.state/ledger")"
  run mi_schema_migrate
  [ "$status" -eq 0 ]
  [ "$h" = "$(mi_digest "$MYTHICAL_HOME/.state/ledger")" ]
  mi_lock_release
}

@test "repair candidates are the DISTINCT installation identities present in object labels" {
  mi_rt_volume_create v1 n1 instA
  mi_rt_volume_create v2 n2 instA
  mi_rt_volume_create v3 n3 instB
  run mi_repair_candidates
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
  assert_contains instA
  assert_contains instB
}

@test "EXACTLY ONE candidate is still shown and still confirmed — never silently adopted" {
  mi_rt_volume_create v1 n1 instA
  MI_CONFIRM=no run mi_repair_run "$IDX"
  [ "$status" -ne 0 ]
  assert_contains instA
  assert_contains "choose"
}

@test "two candidates: both shown, no action until one is chosen, the other's objects untouched" {
  mi_rt_volume_create v1 n1 instA
  mi_rt_volume_create v3 n3 instB
  MI_CONFIRM=no run mi_repair_run "$IDX"
  [ "$status" -ne 0 ]
  assert_contains instA
  assert_contains instB
  [ -e "$FAKE_DOCKER_STATE/volumes/v3" ]
}

@test "choosing an identity rebuilds provenance for containers, volumes and networks from labels" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_volume_create v1 n1 instA
  # `container create` refuses an image that was never pulled, exactly as a real daemon does.
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_repair_run "$IDX" instA
  run mi_ident_get
  [ "$output" = instA ]
  run mi_prov_find volume v1
  [ "$status" -eq 0 ]
  run mi_prov_find network netA
  [ "$status" -eq 0 ]
  run mi_prov_find container c1
  [ "$status" -eq 0 ]
}

@test "repair NEVER rebuilds image provenance and never claims to enumerate images" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" instA
  assert_contains "no image is deleted"
  assert_contains "cannot say which"
  load_mctl
  run mi_led_all image
  [ -z "$output" ]
}

@test "outstanding checks are initialized to {alias} for EVERY recovered container" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_repair_run "$IDX" instA
  run mi_state_outstanding c1
  assert_contains alias
}

@test "a RUNNING recovered container is verified IN THE SAME REPAIR RUN" {
  # A live verification names the probe container `mythical-<identity>-probe-<nonce>`, validating the
  # identity as a doc.sh `ident` (lowercase letter, then [a-z0-9-]) exactly as a minted identity always
  # is — so this fixture's chosen identity must actually be one, unlike the "instA" spelling other
  # repair tests use for identities that never reach probe naming.
  net="$(mi_rt_network_create netA insta nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=insta label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_prov_record_stub() { :; }
  mi_repair_run "$IDX" insta
  run mi_state_outstanding c1
  [ -z "$output" ]
}

@test "desired state is set from OBSERVATION and reported as inferred, listing each container" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_image_pull "$(a_digestref p2)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_create c2 "$(a_digestref p2)" "$net" p2 - label=installation=instA label=nonce=nc2 >/dev/null
  mi_rt_container_start c2 >/dev/null
  run mi_repair_run "$IDX" instA
  assert_contains "inferred from observation"
  assert_contains c1
  assert_contains c2
  load_mctl
  run mi_state_desired_get c1
  [ "$output" = stopped ]
  run mi_state_desired_get c2
  [ "$output" = running ]
}

@test "trust floors are RESET, with the rollback window stated and confirmed" {
  mi_rt_volume_create v1 n1 instA
  MI_CONFIRM=no run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "rollback"
  run mi_repair_run "$IDX" instA
  [ "$status" -eq 0 ]
}

@test "ZERO candidates offers confirmed REINITIALIZATION rather than deadlocking" {
  printf 'X=1\n' > "$MYTHICAL_HOME/brokkr.conf"
  run mi_repair_run "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "reinitializ"
  assert_contains "will not be recognised"
  load_mctl
  run mi_ident_get
  [ "$status" -eq 0 ]
}

@test "reinitialization is REFUSED when candidates were found — then the answer is to choose one" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" --reinitialize
  [ "$status" -ne 0 ]
  assert_contains "choose"
}

@test "repair refuses while a LIVE lock is held" {
  mi_lock_acquire
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  mi_lock_release
}

@test "repair states plainly that it cannot prove nothing is in flight" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" instA
  assert_contains "cannot prove"
}

@test "an object arriving AFTER a repair that RETAINED the identity is unrecorded same-identity" {
  mi_rt_volume_create v1 n1 instA
  mi_repair_run "$IDX" instA
  mi_rt_volume_create late n9 instA
  load_mctl; mi_lock_acquire
  run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains unrecorded
  mi_lock_release
}

@test "an object arriving after a REINITIALIZING repair is foreign-identity, listed, never touched" {
  # instOLD's object must arrive AFTER the reinitializing repair, not before it: were it created first
  # it would be a genuine candidate, and mi_repair_run --reinitialize correctly REFUSES to reinitialize
  # over an existing candidate (see "reinitialization is REFUSED when candidates were found" above) —
  # reinitializing anyway would strand it silently instead of reporting it.
  printf 'X=1\n' > "$MYTHICAL_HOME/brokkr.conf"
  mi_repair_run "$IDX" --reinitialize || true
  mi_rt_volume_create old n1 instOLD
  load_mctl; mi_lock_acquire
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
  run mi_unaccounted_scan
  assert_contains unattributed
  [ -e "$FAKE_DOCKER_STATE/volumes/old" ]
  mi_lock_release
}

@test "the non-owned reference is reconstructed from mythical.conf, not from the ledger" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_rt_volume_create v1 n1 instA
  mi_repair_run "$IDX" instA
  load_mctl
  run mi_net_ref_get
  [ "$status" -eq 0 ]
  run mi_led_find netref key family
  assert_contains "owned=no"
}

@test "reconstruction that finds a DIFFERENT network than the containers' stops and enters the migration" {
  src="$(mi_rt_network_create oldnet "" x)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$src" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  assert_contains "differs"
  load_mctl
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  # The reference must name the OBSERVED network, and the intent must name it as the SOURCE.
  run mi_net_ref_get
  [ "$output" = "$src" ]
  run mi_led_find netmig key family
  assert_contains "source=$src"
}

@test "containers disagreeing about their network stops and reports — a migration cannot pick a side" {
  a="$(mi_rt_network_create na "" x)"; b="$(mi_rt_network_create nb "" y)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_image_pull "$(a_digestref p2)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$a" p1 - label=installation=instA label=nonce=n1 >/dev/null
  mi_rt_container_create c2 "$(a_digestref p2)" "$b" p2 - label=installation=instA label=nonce=n2 >/dev/null
  mi_rt_network_create opnet "" z >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "already split"
}

@test "abandon-intent refuses before the grace period and succeeds after, with confirmation" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  n="$(mi_nonce_new)"; mi_intent_open network net1 "$n"; mi_lock_release
  run mi_verb_abandon_intent network net1
  [ "$status" -ne 0 ]
  MI_INTENT_GRACE=0 run mi_verb_abandon_intent network net1
  [ "$status" -eq 0 ]
}

@test "abandon-intent will NOT run without confirmation" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  n="$(mi_nonce_new)"; mi_intent_open network net1 "$n"; mi_lock_release
  MI_CONFIRM=no MI_INTENT_GRACE=0 run mi_verb_abandon_intent network net1
  [ "$status" -ne 0 ]
}

# --- codex round 1: unchecked reads / rc-3-vs-rc-1 conflation, fail-closed pins ---------------------
# Each of these makes ONE specific inspect/ledger read fail with "the runtime could not answer" (rc 1
# — never "gone", rc 3), by counting invocations under FAKE_DOCKER_DOWN_AFTER the same way
# tests/unit/intent.bats and tests/unit/probe.bats already do. Before the fix each of these silently
# read the failure as an empty value — "no label", "no identity", "nothing owed" — and proceeded; each
# must now FAIL CLOSED and say so, never quietly drop or adopt installation state.

@test "candidate discovery FAILS CLOSED when an object's installation label cannot be read" {
  mi_rt_volume_create v1 n1 instA
  # Call 1: container ls · call 2: volume ls · call 3: the volume's install-label inspect — the one
  # this pins. Before the fix, `2>/dev/null || true` turned that failure into an empty label, v1 was
  # silently omitted, and discovery could report zero or one candidate with an object it never asked
  # about left out entirely.
  FAKE_DOCKER_DOWN_AFTER=2 run mi_repair_candidates
  [ "$status" -ne 0 ]
  assert_contains "could not be asked for its installation label"
  assert_contains "cannot prove which identities are present"
}

@test "the post-reset rebuild loop FAILS CLOSED when an object's installation label cannot be read" {
  mi_rt_volume_create v1 n1 instA
  # The ledger has already been reset for identity instA by the time this fails (calibrated: the 11th
  # runtime call under the knob is v1's install-label read inside the rebuild loop, AFTER candidate
  # discovery already succeeded once against it). Before the fix this silently skipped v1 — the ledger
  # ends up with an identity and no provenance for the object that identity was chosen for, reported
  # as a completed repair.
  FAKE_DOCKER_DOWN_AFTER=10 run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "could not be asked for its installation label"
  assert_contains "already been reset"
  load_mctl
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
}

@test "network reconstruction FAILS CLOSED when a container's installation label cannot be read" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  # Calibrated to land on _mi_repair_netref's OWN read of c1's install label (after candidate discovery
  # and the whole rebuild loop have already succeeded once against every object). Before the fix this
  # silently skipped c1 from the "do the containers agree" comparison, so repair could record a clean
  # non-owned reference even though c1 might still be on the OLD network — a split fleet the ledger
  # would then report as healthy.
  FAKE_DOCKER_DOWN_AFTER=24 run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "could not be asked for its installation label"
  assert_contains "fleet agrees"
  load_mctl
  run mi_net_ref_get
  [ "$status" -eq 3 ]
}

@test "'+none' is never recorded from an unread network-attachment state" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  # Calibrated to land on c1's c.nets read inside the desired-state block, after its provenance record
  # has already been written. Before the fix, a failed read here defaulted to empty and was recorded as
  # "+none" — asserting NO live verification is owed for a container that may well be attached and
  # running, the opposite of the honest "outstanding" default this whole module exists to keep.
  FAKE_DOCKER_DOWN_AFTER=18 run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "'+none' from an unread state"
  load_mctl
  run mi_state_desired_get c1
  [ "$status" -eq 3 ]
}

@test "net rebind FAILS CLOSED on an unreadable/ambiguous migration record instead of starting fresh" {
  mi_lock_acquire
  mi_ident_ensure >/dev/null
  # A second raw `netmig key=family` row, written directly rather than through mi_led_put (which would
  # replace the first), makes the key AMBIGUOUS — mi_led_find's rc 1, never rc 3. Before the fix, a bare
  # `if mi_led_find …; then resume; fi` with no else treated rc 1 exactly like rc 3 (no migration) and
  # fell through to starting a brand-new rebind, discarding the only record of an in-flight one.
  mi_led_put netmig key family "key=family" "phase=2" "source=srcid" "target=tgtid" "containers="
  { mi_ledger_read; printf 'netmig\tkey=family\tphase=2\tsource=srcid\ttarget=other\tcontainers=\n'; } | mi_ledger_write
  mi_lock_release
  printf 'MYTHICAL_NET=whatever\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_verb_net_rebind "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "could not be read from the"
  assert_contains "ledger"
}

# --- codex round 1: the two CLI dispatch bugs (bin/mythical-ctl) ------------------------------------
# These go through run_mctl — the REAL entrypoint as a subprocess — because the bug is in main()'s own
# argument handling, not in the library functions repair.bats calls directly everywhere else.

@test "CLI: 'state repair <identity>' threads the chosen identity through to the library" {
  mi_rt_volume_create v1 n1 instA
  # Before the fix, main() parsed products[1] (the identity) but called mi_verb_state_repair "$idx"
  # WITHOUT it, so the library saw no choice at all and printed the "choose one explicitly" refusal
  # even though the operator DID choose — the one documented safe recovery path was unusable from the
  # CLI.
  run_mctl state repair instA --index "$IDX"
  assert_ok
  load_mctl
  run mi_ident_get
  [ "$output" = instA ]
}

@test "CLI: 'state abandon-intent <class> <name> <extra>' is a usage error, nothing attempted" {
  mi_lock_acquire
  mi_ident_ensure >/dev/null
  n="$(mi_nonce_new)"
  mi_intent_open network net1 "$n"
  mi_lock_release
  # Before the fix, main() read only products[1]/products[2] and silently dropped a third operand,
  # so this ran exactly as "state abandon-intent network net1" — a malformed invocation that still
  # confirmed and performed the state-deleting action.
  MI_CONFIRM=yes MI_INTENT_GRACE=0 run_mctl state abandon-intent network net1 extra-garbage --index "$IDX"
  assert_fail "$MI_EX_USAGE"
  load_mctl
  run mi_intent_find network net1
  [ "$status" -eq 0 ]
}

# --- codex round 2: 3 more HIGH findings + the net-rebind surplus-operand CLI bug ------------------

@test "a ledger with a NEWER schema is refused by repair, never renamed aside as if corrupt" {
  mi_lock_acquire; mi_ident_ensure >/dev/null; mi_lock_release
  ledger="$MYTHICAL_HOME/.state/ledger"
  sed 's/schema=1/schema=99/' "$ledger" > "$MYTHICAL_HOME/.state/l2"
  mv "$MYTHICAL_HOME/.state/l2" "$ledger"
  before="$(cat "$ledger")"
  # Before the fix, `_mi_repair_reset_ledger` could tell only "mi_ledger_read failed", never WHY — a
  # checksum mismatch, a truncated file, and a schema NEWER than this build understands all produce
  # the identical subshell exit status. Reached through the zero-candidates reinitialize path (no
  # runtime object carries a label here), it would have renamed this STILL-VALID, merely-newer ledger
  # to `.corrupt.$$` and replaced it with an empty one — discarding whatever a newer mythical-ctl had
  # already recorded, through the repair door instead of the read door mi_ledger_read itself guards.
  run mi_repair_run "$IDX" --reinitialize
  [ "$status" -ne 0 ]
  assert_contains "newer than this build"
  # The file is untouched: same path, same bytes, and no `.corrupt.*` sibling was created.
  [ -f "$ledger" ]
  [ "$(cat "$ledger")" = "$before" ]
  corrupt_count=0
  for f in "$MYTHICAL_HOME/.state/"ledger.corrupt.*; do [ -e "$f" ] && corrupt_count=$((corrupt_count + 1)); done
  [ "$corrupt_count" -eq 0 ]
}

@test "candidate discovery keeps DISTINCT identities distinct even when one is a prefix of another" {
  # "A B" and "A": a space-padded `case " $seen " in *" $id "*)` dedup treats "A" as already counted
  # once "A B" is in the set, because " A " is a literal substring of " A B ". Before the fix, "A"
  # vanished from the candidate list entirely — two distinct installations collapsed into one, which
  # is exactly what the exactly-one-candidate adoption rule depends on never happening.
  mi_rt_volume_create v1 n1 "A B"
  mi_rt_volume_create v2 n2 "A"
  run mi_repair_candidates
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
  assert_contains "A B"
}

@test "a repair-reconstructed network migration never records an empty fleet" {
  src="$(mi_rt_network_create oldnet "" x)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$src" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  # Before the fix, the migration record this writes hardcoded `containers=` with nothing after the
  # `=` — ALWAYS, regardless of how many containers were actually found — so 'net rebind' would read
  # an empty fleet back from the very record that is supposed to describe it and have nothing to move.
  run mi_repair_run "$IDX" instA
  [ "$status" -eq 0 ]
  load_mctl
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  assert_contains "containers=c1"
}

@test "CLI: 'net rebind <extra>' is a usage error, nothing done" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  # Before the fix, main()'s "net" case checked only that products[0] was "rebind" and never the
  # count — a surplus operand was silently dropped and the rebind performed anyway, which (with
  # MI_CONFIRM=yes, a non-interactive operator or a script) moves the whole fleet's network attachment
  # on a malformed invocation.
  MI_CONFIRM=yes run_mctl net rebind extra-garbage --index "$IDX"
  assert_fail "$MI_EX_USAGE"
  load_mctl
  run mi_net_ref_get
  [ "$status" -eq 3 ]
}

# --- codex round 3: 3 more HIGH findings, same class, plus a mechanical $(/pipe/|| true audit --------

@test "containers that exist but share no attached network are NOT recorded as a clean reference" {
  # A container with zero network attachments at all: c.nets reads back successfully (rc 0) but
  # EMPTY, which is a different fact from "no containers carry this identity" — $fleet is non-empty
  # (the container exists and carries the label) while $common stays empty (nothing to agree on).
  # Before the fix, `[ -z "$common" ]` alone took the "no containers yet" branch and recorded 'opnet'
  # as a clean family-network reference anyway — the recovered container is not attached to it at
  # all, the exact split state D46 exists to prevent, reached from the empty-fleet branch instead of
  # the disagreement branch a few lines above it.
  net="$(mi_rt_network_create netA "" x)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_network_disconnect "$net" c1 >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "none of them share a single attached"
  load_mctl
  run mi_net_ref_get
  [ "$status" -eq 3 ]
}

@test "a real candidate is never treated as zero and silently reinitialized" {
  # The count that decides between "found N, choose one" and "found none, offer to reinitialize" is
  # derived from mi_repair_candidates' own output by counting non-empty lines in pure shell — never a
  # `grep` pipeline whose own failure (this environment's own ugrep-vs-NUL-byte hazard is exactly this
  # class: a silent no-match that is indistinguishable from a genuine zero) could collapse a real
  # candidate down to a count of zero and, with MI_CONFIRM=yes already set here, mint a brand-new
  # identity and reset the ledger over it instead of asking which one to choose.
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX"
  [ "$status" -ne 0 ]
  assert_contains instA
  assert_contains "found 1 installation identity"
  case "$output" in *reinitializ*) echo "unexpectedly took the reinitialize path" >&2; false ;; esac
  load_mctl
  run mi_ident_get
  [ "$status" -eq 3 ]
}

@test "a reconstructed migration's fleet list names EVERY container, never a truncated prefix" {
  # Two containers on the source network, so the migration's containers= field has to hold both. The
  # historical risk this pins: `flist="$(printf … | tr '\n' ',')"` was an unchecked external-process
  # transform — a partial write before a failure is captured by `$( … )` verbatim, and a TRUNCATED
  # `c1,` (only the first entry) looks like a complete, valid list to everything downstream. The fleet
  # is now joined in pure shell, which has no separate process whose failure could truncate it.
  src="$(mi_rt_network_create oldnet "" x)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_image_pull "$(a_digestref p2)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$src" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_create c2 "$(a_digestref p2)" "$src" p2 - label=installation=instA label=nonce=nc2 >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  [ "$status" -eq 0 ]
  load_mctl
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  assert_contains "containers=c1,c2"
}

# --- codex round 4: 2 HIGH + 1 MEDIUM recovery-SEMANTICS findings ------------------------------------

@test "adoption REFUSES an object whose nonce label is present-but-empty, never writes empty-nonce provenance" {
  # A container carrying the chosen identity's installation label, but no nonce label at all — the
  # inspect answers successfully (rc 0) with an empty value, which is a DIFFERENT fact from "could not
  # be asked" (already handled) or "the object is gone". Before the fix this empty value was recorded
  # as provenance verbatim (`nonce=`), and every later authority check (mi_prov_authority) refuses an
  # empty-nonce record outright — so the object repair had just claimed to recover became permanently
  # unownable: no deletion, no state commit, nothing could act on it through this installer again.
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA >/dev/null
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "no nonce label at all"
  load_mctl
  run mi_prov_find container c1
  [ "$status" -eq 3 ]
}

@test "the PUBLIC verb rejects a surplus operand itself, at the library boundary, nothing attempted" {
  # Before the fix, mi_repair_run and mi_verb_state_repair checked only a LOWER bound ($# -lt 1), so a
  # surplus third operand passed straight through: mi_verb_state_repair "$IDX" instA stray silently
  # used only the first two and, with MI_CONFIRM=yes already set here, would have reset the ledger and
  # adopted instA rather than returning usage. bin/mythical-ctl's own argument parser already rejects
  # this at the CLI, but the operator-verb contract (wrong arity -> rc 2, nothing attempted) has to
  # hold for a caller of the library verb directly too, not only through the CLI in front of it.
  mi_rt_volume_create v1 n1 instA
  run mi_verb_state_repair "$IDX" instA stray
  [ "$status" -eq 2 ]
  load_mctl
  run mi_ident_get
  [ "$status" -eq 3 ]
  run mi_repair_run "$IDX" instA stray
  [ "$status" -ne 0 ]
}

@test "an ambiguous or unusable trust anchor is dropped, not silently preserved, and the loss is named" {
  # Two trust-anchor records in an otherwise checksum-valid ledger (crafted directly, bypassing
  # mi_trust_anchor_set's own validation — a restored or hand-assembled ledger is the realistic
  # source). Before the fix, _mi_repair_reset_ledger copied every raw line matching the trust-anchor
  # kind straight into the rebuild, so both survived; mi_trust_anchor_get's own ambiguity check would
  # then refuse every later trust read (mi_accept_index, at the very next probe or install) — wedging
  # an installation this repair had just reported fixed.
  mi_lock_acquire
  mi_ident_ensure >/dev/null
  d2="$(printf 'b%.0s' $(seq 1 64))"
  { mi_ledger_read; printf 'trust-anchor\tdigest=%s\n' "$d2"; } | mi_ledger_write
  mi_lock_release
  run mi_repair_run "$IDX" --reinitialize
  [ "$status" -eq 0 ]
  assert_contains "GUARANTEE LOST"
  assert_contains "trust anchors, not one"
  load_mctl
  run mi_trust_anchor_get
  [ "$status" -eq 3 ]
}

# --- codex round 5: 2 MEDIUM + 1 LOW, the last edges of the established classes ----------------------

@test "net rebind's NEW-rebind branch normalizes a leaked rc 3 to operational failure 1" {
  # The exact trigger (the migration record vanishing in the window between mi_net_ref_rebind's own
  # phase-1 write and mi_netmig_resume's internal re-read of it, both under the lock this verb holds
  # throughout) is not constructible from outside a single synchronous call, so this pins the
  # NORMALIZATION directly: stub mi_net_ref_rebind to answer exactly as a raced call would (rc 3, "the
  # record I was just told exists is gone") and confirm the verb maps it to 1 rather than leaking 3 —
  # "not launched" is the wrong meaning for a race during a rebind this call itself just started.
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_net_ref_rebind() { return 3; }
  run mi_verb_net_rebind "$IDX"
  [ "$status" -eq 1 ]
}

@test "live-verify FAILS CLOSED on a present-but-invalid product label, never clears from a fallback alias" {
  # c1 carries a product label that is not a valid identifier (mi_name_alias itself refuses it), so the
  # canonical family alias cannot be derived — a DIFFERENT fact from "no product label at all" (D37's
  # legitimate fallback case). Before the fix, `mi_name_alias ... 2>/dev/null || true` swallowed that
  # failure and fell straight into the aliases-based reconstruction, which verifies whatever alias the
  # container actually carries (here, the same "p1" a normal bring-up would also have used) — so the
  # outstanding check was cleared as "confirmed" without ever checking the alias that matters.
  net="$(mi_rt_network_create netA insta nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=insta label=nonce=nc1 label=product=BadProduct >/dev/null
  mi_rt_container_start c1 >/dev/null
  run mi_repair_run "$IDX" insta
  [ "$status" -eq 0 ]
  assert_contains "not a valid identifier"
  load_mctl
  run mi_state_outstanding c1
  assert_contains alias
}

@test "the post-repair verify loop FAILS CLOSED on a container record with no readable name" {
  # A container-class record with no `name=` field is a state mi_prov_record itself never produces (it
  # always includes one) — reached here by stubbing it to omit the field for containers only, standing
  # in for a malformed record this same run just wrote reaching the live-verify loop. Before the fix,
  # `mi_led_field "$rec" name" || continue` silently skipped it and the repair still reported success —
  # the same "reports success while skipping a container's verification" gap round 4's nonce-absent
  # fix closed one field over (the sibling that report flagged forward).
  net="$(mi_rt_network_create netA insta nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=insta label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_prov_record() {
    local class="$1" name="$2" nonce="$3"; shift 3
    local gen
    gen="$(mi_prov_gen "$class" "$name")" || return 1
    gen=$((gen + 1))
    if [ "$class" = container ]; then
      mi_led_put object key "container:${name}" "key=container:${name}" "class=container" "nonce=${nonce}" "gen=${gen}" "$@"
    else
      mi_led_put object key "$(_mi_prov_key "$class" "$name")" "key=$(_mi_prov_key "$class" "$name")" "class=${class}" "name=${name}" "nonce=${nonce}" "gen=${gen}" "$@"
    fi
  }
  run mi_repair_run "$IDX" insta
  [ "$status" -ne 0 ]
  assert_contains "carries no readable name"
}
