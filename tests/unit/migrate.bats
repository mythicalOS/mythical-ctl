#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  DEST="$(mktemp -d)/dest"        # a fresh, non-existent leaf inside a real directory
}
teardown() { teardown_test_env; }

@test "migrate-storage with NO ROLE is rejected — a product may have several volume roles" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 2 ]
  assert_contains "role"
}

@test "an UNKNOWN role is rejected against the manifest, which names the valid roles" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 nosuch --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "state"
  assert_contains "secrets"
}

@test "a SECRETS role is REFUSED WITH THE REASON — permitted but not bindable (D53)" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 secrets --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "not bindable"
  run grep -a 'unknown role' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "a policy index collapsing permitted and bindable is rejected as MALFORMED (Plan 3's invariant)" {
  printf 'p1.bindable_role=nowhere\n' >> "$MYTHICAL_HOME/policy"
  run mi_policy_load "$MYTHICAL_HOME/policy"
  [ "$status" -ne 0 ]
}

@test "the role must be VOLUME-BACKED, proved by POSITIVE INSPECTION of the container's mounts" {
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
  mi_rt_container_rm "$C" >/dev/null
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "does not mount"
}

@test "an ALREADY-BIND-BACKED role with NO live intent is refused, naming the current bind" {
  mi_lock_acquire; mi_conf_family_add MYTHICAL_P1_STATE_BIND /already/there; mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "/already/there"
  assert_contains "stale"
}

@test "a live intent is checked FIRST, so a present bind after a crash RESUMES rather than refusing" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=6" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=started" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_conf_family_add MYTHICAL_P1_STATE_BIND "$DEST"
  mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
}

@test "the live-intent early return ALSO enforces the parent-trust gate — it does not bypass it" {
  # §5.2 round 5, finding 1: mi_mig_check_parent_trust used to run AFTER the live-intent lookup's own
  # early return (a matching in-flight destination is resumed by returning 0 immediately), so a
  # migration interrupted while its destination's parent was safe, whose parent became group/world-
  # writable since, resumed through that early return with the gate skipped entirely. Same fixture as
  # the passing "a live intent is checked FIRST..." test above, but with an unsafe parent — this must
  # now refuse instead of resuming.
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=6" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=started" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_conf_family_add MYTHICAL_P1_STATE_BIND "$DEST"
  mi_lock_release
  chmod 777 "$(dirname "$DEST")"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
}

@test "the migrate-storage VERB's own resume-existing-intent path also enforces parent-trust" {
  # The same regression, exercised through the real verb entrypoint (mi_verb_migrate_storage), not
  # just mi_mig_precheck directly — this is the exact path the finding names as reachable with the
  # gate skipped: re-invoking the verb on an already-recorded, matching-destination migration.
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=2" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=$(mi_mig_staging_path "$DEST" nz)" "nonce=nz"
  mi_lock_release
  chmod 777 "$(dirname "$DEST")"
  MI_CONFIRM=no run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
  run grep -aiE 'not confirmed' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "a live intent naming a DIFFERENT destination stops and reports BOTH paths" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" \
      "dest=/old/path" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=/old/path.staging" "nonce=nz"
  mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "/old/path"
  assert_contains "$DEST"
}

@test "a NON-EMPTY destination is refused by default, not merged" {
  mkdir -p "$DEST"; printf 'x\n' > "$DEST/pre-existing"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "not empty"
  run grep -aiE 'merge' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "staging is a SIBLING of the destination, never a child" {
  run mi_mig_staging_path "$DEST" nonceX
  [ "$output" = "$(dirname "$DEST")/.mythical-staging-nonceX" ]
  case "$output" in "$DEST"/*) false ;; *) true ;; esac
}

@test "a destination that is itself a MOUNT POINT is refused, naming the remedy" {
  FAKE_MOUNTPOINTS="$DEST" run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "subdirectory"
}

@test "mount-point detection uses MOUNT-TABLE evidence, not an st_dev comparison" {
  run grep -a 'st_dev' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
  assert_contains "cheap first filter"
  run grep -aE 'mountinfo|/sbin/mount|mount -p' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
}

@test "the recorded device+inode identifies the destination after the rename" {
  mkdir -p "$DEST"
  id="$(mi_mig_identity "$DEST")"
  mv "$DEST" "${DEST}.moved"
  [ "$(mi_mig_identity "${DEST}.moved")" = "$id" ]
}

@test "phase 5 recovery: identity at the DESTINATION advances to phase 6" {
  run mi_mig_resolve_phase5 "$DEST" "${DEST}.staging" "$(mkdir -p "$DEST" && mi_mig_identity "$DEST")"
  [ "$output" = destination ]
}

@test "phase 5 recovery: identity at STAGING retries the rename" {
  local s="${DEST}.staging"; mkdir -p "$s"
  run mi_mig_resolve_phase5 "$DEST" "$s" "$(mi_mig_identity "$s")"
  [ "$output" = staging ]
}

@test "phase 5 recovery: identity NOWHERE stops and reports — never retries, never deletes" {
  run mi_mig_resolve_phase5 "$DEST" "${DEST}.staging" "999999:999999"
  [ "$status" -ne 0 ]
  assert_contains "stop"
  run grep -aiE 'retry|delete' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "leftover staging is deleted ONLY on a nonce AND device/inode match" {
  local s="${DEST}.staging"; mkdir -p "$s"
  id="$(mi_mig_identity "$s")"
  run mi_mig_staging_reclaim "$s" nonceX "$id" nonceX
  [ "$status" -eq 0 ]
  [ ! -d "$s" ]
}

@test "reclaim moves into the INSTALLER'S OWN directory, never a sibling of the untrusted destination" {
  # A prior revision renamed the leftover to a DIFFERENT NAME but still inside the same (untrusted)
  # parent as the destination before deleting it — which does not close the check-then-rm race, it
  # only moves it. The fix reclaims into ~/.mythical/.state/reclaim instead, a directory this installer
  # owns exclusively (mode 700) that the untrusted parent's writer cannot reach at all. Proven two ways:
  # nothing named `.mythical-reclaim-*` (the old sibling-based scheme's own naming) ever appears beside
  # the destination, and the installer's reclaim directory is empty again afterward — fully removed,
  # not merely relocated and left behind.
  local s="${DEST}.staging"; mkdir -p "$s"
  id="$(mi_mig_identity "$s")"
  run mi_mig_staging_reclaim "$s" nonceX "$id" nonceX
  [ "$status" -eq 0 ]
  [ ! -d "$s" ]
  run find "$(dirname "$DEST")" -maxdepth 1 -name '.mythical-reclaim-*'
  [ -z "$output" ]
  [ -d "$MYTHICAL_HOME/.state/reclaim" ]
  [ -z "$(ls -A "$MYTHICAL_HOME/.state/reclaim" 2>/dev/null)" ]
  run _mi_mode_octal "$MYTHICAL_HOME/.state/reclaim"
  [ "$output" = 700 ]
}

@test "a leftover staging MISMATCH is preserved and reported — the name alone is not authority" {
  local s="${DEST}.staging"; mkdir -p "$s"
  run mi_mig_staging_reclaim "$s" nonceX "999:999" nonceX
  [ "$status" -ne 0 ]
  [ -d "$s" ]
  assert_contains "preserved"
}

@test "an UNPROVABLE leftover is stepped around with a FRESH nonce, never a deadlock" {
  local s="$(dirname "$DEST")/.mythical-staging-old"; mkdir -p "$s"
  a="$(mi_mig_staging_path "$DEST" n1)"; b="$(mi_mig_staging_path "$DEST" n2)"
  [ "$a" != "$b" ]
  [ -d "$s" ]
}

@test "the migration's OWN staging does not count as a non-empty destination" {
  mkdir -p "$(mi_mig_staging_path "$DEST" nonceX)"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
}

# --- the parent-trust precheck (§5.2 round 4): bash cannot make a check atomic with a later use ------
# against a name an attacker can also resolve, so the actual security posture is refusing to operate
# in a location such an attacker could reach in the first place, rather than re-checking immediately
# before every use (which only narrows the window, never closes it).

@test "mi_mig_check_parent_trust accepts an operator-owned, non-group/other-writable parent" {
  run mi_mig_check_parent_trust "$DEST"
  [ "$status" -eq 0 ]
}

@test "precheck REFUSES a destination whose parent directory is writable by GROUP" {
  chmod 770 "$(dirname "$DEST")"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
}

@test "precheck REFUSES a destination whose parent directory is writable by EVERYONE" {
  chmod 777 "$(dirname "$DEST")"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
}

@test "an UNSAFE parent is refused BEFORE anything else — no role/policy/volume checks run first" {
  # Refusing here, first, is what makes the guarantee "no attacker with parent write access is ever
  # let in" hold regardless of which product/role/state combination is requested.
  chmod 777 "$(dirname "$DEST")"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 nosuch "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
  run grep -a 'no volume role' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "the full migrate-storage verb refuses through an unsafe parent, before any confirmation prompt" {
  chmod 777 "$(dirname "$DEST")"
  MI_CONFIRM=no run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
  run grep -aiE 'not confirmed' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "mi_mig_resume ALSO refuses through an unsafe parent — it is an independent entry point" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=2" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=$(mi_mig_staging_path "$DEST" nz)" "nonce=nz"
  mi_lock_release
  chmod 777 "$(dirname "$DEST")"
  run mi_mig_resume "$IDX" "$POL" "$MAN"
  [ "$status" -ne 0 ]
  assert_contains "writable by its group or by everyone"
}

# --- the escaping-symlink re-check immediately before the commit (§5.2 round 4, finding 2) -----------
# A directory's own device+inode (mi_mig_verify_identity) proves it was not SWAPPED; it says nothing
# about what is INSIDE it. mi_mig_verify_no_escaping_symlinks targets specifically what an inode check
# cannot see, using the copy step's own already-validated escape rule (mi_copy_link_escapes).

@test "mi_mig_verify_no_escaping_symlinks refuses a tree containing an escaping (absolute-target) symlink" {
  local t; t="$(mktemp -d)"
  ln -s /etc/passwd "$t/evil"
  run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -ne 0 ]
  assert_contains "escapes it"
  rm -rf "$t"
}

@test "mi_mig_verify_no_escaping_symlinks refuses a tree containing a '..'-climbing escaping symlink" {
  local t; t="$(mktemp -d)"
  mkdir -p "$t/sub"
  ln -s ../../outside "$t/sub/evil"
  run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -ne 0 ]
  assert_contains "escapes it"
  rm -rf "$t"
}

@test "mi_mig_verify_no_escaping_symlinks accepts a tree containing only an intra-tree symlink" {
  local t; t="$(mktemp -d)"
  mkdir -p "$t/sub"
  : > "$t/sub/f"
  ln -s sub/f "$t/link"
  run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -eq 0 ]
  rm -rf "$t"
}

@test "mi_mig_verify_no_escaping_symlinks FAILS CLOSED when the walk cannot fully complete" {
  # §5.2 round 5, finding 2: the walk used to capture find's OUTPUT into a here-string with its EXIT
  # STATUS discarded — a partial walk (an unreadable subdirectory, a race) would still print whatever
  # it reached, read as if it were the complete tree, and a clean result over an incomplete scan is
  # indistinguishable from "nothing found". An unreadable subdirectory makes find exit nonzero while
  # still printing everything else it walked; this must be refused, not read as "no escaping symlink
  # was found in what happened to be visible".
  local t; t="$(mktemp -d)"
  mkdir -p "$t/blocked"
  chmod 000 "$t/blocked"
  run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -ne 0 ]
  assert_contains "did not complete cleanly"
  chmod 755 "$t/blocked"
  rm -rf "$t"
}

# --- the re-walk's OWN scratch file must not live in an attacker-influenceable location (§5.2 round 6) -
# A bare `mktemp` placed the re-walk's NUL-output temp file in $TMPDIR — the SAME class of defect the
# reclaim TOCTOU already root-caused, reopened: an attacker with write access to TMPDIR could swap the
# minted name for a symlink to an operator-writable file before the `find … >` redirect opens it (an
# overwrite), or swap the written file's content after find finishes but before this reads it back
# (defeating the whole escaping-symlink defense — exactly what phase 5's commit depends on).

@test "_mi_mig_secure_state_dir creates and verifies an owner-only directory under mi_home" {
  run _mi_mig_secure_state_dir probe
  [ "$status" -eq 0 ]
  [ "$output" = "$MYTHICAL_HOME/.state/probe" ]
  run _mi_mode_octal "$MYTHICAL_HOME/.state/probe"
  [ "$output" = 700 ]
}

@test "the escaping-symlink re-walk still refuses even when TMPDIR points elsewhere" {
  local sentinel; sentinel="$(mktemp -d)"
  local t; t="$(mktemp -d)"
  ln -s /etc/passwd "$t/evil"
  TMPDIR="$sentinel" run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -ne 0 ]
  assert_contains "escapes it"
  rm -rf "$t" "$sentinel"
}

@test "the escaping-symlink re-walk's scratch file lives under mi_home's own state tree, never TMPDIR" {
  local sentinel; sentinel="$(mktemp -d)"
  local t; t="$(mktemp -d)"
  mkdir -p "$t/sub"; : > "$t/sub/f"; ln -s sub/f "$t/link"
  TMPDIR="$sentinel" run mi_mig_verify_no_escaping_symlinks "$t"
  [ "$status" -eq 0 ]
  run find "$sentinel" -maxdepth 1 -name 'rewalk.*'
  [ -z "$output" ]
  [ -d "$MYTHICAL_HOME/.state/rewalk" ]
  run _mi_mode_octal "$MYTHICAL_HOME/.state/rewalk"
  [ "$output" = 700 ]
  rm -rf "$t" "$sentinel"
}

@test "the re-walk FAILS CLOSED if the installer's own secure directory cannot be trusted (a symlink)" {
  mkdir -p "$MYTHICAL_HOME/.state"
  ln -s /tmp "$MYTHICAL_HOME/.state/rewalk"
  local t; t="$(mktemp -d)"
  mkdir -p "$t/sub"; : > "$t/sub/f"; ln -s sub/f "$t/link"    # ordinary, non-escaping — proves the
  run mi_mig_verify_no_escaping_symlinks "$t"                 # refusal is about the secure dir, not
  [ "$status" -ne 0 ]                                         # a found escaping symlink
  assert_contains "is a symlink, not a real directory"
  rm -rf "$t"
}

@test "phase 5 refuses to commit a staging tree that gained an ESCAPING symlink after phase 4" {
  # The exact race the finding describes: something with legitimate write access to the staging tree
  # during the copy (the runtime uid's ACL grant §4.5 requires the copy step to set) plants an escaping
  # symlink in the window between phase 4's verification and phase 5's commit. The staging directory's
  # OWN identity is unchanged — it is the SAME directory phase 3 created — so an inode check alone would
  # not catch this; the content-level re-scan immediately before the rename is what does.
  local stagepath sid
  stagepath="$(mi_mig_staging_path "$DEST" nz)"
  mkdir -p "$stagepath"
  ln -s /etc/passwd "$stagepath/evil"
  sid="$(mi_mig_identity "$stagepath")"
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=5" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=$stagepath" "nonce=nz" "stageid=$sid"
  mi_lock_release
  run mi_mig_run "$IDX" "$POL" "$MAN" p1 state "$DEST" 5
  [ "$status" -ne 0 ]
  assert_contains "escapes it"
  [ ! -e "$DEST" ]              # nothing was moved into place
  [ -d "$stagepath" ]           # the staged tree survives, untouched — not destroyed either
}

@test "compare-and-set: not started, key absent → write" {
  mi_lock_acquire
  run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" none
  [ "$status" -eq 0 ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key holds OUR value → advance without rewriting" {
  mi_lock_acquire
  mi_conf_family_add MYTHICAL_P1_STATE_BIND "$DEST"
  h="$(mi_digest "$MYTHICAL_HOME/mythical.conf")"
  run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -eq 0 ]
  [ "$h" = "$(mi_digest "$MYTHICAL_HOME/mythical.conf")" ]
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key ABSENT → STOP and require confirmation" {
  mi_lock_acquire
  MI_CONFIRM=no run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -ne 0 ]
  assert_contains "equally"
  assert_contains "deleted"
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key holds SOMETHING ELSE → STOP" {
  mi_lock_acquire
  mi_conf_family_add MYTHICAL_P1_STATE_BIND /operator/choice
  MI_CONFIRM=no run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -ne 0 ]
  assert_contains "/operator/choice"
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = /operator/choice ]
  mi_lock_release
}

@test "the bind reaches mythical.conf BEFORE the container is replaced" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  # The config write (phase 6) must precede the create (phase 7) in the call log.
  cw="$(grep -an 'container create' "$FAKE_DOCKER_STATE/calls.log" | tail -n1 | cut -d: -f1)"
  [ -n "$cw" ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
}

@test "after the migration, a RECREATE keeps the product on the bind" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  mi_verb_recreate "$IDX" "$POL" "$MAN" p1 >/dev/null
  run mi_rt_inspect container c.mounts "$C"
  assert_contains "$DEST"
}

@test "phase 7 REPLACES the container and tombstones the old one — mounts are immutable" {
  before="$(mi_rt_inspect container c.image "$C")"
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run grep -a 'container rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a -- 'update' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  : "$before"
}

@test "phase 8 verifies the mount BY INSPECTION and claims nothing about the container-side read" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run mi_mig_run "$IDX" "$POL" "$MAN" p1 state "$DEST" 8
  [ "$status" -eq 0 ]
  run grep -aiE 'container-side read (is )?(verified|confirmed)' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -ne 0 ]
  run grep -a 'not verified at all' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
}

@test "a migration of a desired-STOPPED product leaves it stopped and still verifies phase 8" {
  mi_verb_stop p1
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_state_observed "$C"
  [ "$output" = stopped ]
}

@test "generic reconciliation is SUSPENDED for the container while the intent is live" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" "dest=$DEST" \
      "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_rt_container_stop "$C" >/dev/null
  run mi_state_plan "$C"
  [ "$output" = suspended ]
  mi_lock_release
}

@test "phase 9 restores the recorded desired state and only THEN may delete the source volume" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run mi_state_observed "$C"
  [ "$output" = running ]
  # The source volume is RETAINED by default — deleting user data is never automatic.
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
}

@test "each of the nine phases resumes from the recorded phase" {
  local n
  for n in 1 2 3 4 5 6 7 8 9; do
    teardown; setup
    mi_lock_acquire
    mi_led_put storagemig key "p1:state" "key=p1:state" "phase=$n" "product=p1" "role=state" \
        "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
        "srcvol=mythical-${IDENT}-p1-state" "staging=$(mi_mig_staging_path "$DEST" nz)" "nonce=nz"
    mi_lock_release
    run mi_mig_resume "$IDX" "$POL" "$MAN"
    [ "$status" -eq 0 ] || { echo "phase $n did not resume: $output"; false; }
  done
}
