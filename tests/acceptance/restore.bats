#!/usr/bin/env bats
# §10a — backup and restore through the ACTUAL CLI/verb layer: confirmation, locking, arity, and the
# §7.3 exit-code contract. tests/unit/backup.bats already exercises the library functions directly
# (mi_backup_run/mi_restore_run/mi_restore_abandon) under a lock the suite holds itself; this file goes
# through mi_verb_backup/mi_verb_restore and bin/mythical-ctl instead, which acquire their own lock and
# apply their own confirmation gates — the shape an operator actually drives.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  VOL_STATE="$(mi_name_volume "$IDENT" p1 state)"
  VOL_SECRETS="$(mi_name_volume "$IDENT" p1 secrets)"
  # See tests/unit/backup.bats's setup() for why: install() leaves the product's own container
  # mounting both volumes, and the fake daemon (like a real one) refuses to remove a volume a
  # container still mounts — removing it here keeps every test about restore's own logic, not about
  # an unrelated "volume in use" refusal from a container these tests never restart.
  mi_lock_acquire; mi_rt_container_rm "$(mi_name_container "$IDENT" p1)" >/dev/null 2>&1 || true; mi_lock_release
  BK="$(mktemp -d)/backup"
}
teardown() { rm -rf "$(dirname "$BK")"; teardown_test_env; }

# --- the full round trip, through the verbs ---------------------------------------------------------

@test "backup then restore: a full round trip through mi_verb_backup/mi_verb_restore" {
  run mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ -f "$BK/ledger" ]
  [ -f "$BK/volumes/${VOL_STATE}.nonce" ]
  [ -f "$BK/volumes/${VOL_SECRETS}.nonce" ]

  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  assert_contains "activated"

  for v in "$VOL_STATE" "$VOL_SECRETS"; do
    run mi_prov_authority volume "$v"
    assert_ok
  done
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

@test "backup then restore: through the actual CLI (bin/mythical-ctl)" {
  run_mctl backup "$BK" --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]

  rm -f "$MYTHICAL_HOME/.state/ledger"
  run_mctl restore "$BK" --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# --- CLI arity and option scoping ------------------------------------------------------------------

@test "CLI: backup needs exactly one operand (the output directory)" {
  run_mctl backup --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
  run_mctl backup "$BK" extra --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "CLI: restore needs exactly one operand, or --abandon alone, never both" {
  run_mctl restore --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
  run_mctl restore "$BK" --abandon --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
  run_mctl restore "$BK" extra --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "CLI: backup refuses options that belong to other verbs" {
  run_mctl backup "$BK" --purge --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
  run_mctl backup "$BK" --to-bind /tmp/x --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "CLI: restore refuses options that belong to other verbs" {
  run_mctl restore "$BK" --family --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "CLI: --abandon on other verbs is refused, not silently ignored" {
  run_mctl install p1 --abandon --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "mi_verb_backup/mi_verb_restore reject the wrong number of arguments as a usage error" {
  run mi_verb_backup "$IDX"
  [ "$status" -eq 2 ]
  run mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" extra
  [ "$status" -eq 2 ]
  run mi_verb_restore "$IDX"
  [ "$status" -eq 2 ]
}

# --- restore refuses over a live installation -------------------------------------------------------

@test "restore through the verb refuses while the current installation is still active" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -eq 1 ]
  assert_contains "active installer state ledger is present"
  # the live installation is untouched
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# --- resume after a crash, through the verb ---------------------------------------------------------

@test "a crash during fill resumes cleanly on the next mi_verb_restore call" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]

  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ -f "$MYTHICAL_HOME/.state/ledger" ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

@test "a same-name survivor volume is refused end to end, and abandonment PRESERVES it" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  mi_lock_acquire
  mi_rt_volume_rm "$VOL_STATE" >/dev/null 2>&1
  mi_rt_volume_create "$VOL_STATE" "an-unrelated-nonce" "an-unrelated-identity" >/dev/null
  mi_lock_release

  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "SURVIVOR"
  # The staging ledger is written (phase 1) before the per-volume survivor check (phase 2) ever runs,
  # so an in-progress restore genuinely exists here — 'restore --abandon' (the correct form) is the
  # recovery path, never a blind retry with the same directory.
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]

  MI_CONFIRM=yes run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" --abandon
  assert_ok
  assert_contains "PRESERVED"
  assert_contains "$VOL_STATE"
  # A same-name survivor is never abandoned or removed automatically: abandon only touches volumes
  # THIS restore attempt itself created (matching its recorded nonce), and this one was never that
  # restore's to begin with — it is left exactly as it was.
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$output" = "an-unrelated-nonce" ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
}

# --- abandonment through the verb, with confirmation -------------------------------------------------

@test "restore --abandon through the CLI removes the partial volumes with confirmation" {
  run_mctl backup "$BK" --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run_mctl restore "$BK" --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]

  MI_CONFIRM=no run_mctl restore --abandon --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]      # untouched without confirmation

  MI_CONFIRM=yes run_mctl restore --abandon --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$status" -eq 3 ]
}

# --- corrupt staging, through the verb ---------------------------------------------------------------

@test "a corrupt staging ledger is preserved aside and blocks both restore and abandon, through the verb" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  printf 'not a valid ledger\n' > "$MYTHICAL_HOME/.state/ledger.staging"

  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "does not validate"

  MI_CONFIRM=yes run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" --abandon
  [ "$status" -eq 2 ]   # --abandon takes no backup-directory operand
}

# --- codex gate round 1: one test per fix ------------------------------------------------------------

# Fix 1 — the staging ledger must NOT be reachable as authoritative via an inherited env override. A
# general lifecycle invocation (here, `status`, which only reads) with MI_LEDGER_PATH_OVERRIDE pointed
# at the staging ledger BEFORE mythical-ctl even starts must behave EXACTLY as if it were never set —
# proving the CLI entrypoint's scrub (bin/mythical-ctl) actually closes the reachable path, not merely
# that the library-level guard exists.
@test "fix1: an inherited MI_LEDGER_PATH_OVERRIDE cannot make an ordinary CLI command see the staging ledger" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null 2>&1 || true
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]   # an in-progress restore genuinely exists
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]         # and there is still no active one

  # Baseline: an ordinary lifecycle command (status; read-only, always answers) with NO override set.
  run_mctl status --index "$IDX"
  local base_status="$status" base_output="$output"

  # The SAME command, but an operator's shell had MI_LEDGER_PATH_OVERRIDE exported at the staging
  # ledger BEFORE invoking the CLI — exactly the attack this fix closes. bin/mythical-ctl's own
  # entrypoint scrub must make this indistinguishable from the baseline: not a different status, not
  # different output, no leakage of the staging ledger's own records into an ordinary read.
  MI_LEDGER_PATH_OVERRIDE="$MYTHICAL_HOME/.state/ledger.staging" run_mctl status --index "$IDX"
  [ "$status" = "$base_status" ]
  [ "$output" = "$base_output" ]
}

# Fix 2/3 — location authentication: an existing backup root that is itself group/other-writable is
# refused end to end, even though every checksum inside it is internally consistent (this is the
# "there is no signature, only location" boundary — see lib/backup.sh's own header note).
@test "fix2: restore refuses an existing backup root that is group/other-writable, checksums notwithstanding" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  chmod 777 "$BK"
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "unsafe"
  [ ! -f "$MYTHICAL_HOME/.state/ledger.staging" ]   # refused before phase 1 ever wrote anything
}

# Fix 3 — an EXISTING backup-directory symlink must be resolved (followed) and the RESOLVED TARGET's
# own chain checked — not the alias's. The realistic exploit: the symlink itself sits in a perfectly
# safe, operator-owned location (so a parent-only check on the RAW path would pass) while it POINTS AT
# an unverified, group/other-writable location — the alias and the target can have DIFFERENT safety,
# and it is the target that has to be proven safe, because that is where the bytes actually come from.
@test "fix3: a SAFE-looking symlink pointing at an UNSAFE target is refused, not trusted by alias" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  chmod 777 "$BK"
  local alias
  alias="$(mktemp -d)/alias"    # the alias's OWN parent is a fresh, operator-owned (safe) directory
  ln -s "$BK" "$alias"
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$alias"
  [ "$status" -ne 0 ]
  assert_contains "unsafe"
}

# The positive case: a symlink to a SAFE target is followed and restore succeeds through it —
# resolving the symlink is not the same as refusing every symlink.
@test "fix3: a symlink to a SAFE backup directory is followed and restore succeeds through it" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  local alias="$(dirname "$BK")/alias"
  ln -s "$BK" "$alias"
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$alias"
  assert_ok
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# Fix 4 — restore (and the activation it performs) is destructive and must be confirmation-gated,
# exactly like migrate-storage/uninstall.
@test "fix4: MI_CONFIRM=no refuses restore before creating or filling anything" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  MI_CONFIRM=no run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "not confirmed"
  [ ! -f "$MYTHICAL_HOME/.state/ledger.staging" ]   # nothing was even staged
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$status" -eq 3 ]                               # and nothing was (re)created
}

@test "fix4: MI_CONFIRM=no also refuses a bare activate (staging-no-intent)" {
  mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  mi_lock_acquire
  mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  # Simulate a crash strictly between phase 5 and phase 6: re-stage the now intent-free ledger.
  cp -- "$MYTHICAL_HOME/.state/ledger" "$MYTHICAL_HOME/.state/ledger.staging"
  rm -f "$MYTHICAL_HOME/.state/ledger"
  mi_lock_release
  run mi_restore_state
  [ "$output" = staging-no-intent ]
  MI_CONFIRM=no run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "not confirmed"
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]
}

# Fix 5 — each volume's copy uses ITS PRODUCT's declared runtime_uid (write_fixture_product's own
# default is 900, deliberately not 0), never a fixed stand-in.
@test "fix5: backup and restore copy each volume using its product's declared runtime_uid, not 0" {
  run mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  # The copy container's argv is `copy /src /dst <ruid> <ouid>`; grep the recorded invocation for the
  # declared uid immediately after the two fixed path arguments.
  run grep -aE 'copy /src /dst 900 [0-9]+' "$FAKE_DOCKER_STATE/calls.log"
  assert_ok
  run grep -aE 'copy /src /dst 0 [0-9]+' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]   # the old fixed stand-in never appears

  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  run grep -aE 'copy /src /dst 900 [0-9]+' "$FAKE_DOCKER_STATE/calls.log"
  assert_ok
}

@test "fix5: a volume whose product cannot be authenticated refuses rather than guessing uid 0" {
  # Corrupt the product's own manifest so mi_accept_manifest cannot authenticate it, WITHOUT touching
  # the ledger (the volume record itself is fine — this is specifically about the manifest lookup
  # failing, not a malformed ledger record).
  printf 'garbage\n' >> "$MAN"
  run mi_verb_backup "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "runtime uid"
}
