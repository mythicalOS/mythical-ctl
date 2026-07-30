#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env
  load_mctl
  mi_ensure_layout
  mi_lock_acquire
}
teardown() { mi_lock_release; teardown_test_env; }

@test "the ledger editor replaces a record keyed by an explicit field" {
  mi_led_put object name mythical-i1-p1 "class=container" "name=mythical-i1-p1" "gen=1"
  mi_led_put object name mythical-i1-p1 "class=container" "name=mythical-i1-p1" "gen=2"
  run mi_led_all object
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 1 ]
  assert_contains "gen=2"
}

@test "the editor preserves every other record" {
  mi_led_put object name a "class=volume" "name=a" "gen=1"
  mi_led_put object name b "class=volume" "name=b" "gen=1"
  mi_led_put object name a "class=volume" "name=a" "gen=2"
  run mi_led_all object
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
  assert_contains "name=b"
}

@test "a field value containing a TAB or newline is REFUSED — it would forge a field or a record" {
  run mi_led_put object name x "class=container" "name=$(printf 'a\tb')"
  [ "$status" -ne 0 ]
  run mi_led_put object name y "class=container" "name=$(printf 'a\nb')"
  [ "$status" -ne 0 ]
}

@test "a field that is not KEY=VALUE is refused" {
  run mi_led_put object name x "classcontainer"
  [ "$status" -ne 0 ]
}

@test "the editor refuses without the family lock" {
  mi_lock_release
  run mi_led_put object name x "class=container"
  [ "$status" -ne 0 ]
  assert_contains "family lock"
  # NAMING THE CALLER'S OPERATION IS THE POINT, and it is what the two assertions below pin.
  # MEASURED: with only the two lines above, mi_led_put's own mi_lock_assert_held could be DELETED
  # with the whole suite green — mi_ledger_write asserts the lock too, so the call still refused, just
  # in the ledger writer's words ("refusing to write the ledger"). A guard whose removal changes
  # nothing observable is a guard that gets removed.
  assert_contains "record installer state"
  # And it must run BEFORE the fields are validated: authorization first, input second. Without the
  # in-function assertion an unlocked caller with a malformed field is answered about the FIELD and
  # never told it was not authorized to write at all — and the read half of the read-modify-write has
  # already run outside the lock by then.
  run mi_led_put object name x "not-a-field"
  [ "$status" -ne 0 ]
  assert_contains "family lock"
  mi_lock_acquire
}

@test "identity is minted once and is stable" {
  a="$(mi_ident_ensure)"
  b="$(mi_ident_ensure)"
  [ "$a" = "$b" ]
  run mi_ident_get
  [ "$output" = "$a" ]
}

@test "a minted identity is a valid name component" {
  id="$(mi_ident_ensure)"
  run mi_name_container "$id" brokkr
  [ "$status" -eq 0 ]
  assert_contains "mythical-${id}-brokkr"
}

@test "the minted identity contains no hyphen, so the flat name join stays unambiguous" {
  id="$(mi_ident_ensure)"
  case "$id" in *-*) echo "identity '$id' contains a hyphen: mi_name_* would be ambiguous" >&2; return 1 ;; esac
  [ "${#id}" -eq 11 ]
}

@test "mi_ident_get reports 3 before any identity exists, never an empty string" {
  run mi_ident_get
  [ "$status" -eq 3 ]
  [ -z "$output" ]
}

@test "a corrupt ledger fails CLOSED for identity — it never looks like first use" {
  mi_ident_ensure >/dev/null
  printf 'garbage\n' > "$MYTHICAL_HOME/.state/ledger"
  run mi_ident_get
  [ "$status" -eq 1 ]
}

@test "membership is a SET, so a second product's absent floor is first-use not rollback" {
  mi_ident_ensure >/dev/null
  mi_member_add brokkr
  run mi_member_has brokkr
  [ "$status" -eq 0 ]
  run mi_member_has saga
  [ "$status" -ne 0 ]
  mi_member_add saga
  run mi_member_has brokkr
  [ "$status" -eq 0 ]
}

@test "a family uninstall drops one membership and keeps the rest, and needs the lock to do it" {
  mi_ident_ensure >/dev/null
  mi_member_add brokkr
  mi_member_add saga
  mi_member_del brokkr
  run mi_member_has brokkr
  [ "$status" -ne 0 ]
  run mi_member_has saga
  [ "$status" -eq 0 ]
  # mi_led_del is a read-modify-write too, and it asserts the lock in the CALLER's words for the same
  # reason mi_led_put does — see the note there.
  mi_lock_release
  run mi_member_del saga
  [ "$status" -ne 0 ]
  assert_contains "remove installer state"
  mi_lock_acquire
  run mi_member_has saga
  [ "$status" -eq 0 ]
}

@test "provenance records an object by name AND nonce, and finds it by both" {
  mi_ident_ensure >/dev/null
  mi_prov_record container mythical-i1-p1 c-nonce id=abc product=p1
  run mi_prov_find container mythical-i1-p1
  assert_contains "nonce=c-nonce"
  assert_contains "id=abc"
}

@test "a re-record SUPERSEDES the prior generation rather than appending beside it" {
  mi_ident_ensure >/dev/null
  mi_prov_record volume mythical-i1-p1-state nonce-a
  mi_prov_record volume mythical-i1-p1-state nonce-b
  run mi_led_all object
  [ "$(printf '%s\n' "$output" | grep -ac 'name=mythical-i1-p1-state')" = 1 ]
  assert_contains "nonce=nonce-b"
  assert_contains "gen=2"
}

@test "CLASS AND NAME together key a record — a container and a volume can derive the same name" {
  mi_ident_ensure >/dev/null
  # `mythical-i1-p1-state` is BOTH the container name for a product literally called `p1-state` and
  # the volume name for product `p1` role `state`: the name derivation joins its parts with `-`, and
  # `-` is inside the charset each part is validated against, so the two derivations are byte-equal.
  # Keying provenance on the name alone would make recording either one DELETE the other's record —
  # and an object whose provenance vanished is unauthorized for deletion forever.
  mi_prov_record container mythical-i1-p1-state c-nonce
  mi_prov_record volume    mythical-i1-p1-state v-nonce
  run mi_prov_find container mythical-i1-p1-state
  [ "$status" -eq 0 ]
  assert_contains "nonce=c-nonce"
  run mi_prov_find volume mythical-i1-p1-state
  [ "$status" -eq 0 ]
  assert_contains "nonce=v-nonce"
  # And tombstoning one must not erase the other's provenance either.
  mi_prov_tombstone volume mythical-i1-p1-state
  run mi_prov_find container mythical-i1-p1-state
  [ "$status" -eq 0 ]
  assert_contains "nonce=c-nonce"
}

@test "removal writes a tombstone and drops the object record" {
  mi_ident_ensure >/dev/null
  mi_prov_record volume v1 nonce-a
  mi_prov_tombstone volume v1
  run mi_prov_find volume v1
  [ "$status" -eq 3 ]
  run mi_led_all tombstone
  assert_contains "name=v1"
  assert_contains "nonce=nonce-a"
}

@test "deletion authority requires the RECORDED nonce to match what is actually there" {
  mi_ident_ensure >/dev/null
  id="$(mi_ident_get)"
  mi_rt_volume_create v1 good-nonce "$id"
  mi_prov_record volume v1 good-nonce
  run mi_prov_authority volume v1
  [ "$status" -eq 0 ]
}

@test "a REUSED volume name fails the nonce check and is NOT authorized for deletion" {
  mi_ident_ensure >/dev/null
  id="$(mi_ident_get)"
  mi_rt_volume_create v1 other-nonce "$id"
  mi_prov_record volume v1 recorded-nonce
  run mi_prov_authority volume v1
  [ "$status" -ne 0 ]
  assert_contains "does not match"
}

@test "an object with NO record is never authorized — it is preserved and reported" {
  mi_ident_ensure >/dev/null
  id="$(mi_ident_get)"
  mi_rt_volume_create v-unknown some-nonce "$id"
  run mi_prov_authority volume v-unknown
  [ "$status" -ne 0 ]
  assert_contains "no provenance"
}

@test "an object that is GONE reports 3, distinctly from a mismatch" {
  mi_ident_ensure >/dev/null
  mi_prov_record volume v-gone nonce-a
  run mi_prov_authority volume v-gone
  [ "$status" -eq 3 ]
}

@test "images are recorded by DIGEST and mi_prov_authority refuses them outright (D37)" {
  mi_ident_ensure >/dev/null
  mi_prov_image_record "$(a_digestref brokkr)" brokkr
  run mi_led_all image
  assert_contains "product=brokkr"
  run mi_prov_authority image "$(a_digestref brokkr)"
  [ "$status" -ne 0 ]
  assert_contains "never removed automatically"
}

@test "first use is ledger-absent AND every other trace absent" {
  run mi_first_use
  [ "$status" -eq 0 ]
}

@test "no ledger BESIDE a product conf is INCONSISTENT, not first use" {
  printf 'X=1\n' > "$MYTHICAL_HOME/brokkr.conf"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "inconsistent"
}

@test "no ledger BESIDE a product directory is inconsistent" {
  mkdir -p "$MYTHICAL_HOME/brokkr"
  run mi_first_use
  [ "$status" -eq 1 ]
}

@test "no ledger BESIDE a labelled runtime object is inconsistent" {
  mi_rt_volume_create mythical-zz-p1-state n1 zz
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "labelled"
}

@test "a ledger that EXISTS is not first use" {
  mi_ident_ensure >/dev/null
  run mi_first_use
  [ "$status" -eq 3 ]
}
