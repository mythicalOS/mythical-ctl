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

# --- the module's rules applied to EVERY input, not to one of them --------------------------------
# Each test below is a case where a rule this file states in prose was enforced on one of the inputs
# it reaches and not on the others. They are grouped because they are one defect repeated, not three.

@test "a runtime that CANNOT BE ASKED is not evidence of a fresh machine" {
  # Labelled objects outlive `rm -rf` of the home entirely, which is the only reason they are swept
  # at all. An empty listing because the daemon refused to answer is not the same fact as an empty
  # listing, and only the second is first-use evidence.
  FAKE_DOCKER_DOWN=1 run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "could not be asked"
}

@test "an unlistable object kind is a listing FAILURE, not an empty listing" {
  # The same fail-open one level down: the lister's case statement had no default arm, so an
  # unknown kind returned 0 with no output — indistinguishable from "asked, and there are none".
  run _mi_prov_list_all zebra
  [ "$status" -ne 0 ]
  assert_contains "not a listable"
}

@test "the record KIND is validated too — it is serialized exactly like a field is" {
  id="$(mi_ident_ensure)"
  # A TAB forges a field boundary and a newline forges a whole record. That rule was applied to the
  # appended fields and not to the kind, which is written to the same line by the same function.
  run mi_led_put "$(printf 'identity\tid=forged\nobject')" ignored ignored "x=y"
  [ "$status" -ne 0 ]
  run mi_ident_get
  [ "$status" -eq 0 ]
  [ "$output" = "$id" ] || { echo "identity forged through the record kind: '$output'" >&2; return 1; }
}

@test "the key SELECTOR is validated too — it is one field split in two" {
  mi_ident_ensure >/dev/null
  run mi_led_put object "$(printf 'na\tme')" x "class=container"
  [ "$status" -ne 0 ]
  run mi_led_put object name "$(printf 'a\nb')" "class=container"
  [ "$status" -ne 0 ]
  # And the key half obeys the key grammar, because the selector has to match a serialized field
  # byte for byte — a selector no field can ever equal silently supersedes nothing.
  run mi_led_put object Name x "class=container"
  [ "$status" -ne 0 ]
}

@test "a tombstone cannot forge a record through the object NAME it serializes" {
  id="$(mi_ident_ensure)"
  # mi_prov_tombstone builds its own record rather than going through mi_led_put, so it reaches the
  # serializer without passing the field rule — the third input, and the one nobody had checked.
  run mi_prov_tombstone volume "$(printf 'v1\nidentity\tid=forged')"
  [ "$status" -ne 0 ]
  run mi_ident_get
  [ "$status" -eq 0 ]
  [ "$output" = "$id" ] || { echo "identity forged through a tombstone name: '$output'" >&2; return 1; }
}

@test "a ledger path that is a DIRECTORY is inconsistent, not a fresh machine" {
  mkdir -p "$MYTHICAL_HOME/.state/ledger"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "not a regular file"
}

@test "a DANGLING SYMLINK at the ledger path is inconsistent, not a fresh machine" {
  ln -s "$MYTHICAL_HOME/.state/gone" "$MYTHICAL_HOME/.state/ledger"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "not a regular file"
}

@test "a STAGING ledger that is not a regular file still blocks first use" {
  mkdir -p "$MYTHICAL_HOME/.state/ledger.staging"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "restore is in progress"
  rm -rf "$MYTHICAL_HOME/.state/ledger.staging"
  # COVERAGE, not a fix: the `-e || -L` here already saw this input. It is pinned now because the
  # dangling link is the input the other three trace sites each got wrong in turn, and this was the
  # one site where it was handled but nothing would have noticed it regressing.
  ln -s "$MYTHICAL_HOME/.state/gone" "$MYTHICAL_HOME/.state/ledger.staging"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "restore is in progress"
}

@test "a DANGLING SYMLINK product conf is a trace too — presence is the test, not readability" {
  ln -s "$MYTHICAL_HOME/gone.conf" "$MYTHICAL_HOME/brokkr.conf"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "brokkr.conf"
}

@test "a product DIRECTORY entry is a trace whether it is real, a link, or a dangling link" {
  # THE GLOB WAS THE FILTER, NOT THE TEST. The sweep globbed `"$h"/*/`, and bash expands a
  # trailing-slash pattern by testing each candidate for directory-ness — so a dangling symlink was
  # never offered to the `[ -d ]` beside it, and changing that test alone would have fixed nothing.
  # Measured: `[ -L "$h/link/" ]` is false even for a live link to a directory, so a trailing slash
  # defeats every test that could be put next to it.
  ln -s "$MYTHICAL_HOME/gone" "$MYTHICAL_HOME/brokkr"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "already holds"
  assert_contains "brokkr"
  rm -f "$MYTHICAL_HOME/brokkr"

  # The other two answers the same question has on disk. The link target is deliberately OUTSIDE the
  # home, or the target directory would itself be the trace and the assertion would prove nothing.
  mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
  ln -s "$BATS_TEST_TMPDIR/elsewhere" "$MYTHICAL_HOME/saga"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "saga"
  rm -f "$MYTHICAL_HOME/saga"

  mkdir -p "$MYTHICAL_HOME/skuld"
  run mi_first_use
  [ "$status" -eq 1 ]
  assert_contains "skuld"
}

# --- a value parsed out of a file is not a number, and a record answers for ONE object -------------

@test "a GENERATION out of the ledger is DIGITS before arithmetic — it is never EVALUATED" {
  mi_ident_ensure >/dev/null
  marker="${BATS_TEST_TMPDIR}/gen-payload-ran"
  # A field is only ever asked to carry no TAB and no newline, so the value below is a VALID field
  # and reaches the ledger through this module's own public editor — as it also would in a ledger
  # restored from a backup, which the checksum proves unaltered but does not prove ours. `$(( ))` is
  # an evaluator, not a parser: bash evaluates a command substitution inside an arithmetic array
  # subscript, so `gen=$((gen + 1))` RUNS this the next time anything records the object.
  mi_led_put object key volume:v1 "key=volume:v1" "class=volume" "name=v1" "nonce=n1" \
    "gen=a[\$(touch '${marker}')]"
  run mi_prov_record volume v1 n2
  [ "$status" -ne 0 ]
  assert_contains "not a number"
  # THE RETURN VALUE ALONE PROVES NOTHING. Code that refused AFTER the substitution had already run
  # satisfies the assertion above and has still executed the payload, which is the failure mode that
  # matters here — so the marker, not the status, is what separates "refused" from "refused too late".
  [ ! -e "$marker" ] || { echo "the payload EXECUTED: '$marker' was created" >&2; return 1; }
  # The bound is part of the rule rather than decoration: 64-bit arithmetic wraps silently past 19
  # digits, and a generation that wrapped reads exactly like a legitimate one afterwards.
  mi_led_put object key volume:v2 "key=volume:v2" "class=volume" "name=v2" "nonce=n1" \
    "gen=99999999999999999999"
  run mi_prov_record volume v2 n2
  [ "$status" -ne 0 ]
}

@test "a generation this module refuses to READ is never carried into a tombstone either" {
  mi_ident_ensure >/dev/null
  mi_led_put object key volume:v1 "key=volume:v1" "class=volume" "name=v1" "nonce=n1" "gen=9-9"
  # Nothing in the tombstone path evaluates the value — but this is the module's only writer of a
  # generation it did not compute, and copying one it has just refused to read into the record that
  # OUTLIVES the object would preserve it for the next reader instead of reporting it.
  run mi_prov_tombstone volume v1
  [ "$status" -ne 0 ]
  assert_contains "not a number"
  # Any mismatch preserves: the record it could not read is still there.
  run mi_led_all object
  assert_contains "name=v1"
}

@test "a record carrying one field name TWICE is refused — it would answer for two objects" {
  mi_ident_ensure >/dev/null
  mi_prov_record volume target target-nonce
  # A record's extra fields are passed straight through, so a record this installer legitimately owns
  # could be given a SECOND `key=`. The matcher accepts a record when ANY field equals the selector,
  # so that record then answers the lookup for the OTHER object's key while describing its own — and
  # authority reads ITS nonce and compares it against the other object's label.
  run mi_prov_record volume installer-owned n1 "key=volume:target"
  [ "$status" -ne 0 ]
  assert_contains "twice"
  # The object it tried to speak for is untouched and still answers for itself; the forged one exists
  # nowhere.
  run mi_prov_find volume target
  [ "$status" -eq 0 ]
  assert_contains "nonce=target-nonce"
  run mi_prov_find volume installer-owned
  [ "$status" -eq 3 ]
}

@test "a record ALREADY carrying a duplicate selector matches nothing — not even its own key" {
  mi_ident_ensure >/dev/null
  # mi_led_put now refuses to WRITE this record, so put it there the way a restore does: through the
  # ledger writer, checksum and all. A checksum proves the bytes were not altered after they were
  # written; it does not prove this installation wrote them. So the reader has to refuse the record
  # independently of the writer, or the writer's rule is only a rule for well-behaved ledgers.
  { mi_ledger_read
    printf 'object\tkey=volume:mine\tclass=volume\tname=mine\tnonce=n1\tgen=1\tkey=volume:target\n'
  } | mi_ledger_write
  run mi_prov_find volume target
  [ "$status" -eq 3 ]
  assert_contains "ambiguous"
  run mi_prov_find volume mine
  [ "$status" -eq 3 ]
  # Inert, not deleted — any mismatch preserves and reports. Asserted against the ledger FILE rather
  # than against a listing: a listing now refuses a kind it cannot read completely, and the bytes on
  # disk are the stronger evidence of preservation in any case — they prove the record survived,
  # rather than proving that some reader was willing to hand it back.
  [ "$(grep -ac 'key=volume:target' "$MYTHICAL_HOME/.state/ledger")" = 1 ] \
    || { echo "the ambiguous record was not preserved" >&2; return 1; }
}

@test "authority checks that the record it found DESCRIBES the object it was asked about" {
  mi_ident_ensure >/dev/null
  id="$(mi_ident_get)"
  mi_rt_volume_create target target-nonce "$id"
  # One `key=` field, so neither duplicate rule sees this, and the key genuinely names `target` — but
  # the record describes something else. `key`, `class` and `name` are three independent fields and
  # nothing made them agree. The nonce here MATCHES what the volume actually carries, so without the
  # check this authorizes deleting an object the record is not about.
  mi_led_put object key volume:target "key=volume:target" "class=volume" "name=installer-owned" \
    "nonce=target-nonce" "gen=1"
  run mi_prov_authority volume target
  [ "$status" -ne 0 ]
  assert_contains "does not describe it"
}

# --- a record is well-formed, or it matches nothing and is preserved and reported ------------------
# The rule was applied to the SELECTOR and to nothing else, so a record could be ill-formed or
# self-contradictory in any OTHER field and every read path tolerated it: matching accepted it,
# extraction returned the first of two values and ignored the second, and the two editors matched the
# single `key=` and removed or superseded it — destroying the evidence that should have been kept.

# Put one record on disk the way a RESTORE does: through the ledger writer, checksum and all. The
# editor refuses to write these, which is precisely why the READER has to refuse them independently —
# a checksum proves the bytes were not altered after they were written, not that this installation
# wrote them.
put_raw() { { mi_ledger_read; printf '%s\n' "$1"; } | mi_ledger_write; }

@test "a record ill-formed in a field OTHER than the selector is never authority, and is preserved" {
  mi_ident_ensure >/dev/null
  id="$(mi_ident_get)"
  led="$MYTHICAL_HOME/.state/ledger"
  for n in v1 v2 v3; do mi_rt_volume_create "$n" actual-nonce "$id"; done

  # Each of the three carries exactly ONE `key=`, and its class and name describe the object it is
  # found under — so the selector rule, the duplicate-selector rule and the class/name agreement rule
  # all pass it. The nonce it then hands over is the LIVE one, so with no rule about the rest of the
  # record, deleting each of these objects was authorized on the strength of a record that
  # contradicts itself.
  put_raw "$(printf 'object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=actual-nonce\tgen=1\tnonce=other')"
  put_raw "$(printf 'object\tkey=volume:v2\tclass=volume\tname=v2\tnonce=actual-nonce\tgen=1\tclass=container')"
  put_raw "$(printf 'object\tkey=volume:v3\tclass=volume\tname=v3\tnonce=actual-nonce\tgen=1\tnot-a-field')"

  run mi_prov_authority volume v1
  [ "$status" -ne 0 ] || { echo "a duplicate nonce= AUTHORIZED deletion" >&2; return 1; }
  run mi_prov_authority volume v2
  [ "$status" -ne 0 ] || { echo "a duplicate class= AUTHORIZED deletion" >&2; return 1; }
  run mi_prov_authority volume v3
  [ "$status" -ne 0 ] || { echo "a bare non-field token AUTHORIZED deletion" >&2; return 1; }

  # PRESERVATION IS THE OTHER HALF OF THE INVARIANT, and a test that asserts only the return value
  # proves only half the rule: refusing while quietly dropping the record destroys exactly the
  # evidence that says this ledger needs repairing.
  [ "$(grep -ac 'nonce=other' "$led")" = 1 ] || { echo "the duplicate-nonce record was not preserved" >&2; return 1; }
  [ "$(grep -ac 'class=container' "$led")" = 1 ] || { echo "the duplicate-class record was not preserved" >&2; return 1; }
  [ "$(grep -ac 'not-a-field' "$led")" = 1 ] || { echo "the bare-token record was not preserved" >&2; return 1; }
}

@test "neither editor deletes or supersedes a record it refuses to read" {
  mi_ident_ensure >/dev/null
  led="$MYTHICAL_HOME/.state/ledger"
  put_raw "$(printf 'object\tkey=volume:v9\tclass=volume\tname=v9\tnonce=preserve-me\tgen=1\tgen=2')"

  # A deletion that finds nothing has achieved its purpose — but it must find nothing HERE, and leave
  # what it could not read behind. Matching on the single `key=` made both editors act on the record.
  run mi_led_del object key volume:v9
  [ "$status" -eq 0 ] || { echo "expected 0, got $status: $output" >&2; return 1; }
  [ "$(grep -ac 'nonce=preserve-me' "$led")" = 1 ] || { echo "mi_led_del REMOVED a record it cannot read" >&2; return 1; }

  # Supersession is the same act by another name: it drops the matched record and writes one in its
  # place, so an unreadable record disappeared at the first ordinary re-record of that object.
  mi_prov_record volume v9 n2
  [ "$(grep -ac 'nonce=preserve-me' "$led")" = 1 ] || { echo "mi_led_put SUPERSEDED a record it cannot read" >&2; return 1; }
  [ "$(grep -ac 'nonce=n2' "$led")" = 1 ] || { echo "the new record was not written beside it" >&2; return 1; }
}

@test "mi_led_field refuses to read a field out of a record that is not well-formed" {
  # The extraction half of the same rule. Every reader here takes the FIRST hit and ignores the rest,
  # so a record carrying a name twice does not read as ambiguous — it reads as whichever value comes
  # first, and the caller is never told there was a second one.
  run mi_led_field "$(printf 'key=volume:v1\tclass=volume\tname=v1\tnonce=actual\tnonce=other')" nonce
  [ "$status" -ne 0 ] || { echo "extracted '$output' from a record carrying nonce= twice" >&2; return 1; }
  run mi_led_field "$(printf 'key=volume:v1\tclass=volume\tname=v1\tnot-a-field')" name
  [ "$status" -ne 0 ] || { echo "extracted '$output' from a record carrying a bare token" >&2; return 1; }
  # A record with no fields at all describes nothing. That is not the same as a record whose field is
  # merely absent, which is rc 3.
  run mi_led_field "" nonce
  [ "$status" -eq 1 ] || { echo "expected 1, got $status: $output" >&2; return 1; }
  # The gate is in this function, not only in the ones that call it: it is public, it is the only
  # reader of a field out of a record, and the next caller may hold a record from a path that did not
  # check. A well-formed record still answers.
  run mi_led_field "$(printf 'key=volume:v1\tclass=volume\tname=v1\tnonce=actual')" nonce
  [ "$status" -eq 0 ] || { echo "expected 0, got $status: $output" >&2; return 1; }
  [ "$output" = actual ] || { echo "expected 'actual', got '$output'" >&2; return 1; }
}

@test "a listing refuses rather than silently omitting a record it cannot read" {
  mi_ident_ensure >/dev/null
  led="$MYTHICAL_HOME/.state/ledger"
  mi_prov_record volume good good-nonce
  put_raw "$(printf 'object\tkey=volume:bad\tclass=volume\tname=bad\tnonce=n1\tgen=1\tnonce=n2')"
  # A selector asks about ONE object, so a record that is not well-formed simply does not match it and
  # the others still answer for themselves. A listing claims to be ALL of them: one that quietly
  # leaves out what it could not read cannot be reasoned about by a caller enumerating records in
  # order to act on them, because "is this all of them?" has no answer.
  run mi_led_all object
  [ "$status" -ne 0 ] || { echo "listed a kind it cannot read completely: $output" >&2; return 1; }
  case "$output" in
    *good-nonce*) echo "a partial listing was printed beside the failure: $output" >&2; return 1 ;;
  esac
  [ "$(grep -ac 'nonce=n2' "$led")" = 1 ] || { echo "the unreadable record was not preserved" >&2; return 1; }
}

@test "an identity the ledger cannot answer for is refused, not read as a fresh machine" {
  led="$MYTHICAL_HOME/.state/ledger"
  # The identity scopes every runtime name, and therefore every deletion decision. It used to be read
  # through a convenience getter that answers from any record of the kind without judging it: the
  # getter prints the value of EVERY `id=` it finds, so the record below answered with a TWO-LINE
  # identity, reported as success.
  printf 'identity\tid=i0000000000\tid=iffffffffff\n' | mi_ledger_write
  run mi_ident_get
  [ "$status" -eq 1 ] || { echo "expected 1, got $status: $output" >&2; return 1; }
  # And 1, not 3: 3 is "no identity recorded", which is first use — minting a fresh identity over a
  # record we could not read is how every object the previous identity named becomes unreachable.
  run mi_ident_ensure
  [ "$status" -ne 0 ] || { echo "minted a new identity over one it could not read: $output" >&2; return 1; }
  [ "$(grep -ac 'id=iffffffffff' "$led")" = 1 ] || { echo "the unreadable identity record was not preserved" >&2; return 1; }

  # TWO well-formed identity records are the same question one level up: each is fine on its own, and
  # "which installation is this?" still has no answer.
  printf 'identity\tid=i0000000000\nidentity\tid=iffffffffff\n' | mi_ledger_write
  run mi_ident_get
  [ "$status" -eq 1 ] || { echo "expected 1, got $status: $output" >&2; return 1; }
  assert_contains "identities"
}

@test "a REPEATED tombstone keeps the identity the tombstone exists to preserve" {
  mi_ident_ensure >/dev/null
  mi_prov_record volume v1 nonce-a
  mi_prov_tombstone volume v1
  # A retry is safe everywhere else in this module, and the second call had nothing to read: the
  # object record is gone by then, so it re-initialised nonce="" gen=0, dropped the tombstone it had
  # just written and replaced it with an EMPTY one — a repeat of the operation whose entire purpose
  # is preserving the identity of something removed destroyed exactly that.
  mi_prov_tombstone volume v1
  run mi_led_all tombstone
  [ "$status" -eq 0 ]
  [ "$(printf '%s\n' "$output" | grep -ac 'name=v1')" = 1 ]
  assert_contains "nonce=nonce-a"
  assert_contains "gen=1"
}
