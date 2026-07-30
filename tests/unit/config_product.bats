#!/usr/bin/env bats
load '../lib/test_helper'

# setup_test_env FIRST — see Task 1 Step 4. Without it mi_ensure_layout creates ~/.mythical in the
# engineer's REAL home and this suite writes there.
setup() {
  setup_test_env
  load_mctl
  mi_ensure_layout
  mi_lock_acquire
  SPEC="$(printf 'MYTHICAL_BROKKR_RETENTION\tint:1:365\nMYTHICAL_BROKKR_THEME\tenum:light|dark')"
  # chgrp to an arbitrary gid needs root, so a group this user is ALREADY in is what proves the
  # mechanism honestly as an ordinary user; a later test forces the failure path with an impossible
  # one. The gid is just an argument, so a test needs no seam at all.
  TEST_GID="$(id -G | awk '{print $1}')"
}
# No teardown(): the helper's removes MYTHICAL_HOME (and the lock file inside it). Defining one here
# would replace the helper's and leak a temp directory per test.

write_conf() { mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 30; }
write_records_gid() { local g="$1"; shift; mi_conf_product_add brokkr "$SPEC" "$g" "$@"; }

# Read one value from the product conf. NOT mi_conf_get: that scans the raw file, and a product conf
# still carries its trailing marker, which the scanner refuses by design. mi_conf_product_load is
# the supported reader — it strips and validates the marker first.
pget() { mi_conf_product_load brokkr "$SPEC" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }

# Plant a raw body with a CORRECT marker, bypassing the writer. Needed because the marker gate is
# strict: any fixture that must reach the parser has to carry a valid marker, or the test would be
# measuring the marker gate instead of the thing it names.
plant_conf() {
  local f body sum
  f="$(mi_conf_product_path brokkr)"
  body="$(printf '%s\n' "$1")"
  sum="$(printf '%s\n' "$body" | mi_digest /dev/stdin)"
  printf '%s\n%s%s\n' "$body" "$MI_CONF_MARKER_PREFIX" "$sum" > "$f"
}

@test "the path is ~/.mythical/<product>.conf" {
  [ "$(mi_conf_product_path brokkr)" = "$MYTHICAL_HOME/brokkr.conf" ]
}

@test "a write creates the file with a trailing integrity marker" {
  write_conf
  local f; f="$(mi_conf_product_path brokkr)"
  [ -f "$f" ]
  # Prints the SUBJECT, not $output: this test does not use `run`, so $output is unset here and
  # referencing it under `set -u` would abort with "unbound variable" instead of reporting anything.
  [[ "$(tail -n1 "$f")" == '#mythical-conf-sha256='* ]] \
    || { echo "the last line is not an integrity marker: $(tail -n1 "$f")" >&2; return 1; }
  [ "$(pget MYTHICAL_BROKKR_RETENTION)" = "30" ]
}

# The marker line is exactly why a product conf must not be read with the generic reader.
@test "mi_conf_get refuses a marker-bearing file — product confs go through mi_conf_product_load" {
  write_conf
  run mi_conf_get "$(mi_conf_product_path brokkr)" MYTHICAL_BROKKR_RETENTION
  [ "$status" -eq 1 ]
}

@test "the marker is a checksum of everything above it" {
  write_conf
  local f expected actual
  f="$(mi_conf_product_path brokkr)"
  expected="$(tail -n1 "$f")"; expected="${expected#\#mythical-conf-sha256=}"
  actual="$(sed '$d' "$f" | mi_digest /dev/stdin)"
  [ "$actual" = "$expected" ]
}

# Assert the GROUP as well as the mode. Mode alone passes even if chgrp was skipped entirely or
# set the wrong group — which would leave D60's whole access mechanism untested by a test named
# after it. `ls -ldn` prints the NUMERIC gid in field 4 on both GNU and BSD.
@test "the file lands at 0660 with the family gid when chgrp succeeds" {
  write_conf
  local f; f="$(mi_conf_product_path brokkr)"
  [ "$(ls -l  "$f" | awk 'NR==1{print substr($1,1,10)}')" = "-rw-rw----" ]
  [ "$(ls -ldn "$f" | awk 'NR==1{print $4}')" = "$TEST_GID" ]
}

# Decisions item 5. rc 5 = "written, but NOT to D60's spec". It must NOT be 0: reporting success
# while the product's UI silently cannot write its own settings file is the failure this returns.
@test "when chgrp fails the write reports rc 5 and leaves the file at 0600" {
  run write_records_gid 4294967000 MYTHICAL_BROKKR_RETENTION 30
  [ "$status" -eq 5 ]
  local f; f="$(mi_conf_product_path brokkr)"
  [ -f "$f" ]
  [ "$(ls -l "$f" | awk 'NR==1{print substr($1,1,10)}')" = "-rw-------" ]
  [ "$(ls -ldn "$f" | awk 'NR==1{print $4}')" != "4294967000" ]
  [[ "$output" == *"READ-ONLY"* ]] || { echo "rc 5 does not warn that the settings screen is READ-ONLY: $output" >&2; return 1; }
  # rc 5 has THREE states and this is state (a). Each message must name its own, so that a caller
  # keying on rc 5 to explain it to an operator cannot print a diagnosis belonging to another state.
  #
  # `|| { …; return 1; }` rather than a bare `[[ … ]]`: bash 3.2 does not apply errexit to a failing
  # `[[ ]]`, so on macOS a bare one continues and only the test's LAST command decides pass/fail —
  # verified on 3.2.57, where a bare assertion for a message that had been deleted still passed.
  [[ "$output" == *"could not set the family group"* ]] \
    || { echo "state (a) does not name the group failure: $output" >&2; return 1; }
}

# The critical property: a bind-mounted file must keep its inode across a rewrite.
# rc 5 must be REPAIRABLE: the documented remedy is to get the group sorted and run again, so a
# retry has to re-apply mode and group even when the content merge is a complete no-op.
# A process substitution's exit status is UNOBSERVABLE, so a `sed` that dies after emitting part of
# its output would leave the read loop reporting success — and the writer would hash and write that
# truncated body under a valid marker. Verified against the old form: it returned 0 and grew the
# file from 2 lines to 3 (the merge applied to a truncated body); the current form returns 1 and
# leaves the file byte-identical.
@test "a failure while re-reading the body refuses instead of writing a truncated file" {
  local shim="$BATS_TEST_TMPDIR/shim" f total before
  mkdir -p "$shim"
  # Count ONLY `sed '$d'` calls — the lock parser's `sed -n` must not shift the ordinal — and fail
  # the one named by SEDSHIM_FAIL_ON.
  cat > "$shim/sed" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = '$d' ]; then
  c="$SEDSHIM_COUNTER"; n=$(( $(cat "$c" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$c"
  if [ "$n" = "${SEDSHIM_FAIL_ON:-0}" ]; then printf 'MYTHICAL_BROKKR_RETENTION=30\n'; exit 3; fi
fi
exec /usr/bin/sed "$@"
EOF
  chmod +x "$shim/sed"

  write_conf                                   # a file holding only RETENTION
  f="$(mi_conf_product_path brokkr)"
  cp "$f" "$BATS_TEST_TMPDIR/orig"
  SEDSHIM_COUNTER="$BATS_TEST_TMPDIR/n"; export SEDSHIM_COUNTER

  # CALIBRATE, do not hard-code. The body capture is the LAST `sed '$d'` of the operation, but how
  # many precede it is an implementation detail that has already changed twice in this plan's
  # history — and a wrong ordinal makes this test silently unable to fail. So: run the identical
  # operation once counting only, take the total, restore, then fail exactly that call.
  echo 0 > "$SEDSHIM_COUNTER"
  SEDSHIM_FAIL_ON=0 PATH="$shim:$PATH" mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  total="$(cat "$SEDSHIM_COUNTER")"
  [ "$total" -ge 1 ]                           # a zero total would make the injection a no-op

  cp "$BATS_TEST_TMPDIR/orig" "$f"
  echo 0 > "$SEDSHIM_COUNTER"
  before="$(mi_digest "$f")"

  SEDSHIM_FAIL_ON="$total" PATH="$shim:$PATH" run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  [ "$status" -ne 0 ]
  [ "$(mi_digest "$f")" = "$before" ]
}

# The file is bind-mounted into a container, so its SIZE is attacker-controlled too. An unbounded
# copy would expand it into real TMPDIR storage and then into a bash variable.
@test "an oversized product conf is refused, and leaves no snapshot behind" {
  local iso f; iso="$(mktemp -d)"; f="$(mi_conf_product_path brokkr)"
  { printf 'MYTHICAL_BROKKR_RETENTION=30\n'
    head -c "$MI_CONF_MAXBYTES" /dev/zero | tr '\0' '#'
    printf '\n'; } > "$f"
  TMPDIR="$iso" run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  [ -z "$(find "$iso" -type f)" ]
  rm -rf "$iso"
}

@test "a retry after rc 5 repairs the mode and the group" {
  run write_records_gid 4294967000 MYTHICAL_BROKKR_RETENTION 30
  [ "$status" -eq 5 ]
  run write_conf                       # identical pairs, real gid: nothing to merge
  [ "$status" -eq 0 ]
  local f; f="$(mi_conf_product_path brokkr)"
  [ "$(ls -l  "$f" | awk 'NR==1{print substr($1,1,10)}')" = "-rw-rw----" ]
  [ "$(ls -ldn "$f" | awk 'NR==1{print $4}')" = "$TEST_GID" ]
}

# A pure CONTENT no-op must not truncate and rewrite the live file. This is the ORDINARY path —
# re-install idempotence is "call it again with the same values" — and on a single-file bind mount a
# concurrently reading container can observe the truncated intermediate state, for zero content change.
#
# THE SIGNAL IS THE HARD PART, so it is built with its own control. Byte-identity and the inode cannot
# tell a rewrite from a skip (an in-place rewrite preserves both, by design), and an mtime read at
# 1-second granularity cannot be compared against a timestamp taken in the same second. So: plant a
# reference file, wait past a full timestamp tick, and ask `find -newer` — POSIX, and it compares at
# whatever resolution the filesystem actually keeps. mtime is the right clock precisely because the
# chgrp/chmod that the no-op path still applies by contract move ctime only.
#
# The CONTROL at the end is what stops this passing vacuously: the same signal must SEE a real merge.
# Without it, a `find` that never reports anything would make every assertion above trivially true.
@test "a no-op merge does not rewrite the file" {
  write_conf
  local f ref before inode
  f="$(mi_conf_product_path brokkr)"
  before="$(mi_digest "$f")"
  inode="$(ls -i "$f" | awk '{print $1}')"

  ref="$BATS_TEST_TMPDIR/ref"; : > "$ref"
  sleep 1

  run write_conf                       # identical pairs: nothing to merge
  [ "$status" -eq 0 ]
  [ -z "$(find "$f" -newer "$ref")" ] || { echo "the no-op rewrote $f" >&2; return 1; }
  [ "$(mi_digest "$f")" = "$before" ]
  [ "$(ls -i "$f" | awk '{print $1}')" = "$inode" ]

  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  [ "$status" -eq 0 ]
  [ -n "$(find "$f" -newer "$ref")" ] \
    || { echo "the -newer signal cannot see a real write — the assertion above proves nothing" >&2; return 1; }
}

# rc 1 in this module means "refused, file untouched" everywhere else, so a chmod failure — which
# happens AFTER the bytes have landed — must not borrow it. That state is exactly what rc 5 names.
#
# rc 5 is reached from THREE states, and the interface publishes only one of them ("the family group
# could not be set (0600)") — so a caller keying on rc 5 to tell an operator that would print a false
# diagnosis in state (b) below, where the group is exactly right and only the mode is wrong. The
# behaviour is correct; the messages have to be distinguishable. Both halves below assert that.
@test "a chmod failure after the bytes have landed reports rc 5, not rc 1" {
  local shim="$BATS_TEST_TMPDIR/chmodshim" f
  mkdir -p "$shim"
  cat > "$shim/chmod" <<'EOF'
#!/usr/bin/env bash
case "$1" in 660|600) exit 1 ;; esac
exec /bin/chmod "$@"
EOF
  chmod +x "$shim/chmod"                          # real chmod: the shim is not on PATH yet
  f="$(mi_conf_product_path brokkr)"

  # STATE (b): chgrp SUCCEEDS, chmod 660 fails. The group is correct.
  #
  # Every message assertion below uses `|| { …; return 1; }` rather than a bare `[[ … ]]`: bash 3.2
  # does not apply errexit to a failing `[[ ]]`, so on macOS a bare one continues and only the test's
  # LAST command decides pass/fail. Verified on 3.2.57 by deleting the message these assert and
  # watching the bare form still pass.
  PATH="$shim:$PATH" run write_conf
  [ "$status" -eq 5 ]
  [[ "$output" == *"0660"* ]] || { echo "state (b) does not name mode 0660: $output" >&2; return 1; }
  # …and the message says the group IS set, rather than blaming it. This is the false diagnosis the
  # single-message version invited: "the family group could not be set" is simply untrue here.
  [[ "$output" == *"The group IS set"* ]] \
    || { echo "state (b) does not say the group is set: $output" >&2; return 1; }
  [[ "$output" != *"could not set the family group"* ]] \
    || { echo "state (b) falsely blames the family group: $output" >&2; return 1; }
  [ "$(ls -ldn "$f" | awk 'NR==1{print $4}')" = "$TEST_GID" ]     # the group really is the family gid
  # The distinction rc 5 carries and rc 1 would deny: the content is committed and readable.
  [ -f "$f" ]
  [ "$(pget MYTHICAL_BROKKR_RETENTION)" = "30" ]

  # STATE (c): chgrp FAILS and so does the 0600 fallback — still rc 5, with its own message, and NOT
  # the "It is mode 0600" claim, which would now be false.
  PATH="$shim:$PATH" run write_records_gid 4294967000 MYTHICAL_BROKKR_RETENTION 30
  [ "$status" -eq 5 ]
  [[ "$output" == *"OR mode 0600"* ]] \
    || { echo "state (c) does not name both failures: $output" >&2; return 1; }
  [[ "$output" == *"neither 0660 nor 0600"* ]] \
    || { echo "state (c) does not say the mode is unknown: $output" >&2; return 1; }
  [[ "$output" != *"It is mode 0600"* ]] \
    || { echo "state (c) claims mode 0600, which it could not set: $output" >&2; return 1; }
  [ "$(pget MYTHICAL_BROKKR_RETENTION)" = "30" ]
}

@test "a rewrite keeps the same inode — a bind mount must not be detached" {
  write_conf
  local f before after
  f="$(mi_conf_product_path brokkr)"
  before="$(ls -i "$f" | awk '{print $1}')"
  mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  after="$(ls -i "$f" | awk '{print $1}')"
  [ "$before" = "$after" ]
  [ "$(pget MYTHICAL_BROKKR_RETENTION)" = "30" ]
  [ "$(pget MYTHICAL_BROKKR_THEME)" = "dark" ]
}

# D19 "serialize safely on write": a value carrying a newline must not be able to forge a second
# KEY=VALUE line in the written file. The value is a single ARGUMENT carrying a newline — which is
# what a record-stream interface could not distinguish from a deliberate second record.
# _mi_conf_value_ok is what refuses it.
@test "a value containing a newline is refused and nothing is written" {
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME "$(printf 'dark\nMYTHICAL_BROKKR_RETENTION=1')"
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_product_path brokkr)" ]
}

@test "a key outside the product spec is refused on write, leaving no partial file" {
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_NET evil
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_product_path brokkr)" ]
}

@test "one bad pair in a batch rejects the whole write — no partial file" {
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark MYTHICAL_BROKKR_RETENTION 999
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_product_path brokkr)" ]
}

@test "the same key given twice in one call is refused" {
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 30 MYTHICAL_BROKKR_RETENTION 40
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_product_path brokkr)" ]
}

@test "an odd number of arguments is refused" {
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION
  [ "$status" -ne 0 ]
}

# D9: *.conf is user-owned, so adding a key must not destroy what this call did not write.
@test "adding a key preserves comments, ordering and untouched keys" {
  local f; f="$(mi_conf_product_path brokkr)"
  plant_conf "$(printf '# my note\nMYTHICAL_BROKKR_RETENTION=30')"

  mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark

  [ "$(head -n1 "$f")" = "# my note" ]
  [ "$(sed -n '2p' "$f")" = "MYTHICAL_BROKKR_RETENTION=30" ]
  [ "$(sed -n '3p' "$f")" = "MYTHICAL_BROKKR_THEME=dark" ]
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
}

@test "adding a key that already holds a different value is refused" {
  plant_conf 'MYTHICAL_BROKKR_RETENTION=30'
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 90
  [ "$status" -ne 0 ]
  [ "$(pget MYTHICAL_BROKKR_RETENTION)" = "30" ]
}

# B3: a body line that merely LOOKS like a marker must not be treated as a comment — and must
# certainly not be silently deleted by the next write.
@test "a marker-prefix line in the body is rejected, not treated as a comment" {
  plant_conf "$(printf '%sdeadbeef\nMYTHICAL_BROKKR_RETENTION=30' "$MI_CONF_MARKER_PREFIX")"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *"final line"* ]]
}

@test "a call with too few arguments refuses instead of aborting under set -u" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_conf_product_add brokkr; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]] || { echo "execution continued past the refusal: $output" >&2; return 1; }
  [[ "$output" != *"unbound variable"* ]]
}

@test "a set into a torn file is refused rather than re-blessing damage" {
  write_conf
  local f; f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENTION=30\n#mythical-conf-sha256=deadbeef\n' > "$f"
  run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  [ "$status" -eq 4 ]
  [ "$(tail -n1 "$f")" = "#mythical-conf-sha256=deadbeef" ]
}

# §10a / D19: a launch-spec key must not be settable through the product file.
@test "a launch-spec key is not in the product spec, so reading it is a rejection" {
  plant_conf 'MYTHICAL_NET=host'
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *MYTHICAL_NET* ]]
}

@test "a symlinked product conf is refused on both read and write" {
  local f; f="$(mi_conf_product_path brokkr)"
  ln -s "$(mi_conf_family_path)" "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  run write_conf
  [ "$status" -ne 0 ]
}

# §10a: "hardlinked <product>.conf — to mythical.conf, or to bin/mythical-ctl — refused on
# distinct-identity and link-count checks; symlink tests alone pass this".
@test "a product conf hardlinked to mythical.conf is refused" {
  local fam prod; fam="$(mi_conf_family_path)"; prod="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_NET=n\n' > "$fam"; chmod 600 "$fam"
  ln "$fam" "$prod"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  run write_conf
  [ "$status" -ne 0 ]
  # mythical.conf survived untouched
  [ "$(mi_conf_get "$fam" MYTHICAL_NET)" = "n" ]
}

@test "a product conf hardlinked to a file under bin/ is refused" {
  local victim prod
  victim="$MYTHICAL_HOME/bin/mythical-ctl"; prod="$(mi_conf_product_path brokkr)"
  printf '#!/usr/bin/env bash\necho hi\n' > "$victim"
  ln "$victim" "$prod"
  run write_conf
  [ "$status" -ne 0 ]
  [ "$(head -n1 "$victim")" = "#!/usr/bin/env bash" ]
}

# OWNERSHIP. §4.5/D60 fixes owner=operator and mi_conf_product_add's comment asserts it, but nothing
# verified it: the gate checked symlink, regular-file and link count only. On a rootful runtime with no
# userid remapping, a compromised container can `chown 0:0 <product>.conf; chmod 0666` — every other
# check still passes, the host reads and accepts the file, the content write SUCCEEDS because the mode
# is world-writable, and only the chgrp/chmod afterwards fail. The file is left rewritten, root-owned
# and world-writable, i.e. steerable by any local user.
#
# SHIMMING `ls` IS THE HONEST TEST HERE, and the alternative is worse. chown'ing to a uid we are not is
# root-only, so a behavioural version of this test would have to `skip` on every developer machine and
# in CI — permanently green, proving nothing. The check reads the owner through exactly ONE observable,
# `ls -ldn` field 3, so substituting that observable exercises the real gate on the real code path: the
# refusal itself, its ordering against the other gates, and that neither reader nor writer proceeds.
# What the shim does not prove is that the kernel and `ls` agree about uids — which is not what is
# under test, and is separately covered by running the whole suite under a BSD-only userland.
@test "a product conf owned by another uid is refused on both read and write" {
  local shim="$BATS_TEST_TMPDIR/lsshim" f before
  mkdir -p "$shim"
  # Rewrite ONLY the numeric long listing, where the owner is read. Everything else — including the
  # `ls -ld` link count the gate above it uses — passes through untouched.
  cat > "$shim/ls" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-ldn" ]; then
  /bin/ls "$@" | awk 'NR==1{$3="4294967000"}1'
  exit $?
fi
exec /bin/ls "$@"
EOF
  chmod +x "$shim/ls"

  write_conf
  f="$(mi_conf_product_path brokkr)"
  before="$(mi_digest "$f")"

  PATH="$shim:$PATH" run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *"owned by uid 4294967000"* ]] || { echo "the refusal does not name the foreign owner: $output" >&2; return 1; }

  PATH="$shim:$PATH" run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  [ "$status" -ne 0 ]
  # untouched: the refusal happens before the create and before the write
  [ "$(mi_digest "$f")" = "$before" ]
}

# Guarded like the link count: an identity we cannot read is a refusal, never an assumption that the
# file is ours.
@test "an unreadable owner is refused rather than assumed to be ours" {
  local shim="$BATS_TEST_TMPDIR/lsshim-mute" f before
  mkdir -p "$shim"
  cat > "$shim/ls" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-ldn" ]; then exit 0; fi    # a listing that says nothing at all about the owner
exec /bin/ls "$@"
EOF
  chmod +x "$shim/ls"

  write_conf
  f="$(mi_conf_product_path brokkr)"
  before="$(mi_digest "$f")"

  PATH="$shim:$PATH" run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
  [[ "$output" == *"cannot read the owner"* ]] || { echo "the refusal does not name an unreadable owner: $output" >&2; return 1; }

  PATH="$shim:$PATH" run mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_THEME dark
  [ "$status" -ne 0 ]
  [ "$(mi_digest "$f")" = "$before" ]
}

@test "a matching marker reads silently" {
  write_conf
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
  [ "$output" = "$(printf 'MYTHICAL_BROKKR_RETENTION\t30')" ]
}

# Decisions item 3, strict: a stale marker is torn even when the body still parses. This is the
# case that matters — a write torn at a LINE BOUNDARY leaves a parseable file missing settings.
@test "a stale marker over a parseable body is torn, not accepted" {
  write_conf
  local f marker; f="$(mi_conf_product_path brokkr)"
  marker="$(tail -n1 "$f")"
  # an editor rewrite: body changed, marker line left as it was
  printf 'MYTHICAL_BROKKR_RETENTION=90\n%s\n' "$marker" > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
  [[ "$output" != *$'\t'"90"* ]]
}

# The truncation this strictness exists to catch: a two-setting file cut after the first line.
@test "a write torn at a line boundary is detected, not silently applied" {
  mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 30 MYTHICAL_BROKKR_THEME dark
  local f; f="$(mi_conf_product_path brokkr)"
  head -n1 "$f" > "$f.cut" && mv "$f.cut" "$f"     # a clean, parseable, INCOMPLETE file
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
}

# Intact bytes that are nonetheless not valid config: a rejection, not damage.
@test "a matching marker over a malformed body is rejected, not reported as torn" {
  plant_conf 'this is not an assignment'
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]
}

@test "reading never rewrites the file" {
  write_conf
  local f before after
  f="$(mi_conf_product_path brokkr)"
  before="$(mi_digest "$f")"
  mi_conf_product_load brokkr "$SPEC" >/dev/null 2>&1 || true
  after="$(mi_digest "$f")"
  [ "$before" = "$after" ]
}

# A torn write cut mid-line: neither parses nor matches the marker. The report must name BOTH
# causes, because the operator cannot tell them apart from the file alone.
@test "a torn file reports rc 4 so the caller uses defaults, and names both remedies" {
  local f; f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENT\n#mythical-conf-sha256=deadbeef\n' > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
  [[ "$output" == *"recompute the marker"* ]] || { echo "the torn report does not name the recompute remedy: $output" >&2; return 1; }
  [[ "$output" == *"interrupted"* ]]
}

@test "a file with no marker at all is torn — a writer that skipped the contract is not trusted" {
  local f; f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENTION=15\n' > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
  [[ "$output" != *$'\t'"15"* ]]
}

# The rc-4 contract must survive the entrypoint's strict mode, where a bare `x="$(cmd)"; rc=$?`
# would abort at the assignment and never return 4 at all.
@test "the torn contract holds under set -euo pipefail" {
  local f; f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENT\n#mythical-conf-sha256=deadbeef\n' > "$f"
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_conf_product_load brokkr "$1"; echo "unreachable"' _ "$SPEC"
  [ "$status" -eq 4 ]
  [[ "$output" != *unreachable* ]]
}

# B2: the product name becomes a pathname. 'mythical' is the host-only file; the rest escape the
# flat namespace entirely. None may produce a path, and none may create a file.
@test "an invalid product name is refused and creates nothing" {
  local n
  for n in mythical ../outside bin/x .. . 'Brokkr' 'a b' '' '-lead' 'x/../y'; do
    run mi_conf_product_path "$n"
    [ "$status" -ne 0 ] || { echo "path accepted product name '$n'" >&2; return 1; }
    # STDOUT only. bats folds stderr into $output, and the refusal message quotes the name back —
    # which for '../outside' contains a '/', so asserting on $output would fail on the diagnostic
    # rather than on a leaked path. The contract is "prints no path", not "prints nothing at all".
    local out; out="$(mi_conf_product_path "$n" 2>/dev/null || true)"
    [ -z "$out" ] || { echo "path leaked for '$n': $out" >&2; return 1; }
    run mi_conf_product_add "$n" "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 30
    [ "$status" -ne 0 ] || { echo "write accepted product name '$n'" >&2; return 1; }
  done
  # nothing outside the one legitimate name was created
  [ ! -e "$MYTHICAL_HOME/mythical.conf" ]
  [ ! -e "$MYTHICAL_HOME/../outside.conf" ]
}

@test "valid product names are accepted" {
  local n
  for n in brokkr skuld saga my-product a a1; do
    run mi_conf_product_path "$n"
    [ "$status" -eq 0 ] || { echo "rejected valid name '$n'" >&2; return 1; }
    [ "$output" = "$MYTHICAL_HOME/${n}.conf" ]
  done
}

@test "mi_conf_product_load refuses bad arity instead of aborting under set -u" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_conf_product_load brokkr; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]] || { echo "execution continued past the refusal: $output" >&2; return 1; }
  [[ "$output" != *"unbound variable"* ]]
}

# The file is container-writable, so every byte examined must come from ONE snapshot. A behavioural
# test cannot interleave a container's rewrite between two internal opens without a hook, so this
# locks in the structure: the only place the live file is read is the snapshot copy, and NEITHER
# public function re-opens it afterwards. Both races this closes are real — the reader's (validate
# then parse) and the writer's (validate then rebuild the body) — and the writer's is the worse one,
# because it ends with the host re-blessing the swapped content with a valid marker.
@test "the live file is read exactly once, into a snapshot" {
  local src="${_MCTL_ROOT}/lib/config.sh" fn
  [ -n "$(awk '/^_mi_conf_snap\(\) \{/,/^\}/' "$src" | grep -F 'head -c "$MI_CONF_SNAP_LIMIT" "$f" > "$snap"')" ]
  [ -n "$(awk '/^_mi_conf_snap_load\(\) \{/,/^\}/' "$src" | grep -F "sed '\$d' \"\$snap\"")" ]
  # No function except _mi_conf_snap may READ the live file's content. Be honest about what this is:
  # a DENYLIST. It names the plausible content-reading commands and the internal helpers that read on
  # a caller's behalf, and catches the forms a regression would actually be written in — `cat "$f"`,
  # `tail "$f"`, `< "$f"`, `_mi_conf_marker_ok "$f"`, and the same with braces. It does not and cannot
  # prove the negative: a sufficiently inventive spelling would still get past it. (An earlier version
  # of this comment claimed the pattern "denies the whole class" and called naming individual commands
  # "a fig leaf" — while itself naming individual commands. Three evasions were green at the time:
  # `od -c "$f"`, `nl "$f"`, and a braced `_mi_conf_marker_ok "${f}"`.)
  #
  # What keeps it from going VACUOUS — the failure mode that actually bit here — is the range
  # assertion below: if the awk range ever stops matching the function it names, the loop fails loudly
  # instead of silently checking nothing.
  #
  # The permitted uses ([ -f "$f" ], chmod, chgrp, > "$f", the identity checks, diagnostics) pass by
  # not matching. `ls` is deliberately absent: _mi_conf_identity_ok only STATS the path — twice, since
  # it reads the link count and the owner — and never its content.
  #
  # `index($0,f)==1` and not a -v regex: `awk -v f="^${fn}\\(\\) \\{"` mangles the escapes, awk warns
  # "escape sequence \( treated as plain (", the range matches ZERO lines, and the loop passes
  # vacuously — a test that cannot fail. The wc -l guard below makes that impossible to reintroduce.
  # Both halves matter. External commands are the obvious way to reopen the file; INTERNAL helpers
  # are the quiet one — a regression calling `_mi_conf_marker_ok "$f"` reads the live file just as
  # thoroughly as `tail "$f"` does, and a check that only knew about commands would wave it through.
  # `_mi_conf_snap "$f"` and `_mi_conf_identity_ok "$f"` are deliberately absent: the first IS the
  # sanctioned read, and the second only stats. `_mi_conf_unchanged "$f"` is absent for the third
  # reason given at its definition — it compares a digest and never derives configuration from what it
  # reads, which is why it is a named function at all. Adding any of those three would fail this test
  # against correct code.
  #
  # BRACE-TOLERANT: `"${f}"` reads the live file exactly as thoroughly as `"$f"` does, and a pattern
  # that only knew the unbraced spelling waved it through. `[{]?`/`[}]?` rather than `\{?`/`\}?` — a
  # bare `{` in an ERE starts an interval, and the escaped form is not equally accepted everywhere.
  local F='"\$[{]?f[}]?"'
  local READERS='\b(cat|sed|awk|grep|head|tail|cut|tr|wc|sort|source|od|nl|dd|rev|xxd|cmp|md5sum|shasum|sha256sum|python3|perl)\b[^#]*'"$F"
  local HELPERS='\b(_mi_conf_marker_ok|_mi_conf_last_is_marker|_mi_conf_bytes_ok|_mi_conf_scan_stream|_mi_conf_snap_load|mi_digest|mi_conf_scan|mi_conf_load|mi_conf_get)[[:space:]]+'"$F"
  local REDIR='<[[:space:]]*'"$F"
  for fn in mi_conf_product_load mi_conf_product_add _mi_conf_snap_load; do
    [ "$(awk -v f="${fn}() {" 'index($0,f)==1,/^\}/' "$src" | wc -l)" -gt 1 ] \
      || { echo "range for $fn matched nothing — the check would pass vacuously" >&2; return 1; }
    if awk -v f="${fn}() {" 'index($0,f)==1,/^\}/' "$src" | sed 's/#.*//' \
         | grep -qE "${READERS}|${HELPERS}|${REDIR}"; then
      echo "$fn reads the live file's content — only _mi_conf_snap may" >&2; return 1
    fi
  done
}

@test "a file that does not end in a newline is torn, not a parse error" {
  local f; f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENTION=30\n%sdeadbeef' "$MI_CONF_MARKER_PREFIX" > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
}

# Under `set -e` a bare failing call exits the shell on the spot. If the loader invoked
# _mi_conf_snap_load that way, it would never RETURN 4 — the CLI would die — and the snapshot would
# leak. TMPDIR is isolated so "leaked" is directly observable rather than inferred.
@test "a failing load still returns its contract code and leaves no snapshot behind" {
  local iso; iso="$(mktemp -d)"
  local f; f="$(mi_conf_product_path brokkr)"

  printf 'MYTHICAL_BROKKR_RETENT\n%sdeadbeef\n' "$MI_CONF_MARKER_PREFIX" > "$f"
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    TMPDIR="$2" mi_conf_product_load brokkr "$1"' _ "$SPEC" "$iso"
  [ "$status" -eq 4 ]
  [ -z "$(find "$iso" -type f)" ]

  plant_conf 'MYTHICAL_NOT_IN_SPEC=1'
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    TMPDIR="$2" mi_conf_product_load brokkr "$1"' _ "$SPEC" "$iso"
  [ "$status" -eq 1 ]
  [ -z "$(find "$iso" -type f)" ]

  rm -rf "$iso"
}

@test "a missing product conf reports rc 3, distinct from torn" {
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 3 ]
}

@test "writing without the family lock is refused" {
  mi_lock_release
  run write_conf
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_product_path brokkr)" ]
}
