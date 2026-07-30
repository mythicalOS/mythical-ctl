#!/usr/bin/env bats
load '../lib/test_helper'

# setup_test_env FIRST — see Task 1 Step 4. No teardown() override: the helper's cleans up.
setup() {
  setup_test_env
  load_mctl
  mi_ensure_layout
  mi_lock_acquire
  SPEC="$(printf 'MYTHICAL_BROKKR_RETENTION\tint:1:365\nMYTHICAL_BROKKR_THEME\tenum:light|dark')"
  TEST_GID="$(id -G | awk '{print $1}')"
}

# INDEPENDENT implementations of the two recipes docs/CONFIG-FORMAT.md publishes — transcribed from
# the document, deliberately calling nothing in lib/config.sh (not even mi_digest). If either
# disagrees with the CLI, the document or the code is wrong, and the whole point of publishing a
# format is that a second implementation can be written from it.
#
# Both hash a FILE STREAM. Note what neither does: `body=$(cat f)` then hashing "$body" — command
# substitution strips trailing newlines, which silently hashes different bytes than the file holds.
# That is the single easiest way for another implementer to get this wrong.
doc_hash_stream() {   # recipe 1: hash a body file
  if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1" | cut -d' ' -f1
  else                                          shasum -a 256 < "$1" | cut -d' ' -f1; fi
}
doc_hash_finished() { # recipe 2: hash a finished conf minus its last line
  if command -v sha256sum >/dev/null 2>&1; then sed '$d' "$1" | sha256sum | cut -d' ' -f1
  else                                          sed '$d' "$1" | shasum -a 256 | cut -d' ' -f1; fi
}

# The marker prefix as the DOCUMENT spells it, not as the code exports it. Every fixture below builds
# — and strips — its marker line using THIS literal and nothing else, so a fixture cannot be "right"
# merely because it agrees with the constant it is supposed to be checking. One test compares the two
# on purpose; it is the only place in this file where the code's constant appears.
#
# The claim used to be false: one fixture built its marker from $MI_CONF_MARKER_PREFIX and two more
# spelled the prefix inline a third time. A suite whose entire value is being written from the
# published document cannot borrow the code's constant to build the input it feeds the code.
DOC_MARKER='#mythical-conf-sha256='

@test "both documented recipes agree with the CLI, on a multi-line body" {
  mi_conf_product_add brokkr "$SPEC" "$TEST_GID" MYTHICAL_BROKKR_RETENTION 30 MYTHICAL_BROKKR_THEME dark
  local f written
  f="$(mi_conf_product_path brokkr)"
  written="$(tail -n1 "$f")"; written="${written#"$DOC_MARKER"}"
  [ "$written" = "$(doc_hash_finished "$f")" ]
  sed '$d' "$f" > "$MYTHICAL_HOME/body.txt"
  [ "$written" = "$(doc_hash_stream "$MYTHICAL_HOME/body.txt")" ]
}

@test "a file built by hand from the document is accepted by the CLI" {
  local f sum
  f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENTION=7\nMYTHICAL_BROKKR_THEME=light\n' > "$MYTHICAL_HOME/body.txt"
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  cp "$MYTHICAL_HOME/body.txt" "$f"
  printf '%s%s\n' "$DOC_MARKER" "$sum" >> "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
  [[ "$output" == *"MYTHICAL_BROKKR_RETENTION"$'\t'"7"* ]] || { echo "the CLI did not accept the hand-built file: $output" >&2; return 1; }
  [[ "$output" == *"MYTHICAL_BROKKR_THEME"$'\t'"light"* ]]
}

# The trap the document warns about, proved to BE a trap: if it were not, the warning would be
# noise and an implementer would rightly ignore it.
@test "the command-substitution shortcut the document warns against really does differ" {
  printf 'MYTHICAL_BROKKR_RETENTION=7\n' > "$MYTHICAL_HOME/body.txt"
  local correct wrong body
  correct="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  body="$(cat "$MYTHICAL_HOME/body.txt")"          # strips the trailing newline
  if command -v sha256sum >/dev/null 2>&1; then
    wrong="$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
  else
    wrong="$(printf '%s' "$body" | shasum -a 256 | cut -d' ' -f1)"
  fi
  [ "$correct" != "$wrong" ]
}

# The document and the code must not drift apart on the one string every other implementation
# has to hard-code. This is the ONE test that may name both sides — it exists to compare them.
@test "the marker prefix in the document matches the constant in the code" {
  [ "$MI_CONF_MARKER_PREFIX" = "$DOC_MARKER" ]
  grep -Fq "$DOC_MARKER" "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
}

# The document says quotes are NOT stripped — prove it, because it is the single most likely thing
# another implementer gets wrong. The fixture needs a VALID marker: without one the strict marker
# gate returns 4 before the parser ever sees the value, and the test would pass for the wrong reason.
@test "the documented value rules match what the parser enforces" {
  local f body sum
  f="$(mi_conf_product_path brokkr)"
  body='MYTHICAL_BROKKR_THEME="dark"'
  printf '%s\n' "$body" > "$MYTHICAL_HOME/body.txt"
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  printf '%s\n%s%s\n' "$body" "$DOC_MARKER" "$sum" > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 1 ]          # rejected by the enum, not by the marker gate
}

# --- the document's case rule ---------------------------------------------------------------------
# "The hex must be lowercase." The comparison is a literal string compare, so the UPPERCASE form of a
# CORRECT digest is a mismatch. Worth a test rather than a sentence: sha256sum and shasum both emit
# lowercase, so a shell implementer never meets this, while a hex encoder in another language may
# default to uppercase and produce files that are torn forever with a digest that is arithmetically
# right. `tr a-f A-F` on the hex only — the prefix has no hex letters to disturb.
@test "an UPPERCASE marker is rejected even when the digest itself is correct" {
  local f sum upper
  f="$(mi_conf_product_path brokkr)"
  printf 'MYTHICAL_BROKKR_RETENTION=7\n' > "$MYTHICAL_HOME/body.txt"
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  upper="$(printf '%s' "$sum" | tr 'a-f' 'A-F')"
  [ "$upper" != "$sum" ]                        # the fixture must actually differ, or it proves nothing
  cp "$MYTHICAL_HOME/body.txt" "$f"
  printf '%s%s\n' "$DOC_MARKER" "$upper" >> "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]                           # torn, not accepted, not merely malformed

  # …and the lowercase form of the SAME digest is accepted, so the test above isolates case and
  # nothing else.
  cp "$MYTHICAL_HOME/body.txt" "$f"
  printf '%s%s\n' "$DOC_MARKER" "$sum" >> "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
}

# --- the document's empty-configuration rule ------------------------------------------------------
# "A marker-only file is valid": zero body lines, marker = sha256 of the empty byte string. This is
# the form a product UI with nothing to persist should write, so it has to load rather than error.
@test "a marker-only file is valid and loads as an empty configuration" {
  local f empty sum
  f="$(mi_conf_product_path brokkr)"
  : > "$MYTHICAL_HOME/body.txt"                 # zero bytes: no body lines at all
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  # The document publishes this constant; if the independent recipe disagrees with it, the document
  # is wrong about which digest to write.
  empty='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  [ "$sum" = "$empty" ]
  grep -Fq "$empty" "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
  printf '%s%s\n' "$DOC_MARKER" "$sum" > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
  [ -z "$output" ]                              # loaded, and set nothing
}

# The neighbouring claim, which the rule above invites an implementer to get wrong: an EMPTY file is
# not an empty configuration. It has no marker, so it is indistinguishable from a write that died
# before reaching one, and it must fail closed.
@test "a zero-byte file is torn, not an empty configuration" {
  local f
  f="$(mi_conf_product_path brokkr)"
  : > "$f"
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 4 ]
}

# --- the document's whole-file size ceiling -------------------------------------------------------
# Emit a comment-only pad of EXACTLY $1 bytes, in short lines. Independent of lib/config.sh, and
# deliberately not one enormous line: a 1 MiB single line is a line-length limit in some seds, and
# the ceiling is a property of the FILE, not of any line in it.
#
# Grown by DOUBLING, not by appending a line at a time. bats installs a DEBUG trap to track the
# current line, so it pays that trap once per command executed — a 13,000-iteration append loop costs
# ~5s per call, doubling costs ~14 iterations and is immeasurable. The block is a whole number of
# 80-byte lines, so truncating it at a multiple of 80 cannot cut a line in half.
doc_pad() {
  local want="$1" line blk n
  line='#'
  while [ "${#line}" -lt 79 ]; do line="$line$line"; done
  blk="${line:0:79}"$'\n'                       # exactly one 80-byte comment line
  n=$(( want / 80 * 80 ))
  if [ "$n" -gt 0 ]; then
    while [ "${#blk}" -lt "$n" ]; do blk="$blk$blk"; done
    printf '%s' "${blk:0:$n}"
  fi
  want=$(( want - n ))
  if   [ "$want" -eq 1 ]; then printf '\n'
  elif [ "$want" -ge 2 ]; then printf '#%*s\n' "$(( want - 2 ))" ''
  fi
}

# Build a valid <product>.conf of EXACTLY $1 bytes: one real setting, a comment pad, and a correct
# marker computed by the document's own recipe. The marker line is prefix + 64 hex + newline, which
# is where the 65 comes from.
#
# The path is spelled out from the document's own layout (`~/.mythical/<product>.conf`) rather than
# taken from mi_conf_product_path, so that nothing on the document's side of this suite borrows from
# lib/config.sh — the whole point is a second implementation built only from what is published.
doc_conf_of_size() {
  local total="$1" f body
  f="${MYTHICAL_HOME}/brokkr.conf"
  body=$(( total - ${#DOC_MARKER} - 65 ))
  { printf 'MYTHICAL_BROKKR_RETENTION=7\n'; doc_pad $(( body - 28 )); } > "$MYTHICAL_HOME/body.txt"
  [ "$(wc -c < "$MYTHICAL_HOME/body.txt" | tr -d ' ')" -eq "$body" ]
  cp "$MYTHICAL_HOME/body.txt" "$f"
  printf '%s%s\n' "$DOC_MARKER" "$(doc_hash_stream "$MYTHICAL_HOME/body.txt")" >> "$f"
  [ "$(wc -c < "$f" | tr -d ' ')" -eq "$total" ]
}

@test "a <product>.conf of exactly 1048576 bytes is accepted — the ceiling is inclusive" {
  doc_conf_of_size 1048576
  run mi_conf_product_load brokkr "$SPEC"
  [ "$status" -eq 0 ]
  [[ "$output" == *"MYTHICAL_BROKKR_RETENTION"$'\t'"7"* ]]
}

@test "a <product>.conf of 1048577 bytes is refused outright, marker or no marker" {
  doc_conf_of_size 1048577
  run mi_conf_product_load brokkr "$SPEC"
  # REFUSED (1), not torn (4): the size gate runs before the marker is even looked at. The marker in
  # this fixture is correct, so nothing but the size can be the reason.
  [ "$status" -eq 1 ]
  [[ "$output" == *"larger than 1048576 bytes"* ]]
}

# --- the document's own path ---------------------------------------------------------------------
# The torn-file message names this document BY PATH, so the path is shipped runtime output. A rename
# that misses the message leaves every operator who hits a torn file with a dangling pointer, and
# nothing else in the build would notice.
@test "the doc path in the shipped torn-file message resolves to a real file" {
  grep -aq 'docs/CONFIG-FORMAT.md' "${_MCTL_ROOT}/lib/config.sh"
  [ -f "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md" ]
  # …and the document says the reference exists, so a future rename has somewhere to have been warned.
  grep -Fq 'shipped runtime output' "${_MCTL_ROOT}/docs/CONFIG-FORMAT.md"
}

# The document publishes an ORDERED precedence for classification, and the order is the substance: it
# is what stops a NUL-bearing markerless file being reported as "torn, using defaults" when it is
# actually hostile content that must be refused. A cross-repo implementer reads this table to decide
# what to tell their user, so every row is verified against the CLI rather than asserted.
#
# Each fixture builds its marker from DOC_MARKER — the document's literal — and each row names the rc
# the document publishes for it. rc 0 accepted · 1 rejected/malformed · 3 absent · 4 torn.
@test "every row of the document's marker-precedence table matches the CLI" {
  local f sum body rc row
  f="$(mi_conf_product_path brokkr)"

  # Build a conforming file from the document's own recipe.
  doc_write() {
    body="$1"
    printf '%s\n' "$body" > "$MYTHICAL_HOME/body.txt"
    sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
    printf '%s\n%s%s\n' "$body" "$DOC_MARKER" "$sum" > "$f"
  }
  # `if cmd; then rc=0; else rc=$?; fi`, not a bare call followed by `rc=$?`: bats runs test bodies
  # under errexit, so the bare form aborts the test at the first non-zero rc — and every row here but
  # the last expects one.
  check() {                      # check <expected-rc> <row name>
    if mi_conf_product_load brokkr "$SPEC" >/dev/null 2>&1; then rc=0; else rc=$?; fi
    [ "$rc" -eq "$1" ] || { echo "row '$2': document says rc $1, CLI gave rc $rc" >&2; return 1; }
  }

  rm -f "$f"
  check 3 'file absent'

  printf 'MYTHICAL_BROKKR_RETENTION=30\000\n' > "$f"
  check 1 'control byte, no marker — malformed BEFORE any marker classification'

  printf 'MYTHICAL_BROKKR_RETENTION=30\n%sdead' "$DOC_MARKER" > "$f"
  check 4 'does not end in a newline'

  printf 'MYTHICAL_BROKKR_RETENTION=99\n%sdeadbeef\n' "$DOC_MARKER" > "$f"
  check 4 'marker absent or mismatched'

  # Uppercase the DIGEST only. `tail -n1 | tr a-f A-F` would also hit the prefix — the literal
  # `#mythical-conf-sha256=` contains a, c and f — producing `#mythiCAl-ConF-shA256=`, which is no
  # longer a marker line at all. rc 4 would then come from "no marker present", not from a literal
  # comparison against an uppercase digest, and this row would pass while testing nothing of the sort.
  printf 'MYTHICAL_BROKKR_RETENTION=30\n' > "$MYTHICAL_HOME/body.txt"
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  row="$(printf '%s' "$sum" | tr 'a-f' 'A-F')"
  [ "$row" != "$sum" ] || { echo 'the digest has no hex letters — this row proves nothing' >&2; return 1; }
  printf 'MYTHICAL_BROKKR_RETENTION=30\n%s%s\n' "$DOC_MARKER" "$row" > "$f"
  check 4 'marker correct but UPPERCASE — the compare is literal'

  : > "$f"
  check 4 'present but zero bytes'

  doc_write 'MYTHICAL_NOT_IN_SPEC=1'
  check 1 'marker matches, body off-schema — intact bytes are not damage'

  doc_write 'MYTHICAL_BROKKR_RETENTION=999'
  check 1 'marker matches, value fails its type'

  printf 'MYTHICAL_BROKKR_RETENTION=30\n' > "$MYTHICAL_HOME/body.txt"
  sum="$(doc_hash_stream "$MYTHICAL_HOME/body.txt")"
  printf 'MYTHICAL_BROKKR_RETENTION=30\n%s%s trailing\n' "$DOC_MARKER" "$sum" > "$f"
  check 4 'marker line has trailing text'

  doc_write "$(printf '%sdeadbeef\nMYTHICAL_BROKKR_RETENTION=30' "$DOC_MARKER")"
  check 1 'a marker-prefix line anywhere but the final line'

  { printf 'MYTHICAL_BROKKR_RETENTION=30\n'
    head -c 1048576 /dev/zero | tr '\0' '#'; printf '\n'; } > "$f"
  check 1 'over the size ceiling — reported as oversize, ahead of the byte policy'

  { printf 'MYTHICAL_BROKKR_RETENTION=30\000\n'
    head -c 1048576 /dev/zero | tr '\0' '#'; printf '\n'; } > "$f"
  check 1 'oversize AND a control byte — size is decided first'

  doc_write 'MYTHICAL_BROKKR_RETENTION=30'
  check 0 'marker matches and the body is valid'
}

# `<product>` becomes part of a pathname, so the document publishes its grammar — and the reservation
# of `mythical`, which is the HOST-ONLY file's name. An implementation that missed either would aim a
# product write at the file the host/container split depends on being unreachable, while looking
# correct. Both lists are transcribed from the document's own "Names that are refused" sentence.
@test "the product-name grammar the document publishes is the grammar the CLI enforces" {
  local n
  for n in mythical Brokkr 'a b' -lead a.b .. . ../outside bin/x x/../y '' \
           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; do
    if mi_conf_product_path "$n" >/dev/null 2>&1; then
      echo "the document forbids '$n' but the CLI accepted it" >&2; return 1
    fi
  done
  for n in brokkr skuld saga my-product a a1; do
    mi_conf_product_path "$n" >/dev/null 2>&1 \
      || { echo "the document allows '$n' but the CLI refused it" >&2; return 1; }
  done
}
