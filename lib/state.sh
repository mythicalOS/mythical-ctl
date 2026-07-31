#!/usr/bin/env bash
# D43 desired state, D50 its transitions, D52 the typed outstanding-check set, and the reconciler that
# reads them.
#
# THE ORDERING RULE, and it is the whole point: every transition is INTENT-FIRST, then act, then
# reconcile. An earlier revision specified the desired-state field without specifying the order, which
# leaves two broken interleavings:
#
#   stop the container, THEN crash  ⇒ desired is still `running` while it is stopped, so recovery
#                                     RESTARTS what the operator asked to stop.
#   write `stopped`, THEN crash     ⇒ desired is `stopped` while it is still running — a state the
#                                     recovery table did not contain at all.
#
# TWO RULES FROM lib/prov.sh RUN THROUGH EVERY FUNCTION HERE, because this module reads and writes the
# same ledger, and a rule enforced at one module's inputs and not at the next module's is how each of
# that file's defects got in:
#
#   * THE FIELD RULE APPLIES TO EVERY WRITER, INCLUDING THE ONES THAT DO NOT GO THROUGH mi_led_put.
#     mi_state_commit is the fifth such writer (after mi_prov_tombstone and mi_intent_confirm), so it
#     judges the field list it is about to serialize with _mi_led_fields_ok — the writer's own rule,
#     not a second one — or a TAB in a container name forges a field and a newline forges a record.
#   * A LOOKUP THAT DOES NOT RESOLVE TO EXACTLY ONE THING IS AMBIGUOUS, AND AMBIGUITY PRESERVES AND
#     REPORTS. There is one `desired` row per container, so the row a commit supersedes is resolved by
#     _mi_led_select — the one place that cardinality question is asked — and only that row is
#     dropped. Replacing two contradicting rows with one destroys the evidence that the ledger needs
#     repairing, which is the one thing these modules may never do. The OUTSTANDING set is different
#     by design: it is legitimately several rows per container, so the cardinality question does not
#     arise for it — which is exactly why the rule below has to be stated separately for it.
#
# AND THE RULE THIS MODULE OWNS: AN OUTSTANDING CHECK MAY ONLY DISAPPEAR WHEN THE THING IT NAMES WAS
# ACTUALLY VERIFIED. It has ONE home — _mi_state_filter, the single walk that rewrites a container's
# rows — and each entry point declares which of its three modes it uses:
#
#   +keep   mi_state_commit. A desired-state write is not a verification, so it drops NO outstanding
#           row: an entry already recorded survives a commit that does not mention it, and the pairs
#           the commit IS given are ADDED to the set. Replacing the set made a bare
#           `mi_state_commit <container> stopped` retire every check the container owed, with nothing
#           checked and nothing said.
#   +match  mi_state_outstanding_clear — the only path an entry disappears down. It names the KIND
#           AND THE PARAMETER, because the set holds several entries of one kind with different
#           parameters: verifying the alias on one network must not retire the check owed on another.
#           A clear that named only the kind could not express which check it had performed, so the
#           API accepted a state its own clear could not handle.
#   +all    mi_state_forget — a family uninstall, or `state repair` dropping a container's whole
#           recorded state. That is not a claim that anything was verified, and it is the only caller
#           allowed to say it.
#
# The same rule closes the READ side: an entry naming no parameter is refused rather than listed,
# because it schedules a verification of nothing and no clear can ever name it (mi_state_outstanding).
#
# And it is why there is exactly ONE writer of the `desired` row — mi_state_commit, which writes that
# row and the outstanding set in a single ledger write. A second writer that set `desired` alone
# existed for "intent-preserving" recreates, and it reopened precisely the window D50 closes: record
# `running`, start the container, crash before the alias check is written, and the container is
# observed = desired = running with nothing outstanding, so mi_state_plan answers `none` and the live
# verification is simply lost. Its public signature accepted either state and nothing enforced the
# narrow use its comment claimed. It is REMOVED rather than documented against — with the set
# preserved, `mi_state_commit <container> <state>` IS that intent-preserving write, taken through the
# atomic path.
#
# AND THE SAME RULE ONE LEVEL UP, WHICH IS WHAT THAT WINDOW IS AN INSTANCE OF: EVERY TRANSITION THAT
# LEAVES A CONTAINER RUNNING ENDS IN A LIVE VERIFICATION, so a `running` intent must SAY what it owes
# — and "nothing" is a thing it has to say OUT LOUD. `mi_state_commit <container> running` with no
# check wrote an empty outstanding set and recorded nothing about it, so a crash after starting left
# observed = desired = running with an empty set: plan `none`, fully reconciled, the alias never
# resolved even once (measured). That is BYTE FOR BYTE the state a COMPLETED verification leaves, so
# nothing downstream can tell the two apart. The distinction is therefore RECORDED rather than
# inferred from an absence:
#
#   * the `desired` row carries `verify=owed|none` — `owed` when the write leaves at least one
#     outstanding entry, `none` when the caller DECLARED that this intent owes no live verification
#     (the `+none` token, which shares the `+` prefix the modes below use for exactly their reason:
#     _mi_led_field_ok's name grammar excludes it, so a declaration can never be confused with a
#     check kind a later version defines);
#   * a `running` commit that would leave nothing outstanding and declares nothing is REFUSED;
#   * and a `desired` row that does not carry the field is refused ON READ. That is where the crash
#     case actually lives: this core can no longer write a silent row, but a restored, foreign or
#     older ledger still holds one, and reading it as "there is no work to do" is the whole defect.
#
# The declaration is a claim about the state the write LEAVES BEHIND, not about its own argument list.
# A commit preserves the outstanding set, so a commit carrying no pairs is not a commit that owes
# nothing — an intent-preserving rewrite of a container that already owes a check needs no
# declaration, and `+none` beside a surviving entry is a contradiction rather than a retirement.
#
# AND ITS PAIR: A CONTAINER IS RESUMED ONCE, THEN REPORTED. For desired `running`, every observed
# `stopped` planned `start verify` — and starting a container that exits immediately changes neither
# the desired state nor the outstanding set, so the next plan was IDENTICAL, for ever (measured:
# three consecutive plans, all `start verify`). No record could tell "has not been resumed" from "was
# resumed and did not stay up", because they were the same ledger. So the attempt is recorded too, as
# a `resumed` row, and it is:
#
#   set by     mi_state_resume_record — the only writer, called by the verb performing the plan.
#   read by    mi_state_plan, which answers `exited` rather than resuming a second time.
#   dropped by EVERY state write this module makes for that container, which is one line in
#              _mi_state_filter rather than a decision each caller makes: a commit re-states the
#              intent and grants a fresh attempt, a forget drops the container entirely, and a clear
#              reports a live verification — which is evidence the container came up, so the run this
#              row describes is over. Without that last one, a container that started perfectly well,
#              was verified, and was later stopped by hand or by a reboot would be reported for ever
#              as one that does not stay up, and never started again.
#
# And one rule this module shares with lib/intent.sh: ZERO IS ONLY EVIDENCE WHEN THE QUESTION WAS
# ANSWERED. `mi_rt_inspect` splits rc 3 (the object is gone) from rc 1 (the runtime could not answer),
# and the ledger readers split rc 3 (nothing recorded) from rc 1 (unreadable, or ambiguous). Every
# decision below consumes both halves of both splits. Folding either into "there is nothing there"
# makes the reconciler act on a fleet it could not read — which is exactly the direction that starts
# a container the operator stopped.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_STATE_KIND=desired
MI_OUT_KIND=outstanding
# The storage-migration record's kind, declared HERE because this module loads before lib/migrate.sh
# and needs it for the suspension check below. lib/migrate.sh REFERENCES it; it must not redefine it —
# two spellings of one ledger kind is how a suspension check stops matching the records it guards.
MI_MIG_KIND=storagemig
# The attempt record's kind: "this installer has already resumed that container under its currently
# recorded intent". One row per container, presence IS the fact — there is nothing else to say about
# it, and a count would invite a retry budget nobody has specified.
MI_RESUME_KIND=resumed

# D52: the outstanding set is TYPED, not a boolean. A single flag records no kind and no parameters,
# so a `start` would resolve an alias, clear the flag, and report success having never checked
# migrated storage. Each entry carries what kind of check is owed and what it needs.
#
#   alias   carries the network ID the alias must resolve on; cleared by probe resolution matching the
#           post-start endpoint (§6b.3 step 5).
#
# `alias` is the ONLY kind, deliberately. There is no `storage` kind: an earlier revision defined one
# carrying "the destination path and the expectation", cleared by "the container observably reading
# that path" — which is not implementable, because the entry holds a HOST path the container cannot
# see, and reading from inside would require the shell and tooling D48 refuses to assume any product
# image ships. What is verifiable is verified where it belongs: content host-side at D51 phase 4, and
# the mount by inspection at D51 phase 8. The container-side read is not performed and is NOT CLAIMED.
#
# The shape exists anyway because a boolean already proved unable to carry a second kind.
_mi_state_kind_ok() {
  case "$1" in alias) return 0 ;; esac
  mi_warn "state: '$1' is not a check kind this core defines (the only kind is 'alias')"
  return 1
}

# ONE VOCABULARY, BOTH DIRECTIONS. It gates what mi_state_commit will write AND what
# mi_state_desired_get will read back: a `state=paused` arriving in a restored ledger is a value the
# reconciler's table has no row for, and without this it reached that table and fell through every
# arm — printing nothing, returning success, and reading to a caller as "there is no work to do".
# The wording is neutral about direction; each caller's own message says whether it was writing or
# reading.
_mi_state_desired_ok() {
  case "$1" in running|stopped) return 0 ;; esac
  mi_warn "state: desired state must be running or stopped, not '$1'"
  return 1
}

# THE SECOND VOCABULARY ON THE SAME ROW, gated in both directions for the same reason the first one
# is: a `verify=later` arriving in a restored ledger must not reach a caller as a value this core has
# a meaning for. There are two, and neither is an absence — that is the entire point of the field.
_mi_state_verify_ok() {
  case "$1" in owed|none) return 0 ;; esac
  mi_warn "state: a desired-state record says verify='$1' — it must be 'owed' or 'none'"
  return 1
}

# WHAT DOES THIS INTENT OWE, AND MAY IT OWE NOTHING? The whole of the rule above, as one predicate,
# asked once per commit — so no caller can answer half of it and no second place can answer it
# differently.
#
#   <want>      the desired state being recorded.
#   <declared>  yes iff the caller passed `+none`.
#   <owed>      yes iff this write LEAVES at least one outstanding entry for the container.
#
# rc 0 prints the value to record on the row · 1 refused, reported.
_mi_state_verify_of() {
  local want="$1" declared="$2" owed="$3"
  if [ "$owed" = yes ]; then
    # A DECLARATION IS NOT A RETIREMENT. The clear is the only path an entry disappears down, so a
    # commit that says "nothing needs verifying" while an entry stands is a caller contradicting the
    # ledger rather than a caller clearing it — and recording `none` over it would retire an owed
    # check in the one place this module promises never to.
    if [ "$declared" = yes ]; then
      mi_warn "state: refusing to record that nothing needs verifying while this container still owes"
      mi_warn "  an outstanding check. A commit PRESERVES the set; it verifies nothing. Clear the check"
      mi_warn "  with mi_state_outstanding_clear, naming what was verified. Nothing was written."
      return 1
    fi
    printf 'owed\n'
    return 0
  fi
  if [ "$declared" = yes ]; then printf 'none\n'; return 0; fi
  # A `stopped` intent leaves nothing running, so there is no address to resolve and nothing to
  # declare: `none` is structural there rather than a claim. A `running` one has to say it.
  if [ "$want" = running ]; then
    mi_warn "state: refusing to record 'running' for a container that owes no live verification and"
    mi_warn "  does not say so. Every transition that leaves a container running ends in one — 'it"
    mi_warn "  started' is not evidence that its alias resolves — and an empty outstanding set is"
    mi_warn "  exactly what a crash between recording the intent and recording the check leaves"
    mi_warn "  behind, so the two cannot be told apart afterwards. Pass the checks this start owes,"
    mi_warn "  or '+none' to record that it owes none. Nothing was written."
    return 1
  fi
  printf 'none\n'
}

# rc 0 prints running|stopped · 3 nothing recorded · 1 unreadable ledger, or a record that is there and
# cannot be read as one.
#
# NO DEFAULT. A container with no recorded desired state is a container this installer has not been
# told what to do with; defaulting to `running` would start things nobody asked for, and defaulting to
# `stopped` would take a working install down. Callers handle 3 explicitly.
mi_state_desired_get() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_desired_get needs <container>"; return 1; fi
  local rec rc v vfy
  if rec="$(mi_led_find "$MI_STATE_KIND" container "$1")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  # ONE RECORD, ZERO ANSWERS IS NOT ZERO RECORDS. `state=` with nothing after it is a legal field and
  # a record carrying no `state=` at all is legal too, so "the record did not answer" is not "there is
  # no record" — and reporting 3 here would mean "nothing recorded", which invites the next verb to
  # record over the row rather than repair it. Same shape as lib/prov.sh's identity reader.
  if v="$(mi_led_field "$rec" state)"; then :; else
    mi_warn "state: the record of desired state for '$1' does not say which state is wanted. It says"
    mi_warn "  this container was given an intent without saying what it was, so it can be neither"
    mi_warn "  reconciled nor left alone. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  if ! _mi_state_desired_ok "$v"; then
    mi_warn "  — and that value is on DISK, in the ledger, not in this call. The ledger is checksummed,"
    mi_warn "  which proves the bytes were not altered after they were written, not that this"
    mi_warn "  installation wrote them. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  # AND WHETHER A LIVE VERIFICATION IS OWED, by the same rule and in the same direction. A row that
  # does not carry the field says a container should be running and says nothing about what proving
  # that costs — so the empty outstanding set beside it reads as a completed verification. This core
  # can no longer write such a row; a restored, foreign or older ledger holds one, and THIS is where
  # it is caught, because a write-side refusal alone leaves the crash shape readable.
  if vfy="$(mi_led_field "$rec" verify)"; then :; else
    mi_warn "state: the record of desired state for '$1' does not say whether a live verification is"
    mi_warn "  owed. An empty outstanding set beside a silent row is indistinguishable from a crash"
    mi_warn "  between recording the intent and recording the check it owed, so this container can be"
    mi_warn "  neither reconciled nor left alone. It is PRESERVED and reported."
    mi_warn "  Run 'mythical-ctl state repair'."
    return 1
  fi
  if ! _mi_state_verify_ok "$vfy"; then
    mi_warn "  — and that value is on DISK, in the ledger, not in this call. It is PRESERVED and"
    mi_warn "  reported. Run 'mythical-ctl state repair'."
    return 1
  fi
  printf '%s\n' "$v"
}

# The outstanding entries for <container>, one per line as `KIND<TAB>PARAM`.
#
# rc 0 the set is printed (empty means there is nothing outstanding) · 1 the question could not be
# answered, REPORTED — never folded into an empty set. An empty set is what makes a container
# reconciled and what makes the reconciler plan `none`, so a listing that reported "none" for a ledger
# it could not read would declare a fleet settled on the strength of a question nobody answered.
mi_state_outstanding() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_outstanding needs <container>"; return 1; fi
  local c="$1" recs rc line k p out=""
  # The container is a SELECTOR here, judged by the function every editor entry point judges one with:
  # it must equal a serialized field byte for byte to match one, and a selector no field could ever
  # equal answers "nothing is outstanding" for every container name it is given.
  _mi_led_args_ok "$MI_OUT_KIND" container "$c" || return 1
  if recs="$(mi_led_all "$MI_OUT_KIND")"; then rc=0; else rc=$?; fi
  # 3 is "there is no ledger yet", which IS an answer, and the answer is that nothing is outstanding.
  # Anything else is "could not read it", already reported by the reader, and it is propagated.
  if [ "$rc" -eq 3 ]; then return 0; fi
  [ "$rc" -eq 0 ] || return "$rc"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    _mi_led_record_matches "$line" container "$c" || continue
    # AN ENTRY FOR THIS CONTAINER THAT DOES NOT SAY WHAT IT IS refuses the whole listing rather than
    # being skipped. Skipping it removes an owed check from the set, and an empty set means
    # reconciled — so the one record shape that cannot be interpreted would be the one that silently
    # retires the verification it records.
    if k="$(mi_led_field "$line" kind)"; then :; else
      mi_warn "state: an outstanding check recorded for '$c' does not say what KIND of check is owed,"
      mi_warn "  so it can never be performed and never cleared. Leaving it out of the set would make"
      mi_warn "  this container look fully reconciled. It is PRESERVED and reported."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    if [ -z "$k" ]; then
      mi_warn "state: an outstanding check recorded for '$c' carries an EMPTY kind — it says a check is"
      mi_warn "  owed without saying which, which no clear can ever match. It is PRESERVED and reported."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    # AN ENTRY THAT DOES NOT SAY WHAT IT MUST VERIFY is refused for exactly the reason one that does
    # not say what KIND of check it is is refused, and it was the one case left open: `|| p=""` turned
    # a restored `container=C kind=alias` row with no parameter into an ordinary-looking entry. An
    # `alias` entry carries the network the alias must resolve on, so one carrying nothing schedules a
    # `verify` that names nothing to verify — and since the clear names the parameter, nothing could
    # ever match it either. Fail closed, as the missing-kind case does.
    if p="$(mi_led_field "$line" param)"; then :; else
      mi_warn "state: an outstanding '${k}' check recorded for '$c' does not say WHAT it must verify."
      mi_warn "  An 'alias' entry carries the network the alias must resolve on; one carrying nothing"
      mi_warn "  schedules a check of nothing, and no clear can ever name it. It is PRESERVED and"
      mi_warn "  reported. Run 'mythical-ctl state repair'."
      return 1
    fi
    if [ -z "$p" ]; then
      mi_warn "state: an outstanding '${k}' check recorded for '$c' carries an EMPTY parameter — it"
      mi_warn "  names nothing to verify and no clear can match it, so it would keep this container"
      mi_warn "  unreconciled forever. It is PRESERVED and reported."
      mi_warn "  Run 'mythical-ctl state repair'."
      return 1
    fi
    # Buffered rather than printed as the loop goes: a partial listing followed by a failure status is
    # the shape a caller reads as success with data. Same reason mi_led_all buffers.
    out="${out}${k}"$'\t'"${p}"$'\n'
  done <<< "$recs"
  printf '%s' "$out"
}

# ONE WALK OF THE LEDGER BODY: drop this container's state rows, preserve every other row byte for
# byte, and hand back what remains (no trailing newline, as `$( )` would strip one anyway).
#
#   <drop-desired>  the fields of the ONE `desired` row _mi_led_select resolved to, or empty for none.
#   <mode>          WHICH OUTSTANDING ROWS MAY DISAPPEAR — the whole of this module's own rule, asked
#                   in this one place so no caller can answer it a second way:
#                     +keep   none of them (mi_state_commit)
#                     +match  the ones naming <kind> AND <param> (mi_state_outstanding_clear)
#                     +all    the container's whole set (mi_state_forget)
#                   All three start with `+`, which _mi_led_field_ok's name grammar excludes, so no
#                   mode can ever be confused with a real check kind. An unknown mode drops nothing:
#                   the safe direction is to keep an owed check, never to retire one.
#
# The mode is not read here. The question "may this row disappear" is _mi_state_out_drop's, in one
# piece, so that every part of the answer is load-bearing and a mode is a value rather than a branch
# the next author extends in place.
#
# It performs _mi_led_without's single-row drop inline rather than calling it, because this edit
# touches TWO record sets in one write and the body must be walked ONCE: a second pass reports the
# same blank rows a second time and rewrites what the first pass just rewrote. Every JUDGEMENT is
# still delegated to the function that owns it, and that is not decoration:
#
#   _mi_led_row_of decides what is a record of a kind. A bare `outstanding` row with no TAB and no
#   fields IS one — the `case "$kind"$'\t'*` pattern this function used to carry made it a record of
#   no kind at all, so it was neither matched nor dropped nor reported, and the next ordinary edit
#   lost it.
#   _mi_led_record_matches decides whether a record answers, and it gates the record first, so a row
#   this module cannot read matches nothing and stays exactly where it is.
#
# A BLANK ROW IS PRESERVED AND REPORTED, not skipped. `[ -n "$line" ] || continue` in a rewriting loop
# reads as harmless and is not: the row is silently absent from the output, so a foreign or restored
# ledger quietly loses a row at the first operation that touches this container.
# MAY THIS OUTSTANDING ROW DISAPPEAR? The whole of this module's rule, as one predicate, asked in one
# place — so no caller can answer half of it, and every line of it is load-bearing.
#
#   * An unrecognised mode KEEPS, and so does +keep. The safe direction is to keep an owed check;
#     retiring one is the thing that needs a reason. A mode added later without an arm here therefore
#     preserves rather than deletes.
#   * The CONTAINER must match, in every mode. Without it a forget or a clear would retire checks owed
#     by every other container the ledger records.
#   * +match needs the KIND AND THE PARAMETER. The kind alone is what let a verified alias on one
#     network retire the check owed on another. Both halves are compared by _mi_led_record_matches,
#     which gates the record first, so a row this module cannot read matches nothing and stays.
#
# It matches EVERY row that answers, not one, and that is the contract here rather than the defect it
# would be elsewhere in these modules: rows naming the same (kind, param) name the SAME verification,
# and that verification happened. The cardinality question belongs to keyed records; this set is
# legitimately several rows per container.
#
# rc 0 drop it · 1 keep it.
_mi_state_out_drop() {
  local rec="$1" c="$2" mode="$3" kind="$4" param="$5"
  case "$mode" in
    '+all'|'+match') : ;;
    *) return 1 ;;
  esac
  _mi_led_record_matches "$rec" container "$c" || return 1
  if [ "$mode" = '+all' ]; then return 0; fi
  _mi_led_record_matches "$rec" kind "$kind" || return 1
  _mi_led_record_matches "$rec" param "$param"
}

_mi_state_filter() {
  local records="$1" c="$2" want="$3" mode="$4" kind="${5:-}" param="${6:-}" line rec out="" blank=0
  # AN EMPTY BODY IS NOT A BLANK ROW. The here-string below supplies a newline of its own, so `""`
  # would arrive as one empty line and be reported as a blank row on the first write of every install.
  [ -n "$records" ] || return 0
  if [ -n "$want" ]; then want="${MI_STATE_KIND}"$'\t'"${want}"; fi
  while IFS= read -r line; do
    # The one desired row the selector resolved to, matched as a WHOLE LINE, byte for byte — so the
    # row removed is the row that was judged. `want` is cleared on the first hit, so a ledger holding
    # those bytes twice cannot lose both rows here.
    if [ -n "$want" ] && [ "$line" = "$want" ]; then want=""; continue; fi
    if _mi_led_row_of "$line" "$MI_OUT_KIND"; then
      rec="$MI_LED_ROW"          # copied out before anything else runs; the global is valid until the next call
      if _mi_state_out_drop "$rec" "$c" "$mode" "$kind" "$param"; then continue; fi
    fi
    # THE ATTEMPT RECORD IS STALE THE MOMENT ANY OF THESE WRITES HAPPENS, in EVERY mode — which is
    # why it is dropped here rather than by each caller. A commit re-states the intent and so grants
    # a fresh attempt; a forget drops the container from the records entirely; and a clear reports a
    # live verification, which is evidence the container came up, so the run this row describes is
    # over. "The attempt is stale" has one meaning, so it is asked once and not gated on the mode.
    if _mi_led_row_of "$line" "$MI_RESUME_KIND"; then
      rec="$MI_LED_ROW"
      if _mi_led_record_matches "$rec" container "$c"; then continue; fi
    fi
    if [ -z "$line" ]; then blank=$((blank + 1)); fi   # a loop counter, not a value out of a file
    out="${out}${line}"$'\n'
  done <<< "$records"
  if [ "$blank" -gt 0 ]; then
    mi_warn "state: the installer state ledger holds ${blank} blank row(s) — a row that is not a record"
    mi_warn "  of any kind. It grants nothing and answers nothing, and it is kept exactly where it is"
    mi_warn "  rather than dropped by this write. Run 'mythical-ctl state repair'."
  fi
  printf '%s' "$out"
}

# The read-modify-write mi_state_commit and mi_state_forget share: resolve this container's ONE
# `desired` row, then hand back the body with that row removed and its outstanding set treated
# according to <mode>. rc 0 the remainder is printed · 1 refused, reported.
#
# The mode is the CALLER's to state and is passed straight through: commit and forget differ in
# exactly that one answer, and a shared helper that chose for them would be the second place the
# question is settled.
_mi_state_take() {
  local records="$1" c="$2" mode="$3" old="" rc
  if old="$(_mi_led_select "$records" "$MI_STATE_KIND" container "$c")"; then :; else
    rc=$?; [ "$rc" -eq 3 ] || return 1; old=""
  fi
  _mi_state_filter "$records" "$c" "$old" "$mode"
}

# Does <records> hold an outstanding row for <container> that <mode>/<kind>/<param> selects? TWO
# questions are asked through this one walk, and both are asked with the SAME predicate the rewrite
# uses to decide what may disappear — "is this row the check I am about to write?" and "may this row
# disappear when that check is verified" are the same comparison, and two implementations of one
# match drift the moment either is touched.
#
#   '+match' <kind> <param>  IS THIS CHECK ALREADY OWED? An obligation already recorded is the same
#                            obligation: writing it twice puts two rows in the ledger naming ONE
#                            verification, which is not two things to check — it is one thing written
#                            down twice, and it makes the listing report a member the set does not
#                            have.
#   '+all'                   DOES THIS CONTAINER OWE ANYTHING AT ALL after this write? That is what
#                            decides whether a `running` intent is allowed to record that it owes
#                            nothing, and it is the container half of the same predicate.
#
# rc 0 yes · 1 no, or the rows could not be read as records. In that case nothing here matches, and
# both callers take the safe direction from it: the dedupe adds its entry rather than assuming it is
# covered, and a `running` commit that cannot see a surviving entry must still say what it owes.
_mi_state_out_scan() {
  local records="$1" c="$2" mode="$3" kind="${4:-}" param="${5:-}" line rec
  [ -n "$records" ] || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    _mi_led_row_of "$line" "$MI_OUT_KIND" || continue
    rec="$MI_LED_ROW"
    if _mi_state_out_drop "$rec" "$c" "$mode" "$kind" "$param"; then return 0; fi
  done <<< "$records"
  return 1
}

# D50's ordering, made unavoidable: desired state AND the outstanding set commit in ONE atomic ledger
# write. Splitting them leaves a window where desired is `running` and the set is empty — and a crash
# there produces a container that recovery starts and then considers fully reconciled, SKIPPING LIVE
# VERIFICATION ENTIRELY. The ledger is one atomic document (§6b) precisely so related fields need not
# be written separately; two updates to it in sequence is the same defect the consolidation removed.
#
# Usage: mi_state_commit <container> <running|stopped> [<kind> <param>]...
#        mi_state_commit <container> <running|stopped> +none
mi_state_commit() {
  if [ "$#" -lt 2 ]; then mi_warn "state: mi_state_commit needs <container> <desired> [<kind> <param>]... | +none"; return 1; fi
  local c="$1" want="$2"; shift 2
  _mi_state_desired_ok "$want" || return 1
  mi_lock_assert_held "record desired state"

  # Validate every pair BEFORE building the record: a rejected kind or field halfway through would
  # otherwise commit a partial set. `pairs` is the array name deliberately — the release bundler
  # flattens every module into one file, after which shellcheck's array tracking is not per-function,
  # so an array-typed local must not reuse a name another module uses for a scalar.
  local -a pairs
  pairs=()
  local declared=no
  while [ "$#" -gt 0 ]; do
    # THE DECLARATION, WHICH IS NOT A CHECK KIND. It carries the `+` prefix the filter's modes carry,
    # for their reason: _mi_led_field_ok's name grammar excludes `+`, so no declaration can ever
    # collide with a kind a later version defines. It must stand ALONE — given beside a pair it would
    # be one call saying both "this owes that check" and "this owes nothing".
    if [ "$1" = '+none' ]; then
      if [ "$#" -ne 1 ] || [ "${#pairs[@]}" -ne 0 ]; then
        mi_warn "state: '+none' records that this intent owes NO live verification, so it cannot be"
        mi_warn "  given beside a check that IS owed. Nothing was written."
        return 1
      fi
      declared=yes
      shift
      continue
    fi
    _mi_state_kind_ok "$1" || return 1
    # AN ENTRY WITH NO PARAMETER IS THE BOOLEAN D52 REPLACED. `alias` carries the network its alias
    # must resolve on, and the clear matches on it — so an entry with nothing to match keeps its
    # container unreconciled forever, with nothing that could ever retire it. A trailing kind with no
    # argument at all lands here too: it is the same missing parameter, one position earlier.
    if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
      mi_warn "state: the outstanding '${1}' check carries no parameter. D52 made this set TYPED"
      mi_warn "  because a flag records no kind and no parameters: an 'alias' entry carries the network"
      mi_warn "  the alias must resolve on, and one carrying nothing can never be matched and so can"
      mi_warn "  never be cleared. Nothing was written."
      return 1
    fi
    if ! _mi_led_fields_ok "container=${c}" "kind=${1}" "param=${2}"; then
      mi_warn "state: refusing to record the outstanding '${1}' check for '${c}'. Nothing was written."
      return 1
    fi
    pairs+=("$1" "$2")
    shift 2
  done

  local records rest rc acc="" i k p owed vfy
  if records="$(mi_ledger_read)"; then :; else
    # rc 3 is "no ledger yet", a legitimate first write. Anything else is corruption, already reported
    # by the reader — never overwrite a ledger we could not read.
    rc=$?; [ "$rc" -eq 3 ] || return "$rc"; records=""
  fi
  # +keep: THE OUTSTANDING SET IS PRESERVED. This write records an intent; it verifies nothing, so it
  # may not retire a check. The entries below are ADDED to what survives.
  rest="$(_mi_state_take "$records" "$c" '+keep')" || return 1
  [ -z "$rest" ] || acc="${rest}"$'\n'
  i=0
  # `i` is a loop counter this function set to 0 and advances by 2 — never a value parsed out of a
  # file. That distinction is the whole of lib/prov.sh's _mi_prov_gen_ok note: bash EVALUATES a
  # command substitution inside an arithmetic array subscript, so a subscript derived from ledger
  # content would be an execution surface. No value read from the ledger reaches arithmetic here.
  while [ "$i" -lt "${#pairs[@]}" ]; do
    k="${pairs[$i]}"; p="${pairs[$((i + 1))]}"
    i=$((i + 2))
    # Already owed? Then it is already recorded. Asked of `$acc`, which is what this write will
    # actually contain — the rows it kept AND the ones this loop has already appended — so a check
    # carried over from an earlier commit and a pair repeated within ONE call are the same question,
    # answered once.
    if _mi_state_out_scan "$acc" "$c" '+match' "$k" "$p"; then continue; fi
    acc="${acc}${MI_OUT_KIND}"$'\t'"container=${c}"$'\t'"kind=${k}"$'\t'"param=${p}"$'\n'
  done

  # WHAT THIS WRITE LEAVES BEHIND is the question the rule turns on, so it is asked of `$acc` — the
  # rows kept plus the ones just added — and never of the argument list. That is what makes an
  # intent-preserving rewrite of a container which already owes a check need no declaration, and a
  # bare `running` commit on one that owes nothing need one.
  if _mi_state_out_scan "$acc" "$c" '+all'; then owed=yes; else owed=no; fi
  vfy="$(_mi_state_verify_of "$want" "$declared" "$owed")" || return 1

  # THE FIELD RULE, ON A WRITER THAT SERIALIZES ITS OWN RECORD. mi_led_put is not on this path — this
  # function writes two kinds in one ledger write and mi_led_put writes one record — so `container`
  # and `param` would otherwise reach the serializer unchecked, and a TAB in either forges a field
  # boundary while a newline forges a whole record. It is the WRITER's own list rule, applied to the
  # EXACT list about to be serialized, which is why it is asked here and not on the way in: the third
  # field does not exist until the question above has been answered. The pairs were judged as they
  # were validated, against this same rule, before any of this ran.
  if ! _mi_led_fields_ok "container=${c}" "state=${want}" "verify=${vfy}"; then
    mi_warn "state: refusing to record desired state for '${c}'. Nothing was written."
    return 1
  fi

  printf '%s%s\n' "$acc" "${MI_STATE_KIND}"$'\t'"container=${c}"$'\t'"state=${want}"$'\t'"verify=${vfy}" | mi_ledger_write
}

# Record that this installer has RESUMED <container> — started it while performing a `start verify`
# plan. The verb calls this BEFORE it starts the container, not after: a crash between the start and
# the record would leave a container nobody knows was tried, and a start that does not survive is
# still an attempt. It is what makes the SECOND plan differ from the first.
#
# It is one keyed record, so it goes through mi_led_put — the editor that already applies the field
# rule, ties the replacement to its selector, and asks the cardinality question in the one place that
# asks it. Recording the same attempt twice is therefore one row, and a ledger holding two rows for
# one container is refused rather than quietly collapsed. There is nothing this function needs that
# would justify a second serializer beside it.
mi_state_resume_record() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_resume_record needs <container>"; return 1; fi
  mi_lock_assert_held "record a resume attempt"
  mi_led_put "$MI_RESUME_KIND" container "$1" "container=$1"
}

# There is no mi_state_desired_set, deliberately — see the rule at the top of this file. The verbs
# that preserve intent rather than express it (a `recreate` of a stopped product must stay stopped,
# §6b.3's verb table) read the recorded state with mi_state_desired_get and write it back through
# mi_state_commit, which preserves the outstanding set. That is the same operation, taken through the
# one writer that cannot leave desired state and the checks it owes in separate ledger writes.

# Clear ONE outstanding check: the entry naming <kind> AND <param>. THIS IS THE ONLY PLACE AN
# OUTSTANDING ENTRY DISAPPEARS, and it names the exact thing that was verified.
#
# The parameter is not decoration. mi_state_commit accepts several entries of one kind with different
# parameters — an `alias` check per network — so a clear keyed on the kind alone said "some alias was
# verified" and retired every alias check the container owed, including ones nothing had looked at.
# A `start` likewise clears only the kinds it actually performed: one kind of check must not be
# retired by another that happened to succeed (D52). Anything left outstanding keeps the container
# NOT RECONCILED.
#
# Clearing a check that is not recorded is a no-op success, exactly as mi_led_del is: the caller
# verified something and the ledger already owes nothing for it.
mi_state_outstanding_clear() {
  if [ "$#" -ne 3 ]; then mi_warn "state: mi_state_outstanding_clear needs <container> <kind> <param>"; return 1; fi
  local c="$1" kind="$2" param="$3" records rest rc
  _mi_state_kind_ok "$kind" || return 1
  # AN EMPTY PARAMETER IS THE BY-KIND CLEAR THIS REPLACED, one argument later. It names no check, and
  # a match on it would either retire everything of the kind or nothing at all depending on how the
  # matcher happened to treat the empty string — neither of which is "this is what I verified".
  if [ -z "$param" ]; then
    mi_warn "state: refusing to clear the outstanding '${kind}' check for '${c}' without saying WHICH"
    mi_warn "  one was verified. This set holds several entries of one kind with different parameters"
    mi_warn "  — an 'alias' check per network — so a clear that names only the kind retires checks"
    mi_warn "  nobody performed. Nothing was written."
    return 1
  fi
  # THE WRITER'S OWN LIST RULE, ON THE SELECTOR. The entry was serialized from exactly these three
  # fields, so judging them with the same function is what makes a clear able to name only something a
  # commit could have recorded — and a selector no field could ever equal matches nothing and clears
  # nothing, silently. It subsumes the container check the other selector paths make with
  # _mi_led_args_ok; a second copy of it here would be a guard whose removal changes nothing.
  if ! _mi_led_fields_ok "container=${c}" "kind=${kind}" "param=${param}"; then
    mi_warn "state: refusing to clear the outstanding '${kind}' check for '${c}'. Nothing was written."
    return 1
  fi
  mi_lock_assert_held "clear an outstanding check"
  if records="$(mi_ledger_read)"; then :; else
    rc=$?
    # No ledger at all: there is nothing recorded to clear, and this has achieved its purpose — the
    # same answer mi_led_del gives. It does NOT create one: writing an empty ledger as a side effect
    # of clearing nothing is a state change nobody asked for.
    [ "$rc" -eq 3 ] && return 0
    return "$rc"
  fi
  rest="$(_mi_state_filter "$records" "$c" "" '+match' "$kind" "$param")" || return 1
  printf '%s' "$rest" | mi_ledger_write
}

# Drop every state record for a container. Only a family uninstall and `state repair` use this — a
# product uninstall keeps trust state (§6c), and desired state for a container that no longer exists is
# harmless where losing it is not.
#
# ONE ledger write, through the same read-modify-write mi_state_commit uses. Two calls to mi_led_del
# would be two writes, with a window between them in which the container has an outstanding set and no
# desired state — and mi_led_del removes the ONE row a selector resolves to, so on a container with
# two outstanding kinds it would refuse the second call outright and leave the set half-forgotten
# behind a deleted desired row.
#
# `+all` — the ONE caller permitted to make an unverified check disappear, and it is not claiming
# verification: it is dropping the container from this installation's records entirely, after which
# there is nothing left to be outstanding for. Every other path preserves.
mi_state_forget() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_forget needs <container>"; return 1; fi
  local c="$1" records rest rc
  _mi_led_args_ok "$MI_STATE_KIND" container "$c" || return 1
  mi_lock_assert_held "forget a container's recorded state"
  if records="$(mi_ledger_read)"; then :; else
    rc=$?
    [ "$rc" -eq 3 ] && return 0
    return "$rc"
  fi
  rest="$(_mi_state_take "$records" "$c" '+all')" || return 1
  printf '%s' "$rest" | mi_ledger_write
}

# What the RUNTIME says: running | stopped | absent. Never the ledger — the whole point of a separate
# desired field is that the two can disagree.
#
# rc 0 one of the three words · 1 the runtime could not be asked, or answered something this adapter
# does not understand.
mi_state_observed() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_observed needs <container>"; return 1; fi
  local v rc
  if v="$(mi_rt_inspect container c.running "$1")"; then rc=0; else rc=$?; fi
  case "$rc" in
    0) : ;;
    3) printf 'absent\n'; return 0 ;;        # the object is genuinely gone — mi_rt_inspect proved the daemon answers
    *) return 1 ;;                           # could not ask; already reported by the adapter
  esac
  # `{{.State.Running}}` renders `true` or `false` and nothing else. ANYTHING ELSE IS NOT `stopped`:
  # treating an unrecognised answer as "not running" is the same fail-open as treating a down daemon
  # as an absent object, one layer up — desired=running plus a manufactured `stopped` plans a start
  # against a container that may well be running.
  case "$v" in
    true)  printf 'running\n' ;;
    false) printf 'stopped\n' ;;
    *) mi_warn "state: the runtime answered '${v}' when asked whether '$1' is running, which is neither"
       mi_warn "  true nor false. Reading that as 'stopped' would plan a start against a container"
       mi_warn "  whose state was never established."
       return 1 ;;
  esac
}

# rc 0 iff the container is FULLY reconciled. D50: an outstanding entry means NOT RECONCILED even when
# actual and desired both say `running`. Without that, the reconciler sees a running container that
# should be running, calls it settled, and the deferred verification is never performed — the entry
# survives forever with nothing scheduled to clear it.
#
# Every failure to ANSWER also reports not-reconciled, which is the safe direction: an unreadable
# ledger or an unreachable runtime leaves the container in the set the reconciler still has work for,
# rather than in the set it has declared settled. Each of the three readers below has already reported
# why on stderr.
mi_state_reconciled() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_reconciled needs <container>"; return 1; fi
  local want obs out
  # rc 3 (nothing recorded) lands here as "not reconciled" too. There is no desired state to have
  # converged to, so nothing can claim it has.
  want="$(mi_state_desired_get "$1")" || return 1
  obs="$(mi_state_observed "$1")" || return 1
  out="$(mi_state_outstanding "$1")" || return 1
  [ -z "$out" ] || return 1
  [ "$want" = "$obs" ]
}

# A recorded STORAGE migration suspends reconciliation for its container. Its record is kind
# `storagemig`, keyed <product>:<role> — NOT an `intent` record keyed by container — so it cannot be
# found with mi_intent_find, and an earlier draft of this module tried exactly that: the lookup never
# matched, the suspension was silently dead, and the reconciler would have restarted a container the
# migration deliberately stopped. The container's product comes from its provenance record.
#
# rc 0 a migration governs this container · 1 none does · 2 THE QUESTION COULD NOT BE ANSWERED,
# reported. The third value is the point of this function's shape: both lookups it makes can fail for
# a reason that is not "there is none" — an unreadable ledger, an ambiguous record set, a listing that
# refuses because one row cannot be read — and the caller must not act on any of them. A `|| return 1`
# over both, which is what this had, made every one of those mean "no migration governs", i.e.
# "proceed", i.e. start or stop a container a migration deliberately stopped.
_mi_state_storagemig_for() {
  local c="$1" rec product recs line rc
  if rec="$(mi_prov_find container "$c")"; then rc=0; else rc=$?; fi
  # No provenance record: nothing says which product this container belongs to, and a storage
  # migration is keyed by product — so there is no migration this container could be under. That is an
  # answer, not a failure. (§6b's "is this mine?" question is deletion authority's, and it is asked at
  # the removal paths, not here.)
  if [ "$rc" -eq 3 ]; then return 1; fi
  [ "$rc" -eq 0 ] || return 2
  if product="$(mi_led_field "$rec" product)"; then :; else
    rc=$?
    [ "$rc" -eq 3 ] && return 1      # the record names no product; nothing can be keyed on one
    return 2
  fi
  # `product=` with an empty value would match a migration record carrying an equally empty one, so a
  # container whose provenance names no product would be suspended by a migration for a different
  # nothing. Empty is "no product", exactly as an absent field is.
  [ -n "$product" ] || return 1
  if recs="$(mi_led_all "$MI_MIG_KIND")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 1; fi
  [ "$rc" -eq 0 ] || return 2
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if _mi_led_record_matches "$line" product "$product"; then return 0; fi
  done <<< "$recs"
  return 1
}

# Has <container> already been resumed under its currently recorded intent?
#
# rc 0 yes · 1 no · 2 THE QUESTION COULD NOT BE ANSWERED, reported — the same three-valued shape
# _mi_state_storagemig_for has, for the same reason: folding "could not read it" into "no attempt
# recorded" is the direction that starts the container AGAIN, which is the loop this record exists to
# stop.
#
# It reads with mi_led_all rather than mi_led_find deliberately, and the choice is the rc-3 question
# again. A selector-based lookup answers 3 — "there is none" — for a set in which a row is ILL-FORMED,
# because an ill-formed record matches nothing; that is right when asking about one object among many
# and wrong here, where the ABSENCE of an answer is itself the licence to act. mi_led_all's contract
# is completeness, so one unreadable row refuses the whole listing. Same choice, same reason, as
# mi_state_outstanding.
_mi_state_resumed() {
  local c="$1" recs rc line
  # The container is a SELECTOR, judged by the function every editor entry point judges one with: a
  # selector no field could ever equal would otherwise answer "never resumed" for every name given.
  _mi_led_args_ok "$MI_RESUME_KIND" container "$c" || return 2
  if recs="$(mi_led_all "$MI_RESUME_KIND")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 1; fi   # no ledger yet: nothing has ever been resumed. An answer.
  [ "$rc" -eq 0 ] || return 2
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if _mi_led_record_matches "$line" container "$c"; then return 0; fi
  done <<< "$recs"
  return 1
}

# The `running`/`stopped` row of the table below, which is the one that can loop, so it is the one
# whose answer is not a constant. Kept as its own function rather than a nested `case` inside the
# table, so the table stays a lookup.
#
# rc 0 the word is printed · 1 refused, reported.
_mi_state_resume_plan() {
  local c="$1" rc
  if _mi_state_resumed "$c"; then rc=0; else rc=$?; fi
  case "$rc" in
    0) printf 'exited\n'; return 0 ;;
    1) printf 'start verify\n'; return 0 ;;
  esac
  mi_warn "state: cannot tell whether '${c}' was already resumed, so this container gets no plan."
  mi_warn "  Reading that as 'not yet' would start it again — and starting a container that does not"
  mi_warn "  stay up, on every pass, for ever, is the loop the attempt record exists to stop."
  return 1
}

# THE reconciler's decision, as one word. Callers act on it; the table lives here so §6b.3's recovery
# rows are a lookup rather than a judgement at each call site.
#
#   suspended  a live intent for this container governs — the reconciler must not "fix" a container a
#              migration deliberately stopped (§5.2), exactly as the exact-set invariant defers to a
#              network-migration intent (§6b.2).
#   rebuild    desired=running and the container is ABSENT. Never a bare `start`: there is nothing to
#              start, and the launch spec is the verb's to supply.
#   stop       desired=stopped, still running — a `stop` that crashed after writing intent.
#   start verify  desired=running, stopped, AND THIS INSTALLER HAS NOT ALREADY TRIED. Every path that
#              leaves a container running walks the live verification, whether or not something was
#              already outstanding. The tempting shape is `start` when the set is empty and `start
#              verify` when it is not — and that is the D42 defect: the outstanding entry was
#              introduced for deferred migration checks and never wired into ordinary bring-up, so a
#              fresh install or a `recreate` reported success having never resolved the container's
#              alias even once. "It started" is not evidence that its alias resolves.
#   exited     desired=running, stopped, and a resume was ALREADY attempted under this intent. The
#              container does not stay up. Reported, not started a second time: neither the desired
#              state nor the outstanding set changes when a container exits immediately, so without
#              the attempt record this row produced `start verify` again, and again, for ever. A
#              re-stated intent (any mi_state_commit) grants a fresh attempt, and so does the clear
#              that reports a live verification — see _mi_state_filter.
#   verify     running, with something outstanding: verified NOW, not at a hypothetical next start. A
#              container already running HAS an address, and D50 makes an outstanding entry mean
#              not-reconciled — leaving it for a future `start` that may never come would let it sit
#              indefinitely on a running product while every pass declares the fleet settled.
#   defer      STOPPED with something outstanding: it has no address, so there is nothing to resolve.
#              Deferred to its next explicit start. Deferring is not skipping — the entry stays.
#   none       reconciled, or a completed `stop`.
#
# rc 0 the word is printed · 1 refused: something this decision rests on could not be read, and it is
# reported rather than resolved into a plan.
mi_state_plan() {
  if [ "$#" -ne 1 ]; then mi_warn "state: mi_state_plan needs <container>"; return 1; fi
  local c="$1" want obs out rc

  # AN INTENT LOOKUP HAS THREE ANSWERS AND ONLY ONE OF THEM IS "NO INTENT". mi_led_find returns 1 for
  # an unreadable ledger AND for a key more than one record answers for; a bare `if mi_intent_find …;
  # then suspended; fi` folded both into "proceed", which is the direction that acts on a container
  # whose half-built state nobody could read. stdout is discarded because only the status is wanted;
  # stderr is NOT, or the reason for a refusal would be swallowed with it.
  if mi_intent_find container "$c" >/dev/null; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then printf 'suspended\n'; return 0; fi
  if [ "$rc" -ne 3 ]; then
    mi_warn "state: cannot tell whether an unconfirmed intent governs '${c}', so this container gets no"
    mi_warn "  plan. A half-built container is not reconcilable, and 'the question failed' is not"
    mi_warn "  'there is no intent'."
    return 1
  fi

  if _mi_state_storagemig_for "$c"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then printf 'suspended\n'; return 0; fi
  if [ "$rc" -ne 1 ]; then
    mi_warn "state: cannot tell whether a storage migration governs '${c}', so this container gets no"
    mi_warn "  plan. Acting here would be acting on a container a migration may have stopped on purpose."
    return 1
  fi

  if want="$(mi_state_desired_get "$c")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then printf 'none\n'; return 0; fi     # nothing recorded: nothing to converge to
  [ "$rc" -eq 0 ] || return 1

  obs="$(mi_state_observed "$c")" || return 1
  out="$(mi_state_outstanding "$c")" || return 1

  case "${want}/${obs}" in
    running/absent)   printf 'rebuild\n' ;;
    running/stopped)  _mi_state_resume_plan "$c" || return 1 ;;
    running/running)  if [ -n "$out" ]; then printf 'verify\n'; else printf 'none\n'; fi ;;
    stopped/running)  printf 'stop\n' ;;
    stopped/stopped)  if [ -n "$out" ]; then printf 'defer\n'; else printf 'none\n'; fi ;;
    stopped/absent)   printf 'none\n' ;;
    # Structurally unreachable today: both vocabularies are closed above this line, by
    # _mi_state_desired_ok on the way out of the ledger and by mi_state_observed's own true/false
    # gate. It is here because a `case` with no default RETURNS SUCCESS HAVING PRINTED NOTHING, and a
    # caller reading a plan of "" as "no work" is the silent form of every failure this table exists
    # to make explicit. Adding a state to either vocabulary should land here loudly.
    *) mi_warn "state: '${c}' is desired '${want}' and observed '${obs}', which is not a row of the"
       mi_warn "  reconciler's table. Refusing rather than printing an empty plan."
       return 1 ;;
  esac
}
