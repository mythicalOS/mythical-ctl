#!/usr/bin/env bash
# D49 — the probe: a real artifact with a real contract.
#
#   Image     a single, minimal, DIGEST-PINNED image, named in the family index and verified through
#             the same chain as everything else (§8.1). Not an unpinned tag, not "whatever busybox is
#             around".
#   Commands  a fixed, closed set — resolve an alias, report the address, test egress. Nothing
#             configurable, nothing manifest-supplied. A probe that takes instructions is an execution
#             primitive.
#   Offline   if the pinned image is not present and cannot be fetched, verification CANNOT BE
#             PERFORMED — so the caller stops rather than proceeding unverified. Proceeding because the
#             checker was unavailable is the failure the verification exists to prevent.
#   Lifecycle created under write-ahead intent and labelled like any other object (§6b), so a crash
#             mid-probe leaves a reconcilable record rather than a stray container. Removed when the
#             phase completes; a leftover from an earlier crash is recognised by its LABEL and cleaned
#             up rather than treated as an unrecorded object.
#
# Why the probe and not the product containers (D48): the core cannot assume a product image ships a
# shell or a resolver — that would contradict D8 — and a STOPPED container has no address to verify
# against at all, since Docker releases it.
#
# ONE RULE RUNS THROUGH EVERY FUNCTION HERE, and it is the one this plan keeps getting wrong: "I COULD
# NOT ASK" IS NEVER "THERE IS NOTHING THERE". mi_rt_inspect splits rc 3 (the object is genuinely gone)
# from rc 1 (the runtime could not answer), and both halves of that split are consumed below — a probe
# container that might still be standing keeps the intent that accounts for it, because dropping the
# record of an object nobody could ask about is how §6b.2's unaccounted class is manufactured.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

# The probe image, from the verified family index and nowhere else.
#
# It is mi_accept_index, not mi_index_load: the two have the same signature and the same success shape,
# and the second one merely PARSES. Reading the probe image out of an index that was never
# authenticated would let anyone with local write access to the cached index name the image the
# installer runs on the operator's daemon.
mi_probe_image() {
  if [ "$#" -ne 1 ]; then mi_warn "probe: mi_probe_image needs an <index file>"; return 1; fi
  local idx rc
  if idx="$(mi_accept_index "$1")"; then rc=0; else rc=$?; fi
  # The chain's own codes are propagated rather than flattened: 4 means "no anchor has ever been
  # recorded", which asks the operator to be online once, and 1 means the index was refused.
  [ "$rc" -eq 0 ] || return "$rc"
  mi_doc_value "$idx" probe_image
}

# rc 0 the image is usable · 1 it cannot be obtained (reported).
#
# Present-then-pull, not pull-always: a machine that already has the digest must not need the network,
# and §10a's "probe image unavailable (offline, not cached)" case is exactly the pair of conditions.
mi_probe_available() {
  if [ "$#" -ne 1 ]; then mi_warn "probe: mi_probe_available needs an <index file>"; return 1; fi
  local ref
  ref="$(mi_probe_image "$1")" || return 1
  if mi_rt_image_present "$ref"; then return 0; fi
  # STDERR IS NOT SWALLOWED. mi_rt_image_pull passes the registry's own words through deliberately
  # (§7.3), and §10a requires auth and network failures never to be folded into one message — an
  # operator debugging a broken publication needs "denied" rather than a generic refusal. Only stdout
  # (the progress lines) is discarded.
  if mi_rt_image_pull "$ref" >/dev/null; then return 0; fi
  mi_warn "probe: the pinned probe image cannot be obtained:"
  mi_warn "    $ref"
  mi_warn "  Verification cannot be performed, so the operation STOPS here rather than continuing"
  mi_warn "  unverified. There is deliberately no substitute image."
  return 1
}

# The probe container's name: `mythical-<identity>-probe-<nonce>`.
#
# It is not one of lib/manifest.sh's mi_name_* helpers because none of them takes a nonce, and the
# nonce has to be IN the name: a probe is created per run, so a fixed name would make two runs contend
# for one name and make a leftover indistinguishable from the run that is happening now. The parts are
# validated against the same `ident` type those helpers validate theirs with, so the flat join stays
# unambiguous — and the `<prefix>-<identity>-` shape is what makes §6b.2's classifier read a leaked
# probe as a name this installer would create rather than as a stranger's object.
_mi_probe_name() {
  local ident="$1" nonce="$2"
  if ! _mi_doc_type_ok ident "$ident" || ! _mi_doc_type_ok ident "$nonce"; then
    mi_warn "probe: cannot derive a probe container name from '$ident'/'$nonce'"
    return 1
  fi
  printf '%s-%s-probe-%s\n' "$MI_NAME_PREFIX" "$ident" "$nonce"
}

# IS OUR PROBE CONTAINER STILL STANDING, AND IF SO REMOVE IT — asked in ONE place, for BOTH callers.
#
# rc 0 nothing of ours stands at <name> any more: it was never there, it is gone (`--rm` did its job),
# or it was ours and has now been removed. The caller may drop the intent.
# rc 1 it could not be settled, REPORTED. The caller must PRESERVE the intent.
#
# The two callers are the same decision reached from two directions — the run that has just finished,
# and a leftover from a run that never did — so it is one function rather than two copies. A copy at
# the second site is a guard that can be deleted with nothing observable changing, which is the shape
# lib/prov.sh and lib/intent.sh have each already shipped a fix for.
#
# THE LABELS ARE READ THROUGH lib/intent.sh's READER, not through a second one: it is the one place
# Docker's `<no value>` spelling is normalised and the one place "the object is gone" is split from
# "the question could not be answered". Two normalisations of that answer already disagreed once.
_mi_probe_reap() {
  local name="$1" nonce="$2" ident="$3" owner actual rc
  if owner="$(_mi_intent_label container "$name" install)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 0; fi        # genuinely gone — the ordinary path
  [ "$rc" -eq 0 ] || return 1                  # could not ask; _mi_intent_label has reported it
  # A NONCE SAYS WHICH OBJECT, NEVER WHOSE (§6a). The installation label is the only evidence that an
  # object is ours, and an UNLABELLED container is not weaker evidence, it is none: nothing about it
  # says this installation created it, and nothing says it is not someone else's.
  if [ -z "$owner" ] || [ "$owner" != "$ident" ]; then
    mi_warn "probe: a container stands at '$name', which is the name this installation's probe intent"
    mi_warn "  records, but it is labelled for installation '${owner:-<none>}' rather than '$ident'."
    mi_warn "  A name can be reassigned, so the name alone proves nothing. It is NOT removed, and the"
    mi_warn "  intent is PRESERVED rather than dropped for an object that was never accounted for."
    return 1
  fi
  if actual="$(_mi_intent_label container "$name" nonce)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then return 0; fi
  [ "$rc" -eq 0 ] || return 1
  if [ -z "$nonce" ] || [ "$actual" != "$nonce" ]; then
    mi_warn "probe: the container at '$name' carries nonce '${actual:-<none>}', which is not the"
    mi_warn "  '${nonce:-<none>}' this intent recorded. It is a different object standing at the same"
    mi_warn "  name. It is NOT removed and the intent is PRESERVED."
    return 1
  fi
  if mi_rt_container_rm "$name" >/dev/null 2>&1; then
    mi_warn "probe: removed a leftover probe container from an interrupted run ($name)."
    return 0
  fi
  mi_warn "probe: the leftover probe container '$name' is this installation's and could not be removed."
  mi_warn "  Its intent is PRESERVED, so the object stays accounted for until it can be."
  return 1
}

# Run one closed command, under write-ahead intent, and account for the container afterwards. Prints
# the helper's `key=value` lines on stdout.
#
# rc 0 the helper answered AND its container is accounted for — the only status that means the run is
#      finished · 4 the container could not be accounted for (REPORTED); whatever the check itself
#      said, this run left an object nobody can speak for · otherwise the helper's own status.
#
# 4 IS SEPARATE ON PURPOSE. Folding it into the check's own failure would make every caller report a
# verification verdict it never obtained — "DNS is broken" for a daemon that stopped answering after
# the probe had already resolved its alias.
_mi_probe_run() {
  if [ "$#" -lt 4 ]; then
    mi_warn "probe: _mi_probe_run needs an <index file>, a <network id>, a <network alias|-> and a <command>"
    return 1
  fi
  # <network alias> is the name to REGISTER this container under on the network, or `-` for none. It
  # is deliberately not derived from the nonce below: the caller has to know the name in order to
  # check the answer against it, and a run that minted it privately could only hand it back through
  # the same stdout the helper's answer uses.
  local idx="$1" netid="$2" netalias="$3" cmd="$4"; shift 4
  local ref ident nonce name out rc
  ref="$(mi_probe_image "$idx")" || return 1
  ident="$(mi_ident_get)" || return 1
  nonce="$(mi_nonce_new)" || return 1
  name="$(_mi_probe_name "$ident" "$nonce")" || return 1

  # Write-ahead: the intent exists before the container does, so a crash mid-probe is reconcilable.
  mi_intent_open probe "$name" "$nonce" || return 1

  # ARRAY-TYPED LOCAL. tools/bundle.sh flattens every module into one file, after which shellcheck's
  # array tracking is no longer per-function, so a later module using this name for an ordinary scalar
  # draws SC2178 plus an SC2128 per use with only `shellcheck dist/mythical-ctl` red. The names already
  # spoken for this way are `args`, `pk`, `pv`, `placed` (lib/config.sh), `fields` (lib/ledger.sh),
  # `triples` (lib/trust.sh), `rtargv`/`rtpost` (lib/runtime.sh) and `hspecs` here.
  local -a hspecs
  # `install=`/`name=` make the container an object §6a can speak about; extra arguments go through as
  # `arg=` so they land AFTER the command word, where the helper's own entrypoint reads them — not
  # among the docker flags.
  hspecs=("install=${ident}" "name=${name}")
  if [ "$netalias" != "-" ]; then hspecs+=("netalias=${netalias}"); fi
  local x
  for x in "$@"; do hspecs+=("arg=${x}"); done
  # No `2>/dev/null`: a helper that could not be launched at all and a check that ran and failed are
  # different facts, and the runtime's own words are what tell them apart (§7.3).
  if out="$(mi_rt_run_helper "$ref" "$netid" - "$nonce" "$cmd" "${hspecs[@]}")"; then rc=0; else rc=$?; fi
  # The helper's contract is 0 (the check ran and passed) · 1 (it ran and FAILED) · 2 (the command
  # word is not implemented). ANYTHING ELSE IS OUT OF CONTRACT and is normalised to a failed check —
  # loudly, because an unnormalised one would COLLIDE with this function's own 4 below, and the caller
  # would then suppress its verdict as "already reported by the accounting path" while the accounting
  # path said nothing: a silent non-zero, from the module whose subject is never confusing two facts.
  # (Measured — a mutation that removed only the normalisation survived a test asserting absences.)
  case "$rc" in
    0|1|2) : ;;
    *) mi_warn "probe: the probe exited $rc, which is not a status the helper contract defines"
       mi_warn "  (0 the check passed · 1 the check FAILED · 2 the command is not implemented). It is"
       mi_warn "  treated as a FAILED CHECK — never as this installer's own accounting failure."
       rc=1 ;;
  esac

  # `--rm` removes the container, so the ordinary path has nothing to delete — but "ordinary" is not
  # "always", and the intent is the only thing that accounts for the container if one survived. So the
  # record goes only once the runtime has SAID the object is gone (or it has been removed here). A
  # question that could not be asked leaves both the container and its record exactly where they are.
  local accounted=0
  if _mi_probe_reap "$name" "$nonce" "$ident"; then
    mi_intent_drop probe "$name" || accounted=1
  else
    accounted=1
  fi

  # A FAILED REAP IS NOT A SUCCESSFUL RUN. Preserving the intent while returning the helper's earlier
  # zero told the caller both "there might still be a container" (the record) and "there is nothing
  # outstanding" (rc 0) at once — and the caller acts on the rc. It then proceeds believing a probe
  # container nobody can account for was cleaned up, which is §6b.2's unaccounted class being
  # manufactured by the very function that exists to prevent it. It takes precedence over the check's
  # own status: an outstanding object is what the caller must act on, and the check's verdict has
  # already been reported by whoever asked for it.
  if [ "$accounted" -ne 0 ]; then
    mi_warn "probe: the '$cmd' probe container could not be accounted for, so this run REPORTS FAILURE"
    mi_warn "  whatever the check itself answered. Its intent is preserved; run 'mythical-ctl state repair'."
    return 4
  fi

  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  printf '%s\n' "$out"
  return 0
}

# One field out of the helper's answer. rc 0 the value is printed — an EMPTY value is a real answer —
# · 3 the answer carries no such field at all · 1 the answer states the field MORE THAN ONCE, which is
# not one answer (REPORTED).
#
# THE DUPLICATE RULE IS THE READER'S, NOT EACH CALLER'S. The flat response format has no meaning for a
# repeated key: nothing in it says a second copy replaces, refines or contradicts the first. So an
# answer that says `selfcheck=ok` and then `selfcheck=fail` does not say `ok`, it says two things, and
# it is malformed evidence. Returning the FIRST match let every check in this module be passed by an
# answer that also contained its own refutation, and the same trick worked on `alias=` at the door
# whose whole subject is refusing a reply about a different alias.
#
# It is applied HERE, where the format is read, and not at the four call sites: a rule every caller
# must remember is a rule that gets forgotten once, and the copy that is forgotten is the door nobody
# thought about. lib/prov.sh made an ambiguous LEDGER record inert for exactly this reason; this is
# that same rule for the helper's response format.
_mi_probe_field() {
  local blob="$1" key="$2" line val="" seen=0
  # Every line is read, never stopping at the first hit — a reader that returns early cannot see the
  # second copy, which is precisely the evidence it has to refuse on.
  while IFS= read -r line; do
    case "$line" in "${key}="*) val="${line#*=}"; seen=$((seen + 1)) ;; esac
  done <<< "$blob"
  if [ "$seen" -eq 0 ]; then return 3; fi
  if [ "$seen" -gt 1 ]; then
    mi_warn "probe: the probe's answer states '${key}=' more than once (${seen} times), and the answer"
    mi_warn "  format gives a repeated field no meaning — an answer that says a thing twice says two"
    mi_warn "  things. It is REFUSED as ambiguous rather than read down to whichever copy came first."
    return 1
  fi
  printf '%s\n' "$val"
  return 0
}

# AN EXIT STATUS IS NOT A RESULT. rc 0 only when the answer STATES `<key>=ok`; 1 otherwise, REPORTED.
#
# The helper interface declares what each check says (`selfcheck=ok`, `egress=ok`), so that — not the
# exit status beside it — is the check's result. A pinned image that regressed to exiting 0 while
# printing nothing, or while printing `<key>=fail`, would otherwise be accepted as proof by the two
# functions whose entire purpose is to decide whether a network was verified. FAIL CLOSED: the absence
# of the expected result is never the presence of a pass.
#
# It is one function because the two doors are the same decision. Both checks are "did the helper
# state this result", and a second copy at the second site is a guard that can be deleted with nothing
# observable changing — the shape this plan has already shipped fixes for elsewhere.
_mi_probe_asserted() {
  local blob="$1" key="$2" val rc
  if val="$(_mi_probe_field "$blob" "$key")"; then rc=0; else rc=$?; fi
  # rc 1 is the reader's own refusal — the field is stated more than once — and it has already said
  # so. Restating it below as "no such field at all" would report the wrong fact about the answer.
  if [ "$rc" -eq 1 ]; then return 1; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "probe: the probe exited 0 but its answer carries no '${key}=' field at all, so nothing in"
    mi_warn "  it says the check was performed. An exit status is not a result; it is REFUSED rather"
    mi_warn "  than read as a pass."
    return 1
  fi
  if [ "$val" != ok ]; then
    mi_warn "probe: the probe exited 0 but reported '${key}=${val:-<empty>}' rather than '${key}=ok'."
    mi_warn "  The STATED result governs, not the status beside it. It is REFUSED."
    return 1
  fi
  return 0
}

# THE ADDRESS OUT OF AN ANSWER TO ONE QUESTION. rc 0 the address is printed · 3 the probe LOOKED and
# the name did not resolve · 1 the answer is not an answer to this question (REPORTED).
#
# Both doors that read a lookup answer — the selfcheck and the sibling resolve — ask the same three
# things of it, so they ask them once, here. The three are not interchangeable and each is a fact this
# module has already been wrong about:
#
#   the alias ECHO     an answer is only an answer to the question that was asked. A reply about
#                      another name is a malfunctioning probe, and returning its address would hand
#                      D42/D48's rebind the address of a different container entirely.
#   a MISSING address  is not an empty one. An empty value is the documented "did not resolve"; no
#                      field at all means the probe did not answer the question, and folding the
#                      second into the first reports a working probe that found nothing.
#   the address ITSELF a sanity gate on a value crossing a trust boundary. The image is digest-pinned,
#                      so this is not the security boundary — but the value is printed to callers that
#                      compare it, log it and put it in messages, and an address is an address. 45
#                      characters is the longest textual IPv6 form.
_mi_probe_address() {
  local blob="$1" want="$2" answered addr rc
  if answered="$(_mi_probe_field "$blob" alias)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 1 ]; then return 1; fi          # ambiguous; the reader has reported it
  if [ "$rc" -ne 0 ] || [ "$answered" != "$want" ]; then
    mi_warn "probe: the probe answered about alias '${answered:-<none>}' when it was asked about '$want'."
    mi_warn "  An answer to another question is not this alias's address, so nothing is returned."
    return 1
  fi
  if addr="$(_mi_probe_field "$blob" address)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 1 ]; then return 1; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "probe: the probe's answer carries no address at all — it did not answer the question."
    return 1
  fi
  if [ -z "$addr" ]; then return 3; fi
  local LC_ALL=C ok=1        # byte order, not locale collation: the class must mean ASCII
  case "$addr" in *[!0-9a-fA-F:.]*) ok=0 ;; esac
  if [ "${#addr}" -gt 45 ]; then ok=0; fi
  if [ "$ok" -eq 0 ]; then
    mi_warn "probe: the probe reported '$addr', which is not an address. Nothing is returned."
    return 1
  fi
  printf '%s\n' "$addr"
}

# THE NAME THE SELFCHECK ASKS ABOUT — minted here, per run, by the CALLER.
#
# This is what makes the check a check. A probe asked "is DNS working?" can answer yes without doing
# anything; a probe asked "what address does <a name you have never seen> have?" cannot, because the
# name did not exist when the image was built. The caller registers it with the network itself
# (`--network-alias`, see _mi_probe_run) immediately before asking, so:
#
#   * no `/etc/hosts` INSIDE the image can contain it — it is minted after the image is;
#   * no hosts file the DAEMON writes contains it either. Docker writes the container's own HOSTNAME
#     there; a network ALIAS is a name the network's embedded resolver answers for, and nothing else
#     does. It is deliberately NOT the container's name for that reason: whatever a given engine
#     version chooses to put in a hosts file, this name is not it.
#
# So a conforming selfcheck MUST query the resolver, and the answer is bound to a lookup that a
# working resolver is the only thing able to satisfy.
#
# The nonce here is NOT the container's — it is the freshness of the QUESTION, not the identity of an
# object, and §6a's "a nonce says which object" is about objects. Deriving it from the container's
# would mean the run had to hand its nonce back out, and this function exists precisely so the caller
# knows the name it is about to ask about without waiting for the run to tell it.
_mi_probe_alias() {
  local nonce alias
  nonce="$(mi_nonce_new)" || { mi_warn "probe: cannot mint a selfcheck alias"; return 1; }
  alias="probe-selfcheck-${nonce}"
  # The same `ident` type every runtime name in this installer is checked against, so the alias cannot
  # be a shape the daemon (or a later reader of a log line) has to guess the boundaries of.
  if ! _mi_doc_type_ok ident "$alias"; then
    mi_warn "probe: '$alias' is not a usable network alias"
    return 1
  fi
  printf '%s\n' "$alias"
}

# One wording, at both doors that reach it. A verdict this load-bearing spelled twice is a verdict
# that gets edited once.
_mi_probe_dns_verdict() {
  mi_warn "probe: the probe could not resolve its OWN per-run alias '$2' on network '$1'."
  mi_warn "  DNS on this network is not working — this is not about any one product being stopped."
}

# THE DNS-mechanism check. The probe's OWN alias is what separates "DNS on this network is broken" from
# "that product is simply not running" — an earlier revision required "every alias, always" from the
# probe, which no fleet containing a stopped product can satisfy.
#
# `selfcheck=ok` IS NOT THE EVIDENCE, it is the probe's opinion of the evidence. What is accepted is
# the probe RESOLVING the per-run alias the caller registered for it and reporting the address it got;
# the stated result is required as well, so a probe that looked and considers the result wrong is not
# overruled. Both, or the network is not verified.
mi_probe_selfcheck() {
  if [ "$#" -ne 2 ]; then mi_warn "probe: mi_probe_selfcheck needs an <index file> and a <network id>"; return 1; fi
  mi_probe_available "$1" || return 1
  local alias out rc
  alias="$(_mi_probe_alias)" || return 1
  # The alias is passed TWICE on purpose, and the two are different things: the first registers the
  # container under that name with the network, the second asks the probe to look that name up. The
  # check is exactly "resolve the name I have just registered you under".
  if out="$(_mi_probe_run "$1" "$2" "$alias" selfcheck "$alias")"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ]; then
    # rc 4 is "the container could not be accounted for", already reported by _mi_probe_run. The probe
    # may well have resolved its own alias before the runtime stopped answering, so calling DNS broken
    # here would send an operator to debug a network that was never shown to be at fault.
    if [ "$rc" -ne 4 ]; then _mi_probe_dns_verdict "$2" "$alias"; fi
    return 1
  fi
  # rc 3 — the probe looked and the resolver had no answer — IS the broken-DNS finding, and the only
  # thing here that is. Everything else (no echo, no address, a reply about another name) is a broken
  # PROBE, reported by the reader as such: a malfunctioning verifier is not a verification result.
  if _mi_probe_address "$out" "$alias" >/dev/null; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 3 ]; then _mi_probe_dns_verdict "$2" "$alias"; fi
    return 1
  fi
  _mi_probe_asserted "$out" selfcheck || return 1
  return 0
}

# Resolve <alias> on <network id>. rc 0 prints the address · 3 the alias did not resolve · 1 the probe
# itself could not run, or answered something that is not an answer to this question.
#
# The 3-vs-1 split is load-bearing for D48: a running sibling that does not resolve is a verification
# FAILURE (which keeps its outstanding entry and is reported), while a probe that could not run is a
# reason to stop before detaching anything. Everything that is not a clean answer therefore lands on
# 1 — a probe that malfunctioned must never be read as a probe that looked and found nothing.
mi_probe_resolve() {
  if [ "$#" -ne 3 ]; then mi_warn "probe: mi_probe_resolve needs an <index file>, a <network id> and an <alias>"; return 1; fi
  mi_probe_available "$1" || return 1
  local out addr rc
  # EVERY non-zero lands on 1, including _mi_probe_run's 4 (the run's container could not be accounted
  # for): rc 3 is reserved for the probe having LOOKED and found nothing, and a run that did not
  # finish never looked.
  #
  # No `--network-alias` for this one: the question is about a SIBLING's name, and registering a name
  # of our own would add an attachment to the family network for no reason the answer depends on.
  out="$(_mi_probe_run "$1" "$2" - resolve "$3")" || return 1
  # The alias echo, the missing-vs-empty address split and the sanity gate are _mi_probe_address's,
  # shared with the selfcheck door — including the rc 3 this function's contract is built on.
  if addr="$(_mi_probe_address "$out" "$3")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  printf '%s\n' "$addr"
}

mi_probe_egress() {
  if [ "$#" -ne 2 ]; then mi_warn "probe: mi_probe_egress needs an <index file> and a <network id>"; return 1; fi
  mi_probe_available "$1" || return 1
  local out rc
  if out="$(_mi_probe_run "$1" "$2" - egress)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ]; then
    # The same rule as selfcheck's, for the same reason: `egress=ok` is this check's stated result,
    # and an answer about a DIFFERENT check is no more this one's answer than a resolve reply about
    # another alias is that alias's address.
    _mi_probe_asserted "$out" egress || return 1
    return 0
  fi
  if [ "$rc" -ne 4 ]; then mi_warn "probe: egress from network '$2' is not working."; fi
  return 1
}

# Reconcile leftovers. A probe container from an earlier crash is OURS — labelled with this
# installation's identity and a nonce we recorded — so it is removed, not reported as an unrecorded
# object. That distinction matters: §6b.2's unrecorded class STOPS every operation, and a stray probe
# would wedge the installation over a container whose whole purpose was to be temporary.
#
# Only probes are cleaned up this way. Every other class goes through mi_intent_reconcile, because
# every other class holds state.
#
# rc 0 every probe intent was settled · 1 at least one could not be, REPORTED. Nothing that could not
# be settled is dropped, so a later run sees exactly what this one did.
mi_probe_cleanup() {
  local ident records rec name nonce rc failed=0
  if ident="$(mi_ident_get)"; then rc=0; else rc=$?; fi
  # rc 3 is "no identity has ever been recorded" — first use, so nothing of ours can exist and there is
  # nothing to clean up. ANY OTHER failure is a question that could not be answered, and every removal
  # below is scoped by the identity: a ledger that cannot say which installation this is cannot say
  # which objects are ours, so it cannot say that none of them are. `|| return 0` here would be exactly
  # the fold this module exists to refuse.
  if [ "$rc" -eq 3 ]; then return 0; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "probe: the installation identity could not be read, so no probe container can be shown to"
    mi_warn "  be this installation's. Nothing is removed and nothing is forgotten."
    return 1
  fi
  if records="$(mi_intent_all)"; then rc=0; else rc=$?; fi
  # Same split one level along: rc 3 is "there is no ledger yet", which is the same first-use fact.
  if [ "$rc" -eq 3 ]; then return 0; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "probe: the intent records could not be listed, so no leftover probe can be shown to exist"
    mi_warn "  or not to. Nothing is removed and nothing is forgotten."
    return 1
  fi
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    # An ill-formed record matches nothing, including its own class — lib/prov.sh's gate says so, and
    # it is preserved and reported there rather than acted on here.
    _mi_led_record_matches "$rec" class probe || continue
    if name="$(mi_led_field "$rec" name)"; then :; else
      mi_warn "probe: a probe intent carries no name — it says a container was about to be created"
      mi_warn "  without saying which. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
      failed=1; continue
    fi
    if [ -z "$name" ]; then
      mi_warn "probe: a probe intent carries an EMPTY name, which identifies nothing the runtime can be"
      mi_warn "  asked about. It is PRESERVED and reported. Run 'mythical-ctl state repair'."
      failed=1; continue
    fi
    # lib/intent.sh's reader: it refuses a missing AND an empty nonce, and reports both itself.
    if nonce="$(_mi_intent_nonce "$rec" "$name")"; then :; else failed=1; continue; fi
    # Remove by NAME only after confirming the label — the same rule §6a applies everywhere: a name can
    # be reassigned to something the installer never created.
    if _mi_probe_reap "$name" "$nonce" "$ident"; then
      mi_intent_drop probe "$name" || failed=1
    else
      failed=1
    fi
  done <<< "$records"
  return "$failed"
}
