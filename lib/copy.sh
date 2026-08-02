#!/usr/bin/env bash
# §5.1 — the privileged copy, in the pinned container that is the only thing able to read a named
# volume.
#
# WHY A CONTAINER AND NOT A HOST-SIDE WALK (D54). A named volume is daemon-managed: `docker volume
# inspect` reports /var/lib/docker/volumes/<name>/_data, and on Docker Desktop that path does not exist
# on the host at all — it lives inside the VM — while on Linux it is root-owned and explicitly
# unsupported as a host-access path. A host-side filesystem walk over the volume's mountpoint could not
# have read the source on the platform most operators run.
#
# THE HOST CLI HAS NO ACL CODE AT ALL (this plan's Decisions item 6). `setfacl` is not on §7.5's
# dependency floor and does not exist on macOS; the copy container's image is OURS, so the ownership
# mapping, the ACL application and the empirical preflight all happen there. D48 only forbids requiring
# tools in PRODUCT images — the pinned helper is not a product image.
#
# ONE RULE RUNS THROUGH EVERY READER BELOW, and it is the one this plan keeps getting wrong: AN ABSENT
# OBSERVATION IS A REFUSAL, NEVER A PASS. A helper that ran, exited 0 and printed nothing would
# otherwise satisfy every contract check on no evidence at all — the destination declared able to hold
# ownership, permissions, symlinks and inherited ACLs because nobody said it could not. Unmeasured is
# not measured-clean. It is enforced in ONE place (_mi_copy_stated) rather than at each of the eight
# call sites, because a rule every caller must remember is a rule that gets forgotten once, and the
# copy that is forgotten is the door nobody thought about.
#
# ARRAY-TYPED LOCALS DECLARED HERE: `cspecs`. tools/bundle.sh flattens every module into one file,
# after which shellcheck's array tracking is no longer per-function — so a later module using this name
# for an ordinary scalar draws SC2178 plus an SC2128 per use, with the tree clean and only
# `shellcheck dist/mythical-ctl` red. The names already spoken for are `args`, `pk`, `pv`, `placed`
# (lib/config.sh), `fields` (lib/ledger.sh), `triples` (lib/trust.sh), `rtargv`/`rtpost`
# (lib/runtime.sh), `hspecs` (lib/probe.sh), `pairs` (lib/state.sh) and `srcs`, `modes`, `bspecs`,
# `broles`, `ids`, `permitted` (lib/bringup.sh).
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

# The copy image, from the verified family index and nowhere else.
#
# It is mi_accept_index, not mi_index_load: the two have the same signature and the same success shape,
# and the second one merely PARSES. Reading the copy image out of an index that was never authenticated
# would let anyone with local write access to the cached index name the image that is about to be
# handed every byte of a product's data with a writable mount.
mi_copy_image() {
  if [ "$#" -ne 1 ]; then mi_warn "copy: mi_copy_image needs an <index file>"; return 1; fi
  local idx rc
  if idx="$(mi_accept_index "$1")"; then rc=0; else rc=$?; fi
  # The chain's own codes are propagated rather than flattened: 4 means "no anchor has ever been
  # recorded", which asks the operator to be online once, and 1 means the index was refused.
  [ "$rc" -eq 0 ] || return "$rc"
  mi_doc_value "$idx" copy_image
}

# rc 0 the image is usable · 1 it cannot be obtained (reported).
#
# Present-then-pull, not pull-always: a machine that already has the digest must not need the network.
mi_copy_available() {
  if [ "$#" -ne 1 ]; then mi_warn "copy: mi_copy_available needs an <index file>"; return 1; fi
  local ref
  ref="$(mi_copy_image "$1")" || return 1
  if mi_rt_image_present "$ref"; then return 0; fi
  # STDERR IS NOT SWALLOWED, exactly as in lib/probe.sh. mi_rt_image_pull passes the registry's own
  # words through deliberately (§7.3), and §10a requires auth and network failures never to be folded
  # into one message — "denied" and "no such host" send an operator to two different places. Only
  # stdout (the progress lines) is discarded.
  if mi_rt_image_pull "$ref" >/dev/null; then return 0; fi
  mi_warn "copy: the pinned copy image cannot be obtained:"
  mi_warn "    $ref"
  mi_warn "  The migration STOPS. There is deliberately no fallback to an unverified copy path — a copy"
  mi_warn "  performed by something we did not pin is a copy whose confinement nothing guarantees."
  return 1
}

# The same flat key=value reader the probe uses, and deliberately the same one: the response format is
# shared by both pinned helpers, and a second reader of it would be a second (drifting) opinion about
# what a repeated field means. It refuses an answer that states a key twice rather than reading down to
# whichever copy came first.
_mi_copy_field()  { _mi_probe_field "$@"; }

# Every value for a REPEATED key, in order. The repeated keys are the copy's own vocabulary —
# `entry`, `linktarget`, `stripped`, `mapped`, `refused`, `mismatch` — where a second copy of the key
# is a second observation rather than a contradiction, which is why they are read here and not through
# the single-value reader above.
_mi_copy_fields() {
  local blob="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in "${key}="*) printf '%s\n' "${line#*=}" ;; esac
  done <<< "$blob"
}

# Is <key> STATED AT ALL, whatever its value — including an empty one? A problem record (`refused=`,
# `mismatch=`) is a problem by its PRESENCE, so it must be detected by the key, not by iterating its
# values: `_mi_copy_fields` hands back an empty string for `refused=` with no path, and a
# value-iterating loop that does `[ -n "$v" ] || continue` then skips exactly the problem it was meant
# to catch. rc 0 present · 1 absent.
_mi_copy_has_key() {
  local blob="$1" key="$2" line
  while IFS= read -r line; do
    case "$line" in "${key}="*) return 0 ;; esac
  done <<< "$blob"
  return 1
}

# THE VALUE OF ONE STATED OBSERVATION, or a refusal. rc 0 the value is printed (an empty value is a
# real answer and is handed back as one) · 1 it was not stated at all, or was stated twice (REPORTED).
#
# This is the one place "absent is not ok" lives. See the header. <noun> only names the observation in
# the refusal, so an operator is told what was missing rather than which key spells it.
_mi_copy_stated() {
  local blob="$1" key="$2" what="$3" noun="${4:-}" v rc
  [ -n "$noun" ] || noun="the '${key}' observation"
  if v="$(_mi_copy_field "$blob" "$key")"; then rc=0; else rc=$?; fi
  # rc 1 is the shared reader's own refusal — the field is stated more than once — and it has already
  # said so. Restating it as "not stated at all" would report the wrong fact about the answer.
  if [ "$rc" -eq 1 ]; then return 1; fi
  if [ "$rc" -ne 0 ]; then
    mi_warn "copy: the $what helper stated nothing about ${noun}."
    mi_warn "  Refusing: a missing observation is not a passing one — unmeasured is not measured-clean."
    return 1
  fi
  printf '%s\n' "$v"
  return 0
}

# A uid PRINCIPAL is a bare decimal in the kernel's range — uid_t is 32-bit, so 0..4294967295.
# Validated HERE, in the copy module, before EVERY helper call that carries a uid, and in ONE place
# rather than per call site. The runtime adapter validates a `--user` value, but the runtime and
# operator uids reach the helper as `arg=` values it does not type-check, and both are also written
# into /dst ACL entries and named in every message below. A non-numeric or out-of-range principal
# would have the ownership/ACL contract claimed for a uid no step ever ran as.
#
# Leading zeros are stripped before the range test so the digit count means what it says: on bash 3.2
# `[` parses base 10, but a digit string too long for a machine integer makes it print "integer
# expression expected" and return 2 — which an `if` reads as false, so a 20-digit "uid" would slip
# past a bare `-gt`. The length bound refuses it first. (Same shape as lib/runtime.sh's port gate.)
_mi_copy_uid_ok() {
  local uid="$1" what="$2" n
  case "$uid" in ''|*[!0-9]*) mi_warn "copy: $what '$uid' is not a numeric uid"; return 1 ;; esac
  n="$uid"
  while [ "${#n}" -gt 1 ] && [ "${n:0:1}" = 0 ]; do n="${n:1}"; done
  if [ "${#n}" -gt 10 ] || [ "$n" -gt 4294967295 ]; then
    mi_warn "copy: $what '$uid' is out of range — a uid is 0..4294967295"
    return 1
  fi
  return 0
}

# Run one closed command in the pinned copy container.
#
# `--network none`: the copy needs no network, and a privileged container reading every byte of a
# product's data is precisely what should not also be able to reach one. This is the ONE legitimate use
# of `none` in the design — unlike a product container, D42's connect-later problem never arises,
# because this container never joins a network.
#
# Stderr is deliberately NOT folded into the captured stdout: a helper that could not be LAUNCHED and a
# check that ran and failed are different facts, and the runtime's own words are what tell them apart
# (§7.3). They go to the operator; only the answer is parsed.
_mi_copy_helper() {
  local idx="$1" cmd="$2"; shift 2
  local ref nonce
  ref="$(mi_copy_image "$idx")" || return 1
  nonce="$(mi_nonce_new)" || return 1
  mi_rt_run_helper "$ref" none "${MI_COPY_RUNAS:--}" "$nonce" "$cmd" "$@"
}

# The honest three-way statement of whether the dual-principal ACL machinery is MEANINGFULLY ENFORCED
# on this daemon (§4.5 residual 2 / D60). SHARED by preflight — which SETS the default entries — and
# verify — which checks they were APPLIED — so the two halves cannot tell the operator different
# stories about the same daemon. Docker Desktop translates ownership at the file-sharing layer, so the
# gid/ACL path is bypassed there; native Linux enforces it (the silent default); and an endpoint that
# could not be read at all is UNKNOWN — neither claimed nor dismissed, because "I could not ask" is
# never "there is nothing there", and silence there would let the run be read as the native-Linux case
# where the step IS enforced. <subject> names the step so the one message fits both callers.
_mi_copy_acl_context_note() {
  local subject="$1" ep
  if [ -n "${DOCKER_HOST:-}" ]; then ep="$DOCKER_HOST"; else ep="$(mi_rt_context_host 2>/dev/null)" || ep=""; fi
  case "$ep" in
    *"/.docker/run/docker.sock"|npipe://*)
      mi_warn "copy: this is Docker Desktop, where ownership is translated at the file-sharing layer, so"
      mi_warn "  $subject is not meaningfully enforced here. It is exercised and reported, but passing on"
      mi_warn "  Docker Desktop proves NOTHING about the gid/ACL path — that is exercised on native Linux"
      mi_warn "  (§4.5, §10a)." ;;
    '')
      mi_warn "copy: the active daemon endpoint could not be read, so whether $subject is meaningfully"
      mi_warn "  enforced on this daemon is UNKNOWN. It is neither claimed nor dismissed: it is enforced"
      mi_warn "  on native Linux and bypassed by Docker Desktop's file-sharing layer, and nothing here"
      mi_warn "  established which of those this is." ;;
  esac
}

# EMPIRICAL destination preflight, probed rather than inferred from the filesystem's name: create,
# chown, link, stat, set a default ACL, create a child AS EACH UID, read it as the other. A destination
# that cannot represent the contract is REFUSED, naming what failed — a silent best-effort copy is a
# copy that lies.
mi_copy_preflight() {
  if [ "$#" -ne 4 ]; then mi_warn "copy: mi_copy_preflight needs <index> <staging> <runtime-uid> <operator-uid>"; return 1; fi
  local idx="$1" stage="$2" ruid="$3" ouid="$4" out rc k v
  _mi_copy_uid_ok "$ruid" "the product's runtime uid" || return 1
  _mi_copy_uid_ok "$ouid" "the operator uid" || return 1
  mi_copy_available "$idx" || return 1

  # Whether the ACL step below is meaningfully enforced on this daemon — Docker Desktop bypasses it,
  # native Linux enforces it, an unreadable endpoint is UNKNOWN. Shared with verify (see the function).
  _mi_copy_acl_context_note "the ACL step"

  if [ "$ruid" = "$ouid" ]; then
    mi_log "copy: the product's runtime uid equals the operator's ($ruid), so the ACL step is a no-op"
    mi_log "  (same uid) and is skipped."
  fi

  if out="$(_mi_copy_helper "$idx" preflight "arg=/dst" "arg=${ruid}" "arg=${ouid}" \
             "staging=${stage}")"; then rc=0; else rc=$?; fi

  for k in ownership permissions symlink inherit; do
    v="$(_mi_copy_stated "$out" "$k" preflight)" || return 1
    if [ "$v" != ok ]; then
      mi_warn "copy: the destination did not pass the '$k' check of the copy contract (${k}=${v:-<empty>})."
      mi_warn "  Refusing: a destination that cannot represent the copy contract would give you a"
      mi_warn "  best-effort copy that reports success while dropping what it could not carry."
      return 1
    fi
  done

  v="$(_mi_copy_stated "$out" acl preflight)" || return 1
  case "$v" in
    ok) : ;;
    skipped)
      # `skipped` is a no-op ONLY where the two principals are one. Accepting it unconditionally — the
      # obvious `case … in ok|skipped)` — lets a helper skip the single step §4.5's dual-owner problem
      # turns on and still be believed, on exactly the installations where it matters.
      if [ "$ruid" != "$ouid" ]; then
        mi_warn "copy: the preflight reports the ACL step SKIPPED, but the product's runtime uid ($ruid)"
        mi_warn "  is not the operator's ($ouid) — and equal uids are the only condition under which"
        mi_warn "  skipping it is a no-op. Refusing: a load-bearing step reported as skipped is a step"
        mi_warn "  that did not run."
        return 1
      fi ;;
    *)
      mi_warn "copy: the destination cannot hold or inherit ACLs (acl=${v:-<empty>})."
      mi_warn "  Refusing, like one that cannot hold ownership: without default entries naming BOTH the"
      mi_warn "  operator and the runtime uid, the first file the product writes after migration is"
      mi_warn "  unreadable by you — the failure reappears on the first post-migration write."
      return 1 ;;
  esac

  [ "$rc" -eq 0 ] || { mi_warn "copy: the destination preflight failed."; return 1; }
  return 0
}

# THE EMPTY-STAGING GUARANTEE IS ESTABLISHED INSIDE THE COPY CONTAINER, not here. Staging is the only
# writable mount the copy container holds, so its emptiness is a precondition the container checks
# where the mount actually is — on the mount it is about to write, ATOMICALLY with the copy — and
# refuses with `refused=<entry>:staging-nonempty` naming the offending entry. A host-side `ls -A` was
# wrong twice over: it mangles untrusted filenames, and it RACES the mount (an entry created after the
# host looks and before the container mounts staging is invisible to it). See _mi_copy_refusals and the
# helper-image contract (tests/harness/helperimg). The EMPIRICAL preflight writes probe files into this
# same staging and MUST remove them before returning, or the copy that follows will refuse it as
# non-empty: a preflight that leaves droppings has corrupted the tree it was validating.

# The copy itself. Entry types and metadata are a stated contract, not a tool's defaults:
#
#   regular file, directory   copied; mtime preserved; ownership and mode per the policy below
#   symlink                   recreated as a SYMLINK with its target string VERBATIM, never resolved. An
#                             absolute or escaping target is preserved AS TEXT and is harmless: it is
#                             not followed during the copy, and inside the container it resolves under
#                             that container's own root.
#   hardlink                  link structure preserved WITHIN the copy — breaking it silently doubles
#                             disk use and de-couples files a product expects to be the same inode
#   device, socket, FIFO      REFUSED, naming the path — enumerated as `entry=special:<path>`
#
# The enumerated type is a CLOSED vocabulary (file|dir|symlink|hardlink|special) and EVERY `entry=` is
# checked against it. A type outside the set — a copier that enumerated a FIFO or socket as `fifo:`/
# `socket:` rather than `special:`, or a malformed line — is refused, not silently counted toward a
# copy reported complete (see _mi_copy_refusals).
#
# Ownership: uid/gid are MAPPED, not copied, and access is GRANTED, not assumed. Existing files are
# chowned to the operator with an access entry for the runtime uid; and every directory carries DEFAULT
# entries for BOTH principals (u:<operator>:rwX and u:<runtime-uid>:rwX), because the problem is
# symmetric across time — the first file the PRODUCT writes after migration is owned by the runtime uid,
# and a default ACL naming only that uid grants it what it already has and the operator nothing.
mi_copy_run() {
  if [ "$#" -lt 5 ]; then
    mi_warn "copy: mi_copy_run needs <index> <source volume> <staging> <runtime-uid> <operator-uid> [--map-foreign-to-operator]"
    return 1
  fi
  local idx="$1" srcvol="$2" stage="$3" ruid="$4" ouid="$5"; shift 5
  local mapforeign=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --map-foreign-to-operator) mapforeign=1; shift ;;
      *) mi_warn "copy: unknown option '$1'"; return 1 ;;
    esac
  done
  _mi_copy_uid_ok "$ruid" "the product's runtime uid" || return 1
  _mi_copy_uid_ok "$ouid" "the operator uid" || return 1
  mi_copy_available "$idx" || return 1
  # Cleared up front so a refused or failed copy never leaves a STALE source count behind for the
  # verify half to be measured against. Set only on a completed, non-empty copy at the very end.
  MI_COPY_ENTRIES=

  local -a cspecs
  cspecs=("arg=/src" "arg=/dst" "arg=${ruid}" "arg=${ouid}")
  if [ "$mapforeign" -ne 0 ]; then cspecs+=("arg=--map-foreign"); fi

  local out rc
  if out="$(_mi_copy_helper "$idx" copy "${cspecs[@]}" "srcvol=${srcvol}" "staging=${stage}")"; then rc=0; else rc=$?; fi

  # Report the contract observations BEFORE deciding, so a refusal still tells the operator what the
  # copier saw. `refused` is declared up here because an unrequested mapping (below) sets it too.
  local v refused=0 seen="" reason detail path
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if _mi_copy_linktarget_split "$v"; then
      mi_log "  symlink preserved verbatim: ${_MI_COPY_LT_PATH} -> ${_MI_COPY_LT_TARGET}"
    else
      mi_log "  symlink target logged in a form this core could not read: ${v}"
    fi
  done <<< "$(_mi_copy_fields "$out" linktarget)"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_log "  privileged bits stripped: ${v}"
    mi_log "    Nothing a product legitimately stores needs setuid/setgid/sticky on the host."
  done <<< "$(_mi_copy_fields "$out" stripped)"
  # A `mapped=` observation is honoured ONLY when the operator opted in with
  # --map-foreign-to-operator. The flag changes the helper's argv, but a regressed or hostile helper
  # can report a mapping on a DEFAULT invocation — and folding foreign ownership into the operator's
  # is exactly the decision the opt-in exists to gate. So an UNREQUESTED mapping is REFUSED, never
  # logged-and-accepted; a requested one is reported with its numeric value preserved.
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if [ "$mapforeign" -eq 0 ]; then
      mi_warn "copy: REFUSED ${v} — the copier reports folding a foreign uid into the operator's on a"
      mi_warn "  copy that did NOT request it. Mapping foreign ownership is opt-in: re-run with"
      mi_warn "  --map-foreign-to-operator if that is your intent, or investigate the foreign uid"
      mi_warn "  first. An unrequested mapping is refused, never applied silently."
      refused=1
    else
      mi_log "  foreign uid mapped to the operator: ${v} (the numeric value is preserved here in text)"
    fi
  done <<< "$(_mi_copy_fields "$out" mapped)"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    # `refused=<path>:<reason>`, parsed with the REASON LAST and taken from a CLOSED vocabulary, so a
    # path containing a colon — legal on every filesystem this runs on — still parses. Splitting on the
    # FIRST colon (the obvious way) reports `/src/a` as the refused path for
    # `/src/a:b/dev/thing:special-entry`: the wrong path, in the one message an operator acts on.
    detail=""
    case "$v" in
      *:foreign-uid:*)
        detail="${v##*:}"
        path="${v%:*}"
        case "$path" in *:foreign-uid) path="${path%:*}" ;; *) path="" ;; esac
        case "$detail" in ''|*[!0-9]*) path="" ;; esac
        if [ -n "$path" ]; then reason=foreign-uid; else reason=unreadable; path="$v"; fi ;;
      *:special-entry) reason=special-entry; path="${v%:*}" ;;
      *:escaped-write) reason=escaped-write; path="${v%:*}" ;;
      *:escaping-symlink) reason=escaping-symlink; path="${v%:*}" ;;
      *:staging-nonempty) reason=staging-nonempty; path="${v%:*}" ;;
      *:unknown-entry-type) reason=unknown-entry-type; path="${v%:*}" ;;
      *:unreadable-linktarget) reason=unreadable-linktarget; path="${v%:*}" ;;
      *:missing-linktarget) reason=missing-linktarget; path="${v%:*}" ;;
      *) reason=unreadable; path="$v" ;;
    esac
    # One path, one message: the two sources of a refusal (an explicit `refused=` line and an `entry=`
    # line whose type is `special`) legitimately name the same path.
    case "$seen" in *"|${path}|"*) continue ;; esac
    seen="${seen}|${path}|"
    case "$reason" in
      special-entry)
        mi_warn "copy: REFUSED $path — a device, socket or FIFO."
        mi_warn "  These are not product data, cannot be meaningfully copied, and are the entry types a"
        mi_warn "  copier is most easily tricked by." ;;
      foreign-uid)
        mi_warn "copy: REFUSED $path — it is owned by uid $detail, which is neither the product's"
        mi_warn "  runtime uid nor yours. A foreign uid in a product volume is unexpected, and the"
        mi_warn "  decision is yours: re-run with --map-foreign-to-operator to fold them into the"
        mi_warn "  mapping (the numeric information is preserved in the report), or investigate first." ;;
      escaped-write)
        mi_warn "copy: REFUSED $path — the copier reported a write that would land outside the"
        mi_warn "  destination. This is the escape §5.1 exists to prevent; the copy is abandoned." ;;
      escaping-symlink)
        mi_warn "copy: REFUSED $path — its stored symlink target escapes the migrated tree (it is an"
        mi_warn "  absolute path, or climbs above the root with '..'). The copy preserves a target"
        mi_warn "  verbatim and does not resolve it, so carrying this one would point outside the tree"
        mi_warn "  the moment any later product or container followed it. Refused rather than kept." ;;
      staging-nonempty)
        mi_warn "copy: REFUSED $path — the staging destination was not empty when the copy container"
        mi_warn "  reached it. Emptiness is checked INSIDE the container, on the writable mount and"
        mi_warn "  atomically with the copy: the copy MERGES the source over whatever is already there"
        mi_warn "  and verification checks only the source, so a pre-existing entry would survive inside"
        mi_warn "  the migrated tree unexamined. Refused." ;;
      unknown-entry-type)
        mi_warn "copy: REFUSED $path — the copier enumerated an entry whose type is not one of file,"
        mi_warn "  dir, symlink, hardlink or special (or the entry line carries no path). An entry the"
        mi_warn "  core cannot classify — a FIFO or socket smuggled past the special-entry check — is"
        mi_warn "  refused rather than silently counted toward a copy reported complete." ;;
      unreadable-linktarget)
        mi_warn "copy: REFUSED $path — the copier logged a symlink target this core could not read (its"
        mi_warn "  trailing length field is missing or not a number). A target we cannot parse might be"
        mi_warn "  concealing one that escapes the migrated tree, so it is refused rather than guessed." ;;
      missing-linktarget)
        mi_warn "copy: REFUSED $path — the copier enumerated a symlink but disclosed no linktarget record"
        mi_warn "  for it, so its stored target was never shown and the escape backstop never ran on it. A"
        mi_warn "  symlink entry without a matching linktarget is refused: an undisclosed target cannot be"
        mi_warn "  shown not to escape the migrated tree." ;;
      *)
        mi_warn "copy: REFUSED — the copier stated a refusal in a form this core cannot read: '$v'."
        mi_warn "  It is treated as a refusal rather than skipped: an unreadable refusal is still one." ;;
    esac
    refused=1
  done <<< "$(_mi_copy_refusals "$out" /src)"

  # An EMPTY `refused=` line (no path) is a stated refusal the loop above skips, because
  # `_mi_copy_refusals` passes it through as an empty line and the consumer drops empties. Its presence
  # is the problem, so it is caught here by the key — a copier that refuses without naming what is still
  # a copier that refused.
  if _mi_copy_has_key "$out" refused && [ "$refused" -eq 0 ]; then
    mi_warn "copy: the copier stated a refusal that named nothing (an empty 'refused=' record). A"
    mi_warn "  refusal is a refusal whether or not it says what — the copy is abandoned."
    refused=1
  fi

  [ "$refused" -eq 0 ] || return 1
  [ "$rc" -eq 0 ] || { mi_warn "copy: the copy did not complete."; return 1; }
  v="$(_mi_copy_stated "$out" "done" copy completion)" || return 1
  if [ "$v" != ok ]; then
    mi_warn "copy: the copier reported 'done=${v:-<empty>}' rather than completion — treating that as a"
    mi_warn "  failure. An exit status is not a result."
    return 1
  fi
  # THE COPY'S OWN ENUMERATION OF THE SOURCE is the number that binds verification. Every `entry=` line
  # is one source entry the copier read; their count is a source-derived number no caller invents, and
  # it is PERSISTED here (MI_COPY_ENTRIES) for the verify half to be measured against — the real call
  # site (mi_copy_run_verify) threads it through, closing the "count nobody derives" hole (round-2
  # finding 1). A copy that reports done=ok having enumerated ZERO entries is a vacuous completion —
  # unmeasured is not measured-clean, and over a non-empty source it is exactly that fail-open — so it
  # is REFUSED here rather than recorded as a success measured on nothing.
  # The count binds verification, so it must be a count of DISTINCT source entries — one line per path
  # the copier read. A repeated path is refused, because otherwise a copier can pad the count: emit one
  # valid entry N times and OMIT an escaping symlink or a special entry, and `checked=N` then matches a
  # total that never included the dangerous one. The path is the identity of a source entry (a path is
  # one filesystem object whatever type is claimed for it), so duplicates are detected on the path, not
  # the raw line. This makes the count a count of things, not of claims about things — the internal
  # consistency the verify half is measured against. (Whether the copier's per-entry COMPARISON is
  # honest is the pinned image's responsibility, verified by its own build/CI against the release
  # digest; the core's responsibility is confinement, refusing on any reported refusal/mismatch, and
  # this internal consistency of the report.)
  local entries=0 epath eseen=$'\n'
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in *:*) epath="${v#*:}" ;; *) epath="" ;; esac
    if [ -z "$epath" ]; then
      mi_warn "copy: the copier enumerated an entry line with no path ('${v}'). Refusing rather than"
      mi_warn "  counting a claim that names nothing toward a completed copy."
      return 1
    fi
    case "$eseen" in *$'\n'"${epath}"$'\n'*)
      mi_warn "copy: the copier enumerated '${epath}' more than once. A repeated source path pads the"
      mi_warn "  entry count without adding a distinct entry — and a padded count can match a 'checked='"
      mi_warn "  total that omitted a dangerous entry. Refusing rather than binding verification to a"
      mi_warn "  count of duplicated claims."
      return 1 ;;
    esac
    eseen="${eseen}${epath}"$'\n'
    entries=$((entries + 1))
  done <<< "$(_mi_copy_fields "$out" entry)"
  if [ "$entries" -eq 0 ]; then
    mi_warn "copy: the copier reported done=ok having enumerated ZERO source entries. A completed copy"
    mi_warn "  that measured nothing is not evidence of a copy — refusing rather than recording a"
    mi_warn "  vacuous success over what may be a non-empty source."
    return 1
  fi
  MI_COPY_ENTRIES="$entries"
  return 0
}

# THE REAL CALL SITE THAT BINDS THE COPY TO ITS VERIFICATION. It runs the copy and then verifies it
# against the source using the count the COPY ITSELF enumerated (persisted in MI_COPY_ENTRIES by
# mi_copy_run), never a number chosen here or at any call site. Without a caller that threads that
# count, the "checked matches the source" gate is a convention nobody honours: the count degenerates to
# "whatever the caller invents", the tests hard-code it, and the vacuity simply moves (round-2 finding
# 1). Task 12's migrate verb calls THIS — the two halves are never wired by hand with a caller-chosen
# count.
#
# The runtime and operator uids are threaded on to verification so it can confirm the dual-principal
# default ACL was actually APPLIED to the copied tree (round-2 finding 3), not merely possible.
mi_copy_run_verify() {
  if [ "$#" -lt 5 ]; then
    mi_warn "copy: mi_copy_run_verify needs <index> <source volume> <staging> <runtime-uid> <operator-uid> [--map-foreign-to-operator]"
    return 1
  fi
  local idx="$1" srcvol="$2" stage="$3" ruid="$4" ouid="$5"
  mi_copy_run "$@" || return 1
  local n="${MI_COPY_ENTRIES:-}"
  case "$n" in
    ''|*[!0-9]*)
      mi_warn "copy: the copy did not report how many source entries it enumerated, so verification"
      mi_warn "  cannot be bound to the source. Refusing rather than verifying against a count no step"
      mi_warn "  derived."
      return 1 ;;
  esac
  mi_copy_verify "$idx" "$srcvol" "$stage" "$n" "$ruid" "$ouid"
}

# UNAMBIGUOUSLY split a `linktarget=` VALUE into the symlink's path and its verbatim target,
# regardless of colons in EITHER of them. The value is `<path><target>:<pathlen>` — a LENGTH-DELIMITED
# encoding whose trailing, colon-free field is the path's BYTE length: the path is the first <pathlen>
# bytes of the body and the target is the rest. This REPLACES the old first-colon split, which reported
# the wrong path — and could MISS an escape — for a symlink whose own path contained a colon, a legal
# byte on every filesystem this runs on. The length is a fixed-shape (numeric) token placed where
# neither a path's nor a target's own bytes can reach it, the same discipline `refused=` (reason last)
# and `entry=` (type first) use for their one variable component.
#
# Sets _MI_COPY_LT_PATH and _MI_COPY_LT_TARGET. rc 0 parsed · 1 the value is malformed (a non-numeric
# or out-of-range length). A linktarget the core cannot parse is REFUSED by the caller, never guessed:
# an unreadable target could be concealing an escape.
_mi_copy_linktarget_split() {
  local v="$1" pathlen body
  local LC_ALL=C            # <pathlen> is a BYTE length; slice in bytes, not the operator's locale
  pathlen="${v##*:}"
  case "$pathlen" in ''|*[!0-9]*) return 1 ;; esac
  body="${v%:*}"
  # The path is at least one byte and cannot be longer than the body it prefixes. Length-bounded before
  # the arithmetic so an absurd stated length cannot trip `[`'s integer-expression path (bash 3.2).
  if [ "${#pathlen}" -gt 10 ] || [ "$pathlen" -lt 1 ] || [ "$pathlen" -gt "${#body}" ]; then return 1; fi
  _MI_COPY_LT_PATH="${body:0:pathlen}"
  _MI_COPY_LT_TARGET="${body:pathlen}"
  return 0
}

# Does a symlink at <linkpath> whose stored target is <target> point OUTSIDE the tree rooted at
# <root>? Purely LEXICAL — the target is never resolved on disk, because following it is exactly the
# escape this refuses (the host-side walk deliberately does not follow links either). A target
# escapes when it is ABSOLUTE, or when its `..` components climb above the root from the directory the
# symlink sits in. A verbatim intra-tree relative target (`../sibling/f`) is NOT an escape.
#
# The strings are walked one `/`-separated component at a time by parameter expansion, never by
# `set -- $target`: under IFS=/ that both DROPS empty fields and GLOB-EXPANDS a component like `*`,
# and a symlink target may legally contain either. rc 0 escapes · 1 stays inside.
_mi_copy_link_escapes() {
  local linkpath="$1" target="$2" root="$3" rel dir rest comp depth
  case "$target" in /*) return 0 ;; esac              # absolute → outside the tree by definition
  case "$linkpath" in
    "$root"/*) rel="${linkpath#"$root"/}" ;;
    *) return 0 ;;                                     # not under the root we were handed — refuse, don't guess
  esac
  # Depth of the symlink's PARENT directory below root = rel minus its last (basename) component.
  case "$rel" in */*) dir="${rel%/*}" ;; *) dir="" ;; esac
  depth=0; rest="$dir"
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    case "$rest" in */*) rest="${rest#*/}" ;; *) rest="" ;; esac
    case "$comp" in ''|.) continue ;; esac
    depth=$((depth + 1))
  done
  rest="$target"
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    case "$rest" in */*) rest="${rest#*/}" ;; *) rest="" ;; esac
    case "$comp" in
      ''|.) : ;;
      ..) depth=$((depth - 1)); if [ "$depth" -lt 0 ]; then return 0; fi ;;
      *)  depth=$((depth + 1)) ;;
    esac
  done
  return 1
}

# EVERY REFUSAL THE ANSWER STATES, from every thing that can state one, in ONE place.
#
#   `refused=<path>:<reason>`      the copier's own refusal
#   `entry=<type>:<path>`          EVERY enumerated entry, checked against the closed type set AND for
#                                  its required companion record (a `symlink` needs a `linktarget=`)
#   `linktarget=<path><target>:<pathlen>`  a symlink it enumerated whose target ESCAPES the tree (<root>)
#
# REQUIRED COMPANIONS ARE CROSS-CHECKED, not assumed. A `symlink` entry whose path has no matching
# `linktarget=` record is refused (`:missing-linktarget`): its target was never disclosed, so the
# escape backstop below never ran on it, and a copier could otherwise smuggle an escaping symlink past
# by omitting the linktarget (and any refused=) line while still counting the entry and reporting
# done=ok. This is the CLASS — an entry whose type carries required companion data must have it present.
# `file`/`dir` carry no core-required companion; a `hardlink`'s referent is a real in-tree inode, not
# an escapable target string, so it needs none.
#
# The last two are folded in here rather than checked beside the loop because they are the same
# decision: an unclassifiable entry, or an escaping symlink, is a refusal whether or not the copier
# remembered to say so — a copier that enumerated one and then exited 0 must not be believed. Two
# separate checks would be two verdicts that can drift, and the one that drifts is the one nobody
# re-reads.
#
# ENTRY TYPES ARE A CLOSED VOCABULARY, and EVERY `entry=` is checked against it — not just `special`.
# The type is bounded on the left by the first colon (`entry=<type>:<path>`, type first). A type
# outside `file|dir|symlink|hardlink|special`, or a line with no path, is a `fifo:`/`socket:` (or
# malformed) entry a copier could otherwise smuggle past a `special`-only check: it would be counted
# toward a copy reported complete while nothing ever classified it. So it is refused
# (`:unknown-entry-type`), and `special` with a path is folded as before.
#
# For the symlink fold the authoritative, colon-robust refusal is the copier's own
# `refused=<path>:escaping-symlink` (reason LAST); this backstop parses `linktarget=` through the
# LENGTH-DELIMITED `_mi_copy_linktarget_split`, so a colon inside EITHER the link's own path or its
# target no longer degrades it (the old first-colon split did). A linktarget it cannot parse is refused
# (`:unreadable-linktarget`), never guessed.
_mi_copy_refusals() {
  local blob="$1" root="$2" v etype epath ltpaths="" p found
  _mi_copy_fields "$blob" refused
  # LINKTARGETS FIRST, so the entry pass below can cross-check every `symlink` against the set of paths
  # that actually DISCLOSED a target. Each parsed linktarget is recorded in `ltpaths` (newline-delimited
  # — a path may contain any byte but a newline, which the one-line format already forbids) and run
  # through the escape backstop; an unparseable one is refused rather than guessed.
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if _mi_copy_linktarget_split "$v"; then
      ltpaths="${ltpaths}${_MI_COPY_LT_PATH}"$'\n'
      if _mi_copy_link_escapes "$_MI_COPY_LT_PATH" "$_MI_COPY_LT_TARGET" "$root"; then
        printf '%s:escaping-symlink\n' "$_MI_COPY_LT_PATH"
      fi
    else
      printf '%s:unreadable-linktarget\n' "$v"
    fi
  done <<< "$(_mi_copy_fields "$blob" linktarget)"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in
      *:*) etype="${v%%:*}"; epath="${v#*:}" ;;
      *)   etype=""; epath="" ;;
    esac
    if [ -n "$epath" ]; then
      case "$etype" in
        special) printf '%s:special-entry\n' "$epath"; continue ;;
        # REQUIRED-COMPANION CROSS-CHECK. A `symlink` entry MUST come with a `linktarget=` record for
        # the SAME path. Without it the target was never disclosed, the escape backstop above never saw
        # it, and a copier could smuggle an escaping symlink past by simply OMITTING the linktarget (and
        # any refused=) line while still counting the entry and reporting done=ok. Refuse it. This closes
        # the CLASS "an entry whose type carries required companion data must have it": `file`/`dir`
        # carry no core-required companion, and a `hardlink`'s referent is a real in-tree inode — not an
        # arbitrary target string that can point outside — so it needs none.
        symlink)
          found=0
          while IFS= read -r p; do [ "$p" = "$epath" ] && { found=1; break; }; done <<< "$ltpaths"
          if [ "$found" -eq 0 ]; then printf '%s:missing-linktarget\n' "$epath"; fi
          continue ;;
        file|dir|hardlink) continue ;;
      esac
    fi
    # A type outside the closed set, or an entry line with no path: refused, carrying the raw entry so
    # the operator sees exactly what the copier emitted (reason last, colon-robust downstream).
    printf '%s:unknown-entry-type\n' "$v"
  done <<< "$(_mi_copy_fields "$blob" entry)"
}

# VERIFICATION IS OVER THE CONTRACT, NOT A BYTE COUNT: every source entry has a counterpart of the same
# TYPE at the destination, regular-file contents match by DIGEST, symlink targets match AS STRINGS,
# hardlink topology is preserved, and the preserved metadata matches. A copy that "succeeded" while
# dropping modes is a copy that hands the product a directory it cannot write.
#
# The destination is mounted READ-ONLY here (`dstro=`): a verifier that can repair what it finds cannot
# report it.
mi_copy_verify() {
  if [ "$#" -ne 6 ]; then mi_warn "copy: mi_copy_verify needs <index> <source volume> <destination> <expected-entries> <runtime-uid> <operator-uid>"; return 1; fi
  local idx="$1" srcvol="$2" dst="$3" expect="$4" ruid="$5" ouid="$6" out rc bad=0 v n da
  # <expected-entries> is the source's entry count, derived by the CALLER from the copy step's own
  # `entry=` enumeration — an INDEPENDENT, source-derived number the verifier is measured against, and
  # the thing that binds `checked` to the source. Without it `checked=0 done=ok` is a completion claim
  # over no evidence, and `checked=<a large number> done=ok` is a claim to have compared entries that
  # were never there. Neither the count nor the verdict may come from the verifier alone.
  case "$expect" in ''|*[!0-9]*) mi_warn "copy: mi_copy_verify's <expected-entries> '$expect' is not a count"; return 1 ;; esac
  # The uids are validated HERE too (not only in the adapter's --user gate): they are passed to the
  # verifier so it can check the copied tree for the default entries naming BOTH principals, and are
  # named in the messages below.
  _mi_copy_uid_ok "$ruid" "the product's runtime uid" || return 1
  _mi_copy_uid_ok "$ouid" "the operator uid" || return 1
  mi_copy_available "$idx" || return 1
  # Whether the default-ACL application check below is meaningfully enforced on THIS daemon — the same
  # honest three-way statement preflight makes, shared so verify never claims enforcement Docker Desktop
  # does not give (round-2 finding 3).
  _mi_copy_acl_context_note "the default-ACL application check"
  if out="$(_mi_copy_helper "$idx" verify "arg=/src" "arg=/dst" "arg=${ruid}" "arg=${ouid}" "srcvol=${srcvol}" "dstro=${dst}")"; then rc=0; else rc=$?; fi
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_warn "copy: VERIFICATION MISMATCH ${v}"
    bad=1
  done <<< "$(_mi_copy_fields "$out" mismatch)"
  # ANY refused= OR mismatch= LINE FAILS THE COPY, DETECTED BY PRESENCE. The verifier can report a
  # refusal (`refused=`) exactly as the copy step can — a device it met while walking the destination,
  # an entry it could not compare — and this function never read `refused=` at all, so a transcript of
  # `refused=<anything> checked=<expected> acl=ok done=ok` was accepted. And an EMPTY problem record
  # (`refused=` / `mismatch=` with no value) is a stated problem too: the value loop above skips it, so
  # it is caught here by the key. A problem is a problem by being reported, whatever it says.
  if _mi_copy_has_key "$out" refused; then
    while IFS= read -r v; do mi_warn "copy: the verifier REFUSED ${v:-<an entry it did not name>}"; done <<< "$(_mi_copy_fields "$out" refused)"
    bad=1
  fi
  if _mi_copy_has_key "$out" mismatch; then bad=1; fi
  if [ "$bad" -ne 0 ]; then
    mi_warn "copy: the copy does not match the source over the per-entry contract."
    return 1
  fi
  [ "$rc" -eq 0 ] || { mi_warn "copy: verification did not run to completion."; return 1; }
  v="$(_mi_copy_stated "$out" "done" verify completion)" || return 1
  if [ "$v" != ok ]; then
    mi_warn "copy: verification reported 'done=${v:-<empty>}' rather than completion — treating that as"
    mi_warn "  a failure."
    return 1
  fi
  # A COUNT IS PART OF THE RESULT. "done=ok" with no count is a verification claim on no evidence: a
  # verifier that walked zero entries and exited 0 would otherwise report the copy good.
  n="$(_mi_copy_stated "$out" checked verify "how many entries it checked")" || return 1
  case "$n" in
    ''|*[!0-9]*)
      mi_warn "copy: verification did not say how many entries it checked (checked=${n:-<empty>})."
      mi_warn "  Refusing: a completion claim with no count is not evidence that anything was compared."
      return 1 ;;
  esac
  # BIND THE COUNT TO THE SOURCE. The verifier must have checked EXACTLY the source's entries — not
  # zero of them (a vacuous pass over a non-empty source), and not a fabricated surplus. A count that
  # differs from the source's own means the per-entry walk did not cover the source the copy read, so
  # the copy is not verified. Compared as STRINGS: both are validated `[0-9]+`, and string equality
  # sidesteps `[`'s integer-overflow trap on an absurd stated count.
  if [ "$n" != "$expect" ]; then
    mi_warn "copy: the verifier checked $n entries but the source has $expect — the per-entry walk did"
    mi_warn "  not cover exactly the source the copy read, so the copy is NOT verified. (A count of"
    mi_warn "  zero against a non-empty source is this failure's most important shape.)"
    return 1
  fi
  # THE DUAL-PRINCIPAL DEFAULT ACL WAS ACTUALLY APPLIED to the copied tree — checked empirically here,
  # not inferred from preflight capability (capability is not application — round-2 finding 3). A
  # missing default entry on a copied directory is reported as `mismatch=<dir>:default-acl` above, like
  # any other attribute; this REQUIRES the positive observation on top, because a verifier that never
  # looked emits no acl mismatch and would otherwise pass on no evidence — the very vacuity the finding
  # is about, one level down. Absent is a refusal (_mi_copy_stated); `skipped` is a no-op ONLY when the
  # two principals are one uid, exactly as preflight's acl step.
  da="$(_mi_copy_stated "$out" acl verify "the default-ACL application")" || return 1
  case "$da" in
    ok) : ;;
    skipped)
      if [ "$ruid" != "$ouid" ]; then
        mi_warn "copy: verification reports the default-ACL check SKIPPED, but the product's runtime uid"
        mi_warn "  ($ruid) is not the operator's ($ouid) — the only condition under which it is a no-op."
        mi_warn "  Refusing: a load-bearing check reported as skipped is a check that did not run."
        return 1
      fi ;;
    *)
      mi_warn "copy: the copied tree did not pass the default-ACL application check (acl=${da:-<empty>})."
      mi_warn "  Refusing: capability at preflight is not proof of application. Without the default"
      mi_warn "  entries naming BOTH the operator and the runtime uid, the first file the product writes"
      mi_warn "  after migration is unreadable by you — the failure reappears on the first post-migration"
      mi_warn "  write."
      return 1 ;;
  esac
  mi_log "copy: verified $n entries against the source over the per-entry contract."
  return 0
}

# CONTAINER-SIDE EFFECTIVE ACCESS, by OUR helper running AS THE PRODUCT'S RUNTIME UID.
#
# ACL PRESENCE IS NOT EFFECTIVE ACCESS — a restrictive ACL mask silently limits a present entry — and
# D48 only forbids requiring tools in PRODUCT images; the pinned helper is ours. So it mounts the
# destination, actually traverses, reads, and writes a probe file, then removes it. That is
# effective-access verification without asking anything of the product image.
#
# WHAT REMAINS UNCLAIMED is only the product's OWN runtime behaviour: the filesystem access itself is
# tested, not constructed-and-hoped.
mi_copy_access_check() {
  if [ "$#" -ne 3 ]; then mi_warn "copy: mi_copy_access_check needs <index> <destination> <runtime-uid>"; return 1; fi
  local idx="$1" dst="$2" ruid="$3" out rc k v
  # Checked HERE as well as in the runtime adapter, because the value is also printed in every message
  # below and a non-numeric one would name a uid this check never ran as.
  _mi_copy_uid_ok "$ruid" "the runtime uid" || return 1
  mi_copy_available "$idx" || return 1
  if out="$(MI_COPY_RUNAS="$ruid" _mi_copy_helper "$idx" access "arg=/dst" "staging=${dst}")"; then rc=0; else rc=$?; fi
  for k in traverse read write; do
    v="$(_mi_copy_stated "$out" "$k" access)" || return 1
    if [ "$v" != ok ]; then
      mi_warn "copy: as uid $ruid, the destination failed the '$k' check (${k}=${v:-<empty>})."
      mi_warn "  ACL presence is not effective access — a restrictive mask silently limits an entry that"
      mi_warn "  is present — which is why this is TESTED as that uid rather than inferred from the"
      mi_warn "  entries we set. Refusing."
      return 1
    fi
  done
  [ "$rc" -eq 0 ] || { mi_warn "copy: the container-side access check did not run to completion."; return 1; }
  return 0
}

# HOST-SIDE: the operator can traverse and read the tree. Done on the host, with no container, because
# it is the operator's own access that is in question.
#
# DIRECTORIES AND FILES BOTH, in one walk. A tree whose directories are all traversable but whose FILES
# cannot be read is exactly as unusable as the other way round, and checking only one of them is this
# plan's most common defect shape: a rule applied to some of the things that reach it.
#
# `find` WITHOUT `-L`, deliberately. The copy preserves an escaping symlink as TEXT and never follows
# it; following it here would report on /etc rather than on the migrated tree, and could refuse a
# perfectly good copy because of something outside it entirely.
#
# find's own STDERR is folded in rather than discarded: a directory it could not descend into is a
# subtree nobody checked, and "I could not look" is not "there is nothing wrong there".
#
# THE BOUND ON WHAT THIS PROVES, stated rather than implied: `-perm` reads the OWNER's bits, which is
# the operator's own permission on a tree this copy has just chowned to the operator, and is not the
# same question as "can this process open it" on a tree owned by someone else. It is the portable half
# — GNU's `-readable` does not exist on macOS, and §10a requires identical behaviour on both.
mi_copy_host_access_check() {
  if [ "$#" -ne 1 ]; then mi_warn "copy: mi_copy_host_access_check needs a <destination>"; return 1; fi
  local dst="$1" bad=0 p out
  [ -d "$dst" ] || { mi_warn "copy: '$dst' is not a directory"; return 1; }
  out="$(find "$dst" \( \( -type d ! -perm -u+rx \) -o \( -type f ! -perm -u+r \) \) -print 2>&1)" || true
  if [ -n "$out" ]; then
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      mi_warn "copy: the migrated tree is not fully readable by you: $p"
      bad=1
    done <<< "$out"
  fi
  [ "$bad" -eq 0 ]
}
