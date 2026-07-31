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

# EMPIRICAL destination preflight, probed rather than inferred from the filesystem's name: create,
# chown, link, stat, set a default ACL, create a child AS EACH UID, read it as the other. A destination
# that cannot represent the contract is REFUSED, naming what failed — a silent best-effort copy is a
# copy that lies.
mi_copy_preflight() {
  if [ "$#" -ne 4 ]; then mi_warn "copy: mi_copy_preflight needs <index> <staging> <runtime-uid> <operator-uid>"; return 1; fi
  local idx="$1" stage="$2" ruid="$3" ouid="$4" out rc k v ep
  mi_copy_available "$idx" || return 1

  # §4.5 residual 2 / D60: Docker Desktop translates ownership at the file-sharing layer, so group and
  # ACL semantics are effectively bypassed there — both sides simply see access. The mechanism is
  # load-bearing on NATIVE LINUX specifically. Say so rather than claiming a check that is not enforced.
  #
  # THREE ANSWERS, NOT TWO. "Docker Desktop", "something else", and "the endpoint could not be read at
  # all" — and the third is not the second. Saying nothing when the question could not be asked would
  # let the run be read as the native-Linux case, where the ACL step IS enforced: a claim nothing here
  # established. "I could not ask" is never "there is nothing there".
  if [ -n "${DOCKER_HOST:-}" ]; then ep="$DOCKER_HOST"; else ep="$(mi_rt_context_host 2>/dev/null)" || ep=""; fi
  case "$ep" in
    *"/.docker/run/docker.sock"|npipe://*)
      mi_warn "copy: this is Docker Desktop, where ownership is translated at the file-sharing layer, so"
      mi_warn "  the ACL step is not meaningfully enforced here. It is applied and reported, but passing"
      mi_warn "  on Docker Desktop proves NOTHING about the gid/ACL path — that is exercised on native"
      mi_warn "  Linux (§4.5, §10a)." ;;
    '')
      mi_warn "copy: the active daemon endpoint could not be read, so whether the ACL step below is"
      mi_warn "  meaningfully enforced on this daemon is UNKNOWN. It is neither claimed nor dismissed:"
      mi_warn "  it is enforced on native Linux and bypassed by Docker Desktop's file-sharing layer, and"
      mi_warn "  nothing here established which of those this is." ;;
  esac

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

# The copy itself. Entry types and metadata are a stated contract, not a tool's defaults:
#
#   regular file, directory   copied; mtime preserved; ownership and mode per the policy below
#   symlink                   recreated as a SYMLINK with its target string VERBATIM, never resolved. An
#                             absolute or escaping target is preserved AS TEXT and is harmless: it is
#                             not followed during the copy, and inside the container it resolves under
#                             that container's own root.
#   hardlink                  link structure preserved WITHIN the copy — breaking it silently doubles
#                             disk use and de-couples files a product expects to be the same inode
#   device, socket, FIFO      REFUSED, naming the path
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
  mi_copy_available "$idx" || return 1

  local -a cspecs
  cspecs=("arg=/src" "arg=/dst" "arg=${ruid}" "arg=${ouid}")
  if [ "$mapforeign" -ne 0 ]; then cspecs+=("arg=--map-foreign"); fi

  local out rc
  if out="$(_mi_copy_helper "$idx" copy "${cspecs[@]}" "srcvol=${srcvol}" "staging=${stage}")"; then rc=0; else rc=$?; fi

  # Report the contract observations BEFORE deciding, so a refusal still tells the operator what the
  # copier saw.
  local v
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_log "  symlink preserved verbatim: ${v}"
  done <<< "$(_mi_copy_fields "$out" linktarget)"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_log "  privileged bits stripped: ${v}"
    mi_log "    Nothing a product legitimately stores needs setuid/setgid/sticky on the host."
  done <<< "$(_mi_copy_fields "$out" stripped)"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_log "  foreign uid mapped to the operator: ${v} (the numeric value is preserved here in text)"
  done <<< "$(_mi_copy_fields "$out" mapped)"

  local refused=0 seen="" reason detail path
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
      *)
        mi_warn "copy: REFUSED — the copier stated a refusal in a form this core cannot read: '$v'."
        mi_warn "  It is treated as a refusal rather than skipped: an unreadable refusal is still one." ;;
    esac
    refused=1
  done <<< "$(_mi_copy_refusals "$out")"

  [ "$refused" -eq 0 ] || return 1
  [ "$rc" -eq 0 ] || { mi_warn "copy: the copy did not complete."; return 1; }
  v="$(_mi_copy_stated "$out" "done" copy completion)" || return 1
  if [ "$v" != ok ]; then
    mi_warn "copy: the copier reported 'done=${v:-<empty>}' rather than completion — treating that as a"
    mi_warn "  failure. An exit status is not a result."
    return 1
  fi
  return 0
}

# EVERY REFUSAL THE ANSWER STATES, from both things that can state one, in ONE place.
#
#   `refused=<path>:<reason>`   the copier's own refusal
#   `entry=special:<path>`      an entry it ENUMERATED as a device, socket or FIFO
#
# The second is folded in here rather than checked beside the loop because it is the same decision: a
# special entry is a refusal whether or not the copier remembered to say so, and a copier that
# enumerated one and then exited 0 must not be believed. Two separate checks would be two verdicts that
# can drift, and the one that drifts is the one nobody re-reads.
_mi_copy_refusals() {
  local blob="$1" v
  _mi_copy_fields "$blob" refused
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    # `entry=<type>:<path>` — TYPE FIRST, so the path is everything after the first colon and may
    # contain colons of its own.
    case "$v" in special:*) printf '%s:special-entry\n' "${v#*:}" ;; esac
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
  if [ "$#" -ne 3 ]; then mi_warn "copy: mi_copy_verify needs <index> <source volume> <destination>"; return 1; fi
  local idx="$1" srcvol="$2" dst="$3" out rc bad=0 v n
  mi_copy_available "$idx" || return 1
  if out="$(_mi_copy_helper "$idx" verify "arg=/src" "arg=/dst" "srcvol=${srcvol}" "dstro=${dst}")"; then rc=0; else rc=$?; fi
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_warn "copy: VERIFICATION MISMATCH ${v}"
    bad=1
  done <<< "$(_mi_copy_fields "$out" mismatch)"
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
  case "$ruid" in ''|*[!0-9]*) mi_warn "copy: '$ruid' is not a numeric uid"; return 1 ;; esac
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
