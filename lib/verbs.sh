#!/usr/bin/env bash
# The lifecycle verbs. Deliberately THIN: each holds the lock, walks a sequence the earlier modules
# define, and reports. The sequence, the reconciler and the recovery tables are not here.
#
# EVERY VERB DECLARES ITS EFFECT ON DESIRED STATE — there is no default (§6b.3's verb table). Two rules
# with no exception: a verb that stops a container as a MEANS (recreate, migrate) must not overwrite
# what the operator wants — only install/start/stop express intent — and every transition that leaves a
# container running ends in a live verification, because "it started" is not evidence its alias
# resolves.
#
# THE FAMILY LOCK IS HELD ACROSS A WHOLE MUTATING VERB THROUGH _mi_with_lock, NOT A `trap … RETURN`.
# A RETURN trap set in a verb is fired by bash on every NESTED function return when functrace (`set
# -T`) is on — which is exactly how the test harness runs a test body — so the trap would release the
# lock on the first inner call and every later ledger write would refuse for want of it. An explicit
# acquire-run-release is correct whether functrace is on or off, so it is what the verbs use.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.
#
# ARRAY-TYPED LOCALS DECLARED HERE: `specs`, `wanted`, `vroles`, `codes`, `extra`. tools/bundle.sh
# flattens every module into one file, after which shellcheck's array tracking is no longer
# per-function — so a later module using one of these names for an ordinary scalar draws SC2178 plus an
# SC2128 per use. None collide with the names already spoken for elsewhere (`args`, `pk`, `pv`,
# `placed`, `fields`, `triples`, `rtargv`, `rtpost`, `hspecs`, `pairs`, `srcs`, `modes`, `bspecs`,
# `broles`, `ids`, `permitted`).

# --- lock discipline ------------------------------------------------------------------------------
# Hold the family lock across <fn> <args...>, releasing it on EVERY return path the function takes and
# preserving its exit status. See the header: this is deliberately NOT a RETURN trap.
_mi_with_lock() {
  mi_lock_acquire || return 1
  local _rc=0
  "$@" || _rc=$?
  mi_lock_release
  return "$_rc"
}

# The preamble every non-install mutating verb runs INSIDE the lock: layout, probe cleanup, and the
# §6b.2 unaccounted-object gate that stops a verb before it touches anything.
_mi_verb_prepare() {
  mi_ensure_layout || return 1
  mi_probe_cleanup
  mi_unaccounted_gate || return 1
  return 0
}

_mi_verb_container() {   # <product> → the container name, or rc 1
  local ident
  ident="$(mi_ident_get)" || { mi_warn "verbs: no installation identity — has anything been installed?"; return 1; }
  mi_name_container "$ident" "$1"
}

# The core-fixed user-data mount points (§4.1a): ~/.mythical/transcripts and ~/.mythical/logs.
# mi_ensure_layout deliberately leaves these "to appear when a product binds them" — they are the
# user-data ownership class, not installer state — and binding them is exactly what a launch does. So
# they are created HERE, before mi_mount_check_fixed validates the core-fixed set (which is always all
# three, whatever the manifest selects) and before the runtime refuses a bind whose source is missing.
# Created if absent, never touched otherwise (D9); mkdir makes real directories, which is what the
# no-symlink / exact-canonical checks in mi_mount_check_fixed require.
_mi_ensure_mount_points() {
  local h; h="$(mi_home)" || return 1
  local d
  for d in transcripts logs; do
    [ -d "$h/$d" ] || mkdir -p "$h/$d" || { mi_warn "verbs: cannot create the '$d' mount point under ~/.mythical/"; return 1; }
  done
  return 0
}

# --- confirmation ---------------------------------------------------------------------------------
# A destructive family-scoped action asks first. MI_CONFIRM short-circuits it non-interactively —
# `yes` to proceed, `no` to refuse — so the family uninstall is testable without a tty; with neither
# set, the operator is prompted and anything but an explicit yes refuses.
mi_confirm() {
  local prompt="${1:-Proceed?}" reply
  case "${MI_CONFIRM:-}" in
    yes) return 0 ;;
    no)  return 1 ;;
  esac
  printf '%s [y/N] ' "$prompt" >&2
  if ! IFS= read -r reply; then return 1; fi
  case "$reply" in y|Y|yes|Yes|YES) return 0 ;; *) return 1 ;; esac
}

# --- product context ------------------------------------------------------------------------------
# Everything a verb needs about one product, derived once from the authenticated documents. Printed as
# ONE TAB-separated line of `key=value` fields, so a caller reads it with mi_led_field.
#
# rc 0 · 1 refused (reported) · 3 the manifest says NOT LAUNCHED (§7.3's contract code, carried
# straight through from Plan 3's mi_accept_manifest).
mi_product_ctx() {
  if [ "$#" -ne 4 ]; then mi_warn "verbs: mi_product_ctx needs <index> <policy> <manifest> <product>"; return 1; fi
  local idx="$1" pol="$2" man="$3" product="$4" mrec prec rc ident

  # ONE door (Plan 3): index vouches → digest verified → parse → product identity → freshness →
  # entitlements → min_core → launch state. Nothing here re-implements any of it.
  if mrec="$(mi_accept_manifest "$idx" "$pol" "$man" "$product")"; then rc=0; else rc=$?; fi
  # rc 3 still PRINTS the records — a caller reporting "not launched yet" legitimately wants them, and
  # the trust floor has already been recorded (§7.3's enumerated exempt side effects).
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then return "$rc"; fi
  prec="$(mi_accept_policy "$idx" "$pol")" || return 1
  ident="$(mi_ident_ensure)" || return 1

  # ONE TAB-SEPARATED LINE, because mi_led_field splits on TAB. Emitting one `key=value` per LINE and
  # then reading it with mi_led_field — which sets IFS to TAB — sees the whole blob as a single token
  # and matches nothing else, so every lookup returns absent and the caller proceeds on empty data.
  # The multi-line records blobs carry TABs of their own (they are `key<TAB>value` lines), so they are
  # folded: newline → RS (\036), tab → US (\037); the caller reverses both. Nothing carrying either
  # byte is ever written to the ledger — this record is in-process only.
  local launched=true
  [ "$rc" -ne 3 ] || launched=false
  printf 'product=%s' "$product"
  printf '\tlaunched=%s' "$launched"
  printf '\tcontainer=%s' "$(mi_name_container "$ident" "$product")"
  printf '\talias=%s' "$(mi_name_alias "$product")"
  printf '\timage=%s' "$(mi_manifest_image "$mrec")"
  printf '\tmanifest_records=%s' "$(printf '%s' "$mrec" | tr '\n\t' '\036\037')"
  printf '\tpolicy_records=%s\n' "$(printf '%s' "$prec" | tr '\n\t' '\036\037')"
  return "$rc"
}

# --- launch specs ---------------------------------------------------------------------------------
# The mount and publish specs for one product, from its manifest, the policy index and mythical.conf.
# D19's launch-argument invariant in practice: the ONLY sources are the authenticated manifest, the
# authenticated policy index, and mythical.conf — never <product>.conf.
#
# Operator BINDS are produced by lib/bringup.sh's mi_mount_binds, which maps each role to its
# authenticated container path, asks the bindability entitlement at the point the mount is produced,
# validates both spec components and applies the pairwise-overlap rule to the whole set. Every role it
# does NOT emit a bind for falls through here to a NAMED VOLUME (D6). Reusing that one owner is the
# whole point: a second implementation of the bind rule is one that drifts until the producer accepts
# what the consumer refuses.
mi_bringup_specs() {
  if [ "$#" -ne 3 ]; then mi_warn "verbs: mi_bringup_specs needs <product> <manifest-records> <policy-records>"; return 1; fi
  local product="$1" mrec="$2" prec="$3" ident up v role target vol port
  ident="$(mi_ident_get)" || return 1
  up="$(printf '%s' "$product" | tr 'a-z-' 'A-Z_')"

  # Volume roles the manifest declares.
  local -a vroles
  vroles=()
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    case "$v" in *:*) : ;; *) continue ;; esac
    vroles+=("${v%%:*}")
  done <<< "$(mi_doc_values "$mrec" volume)"

  # Operator binds for the bound roles — validated, entitled and pairwise-checked by the one owner.
  # CAPTURED AND CHECKED before the loop: `done <<< "$(mi_mount_binds …)"` takes the WHILE loop's
  # status, not the substitution's, so a REFUSED bind build (a bind inside the family home, a role the
  # policy index does not make bindable, two overlapping writable binds) would be silently swallowed.
  local bound_out=""
  if [ "${#vroles[@]}" -gt 0 ]; then
    bound_out="$(mi_mount_binds "$product" "$mrec" "$prec" "${vroles[@]}")" || return 1
  fi

  local -a specs
  specs=()
  # The set of roles that got a bind, and their specs. `role<TAB>bind=…` — role first, carried rather
  # than parsed back out of the spec (neither of a spec's path components is distinguishable from the
  # other once it is a string).
  local bound_roles="" line brole bspec
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    brole="${line%%$'\t'*}"; bspec="${line#*$'\t'}"
    bound_roles="${bound_roles}${brole}"$'\n'
    specs+=("$bspec")
  done <<< "$bound_out"

  # Every role with NO bind → a named volume at its authenticated container path.
  for role in ${vroles[@]+"${vroles[@]}"}; do
    case $'\n'"${bound_roles}" in *$'\n'"${role}"$'\n'*) continue ;; esac
    target="$(_mi_bringup_role_target "$mrec" "$role")" || return 1
    vol="$(mi_name_volume "$ident" "$product" "$role")" || return 1
    specs+=("volume=${vol}:${target}:rw")
  done

  # Core-fixed mounts (§4.1a): the closed allowlist, validated, never manifest-extended. The manifest
  # only SELECTS from it (`mount=transcripts`), and the policy index must permit the selection.
  mi_mount_check_fixed "$product" || return 1
  # The SAME canonical home the check validated — validate and launch against the same resolved path.
  local h; h="$(mi_home_canon)" || return 1
  specs+=("bind=${h}/${product}.conf:/etc/mythical/${product}.conf:rw")
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_policy_permits "$prec" "$product" mount "$v" || {
      mi_warn "verbs: '$product' selects the core-fixed mount '$v', which the policy index does not permit."
      return 1; }
    case "$v" in
      transcripts) specs+=("bind=${h}/transcripts:/home/mythical/transcripts:rw") ;;
      logs)        specs+=("bind=${h}/logs:/home/mythical/logs:rw") ;;
      *) mi_warn "verbs: '$v' is not a core-fixed mount"; return 1 ;;
    esac
  done <<< "$(mi_doc_values "$mrec" mount)"

  # Ports. The container port comes from the manifest; the HOST port from mythical.conf if set,
  # otherwise the same number. The 127.0.0.1 host IP is added by the adapter, not here.
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    # ONLY rc 3 (the key is absent) falls back to the manifest's port. Any other status means the file
    # did not parse or the value did not validate, and quietly publishing a different port than the
    # operator configured is the wrong answer to "I could not read your configuration".
    local prc
    if port="$(mi_conf_get "$(mi_conf_family_path)" "MYTHICAL_${up}_PORT")"; then prc=0; else prc=$?; fi
    if [ "$prc" -eq 3 ]; then port="$v"
    elif [ "$prc" -ne 0 ]; then
      mi_warn "verbs: could not read MYTHICAL_${up}_PORT from mythical.conf — refusing rather than"
      mi_warn "  silently publishing the manifest's default port instead of your configured one."
      return 1
    fi
    specs+=("publish=${port}:${v}")
  done <<< "$(mi_doc_values "$mrec" port)"

  printf '%s\n' "${specs[@]}"
}

# --- <product>.conf ------------------------------------------------------------------------------
# Create <product>.conf if absent; never modify it thereafter (§6's user-owned class). The gid comes
# from the AUTHENTICATED policy index (D60), used numerically — `chgrp <gid>` needs no /etc/group
# entry, so the installer creates no host groups and makes no machine change.
mi_conf_product_ensure() {
  if [ "$#" -ne 3 ]; then mi_warn "verbs: mi_conf_product_ensure needs <product> <gid> <manifest-records>"; return 1; fi
  local product="$1" gid="$2" f
  f="$(mi_conf_product_path "$product")" || return 1
  if [ -f "$f" ]; then
    # Additive only. There is nothing this verb adds today — the product's own UI writes its settings
    # (D3) — so an existing file is left byte-identical, which is what §10a's re-install case asserts.
    return 0
  fi
  # No KEY VALUE pairs: the file is created with the marker and the mode and NO settings, because the
  # product's own UI is what writes them (D3). Plan 2 owns the mechanism (its arity was relaxed to
  # permit a keyless create); this is the one call site that decides WHEN.
  #
  # rc 5 is Plan 2's "written, but not to D60's spec": the file exists and is correct, only the
  # shared-group chgrp did not take — the ordinary outcome for an unprivileged installer whose operator
  # is not in the family group. That is a REPORTED CONDITION, not an install failure: the product runs;
  # its settings screen is read-only until the group is fixed.
  local crc
  if mi_conf_product_add "$product" "$(printf '')" "$gid"; then crc=0; else crc=$?; fi
  case "$crc" in
    0) return 0 ;;
    5) mi_warn "verbs: ${product}.conf was created, but its group could not be set to ${gid}."
       mi_warn "  The file is mode 0600 and yours. The product's own settings screen will be"
       mi_warn "  READ-ONLY until the group is set (§4.5/D60). The install continues."
       return 0 ;;
    *) return "$crc" ;;
  esac
}

# --- install (desired state: running) -------------------------------------------------------------
mi_verb_install() {
  if [ "$#" -lt 4 ]; then mi_warn "verbs: install needs <index> <policy> <manifest> <product> [--image REF] [--force-install]"; return 2; fi
  local idx="$1" pol="$2" man="$3" product="$4"; shift 4
  local override="" forced=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --image) override="${2:-}"; shift 2 ;;
      --force-install) forced=1; shift ;;
      *) mi_warn "verbs: unknown install option '$1'"; return 2 ;;
    esac
  done
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_install_locked "$idx" "$pol" "$man" "$product" "$override" "$forced"
}

_mi_verb_install_locked() {
  local idx="$1" pol="$2" man="$3" product="$4" override="$5" forced="$6"

  mi_ensure_layout || return 1
  # if/else, not `mi_first_use; fu=$?` — a bare call would abort a `set -e` caller on rc 3, which is
  # the ORDINARY "this machine already has a ledger" answer.
  local fu
  if mi_first_use; then fu=0; else fu=$?; fi
  [ "$fu" -ne 1 ] || return 1
  mi_probe_cleanup

  local ctx rc mrec prec
  if ctx="$(mi_product_ctx "$idx" "$pol" "$man" "$product")"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then return 1; fi

  # §7.3's enumerated exempt side effects, and NOTHING else, on the not-launched path — the trust floor
  # for the manifest that was read has ALREADY been recorded by mi_accept_manifest, before the
  # launch-state branch, so a withdrawn `launched` manifest cannot be replayed later against a machine
  # that never established one.
  if [ "$rc" -eq 3 ]; then
    if [ "$forced" -eq 0 ]; then
      mi_log "$product has not launched yet."
      mi_log "  Its manifest declares it unpublished, so no pull was attempted and nothing was created."
      mi_log "  Nothing is wrong — this product is not available yet."
      return 3
    fi
    mi_warn "verbs: FORCED install of '$product', whose manifest says it has not launched."
    mi_warn "  You are asserting the image is published. This is recorded and reported by 'status'."
    mi_led_put forced key "${product}:force-install" "key=${product}:force-install" \
      "product=${product}" "kind=force-install" || return 1
  fi

  # Read then transform — a pipeline's status under `pipefail` is the LEFT side's, so `… | tr` would
  # abort on a missing field rather than report it.
  mrec="$(mi_led_field "$ctx" manifest_records)" || { mi_warn "verbs: context has no manifest records"; return 1; }
  mrec="$(printf '%s' "$mrec" | tr '\036\037' '\n\t')"
  prec="$(mi_led_field "$ctx" policy_records)"   || { mi_warn "verbs: context has no policy records"; return 1; }
  prec="$(printf '%s' "$prec" | tr '\036\037' '\n\t')"
  local container alias image
  container="$(mi_led_field "$ctx" container)" || return 1
  alias="$(mi_led_field "$ctx" alias)" || return 1
  image="$(mi_led_field "$ctx" image)" || return 1

  if [ -n "$override" ]; then
    # D22/§13: an override may name ANY reference, including a local build. Loud, recorded, reported.
    mi_warn "verbs: IMAGE OVERRIDE — '$product' will run '$override' instead of the manifest's image."
    mi_warn "  The manifest's digest pin does not apply to an overridden reference. Recorded, and"
    mi_warn "  reported by 'status'."
    image="$override"
    # Keyed by product AND kind: an install that is BOTH forced and image-overridden must record two
    # facts, and a shared key made the second silently replace the first.
    mi_led_put forced key "${product}:image-override" "key=${product}:image-override" \
      "product=${product}" "kind=image-override" "ref=${override}" || return 1
  fi

  mi_unaccounted_gate || return 1

  local netid
  netid="$(mi_net_target "$idx")" || return 1

  # The pull. EVERY failure is loud and distinguishable (§7.3) and exits 1 — never folded into the
  # pre-launch message, whatever status the runtime reports it as.
  if ! mi_rt_image_present "$image"; then
    local perr
    if ! perr="$(mi_rt_image_pull "$image" 2>&1)"; then
      mi_warn "verbs: the image for '$product' could not be pulled:"
      mi_warn "    $image"
      mi_warn "  The runtime said:"
      mi_warn "    $perr"
      mi_warn "  The manifest declares this product LAUNCHED, so this is a release or registry problem,"
      mi_warn "  not a pre-launch state. It is reported as a failure deliberately."
      return 1
    fi
  fi
  mi_prov_image_record "$image" "$product" || return 1

  # <product>.conf, created if absent, additive thereafter (§6/D9), 0660 with the policy index's
  # canonical family gid (D60/§4.5).
  local gid
  gid="$(mi_policy_family_gid "$prec")" || return 1
  mi_conf_product_ensure "$product" "$gid" "$mrec" || return 1

  # The core-fixed user-data mount points, before the mount check validates them.
  _mi_ensure_mount_points || return 1

  # Named volumes for every role with no bind, under write-ahead intent.
  local v role vol nonce
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    role="${v%%:*}"
    vol="$(mi_name_volume "$(mi_ident_get)" "$product" "$role")" || return 1
    if mi_prov_find volume "$vol" >/dev/null 2>&1; then continue
    elif mi_intent_find volume "$vol" >/dev/null 2>&1; then mi_intent_reconcile volume "$vol" || return 1
    else
      nonce="$(mi_nonce_new)" || return 1
      mi_intent_open volume "$vol" "$nonce" "product=${product}" "role=${role}" || return 1
      mi_rt_volume_create "$vol" "$nonce" "$(mi_ident_get)" >/dev/null || return 1
      # RE-INSPECT: `volume create` against an existing name succeeds WITHOUT applying the labels.
      local an
      an="$(mi_rt_inspect volume v.nonce "$vol" 2>/dev/null || true)"
      if [ "$an" != "$nonce" ]; then
        mi_warn "verbs: volume '$vol' already existed and does not carry our nonce. Not adopted, not"
        mi_warn "  removed. The intent is retained."
        return 1
      fi
      mi_intent_confirm volume "$vol" "$nonce" "product=${product}" "role=${role}" || return 1
    fi
  done <<< "$(mi_doc_values "$mrec" volume)"

  # CAPTURE AND CHECK FIRST. `done <<< "$(mi_bringup_specs …)"` takes the WHILE loop's status, not the
  # substitution's — so a REFUSED spec build produced an empty list and the install carried on having
  # skipped §4.1a entirely. Read line by line so no bind path is word-split or glob-expanded.
  local -a specs
  local envfile="" _line _specs
  _specs="$(mi_bringup_specs "$product" "$mrec" "$prec")" || return 1
  specs=()
  while IFS= read -r _line; do
    [ -n "$_line" ] || continue
    specs+=("$_line")
  done <<< "$_specs"
  # Always non-empty from here (the label is unconditional), so "${specs[@]}" below is safe even
  # though bash 3.2 errors on an empty array under `set -u`.
  specs+=("label=product=${product}")

  # Bootstrap secrets, per-key, from the policy index's grant — never the whole file.
  local -a wanted
  wanted=()
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    mi_policy_permits "$prec" "$product" secret "$v" || {
      mi_warn "verbs: '$product' asks for secret '$v', which the policy index does not grant it."; return 1; }
    wanted+=("$v")
  done <<< "$(mi_doc_values "$mrec" secret)"
  if [ "${#wanted[@]}" -gt 0 ]; then
    envfile="$(mi_secrets_envfile "$product" "${wanted[@]}")" || return 1
  else
    envfile="-"
  fi

  # A previously-installed container is replaced, preserving desired state; a fresh one is `running`.
  local desired=running arc
  if mi_prov_find container "$container" >/dev/null 2>&1; then
    # §6a applies to a REPLACEMENT exactly as it applies to an uninstall: prove the container carries
    # the nonce we recorded before removing it. "We are about to replace it" is not an exemption.
    if mi_prov_authority container "$container"; then arc=0; else arc=$?; fi
    case "$arc" in
      0) mi_rt_container_stop "$container" >/dev/null 2>&1 || true
         mi_rt_container_rm "$container" >/dev/null 2>&1 || true ;;
      3) : ;;                       # already gone: nothing to remove, nothing to fear
      *) # A 0600 file of bootstrap secrets must not outlive the run on ANY path — including refusals.
         [ "$envfile" = "-" ] || rm -f "$envfile"
         mi_warn "verbs: refusing to replace '$container' (see above). It is preserved, and this"
         mi_warn "  install stops rather than creating a second container under the same name."
         return 1 ;;
    esac
    desired=preserve
  fi

  # if/else, NOT `mi_bringup …; rc=$?`: a bare call is a simple command, so a failed bring-up aborts a
  # `set -e` caller before the cleanup below — leaking a 0600 file of bootstrap secrets on exactly the
  # path most likely to be hit.
  if mi_bringup "$idx" "$container" "$image" "$netid" "$alias" "$desired" "$envfile" "${specs[@]}"; then
    rc=0
  else
    rc=$?
  fi
  # The env file is removed on EVERY path, including failure — a 0600 file of bootstrap secrets must not
  # outlive the run that needed it.
  [ "$envfile" = "-" ] || rm -f "$envfile"
  [ "$rc" -eq 0 ] || return 1

  mi_member_add "$product" || return 1
  mi_log "$product: installed and running."
  return 0
}

# --- start (desired state: running) ---------------------------------------------------------------
# Intent → set the entry → start → verify live → clear. The `start verify` reconciliation records a
# resume attempt (mi_state_resume_record) before the start, inside mi_bringup_reconcile.
mi_verb_start() {
  if [ "$#" -ne 2 ]; then mi_warn "verbs: start needs <index> <product>"; return 2; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_start_locked "$1" "$2"
}
_mi_verb_start_locked() {
  local idx="$1" product="$2" c netid alias
  _mi_verb_prepare || return 1
  c="$(_mi_verb_container "$product")" || return 1
  mi_prov_find container "$c" >/dev/null 2>&1 || { mi_warn "verbs: '$product' is not installed"; return 1; }
  netid="$(mi_net_target "$idx")" || return 1
  alias="$(mi_name_alias "$product")" || return 1
  # ONE atomic write: desired=running AND the outstanding alias check it owes. Splitting them leaves a
  # window where a crash produces a container recovery starts and then considers fully reconciled (D50).
  mi_state_commit "$c" running alias "$netid" || return 1
  mi_bringup_reconcile "$idx" "$c" "$netid" "$alias"
}

# --- stop (desired state: stopped) ----------------------------------------------------------------
# Intent FIRST, then act — the ordering is the whole point (D43). mi_state_commit records desired
# state and PRESERVES the outstanding set (there is no mi_state_desired_set); a `stopped` intent owes
# no live verification, so it declares none structurally.
mi_verb_stop() {
  if [ "$#" -ne 1 ]; then mi_warn "verbs: stop needs <product>"; return 2; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_stop_locked "$1"
}
_mi_verb_stop_locked() {
  local product="$1" c
  _mi_verb_prepare || return 1
  c="$(_mi_verb_container "$product")" || return 1
  mi_prov_find container "$c" >/dev/null 2>&1 || { mi_warn "verbs: '$product' is not installed"; return 1; }
  mi_state_commit "$c" stopped || return 1
  # No live check: nothing is running to verify.
  mi_rt_container_stop "$c" >/dev/null 2>&1 || true
  mi_log "$product: stopped."
  return 0
}

# --- restart (desired state: PRESERVED; refused on a stopped product) -----------------------------
mi_verb_restart() {
  if [ "$#" -ne 2 ]; then mi_warn "verbs: restart needs <index> <product>"; return 2; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_restart_locked "$1" "$2"
}
_mi_verb_restart_locked() {
  local idx="$1" product="$2" c want netid alias
  _mi_verb_prepare || return 1
  c="$(_mi_verb_container "$product")" || return 1
  want="$(mi_state_desired_get "$c")" || { mi_warn "verbs: '$product' is not installed"; return 1; }
  if [ "$want" = stopped ]; then
    mi_warn "verbs: '$product' is stopped, so there is nothing to restart."
    mi_warn "  Refusing rather than starting it: 'restart' preserves what you asked for, and you asked"
    mi_warn "  for it to be stopped. Use 'start' if you want it running."
    return 1
  fi
  netid="$(mi_net_target "$idx")" || return 1
  alias="$(mi_name_alias "$product")" || return 1
  mi_state_commit "$c" running alias "$netid" || return 1
  mi_rt_container_stop "$c" >/dev/null 2>&1 || true
  mi_bringup_reconcile "$idx" "$c" "$netid" "$alias"
}

# --- recreate (desired state: PRESERVED) ----------------------------------------------------------
# Same path as install's replacement branch, without touching membership, config or volumes. A
# recreate of a stopped product leaves it stopped; it live-verifies like a fresh install.
mi_verb_recreate() {
  if [ "$#" -ne 4 ]; then mi_warn "verbs: recreate needs <index> <policy> <manifest> <product>"; return 2; fi
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_recreate_locked "$1" "$2" "$3" "$4"
}
_mi_verb_recreate_locked() {
  local idx="$1" pol="$2" man="$3" product="$4" ctx rc c
  _mi_verb_prepare || return 1
  c="$(_mi_verb_container "$product")" || return 1
  mi_state_desired_get "$c" >/dev/null || { mi_warn "verbs: '$product' is not installed"; return 1; }

  if ctx="$(mi_product_ctx "$idx" "$pol" "$man" "$product")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  # `mi_led_field … | tr` under a `pipefail` caller carries the LEFT side's status, so a missing field
  # aborts instead of being reported. Read the field, then transform it.
  local mrec prec netid alias image envfile
  mrec="$(mi_led_field "$ctx" manifest_records)" || { mi_warn "verbs: context has no manifest records"; return 1; }
  mrec="$(printf '%s' "$mrec" | tr '\036\037' '\n\t')"
  prec="$(mi_led_field "$ctx" policy_records)"   || { mi_warn "verbs: context has no policy records"; return 1; }
  prec="$(printf '%s' "$prec" | tr '\036\037' '\n\t')"
  image="$(mi_led_field "$ctx" image)" || { mi_warn "verbs: context names no image"; return 1; }
  alias="$(mi_led_field "$ctx" alias)" || { mi_warn "verbs: context names no alias"; return 1; }
  netid="$(mi_net_target "$idx")" || return 1
  # The core-fixed user-data mount points, before the mount check validates them (a recreate after a
  # manual deletion of transcripts/ or logs/ must re-create them rather than refuse).
  _mi_ensure_mount_points || return 1

  # Captured and CHECKED first — see mi_verb_install.
  local -a specs; specs=()
  local _line _specs
  _specs="$(mi_bringup_specs "$product" "$mrec" "$prec")" || return 1
  while IFS= read -r _line; do
    [ -n "$_line" ] || continue
    specs+=("$_line")
  done <<< "$_specs"
  specs+=("label=product=${product}")
  local -a wanted; wanted=()
  local v
  while IFS= read -r v; do [ -n "$v" ] && wanted+=("$v"); done <<< "$(mi_doc_values "$mrec" secret)"
  if [ "${#wanted[@]}" -gt 0 ]; then envfile="$(mi_secrets_envfile "$product" "${wanted[@]}")" || return 1
  else envfile="-"; fi

  # §6a: prove it is ours before removing it, on this path too.
  local arc
  if mi_prov_authority container "$c"; then arc=0; else arc=$?; fi
  case "$arc" in
    0) mi_rt_container_stop "$c" >/dev/null 2>&1 || true
       mi_rt_container_rm "$c" >/dev/null 2>&1 || true ;;
    3) : ;;
    *) [ "$envfile" = "-" ] || rm -f "$envfile"
       mi_warn "verbs: refusing to recreate '$c' (see above) — it is preserved."
       return 1 ;;
  esac
  # if/else — see mi_verb_install: a bare call would abort before the secret env file is removed.
  if mi_bringup "$idx" "$c" "$image" "$netid" "$alias" preserve "$envfile" "${specs[@]}"; then rc=0; else rc=$?; fi
  [ "$envfile" = "-" ] || rm -f "$envfile"
  return "$rc"
}

# --- product uninstall ----------------------------------------------------------------------------
# Removes the CONTAINER; RETAINS volumes, membership and the trust floor (§6c).
#
# UNINSTALLING A PRODUCT MUST NOT CLEAR ITS ANTI-ROLLBACK FLOOR. If it did, `uninstall` then `install`
# would be a supported one-command rollback bypass: drop the floor, replay a withdrawn manifest, recover
# the vulnerable image. The floor outlives the install that established it and a reinstall inherits it.
mi_verb_uninstall() {
  if [ "$#" -lt 1 ]; then mi_warn "verbs: uninstall needs <product> [--purge]"; return 2; fi
  local product="$1"; shift
  local purge=0
  while [ "$#" -gt 0 ]; do
    case "$1" in --purge) purge=1; shift ;; *) mi_warn "verbs: unknown uninstall option '$1'"; return 2 ;; esac
  done
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_uninstall_locked "$product" "$purge"
}
_mi_verb_uninstall_locked() {
  local product="$1" purge="$2"
  _mi_verb_prepare || return 1

  local c rc=0
  c="$(_mi_verb_container "$product")" || return 1
  if mi_prov_authority container "$c"; then rc=0; else rc=$?; fi
  case "$rc" in
    0) mi_rt_container_stop "$c" >/dev/null 2>&1 || true
       # Tombstone ONLY on a removal that actually succeeded. Recording a removal that did not happen
       # strips the container's authority record while it is still running.
       if mi_rt_container_rm "$c" >/dev/null 2>&1; then
         mi_prov_tombstone container "$c" || return 1
         mi_state_forget "$c" || return 1
       else
         mi_warn "verbs: could not remove the container for '$product'. Its record is KEPT so it stays"
         mi_warn "  removable later; nothing is tombstoned for a removal that did not happen."
         rc=1
       fi ;;
    3) mi_prov_tombstone container "$c" || return 1
       mi_state_forget "$c" || return 1 ;;
    *) mi_warn "verbs: the container for '$product' is preserved (see above). Continuing with the rest."
       rc=1 ;;
  esac

  local rec name role
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class volume || continue
    _mi_led_record_matches "$rec" product "$product" || continue
    name="$(mi_led_field "$rec" name)" || continue
    role="$(mi_led_field "$rec" role)" || role="?"
    if [ "$purge" -eq 0 ]; then
      mi_log "  keeping volume $name (role $role) — your data. 'uninstall --purge' removes it."
      continue
    fi
    # rc 3 is "already gone": nothing to remove and nothing to preserve, so the record is tombstoned.
    # Only a real refusal (rc 1 — no record, or a nonce that does not match) preserves.
    local varc
    if mi_prov_authority volume "$name"; then varc=0; else varc=$?; fi
    if [ "$varc" -eq 0 ]; then
      if mi_rt_volume_rm "$name" >/dev/null 2>&1; then
        mi_prov_tombstone volume "$name" || return 1
        mi_log "  removed volume $name (role $role)."
      else
        mi_warn "  could NOT remove volume $name — its record is kept, so it stays removable later."
        rc=1
      fi
    elif [ "$varc" -eq 3 ]; then
      mi_prov_tombstone volume "$name" || return 1
      mi_log "  volume $name was already gone; its record is tombstoned."
    else
      mi_log "  PRESERVED volume $name — see the reason above."
      rc=1
    fi
  done <<< "$(mi_led_all object)"

  # IMAGES ARE NEVER REMOVED AUTOMATICALLY (D37) — not by uninstall, not by --purge. `--purge` may only
  # OFFER it, naming the digests and stating plainly that they may be in use elsewhere.
  if [ "$purge" -eq 1 ]; then
    local imgs="" iref
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      _mi_led_record_matches "$rec" product "$product" || continue
      iref="$(mi_led_field "$rec" ref)" || continue
      imgs="${imgs}    ${iref}"$'\n'
    done <<< "$(mi_led_all image)"
    if [ -n "$imgs" ]; then
      mi_log "  Images acquired for $product are NOT removed:"
      printf '%s' "$imgs"
      mi_log "  They may be in use by another installation on this daemon, or by your own local work —"
      mi_log "  the ledger records that this installer PULLED them, which is not the same as owning them."
      mi_log "  To reclaim the space yourself: docker image rm <digest>   (or: docker image prune)"
    fi
  fi

  [ "$rc" -eq 0 ] || return 1
  # RETAINED, deliberately: membership and the trust floor. Do not add a mi_member_del here.
  mi_log "$product: uninstalled. Its rollback floor and initialization record are retained, so a"
  mi_log "  reinstall cannot replay a withdrawn manifest."
  return 0
}

# --- family uninstall (§6c) -----------------------------------------------------------------------
# Deliberately resets everything: afterwards the machine is genuinely indistinguishable from a fresh
# one — acceptable precisely because it is an explicit operator action rather than a remote input.
#
# This is the ONLY caller of mi_rt_network_rm, and the only path that removes identity, membership,
# trust floors and the family-index anchor. A PRODUCT uninstall removes none of them (the
# rollback-bypass row), so the two verbs do not share an implementation.
#
# USER DATA IS STILL NOT TOUCHED. transcripts/, logs/ and host binds are the user-data ownership class
# (§6). Named volumes go only with --purge, under the same authority check as a product uninstall.
mi_verb_uninstall_family() {
  local purge=0
  while [ "$#" -gt 0 ]; do
    case "$1" in --purge) purge=1; shift ;; *) mi_warn "verbs: unknown option '$1'"; return 2 ;; esac
  done
  mi_preflight_daemon || return 1
  _mi_with_lock _mi_verb_uninstall_family_locked "$purge"
}
_mi_verb_uninstall_family_locked() {
  local purge="$1"
  _mi_verb_prepare || return 1

  local ident
  ident="$(mi_ident_get)" || { mi_warn "verbs: there is no installation to uninstall."; return 1; }
  mi_warn "verbs: FAMILY UNINSTALL of installation '$ident'."
  mi_warn "  Every product's container is removed, and the ledger is reset ENTIRELY: the installation"
  mi_warn "  identity, the initialized-product set, every anti-rollback trust floor, and the"
  mi_warn "  family-index anchor. Afterwards this machine is indistinguishable from a fresh one."
  if [ "$purge" -eq 1 ]; then
    mi_warn "  --purge: this installation's named volumes are removed too. THAT IS YOUR DATA."
  else
    mi_warn "  Named volumes are KEPT (your data). 'uninstall --family --purge' removes them."
  fi
  mi_warn "  transcripts/, logs/ and any host binds are never touched by any verb."
  mi_confirm "verbs: uninstall the whole family?" || { mi_warn "verbs: not confirmed."; return 1; }

  # Containers first, then volumes, then the network — a network cannot be removed while a container is
  # attached. `preserved` is what stops the ledger reset at the end: wiping the ledger while an object
  # it describes is still there would strip that object's provenance, making it permanently
  # unauthorized for deletion and an unrecorded same-identity object that stops every later operation.
  local rec name arc preserved=0 retained=0
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class container || continue
    name="$(mi_led_field "$rec" name)" || continue
    if mi_prov_authority container "$name"; then arc=0; else arc=$?; fi
    if [ "$arc" -eq 0 ]; then
      mi_rt_container_stop "$name" >/dev/null 2>&1 || true
      # A removal that FAILED must not be followed by forgetting its state: that would leave the
      # container running with nothing recording it.
      if mi_rt_container_rm "$name" >/dev/null 2>&1; then
        mi_log "  removed container $name."
        mi_state_forget "$name" || return 1
      else
        mi_warn "  could NOT remove container $name — it is left alone and its record is kept."
        preserved=1
      fi
    elif [ "$arc" -eq 3 ]; then
      mi_state_forget "$name" || return 1      # already gone: nothing to preserve
    else
      mi_log "  PRESERVED container $name — see the reason above. Its record is kept."
      preserved=1
    fi
  done <<< "$(mi_led_all object)"

  if [ "$purge" -eq 0 ]; then
    # Volumes are RETAINED without --purge — so their provenance must be too, and that means the ledger
    # cannot be reset. This is the same consequence as a preservation, reached by the INTENDED path
    # rather than a refusal.
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      if _mi_led_record_matches "$rec" class volume; then retained=1; break; fi
    done <<< "$(mi_led_all object)"
  else
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      _mi_led_record_matches "$rec" class volume || continue
      name="$(mi_led_field "$rec" name)" || continue
      local varc
      if mi_prov_authority volume "$name"; then varc=0; else varc=$?; fi
      if [ "$varc" -eq 0 ]; then
        if mi_rt_volume_rm "$name" >/dev/null 2>&1; then
          mi_log "  removed volume $name."
        else
          mi_warn "  could NOT remove volume $name — its record is kept."
          preserved=1
        fi
      elif [ "$varc" -eq 3 ]; then
        :                                        # already gone: nothing to remove, nothing to preserve
      else
        mi_log "  PRESERVED volume $name — see the reason above. Its record is kept."
        preserved=1
      fi
    done <<< "$(mi_led_all object)"
  fi

  # The network, and ONLY if this installer created it. A non-owned reference (D41) is attach-only and
  # carries no deletion authority — it is the operator's network and is left alone. mi_prov_authority
  # cannot see a netref record, so no path can read it as something to remove.
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class network || continue
    name="$(mi_led_field "$rec" name)" || continue
    local narc
    if mi_prov_authority network "$name"; then narc=0; else narc=$?; fi
    if [ "$narc" -eq 0 ]; then
      if mi_rt_network_rm "$name" >/dev/null 2>&1; then
        mi_log "  removed network $name."
      else
        mi_warn "  could NOT remove network $name — its record is kept."
        preserved=1
      fi
    elif [ "$narc" -eq 3 ]; then
      :                                          # already gone
    else
      mi_log "  PRESERVED network $name — see the reason above. Its record is kept."
      preserved=1
    fi
  done <<< "$(mi_led_all object)"
  if mi_net_ref_get >/dev/null 2>&1; then
    mi_log "  the operator-supplied network is LEFT ALONE — it was never this installer's to remove."
  fi

  # IMAGES ARE STILL NEVER REMOVED (D37). Family uninstall is not an exemption: the ledger proves
  # acquisition, not ownership, and another installation on this daemon may depend on the same digest.
  local iref imgs=""
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    iref="$(mi_led_field "$rec" ref)" || continue
    imgs="${imgs}    ${iref}"$'\n'
  done <<< "$(mi_led_all image)"
  if [ -n "$imgs" ]; then
    mi_log "  Images are NOT removed, by this verb or any other:"
    printf '%s' "$imgs"
    mi_log "  Reclaim the space yourself with: docker image prune"
  fi

  # Reset the ledger LAST, and ONLY if nothing was preserved.
  if [ "$preserved" -eq 1 ]; then
    mi_warn "family: some objects could not be removed (see above), so the ledger is NOT reset — it is"
    mi_warn "  the only record of what they are. Resolve them, then re-run."
    return 1
  fi
  if [ "$retained" -eq 1 ]; then
    mi_log "family: containers and the network are gone. The ledger is KEPT because your named volumes"
    mi_log "  are still here and it is the only record of what they are — without it they could never"
    mi_log "  be removed by this installer again."
    mi_log "  'uninstall --family --purge' removes them and then resets the ledger."
    return 0
  fi
  printf '' | mi_ledger_write || return 1
  mi_log "family: uninstalled. ~/.mythical/ still holds your transcripts, logs and config files;"
  mi_log "  remove the directory by hand if you want them gone too."
  return 0
}

# --- status (READ-ONLY, exits 0 even with bad news) ----------------------------------------------
# An operator running it in a loop must not have their fleet mutated by the act of looking, and a
# monitoring wrapper needs it to succeed in order to read its output (the plan's Decisions item 9).
# It takes NO lock — it mutates nothing — and it must never be gated by its own findings.
mi_verb_status() {
  if [ "$#" -lt 1 ]; then mi_warn "verbs: status needs <index> [product...]"; return 2; fi
  local idx="$1"; shift
  local ident rec c product

  if ! ident="$(mi_ident_get)"; then
    mi_log "No installation state found. Nothing has been installed yet."
    return 0
  fi
  mi_log "installation: $ident"

  local nref
  if nref="$(mi_net_ref_get)"; then
    mi_log "network:      $nref (operator-supplied, attach-only — this installer will never remove it)"
  else
    local nname
    nname="$(mi_name_network "$ident")"
    if rec="$(mi_prov_find network "$nname")"; then
      mi_log "network:      $(mi_led_field "$rec" id) ($nname, created by this installer)"
    else
      mi_log "network:      not created yet"
    fi
  fi

  local mig
  if mig="$(mi_led_find netmig key family 2>/dev/null)"; then
    mi_log "NETWORK MIGRATION IN PROGRESS — phase $(mi_led_field "$mig" phase)"
    mi_log "  source $(mi_led_field "$mig" source) → target $(mi_led_field "$mig" target)"
    mi_log "  Containers are on both networks; family DNS resolves on either. Resume with 'net rebind'."
  fi

  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    _mi_led_record_matches "$rec" class container || continue
    c="$(mi_led_field "$rec" name)" || continue
    # The container's provenance record does not carry the product — bring-up opens its write-ahead
    # intent before the product name is in scope, so the confirmation writes no `product` field. Derive
    # it from the installation-scoped container name (mythical-<ident>-<product>), which is the same
    # value the product filter and the forced-record lookup below key on.
    if product="$(mi_led_field "$rec" product)"; then :; else product=""; fi
    [ -n "$product" ] || product="${c#"${MI_NAME_PREFIX}"-"${ident}"-}"
    if [ "$#" -gt 0 ]; then
      local match=0 p
      for p in "$@"; do [ "$p" = "$product" ] && match=1; done
      [ "$match" -eq 1 ] || continue
    fi
    local desired observed out plan
    desired="$(mi_state_desired_get "$c" 2>/dev/null || printf '(none)')"
    observed="$(mi_state_observed "$c" 2>/dev/null || printf '(unknown)')"
    # `|| true`: under `pipefail` this assignment carries mi_state_outstanding's status, and status is
    # documented to be read-only and always succeed. A diagnostic that aborts is not a diagnostic.
    out="$(mi_state_outstanding "$c" 2>/dev/null | cut -f1 | tr '\n' ',' || true)"
    plan="$(mi_state_plan "$c" 2>/dev/null || printf '?')"
    mi_log "$product: desired=$desired observed=$observed outstanding=${out:-none} next=$plan"
    local fr
    while IFS= read -r fr; do
      [ -n "$fr" ] || continue
      _mi_led_record_matches "$fr" product "$product" || continue
      case "$(mi_led_field "$fr" kind)" in
        image-override) mi_log "  image override in effect — running $(mi_led_field "$fr" ref) instead of the manifest's pinned image" ;;
        force-install)  mi_log "  installed with --force-install (the manifest said not launched)" ;;
      esac
    done <<< "$(mi_led_all forced)"
  done <<< "$(mi_led_all object)"

  # Live intents, so a wedge is visible rather than mysterious.
  local irec
  while IFS= read -r irec; do
    [ -n "$irec" ] || continue
    mi_log "PENDING: $(mi_led_field "$irec" class) $(mi_led_field "$irec" name) — created and not yet confirmed"
  done <<< "$(mi_intent_all)"

  # §6b.1/§6b.2's unattributed and unrecorded classes, reported, never actioned.
  local ln cls kind name
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    cls="${ln%%$'\t'*}"
    kind="$(printf '%s' "$ln" | cut -f2)"; name="$(printf '%s' "$ln" | cut -f3)"
    case "$cls" in
      unattributed)
        mi_log "unattributed $kind: $name"
        mi_log "  Carries a mythicalOS installation label that is not this installation's. It may belong"
        mi_log "  to another user on this daemon. Diagnostic only." ;;
      unrecorded)
        mi_log "unrecorded $kind: $name"
        mi_log "  Labelled for THIS installation but absent from the ledger. Mutating operations will"
        mi_log "  stop until this is resolved — run 'state repair'." ;;
      colliding)
        mi_log "name collision, $kind: $name (unlabelled, holds a name this installer would create)" ;;
    esac
  done <<< "$(mi_unaccounted_scan)"
  return 0
}

# --- the batch driver (§7.3) ----------------------------------------------------------------------
# Per-product reporting, CONTINUE PAST A FAILURE, worst-wins aggregate.
mi_verb_batch() {
  if [ "$#" -lt 5 ]; then mi_warn "verbs: mi_verb_batch needs <verb> <index> <policy> <manifest-dir> <product>..."; return 2; fi
  local verb="$1" idx="$2" pol="$3" mdir="$4"; shift 4
  local p rc
  local -a codes
  codes=()
  for p in "$@"; do
    # EVERY capture is an if/else. `verb …; rc=$?` is a simple command, so under a `set -e` caller the
    # FIRST product that fails exits the CLI — and this function's entire reason to exist ("failing one
    # product must not abort the others", §7.3) would be unreachable code.
    case "$verb" in
      install)  if mi_verb_install  "$idx" "$pol" "${mdir}/${p}.manifest" "$p"; then rc=0; else rc=$?; fi ;;
      recreate) if mi_verb_recreate "$idx" "$pol" "${mdir}/${p}.manifest" "$p"; then rc=0; else rc=$?; fi ;;
      start)    if mi_verb_start    "$idx" "$p"; then rc=0; else rc=$?; fi ;;
      stop)     if mi_verb_stop     "$p"; then rc=0; else rc=$?; fi ;;
      restart)  if mi_verb_restart  "$idx" "$p"; then rc=0; else rc=$?; fi ;;
      *) mi_warn "verbs: '$verb' is not a batchable verb"; return 2 ;;
    esac
    # A usage error from ONE product is that product's operational failure from the batch's point of
    # view: the batch itself was invoked correctly. Mapping it to 1 keeps mi_ex_worst's contract (usage
    # is never a batch outcome) without losing the failure.
    [ "$rc" -eq 2 ] && rc=1
    mi_log "$p: $(mi_ex_name "$rc")"
    codes+=("$rc")
  done
  local agg
  agg="$(mi_ex_worst "${codes[@]}")" || return 1
  return "$agg"
}
