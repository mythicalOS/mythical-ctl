#!/usr/bin/env bash
# Per-product manifests (D8/D21/D22, §8) and the core's name derivation (D32).
#
# A manifest declares ROLES; the core derives NAMES. The manifest says "I have a state volume
# mounted at /data", never "mythical-brokkr-state" — so a manifest has no vocabulary in which to
# name a sibling's resources: the colliding role would have to be granted by the authenticated
# policy and the colliding product vouched for by the authenticated index, so THIS guarantee holds
# unconditionally from this module alone. The STRONGER claim — that two installations on one daemon
# cannot collide — is conditional on a hyphen discipline in the installation identity that this
# module does not state or enforce; see "NOT INJECTIVE" at the naming functions below. This is why
# the grammar below has no key for a volume name, a network name, or a config path: absence is the
# enforcement.
#
# PURE library — no side effects at source time; no `set -euo pipefail`.

MI_NAME_PREFIX=mythical

mi_manifest_spec() {
  printf 'version\tdocver\tone\n'
  printf 'expires\tepoch\tone\n'
  printf 'product\tident\tone\n'
  # §7.3: launch state is DECLARED, not inferred, and is required — inferring it from a registry
  # 404 turns a broken publication into a reassuring "not launched yet" notice.
  printf 'launched\tbool\tone\n'
  printf 'image\tdigestref\tone\n'
  printf 'volume\trolemount\tmany\n'
  printf 'secret\tstr:128\tmany\n'
  printf 'mount\tident\tmany\n'
  printf 'port\tint:1:65535\tmany\n'
  printf 'probe\tstr:256\topt\n'
  # §8: every manifest declares the minimum core it needs. REQUIRED — a manifest that does not say
  # cannot be checked, and "unstated" would silently mean "any core will do", which is the one
  # answer that is never safe.
  printf 'min_core\tcoreversion\tone\n'
  # Deliberately ABSENT, and their absence is the enforcement (§8.1):
  #   bindable_role  — bindability comes from the policy index, never from the product (D53)
  #   network        — joining a network is the cross-product reach D21 exists to prevent
  #   volume_name    — the core derives names; a manifest may only select from what its identity
  #                    already scopes
  # Each falls out of the allowlist as an unknown key, which is louder than ignoring it: a product
  # shipping one learns immediately instead of shipping a silently dead field.
}

# rc 0 · 1 rejected (reported) · 3 file missing (mi_doc_scan's contract, carried through unchanged).
#
# rc 3 IS OVERLOADED IN THIS MODULE. mi_manifest_launched (below) and the door (mi_accept_manifest)
# both also use rc 3, for an entirely different meaning: "authentic, but launched=false". Neither of
# those call sites is confused — each only ever sees a 3 from the meaning it defines, since the door
# never lets a missing-file 3 from this function reach a caller (mi_accept_manifest returns 1 first,
# from the snapshot step, on anything it cannot read). The risk is a FUTURE caller that forwards this
# function's own status code outward: it would report "not launched" for what was actually a missing
# file. Keep the two meanings at their own call sites; do not let one flow through as the other's.
mi_manifest_load() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then mi_warn "manifest: mi_manifest_load needs a <file> and an optional <label>"; return 1; fi
  mi_doc_load "$1" manifest "$(mi_manifest_spec)" "${2:-$1}"
}

mi_manifest_image() {
  if [ "$#" -ne 1 ]; then mi_warn "manifest: mi_manifest_image needs <records>"; return 1; fi
  mi_doc_value "$1" image
}

# rc 0 launched · 3 NOT launched · 1 unreadable.
#
# Rc 3 is §7.3's contract code, carried from here so a caller cannot accidentally map "not launched"
# onto 0 (a script would read that as "installed and running") or onto 1 (indistinguishable from a
# registry outage). NOTE THE REUSE: mi_manifest_load's own rc 3 means something else entirely ("file
# missing", from mi_doc_scan) — the two never collide at a single call site today, but a caller that
# forwards mi_manifest_load's status onward and reads a 3 from it as "not launched" would be wrong.
mi_manifest_launched() {
  if [ "$#" -ne 1 ]; then mi_warn "manifest: mi_manifest_launched needs <records>"; return 1; fi
  local v
  v="$(mi_doc_value "$1" launched)" || { mi_warn "manifest: no launch state declared"; return 1; }
  case "$v" in
    true)  return 0 ;;
    false) return 3 ;;
    *) mi_warn "manifest: launch state '$v' is not true or false"; return 1 ;;
  esac
}

# Enforce entitlements: every role, secret and mount the manifest selects must already be granted to
# that product by the policy index. rc 0 entitled · 1 violation (each reported).
#
# ALL violations are reported, not just the first: a product author fixing one at a time learns the
# next only after another release cycle.
mi_manifest_check() {
  if [ "$#" -ne 2 ]; then mi_warn "manifest: mi_manifest_check needs <manifest-records> and <policy-records>"; return 1; fi
  local m="$1" pol="$2" product rc=0 v role
  product="$(mi_doc_value "$m" product)" || { mi_warn "manifest: no product declared"; return 1; }

  while IFS= read -r v; do
    [ -n "$v" ] || continue
    role="${v%%:*}"
    if ! mi_policy_permits "$pol" "$product" role "$role"; then
      mi_warn "manifest: $product is not entitled to the volume role '$role'"
      rc=1
    fi
  done <<< "$(mi_doc_values "$m" volume)"

  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if ! mi_policy_permits "$pol" "$product" secret "$v"; then
      mi_warn "manifest: $product is not entitled to the bootstrap secret '$v'"
      rc=1
    fi
  done <<< "$(mi_doc_values "$m" secret)"

  while IFS= read -r v; do
    [ -n "$v" ] || continue
    if ! mi_policy_permits "$pol" "$product" mount "$v"; then
      mi_warn "manifest: $product is not entitled to the fixed mount '$v'"
      rc=1
    fi
  done <<< "$(mi_doc_values "$m" mount)"

  return "$rc"
}

# THE SINGLE DOOR. Accept a manifest for an EXPECTED product, or refuse.
#
# Every other function in this plan is a step; this is the only composition of them, and it exists
# because a chain nobody is forced to walk is not a boundary. mi_manifest_load on its own will parse
# any file you hand it — that is correct for a parser and catastrophic as an acceptance policy, so
# the acceptance policy is here, in one place, in this order:
#
#   1. the family index (ixf) must itself be authenticated against the trust anchor
#      (mi_accept_index) — nothing below is meaningful against an index that was merely parsed
#   2. the policy index (polf) must be authenticated against THAT SAME family index
#      (mi_accept_policy) — a digest is not authentication, and entitlement enforcement (step 7
#      below) against a policy this door merely PARSED rather than VERIFIED would let a locally
#      tampered policy grant anything it likes
#   3. the family index must vouch for THIS product          (an index that does not list it is not
#                                                              silence, it is a refusal)
#   4. the bytes must hash to the digest the index names     (a digest is not authentication — the
#                                                              expectation came from an authenticated
#                                                              document, which is what makes it one)
#   5. only then parse
#   6. the manifest's own product must equal the expected one (§10a: "manifest for a different
#                                                              product" — a perfectly valid sibling
#                                                              manifest is still the wrong answer)
#   7. freshness CHECKED (version floor and expiry) — but the floor is not yet COMMITTED; see step 10
#   8. entitlements: nothing outside what the policy index already grants
#   9. the minimum core version this product requires (§8)
#   10. THEN, and only then, the version floor is committed. Checking freshness (7) and committing it
#       (10) are deliberately two different steps around (8) and (9): a manifest that is fresh but
#       fails entitlement or min_core must be refused WITHOUT raising the replay bar, or a publisher's
#       typo (an unentitled role, a min_core bump nothing here can satisfy) permanently blocks every
#       future version at or below the one that was refused — including a perfectly good earlier
#       release. See lib/trust.sh's AMENDMENT A2 for why the check/commit split exists at all; this
#       door is the reason it exists.
#   11. §7.3's launch state, LAST — "not launched" is only trustworthy once the document saying it
#       has been authenticated. This is still an ACCEPTANCE (the floor was already committed in step
#       10): an authentic manifest that says "not launched" is not a manifest to be replayed around.
#
# rc 0 accept (prints the records) · 1 refused (reported) · 3 AUTHENTIC but declares not-launched
# (§7.3's contract code, carried through unchanged) · 4 no anchor.
mi_accept_manifest() {
  if [ "$#" -ne 4 ]; then
    mi_warn "manifest: mi_accept_manifest needs an <index file>, a <policy file>, a <manifest file> and a <product>"
    return 1
  fi
  local ixf="$1" polf="$2" f="$3" want="$4" idx pol expected records got rc

  # FILES, not record strings. A record blob is data any caller can fabricate, so accepting one as
  # "the authenticated index" would make the chain a convention rather than a boundary — the same
  # defect one level up from parsing an unverified manifest. Everything is re-derived here from the
  # anchor, which is the only thing this process did not receive from its caller.
  if idx="$(mi_accept_index "$ixf")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"
  if pol="$(mi_accept_policy "$ixf" "$polf")"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ] || return "$rc"

  if expected="$(_mi_index_manifest_digest "$idx" "$want")"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 3 ]; then
    mi_warn "manifest: the family index does not vouch for '$want' — refusing to install an unattested product"
    return 1
  fi
  [ "$rc" -eq 0 ] || return 1

  # Same snapshot discipline: verify and parse one private copy, never the live pathname twice.
  # The label ("$f") keeps a digest-mismatch diagnostic naming the operator's pathname rather than
  # the private snapshot's — the snapshot is removed a few lines below and would no longer exist by
  # the time anyone read a message naming it.
  local snap rc2
  snap="$(_mi_conf_snap "$f")" || return 1
  if mi_trust_verify_digest "$snap" "$expected" "$f"; then rc2=0; else rc2=$?; fi
  if [ "$rc2" -eq 0 ]; then
    if records="$(mi_manifest_load "$snap" "$f")"; then rc2=0; else rc2=$?; fi
  fi
  rm -f "$snap"
  [ "$rc2" -eq 0 ] || return 1

  got="$(mi_doc_value "$records" product)" || { mi_warn "manifest: $f declares no product"; return 1; }
  if [ "$got" != "$want" ]; then
    mi_warn "manifest: $f is the manifest for '$got', but '$want' was requested — refusing"
    return 1
  fi

  # FIX: freshness is CHECKED here (mi_trust_check_only), but the floor is deliberately NOT committed
  # yet. mi_trust_check — check-then-commit in one call — used to run here, which advances the
  # persisted version floor as part of a check that is not this door's last word: entitlement (below)
  # and min_core (below that) can still refuse this exact manifest. A manifest refused for either
  # reason must not have already raised the replay bar — that would turn a publisher's typo (an
  # unentitled role, an unsatisfiable min_core) into a permanent block on every future manifest at or
  # below the refused version, including a perfectly good EARLIER one already in the field. This is
  # the exact shape lib/trust.sh's AMENDMENT A2 documents; this door is the reason the split exists,
  # and this is the fix for not having used it.
  mi_trust_check_only "manifest:${want}" "$records" || return $?
  mi_manifest_check "$records" "$pol" || return 1

  # §8's minimum core, before ANY success is reported. An authenticated manifest that needs
  # semantics this CLI does not have must not be acted on merely because it is authentic.
  mi_manifest_core_ok "$records" || return 1

  # Commit the floor NOW — fresh, entitled, and satisfying min_core: every gate that can refuse this
  # manifest outright has run. "Not launched" (rc 3, below) is checked AFTER this commit on purpose:
  # it is still an ACCEPTANCE (the manifest is authentic, entitled, and compatible), not a refusal, so
  # it must still advance the floor like any other accepted document.
  mi_trust_commit "manifest:${want}" "$records" || return $?

  # §7.3's launch state, checked LAST and reported as rc 3 — after the manifest has been proved
  # authentic, because "not launched" is only trustworthy if the document saying so is. The records
  # are still printed: a caller reporting "not launched yet" may legitimately want them.
  printf '%s' "$records"
  if mi_manifest_launched "$records"; then return 0; else return $?; fi
}

# The core's own version. It MUST track bin/mythical-ctl's VERSION, and a test asserts they are
# equal: a min_core check against a stale number is worse than none, because it passes while the CLI
# lacks the semantics the manifest asked for.
MI_CORE_VERSION="0.1.0"

# rc 0 iff <a> >= <b>, comparing MAJOR.MINOR.PATCH component-wise with missing components as 0.
#
# Components are peeled off one dot at a time with parameter expansion — the same idiom
# lib/doc.sh's `coreversion` type check uses to walk a dotted version — rather than split into an
# ARRAY-typed local. tools/bundle.sh concatenates every lib/*.sh module into one file, and in that
# flattened file shellcheck's array-type tracking is no longer scoped per function: a later module
# that reused an array-typed local's name for an ordinary string would only go red on
# `shellcheck dist/mythical-ctl`, the generated artifact, never in repo-mode linting. The names
# already spoken for this way are `args`, `pk`, `pv`, `placed` (lib/config.sh), `fields`
# (lib/ledger.sh) and `triples` (lib/trust.sh); this function adds none.
#
# Components are compared through the ledger's decimal-STRING comparator, never `[ -gt ]`: a
# component long enough to overflow shell arithmetic would otherwise wrap and read as smaller than
# it is.
_mi_version_ge() {
  local resta="$1" restb="$2" i=0 pa pb
  while [ "$i" -lt 3 ]; do
    case "$resta" in
      *.*) pa="${resta%%.*}"; resta="${resta#*.}" ;;
      '')  pa=0 ;;
      *)   pa="$resta"; resta='' ;;
    esac
    case "$restb" in
      *.*) pb="${restb%%.*}"; restb="${restb#*.}" ;;
      '')  pb=0 ;;
      *)   pb="$restb"; restb='' ;;
    esac
    if _mi_num_gt "$pa" "$pb"; then return 0; fi
    if _mi_num_gt "$pb" "$pa"; then return 1; fi
    i=$((i + 1))
  done
  return 0                      # equal
}

# rc 0 iff THIS core satisfies the manifest's declared minimum.
#
# PUBLIC, and on the roster later plans call directly (§/__selftest) — so it cannot assume its
# caller already typed <records> the way mi_manifest_load's `coreversion`-typed spec would have.
# Through the door (mi_accept_manifest), min_core is already bounded to MAJOR[.MINOR[.PATCH]] by
# that spec and mi_manifest_load already refuses a 4th component. Called directly against a
# hand-built or otherwise unvalidated records string, no such gate has run — and _mi_version_ge
# compares at most three components, so a value with a stray 4th (`0.1.0.9`) is silently truncated
# to `0.1.0` rather than refused, and a core can appear to satisfy a requirement it does not.
mi_manifest_core_ok() {
  if [ "$#" -ne 1 ]; then mi_warn "manifest: mi_manifest_core_ok needs <records>"; return 1; fi
  local need
  need="$(mi_doc_value "$1" min_core)" || { mi_warn "manifest: no minimum core version declared"; return 1; }
  if ! _mi_doc_type_ok coreversion "$need"; then
    mi_warn "manifest: '$need' is not a valid core version (MAJOR[.MINOR[.PATCH]]) — refusing rather than comparing it"
    return 1
  fi
  if _mi_version_ge "$MI_CORE_VERSION" "$need"; then return 0; fi
  mi_warn "manifest: this product needs mythical-ctl $need or newer; this core is $MI_CORE_VERSION"
  mi_warn "  Upgrade mythical-ctl — a newer manifest may rely on semantics this core does not have."
  return 1
}

# --- core-derived naming (D32) ----------------------------------------------------------------------
# Runtime identifiers are computed from the INSTALLATION identity plus the product identity.
# ~/.mythical/ is per-user, but container and volume names are daemon-global: two OS users on one
# daemon would otherwise compute the same names and adopt or delete each other's containers.
#
# NOT INJECTIVE. `-` is inside the `ident` charset (lib/doc.sh's `ident` type — what
# `_mi_name_part_ok` validates every part against below), so the flat `<prefix>-<a>-<b>-<c>` join is
# ambiguous about where one part ends and the next begins: `mi_name_volume inst1 brokkr state-x` and
# `mi_name_volume inst1 brokkr-state x` both yield `mythical-inst1-brokkr-state-x`, and
# `mi_name_alias inst1-brokkr` equals `mi_name_container inst1 brokkr` — a collision in the SAME DNS
# namespace (both are resolved as container/network aliases on the daemon). A manifest alone cannot
# reach this: as the header above notes, the colliding role must be granted by the authenticated
# policy and the colliding product vouched for by the authenticated index, so "a manifest cannot name
# a sibling's resources" still holds. But two DIFFERENT installation identities that happen to
# collide under this join are not something this module can rule out on its own — it is a
# precondition on the STRING CHOSEN for the installation identity (a hyphen discipline), and `ident`
# cannot enforce it, because `ident` is exactly what allows the hyphen in the first place. Nothing in
# this repository produces an installation identity yet; whichever later plan does inherits this
# precondition, and must either forbid `-` in one of the parts it joins here or reserve a non-`ident`
# separator.
#
# BOUNDED, BUT NOT BY THIS MODULE. A derived name can also exceed the 63-character DNS label limit a
# container runtime enforces: a 64-character product identifier (the `ident` type allows up to 64)
# yields a 73-character alias. This module does not refuse that — the identity producer above must
# respect the bound; failing loudly at the container runtime is a known, later concern, not a
# security problem for this module to close.

_mi_name_part_ok() {
  _mi_doc_type_ok ident "$1"
}

mi_name_volume() {
  if [ "$#" -ne 3 ]; then mi_warn "manifest: mi_name_volume needs <identity> <product> <role>"; return 1; fi
  if ! _mi_name_part_ok "$1" || ! _mi_name_part_ok "$2" || ! _mi_name_part_ok "$3"; then
    mi_warn "manifest: cannot derive a volume name from '$1'/'$2'/'$3'"; return 1
  fi
  printf '%s-%s-%s-%s\n' "$MI_NAME_PREFIX" "$1" "$2" "$3"
}

mi_name_container() {
  if [ "$#" -ne 2 ]; then mi_warn "manifest: mi_name_container needs <identity> <product>"; return 1; fi
  if ! _mi_name_part_ok "$1" || ! _mi_name_part_ok "$2"; then
    mi_warn "manifest: cannot derive a container name from '$1'/'$2'"; return 1
  fi
  printf '%s-%s-%s\n' "$MI_NAME_PREFIX" "$1" "$2"
}

mi_name_network() {
  if [ "$#" -ne 1 ]; then mi_warn "manifest: mi_name_network needs <identity>"; return 1; fi
  _mi_name_part_ok "$1" || { mi_warn "manifest: cannot derive a network name from '$1'"; return 1; }
  printf '%s-%s-net\n' "$MI_NAME_PREFIX" "$1"
}

# The network ALIAS is `mythical-<product>` — RULED by the maintainer 2026-07-29, correcting what
# this function shipped, and it is the one name the whole family already agrees on.
#
# It exists BECAUSE the container name cannot serve: mi_name_container produces
# `mythical-<identity>-<product>`, scoped to an installation identity a sibling has no way to know.
# The alias is the stable, guessable name that makes cross-product discovery possible at all.
#
# So it has to be the name the siblings actually resolve, and they resolve the PREFIXED one. Each
# shipped product states this contract as data in its own source, as a table it calls the single
# source of truth, for candidate ②. The container is `mythical-<product>` (mi_name_alias) and the
# service DNS is `http://mythical-<product>:<UI port>`; the UI ports are:
#
#     product   container          service DNS
#     brokkr    mythical-brokkr    http://mythical-brokkr:<port>
#     saga      mythical-saga      http://mythical-saga:<port>
#     skuld     mythical-skuld     http://mythical-skuld:<port>
#
# The UI ports themselves are declared BELOW as machine-readable data (mi_family_ports), not left
# in this prose block — because a cross-repo contract test (D15) cannot assert a comment, and the
# three independent owners of this table (this file, mythical-saga's core/family-peers.ts and
# mythical-brokkr's ui/src/server/route-family.ts) are reconciled by that test rather than by a
# shared source. Change a port here without changing the other two owners and the test fails.
# TWO DIFFERENT NAMES, AND CONFLATING THEM IS WHAT PUT THE BARE FORM HERE. The DNS name is
# `mythical-<product>`; the `product` STRING each sibling reports at `GET /detect` is the BARE key
# (`brokkr`, not `mythical-brokkr`) — that source says so explicitly, and notes the family
# converged there so that "there is no long-name/short-alias accept-set any more". An earlier
# revision of this plan defended a bare ALIAS by citing those accept-sets, which are about the
# identity string in the response body and say nothing about the hostname the request goes to.
#
# What the bare alias would have cost, had it shipped: mythical-ctl would register `brokkr` while
# every product resolves `mythical-brokkr`, so service-DNS candidate ② misses, discovery silently
# falls through to `host.docker.internal:<port>`, and the family reads as "not detected" on any
# deployment that does not publish ports to the host — with every component reporting healthy.
mi_name_alias() {
  if [ "$#" -ne 1 ]; then mi_warn "manifest: mi_name_alias needs <product>"; return 1; fi
  _mi_name_part_ok "$1" || { mi_warn "manifest: '$1' is not a product identifier"; return 1; }
  printf '%s-%s\n' "$MI_NAME_PREFIX" "$1"
}

# The family UI-port table (D15) — this repo's machine-readable single source of truth for the
# family's UI ports, promoted from the prose block above so a test can assert it. Emitted as
# `<product>\t<port>` rows, the same tab-separated shape mi_manifest_spec uses, so it is DATA a
# reader parses rather than a comment it cannot. This is one of THREE independent owners of the
# same numbers (mythical-saga core/family-peers.ts, mythical-brokkr ui/src/server/route-family.ts);
# the cross-repo contract test executes this function and asserts all three agree. Changing a port
# here without changing the other two owners fails that test — which is the whole point (D15: the
# table is reconciled by a test, never by a vendored shared copy).
mi_family_ports() {
  printf 'brokkr\t7480\n'
  printf 'saga\t7482\n'
  printf 'skuld\t7481\n'
}
