#!/usr/bin/env bash
# dev-bootstrap.sh — stand up a LOCAL mythical-ctl install against a locally-built image.
#
# WHAT THIS IS FOR. A normal install verifies an authenticated document chain (family index -> policy
# -> per-product manifest) rooted in a trust ANCHOR that the get.mythicalos.ai bootstrap establishes
# over TLS on first use. Until that bootstrap ships, there is no supported way to exercise `install`
# end-to-end against a locally-built image. This dev helper does, by hand and into a SANDBOX family
# home, exactly what the real front door will do:
#   1. author a valid family index + policy + <product>.manifest (digest-chained key=value docs)
#   2. seed the trust anchor = sha256(index)   -- the one step the TLS bootstrap will own
#   3. run `mythical-ctl install <product> --image <local-ref>` — the override runs the local build,
#      and because the image is already present NOTHING is pulled from a registry.
#
# It is a DEVELOPMENT convenience, never part of an install. It seeds a trust-on-first-use anchor from
# a local file — which is exactly the fetch the real bootstrap authenticates with TLS instead — so it
# is safe only on a machine you control, and it refuses to touch a real ~/.mythical.
#
# Usage:  tools/dev-bootstrap.sh <product> <local-image-ref>
# Env:
#   MYTHICAL_HOME   (required) the SANDBOX family home to build in. Refused if it is ~/.mythical.
#   MCTL_HOST_PORT  host port to publish (default 7480). Set this if 7480 is already taken.
#   MCTL_RUNTIME_UID the uid the product runs as (default 900).
#   MCTL_PORT       the container port the product listens on (default 7480).
#   MCTL_STATE_MOUNT where the product's state volume mounts (default /data).
set -o pipefail

PRODUCT="${1:-}"
IMAGE="${2:-}"
if [ -z "$PRODUCT" ] || [ -z "$IMAGE" ]; then
  printf 'usage: dev-bootstrap.sh <product> <local-image-ref>\n' >&2; exit 2
fi
: "${MYTHICAL_HOME:?set MYTHICAL_HOME to a sandbox dir — this helper refuses to touch a real ~/.mythical}"
case "$MYTHICAL_HOME" in "$HOME/.mythical"|"$HOME/.mythical/")
  printf 'dev-bootstrap: MYTHICAL_HOME is your real ~/.mythical — refusing. Point it at a scratch dir.\n' >&2
  exit 1 ;;
esac
export MYTHICAL_HOME

HOST_PORT="${MCTL_HOST_PORT:-7480}"
RUNTIME_UID="${MCTL_RUNTIME_UID:-900}"
PORT="${MCTL_PORT:-7480}"
STATE_MOUNT="${MCTL_STATE_MOUNT:-/data}"

# Resolve the repo this script ships in (tools/ -> repo root), symlink-tolerant enough for dev use.
_self="$0"; case "$_self" in */*) : ;; *) _self="./$_self" ;; esac
REPO="$(cd "$(dirname "$_self")/.." && pwd -P)"
CLI="$REPO/bin/mythical-ctl"
LIB="$REPO/lib"
[ -x "$CLI" ] || { printf 'dev-bootstrap: cannot find %s\n' "$CLI" >&2; exit 1; }

die()  { printf 'dev-bootstrap: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }
rep()  { printf "%.0s$1" $(seq 1 64); }   # 64 repetitions of a hex char, for placeholder digests

DOCS="$MYTHICAL_HOME/dev-docs"
mkdir -p "$DOCS" || die "cannot create $DOCS"

# The entrypoint scrubs these two internal-only ledger-staging vars before anything runs; do the same.
unset _MI_LEDGER_STAGING_INTERNAL MI_LEDGER_PATH_OVERRIDE 2>/dev/null || true
for _m in common layout config lock ledger doc trust policy manifest detect runtime preflight exit \
          prov intent state probe bringup netref verbs repair copy migrate backup; do
  # shellcheck disable=SC1090
  source "$LIB/$_m.sh" || die "could not source lib/$_m.sh"
done

NOW="$(date +%s)"
EXPIRES="$(( NOW + 86400 ))"                 # every doc type requires a future expiry
FAMILY_GID=60748                             # the recommended family gid (docs/DOCUMENT-FORMAT.md)
# The manifest's image= is a REQUIRED digestref (repo@sha256:…). --image overrides it at runtime, so
# its value is never pulled — a syntactically valid placeholder is all it needs.
PLACEHOLDER="local/${PRODUCT}@sha256:$(rep a)"
# The index MUST name a probe_image and copy_image (both digestref). Unpublished pre-go-live, so the
# post-start DNS self-check can't run — the container still comes up, honestly reporting the check
# as outstanding.
PROBE_IMG="local/probe@sha256:$(rep b)"
COPY_IMG="local/copy@sha256:$(rep c)"

step "1. manifest ($DOCS/${PRODUCT}.manifest)"
MAN="$DOCS/${PRODUCT}.manifest"
{
  printf 'mythical-manifest 1\n'
  printf 'version=1\n'
  printf 'expires=%s\n' "$EXPIRES"
  printf 'product=%s\n' "$PRODUCT"
  printf 'launched=true\n'
  printf 'image=%s\n' "$PLACEHOLDER"
  printf 'min_core=0.1.0\n'
  printf 'runtime_uid=%s\n' "$RUNTIME_UID"
  printf 'volume=state:%s\n' "$STATE_MOUNT"
  printf 'port=%s\n' "$PORT"
} > "$MAN" || die "manifest write failed"
cat "$MAN"

step "2. policy ($DOCS/policy)"
POL="$DOCS/policy"
{
  printf 'mythical-policy 1\n'
  printf 'version=1\n'
  printf 'expires=%s\n' "$EXPIRES"
  printf 'family_gid=%s\n' "$FAMILY_GID"
  printf '%s.permitted_role=state\n' "$PRODUCT"
} > "$POL" || die "policy write failed"
cat "$POL"

step "3. index ($DOCS/index) — digests computed AFTER policy+manifest are final"
IDX="$DOCS/index"
{
  printf 'mythical-index 1\n'
  printf 'version=1\n'
  printf 'expires=%s\n' "$EXPIRES"
  printf 'policy_digest=%s\n' "$(mi_digest "$POL")"
  printf 'probe_image=%s\n' "$PROBE_IMG"
  printf 'copy_image=%s\n' "$COPY_IMG"
  printf 'manifest=%s:%s\n' "$PRODUCT" "$(mi_digest "$MAN")"
} > "$IDX" || die "index write failed"
cat "$IDX"

step "4. seed the trust anchor = sha256(index)  [what the get.mythicalos.ai bootstrap will do over TLS]"
mi_ensure_layout || die "mi_ensure_layout failed"
mi_lock_acquire  || die "could not acquire the family lock"
if mi_trust_anchor_set "$(mi_digest "$IDX")"; then
  printf 'anchor set to %s\n' "$(mi_digest "$IDX")"
  mi_lock_release
else
  mi_lock_release
  die "mi_trust_anchor_set failed"
fi

step "4b. host port -> ${HOST_PORT} in mythical.conf"
UP="$(printf '%s' "$PRODUCT" | tr 'a-z-' 'A-Z_')"
printf 'MYTHICAL_%s_PORT=%s\n' "$UP" "$HOST_PORT" > "$MYTHICAL_HOME/mythical.conf" || die "mythical.conf write failed"
printf 'publishes 127.0.0.1:%s->%s\n' "$HOST_PORT" "$PORT"

step "5. install '$PRODUCT' running the LOCAL image '$IMAGE' (via --image override)"
set -x
"$CLI" install "$PRODUCT" \
  --index "$IDX" --policy "$POL" --manifest-dir "$DOCS" \
  --image "$IMAGE"
rc=$?
set +x
printf '\ninstall exit code: %s\n' "$rc"
exit "$rc"
