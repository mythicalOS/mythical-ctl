#!/usr/bin/env bats
# §5.1 / D54 — the pinned copy container and the entry/ownership contract.
#
# WHY A CONTAINER AT ALL. The host cannot read a named volume: `docker volume inspect` reports
# /var/lib/docker/volumes/<name>/_data, and on Docker Desktop that path does not exist on the host at
# all — it lives inside the VM — while on Linux it is root-owned and explicitly unsupported as a
# host-access path. So the copy runs inside a DIGEST-PINNED container we control, with `--network
# none`, the source volume mounted READ-ONLY, and staging as the only writable mount.
#
# AND THE ACLs ARE SET BY THAT CONTAINER, NEVER BY THE HOST CLI. `setfacl` is not on the dependency
# floor and does not exist on macOS at all; the copy container's image is ours, so the tool is there
# by construction. The host CLI has no ACL code, and these tests are written so that a host-side
# implementation could not satisfy them.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire; install_helper_img
  IDENT="$(mi_ident_ensure)"
  write_index_fixture "$MYTHICAL_HOME/index"; IDX="$MYTHICAL_HOME/index"
  DST="$(mktemp -d)"; STAGE="${DST}.staging"
}
teardown() { rm -rf "$DST" "$STAGE"; mi_lock_release; teardown_test_env; }

@test "the copy image comes from the verified family index" {
  run mi_copy_image "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "@sha256:"
}

# The index is the ONLY source. An index that does not verify yields no image at all, rather than a
# parsed one — the same door lib/probe.sh uses, for the same reason: reading the image out of a
# merely-parsed index would let anyone with local write access to the cached index name the image the
# installer runs on the operator's daemon.
@test "an index that does not verify yields no copy image" {
  printf 'tampered\n' >> "$IDX"
  run mi_copy_image "$IDX"
  [ "$status" -ne 0 ]
}

@test "an unobtainable copy image STOPS — no fallback to an unverified copy path" {
  FAKE_DOCKER_PULL=notfound run mi_copy_available "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "cannot be obtained"
}

# §7.3/§10a: the registry's own words are NOT swallowed. "denied" and "no such host" send an operator
# to two completely different places, and folding them into one refusal costs a debugging round.
@test "a pull failure keeps the registry's own words" {
  FAKE_DOCKER_PULL=auth run mi_copy_available "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "denied"
}

@test "the copy container mounts the source READ-ONLY, staging writable, and --network none" {
  mkdir -p "$STAGE"
  mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000 || true
  run grep -a 'type=volume,source=srcvol1,target=/src,readonly' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a "type=bind,source=${STAGE},target=/dst" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a -- '--network none' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
}

@test "nothing else from the host is mounted into the copy container" {
  mkdir -p "$STAGE"
  mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000 || true
  run grep -ac -- '--mount' "$FAKE_DOCKER_STATE/calls.log"
  [ "$output" = 1 ]
  # `grep -c` counts LINES, and the whole invocation is ONE line, so the assertion above holds just as
  # well over a container carrying five extra host mounts. Count the FLAGS: exactly two, the read-only
  # source volume and the writable staging bind, and nothing else from the host at all.
  local n
  n="$(tr ' ' '\n' < "$FAKE_DOCKER_STATE/calls.log" | grep -ac -- '--mount' || true)"
  [ "$n" = 2 ] || { echo "expected exactly 2 --mount flags, got $n" >&2; return 1; }
}

@test "an empirical destination preflight is run, and a failing one REFUSES naming what failed" {
  mkdir -p "$STAGE"
  HELPER_PREFLIGHT=noown run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "ownership"
  HELPER_PREFLIGHT=nolink run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "symlink"
  HELPER_PREFLIGHT=noacl run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "ACL"
  HELPER_PREFLIGHT=noperm run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "permissions"
}

@test "the preflight creates a child as EACH uid and verifies the other can read it" {
  mkdir -p "$STAGE"
  run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -eq 0 ]
  run grep -a 'preflight' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  # BOTH uids reach the helper — the check is "create a child as each of them and read it as the
  # other", which a helper handed only one of them cannot perform at all.
  run grep -a -- 'preflight /dst 900 1000' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  # And the cross-read result is READ, not decoration: a destination whose default entries do not
  # carry to a child is refused.
  HELPER_PREFLIGHT=noinherit run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "inherit"
}

@test "the preflight is a no-op for the ACL step when runtime uid == operator uid" {
  mkdir -p "$STAGE"
  run mi_copy_preflight "$IDX" "$STAGE" 1000 1000
  [ "$status" -eq 0 ]
  assert_contains "same uid"
}

# The other half of that rule, and the half a `case … in ok|skipped)` arm silently loses: `skipped` is
# only a no-op when the two uids are the SAME. A copier that reports it when they differ has skipped
# the one step §4.5's dual-owner problem turns on, and accepting that is the fail-open this file
# exists to prevent.
@test "the ACL step may NOT be reported as skipped when the two uids differ" {
  mkdir -p "$STAGE"
  HELPER_PREFLIGHT=aclskip run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "SKIPPED"
}

# rc 3 (absent) is not rc 0 (measured clean). A helper that ran, exited 0 and printed nothing must not
# satisfy five contract checks on no evidence at all.
@test "a preflight that reports nothing is REFUSED — a missing observation is not a passing one" {
  mkdir -p "$STAGE"
  HELPER_PREFLIGHT=silent run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "missing observation"
}

@test "a device, socket or FIFO in the source is REFUSED, naming the path" {
  mkdir -p "$STAGE"
  HELPER_COPY=special run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "/src/dev/thing"
  assert_contains "not product data"
}

# The copier ENUMERATED a special entry and then did not refuse it. The type is a refusal in itself,
# so the CLI refuses on the enumeration alone — otherwise a copier that forgot one line hands back a
# clean exit over a device node it copied.
@test "a special entry the copier enumerated but did NOT refuse is refused anyway" {
  mkdir -p "$STAGE"
  HELPER_COPY=special-unrefused run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "/src/dev/thing"
}

@test "SYMLINKS are copied AS symlinks, targets verbatim, never resolved" {
  mkdir -p "$STAGE"
  run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -eq 0 ]
  assert_contains "symlink"
  run grep -a 'resolved' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "an ESCAPING symlink target is preserved as TEXT and is not followed" {
  mkdir -p "$STAGE"
  HELPER_COPY=escape run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -eq 0 ]
  assert_contains "../../../../etc/passwd"
  run grep -aiE 'followed|wrote outside' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "a copier that reports writing OUTSIDE the destination is a hard failure" {
  mkdir -p "$STAGE"
  HELPER_COPY=escaped-write run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "outside"
}

@test "setuid, setgid and sticky bits are STRIPPED and each strip is reported" {
  mkdir -p "$STAGE"
  HELPER_COPY=setuid run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -eq 0 ]
  assert_contains "stripped"
  assert_contains "/src/bin/tool"
}

@test "FOREIGN-uid entries are refused by default, each named" {
  mkdir -p "$STAGE"
  HELPER_COPY=foreign run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "uid 4242"
  assert_contains "--map-foreign-to-operator"
}

@test "--map-foreign-to-operator folds them in, preserving the numeric info in the report" {
  mkdir -p "$STAGE"
  HELPER_COPY=foreign run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000 --map-foreign-to-operator
  [ "$status" -eq 0 ]
  assert_contains "4242"
  assert_contains "mapped"
}

# The refused path is what the operator acts on, and a colon is a legal byte in a path. Splitting on
# the FIRST colon reports `/src/a` for `/src/a:b/dev/thing:special-entry` — the wrong path, in the one
# message that matters.
@test "a refused path containing a colon is reported WHOLE, not truncated at the colon" {
  mkdir -p "$STAGE"
  HELPER_COPY=colon run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "/src/od:d/dev/thing"
}

# AN EXIT STATUS IS NOT A RESULT. A copier that exits 0 having said nothing has not said it finished.
@test "a copier that exits 0 without reporting completion is a failure" {
  mkdir -p "$STAGE"
  HELPER_COPY=silent run mi_copy_run "$IDX" srcvol1 "$STAGE" 900 1000
  [ "$status" -ne 0 ]
  assert_contains "completion"
}

@test "verification is PER-ENTRY over the contract, not a byte count" {
  mkdir -p "$STAGE"
  run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -eq 0 ]
  HELPER_VERIFY=type run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  assert_contains "type"
  HELPER_VERIFY=digest run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  HELPER_VERIFY=linktarget run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  HELPER_VERIFY=mode run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  HELPER_VERIFY=hardlink run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  HELPER_VERIFY=owner run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  HELPER_VERIFY=mtime run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
}

# The destination is mounted READ-ONLY for verification: the verifier has no reason to write to what
# it is checking, and a verifier that can repair what it finds cannot report it.
@test "verification mounts the destination read-only" {
  mkdir -p "$STAGE"
  mi_copy_verify "$IDX" srcvol1 "$STAGE" || true
  run grep -a "type=bind,source=${STAGE},target=/dst,readonly" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
}

# "Verified" with no count is a verification claim on no evidence: a verifier that walked zero entries
# and exited 0 would otherwise report the copy good.
@test "a verification that does not say how many entries it checked is refused" {
  mkdir -p "$STAGE"
  HELPER_VERIFY=nocount run mi_copy_verify "$IDX" srcvol1 "$STAGE"
  [ "$status" -ne 0 ]
  assert_contains "how many"
}

@test "effective container-side access is TESTED as the runtime uid, not inferred from ACL presence" {
  mkdir -p "$STAGE"
  run mi_copy_access_check "$IDX" "$STAGE" 900
  [ "$status" -eq 0 ]
  run grep -a -- '--user 900' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  HELPER_ACCESS=mask run mi_copy_access_check "$IDX" "$STAGE" 900
  [ "$status" -ne 0 ]
  assert_contains "not effective access"
}

@test "an access answer that omits a check is refused, not read as a pass" {
  mkdir -p "$STAGE"
  HELPER_ACCESS=silent run mi_copy_access_check "$IDX" "$STAGE" 900
  [ "$status" -ne 0 ]
  assert_contains "missing observation"
}

@test "the host side is verified too: the operator can traverse and read" {
  mkdir -p "$STAGE/sub"; printf 'x\n' > "$STAGE/sub/f"
  run mi_copy_host_access_check "$STAGE"
  [ "$status" -eq 0 ]
  chmod 000 "$STAGE/sub"
  run mi_copy_host_access_check "$STAGE"
  [ "$status" -ne 0 ]
  chmod 755 "$STAGE/sub"
}

# The same rule, over the other half of its inputs. A tree whose directories are all traversable and
# whose FILES cannot be read is exactly as unusable, and checking only directories is this plan's most
# common defect shape: a rule applied to some of the things that reach it.
@test "an unreadable FILE in the migrated tree is a finding too, not only a directory" {
  mkdir -p "$STAGE/sub"; printf 'x\n' > "$STAGE/sub/f"
  run mi_copy_host_access_check "$STAGE"
  [ "$status" -eq 0 ]
  chmod 000 "$STAGE/sub/f"
  run mi_copy_host_access_check "$STAGE"
  chmod 644 "$STAGE/sub/f"
  [ "$status" -ne 0 ]
  assert_contains "sub/f"
}

# The copy preserves an escaping symlink as TEXT and does not follow it; the host-side check must not
# follow it either, or it reports on /etc rather than on the migrated tree — and could refuse a
# perfectly good copy because of something outside it entirely.
@test "the host-side check does not FOLLOW an escaping symlink out of the tree" {
  mkdir -p "$STAGE/sub" "$DST/outside/locked"
  printf 'x\n' > "$STAGE/sub/f"
  chmod 000 "$DST/outside/locked"
  ln -s "$DST/outside" "$STAGE/escape"
  run mi_copy_host_access_check "$STAGE"
  chmod 755 "$DST/outside/locked"
  [ "$status" -eq 0 ] || { echo "followed the symlink out of the tree: $output" >&2; return 1; }
  # …and the walk really is live: an unreadable directory INSIDE the tree is still found, so the pass
  # above is "nothing wrong here", not "nothing was looked at".
  chmod 000 "$STAGE/sub"
  run mi_copy_host_access_check "$STAGE"
  chmod 755 "$STAGE/sub"
  [ "$status" -ne 0 ]
}

@test "on Docker Desktop the ACL step is reported as not meaningfully enforced, never claimed" {
  mkdir -p "$STAGE"
  FAKE_DOCKER_CONTEXT_HOST="unix://$HOME/.docker/run/docker.sock" run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  assert_contains "not meaningfully enforced"
}

# The third answer, which is neither "Docker Desktop" nor "native Linux": the endpoint could not be
# read at all. Saying nothing there would let the operator read the run as the native-Linux case,
# where the ACL step IS enforced — a claim nothing here established.
@test "when the daemon endpoint cannot be read, neither enforcement claim is made" {
  mkdir -p "$STAGE"
  mi_rt_context_host() { return 1; }
  run mi_copy_preflight "$IDX" "$STAGE" 900 1000
  [ "$status" -eq 0 ]
  assert_contains "UNKNOWN"
}

# --- the manifest amendment this task depends on (D58) -----------------------------------------

@test "the manifest declares the product's runtime uid, and it is REQUIRED" {
  run mi_manifest_spec
  assert_contains "runtime_uid"
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' $(seq 1 64))"
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nimage=r@%s\n' "$dig" > "$d/m-nouid"
  run mi_manifest_load "$d/m-nouid"
  [ "$status" -eq 1 ]
  assert_contains "runtime_uid"
}

@test "mi_manifest_runtime_uid returns the declared uid" {
  local d="$MYTHICAL_HOME" dig="sha256:$(printf 'a%.0s' $(seq 1 64))" m
  printf 'mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\nruntime_uid=900\nimage=r@%s\n' "$dig" > "$d/m-uid"
  m="$(mi_manifest_load "$d/m-uid")"
  run mi_manifest_runtime_uid "$m"
  [ "$status" -eq 0 ]
  [ "$output" = 900 ]
}
