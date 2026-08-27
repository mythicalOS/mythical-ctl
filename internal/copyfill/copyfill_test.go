package copyfill_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/copyfill"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — tests/unit/copy.bats (this task owns the file WHOLE; every one of its 87 tests
// is claimed exactly once below):
// PORTED: tests/unit/copy.bats: "the copy image comes from the verified family index" -> TestImageFromIndex
// PORTED: tests/unit/copy.bats: "an index that does not verify yields no copy image" -> TestImageFromIndex (structural: Image takes the acceptors' sealed *trust.Index, so a refused index yields no value to pass — the acceptor's own refusal is re-measured here)
// PORTED: tests/unit/copy.bats: "an unobtainable copy image STOPS — no fallback to an unverified copy path" -> TestAvailable
// PORTED: tests/unit/copy.bats: "a pull failure keeps the registry's own words" -> TestAvailable
// PORTED: tests/unit/copy.bats: "the copy container mounts the source READ-ONLY, staging writable, and --network none" -> TestCopyLaunchContract
// PORTED: tests/unit/copy.bats: "nothing else from the host is mounted into the copy container" -> TestCopyLaunchContract
// PORTED: tests/unit/copy.bats: "an empirical destination preflight is run, and a failing one REFUSES naming what failed" -> TestPreflightRefusesNamingWhatFailed
// PORTED: tests/unit/copy.bats: "the preflight creates a child as EACH uid and verifies the other can read it" -> TestPreflightBothPrincipals
// PORTED: tests/unit/copy.bats: "the preflight is a no-op for the ACL step when runtime uid == operator uid" -> TestPreflightSameUid
// PORTED: tests/unit/copy.bats: "the ACL step may NOT be reported as skipped when the two uids differ" -> TestPreflightACLSkipRefused
// PORTED: tests/unit/copy.bats: "a stray done= in an ACCESS transcript is REFUSED — not an access key" -> TestClosedGrammar
// PORTED: tests/unit/copy.bats: "a stray refused= in a PREFLIGHT transcript is REFUSED — not a preflight key" -> TestClosedGrammar
// PORTED: tests/unit/copy.bats: "a preflight that reports nothing is REFUSED — a missing observation is not a passing one" -> TestPreflightSilent
// PORTED: tests/unit/copy.bats: "a device, socket or FIFO in the source is REFUSED, naming the path" -> TestSpecialEntriesRefused
// PORTED: tests/unit/copy.bats: "a special entry the copier enumerated but did NOT refuse is refused anyway" -> TestSpecialEntriesRefused
// PORTED: tests/unit/copy.bats: "a BLANK line in the transcript is REFUSED — it can be a truncated continuation" -> TestClosedGrammar
// PORTED: tests/unit/copy.bats: "a transcript line that is not a key=value record is REFUSED — closed grammar" -> TestClosedGrammar
// PORTED: tests/unit/copy.bats: "a transcript line with an unexpected KEY is REFUSED — only this command's keys are accepted" -> TestClosedGrammar
// PORTED: tests/unit/copy.bats: "a linktarget whose TARGET suffix is empty is REFUSED — a symlink pointing at nothing" -> TestLinktargetRefusals
// PORTED: tests/unit/copy.bats: "an EMPTY linktarget= record is REFUSED — a disclosed target that names nothing" -> TestLinktargetRefusals
// PORTED: tests/unit/copy.bats: "a linktarget for a path that is NOT a symlink entry is REFUSED (unassociated)" -> TestLinktargetRefusals
// PORTED: tests/unit/copy.bats: "TWO linktargets for one symlink is REFUSED (duplicate) — one symlink has one target" -> TestLinktargetRefusals
// PORTED: tests/unit/copy.bats: "a copier padding with a NON-CANONICAL spelling of one path is REFUSED" -> TestEntryCountIsOfDistinctThings
// PORTED: tests/unit/copy.bats: "an EMPTY entry= record (a claimed entry naming nothing) is REFUSED" -> TestEntryCountIsOfDistinctThings
// PORTED: tests/unit/copy.bats: "a MISMATCH reported during the COPY step fails, not only in verify" -> TestCopyStepMismatchIsFatal
// PORTED: tests/unit/copy.bats: "an EMPTY mapped= is REFUSED even when mapping WAS requested — a mapping naming no uid" -> TestEmptyObservationRecords
// PORTED: tests/unit/copy.bats: "an EMPTY stripped= record is REFUSED — a privileged-bits observation of nothing" -> TestEmptyObservationRecords
// PORTED: tests/unit/copy.bats: "an EMPTY mapped= on a copy that did not opt in is REFUSED — presence is the problem" -> TestEmptyObservationRecords
// PORTED: tests/unit/copy.bats: "a copier padding the count with a DUPLICATE source path is REFUSED" -> TestEntryCountIsOfDistinctThings
// PORTED: tests/unit/copy.bats: "an entry TYPE outside the closed set (a FIFO) is REFUSED even with done=ok" -> TestEntryTypeVocabularyIsClosed
// PORTED: tests/unit/copy.bats: "an entry TYPE outside the closed set (a socket) is REFUSED even with done=ok" -> TestEntryTypeVocabularyIsClosed
// PORTED: tests/unit/copy.bats: "a malformed entry line (no path) is REFUSED" -> TestEntryTypeVocabularyIsClosed
// PORTED: tests/unit/copy.bats: "SYMLINKS are copied AS symlinks, targets verbatim, never resolved" -> TestSymlinksPreservedVerbatim
// PORTED: tests/unit/copy.bats: "an escaping (relative) symlink target the copier only logged is REFUSED" -> TestEscapingSymlinkRefused
// PORTED: tests/unit/copy.bats: "an absolute symlink target the copier only logged is REFUSED" -> TestEscapingSymlinkRefused
// PORTED: tests/unit/copy.bats: "a copier that refuses an escaping symlink is read with the escape-specific reason" -> TestEscapingSymlinkRefused
// PORTED: tests/unit/copy.bats: "an escaping symlink whose PATH contains a colon is REFUSED, path reported whole" -> TestEscapingSymlinkRefused
// PORTED: tests/unit/copy.bats: "an escaping symlink whose TARGET contains a colon is REFUSED" -> TestEscapingSymlinkRefused
// PORTED: tests/unit/copy.bats: "a linktarget with a malformed length field is REFUSED, not guessed" -> TestLinktargetRefusals
// PORTED: tests/unit/copy.bats: "a symlink entry WITHOUT a matching linktarget record is REFUSED" -> TestSymlinkRequiresItsLinktarget
// PORTED: tests/unit/copy.bats: "a symlink entry WITH its matching linktarget passes the companion check" -> TestSymlinkRequiresItsLinktarget
// PORTED: tests/unit/copy.bats: "a copier that reports writing OUTSIDE the destination is a hard failure" -> TestEscapedWriteRefused
// PORTED: tests/unit/copy.bats: "setuid, setgid and sticky bits are STRIPPED and each strip is reported" -> TestStrippedBitsReported
// PORTED: tests/unit/copy.bats: "FOREIGN-uid entries are refused by default, each named" -> TestForeignUid
// PORTED: tests/unit/copy.bats: "--map-foreign-to-operator folds them in, preserving the numeric info in the report" -> TestForeignUid
// PORTED: tests/unit/copy.bats: "a refused path containing a colon is reported WHOLE, not truncated at the colon" -> TestRefusedPathWithColonReportedWhole
// PORTED: tests/unit/copy.bats: "a copier that exits 0 without reporting completion is a failure" -> TestCopySilentIsNotCompletion
// PORTED: tests/unit/copy.bats: "an UNREQUESTED foreign-uid mapping is REFUSED, not applied" -> TestUnrequestedMappingRefused
// PORTED: tests/unit/copy.bats: "the same mapping WITH --map-foreign-to-operator is honoured" -> TestUnrequestedMappingRefused
// PORTED: tests/unit/copy.bats: "a NON-EMPTY staging destination is REFUSED inside the copy container, naming the entry" -> TestStagingEmptiness
// PORTED: tests/unit/copy.bats: "an empty staging destination passes" -> TestStagingEmptiness
// PORTED: tests/unit/copy.bats: "a copy reporting done=ok with ZERO enumerated source entries is REFUSED" -> TestZeroEnumeratedEntriesRefused
// PORTED: tests/unit/copy.bats: "the real copy->verify path threads the copy's own source count into verification" -> TestRunVerifyThreadsTheCopysOwnCount
// PORTED: tests/unit/copy.bats: "copy->verify catches a helper UNDERSTATING its checked count vs the copy's source count" -> TestRunVerifyThreadsTheCopysOwnCount
// PORTED: tests/unit/copy.bats: "the source count that binds verification TRACKS the copy's enumeration, not a constant" -> TestRunVerifyThreadsTheCopysOwnCount
// PORTED: tests/unit/copy.bats: "copy->verify catches a verifier OVERSTATING its count against a three-entry copy" -> TestRunVerifyThreadsTheCopysOwnCount
// PORTED: tests/unit/copy.bats: "a non-numeric uid is REFUSED before the copier runs" -> TestUidPrincipalsValidatedEverywhere
// PORTED: tests/unit/copy.bats: "an out-of-range uid (> 2^32-1) is REFUSED by mi_copy_run" -> TestUidPrincipalsValidatedEverywhere
// PORTED: tests/unit/copy.bats: "the preflight validates both uid principals for range too" -> TestUidPrincipalsValidatedEverywhere
// PORTED: tests/unit/copy.bats: "the access check validates the runtime uid range, not only that it is numeric" -> TestUidPrincipalsValidatedEverywhere
// PORTED: tests/unit/copy.bats: "a verify transcript that REFUSES an entry fails, even with checked= and done=ok" -> TestVerifyProblemRecords
// PORTED: tests/unit/copy.bats: "an EMPTY problem record (refused= / mismatch= with no value) fails — presence is the problem" -> TestVerifyProblemRecords
// PORTED: tests/unit/copy.bats: "verification is PER-ENTRY over the contract, not a byte count" -> TestVerifyIsPerEntry
// PORTED: tests/unit/copy.bats: "verification mounts the destination read-only" -> TestVerifyMountsDestinationReadOnly
// PORTED: tests/unit/copy.bats: "verification catches a copied directory MISSING the dual-principal default ACL" -> TestVerifyDefaultACLApplication
// PORTED: tests/unit/copy.bats: "a verification that never reports the default-ACL application is REFUSED" -> TestVerifyDefaultACLApplication
// PORTED: tests/unit/copy.bats: "the default-ACL check may NOT be reported skipped when the two uids differ" -> TestVerifyDefaultACLApplication
// PORTED: tests/unit/copy.bats: "the default-ACL check skipped is ACCEPTED when runtime uid == operator uid" -> TestVerifyDefaultACLApplication
// PORTED: tests/unit/copy.bats: "on Docker Desktop verify reports the default-ACL application as not meaningfully enforced" -> TestACLEnforcementContextIsStatedHonestly
// PORTED: tests/unit/copy.bats: "when the daemon endpoint cannot be read, verify makes neither enforcement claim" -> TestACLEnforcementContextIsStatedHonestly
// PORTED: tests/unit/copy.bats: "verify validates the uid principals for range too" -> TestUidPrincipalsValidatedEverywhere
// PORTED: tests/unit/copy.bats: "a verification that does not say how many entries it checked is refused" -> TestVerifyCountIsBoundToTheSource
// PORTED: tests/unit/copy.bats: "a verification that checked ZERO entries against a non-empty source is refused" -> TestVerifyCountIsBoundToTheSource
// PORTED: tests/unit/copy.bats: "a verifier that checked a different count than the source is refused" -> TestVerifyCountIsBoundToTheSource
// PORTED: tests/unit/copy.bats: "effective container-side access is TESTED as the runtime uid, not inferred from ACL presence" -> TestAccessCheckIsExercisedAsTheRuntimeUid
// PORTED: tests/unit/copy.bats: "an access answer that omits a check is refused, not read as a pass" -> TestAccessCheckIsExercisedAsTheRuntimeUid
// PORTED: tests/unit/copy.bats: "the host side is verified too: the operator can traverse and read" -> TestHostAccessCheck
// PORTED: tests/unit/copy.bats: "an unreadable FILE in the migrated tree is a finding too, not only a directory" -> TestHostAccessCheck
// PORTED: tests/unit/copy.bats: "the host-side check does not FOLLOW an escaping symlink out of the tree" -> TestHostAccessCheckDoesNotFollowSymlinks
// PORTED: tests/unit/copy.bats: "on Docker Desktop the ACL step is reported as not meaningfully enforced, never claimed" -> TestACLEnforcementContextIsStatedHonestly
// PORTED: tests/unit/copy.bats: "when the daemon endpoint cannot be read, neither enforcement claim is made" -> TestACLEnforcementContextIsStatedHonestly
// PORTED: tests/unit/copy.bats: "a preflight failure stated with a ZERO exit is still a refusal" -> TestAnExitStatusIsNotAResult
// PORTED: tests/unit/copy.bats: "a refusal stated with a ZERO exit still abandons the copy" -> TestAnExitStatusIsNotAResult
// PORTED: tests/unit/copy.bats: "a verification MISMATCH stated with a ZERO exit still fails the verification" -> TestAnExitStatusIsNotAResult
// PORTED: tests/unit/copy.bats: "an access failure stated with a ZERO exit is still a refusal" -> TestAnExitStatusIsNotAResult
// PORTED: tests/unit/copy.bats: "the manifest declares the product's runtime uid, and it is REQUIRED" -> TestManifestDeclaresTheRuntimeUid
// PORTED: tests/unit/copy.bats: "mi_manifest_runtime_uid returns the declared uid" -> TestManifestDeclaresTheRuntimeUid

var hex64 = strings.Repeat("cd", 32)

const copyRef = "ghcr.io/x/copy@sha256:" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// nativeSocket is the endpoint a plain rig reports: NOT Docker Desktop's, so the ACL-context
// note stays silent and every other assertion reads a clean transcript. The two knobbed cases
// (Desktop, unreadable) set their own.
const nativeSocket = "/var/run/docker.sock"

type rig struct {
	t     *testing.T
	fake  *enginetest.Fake
	rt    *runtime.Runtime
	c     *copyfill.Copier
	ix    *trust.Index
	img   *enginetest.HelperImage
	out   *bytes.Buffer // the operator-facing narration
	diag  *bytes.Buffer // the helper's stderr + the non-fatal advisories
	stage string        // an empty staging directory, the copy's writable destination
	dst   string        // the sibling scratch directory the reference's tests use
	n     int
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	home := t.TempDir()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	st, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(h, f.Client())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, fake: f, rt: rt, img: &enginetest.HelperImage{},
		out: &bytes.Buffer{}, diag: &bytes.Buffer{}}
	f.HelperEntry = r.img.Entry

	r.c, err = copyfill.New(rt, "i1", func() (string, error) {
		r.n++
		return fmt.Sprintf("n%d", r.n), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.c.SetOutput(r.out); err != nil {
		t.Fatal(err)
	}
	if err := r.c.SetDiagnostics(r.diag); err != nil {
		t.Fatal(err)
	}
	r.setEndpoint(nativeSocket, nil)

	// An anchored, ACCEPTED index — the only way to a *trust.Index.
	dir := t.TempDir()
	ixBytes := indexBytes("copy_image=" + copyRef)
	p := filepath.Join(dir, "index")
	if err := os.WriteFile(p, ixBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(h, st, cliio.SHA256Hex(ixBytes)); err != nil {
		t.Fatal(err)
	}
	r.ix, err = trust.AcceptIndex(h, st, p)
	if err != nil {
		t.Fatal(err)
	}
	f.PullImage(copyRef)

	// The staging destination and the scratch sibling, as the reference's setup makes them.
	r.dst = t.TempDir()
	r.stage = r.dst + ".staging"
	if err := os.MkdirAll(r.stage, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(r.stage) })
	return r
}

func (r *rig) setEndpoint(ep string, err error) {
	r.t.Helper()
	if serr := r.c.SetEndpoint(func() (string, error) { return ep, err }); serr != nil {
		r.t.Fatal(serr)
	}
}

// said is everything the operator saw — narration and advisories together, the way the
// reference's `run` captures stdout and stderr as one stream.
func (r *rig) said() string { return r.out.String() + r.diag.String() }

// reported is what the operator saw PLUS the refusal, which is where the reference's mi_warn
// lines live in this port. Every assert_contains in the bats file reads that union.
func (r *rig) reported(err error) string {
	s := r.said()
	if err != nil {
		s += "\n" + err.Error()
	}
	return s
}

func indexBytes(overrides ...string) []byte {
	lines := map[string]string{
		"version": "1", "expires": "99999999999",
		"policy_digest": hex64,
		"probe_image":   "ghcr.io/x/probe@sha256:" + hex64,
		"copy_image":    "ghcr.io/x/copy@sha256:" + hex64,
	}
	for _, o := range overrides {
		k, v, _ := strings.Cut(o, "=")
		if v == "" {
			delete(lines, k)
		} else {
			lines[k] = v
		}
	}
	var b strings.Builder
	b.WriteString("mythical-index 1\n")
	for _, k := range []string{"version", "expires", "policy_digest", "probe_image", "copy_image"} {
		if v, ok := lines[k]; ok {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return []byte(b.String())
}

// run is the ordinary five-entry copy every knobbed case is a variation of.
func (r *rig) run(opts ...copyfill.Options) (int, error) {
	var o copyfill.Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return r.c.Run(context.Background(), r.ix, "srcvol1", r.stage, "900", "1000", o)
}

func (r *rig) preflight(ruid, ouid string) error {
	return r.c.Preflight(context.Background(), r.ix, r.stage, ruid, ouid)
}

func (r *rig) verify(expect int, ruid, ouid string) error {
	return r.c.Verify(context.Background(), r.ix, "srcvol1", r.stage, expect, ruid, ouid)
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("expected the report to contain %q; it was:\n%s", want, got)
	}
}

func TestImageFromIndex(t *testing.T) {
	r := newRig(t)
	ref, err := r.c.Image(r.ix)
	if err != nil || ref != copyRef {
		t.Fatalf("the copy image is the INDEX's: %q %v", ref, err)
	}
	mustContain(t, ref, "@sha256:")
	// No index, no image: the *trust.Index is constructible only by the acceptors, so an index
	// that did not verify has no value to pass here at all.
	if _, err := r.c.Image(nil); err == nil {
		t.Fatal("no index, no image")
	}
	// ...and the acceptor really does refuse a tampered index, so that is not a hypothetical.
	home := t.TempDir()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	good := indexBytes()
	p := filepath.Join(home, "index")
	if err := os.WriteFile(p, append(good, []byte("tampered\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(h, st, cliio.SHA256Hex(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.AcceptIndex(h, st, p); err == nil {
		t.Fatal("a tampered index was accepted")
	}
}

func TestAvailable(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	// Present-then-pull: the rig has already registered the digest, so no network is needed.
	if err := r.c.Available(ctx, r.ix); err != nil {
		t.Fatalf("a present image needs no pull: %v", err)
	}
	// UNOBTAINABLE: reported, and the migration STOPS — there is no fallback path.
	r2 := newRig(t)
	r2.fake.InspectMissing = copyRef // the digest is not present locally
	r2.fake.PullOutcome = "notfound"
	err := r2.c.Available(ctx, r2.ix)
	if err == nil {
		t.Fatal("an unobtainable copy image must stop the migration")
	}
	mustContain(t, err.Error(), "cannot be obtained")
	mustContain(t, err.Error(), "no fallback to an unverified copy path")
	// A pull failure keeps THE REGISTRY'S OWN WORDS: "denied" and "no such host" send an
	// operator to two completely different places.
	r3 := newRig(t)
	r3.fake.InspectMissing = copyRef
	r3.fake.PullOutcome = "auth"
	err = r3.c.Available(ctx, r3.ix)
	if err == nil {
		t.Fatal("a pull refusal must fail")
	}
	mustContain(t, err.Error(), "denied")
}

func TestCopyLaunchContract(t *testing.T) {
	r := newRig(t)
	if _, err := r.run(); err != nil {
		t.Fatalf("the ordinary copy: %v", err)
	}
	ls := r.fake.HelperLaunches()
	if len(ls) != 1 {
		t.Fatalf("expected exactly one helper launch, got %d", len(ls))
	}
	l := ls[0]
	// The source volume is READ-ONLY at /src; staging is the ONE writable mount, at /dst.
	want := []enginetest.HelperMount{
		{Type: "volume", Source: "srcvol1", Target: "/src", ReadOnly: true},
		{Type: "bind", Source: r.stage, Target: "/dst", ReadOnly: false},
	}
	// NOTHING ELSE FROM THE HOST IS MOUNTED AT ALL — asserted as an exact set, not a
	// containment: a container carrying five extra host mounts satisfies "the two we wanted are
	// present" just as well.
	if len(l.Mounts) != len(want) {
		t.Fatalf("expected exactly %d mounts, got %d: %+v", len(want), len(l.Mounts), l.Mounts)
	}
	for i := range want {
		if l.Mounts[i] != want[i] {
			t.Fatalf("mount %d: got %+v want %+v", i, l.Mounts[i], want[i])
		}
	}
	// --network none: the copy needs no network, and a privileged container reading every byte
	// of a product's data is precisely what must not be able to reach one.
	if l.NetMode != "none" || l.Network != "" || len(l.Aliases) != 0 {
		t.Fatalf("the copy container must run private: %+v", l)
	}
	if l.Image != copyRef {
		t.Fatalf("the copy runs the PINNED image: %q", l.Image)
	}
	if got := strings.Join(l.Cmd, " "); got != "copy /src /dst 900 1000" {
		t.Fatalf("argv: %q", got)
	}
}

// The reverse direction has no row of its own in the reference's unit file (its caller, the
// restore verb, is a later task) — but the mount ROLES are exactly reversed, and that reversal
// is the whole of it: an untrusted host tree read-only at /src, the volume being filled
// writable at /dst. Asserted here so the two directions cannot quietly become one.
func TestFillReversesTheMountRoles(t *testing.T) {
	r := newRig(t)
	src := t.TempDir()
	n, err := r.c.Fill(context.Background(), r.ix, src, "dstvol1", "900", "1000", copyfill.Options{})
	if err != nil || n != 5 {
		t.Fatalf("fill: %d %v", n, err)
	}
	l := r.fake.HelperLaunches()[0]
	want := []enginetest.HelperMount{
		{Type: "bind", Source: src, Target: "/src", ReadOnly: true},
		{Type: "volume", Source: "dstvol1", Target: "/dst", ReadOnly: false},
	}
	if len(l.Mounts) != 2 || l.Mounts[0] != want[0] || l.Mounts[1] != want[1] {
		t.Fatalf("fill mounts: %+v", l.Mounts)
	}
	if got := strings.Join(l.Cmd, " "); got != "copy /src /dst 900 1000" {
		t.Fatalf("the command word and its arguments do not change with the mounts: %q", got)
	}
}

func TestPreflightRefusesNamingWhatFailed(t *testing.T) {
	for knob, want := range map[string]string{
		"noown":  "ownership",
		"nolink": "symlink",
		"noacl":  "ACL",
		"noperm": "permissions",
	} {
		r := newRig(t)
		r.img.Preflight = knob
		err := r.preflight("900", "1000")
		if err == nil {
			t.Fatalf("%s: a destination that cannot represent the contract must be refused", knob)
		}
		mustContain(t, err.Error(), want)
	}
}

func TestPreflightBothPrincipals(t *testing.T) {
	r := newRig(t)
	if err := r.preflight("900", "1000"); err != nil {
		t.Fatalf("the conforming preflight: %v", err)
	}
	l := r.fake.HelperLaunches()[0]
	// BOTH uids reach the helper — the check is "create a child as each of them and read it as
	// the other", which a helper handed only one of them cannot perform at all.
	if got := strings.Join(l.Cmd, " "); got != "preflight /dst 900 1000" {
		t.Fatalf("argv: %q", got)
	}
	// And the cross-read result is READ, not decoration: a destination whose default entries do
	// not carry to a child is refused.
	r2 := newRig(t)
	r2.img.Preflight = "noinherit"
	err := r2.preflight("900", "1000")
	if err == nil {
		t.Fatal("a destination whose default entries do not carry must be refused")
	}
	mustContain(t, err.Error(), "inherit")
}

func TestPreflightSameUid(t *testing.T) {
	r := newRig(t)
	if err := r.preflight("1000", "1000"); err != nil {
		t.Fatalf("equal principals: %v", err)
	}
	mustContain(t, r.said(), "same uid")
}

func TestPreflightACLSkipRefused(t *testing.T) {
	// The half a `case … in ok|skipped)` arm silently loses: `skipped` is only a no-op when the
	// two uids are the SAME. A copier that reports it when they differ has skipped the one step
	// the dual-owner problem turns on.
	r := newRig(t)
	r.img.Preflight = "aclskip"
	err := r.preflight("900", "1000")
	if err == nil {
		t.Fatal("a load-bearing step reported as skipped is a step that did not run")
	}
	mustContain(t, err.Error(), "SKIPPED")
}

func TestPreflightSilent(t *testing.T) {
	r := newRig(t)
	r.img.Preflight = "silent"
	err := r.preflight("900", "1000")
	if err == nil {
		t.Fatal("a preflight that reports nothing must be refused")
	}
	mustContain(t, err.Error(), "missing observation")
}

func TestClosedGrammar(t *testing.T) {
	// A stray key from ANOTHER command's vocabulary is outside this one's grammar and is
	// refused, not passed over while every positive observation is read.
	r := newRig(t)
	r.img.Access = "straydone"
	err := r.c.AccessCheck(context.Background(), r.ix, r.stage, "900")
	if err == nil {
		t.Fatal("a stray done= in an access transcript must be refused")
	}
	mustContain(t, err.Error(), "unexpected key")

	r2 := newRig(t)
	r2.img.Preflight = "strayrefused"
	err = r2.preflight("900", "1000")
	if err == nil {
		t.Fatal("a stray refused= in a preflight transcript must be refused")
	}
	mustContain(t, err.Error(), "unexpected key")

	// The copy's own three grammar failures.
	for knob, want := range map[string]string{
		"blank-line":  "blank line",
		"junk-line":   "not a key=value record",
		"unknown-key": "unexpected key",
	} {
		rr := newRig(t)
		rr.img.Copy = knob
		if _, err := rr.run(); err == nil {
			t.Fatalf("%s: the transcript grammar must fail closed", knob)
		} else {
			mustContain(t, err.Error(), want)
		}
	}
}

func TestSpecialEntriesRefused(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "special"
	_, err := r.run()
	if err == nil {
		t.Fatal("a device, socket or FIFO must be refused")
	}
	mustContain(t, err.Error(), "/src/dev/thing")
	mustContain(t, err.Error(), "not product data")

	// The copier ENUMERATED a special entry and then did not refuse it. The type is a refusal
	// in itself, so the caller refuses on the enumeration alone — otherwise a copier that forgot
	// one line hands back a clean exit over a device node it copied.
	r2 := newRig(t)
	r2.img.Copy = "special-unrefused"
	_, err = r2.run()
	if err == nil {
		t.Fatal("an enumerated-but-unrefused special entry must be refused anyway")
	}
	mustContain(t, err.Error(), "/src/dev/thing")
}

func TestLinktargetRefusals(t *testing.T) {
	cases := map[string]string{
		// pathlen equal to the whole body leaves an EMPTY target: a symlink to the empty
		// string, which cannot be shown not to escape and is not a real disclosed target.
		"emptytarget-lt": "",
		// A disclosed target that names nothing.
		"empty-lt": "names",
		// The relation is one-to-one: a target disclosed for a path never enumerated as a
		// symlink is a contradictory transcript.
		"unassociated-lt": "did NOT enumerate",
		// Two targets for one symlink lets a benign one be shown beside an escaping one.
		"dup-lt": "MORE THAN ONE linktarget",
		// A length field that is not a number: refused, never guessed — an unreadable target
		// could be concealing an escape.
		"linktarget-badlen": "could not read",
		// A ZERO-PADDED length field, refused for the same reason and closing a silent wrong
		// split rather than porting one. The reference reads that token in bash ARITHMETIC,
		// where a leading zero means OCTAL: measured against the frozen lib/copy.sh, ":08"
		// ERRORS out and ":010" splits the body at 8 instead of 10 — putting the path/target
		// boundary in the wrong place, so the bytes checked for an escape are not the bytes the
		// copier disclosed as its target. Here the true path is 21 bytes and the length is
		// written "021": octal 17, decimal 21. Refusing any padded length covers both.
		"escape-padded-len": "could not read",
	}
	for knob, want := range cases {
		r := newRig(t)
		r.img.Copy = knob
		_, err := r.run()
		if err == nil {
			t.Fatalf("%s: must be refused", knob)
		}
		if want != "" {
			mustContain(t, err.Error(), want)
		}
	}
}

func TestEntryCountIsOfDistinctThings(t *testing.T) {
	// Verification is bound to the entry count, so the count must be of DISTINCT source
	// entries. A copier can otherwise emit one valid file N times and OMIT a dangerous entry it
	// also copied — the count still reads N, and a `checked=N` matches a total that never
	// included the dangerous one.
	for knob, want := range map[string]string{
		"dup-entry":    "more than once",
		"noncanon-pad": "canonical path under /src",
		"empty-entry":  "names nothing",
	} {
		r := newRig(t)
		r.img.Copy = knob
		_, err := r.run()
		if err == nil {
			t.Fatalf("%s: must be refused", knob)
		}
		mustContain(t, err.Error(), want)
	}
}

func TestCopyStepMismatchIsFatal(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "copy-mismatch"
	_, err := r.run()
	if err == nil {
		t.Fatal("a mismatch reported during the COPY step is as fatal as a refusal")
	}
	mustContain(t, err.Error(), "MISMATCH")
}

func TestEmptyObservationRecords(t *testing.T) {
	// An empty-valued record is the specific malformed shape a value-iterating loop drops, so
	// each is caught by the key's PRESENCE instead.
	r := newRig(t)
	r.img.Copy = "empty-mapped-req"
	_, err := r.run(copyfill.Options{MapForeignToOperator: true})
	if err == nil {
		t.Fatal("an empty mapped= is malformed even when mapping WAS requested")
	}
	mustContain(t, err.Error(), "names no uid")

	r2 := newRig(t)
	r2.img.Copy = "empty-stripped"
	_, err = r2.run()
	if err == nil {
		t.Fatal("a privileged-bits observation of nothing is malformed")
	}
	mustContain(t, err.Error(), "names no path")

	r3 := newRig(t)
	r3.img.Copy = "empty-mapped"
	_, err = r3.run()
	if err == nil {
		t.Fatal("an empty mapped= on a copy that did not opt in must be refused")
	}
	mustContain(t, err.Error(), "names no uid")
}

func TestEntryTypeVocabularyIsClosed(t *testing.T) {
	// A copier that met a FIFO or a socket and enumerated it as `fifo:`/`socket:` rather than
	// `special:`, then exited 0 with done=ok, would otherwise have that entry COUNTED toward
	// the total and the copy reported verified.
	r := newRig(t)
	r.img.Copy = "unknown-type"
	_, err := r.run()
	if err == nil {
		t.Fatal("an entry type outside the closed set must be refused")
	}
	mustContain(t, err.Error(), "type is not one of file")
	mustContain(t, err.Error(), "fifo:/src/data/q")

	r2 := newRig(t)
	r2.img.Copy = "unknown-socket"
	_, err = r2.run()
	if err == nil {
		t.Fatal("a socket entry type must be refused")
	}
	mustContain(t, err.Error(), "socket:/src/data/s")

	r3 := newRig(t)
	r3.img.Copy = "entry-malformed"
	_, err = r3.run()
	if err == nil {
		t.Fatal("a malformed entry line must be refused")
	}
	mustContain(t, err.Error(), "bogus-no-path")
}

func TestSymlinksPreservedVerbatim(t *testing.T) {
	r := newRig(t)
	if _, err := r.run(); err != nil {
		t.Fatalf("the ordinary copy: %v", err)
	}
	said := r.said()
	mustContain(t, said, "symlink")
	// The target is carried AS TEXT and never resolved — nothing in the report may claim
	// otherwise.
	if strings.Contains(said, "resolved") {
		t.Fatalf("a symlink target is never resolved; the report said:\n%s", said)
	}
	mustContain(t, said, "/src/data/link -> ../data/f")
}

func TestEscapingSymlinkRefused(t *testing.T) {
	// A symlink whose target climbs above the tree, or is absolute, escapes it the moment
	// anything follows it — and the host-side walk deliberately does not follow links, so the
	// copy is where it has to be caught. In the first four the copier only LOGGED the link and
	// exited 0; the caller derives the escape from that line.
	cases := []struct{ knob, path string }{
		{"escape", "/src/data/evil"},
		{"escape-abs", "/src/data/evil"},
		// A conforming copier that refuses it ITSELF is honoured with the same escape-specific
		// message, not the generic "cannot read this refusal" fallback.
		{"escape-refused", "/src/data/evil"},
		// A colon in the link's own PATH: a first-colon split mis-splits the line, reads the
		// target as a non-absolute string, and MISSES the escape. The whole colon-bearing path
		// is named.
		{"escape-colon-path", "/src/data/od:d/evil"},
		// A colon in the TARGET, with a `..` climb: the trailing length field keeps it from
		// being read as the separator, so the climb is still measured.
		{"escape-colon-target", "/src/data/evil"},
		// A symlink that does not SIT in the tree the escape rule is about. The question cannot
		// be asked about it, and a question that could not be asked is never an answer of "no" —
		// so it is refused as an escape rather than measured from a garbage relative depth. (Its
		// target is innocuous, so nothing else here would refuse it for escaping.)
		{"symlink-outside-root", "/elsewhere/evil"},
	}
	for _, tc := range cases {
		r := newRig(t)
		r.img.Copy = tc.knob
		_, err := r.run()
		if err == nil {
			t.Fatalf("%s: an escaping symlink must be refused", tc.knob)
		}
		mustContain(t, err.Error(), tc.path)
		mustContain(t, err.Error(), "escapes the migrated tree")
	}
}

func TestSymlinkRequiresItsLinktarget(t *testing.T) {
	// A copier can otherwise copy an escaping symlink, emit `entry=symlink:<path>` plus
	// `done=ok`, and OMIT both `linktarget=` and `refused=` — the escape backstop then never
	// runs, the entry counts, and verification accepts.
	r := newRig(t)
	r.img.Copy = "symlink-no-linktarget"
	_, err := r.run()
	if err == nil {
		t.Fatal("a symlink whose target was never disclosed must be refused")
	}
	mustContain(t, err.Error(), "/src/data/evil")
	mustContain(t, err.Error(), "no linktarget")

	// The other half: a legitimate symlink (entry + a matching linktarget) is NOT refused — the
	// companion check is targeted at the missing case, not a blanket symlink refusal.
	r2 := newRig(t)
	if _, err := r2.run(); err != nil {
		t.Fatalf("a symlink WITH its linktarget must pass: %v", err)
	}
}

func TestEscapedWriteRefused(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "escaped-write"
	_, err := r.run()
	if err == nil {
		t.Fatal("a reported write outside the destination is a hard failure")
	}
	// The escaped-write-SPECIFIC wording, not a bare "outside": the refused path is
	// /src/data/../outside, so "outside" is satisfied by the path bytes alone — and the generic
	// "cannot read this refusal" fallback echoes the raw value, so it would pass even with the
	// escaped-write reason arm disabled.
	mustContain(t, err.Error(), "would land outside the")
}

func TestStrippedBitsReported(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "setuid"
	n, err := r.run()
	if err != nil {
		t.Fatalf("stripping is reported, not refused: %v", err)
	}
	if n != 6 {
		t.Fatalf("the setuid fixture enumerates six entries, got %d", n)
	}
	mustContain(t, r.said(), "stripped")
	mustContain(t, r.said(), "/src/bin/tool")
	// EACH strip is reported, which one record cannot demonstrate: a reader that processed only
	// the first would pass the assertions above. Three records, all three named.
	r2 := newRig(t)
	r2.img.Copy = "setuid-many"
	if _, err := r2.run(); err != nil {
		t.Fatalf("stripping is reported, not refused: %v", err)
	}
	for _, p := range []string{"/src/bin/suid:4755", "/src/bin/sgid:2755", "/src/bin/sticky:1755"} {
		mustContain(t, r2.said(), p)
	}
}

func TestForeignUid(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "foreign"
	_, err := r.run()
	if err == nil {
		t.Fatal("a foreign uid is refused by default")
	}
	mustContain(t, err.Error(), "uid 4242")
	mustContain(t, err.Error(), "--map-foreign-to-operator")

	// EACH foreign entry is named, which one record cannot demonstrate. Two refusals, different
	// paths AND different uids, so neither can stand in for the other and a reader that stopped
	// at the first fails.
	rm := newRig(t)
	rm.img.Copy = "foreign-many"
	_, merr := rm.run()
	if merr == nil {
		t.Fatal("foreign uids are refused by default")
	}
	for _, want := range []string{"/src/data/alien", "uid 4242", "/src/data/other", "uid 4343"} {
		mustContain(t, merr.Error(), want)
	}

	// With the opt-in they are folded in, and the numeric information is preserved in the
	// report.
	r2 := newRig(t)
	r2.img.Copy = "foreign"
	if _, err := r2.run(copyfill.Options{MapForeignToOperator: true}); err != nil {
		t.Fatalf("the opt-in folds them in: %v", err)
	}
	mustContain(t, r2.said(), "4242")
	mustContain(t, r2.said(), "mapped")
	// ...and the flag really reached the helper's argv.
	if got := strings.Join(r2.fake.HelperLaunches()[0].Cmd, " "); !strings.HasSuffix(got, "--map-foreign") {
		t.Fatalf("argv: %q", got)
	}
}

func TestRefusedPathWithColonReportedWhole(t *testing.T) {
	// The refused path is what the operator acts on, and a colon is a legal byte in a path.
	// Splitting on the FIRST colon reports `/src` for `/src/od:d/dev/thing:special-entry` — the
	// wrong path, in the one message that matters.
	r := newRig(t)
	r.img.Copy = "colon"
	_, err := r.run()
	if err == nil {
		t.Fatal("a special entry must be refused")
	}
	mustContain(t, err.Error(), "/src/od:d/dev/thing")
	// ...and it must be the PARSED refusal that names it, not the raw value echoed by the
	// "cannot read this refusal" fallback. The colon fixture also enumerates the same path as a
	// special ENTRY, so the refusal above could be produced without the reason-last parse
	// working at all. This transcript carries a colon-bearing refused= AND NOTHING ELSE: no
	// entry line to derive it from, and a reason (escaped-write) no entry type can produce.
	r2 := newRig(t)
	r2.img.Copy = "colon-refused-only"
	_, err = r2.run()
	if err == nil {
		t.Fatal("a colon-bearing refusal must be refused")
	}
	mustContain(t, err.Error(), "/src/od:d/data/f")
	// The escaped-write-specific wording proves the reason was READ from the end of the value.
	mustContain(t, err.Error(), "would land outside the")
	// And it is not the fallback, which would echo the raw value (reason and all).
	if strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("the refusal was not parsed, only echoed:\n%s", err.Error())
	}
	if strings.Contains(err.Error(), ":escaped-write") {
		t.Fatalf("the reason leaked into the reported path:\n%s", err.Error())
	}
}

func TestCopySilentIsNotCompletion(t *testing.T) {
	// AN EXIT STATUS IS NOT A RESULT. A copier that exits 0 having said nothing has not said it
	// finished.
	r := newRig(t)
	r.img.Copy = "silent"
	_, err := r.run()
	if err == nil {
		t.Fatal("a copier that reports nothing has not reported completion")
	}
	mustContain(t, err.Error(), "completion")
}

func TestUnrequestedMappingRefused(t *testing.T) {
	// A regressed or hostile copier that maps a foreign uid into the operator's and reports
	// `mapped=` on a DEFAULT invocation must be REFUSED, not logged and accepted. The flag only
	// changes the helper's argv; the decision to fold foreign ownership is the caller's, and it
	// was not asked for.
	r := newRig(t)
	r.img.Copy = "foreign-mapped-unrequested"
	_, err := r.run()
	if err == nil {
		t.Fatal("an unrequested mapping must be refused")
	}
	mustContain(t, err.Error(), "did NOT request")

	// ...but WITH the opt-in the very same mapping is honoured — so the refusal above is the
	// missing flag, not the mapping itself.
	r2 := newRig(t)
	r2.img.Copy = "foreign-mapped-unrequested"
	if _, err := r2.run(copyfill.Options{MapForeignToOperator: true}); err != nil {
		t.Fatalf("the same mapping WITH the opt-in: %v", err)
	}
	mustContain(t, r2.said(), "mapped")
}

func TestStagingEmptiness(t *testing.T) {
	// The check lives INSIDE the copy container, on the writable mount, atomically with the
	// copy — never in a host-side glance that races the mount and mangles untrusted names. The
	// copy merges the source over whatever is already there and verification checks only the
	// source, so a pre-existing entry would survive inside the migrated tree unexamined.
	r := newRig(t)
	r.img.Copy = "stage-nonempty"
	_, err := r.run()
	if err == nil {
		t.Fatal("a non-empty staging destination must be refused")
	}
	mustContain(t, err.Error(), "was not empty")
	mustContain(t, err.Error(), "/dst/leftover")

	// The other half of the rule: an EMPTY staging passes, so the refusal above is the
	// leftover, not the gate refusing everything.
	r2 := newRig(t)
	if _, err := r2.run(); err != nil {
		t.Fatalf("an empty staging destination passes: %v", err)
	}
}

func TestZeroEnumeratedEntriesRefused(t *testing.T) {
	r := newRig(t)
	r.img.Copy = "empty"
	_, err := r.run()
	if err == nil {
		t.Fatal("done=ok over zero enumerated entries is a vacuous completion")
	}
	mustContain(t, err.Error(), "ZERO source entries")
}

func TestRunVerifyThreadsTheCopysOwnCount(t *testing.T) {
	ctx := context.Background()
	// The REAL copy->verify path threads the count the COPY ITSELF enumerated (five entries)
	// into verification — never a constant a caller invents.
	r := newRig(t)
	if err := r.c.RunVerify(ctx, r.ix, "srcvol1", r.stage, "900", "1000", copyfill.Options{}); err != nil {
		t.Fatalf("the conforming path: %v", err)
	}
	mustContain(t, r.said(), "verified 5 entries")

	// A verifier that UNDERSTATES its checked count (3) against the copy's source count (5) is
	// caught: the count it is measured against came from the copy's enumeration.
	r2 := newRig(t)
	r2.img.Verify = "understate"
	err := r2.c.RunVerify(ctx, r2.ix, "srcvol1", r2.stage, "900", "1000", copyfill.Options{})
	if err == nil {
		t.Fatal("an understated checked count must be caught")
	}
	mustContain(t, err.Error(), "checked 3 entries but the source has 5")

	// The count TRACKS the copy's own enumeration and is not a constant: here the copy
	// enumerated THREE and an honest three-entry verify passes. No single hard-coded number
	// could satisfy both this and the five-entry case above.
	r3 := newRig(t)
	r3.img.Copy, r3.img.Verify = "count3", "count3"
	if err := r3.c.RunVerify(ctx, r3.ix, "srcvol1", r3.stage, "900", "1000", copyfill.Options{}); err != nil {
		t.Fatalf("a three-entry copy verified honestly: %v", err)
	}
	mustContain(t, r3.said(), "verified 3 entries")

	// ...and against a three-entry copy, a verifier that reports FIVE is caught — the mirror of
	// the understatement, and the case a caller that hard-coded 5 would wrongly pass.
	r4 := newRig(t)
	r4.img.Copy, r4.img.Verify = "count3", "ok"
	err = r4.c.RunVerify(ctx, r4.ix, "srcvol1", r4.stage, "900", "1000", copyfill.Options{})
	if err == nil {
		t.Fatal("an overstated checked count must be caught")
	}
	mustContain(t, err.Error(), "checked 5 entries but the source has 3")
}

func TestUidPrincipalsValidatedEverywhere(t *testing.T) {
	ctx := context.Background()
	// Both principals are validated as 0..4294967295 before ANY helper call — not just
	// numerically, and not only in the runtime adapter's --user gate. A non-numeric or
	// out-of-range uid would be written into ACL entries and named in messages for a principal
	// no step ever ran as.
	r := newRig(t)
	_, err := r.c.Run(ctx, r.ix, "srcvol1", r.stage, "900", "notauid", copyfill.Options{})
	if err == nil {
		t.Fatal("a non-numeric uid must be refused before the copier runs")
	}
	mustContain(t, err.Error(), "not a numeric uid")
	if n := len(r.fake.HelperLaunches()); n != 0 {
		t.Fatalf("BEFORE the copier runs: %d helper launches", n)
	}

	_, err = r.c.Run(ctx, r.ix, "srcvol1", r.stage, "4294967296", "1000", copyfill.Options{})
	if err == nil {
		t.Fatal("an out-of-range uid must be refused by Run")
	}
	mustContain(t, err.Error(), "out of range")

	// REFUSED BY LENGTH, BEFORE ANY CONVERSION. A digit string too long for a machine integer
	// is the shape that defeats a bare range test: converted first, it WRAPS, and a 20-digit
	// "uid" comes out the other side as a small number that passes. The digit count is checked
	// first precisely so no conversion of it ever happens.
	// 18446744073709551616 is 2^64 exactly: fed to a 64-bit accumulator it WRAPS TO ZERO, and a
	// bare range test then reads it as uid 0 — root. That is the whole reason the digit count is
	// bounded before anything is converted, and it is the one input that proves it.
	for _, huge := range []string{"99999999999", "18446744073709551616", "18446744073709552616", strings.Repeat("9", 20)} {
		if _, err := r.c.Run(ctx, r.ix, "srcvol1", r.stage, huge, "1000", copyfill.Options{}); err == nil {
			t.Fatalf("a %d-digit uid must be refused out of range", len(huge))
		} else {
			mustContain(t, err.Error(), "out of range")
		}
	}

	if err := r.preflight("900", "4294967296"); err == nil {
		t.Fatal("the preflight validates BOTH principals for range")
	} else {
		mustContain(t, err.Error(), "out of range")
	}

	if err := r.c.AccessCheck(ctx, r.ix, r.stage, "4294967296"); err == nil {
		t.Fatal("the access check validates range, not only that the uid is numeric")
	} else {
		mustContain(t, err.Error(), "out of range")
	}

	if err := r.verify(5, "4294967296", "1000"); err == nil {
		t.Fatal("verify validates the uid principals for range too")
	} else {
		mustContain(t, err.Error(), "out of range")
	}
	if n := len(r.fake.HelperLaunches()); n != 0 {
		t.Fatalf("no uid-refused call may reach the daemon: %d helper launches", n)
	}

	// ...and a uid written with leading zeros is still the number it spells: the zeros are
	// stripped BEFORE the digit count is taken, so the count means what it says and a legal uid
	// spelled long is not refused. (A fresh rig: this one succeeds and does reach the daemon.)
	r2 := newRig(t)
	if _, err := r2.c.Run(ctx, r2.ix, "srcvol1", r2.stage, "0000000900", "1000", copyfill.Options{}); err != nil {
		t.Fatalf("leading zeros do not make a uid out of range: %v", err)
	}
}

func TestVerifyProblemRecords(t *testing.T) {
	// The verifier can report a refusal exactly as the copy step can — a device it met, an
	// entry it could not compare — and an otherwise-conforming transcript alongside it must
	// still fail.
	r := newRig(t)
	r.img.Verify = "verify-refused"
	err := r.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("a refusal is as fatal in verification as in the copy")
	}
	mustContain(t, err.Error(), "REFUSED")

	// An EMPTY problem record is a stated problem too: the value loop skips it, so it is caught
	// by the key's presence.
	for _, knob := range []string{"verify-empty-refused", "verify-empty-mismatch"} {
		rr := newRig(t)
		rr.img.Verify = knob
		if err := rr.verify(5, "900", "1000"); err == nil {
			t.Fatalf("%s: a stated problem that names nothing must still fail", knob)
		}
	}
}

func TestVerifyIsPerEntry(t *testing.T) {
	r := newRig(t)
	if err := r.verify(5, "900", "1000"); err != nil {
		t.Fatalf("the conforming verify: %v", err)
	}
	// Verification is over the CONTRACT, not a byte count: type, digest, link target, mode,
	// hardlink topology, owner and mtime each fail it.
	for _, knob := range []string{"type", "digest", "linktarget", "mode", "hardlink", "owner", "mtime"} {
		rr := newRig(t)
		rr.img.Verify = knob
		err := rr.verify(5, "900", "1000")
		if err == nil {
			t.Fatalf("%s: a per-entry mismatch must fail verification", knob)
		}
		mustContain(t, err.Error(), knob)
	}
}

func TestVerifyMountsDestinationReadOnly(t *testing.T) {
	// A verifier that can repair what it finds cannot report it.
	r := newRig(t)
	if err := r.verify(5, "900", "1000"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	l := r.fake.HelperLaunches()[0]
	want := []enginetest.HelperMount{
		{Type: "volume", Source: "srcvol1", Target: "/src", ReadOnly: true},
		{Type: "bind", Source: r.stage, Target: "/dst", ReadOnly: true},
	}
	if len(l.Mounts) != 2 || l.Mounts[0] != want[0] || l.Mounts[1] != want[1] {
		t.Fatalf("verify mounts: %+v", l.Mounts)
	}
}

func TestVerifyDefaultACLApplication(t *testing.T) {
	// The copied tree is EMPIRICALLY checked for the dual-principal default ACL: a copied
	// directory missing it is reported as a mismatch like any other attribute. Capability at
	// preflight is not proof of application.
	r := newRig(t)
	r.img.Verify = "default-acl"
	err := r.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("a copied directory missing the default ACL must fail verification")
	}
	mustContain(t, err.Error(), "default-acl")

	// ...and the positive observation is REQUIRED on its own account: acl=fail with no
	// accompanying mismatch still fails, so the requirement is not merely riding the mismatch
	// pass that happens to accompany it above.
	r1b := newRig(t)
	r1b.img.Verify = "acl-fail-only"
	if err := r1b.verify(5, "900", "1000"); err == nil {
		t.Fatal("acl=fail must fail verification on its own")
	} else {
		mustContain(t, err.Error(), "did not pass the default-ACL application check")
	}

	// ...and non-vacuously: a verifier that never REPORTS the result (never looked) is refused,
	// not read as a pass — the same "absent is not measured-clean" rule, one level down.
	r2 := newRig(t)
	r2.img.Verify = "acl-absent"
	err = r2.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("an unmeasured ACL application is not a measured-clean one")
	}
	mustContain(t, err.Error(), "missing observation")

	// `skipped` is a no-op ONLY when the two principals are one uid. Reported where they
	// DIFFER, it is a load-bearing check that did not run.
	r3 := newRig(t)
	r3.img.Verify = "acl-skip-differ"
	err = r3.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("a skipped default-ACL check where the uids differ must be caught")
	}
	mustContain(t, err.Error(), "SKIPPED")

	// The other half: when the uids are equal the step is genuinely a no-op, so `skipped` is
	// accepted and verification passes.
	r4 := newRig(t)
	if err := r4.verify(5, "1000", "1000"); err != nil {
		t.Fatalf("equal principals make the ACL step a genuine no-op: %v", err)
	}
}

func TestACLEnforcementContextIsStatedHonestly(t *testing.T) {
	// On Docker Desktop the ACL is translated away at the file-sharing layer, so neither half
	// may CLAIM the step it exercised was enforced.
	r := newRig(t)
	r.setEndpoint("/Users/someone/.docker/run/docker.sock", nil)
	_ = r.preflight("900", "1000")
	mustContain(t, r.said(), "not meaningfully enforced")

	r2 := newRig(t)
	r2.setEndpoint("/Users/someone/.docker/run/docker.sock", nil)
	_ = r2.verify(5, "900", "1000")
	mustContain(t, r2.said(), "not meaningfully enforced")

	// The third answer, which is neither "Docker Desktop" nor "native Linux": the endpoint could
	// not be read at all. Saying nothing there would let the operator read the run as the
	// native-Linux case, where the ACL step IS enforced — a claim nothing here established.
	r3 := newRig(t)
	r3.setEndpoint("", errors.New("the context store cannot be read"))
	if err := r3.preflight("900", "1000"); err != nil {
		t.Fatalf("an unreadable endpoint is not a preflight failure: %v", err)
	}
	mustContain(t, r3.said(), "UNKNOWN")

	r4 := newRig(t)
	r4.setEndpoint("", errors.New("the context store cannot be read"))
	if err := r4.verify(5, "900", "1000"); err != nil {
		t.Fatalf("an unreadable endpoint is not a verification failure: %v", err)
	}
	mustContain(t, r4.said(), "UNKNOWN")

	// ...and on native Linux neither claim is made in either direction — the silent default is
	// the case where the step IS enforced, so a note there would be noise.
	r5 := newRig(t)
	if err := r5.preflight("900", "1000"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r5.said(), "not meaningfully enforced") || strings.Contains(r5.said(), "UNKNOWN") {
		t.Fatalf("native Linux enforces the ACL step; the report said:\n%s", r5.said())
	}
}

func TestVerifyCountIsBoundToTheSource(t *testing.T) {
	// "Verified" with no count is a verification claim on no evidence.
	r := newRig(t)
	r.img.Verify = "nocount"
	err := r.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("a completion claim with no count is not evidence")
	}
	mustContain(t, err.Error(), "how many")

	// A stated count is not enough: it must be BOUND to the source. Zero checked against a
	// source of five is not a verification.
	r2 := newRig(t)
	r2.img.Verify = "zero"
	err = r2.verify(5, "900", "1000")
	if err == nil {
		t.Fatal("a vacuous pass over a non-empty source must be refused")
	}
	mustContain(t, err.Error(), "the source has 5")

	// The count is bound in BOTH directions: a fabricated surplus is as wrong as zero.
	r3 := newRig(t)
	err = r3.verify(4, "900", "1000")
	if err == nil {
		t.Fatal("a checked count above the source's own must be refused")
	}
	mustContain(t, err.Error(), "checked 5 entries but the source has 4")
}

func TestAccessCheckIsExercisedAsTheRuntimeUid(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	if err := r.c.AccessCheck(ctx, r.ix, r.stage, "900"); err != nil {
		t.Fatalf("the conforming access check: %v", err)
	}
	l := r.fake.HelperLaunches()[0]
	// Run AS the product's runtime uid, so it answers as the product would.
	if l.User != "900" {
		t.Fatalf("the access check runs as the runtime uid, got user %q", l.User)
	}
	if got := strings.Join(l.Cmd, " "); got != "access /dst" {
		t.Fatalf("argv: %q", got)
	}
	// ACL PRESENCE IS NOT EFFECTIVE ACCESS — a restrictive mask silently limits a present
	// entry, which is why this is TESTED as that uid rather than inferred from the entries set.
	r2 := newRig(t)
	r2.img.Access = "mask"
	err := r2.c.AccessCheck(ctx, r2.ix, r2.stage, "900")
	if err == nil {
		t.Fatal("a masked ACL entry must fail the access check")
	}
	mustContain(t, err.Error(), "not effective access")

	// An answer that omits a check is refused, not read as a pass.
	r3 := newRig(t)
	r3.img.Access = "silent"
	err = r3.c.AccessCheck(ctx, r3.ix, r3.stage, "900")
	if err == nil {
		t.Fatal("an omitted access observation must be refused")
	}
	mustContain(t, err.Error(), "missing observation")
}

func TestHostAccessCheck(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "f")
	if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyfill.HostAccessCheck(dir); err != nil {
		t.Fatalf("a readable tree passes: %v", err)
	}
	// AN UNTRAVERSABLE DIRECTORY IS A FINDING IN ITS OWN RIGHT — isolated here from the
	// "could not look" fold below by making it EMPTY and merely non-executable (mode 0600):
	// the listing succeeds and there is nothing inside to fail on, so the mode bits are the
	// only thing that can report it. The operator cannot cd into it, and a tree with a
	// directory it cannot enter is not a tree it can use.
	shut := filepath.Join(dir, "shut")
	if err := os.Mkdir(shut, 0o600); err != nil {
		t.Fatal(err)
	}
	err0 := copyfill.HostAccessCheck(dir)
	if cerr := os.Chmod(shut, 0o755); cerr != nil {
		t.Fatal(cerr)
	}
	if err0 == nil {
		t.Fatal("a directory the operator cannot traverse must be a finding")
	}
	mustContain(t, err0.Error(), "shut")
	if err := os.Remove(shut); err != nil {
		t.Fatal(err)
	}
	// A directory the operator cannot traverse is a finding.
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	err := copyfill.HostAccessCheck(dir)
	if cerr := os.Chmod(sub, 0o755); cerr != nil {
		t.Fatal(cerr)
	}
	if err == nil {
		t.Fatal("an untraversable directory must be a finding")
	}
	// ...and so is an unreadable FILE. A tree whose directories are all traversable and whose
	// FILES cannot be read is exactly as unusable, and checking only directories is this plan's
	// most common defect shape: a rule applied to some of the things that reach it.
	if err := os.Chmod(f, 0o000); err != nil {
		t.Fatal(err)
	}
	err = copyfill.HostAccessCheck(dir)
	if cerr := os.Chmod(f, 0o644); cerr != nil {
		t.Fatal(cerr)
	}
	if err == nil {
		t.Fatal("an unreadable file must be a finding too")
	}
	mustContain(t, err.Error(), filepath.Join("sub", "f"))
	// A destination that is not a directory at all is refused rather than walked.
	if err := copyfill.HostAccessCheck(f); err == nil {
		t.Fatal("a non-directory destination must be refused")
	}
}

func TestHostAccessCheckDoesNotFollowSymlinks(t *testing.T) {
	// The copy preserves an escaping symlink as TEXT and does not follow it; the host-side check
	// must not follow it either, or it reports on something outside the migrated tree — and
	// could refuse a perfectly good copy because of something outside it entirely.
	root := t.TempDir()
	tree := filepath.Join(root, "tree")
	sub := filepath.Join(tree, "sub")
	outside := filepath.Join(root, "outside")
	locked := filepath.Join(outside, "locked")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tree, "escape")); err != nil {
		t.Fatal(err)
	}
	// ...and one pointing at an unreadable FILE outside the tree. This is the shape that
	// separates an lstat walk from a stat walk: followed, it is a regular file with mode 000 and
	// would be reported as a finding about something that is not in the migrated tree at all.
	lockedFile := filepath.Join(outside, "locked-file")
	if err := os.WriteFile(lockedFile, []byte("x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lockedFile, filepath.Join(tree, "escape-file")); err != nil {
		t.Fatal(err)
	}
	err := copyfill.HostAccessCheck(tree)
	if cerr := os.Chmod(locked, 0o755); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatalf("followed the symlink out of the tree: %v", err)
	}
	// ...and the walk really is live: an unreadable directory INSIDE the tree is still found,
	// so the pass above is "nothing wrong here", not "nothing was looked at".
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	err = copyfill.HostAccessCheck(tree)
	if cerr := os.Chmod(sub, 0o755); cerr != nil {
		t.Fatal(cerr)
	}
	if err == nil {
		t.Fatal("an unreadable directory inside the tree is still found")
	}
}

func TestAnExitStatusIsNotAResult(t *testing.T) {
	// Every knob that makes the helper report a failure ALSO makes it exit nonzero, so each of
	// those tests would pass just as well against a core that read only the status and never
	// looked at the answer. Exit0 separates the two: the image states exactly the same findings
	// and exits 0. A pinned image that regressed this way is the thing the STATED-result rule
	// exists for, and these four are the tests that die if the per-observation reading is
	// deleted.
	ctx := context.Background()

	r := newRig(t)
	r.img.Preflight, r.img.Exit0 = "noown", true
	err := r.preflight("900", "1000")
	if err == nil {
		t.Fatal("a preflight failure stated with a ZERO exit is still a refusal")
	}
	mustContain(t, err.Error(), "ownership")

	r2 := newRig(t)
	r2.img.Copy, r2.img.Exit0 = "special", true
	if _, err := r2.run(); err == nil {
		t.Fatal("a refusal stated with a ZERO exit still abandons the copy")
	} else {
		mustContain(t, err.Error(), "/src/dev/thing")
	}

	r3 := newRig(t)
	r3.img.Verify, r3.img.Exit0 = "digest", true
	if err := r3.verify(5, "900", "1000"); err == nil {
		t.Fatal("a verification MISMATCH stated with a ZERO exit still fails")
	} else {
		mustContain(t, err.Error(), "MISMATCH")
	}

	r4 := newRig(t)
	r4.img.Access, r4.img.Exit0 = "mask", true
	if err := r4.c.AccessCheck(ctx, r4.ix, r4.stage, "900"); err == nil {
		t.Fatal("an access failure stated with a ZERO exit is still a refusal")
	} else {
		mustContain(t, err.Error(), "not effective access")
	}
}

// The manifest amendment this module depends on: the ownership mapping maps TO the product's
// runtime uid, which is read from the AUTHENTICATED manifest — never guessed, never read out of
// the image, never defaulted. (ParseVerified is boundary-gated to the trust acceptors; a test
// file is exempt, and this is the one place the copy module's own dependency on that field is
// pinned.)
func TestManifestDeclaresTheRuntimeUid(t *testing.T) {
	if _, ok := manifest.Spec().Fixed["runtime_uid"]; !ok {
		t.Fatal("the manifest schema must declare runtime_uid")
	}
	dig := "sha256:" + strings.Repeat("a", 64)
	base := "mythical-manifest 1\nversion=1\nexpires=4102444800\nproduct=brokkr\nlaunched=true\nmin_core=0.1.0\n"
	// REQUIRED: a manifest that does not declare it is refused, naming the field.
	_, err := manifest.ParseVerified([]byte(base+"image=r@"+dig+"\n"), "m-nouid")
	if err == nil {
		t.Fatal("a manifest with no runtime_uid must be refused")
	}
	mustContain(t, err.Error(), "runtime_uid")
	// ...and the accessor returns the declared uid.
	m, err := manifest.ParseVerified([]byte(base+"runtime_uid=900\nimage=r@"+dig+"\n"), "m-uid")
	if err != nil {
		t.Fatal(err)
	}
	if m.RuntimeUID() != "900" {
		t.Fatalf("runtime uid: %q", m.RuntimeUID())
	}
}

// Three guards the reference's own fixture cannot reach, and therefore never exercised. They
// are not extra rules — they are rules lib/copy.sh states and copy.bats has no knob for — so
// the port carries them AND the transcripts that make them fire. Each one is the same class:
// a stated problem, or a stated non-answer, that a value-iterating or numeric reader lets past.
func TestGuardsTheReferenceFixtureCannotReach(t *testing.T) {
	// An EMPTY `refused=` on the COPY step. The value pass drops it, so only a check by the KEY
	// sees it — and a copier that refuses without naming what is still a copier that refused.
	r := newRig(t)
	r.img.Copy = "empty-refused"
	if _, err := r.run(); err == nil {
		t.Fatal("a refusal that named nothing must still abandon the copy")
	} else {
		mustContain(t, err.Error(), "refusal that named nothing")
	}

	// `done=` something other than `ok` is not completion. An exit status is not a result, and
	// neither is a completion field that says something else.
	r2 := newRig(t)
	r2.img.Copy = "done-not-ok"
	if _, err := r2.run(); err == nil {
		t.Fatal("done=notok is not completion")
	} else {
		mustContain(t, err.Error(), "rather than completion")
	}

	// A `checked=` that is STATED but is not a count. The absent-observation rule does not fire
	// (something was said), so only the digit check stands between it and a comparison against
	// a number nobody has.
	r3 := newRig(t)
	r3.img.Verify = "badcount"
	if err := r3.verify(5, "900", "1000"); err == nil {
		t.Fatal("a checked= that is not a count must be refused")
	} else {
		mustContain(t, err.Error(), "did not say how many entries it checked")
	}
}

// A NUL byte is where being FAITHFUL TO THE BYTES would make this port weaker than the shell it
// replaces. The reference never sees one — `$(…)` deletes NULs — so bash reads a different
// string than the helper wrote, and in both shapes below its accidental strip is what refuses
// the copy. A byte-faithful reader gets both wrong in the unsafe direction, so the transcript is
// refused outright instead (stripping would silently rewrite a path into a different path).
func TestNulBytesRefuseTheWholeTranscript(t *testing.T) {
	// An absolute symlink target hidden behind a NUL: "\x00/etc/passwd" does not begin with '/',
	// so a byte-faithful escape check reads it as RELATIVE and carries the link into the tree.
	r := newRig(t)
	r.img.Copy = "nul-linktarget"
	if _, err := r.run(); err == nil {
		t.Fatal("a NUL-bearing linktarget must be refused, not read as a relative target")
	} else {
		mustContain(t, err.Error(), "NUL byte")
	}

	// Two spellings of ONE source object: a byte-faithful reader counts 2, and a `checked=2`
	// then matches a total that covered one real entry.
	r2 := newRig(t)
	r2.img.Copy = "nul-entry"
	if _, err := r2.run(); err == nil {
		t.Fatal("a NUL-bearing entry path must be refused, not counted as a distinct entry")
	} else {
		mustContain(t, err.Error(), "NUL byte")
	}
}

// "I COULD NOT ASK" IS NOT "IT ANSWERED BADLY". When the daemon refuses the launch outright the
// transcript is empty, so every observation is missing — and reporting only that tells the
// operator the helper said nothing, when the truth is that no helper ever ran. The reference put
// the runtime's own words on inherited stderr; here they are a value, and both the diagnostics
// channel and the returned error must carry them.
func TestALaunchFailureIsNotAMissingObservation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func(*rig) error
	}{
		{"preflight", func(r *rig) error { return r.preflight("900", "1000") }},
		{"access", func(r *rig) error { return r.c.AccessCheck(ctx, r.ix, r.stage, "900") }},
	} {
		r := newRig(t)
		r.fake.HelperFail = "permission denied while trying to connect to the daemon socket"
		err := tc.call(r)
		if err == nil {
			t.Fatalf("%s: a helper that could not be launched must not pass", tc.name)
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s: the refusal lost the reason there was no answer:\n%s", tc.name, err.Error())
		}
		if !strings.Contains(r.said(), "could not be run") {
			t.Fatalf("%s: the operator was never told the helper could not be run:\n%s", tc.name, r.said())
		}
	}
}

// A compile-time reminder that the copy image is reached through the sealed index type and the
// engine's closed helper vocabulary, never through a free-form string.
var _ = []engine.HelperCommand{engine.HelperPreflight, engine.HelperCopy, engine.HelperVerify, engine.HelperAccess}
