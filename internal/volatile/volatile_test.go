package volatile_test

import (
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/volatile"
)

// Inventory — tests/unit/volatile.bats:
// PORTED: tests/unit/volatile.bats: "the canonical root and the fixed security options are the wire's exact literals" -> TestWireLiterals
// PORTED: tests/unit/volatile.bats: "a bounded absolute path of safe segments is accepted" -> TestPathOKAccepts
// PORTED: tests/unit/volatile.bats: "every path the wire's grammar rejects is rejected" -> TestPathOKRejectsGrammar -- the empty string is added to the bats list: PathOK is a field validator and must refuse rather than panic
// PORTED: tests/unit/volatile.bats: "a value carrying a second token or an option is rejected — the field cannot widen the mount" -> TestPathOKIsTheClosure
// PORTED: tests/unit/volatile.bats: "a whitespace or control byte in the path is rejected" -> TestPathOKRejectsWhitespaceAndControl
// PORTED: tests/unit/volatile.bats: "the length bound is enforced at both ends" -> TestPathOKLengthBound -- 512 accepted, 513 refused, and the 1-byte floor
// PORTED: tests/unit/volatile.bats: "the canonical-root predicate is true only for the fixed root" -> TestIsCanonicalRoot
// PORTED: tests/unit/volatile.bats: "the production guard accepts the canonical root and refuses every other, even valid, path" -> TestAssertProductionRoot -- including that an invalid path and a valid non-canonical one are refused for DIFFERENT stated reasons
// PORTED: tests/unit/volatile.bats: "the security-option check accepts only the exact frozen set" -> TestSecOptsOK
// PORTED: tests/unit/volatile.bats: "path disjointness catches equal, child, and ancestor overlaps but allows a sibling" -> TestPathDisjoint -- every case asserted in BOTH argument orders, the container root included — the boundary a prefix check misses
// PORTED: tests/unit/volatile.bats: "path normalization defeats equivalent spellings of an overlapping path" -> TestPathNorm TestPathDisjointNormalizesFirst -- the normalizer itself, and the overlap answers it produces; `..` is deliberately NOT resolved, so this is not path.Clean
// PORTED: tests/unit/volatile.bats: "the typed launch spec is emitted for a valid path and refused for an invalid one" -> internal/engine.TestTmpfsMountRefusedAtTheLaunchSite internal/engine.TestTmpfsMountRendersFrozenHardening -- Go has no `volatile=<path>` spec STRING — the runtime adapter takes a typed value, so the equivalent is the engine constructor: it validates the path first and either yields the mount the daemon receives or refuses, which is exactly what the row pins

// TestWireLiterals pins the two values the wire is made of.
//
// THE OPTION STRING IS A BYTE-PARITY CONTRACT, NOT A STABLE SPELLING. The three flags and
// THEIR ORDER must stay byte-equal to the LEADING FLAG SEGMENT of the tmpfs option string four
// producers in other repositories write (`nodev,nosuid,noexec,mode=0700,size=16m` — two compose
// files, an install library and its test). Those surfaces and this one are compared as BYTES, so
// reordering the set here — `nosuid,nodev,noexec` mounts the identical filesystem — would be a
// wire change in another repository, not a local style choice, and it would break silently
// because both spellings produce the same kernel flags. That is why the WHOLE string is asserted
// as one literal rather than as a set of three flags.
//
// This tool emits ONLY the three security flags: the daemon establishes the 0700 root and the
// size bound beneath it, so `mode=` and `size=` are deliberately absent here and the parity is
// with the option string's LEADING segment, not with the whole of it.
func TestWireLiterals(t *testing.T) {
	if got := volatile.Root(); got != "/run/mythical/credential-homes" {
		t.Fatalf("Root() = %q, want the canonical production credential-home root", got)
	}
	if got := volatile.TmpfsSecOpts(); got != "nodev,nosuid,noexec" {
		t.Fatalf("TmpfsSecOpts() = %q, want exactly \"nodev,nosuid,noexec\" — this string is byte-compared "+
			"against the leading segment of four producer strings outside this repository; a reordering is a "+
			"wire change there, not a style choice here", got)
	}
}

// TestPathOKAccepts: a bounded absolute path of safe segments.
func TestPathOKAccepts(t *testing.T) {
	for _, v := range []string{"/run/mythical/credential-homes", "/a", "/srv/x.y_z-1", "/a/b/c", "/tmp/inject-root"} {
		if !volatile.PathOK(v) {
			t.Errorf("PathOK(%q) = false — a valid bounded absolute container path was rejected", v)
		}
	}
}

// TestPathOKRejectsGrammar: every shape the grammar refuses. The bare root `/` is in this list
// deliberately: it is refused AT PARSE TIME by the grammar (both the 2-byte floor and the
// no-trailing-slash rule reach it), which is why no later guard has to defend the FIELD against
// it — see TestAssertProductionRoot.
func TestPathOKRejectsGrammar(t *testing.T) {
	// "" is in this list because PathOK must be TOTAL: it is the field validator, and a validator
	// that panics on a value rather than refusing it is not fail-closed. (The empty string is what
	// the length floor uniquely buys — every other under-length value is refused by a second rule
	// as well; see the mutation notes on this package.)
	for _, v := range []string{"", "relative/path", "/", "/a/", "/a//b", "/a/./b", "/a/../b", "/.", "/..", "/a/..", "."} {
		if volatile.PathOK(v) {
			t.Errorf("PathOK(%q) = true — an invalid container path was accepted", v)
		}
	}
}

// TestPathOKIsTheClosure: the grammar is what keeps the manifest field a bare mount point. A
// space, a comma, a colon or an `=` is how a publisher would smuggle `nodev=false` or a bind
// `source=` past a field that has no options sub-grammar; each must be refused by the charset.
func TestPathOKIsTheClosure(t *testing.T) {
	for _, v := range []string{
		"/run/mythical/credential-homes exec",
		"/run/mythical/credential-homes,nodev=false",
		"/run/mythical/credential-homes:rw",
		"/path=exec",
		"/path*",
		"/path;other",
	} {
		if volatile.PathOK(v) {
			t.Errorf("PathOK(%q) = true — a mount-widening value was accepted; the field would no longer be closed", v)
		}
	}
}

// TestPathOKRejectsWhitespaceAndControl: neither is in the safe-segment charset.
func TestPathOKRejectsWhitespaceAndControl(t *testing.T) {
	for _, v := range []string{"/a/\tb", " /a", "/a\nb", "/a\x00b"} {
		if volatile.PathOK(v) {
			t.Errorf("PathOK(%q) = true — a whitespace or control byte was accepted", v)
		}
	}
}

// TestPathOKLengthBound: 2..512 BYTES, enforced at both ends.
func TestPathOKLengthBound(t *testing.T) {
	ok := "/" + strings.Repeat("a", 511)   // 512 bytes
	over := "/" + strings.Repeat("a", 512) // 513 bytes
	if len(ok) != 512 || len(over) != 513 {
		t.Fatalf("fixture lengths are %d and %d, want 512 and 513", len(ok), len(over))
	}
	if !volatile.PathOK(ok) {
		t.Error("PathOK rejected a 512-byte path — the upper bound is inclusive")
	}
	if volatile.PathOK(over) {
		t.Error("PathOK accepted a 513-byte path — the upper bound is not enforced")
	}
	// The lower bound: a 1-byte value cannot be an absolute path with a segment.
	if volatile.PathOK("/") {
		t.Error("PathOK accepted the 1-byte bare root")
	}
}

func TestIsCanonicalRoot(t *testing.T) {
	if !volatile.IsCanonicalRoot("/run/mythical/credential-homes") {
		t.Error("IsCanonicalRoot rejected the fixed root")
	}
	for _, v := range []string{"/tmp/credential-homes", "/run/mythical/credential-homes/session", "/run/mythical", ""} {
		if volatile.IsCanonicalRoot(v) {
			t.Errorf("IsCanonicalRoot(%q) = true", v)
		}
	}
}

// TestAssertProductionRoot: the fail-closed guard for the production bring-up path. A test rig
// may inject a private root at the lower layers; production may not, so this guard refuses every
// path but the canonical one — INCLUDING a perfectly valid one, because "valid" is not the
// property production needs.
func TestAssertProductionRoot(t *testing.T) {
	if err := volatile.AssertProductionRoot("/run/mythical/credential-homes"); err != nil {
		t.Fatalf("the canonical root was refused: %v", err)
	}
	// A valid path that is not the canonical root — production may not fall back to it.
	err := volatile.AssertProductionRoot("/tmp/credential-homes")
	if err == nil {
		t.Fatal("a non-canonical production root was accepted — production could fall back to durable storage")
	}
	if !strings.Contains(err.Error(), "must be rooted at /run/mythical/credential-homes") {
		t.Errorf("the refusal does not name the required root: %v", err)
	}
	// An outright invalid path fails the SAME guard, and says so as a grammar failure rather
	// than as a wrong-root one — an answer that is wrong about WHY is an answer an operator acts
	// on wrongly.
	err = volatile.AssertProductionRoot("/a/../b")
	if err == nil {
		t.Fatal("an invalid path passed the production guard")
	}
	if !strings.Contains(err.Error(), "not a bounded absolute container path") {
		t.Errorf("an invalid path was refused for the wrong reason: %v", err)
	}
	// The bare root is refused HERE TOO, by the grammar arm — the FIELD never needs a separate
	// `/` guard, which is why one does not exist.
	if err := volatile.AssertProductionRoot("/"); err == nil {
		t.Fatal("the container root was accepted as a production credential-home root")
	}
}

// TestSecOptsOK is fail-closed: only the exact frozen set, in order. A missing flag, a
// REORDERING, or an added option is a different — and for the reordering, a byte-different —
// mount, and is refused rather than downgraded.
func TestSecOptsOK(t *testing.T) {
	if !volatile.SecOptsOK("nodev,nosuid,noexec") {
		t.Fatal("the frozen option set was refused")
	}
	for _, bad := range []string{"nodev,nosuid", "nosuid,noexec,nodev", "nodev,nosuid,noexec,exec", "", "rw,nodev,nosuid,noexec", "nodev,nosuid,noexec,mode=0700,size=16m"} {
		if volatile.SecOptsOK(bad) {
			t.Errorf("SecOptsOK(%q) = true — a weakened or reordered option set was accepted", bad)
		}
	}
}

func TestPathNorm(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/run/mythical/./credential-homes//session/", "/run/mythical/credential-homes/session"},
		{"/run/mythical/credential-homes/.", "/run/mythical/credential-homes"},
		{"/", "/"},
		{"///", "/"},
		{"/./", "/"},
		{"/a", "/a"},
		// `..` is NOT resolved — every type feeding this refuses a traversal upstream, and
		// resolving one here would invent a path the caller never wrote.
		{"/a/../b", "/a/../b"},
		// A relative path is returned unchanged rather than given a leading slash it did not have.
		{"relative/path", "relative/path"},
		{"", ""},
	} {
		if got := volatile.PathNorm(c.in); got != c.want {
			t.Errorf("PathNorm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPathDisjoint is the isolation rule, and it is SYMMETRIC. A durable mount at, under, OR
// over the volatile root all put credential bytes on persistent storage inside the tmpfs tree,
// so overlap is judged in both argument orders and the test asserts both orders for every case.
//
// THE CONTAINER ROOT IS THE CASE A PREFIX CHECK MISSES. `/` is an ancestor of everything, but
// appending a boundary slash to it makes `//`, a prefix NO normalized path has — so a target of
// `/`, which the looser mount-target grammar accepts, reads as disjoint from a root beneath it
// unless the root is handled explicitly. It is asserted here on BOTH sides for that reason.
func TestPathDisjoint(t *testing.T) {
	const root = "/run/mythical/credential-homes"
	overlapping := []string{
		root,              // identical
		root + "/session", // a child
		"/run/mythical",   // an ancestor
		"/run",            // a further ancestor
		"/",               // the container root — an ancestor of everything
	}
	for _, bad := range overlapping {
		if volatile.PathDisjoint(root, bad) {
			t.Errorf("PathDisjoint(%q, %q) = true — an overlap was missed", root, bad)
		}
		if volatile.PathDisjoint(bad, root) {
			t.Errorf("PathDisjoint(%q, %q) = true — the overlap was missed in the reversed argument order; the rule is symmetric", bad, root)
		}
	}
	disjoint := []string{
		"/run/mythical/other",              // a sibling
		"/data",                            // an unrelated tree
		"/run/mythical/credential-homes-2", // shares a prefix STRING but not a path boundary
	}
	for _, ok := range disjoint {
		if !volatile.PathDisjoint(root, ok) {
			t.Errorf("PathDisjoint(%q, %q) = false — a disjoint path was wrongly flagged as overlapping", root, ok)
		}
		if !volatile.PathDisjoint(ok, root) {
			t.Errorf("PathDisjoint(%q, %q) = false — asymmetric answer on a disjoint pair", ok, root)
		}
	}
}

// TestPathDisjointNormalizesFirst: overlap is judged on NORMALIZED paths, so a different
// SPELLING of a child cannot slip a durable mount under the root. The looser mount-target
// grammar accepts `.` segments, `//` and a trailing slash, and a bare lexical prefix check would
// miss every one of these.
func TestPathDisjointNormalizesFirst(t *testing.T) {
	const root = "/run/mythical/credential-homes"
	for _, bad := range []string{
		"/run/mythical/./credential-homes/session",
		"/run/mythical/credential-homes//session",
		"/run/mythical/credential-homes/session/",
		"/run/mythical/credential-homes/.",
		"/run/mythical/./credential-homes",
		"//run//mythical//credential-homes//",
	} {
		if volatile.PathDisjoint(root, bad) {
			t.Errorf("PathDisjoint(%q, %q) = true — an equivalent spelling slipped past the overlap check", root, bad)
		}
		if volatile.PathDisjoint(bad, root) {
			t.Errorf("PathDisjoint(%q, %q) = true — the equivalent spelling slipped past in the reversed order", bad, root)
		}
	}
}
