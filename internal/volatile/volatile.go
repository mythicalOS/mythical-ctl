// Package volatile is the closed `volatile_mount` wire — the credential-bearing isolated-home
// mount, installer half.
//
// One manifest field names the mount: a bounded absolute container path, and NOTHING else.
// Every hardening property is FIXED here and is not declarable, so a publisher cannot widen the
// mount into a generic escape hatch. That closure is the whole point of the field being a bare
// path with no options sub-grammar.
//
// This module is one half of a two-surface contract: another surface provisions the volatile
// root, this installer reads the manifest path and renders the mount. Both render the SAME root
// with the SAME hardening. What lives here is the manifest-side rules — the path grammar, the
// canonical production root, and the fixed security-option set. The mount itself is rendered at
// the one launch site (internal/engine's tmpfs constructor, reached only through the runtime
// facade), so no caller can express the mount any other way; the rendered mount is a
// NON-PERSISTENT tmpfs carrying nodev,nosuid,noexec, with the 0700 homes and 0600 credential
// files beneath the root established by the daemon that owns it, excluded from backup and
// restore.
//
// PURE: no filesystem access, no secret bytes, no side effects. It validates and maps metadata.
//
// IT IS THE SINGLE SOURCE FOR BOTH LITERALS. The document type vocabulary (internal/docfmt's
// `cpath`) CALLS PathOK rather than restating it, and the engine's tmpfs constructor calls
// TmpfsSecOpts rather than spelling the flags, so the manifest door and the launch site cannot
// drift into accepting different paths or mounting with different hardening.
package volatile

import (
	"fmt"
	"strings"
)

// canonicalRoot is the ONE production credential-home root. Supported deployments mount THIS
// path as the volatile tmpfs; production may not fall back to a state directory, a bind mount, a
// named volume, or the container writable layer. A test rig may inject a private root at the
// lower layers, but the production bring-up path enforces this one — see AssertProductionRoot.
const canonicalRoot = "/run/mythical/credential-homes"

// tmpfsSecOpts is the three tmpfs security flags IN THE WIRE'S CANONICAL ORDER.
//
// THE ORDER IS A BYTE-PARITY CONTRACT, NOT A SPELLING PREFERENCE. Other producers of this same
// mount write their option string as a literal, and the two surfaces are compared as BYTES —
// this installer's flags must stay byte-equal to the LEADING FLAG SEGMENT of theirs. Reordering
// the set would mount an identical filesystem, so nothing local would fail; what would break is
// the comparison in another repository, silently. That is why this is one frozen literal in one
// place and every other surface asks for it here.
//
// This installer emits ONLY the three security flags: the daemon owning the root establishes the
// 0700 mode and the size bound beneath it, so those options are deliberately not ours to state.
const tmpfsSecOpts = "nodev,nosuid,noexec"

// Root is the canonical production credential-home root.
func Root() string { return canonicalRoot }

// TmpfsSecOpts is the frozen security-option string. See tmpfsSecOpts for why its ORDER is a
// contract with surfaces outside this repository.
func TmpfsSecOpts() string { return tmpfsSecOpts }

// PathOK accepts a bounded absolute container path, and nothing else. This is the closed value
// validator for the `volatile_mount` field: because a segment's charset is only [A-Za-z0-9._-]
// plus the separator, it ALSO rejects every attempt to smuggle a second token or an options
// sub-grammar past it (a space, a comma, a colon, an `=`), which is what keeps a manifest from
// widening the mount.
//
// Accepted: begins with `/`; each segment is [A-Za-z0-9._-]+; no trailing slash; the bare root
// `/` is refused; no empty segment (`//`); no `.` or `..` traversal segment; no whitespace or
// control byte; length 2..512 BYTES.
//
// THE BARE ROOT IS REFUSED HERE, AT PARSE TIME. `/` fails the 2-byte floor, the no-trailing-slash
// rule AND the empty-segment rule, so no downstream guard has to defend the FIELD against a mount
// point of `/` — it can never reach one. (The container root still matters to PathDisjoint below,
// but that is about the OTHER mounts, whose grammar is looser.)
//
// TWO OF THESE RULES ARE DELIBERATELY REDUNDANT, and mutation testing says so out loud: reverting
// the trailing-slash check ALONE changes no answer, because a trailing slash always leaves an
// empty trailing segment for the walk below to refuse; and weakening the length floor from 2 to 1
// changes no answer either, because the only 1-byte candidate is `/`. (The reference bash needs
// its explicit trailing-slash rule — its walk terminates on an empty remainder and never sees the
// trailing empty segment. Go's split-based walk does.) Both are kept, because the refusal of `/`
// is load-bearing enough to be over-determined rather than resting on one rule; what a test can
// pin is the ANSWER, PathOK("/") == false, and that answer is pinned.
//
// The floor's own UNIQUE contribution is the empty string: without it the absolute-path check
// below indexes v[0] and PANICS. A field validator that panics on a value rather than refusing it
// is not fail-closed, which is why "" is an explicit case in this function's tests.
func PathOK(v string) bool {
	// The length bound first, in BYTES — len() on a Go string is exactly that, so a multi-byte
	// rune cannot buy extra path under a rune-counted bound.
	if len(v) < 2 || len(v) > 512 {
		return false
	}
	// Absolute, and no trailing slash — which is also the second refusal of the bare root.
	if v[0] != '/' || strings.HasSuffix(v, "/") {
		return false
	}
	// The safe-segment charset over the WHOLE string, BEFORE the segment walk. One pass rejects
	// whitespace, control bytes, `:` `,` `=` `*` and every other byte outside the grammar.
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '.', b == '_', b == '-', b == '/':
		default:
			return false
		}
	}
	// No empty (`//`), `.` or `..` segment. The leading `/` is dropped once, so there is no
	// leading empty field to special-case.
	for _, seg := range strings.Split(v[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// IsCanonicalRoot is true only for the fixed production credential-home root.
func IsCanonicalRoot(v string) bool { return v == canonicalRoot }

// AssertProductionRoot is the fail-closed guard for the production bring-up path: the declared
// mount must be a valid path AND be the canonical root. A test rig injecting a private root does
// not call this; the installer's real bring-up does, so a manifest cannot point credential homes
// anywhere but the fixed root, nor fall back to durable storage.
//
// The two refusals are DISTINCT because they are different operator problems: a malformed path
// is a publishing error, a valid non-canonical one is a deployment that would silently persist
// credentials. An answer that is wrong about WHY is one an operator acts on wrongly.
func AssertProductionRoot(v string) error {
	if !PathOK(v) {
		return fmt.Errorf("volatile: %q is not a bounded absolute container path", v)
	}
	if v != canonicalRoot {
		return fmt.Errorf("volatile: a production credential-home mount must be rooted at %s, not %q. "+
			"Production may not fall back to a state directory, a bind mount, a named volume, or the "+
			"container writable layer — the mount must be the fixed non-persistent tmpfs root", canonicalRoot, v)
	}
	return nil
}

// SecOptsOK is true only when a security-option string is EXACTLY the fixed set, in the canonical
// order. A weakened set (a missing flag), a REORDERING, or an added option is refused rather than
// downgraded — see tmpfsSecOpts for why a reordering is a real defect and not a cosmetic one.
func SecOptsOK(s string) bool { return s == tmpfsSecOpts }

// PathNorm lexically normalizes an absolute path: collapse repeated slashes, drop `.` segments,
// strip a trailing slash (the bare root stays `/`).
//
// IT DOES NOT RESOLVE `..` — a traversal is refused upstream by every type that feeds this, and
// resolving one here would invent a path the caller never wrote. (This is why it is not
// path.Clean, which does resolve `..`.) It touches no filesystem. Its whole purpose is that two
// spellings of the SAME container path compare equal in PathDisjoint: without it a manifest could
// write a mount target as `/run/mythical/./credential-homes/session` — which the looser mount
// grammar accepts — and slip a durable mount under the volatile root past a lexical prefix check.
//
// A relative path is returned unchanged: callers only pass absolute paths, and this refuses to
// invent a leading slash.
func PathNorm(p string) string {
	if !strings.HasPrefix(p, "/") {
		return p
	}
	var out strings.Builder
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." { // collapse `//`, drop `.`
			continue
		}
		out.WriteByte('/')
		out.WriteString(seg)
	}
	if out.Len() == 0 {
		return "/" // the path was all slashes and `.` segments
	}
	return out.String()
}

// PathDisjoint is true only when two absolute container paths are DISJOINT — neither equal, nor
// one a subpath of the other — compared on their NORMALIZED forms so two spellings of the same
// path cannot slip past.
//
// It keeps the volatile credential-home root isolated from every other mount: a durable mount (a
// named volume or a bind) at, under, or over the volatile root would place credential bytes on
// persistent storage inside the tmpfs tree, defeating the non-persistence the mount exists to
// guarantee. Overlap is therefore SYMMETRIC — at, under and over are all refusals, in either
// argument order.
func PathDisjoint(a, b string) bool {
	na, nb := PathNorm(a), PathNorm(b)
	if na == nb {
		return false // identical mount points
	}
	// THE CONTAINER ROOT IS HANDLED EXPLICITLY, and this is the case a prefix check misses. `/`
	// is an ancestor of everything, but after normalization it is a lone `/`, and appending a
	// boundary slash to it (as the comparisons below do for every other path) makes `//` — a
	// prefix NO normalized path has. A target of `/`, which the looser mount-target grammar
	// accepts, would then read as DISJOINT from a root beneath it and slip the guard entirely.
	if na == "/" || nb == "/" {
		return false
	}
	// Non-root normalized paths carry no trailing slash, so `<p>/` is the exact path boundary:
	// it matches a true child (…/homes/session) but not a mere prefix STRING (…/homes-2).
	if strings.HasPrefix(nb, na+"/") || strings.HasPrefix(na, nb+"/") {
		return false
	}
	return true
}
