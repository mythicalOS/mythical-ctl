// Package migrate is `migrate-storage`: moving one product volume role's data off its named
// volume onto a host directory, in nine durable phases (D51).
//
// THIS IS THE ONE PLACE THE INSTALLER READS ATTACKER-CONTROLLED DATA (a container volume's
// contents) AND WRITES IT TO HOST PATHS. Both trees are untrusted, and every check in this
// package is written on that assumption.
//
// THE CONFINEMENT BOUNDARY IS THE DESTINATION PLUS ONE DERIVED STAGING PATH — stated, not
// assumed (D24, amended). The commit requires a same-filesystem sibling, which literally writes
// outside the destination. The authorization is deliberately narrow, and narrowness is what keeps
// it a boundary: exactly ONE additional path, `<parent-of-destination>/.mythical-staging-<nonce>`,
// DERIVED from the destination rather than configured, so nothing outside can name it; RECORDED IN
// THE INTENT BEFORE IT IS CREATED, so it is attributable rather than discovered; and confinement
// applies within it too.
//
// THE GOVERNING RULE, IN ONE LINE: any mismatch PRESERVES. Nothing here writes, deletes or adopts
// on ambiguous or unreadable evidence; an ANSWER (absent, not-a-member, no) stays DISTINCT from a
// REFUSAL (the question could not be asked); a listing that cannot read one entry REFUSES rather
// than silently shortening; and a refusal partway through leaves NO partial mutation of the
// in-memory ledger, because the caller persists it with one write.
package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/runtime"
)

// Escaper is the copy step's own, already-validated escape rule (a symlink whose target is
// absolute, or whose '..' components climb above the root). It is reached through a seam rather
// than reimplemented so this package never grows a SECOND definition of "escapes" — the one
// definition lives with the copy helper, which is also the step that enforces it during the copy
// itself. Two spellings of that rule is how one of them stops matching.
type Escaper interface {
	LinkEscapes(linkPath, target, root string) bool
}

// StagingPath: STAGING IS A SIBLING OF THE DESTINATION, NEVER INSIDE IT. Putting staging inside
// the destination and then "atomically moving it into place" is renaming a directory onto its own
// parent, which the kernel refuses (ENOTEMPTY). A sibling on the same filesystem renames correctly
// onto a destination that does not exist OR is empty — the only two cases the non-empty-destination
// rule permits.
func StagingPath(dest, nonce string) string {
	return filepath.Join(filepath.Dir(dest), ".mythical-staging-"+nonce)
}

// Identity is a path's `device:inode`. rename() PRESERVES both, which is what makes the destination
// identifiable after a crash between the rename and the phase advance.
//
// BY Lstat, NEVER Stat: the identity of the path ITSELF, not of a symlink's target — so a swap to a
// symlink changes the observed identity and is caught, exactly as a swap to an ordinary different
// directory is.
func Identity(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("migrate: cannot read the identity of %q", path)
	}
	return fmt.Sprintf("%d:%d", sys.Dev, sys.Ino), nil
}

// verifyIdentity CLOSES THE TOCTOU AT THE POINT OF USE, not at the point of the check. A
// device+inode captured once and trusted for everything that follows is only as good as the
// assumption that nothing changes in between — and both trees this module touches are untrusted, so
// a parent directory an attacker can write to can replace a checked path with anything, including a
// symlink, between the check and whatever comes next.
//
// This NARROWS the window to the gap between this call and the very next thing that touches the
// path; it does not eliminate it. A process hands a PATH STRING to whatever it invokes next, never
// a held-open directory handle, so no check here can be perfectly atomic with an external process's
// own path resolution. Called immediately before each place that would otherwise re-resolve the
// path name after checking it once.
func verifyIdentity(path, want, what string) error {
	cur, err := Identity(path)
	if err != nil || cur != want {
		found := cur
		if found == "" {
			found = "<unreadable>"
		}
		return fmt.Errorf("migrate: %s no longer carries the identity this process recorded for it (expected\n"+
			"  %s, found %s). Between the check and this use, whatever is at\n"+
			"  %q changed. Refusing rather than operate on something this process never verified.",
			what, want, found, path)
	}
	return nil
}

// THIS PACKAGE'S THREE TEST SEAMS, for the same reason the config module keeps a read seam: three of
// the guards below defend against a state the filesystem will not produce on demand. A directory
// owned by a third, non-root uid cannot be created without root; a rename cannot be made to land on
// something other than what it just moved; and a freshly minted nonce does not collide. Without
// these, reverting any of those three guards in isolation would break nothing and no test would
// notice — and a guard whose deletion no test notices is not a guard. They are package-level
// function values, never parameters: no caller can pass a different one.
var (
	geteuid         = os.Geteuid
	renameDir       = os.Rename
	newReclaimNonce = intent.NonceNew
)

// dirSafety is why one directory on a path is NOT safe from a non-owner, non-root party.
type dirSafety int

const (
	dirSafe dirSafety = iota
	// dirForeignOwner — owned by neither this process's uid nor root.
	dirForeignOwner
	// dirGroupOrOtherWritable — the group-write or other-write bit is set.
	dirGroupOrOtherWritable
	// dirUnreadable — a stat this process could not perform. A FAILED READ IS A REFUSAL, never
	// assumed safe.
	dirUnreadable
)

// dirOwnerSafe is THE ONE DEFINITION OF "this directory cannot be renamed or replaced by a
// non-owner, non-root party" — shared by CheckParentTrust (the destination's parent) and
// secureStateDir's ancestor-chain walk (every directory from / down to a leaf this module secures).
// A single directory being owner-only-writable proves nothing on its own if something ABOVE it in
// the path can be renamed by someone else, so both callers need the identical per-directory question
// answered the identical way, never two hand-written copies that can drift.
//
// OWNERSHIP, NOT MODE BITS ALONE, is what actually excludes a third party: a privileged process
// bypasses mode-bit enforcement entirely, so a directory some OTHER uid owns may still be writable
// by them regardless of what its mode claims — UNLESS that owner is root (uid 0). A root-owned,
// non-other-writable directory IS accepted: only root could rename through it, and root is trusted
// by definition in this codebase's threat model (if root is adversarial nothing here holds
// regardless). That acceptance is also what makes an ancestor-chain walk POSSIBLE for a non-root
// operator: `/`, and most of the path above a typical home, are root-owned.
//
// dir must already be an absolute, resolved path; this does not canonicalize it.
func dirOwnerSafe(dir string) (dirSafety, string) {
	st, err := os.Lstat(dir)
	if err != nil {
		return dirUnreadable, ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return dirUnreadable, ""
	}
	euid := geteuid()
	if int(sys.Uid) != euid && sys.Uid != 0 {
		return dirForeignOwner, fmt.Sprintf("%d", sys.Uid)
	}
	mode := uint32(sys.Mode) & 0o7777
	// The group-write and other-write bits, whatever the total width of the octal string — a
	// leading setuid/setgid/sticky digit does not shift them.
	if mode&0o022 != 0 {
		return dirGroupOrOtherWritable, fmt.Sprintf("%o", mode)
	}
	return dirSafe, ""
}

// ancestorChain lists every ancestor directory of an absolute, canonical path, from / down to and
// including the path itself.
func ancestorChain(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("migrate: %q is not absolute", path)
	}
	out := []string{"/"}
	cur := ""
	for _, comp := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if comp == "" {
			continue
		}
		cur += "/" + comp
		out = append(out, cur)
	}
	return out, nil
}

// verifyChainOwnerSafe WALKS THE WHOLE ANCESTOR CHAIN of a canonical path (from / down to and
// including it) and refuses if ANY component fails dirOwnerSafe — the ONE walk-and-report
// implementation, shared by secureStateDir (the leaf it creates) and CheckParentTrust (the
// destination's parent), rather than two that can drift.
//
// `what` names what the path IS, in the caller's own voice ("the destination's parent directory",
// "the installer's own secure scratch location"), so one shared walk still reads naturally
// regardless of which caller is asking. Every refusal NAMES THE OFFENDING COMPONENT — the operator
// cannot fix a chain whose broken link is not identified.
func verifyChainOwnerSafe(canon, what string) error {
	chain, err := ancestorChain(canon)
	if err != nil {
		return err
	}
	for _, comp := range chain {
		switch safety, detail := dirOwnerSafe(comp); safety {
		case dirSafe:
		case dirForeignOwner:
			return fmt.Errorf("migrate: %q, on the path to %s, is owned by uid %s — neither\n"+
				"  this process's own uid nor root. Refusing: a directory ANYWHERE on the path that\n"+
				"  someone else can rename through makes everything below it worthless — they can\n"+
				"  rename it away and replace it with their own the instant after a check like this one\n"+
				"  passes. Choose a location whose whole chain this operator (or root) owns.", comp, what, detail)
		case dirGroupOrOtherWritable:
			return fmt.Errorf("migrate: %q, on the path to %s, is writable by its group or by everyone (mode\n"+
				"  %s). Refusing: a directory anyone else can write to lets them rename it\n"+
				"  away and replace it — the one class of attack a re-check immediately before each use\n"+
				"  cannot close without fd-relative filesystem operations. Restrict %q to the owner only\n"+
				"  (e.g. 'chmod 700 %s') and re-run.", comp, what, detail, comp, comp)
		default:
			return fmt.Errorf("migrate: could not verify the ownership or permissions of %q, on the path to\n"+
				"  %s. Refusing rather than guessing it is safe.", comp, what)
		}
	}
	return nil
}

// secureStateDir is THE INSTALLER'S OWN SECURE SCRATCH LOCATION — the ONE definition of "somewhere
// only this process can write". Any security-critical filesystem object this module creates — one
// whose CONTENTS or very PRESENCE gates a commit or identity decision — belongs under `<name>` here,
// never in a generic temp directory (an ATTACKER-INFLUENCEABLE location any co-resident process can
// also write to) and never as a sibling of the untrusted destination. In an attacker-writable
// directory, a pathname this process just created can be swapped for a symlink before it is ever
// opened, or its contents swapped before this process reads them back — TWO separate attacks,
// neither closable by re-checking faster, because there is no operation atomic with a check made a
// moment earlier against a name an attacker can also resolve. A directory only the operator can
// write to closes both by ACCESS CONTROL: there is no party left to run either race.
//
// EVERY PROPERTY IS POSITIVELY VERIFIED, never assumed from a prior call's own reported success —
// MkdirAll on a path that already exists as a symlink-to-directory succeeds silently without
// creating anything, and a privileged process bypasses ownership/mode-bit enforcement entirely, so a
// successful mkdir/chmod alone proves nothing about who else can write there. Checked in an order
// that never mutates through an unverified symlink: RESOLVE AND VERIFY HOME FIRST → create
// (idempotent) → refuse if it is a symlink → refuse if it is not a real directory → THEN chmod
// (only once the target is proven to be the real thing) → re-verify ownership and mode afterward
// rather than trust chmod's own exit status → re-walk the whole chain, because `.state` and
// `.state/<name>` did not exist when the upfront walk ran.
//
// HOME IS RESOLVED AND VERIFIED BEFORE ANY mkdir/chmod TOUCHES IT. Building the leaf from the RAW
// home and creating it before canonicalizing means an unsafe, attacker-repointable alias has already
// been MUTATED (a directory created and chmod'd at whatever it happened to resolve to) by the time
// the chain walk runs on the ALREADY-CREATED target and refuses. The refusal would be correct; the
// mutation that already happened through the unresolved alias would not.
//
// It returns the CANONICAL leaf it verified, never the raw one: a caller writing inside the raw
// path would still resolve through a symlink someone can repoint the instant after this returns —
// the very check-canonical/use-raw gap the whole chain walk exists to close.
func secureStateDir(home, name string) (string, error) {
	hcanon, err := runtime.Canon(home)
	if err != nil {
		return "", fmt.Errorf("migrate: %q does not resolve. Refusing to use it as the installer's own secure\n"+
			"  scratch location's home: %w", home, err)
	}
	if err := verifyChainOwnerSafe(hcanon, "the installer's own secure scratch location's home"); err != nil {
		return "", err
	}

	dir := filepath.Join(hcanon, ".state", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("migrate: cannot create the installer's own %q directory (%s): %w", name, dir, err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("migrate: cannot inspect %q. Refusing to use it as the installer's own secure\n"+
			"  scratch location: %w", dir, err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("migrate: %q is a symlink, not a real directory. Refusing to use it as the installer's\n"+
			"  own secure scratch location — a name this process does not control the target of is not\n"+
			"  a safe place to put anything a commit or identity decision depends on.", dir)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("migrate: %q exists and is not a directory. Refusing to use it as the installer's own\n"+
			"  secure scratch location.", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("migrate: cannot restrict %q to owner-only. Refusing to use a directory this process\n"+
			"  cannot itself prove is safe: %w", dir, err)
	}
	// RE-VERIFIED AFTER THE CHMOD, never trusted from the chmod's own success.
	st2, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("migrate: could not re-read %q after restricting it. Refusing to trust it unverified: %w", dir, err)
	}
	sys, ok := st2.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("migrate: could not read the owner of %q. Refusing to trust it unverified.", dir)
	}
	if int(sys.Uid) != geteuid() {
		return "", fmt.Errorf("migrate: %q is owned by uid %d, not this process's own uid (%d). Refusing to\n"+
			"  use it as the installer's own secure scratch location — a directory someone else owns may\n"+
			"  still be writable by them regardless of what chmod just set.", dir, sys.Uid, geteuid())
	}
	if mode := uint32(sys.Mode) & 0o7777; mode&0o022 != 0 {
		return "", fmt.Errorf("migrate: %q is writable by its group or by everyone (mode %o) even after\n"+
			"  chmod 700 — refusing to trust it as the installer's own secure scratch location.", dir, mode)
	}

	// THE WHOLE ANCESTOR CHAIN, NOT JUST THE LEAF — re-verified on top of the upfront home check,
	// because home alone does not cover `.state` or `.state/<name>`: those two components did not
	// exist before this call's own MkdirAll created them, so they were never part of the chain the
	// upfront walk verified. A directory is only as trustworthy as the least-trusted directory ON
	// THE PATH TO IT.
	lcanon, err := runtime.Canon(dir)
	if err != nil {
		return "", fmt.Errorf("migrate: %q does not resolve. Refusing to use it as the installer's own secure scratch\n"+
			"  location: %w", dir, err)
	}
	if err := verifyChainOwnerSafe(lcanon, "the installer's own secure scratch location"); err != nil {
		return "", err
	}
	return lcanon, nil
}

// ErrIncompleteWalk marks a tree walk that did not finish — an unreadable subdirectory, an entry
// that vanished mid-walk. It is its own error precisely so no caller can fold it into "nothing
// found": "could not fully scan" is not "there is nothing there".
var ErrIncompleteWalk = errors.New("migrate: the walk did not complete cleanly")

// VerifyNoEscapingSymlinks re-walks a staged tree HOST-SIDE, immediately before the commit, and
// refuses any symlink the copy step's own escape rule rejects.
//
// A DIRECTORY'S OWN IDENTITY (verifyIdentity) proves it was not SWAPPED; it says nothing about what
// is INSIDE it — adding an entry, or replacing a file with a symlink, changes nothing about the
// containing directory's inode. Between the copy's verification and the commit, whoever holds the
// runtime uid's write grant on the staging tree — a grant every legitimate migration's copy step
// must set, so it cannot simply be denied — could plant an ESCAPING symlink inside it. This is the
// cheapest host-side check that targets specifically what an inode check cannot see; it is NOT a
// full re-verification against the source (that already happened, expensively, in the copy helper).
// Called immediately before the commit, it narrows the remaining window to the time of this walk
// itself — it does not eliminate it.
//
// THE WALK FAILS CLOSED. Nothing about a partial walk may read as a clean tree: an unreadable
// subdirectory, a vanished entry, or an unreadable symlink target is refused outright. It does not
// FOLLOW any symlink it encounters, matching the copy step's own walk discipline.
//
// PORT NOTE — THERE IS NO SCRATCH FILE. The reference had to spool the walk's NUL-delimited output
// through a temp file, and therefore had to place that file somewhere no other party could swap it;
// that placement (and its own fail-closed checks) was the whole reason this function reached for the
// installer's secure scratch directory. This walk holds its results in process memory, so the file
// the attacks targeted does not exist and neither attack has anything to act on. secureStateDir is
// retained for StagingReclaim, which genuinely needs a private directory to rename into.
func VerifyNoEscapingSymlinks(esc Escaper, root string) error {
	if esc == nil {
		return errors.New("migrate: no escape rule to check the staged tree against — refusing to commit a tree\n" +
			"  nothing examined.")
	}
	canon, err := runtime.Canon(root)
	if err != nil {
		return fmt.Errorf("migrate: %q does not resolve, so its contents cannot be re-verified before the commit: %w", root, err)
	}
	var refusal error
	werr := filepath.WalkDir(canon, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%w: %q could not be read: %v", ErrIncompleteWalk, p, err)
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, rerr := os.Readlink(p)
		if rerr != nil {
			refusal = fmt.Errorf("migrate: could not read the target of the symlink at %q in the staged tree, immediately\n"+
				"  before the commit. Refusing to commit an entry this process cannot show does not escape: %w", p, rerr)
			return filepath.SkipAll
		}
		if esc.LinkEscapes(p, target, canon) {
			refusal = fmt.Errorf("migrate: the staged tree contains a symlink that escapes it, found on the re-check\n"+
				"  immediately before the commit: %q -> %q.\n"+
				"  This is the same escape rule the copy step itself enforces (an absolute target, or one\n"+
				"  whose '..' components climb above the root) — refusing to commit it rather than carry\n"+
				"  it into the replacement container's bind.", p, target)
			return filepath.SkipAll
		}
		return nil
	})
	if werr != nil {
		return fmt.Errorf("migrate: the walk of %q for escaping symlinks did not complete cleanly, so this cannot\n"+
			"  show the staged tree contains no escaping symlink. Refusing to commit over an incomplete\n"+
			"  scan — 'could not fully scan' is not 'nothing found': %w", canon, werr)
	}
	return refusal
}

// MountTable is the system's mount list. It is a seam because the hermetic suite cannot create real
// mounts, and because the two platforms answer the question through different files.
//
// AN ERROR IS "COULD NOT BE READ", NEVER "there are no mount points". A caller that folds the two
// together proceeds on an absence of evidence rather than evidence of absence.
type MountTable interface {
	MountPoints() ([]string, error)
}

// SystemMounts reads the real mount table.
type SystemMounts struct{}

// MountPoints reads /proc/self/mountinfo where it exists (Linux, authoritative — it carries a
// distinct mount ID per mount), and otherwise parses the platform `mount` output.
//
// There is deliberately NO `mount -p` attempt: macOS rejects the flag, so it buys nothing there, and
// on a BSD where it IS supported it prints fstab format this parser does not read — WHILE
// SUCCEEDING, which would suppress the fallback and silently make this check find nothing. A probe
// that quietly finds nothing is worse than one that is not attempted.
func (SystemMounts) MountPoints() ([]string, error) {
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		var out []string
		for _, line := range strings.Split(string(data), "\n") {
			// fields: id parent major:minor root mountpoint ...
			f := strings.Fields(line)
			if len(f) >= 5 {
				out = append(out, unmangleOctal(f[4]))
			}
		}
		return out, nil
	}
	return platformMountPoints()
}

// unmangleOctal decodes the \octal escapes the kernel writes into mountinfo for space, tab,
// newline and backslash. A mount point containing a space would otherwise be read short, and a
// short mount point is a comparison that silently never matches.
func unmangleOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) {
			v := 0
			ok := true
			for k := 1; k <= 3; k++ {
				c := s[i+k]
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + int(c-'0')
			}
			if ok {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// IsMountPoint reports whether path is itself a mount point.
//
// DETECTION MUST CONSULT MOUNT-TABLE EVIDENCE. Comparing st_dev with the parent's does NOT detect
// this on its own: a bind mount of the same filesystem carries the same device number as its parent
// and is still unreplaceable, so a MATCHING st_dev is not conclusive of "not a mount point" — only a
// DIFFERING st_dev is conclusive of the opposite. The device comparison below is therefore a cheap
// first filter, never the test on its own.
//
// THE THREE ANSWERS: (true, nil) it IS a mount point · (false, nil) it is NOT (established
// positively, or the path does not resolve/exist at all — nothing there cannot be a mount point) ·
// (false, err) it COULD NOT BE ESTABLISHED. The third is carried as an ERROR precisely so a caller
// cannot fold it into the second by accident: Go's convention checks the error first.
//
// PORT NOTE — ORDERING. The reference consults its test hook first, then the existence and device
// filters, then the real table. Here the table IS the seam, so its RESULT is consulted first and its
// FAILURE is handled at the same point the reference handles it: after the structural filters, so
// an unreadable table over a destination that does not exist yet still answers "not a mount point"
// rather than refusing every ordinary migration on a host whose table cannot be read.
func IsMountPoint(mt MountTable, path string) (bool, error) {
	if mt == nil {
		return false, errors.New("migrate: no mount table to consult, so whether the destination is a mount point\n" +
			"  cannot be established. Refusing rather than treating 'could not determine' as 'not a\n" +
			"  mount point'.")
	}
	canon, err := runtime.Canon(path)
	if err != nil {
		return false, nil
	}
	entries, terr := mt.MountPoints()
	if terr == nil {
		for _, e := range entries {
			// Each declared entry is canonicalized before the comparison too — a mount point
			// reported through a symlinked component is not the same STRING as the canonical
			// destination, and comparing raw against canonical would silently never match.
			ec, cerr := runtime.Canon(e)
			if cerr != nil {
				continue
			}
			if ec == canon {
				return true, nil
			}
		}
	}
	if st, serr := os.Stat(canon); serr != nil || !st.IsDir() {
		return false, nil
	}
	if d, derr := deviceOf(canon); derr == nil {
		if pd, perr := deviceOf(filepath.Dir(canon)); perr == nil && d != pd {
			return true, nil
		}
	}
	if terr != nil {
		return false, fmt.Errorf("migrate: the mount table could not be read, so whether %q is\n"+
			"  a mount point cannot be established. Refusing rather than treating 'could not determine'\n"+
			"  as 'not a mount point': %w", canon, terr)
	}
	return false, nil
}

func deviceOf(p string) (int64, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("migrate: cannot read the device of %q", p)
	}
	return int64(sys.Dev), nil
}

// CheckParentTrust is THE REAL SECURITY POSTURE, STATED PLAINLY.
//
// There are no fd-relative *at() operations in play here (openat/renameat/unlinkat confined to an
// already-open directory handle). Every check this module makes resolves a PATH NAME, and between
// that resolution and whatever uses the result, anyone who can ALSO write the same parent directory
// can rename or replace what the name refers to. A re-check immediately before each use narrows that
// window; it cannot close it. What CAN be closed is the premise: if NO ONE besides this process can
// write the parent directory in the first place, there is no party left to run the race, regardless
// of how wide the window is. Staging lives as a SIBLING of the destination, in the very same parent,
// so ONE check here covers both.
//
// THE WHOLE CHAIN, not merely the immediate parent. Canonicalizing resolves the parent to a SAFE
// target, but if anything ABOVE that parent is group/other-writable, the parent itself (or an
// ancestor's symlink component resolving into it) can be renamed or repointed by someone else the
// instant after this check passes.
func CheckParentTrust(dest string) error {
	pdir := filepath.Dir(dest)
	canon, err := runtime.Canon(pdir)
	if err != nil {
		return fmt.Errorf("migrate: the destination's parent directory %q does not resolve. Refusing: %w", pdir, err)
	}
	return verifyChainOwnerSafe(canon, "the destination's parent directory")
}

// canonDest CANONICALIZES THE DESTINATION EXACTLY ONCE, AT THE BOUNDARY WHERE IT ENTERS THE
// MIGRATION — every caller downstream (staging, the copy, the rename, the bind, and what gets
// recorded in the ledger and reported back) must then use ONLY this value, never the raw operand
// again.
//
// Checking a canonical parent and then acting on the RAW destination is the exact gap this closes:
// with --to-bind /shared/target/dest (/shared group-writable, target a symlink into a safe tree), a
// check against the canonical target passes, but every subsequent write following the RAW path still
// follows target — which a group member can repoint the instant after the check, redirecting every
// write out of the approved location. Once every caller uses the SAME canonical value
// CheckParentTrust just verified, check-time and use-time are identical and there is no symlinked
// component left for a non-root party to swap.
//
// The destination's own LEAF may not exist yet (the ordinary state for a fresh migration), so it is
// resolved via its PARENT, which the other precheck rules already require to exist. A failed resolve
// is a REFUSAL, never a silent fall-back to the raw value.
func canonDest(dest string) (string, error) {
	pdir := filepath.Dir(dest)
	pcanon, err := runtime.Canon(pdir)
	if err != nil {
		return "", fmt.Errorf("migrate: the destination's parent directory %q does not resolve. Refusing: %w", pdir, err)
	}
	return filepath.Join(pcanon, filepath.Base(dest)), nil
}

// Where names which of the two candidate paths carries the recorded identity.
type Where string

const (
	// AtDestination — the rename completed; advance to phase 6.
	AtDestination Where = "destination"
	// AtStaging — the rename had not run; retry phase 5.
	AtStaging Where = "staging"
)

// ResolvePhase5 decides on POSITIVE EVIDENCE ONLY, and stops when it has none.
//
//	identity at the DESTINATION  the rename completed   → advance to phase 6
//	identity at STAGING          the rename had not run → retry phase 5
//	NOWHERE                      unattributable — the rename may have succeeded and been replaced
//	                             since → stop and report. Never touch either path again on its own.
//
// Acting again on the strength of an ABSENCE is the same error as removing on the strength of a
// NAME.
func ResolvePhase5(dest, stage, want string) (Where, error) {
	d, _ := Identity(dest)
	s, _ := Identity(stage)
	if d != "" && d == want {
		return AtDestination, nil
	}
	if s != "" && s == want {
		return AtStaging, nil
	}
	return "", fmt.Errorf("migrate: the recorded directory identity (%s) is at neither the destination nor the\n"+
		"  staging path. That is unattributable: the rename may already have completed and the\n"+
		"  destination may have been replaced since, in which case trying again would copy over\n"+
		"  whatever replaced it, and the original migrated data would already be gone. This stops\n"+
		"  here and reports. Nothing here is touched or taken away — inspect both paths and decide.", want)
}

// ResumePhase decides where a resume actually starts. RESUME MUST VERIFY, NOT TRUST.
//
// The recorded phase is a WRITE-AHEAD intent — written BEFORE the phase's own action runs, precisely
// so a crash mid-action still names the phase that was in progress. That same property means a
// recorded phase of 6 or later does NOT, by itself, prove phase 5's rename ever produced a
// destination: phases 1-5 are each the first place that establishes their own postcondition, so
// resuming AT any of them is always well-defined, but 6 (write the config) through 9 (restore
// desired state) all depend on phase 5's result already being on disk.
//
// Verified the same way phase 5 itself verifies: the recorded device+inode, found or not, is the ONLY
// evidence trusted — never the destination's mere presence, and never its absence either. If it does
// not check out, resume falls back to phase 5, where the same resolve-and-recover logic re-derives
// the true state and phases 6 on repeat over it. The source volume is untouched throughout, so
// redoing this tail is always well-defined.
func ResumePhase(phase int, dest, stageid string) int {
	if phase >= 1 && phase <= 5 {
		return phase
	}
	if stageid != "" {
		if cur, err := Identity(dest); err == nil && cur == stageid {
			return phase
		}
	}
	return 5
}

// StagingReclaim removes a leftover staging directory — ONLY on a nonce AND device/inode match.
//
// A RECOGNISABLE STAGING NAME IS NOT AUTHORITY. The destination is untrusted, so after a crash a
// directory bearing our staging name may be attacker-placed or may be replacement user data.
// Recovery verifies the NONCE recorded in the intent AND the directory's IMMUTABLE IDENTITY
// (device + inode) before removing anything, and PRESERVES AND REPORTS on any mismatch.
//
// ATOMIC RECLAIM INTO AN INSTALLER-OWNED DIRECTORY — NOT ANOTHER NAME IN THE SAME PARENT. Renaming
// the leftover to a different name still inside the same (untrusted) parent does not close the
// check-then-rm race: whoever can write that parent can rename the NEW name away and replace it too,
// exactly as easily as the old one. A different name in the same unsafe place only MOVES the race.
// What closes it is a different DIRECTORY: one under this installer's own `.state` tree, mode 0700,
// that the untrusted parent's writer cannot reach at all. This is the one place in this package
// where "operate somewhere safe" (an access-control property) replaces "recheck immediately before
// use" (a timing property nothing here can make atomic).
//
// SAME FILESYSTEM IS REQUIRED for the move to be the atomic rename this safety depends on — a
// cross-device move degrades into a recursive copy followed by an ordinary recursive delete of the
// ORIGINAL, untrusted-parent path, which is exactly the unsafe pattern this exists to avoid. Checked
// BEFORE attempting the move, by comparing device numbers, not discovered after the fact.
//
// This is a TOOL, not a step any flow calls on its own: reclaiming an operator's disk space is never
// automatic.
func StagingReclaim(home, stage, recordedNonce, recordedID, pathNonce string) error {
	st, err := os.Lstat(stage)
	if err != nil || !st.IsDir() {
		return nil // nothing there: nothing to reclaim, and nothing to report
	}
	cur, _ := Identity(stage)
	if pathNonce != recordedNonce || cur == "" || cur != recordedID {
		found := cur
		if found == "" {
			found = "<unreadable>"
		}
		return fmt.Errorf("migrate: the staging directory %s does not match the recorded intent\n"+
			"    recorded nonce=%s identity=%s\n"+
			"    found    nonce=%s identity=%s\n"+
			"  it is preserved and reported. A name can be reassigned to something this installer never\n"+
			"  created, so the name alone is not authority to remove it. Whether to reclaim the space is\n"+
			"  your call; a retry proceeds beside it with a fresh nonce and a fresh path.",
			stage, recordedNonce, recordedID, pathNonce, found)
	}

	rdir, err := secureStateDir(home, "reclaim")
	if err != nil {
		return fmt.Errorf("%w\nmigrate: nothing was removed.", err)
	}
	rid, rerr := Identity(rdir)
	if rerr != nil || !sameDeviceID(cur, rid) {
		return fmt.Errorf("migrate: the staging directory %s and the installer's reclaim directory %s are on\n"+
			"  different filesystems, so moving into it would not be the atomic, same-device rename this\n"+
			"  safety depends on — the move would fall back to a recursive copy-then-remove that deletes\n"+
			"  the ORIGINAL by its untrusted-parent name, which is exactly what this function exists to\n"+
			"  avoid. It is preserved and reported rather than reclaimed unsafely; removing it by hand is\n"+
			"  your call.", stage, rdir)
	}
	tag, err := newReclaimNonce()
	if err != nil {
		return fmt.Errorf("migrate: could not mint a reclaim path: %w", err)
	}
	priv := filepath.Join(rdir, tag)
	if _, err := os.Lstat(priv); err == nil {
		return fmt.Errorf("migrate: the private reclaim path %s already exists. Refusing rather than risk the move\n"+
			"  nesting the staging directory inside it instead of claiming it exclusively.", priv)
	}
	if err := renameDir(stage, priv); err != nil {
		return fmt.Errorf("migrate: could not rename the staging directory %s into the installer's own reclaim\n"+
			"  directory. Nothing was removed: %w", stage, err)
	}
	vid, verr := Identity(priv)
	if verr != nil || vid != recordedID {
		found := vid
		if found == "" {
			found = "<unreadable>"
		}
		return fmt.Errorf("migrate: after renaming %s to reclaim it, the renamed directory (now at %s, inside\n"+
			"  the installer's own reclaim directory) no longer carries the identity just verified\n"+
			"  (expected %s, found %s) — something replaced it in the instant between\n"+
			"  the check and the rename. It is preserved at %s, not deleted, and not renamed back onto\n"+
			"  a name that may already be reassigned.", stage, priv, recordedID, found, priv)
	}
	if err := os.RemoveAll(priv); err != nil {
		return fmt.Errorf("migrate: could not remove the staging directory (renamed to %s, inside the installer's\n"+
			"  own reclaim directory, to reclaim it): %w", priv, err)
	}
	return nil
}

// sameDeviceID compares the DEVICE half of two `device:inode` identities. Split out so the
// comparison itself is directly testable: a cross-device pair cannot be conjured on an arbitrary
// host, and an untested comparison here would silently let the reclaim degrade into the recursive
// copy-then-delete it exists to avoid. An unreadable identity on either side is NOT a match.
func sameDeviceID(a, b string) bool {
	da, _, oka := strings.Cut(a, ":")
	db, _, okb := strings.Cut(b, ":")
	if !oka || !okb || da == "" || db == "" {
		return false
	}
	return da == db
}
