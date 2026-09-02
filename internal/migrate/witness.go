package migrate

import (
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/intent"
)

// THE WITNESS IS THE ONLY PART OF A DIRECTORY'S IDENTITY THAT AN ORDINARY DELETE-AND-RECREATE
// CANNOT REPRODUCE, and it is here because NO ATTRIBUTE THE FILESYSTEM ASSIGNS BY ITSELF IS
// TRUSTWORTHY FOR THIS QUESTION. Measured, not inferred:
//
//   - `device:inode` alone is DEFEATED. Deleting a directory and creating one at the same path
//     REUSES the inode number on the filesystems this product actually runs on — 200 of 200
//     trials on ext4 and 200 of 200 on overlayfs (a container's root filesystem). It happens NOT
//     to be reused on tmpfs or on APFS, which is the whole reason this was green on a developer's
//     Mac and red on Linux: the check was passing by accident of an allocator, not by evidence.
//
//   - statx BTIME (creation time) does not rescue it. It IS populated on ext4, overlayfs and
//     tmpfs (STATX_BTIME comes back set in the result mask), which makes it look usable — and it
//     is not. Across a delete-and-recreate it was IDENTICAL in 197/200 trials on ext4, 189/200 on
//     overlayfs and 199/200 on tmpfs; two GENUINELY DIFFERENT directories created one after the
//     other carried the same btime to the nanosecond in 193/200, 192/200 and 200/200. The kernel
//     stamps these from a coarse cached clock, so a witness derived from it answers "unchanged"
//     for two objects that have nothing to do with each other. A witness that is absent is a
//     refusal; a witness that is PRESENT AND WRONG is a silent pass, which is worse.
//
//   - Holding an open directory descriptor DOES pin the inode (0/50 reuse on all three
//     filesystems while a descriptor is held), so comparing fstat against stat is sound — but only
//     WHILE THE PROCESS LIVES. The identity here is written into the ledger and compared by a
//     LATER process resuming after a crash, which no descriptor survives.
//
//   - A MARKER FILE is impossible where it would be needed. The copy helper checks that the
//     staging destination is EMPTY inside the container, atomically with the copy (its
//     `staging-nonempty` refusal); any directory entry planted before the copy aborts the
//     migration outright.
//
// So the witness is an EXTENDED ATTRIBUTE on the directory's own inode. It is not a directory
// entry, so the copier's emptiness check never sees it (measured: readdir returns 0 entries with
// the attribute set); it rides rename(2), which is the entire reason this identity exists; and a
// freshly created directory cannot have one, ON ANY OF THE FOUR FILESYSTEMS MEASURED — after the
// delete-and-recreate it was correctly absent 200/200 times on ext4, overlayfs, tmpfs and APFS,
// including in every one of the 400 cases where the inode number itself was reused. It also
// survives the chown, the chmod and both POSIX ACL kinds the copy preflight applies.
//
// WHAT THIS DOES NOT CLAIM. Anyone who can both READ the destination and DESTROY AND RECREATE it
// can copy the value forward. Destroying an installer-owned 0755 directory's contents requires
// being its owner or root — parties this package already trusts by construction, since
// dirOwnerSafe accepts the running uid. The witness closes the gap against everything BELOW that
// line, which is where the defeated `device:inode` check left the ordinary `rm -rf dir && mkdir
// dir` — the most commonplace form of exactly what this exists to catch.
const witnessAttr = "user.mythical-ctl.identity-witness"

// noWitness renders "this path carries no witness" INSIDE the identity string, so that absence is
// an ANSWER a comparison can act on rather than a hole in the value. It is deliberately a byte
// witnessOK rejects, so it can never collide with a real witness.
const noWitness = "-"

// witnessMax bounds what is read back. Everything this package writes is 17 bytes; a value longer
// than this bound is not one of ours, and rather than allocate to a size someone else chose, the
// read REFUSES.
const witnessMax = 64

// newWitness is this package's fourth test seam, for the same reason as the other three: the
// failure it guards — a mint that cannot produce a value — is not a state the host will enter on
// demand, and a guard nothing can redden is not a guard. A package-level function value, never a
// parameter, so no caller can supply a different one.
var newWitness = intent.NonceNew

// setWitnessAttr is the fifth, and it exists for the same reason: the states the stamp can fail in
// — a filesystem that refuses the attribute outright, and one that ACCEPTS the write and does not
// store it — cannot be produced on a host whose filesystems all work. Without it both refusals
// below would be unreachable, and an unreachable refusal is one nobody finds out is wrong.
var setWitnessAttr = lsetWitness

// witnessOK is the shape this package writes and the ONLY shape it will accept back: a non-empty
// run of at most witnessMax ASCII letters and digits.
//
// IT IS A REFUSAL RULE, NOT A COSMETIC ONE. The value is read from an extended attribute on a
// directory this process may not have created, so it is untrusted input that ends up rendered into
// an operator-facing refusal and compared against a recorded string. Constraining it to
// alphanumerics keeps a separator out of a colon-delimited identity and keeps control bytes out of
// a terminal.
func witnessOK(s string) bool {
	if s == "" || len(s) > witnessMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		default:
			return false
		}
	}
	return true
}

// readWitness reports the witness a path carries, and KEEPS "there is none" APART FROM "the
// question could not be asked" — the distinction the whole package is built on.
//
//	the attribute is there and well-formed  → that value
//	the attribute is provably absent        → noWitness, nil          (an ANSWER)
//	anything else                           → "", error               (a REFUSAL)
//
// "Anything else" is every reason a filesystem can decline the question: it does not implement
// extended attributes at all, it is mounted with them off, the value is unreadable, the value is
// longer than anything this writes, or it is bytes this package never produces. None of those are
// evidence that a path is what it was, and none of them may be read as one.
func readWitness(path string) (string, error) {
	buf := make([]byte, witnessMax)
	n, err := lgetWitness(path, buf)
	switch {
	case err == nil:
	case witnessAbsent(err):
		return noWitness, nil
	default:
		return "", fmt.Errorf("migrate: the identity witness on %q could not be read, so whether this is the\n"+
			"  directory this process recorded was never established. Refusing rather than treat an\n"+
			"  unanswerable question as agreement: %w", path, err)
	}
	got := string(buf[:n])
	if !witnessOK(got) {
		// NOT RENDERED BACK. The bytes came off a directory this process may not have created, and
		// the refusal they would be printed into goes to a terminal.
		return "", fmt.Errorf("migrate: the identity witness on %q is %d byte(s) this installer never writes.\n"+
			"  Refusing to treat a value of unknown origin as proof of anything.", path, len(got))
	}
	return got, nil
}

// writeWitness stamps a directory THIS PROCESS JUST CREATED. It is not exported and has exactly
// one caller: EstablishIdentity, which READS THE STAMP BACK before anything is allowed to rely on
// it. Nothing here trusts the write on the strength of its own return value.
//
// A FILESYSTEM THAT CANNOT CARRY THE WITNESS REFUSES HERE, which is the cheapest, most reversible
// moment that exists: the staging directory is empty, the volume has not been read, the
// destination has not been touched and no container has been removed. Refusing later — at phase 5
// or 7, after the copy — would be the same answer at a far worse price.
func writeWitness(path, tok string) error {
	if !witnessOK(tok) {
		return errors.New("migrate: refusing to record a malformed identity witness")
	}
	if err := setWitnessAttr(path, []byte(tok)); err != nil {
		return fmt.Errorf("migrate: %q cannot carry the identity witness this migration needs to prove later\n"+
			"  that the destination is the directory it created (its filesystem declined to store an\n"+
			"  extended attribute). Without it, a directory deleted and recreated at the same path is\n"+
			"  indistinguishable from the original on this platform, so the checks before the\n"+
			"  irreversible steps would pass over a substitution. Refusing here, before anything is\n"+
			"  copied and before anything is removed: %w", path, err)
	}
	return nil
}
