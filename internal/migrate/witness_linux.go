//go:build linux

package migrate

import (
	"errors"

	"golang.org/x/sys/unix"
)

// lgetWitness / lsetWitness read and write the witness attribute on the path ITSELF.
//
// THE `l` FORMS, NEVER THE PLAIN ONES. getxattr(2) follows a symlink; lgetxattr(2) does not. A
// path swapped for a symlink into an attribute-bearing directory must read as "no witness here",
// not as the target's witness — otherwise the substitution this identity exists to catch would
// answer with the original's own evidence. Measured on ext4, overlayfs and tmpfs: through a
// symlink to a stamped directory, lgetxattr reports the attribute ABSENT.
func lgetWitness(path string, buf []byte) (int, error) {
	return unix.Lgetxattr(path, witnessAttr, buf)
}

func lsetWitness(path string, val []byte) error {
	return unix.Lsetxattr(path, witnessAttr, val, 0)
}

// witnessAbsent is TRUE FOR EXACTLY ONE CONDITION: the path was readable and carries no such
// attribute. Linux reports that as ENODATA.
//
// EOPNOTSUPP (the filesystem has no extended attributes), EACCES, ERANGE and everything else are
// deliberately NOT absence — they are the question failing, and readWitness turns them into a
// refusal. Folding "this filesystem cannot answer" into "there is nothing there" is precisely the
// silent pass this package forbids.
func witnessAbsent(err error) bool { return errors.Is(err, unix.ENODATA) }
