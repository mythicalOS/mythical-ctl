//go:build darwin

package migrate

import (
	"errors"

	"golang.org/x/sys/unix"
)

// lgetWitness / lsetWitness read and write the witness attribute on the path ITSELF — see the
// linux file for why the `l` (XATTR_NOFOLLOW) forms are the only ones that answer the right
// question. Measured on APFS: through a symlink to a stamped directory, the attribute reads as
// absent.
func lgetWitness(path string, buf []byte) (int, error) {
	return unix.Lgetxattr(path, witnessAttr, buf)
}

func lsetWitness(path string, val []byte) error {
	return unix.Lsetxattr(path, witnessAttr, val, 0)
}

// witnessAbsent is TRUE FOR EXACTLY ONE CONDITION: the path was readable and carries no such
// attribute. Darwin reports that as ENOATTR, which is a DIFFERENT errno from Linux's ENODATA —
// the one place the two platforms diverge, and the reason this pair is split per platform at all.
//
// ENOTSUP, EACCES, ERANGE and everything else are the question failing, not an answer.
func witnessAbsent(err error) bool { return errors.Is(err, unix.ENOATTR) }
