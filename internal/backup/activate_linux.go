//go:build linux

package backup

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace is renameat2(2) with RENAME_NOREPLACE: the rename happens only if `to` does
// not already name a directory entry, and the decision is the kernel's, taken once, with
// nothing able to race between it and the move.
//
// AT_FDCWD with absolute paths: both callers derive their paths from the family home, which is
// already absolute, so there is no directory handle to thread and no relative resolution to get
// wrong.
func renameNoReplace(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}

// noReplaceUnsupported reports whether err says the KERNEL OR FILESYSTEM cannot do this, as
// opposed to saying something about these two paths.
//
// EINVAL IS IN THE LIST ON PURPOSE, AND IT IS THE INTERESTING ONE. rename(2) documents EINVAL
// for "flags is unsupported by the filesystem" — which is what several filesystems answer
// rather than ENOSYS — and ENOSYS only for a kernel with no renameat2 at all (pre-3.15). EINVAL
// is also the errno for genuinely invalid arguments, so classifying it as "unsupported" is
// deliberately over-broad; the cost of being wrong is bounded, because the fallback it selects
// has the same two guarantees as the primitive. What is NOT in the list is EEXIST, which is the
// answer this whole file exists to obtain and is handled before this function is consulted.
func noReplaceUnsupported(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)
}
