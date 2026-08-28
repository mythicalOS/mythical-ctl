//go:build darwin

package backup

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace is renamex_np(2) with RENAME_EXCL: the rename happens only if `to` does not
// already name a directory entry, and the decision is the kernel's, taken once, with nothing
// able to race between it and the move. It is the macOS counterpart of Linux's
// renameat2(RENAME_NOREPLACE), and it has been available since 10.12.
func renameNoReplace(from, to string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_EXCL)
}

// noReplaceUnsupported reports whether err says the FILESYSTEM cannot do this, as opposed to
// saying something about these two paths. renamex_np is implemented by APFS and HFS+; a mount
// that is neither (a FUSE filesystem, some network mounts) answers ENOTSUP. EINVAL is included
// for the same reason as on Linux and with the same bounded cost: the fallback it selects has
// the same two guarantees as the primitive. EEXIST is not in the list — it is the answer this
// file exists to obtain, and it is handled before this function is consulted.
func noReplaceUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL)
}
