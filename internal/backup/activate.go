package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ACTIVATION IS ONE ATOMIC, NO-REPLACE STEP — the file that closes phase 6.
//
// WHY NOT A CHECK PLUS A RENAME. The obvious shape is `if the live ledger is not there { rename
// the staging one onto it }`, and it is wrong twice over.
//
//   - The CHECK is not a check. `[ -f p ]` — os.Stat plus IsRegular — is false for four
//     different facts: nothing is there, a DANGLING symlink is there, a FIFO or a directory is
//     there, and the path could not be examined at all. Only the first is an absence. The other
//     three are refusals, and reading them as an absence is how a verb concludes a machine is
//     empty and then writes over the thing standing at the name it just decided was free.
//   - The RENAME is not conditional. rename(2) REPLACES. Whatever the check concluded, the
//     window between the check and the call belongs to anything else on the machine — another
//     copy of this tool built before the family lock existed, an operator restoring a ledger by
//     hand, a scheduled job. A regular ledger that appears inside that window is destroyed, and
//     with it the provenance of every running container of the installation that is there now.
//
// So the guard is not a check at all: it is the rename's own atomicity. The kernel decides,
// once, whether the destination is free, and installs the file only if it is. Nothing races it,
// and nothing that already occupies the name — of any type — can be replaced.
//
// THE PRIMITIVE, PER PLATFORM. Linux has renameat2(RENAME_NOREPLACE); macOS has
// renamex_np(RENAME_EXCL). Those are exactly the two operating systems this project publishes
// (see tools/release-verify's target matrix), so both supported platforms have a real one and
// there is no platform on which this degrades silently — a build for a third GOOS does not
// compile rather than quietly picking a replacing rename. TestPlatformNoReplaceRenameIsAvailable
// measures the claim rather than restating it.
//
// THE FALLBACK IS FOR FILESYSTEMS, NOT FOR PLATFORMS. Both primitives are refused by some
// filesystems rather than by some kernels — Linux answers EINVAL (or ENOSYS on a kernel older
// than the call) when the filesystem does not implement the flag, macOS answers ENOTSUP off
// APFS/HFS+. On such a mount the choice is between refusing every activation and using a
// different primitive with the same two properties. link+unlink has them: link(2) fails with
// EEXIST if the destination exists, and it is a single atomic step. It is used ONLY for those
// errnos, and never as a way to get past an EEXIST.

// activateRename installs `from` at `to`, atomically, and ONLY if nothing occupies `to`.
//
// It returns an error satisfying errors.Is(err, fs.ErrExist) when something is already at `to`
// — of any type, a dangling symlink and a FIFO included, because both are existing directory
// entries. Every other failure is returned as itself: "the parent directory is missing" and
// "something is already there" are different facts and the caller says different things about
// them.
func activateRename(from, to string) error {
	err := renameNoReplace(from, to)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		// An ANSWER: the destination is occupied. Never retried through the fallback — that
		// would be asking a second implementation for a different answer to a settled question.
		return err
	case !noReplaceUnsupported(err):
		return err
	}
	return linkThenUnlink(from, to)
}

// linkThenUnlink is the documented fallback for a filesystem whose kernel no-replace rename is
// refused. Same contract as activateRename, including the fs.ErrExist signal.
//
// THE UNLINK IS CHECKED, AND ITS FAILURE IS NOT AN ACTIVATION FAILURE. Once link(2) returns,
// the restored ledger IS at the active name and the installation IS live; a failed unlink
// leaves a second link to the same inode at the staging name and changes nothing about that.
// Reporting it as "activation failed" would tell the operator to try again on a machine that is
// already restored. So it is returned as its own distinctly-worded error and the caller reports
// the residue rather than the operation.
func linkThenUnlink(from, to string) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	if err := os.Remove(from); err != nil {
		return fmt.Errorf("%w: %w", errActivatedWithResidue, err)
	}
	return nil
}

// errActivatedWithResidue marks the one outcome that is neither success nor failure: the ledger
// is live, and the staging copy could not be removed.
var errActivatedWithResidue = errors.New("restore: the restored ledger is ACTIVE, but the staging copy could not be removed")
