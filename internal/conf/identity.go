package conf

import (
	"fmt"
	"os"
	"syscall"
)

// identityOK refuses a config file whose identity is not its own (§4.1a). Absent is fine — a
// first write creates it. Everything else fails closed:
//
//   - a symlink is refused, never followed and adopted;
//   - a non-regular file (FIFO, directory, device) is refused WITHOUT being opened — an open
//     on a FIFO blocks, so the check runs on Lstat alone;
//   - a link count above 1 is refused: a hardlink is a second name for the same inode, and
//     brokkr.conf hardlinked to mythical.conf turns a product write into a write to the
//     host-only file. Nothing legitimate shares an inode this installer created;
//   - a file owned by another uid is refused, on READ as well as write: on a rootful runtime a
//     compromised container can chown 0:0 + chmod 0666 its conf, and every other check still
//     passes — ownership is what catches it. The comparison is against the EFFECTIVE uid, the
//     identity the kernel enforces writes against;
//   - an unreadable identity (stat shape unknown) is a refusal, never an assumption.
//
// A pathname check is only ever true of the instant it ran — §4.1a records pathname TOCTOU as
// an accepted, irreducible residual; callers re-check immediately before each mutation to make
// the window as small as the platform allows.
func identityOK(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("config: cannot examine %s — refusing: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config: %s is a symlink — refusing (a config file must be its own file)", path)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("config: %s is not a regular file — refusing", path)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("config: cannot read the identity of %s — refusing", path)
	}
	if sys.Nlink > 1 {
		return fmt.Errorf("config: %s has %d names (hardlinked) — refusing; this installer created it and nothing legitimate shares its inode", path, sys.Nlink)
	}
	if int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("config: %s is owned by uid %d, not by you (uid %d) — refusing; nothing legitimate takes it over", path, sys.Uid, os.Geteuid())
	}
	return nil
}
