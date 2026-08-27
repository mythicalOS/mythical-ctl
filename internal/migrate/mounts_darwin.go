//go:build darwin

package migrate

import "golang.org/x/sys/unix"

// platformMountPoints reads the kernel's own mounted-filesystem list.
//
// THROUGH THE SYSCALL, NOT THROUGH THE `mount` COMMAND. The reference had to shell out and parse
// `<device> on <mountpoint> (<type>, …)`, and had to capture the pipeline's exit status first
// because a failed `mount` still leaves a filter reading empty input and exiting 0 — a pipeline that
// "succeeds" having found nothing, which reads exactly like "not a mount point". Getfsstat has no
// pipeline and no text to mis-split: it either fills the buffer or returns an error, and the error is
// carried to the caller as "could not be established".
func platformMountPoints() ([]string, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for _, fs := range buf[:n] {
		b := fs.Mntonname[:]
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		out = append(out, string(b[:i]))
	}
	return out, nil
}
