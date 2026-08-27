//go:build !darwin

package migrate

import "errors"

// platformMountPoints is the fallback for platforms whose mount list this build has no reader for.
//
// IT REFUSES RATHER THAN RETURNING AN EMPTY LIST. Linux answers from /proc/self/mountinfo before
// this is ever reached; a Linux without /proc, or any other platform, must surface "could not be
// established" so the caller refuses — an empty list would read as "not a mount point" and let the
// migration proceed onto a mount whose atomic commit cannot work.
func platformMountPoints() ([]string, error) {
	return nil, errors.New("migrate: this platform exposes no mount table this build can read")
}
