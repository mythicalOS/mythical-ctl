package version

import (
	"regexp"
	"testing"
)

// The default must be non-empty and SemVer-shaped (numeric core, optional -suffix): the smoke
// suite and the min_core comparator both parse this shape, so an empty or free-form default
// would pass unit tests and fail the first real invocation.
func TestDefaultVersionIsSemverShaped(t *testing.T) {
	if Version == "" {
		t.Fatal("Version default is empty")
	}
	re := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version default %q is not X.Y.Z[-suffix]", Version)
	}
}
