//go:build !linux && !darwin

package migrate

import "errors"

// The fallback for a platform whose extended attributes this build has no reader for.
//
// IT REFUSES RATHER THAN REPORTING "NO WITNESS", for the same reason platformMountPoints refuses
// rather than returning an empty mount list. A stub that answered "absent" would make every
// directory look unstamped, and two unstamped directories compare EQUAL — which is the defeated
// `device:inode` check back again, on a platform where nobody measured whether inode numbers are
// reused. migrate-storage therefore does not run at all here, which is the honest outcome: the
// evidence its irreversible steps depend on cannot be produced.
var errNoWitnessSupport = errors.New("this platform exposes no extended-attribute interface this build can use, " +
	"so a directory's identity cannot be established")

func lgetWitness(string, []byte) (int, error) { return 0, errNoWitnessSupport }

func lsetWitness(string, []byte) error { return errNoWitnessSupport }

// NEVER TRUE. There is no condition under which this build can establish that an attribute is
// absent, so nothing here may be reported as an answer.
func witnessAbsent(error) bool { return false }
