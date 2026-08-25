// Package cliio holds the CLI's I/O conventions: the exit-code contract, the warn/die
// message shapes, the destructive-action confirmation, and the digest helper.
package cliio

// The exit-code contract, verbatim from the CLI's published help ("EXIT CODES"):
//
//	0  completed      1  operational failure      2  usage error      3  not launched yet
//
// Exit 3 is a recognised state, not a failure: installing a product whose image has not
// shipped reports that it has not launched yet and creates nothing.
const (
	ExitOK          = 0
	ExitFail        = 1
	ExitUsage       = 2
	ExitNotLaunched = 3
)
