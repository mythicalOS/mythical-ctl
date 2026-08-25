// Command mythical-ctl installs and manages mythicalOS products.
//
// This is the Go successor to the bash entrypoint in bin/mythical-ctl, ported verb by verb —
// a verb appears in this dispatcher and in the usage text only once its implementation lands,
// so --help never advertises what does not exist. The exit-code contract and the flag-refusal
// discipline ("a misplaced option is refused, not ignored") carry over unchanged.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/version"
)

// usage is the help surface. Ported from the bash heredoc, minus the verbs that have not been
// wired yet — each task that lands a verb adds its lines here and to the dispatcher together.
const usage = `mythical-ctl — install and manage mythicalOS products

USAGE
  mythical-ctl <command> [products...] [options]

COMMANDS
  (this build carries no lifecycle verbs yet — they land verb by verb; see --version)

OPTIONS
  -v, --version            print the version and exit
  -h, --help               print this help and exit

EXIT CODES
  0  completed      1  operational failure      2  usage error      3  not launched yet

Documentation: https://docs.mythicalos.ai   Source: https://github.com/mythicalOS/mythical-ctl
`

// run holds the whole entrypoint so it can be exercised in-process: it takes the argument list
// without argv[0] and reads and writes the streams it is handed instead of reaching for the
// process globals. stdin is threaded now, unused yet — the confirmation-reading verbs need it,
// and retrofitting the seam later would churn every call site.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdin
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return cliio.ExitOK
	}
	switch args[0] {
	case "-v", "--version", "-h", "--help":
		// Parity with the frozen dispatcher, MEASURED: it parses the whole argv before acting,
		// so a trailing OPTION (`--version --bogus`) is a usage error — but a trailing bare
		// OPERAND (`--version product`) is collected as a product and then ignored by these
		// verbs, exiting 0. Refuse exactly what bash refuses, no more.
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "mythical-ctl: unknown option: %s\n", a)
				return cliio.ExitUsage
			}
		}
		if args[0] == "-v" || args[0] == "--version" {
			fmt.Fprintf(stdout, "mythical-ctl %s\n", version.Version)
		} else {
			fmt.Fprint(stdout, usage)
		}
		return cliio.ExitOK
	}
	fmt.Fprintf(stderr, "mythical-ctl: unknown command: %s\n\n", args[0])
	fmt.Fprint(stderr, usage)
	return cliio.ExitUsage
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
