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
	verb := args[0]
	// The option loop, ported from the frozen dispatcher: it runs BEFORE the verb acts, so a
	// known option after a global flag is consumed (and then ignored by that flag), an unknown
	// option is a usage error, and a value-taking option with no value is a usage error with
	// nothing attempted — all measured behaviors, all pinned by tests.
	if _, rc := parseOpts(args[1:], stderr); rc >= 0 {
		return rc
	}
	switch verb {
	case "-v", "--version":
		fmt.Fprintf(stdout, "mythical-ctl %s\n", version.Version)
		return cliio.ExitOK
	case "-h", "--help":
		fmt.Fprint(stdout, usage)
		return cliio.ExitOK
	}
	fmt.Fprintf(stderr, "mythical-ctl: unknown command: %s\n\n", verb)
	fmt.Fprint(stderr, usage)
	return cliio.ExitUsage
}

// opts is the parsed option set — the bash loop's locals. Verbs consume it as they land; the
// global flags ignore it, exactly as the frozen dispatcher does.
type opts struct {
	index, policy, manifestDir, image, toBind  string
	purge, family, forced, mapForeign, abandon bool
	products                                   []string
}

// parseOpts ports the frozen dispatcher's while-loop verbatim: known value-taking options
// (--index --policy --manifest-dir --image --to-bind) require a value (`_need_val` — a missing
// one is a usage error, nothing attempted); known flags set booleans; an unknown `-*` is a
// usage error; anything else is an operand. Returns (parsed, -1) on success, or (zero, rc≥0)
// when the caller must exit with rc.
func parseOpts(args []string, stderr io.Writer) (opts, int) {
	var o opts
	i := 0
	for i < len(args) {
		a := args[i]
		needVal := func() (string, bool) {
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "mythical-ctl: option %s requires a value\n", a)
				return "", false
			}
			i++
			return args[i], true
		}
		switch a {
		case "--index":
			v, ok := needVal()
			if !ok {
				return opts{}, cliio.ExitUsage
			}
			o.index = v
		case "--policy":
			v, ok := needVal()
			if !ok {
				return opts{}, cliio.ExitUsage
			}
			o.policy = v
		case "--manifest-dir":
			v, ok := needVal()
			if !ok {
				return opts{}, cliio.ExitUsage
			}
			o.manifestDir = v
		case "--image":
			v, ok := needVal()
			if !ok {
				return opts{}, cliio.ExitUsage
			}
			o.image = v
		case "--to-bind":
			v, ok := needVal()
			if !ok {
				return opts{}, cliio.ExitUsage
			}
			o.toBind = v
		case "--purge":
			o.purge = true
		case "--family":
			o.family = true
		case "--force-install":
			o.forced = true
		case "--map-foreign-to-operator":
			o.mapForeign = true
		case "--abandon":
			o.abandon = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "mythical-ctl: unknown option: %s\n", a)
				return opts{}, cliio.ExitUsage
			}
			o.products = append(o.products, a)
		}
		i++
	}
	return o, -1
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
