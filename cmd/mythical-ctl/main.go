// Command mythical-ctl installs and manages mythicalOS products.
//
// This is the Go successor to the bash entrypoint in bin/mythical-ctl, ported verb by verb —
// a verb appears in this dispatcher and in the usage text only once its implementation lands,
// so --help never advertises what does not exist. The exit-code contract and the flag-refusal
// discipline ("a misplaced option is refused, not ignored") carry over unchanged.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/verbs"
	"mythicalos.ai/ctl/internal/version"
)

// usage is the help surface. Ported from the bash heredoc, minus the verbs that have not been
// wired yet — each task that lands a verb adds its lines here and to the dispatcher together.
const usage = `mythical-ctl — install and manage mythicalOS products

USAGE
  mythical-ctl <command> [products...] [options]

COMMANDS
  install <product>...     install (or converge) one or more products
  start <product>...       start; sets desired state to running
  stop <product>...        stop; sets desired state to stopped
  restart <product>...     restart; refused on a product you have stopped
  recreate <product>...    replace the container, preserving desired state
  status [product...]      report desired vs actual, outstanding checks, unattributed objects
  uninstall <product>      remove the container; keeps your data and the rollback floor
                             --purge   also remove this product's named volumes
  uninstall --family       remove EVERY product and reset the ledger entirely - identity,
                           membership, every rollback floor, the family-index anchor
                             --purge   also remove every named volume (your data)
  backup <output-directory>
                           write the ledger, the tree, and every named volume's contents plus its
                           per-entry manifest and its recorded identity — copying the directory alone
                           is not a backup
  restore <backup-directory>
                           restore installer state and named volumes from a backup, staging the
                           incoming ledger before anything is created; refused while an active
                           installation is present
                             --abandon   abandon an in-progress restore, removing the partial
                                         volumes it created under their recorded identity
  migrate-storage <product> <role> --to-bind PATH
                           move a product's storage from its named volume to a host directory
                             --map-foreign-to-operator   map foreign-uid entries to the operator
  state repair [identity]  rebuild installer state from container-runtime labels
  state abandon-intent <class> <name>
                           give up on a write-ahead intent whose object never appeared
  net rebind               move this installation onto the network MYTHICAL_NET names

OPTIONS
  --index PATH             the family index (default: ~/.mythical/.state/index)
  --policy PATH            the family policy index
  --manifest-dir PATH      where <product>.manifest files are
  --image REF              run this image instead of the manifest's (loud, recorded)
  --force-install          install a product whose manifest says it has not launched
  -v, --version            print the version and exit
  -h, --help               print this help and exit

EXIT CODES
  0  completed      1  operational failure      2  usage error      3  not launched yet

Documentation: https://docs.mythicalos.ai   Source: https://github.com/mythicalOS/mythical-ctl
`

// run holds the whole entrypoint so it can be exercised in-process: it takes the argument list
// without argv[0] and reads and writes the streams it is handed instead of reaching for the
// process globals. stdin is what the confirmation-reading verbs read the operator's reply from,
// so it is threaded rather than reached for; the environment is threaded for the same reason.
// run reads the real process environment; runEnv is the same entrypoint with the environment
// supplied, which is what an in-process test drives.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runEnv(args, os.Environ(), stdin, stdout, stderr)
}

func runEnv(args, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return cliio.ExitOK
	}
	verb := args[0]
	// The option loop, ported from the frozen dispatcher: it runs BEFORE the verb acts, so a
	// known option after a global flag is consumed (and then ignored by that flag), an unknown
	// option is a usage error, and a value-taking option with no value is a usage error with
	// nothing attempted — all measured behaviors, all pinned by tests.
	o, rc := parseOpts(args[1:], stderr)
	if rc >= 0 {
		return rc
	}
	switch verb {
	case "backup":
		return runBackup(o, stdin, stdout, stderr)
	case "restore":
		return runRestore(o, stdin, stdout, stderr)
	case "migrate-storage":
		return migrateStorage(o, stderr)
	case "-v", "--version":
		fmt.Fprintf(stdout, "mythical-ctl %s\n", version.Version)
		return cliio.ExitOK
	case "-h", "--help":
		fmt.Fprint(stdout, usage)
		return cliio.ExitOK
	}
	// ONE list of the five, and it is the verb layer's own: a second copy here is a copy that
	// drifts, and the direction it drifts is a verb this dispatcher accepts and the batch driver
	// then refuses (or the reverse — a verb nothing dispatches at all).
	if verbs.Batchable(verb) {
		return lifecycle(verb, o, env, stdin, stdout, stderr)
	}
	switch verb {
	case "status":
		return status(o, env, stdin, stdout, stderr)
	case "uninstall":
		return uninstall(o, env, stdin, stdout, stderr)
	case "state":
		return stateVerb(o, env, stdin, stdout, stderr)
	case "net":
		return netVerb(o, env, stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "mythical-ctl: unknown command: %s\n\n", verb)
	fmt.Fprint(stderr, usage)
	return cliio.ExitUsage
}

// lifecycle dispatches install/start/stop/restart/recreate.
//
// THE FLAG-REFUSAL MATRIX IS THE FIRST THING IT DOES, and every refusal is a usage error with
// NOTHING attempted. --purge and --family belong to uninstall ONLY; --to-bind and
// --map-foreign-to-operator to migrate-storage ONLY; --abandon to restore ONLY. Silently ignoring a
// misplaced option is how `install p1 --purge` returns 0 having quietly done something other than
// what was written.
func lifecycle(verb string, o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	refuse := func(msg string) int {
		fmt.Fprintf(stderr, "mythical-ctl: %s\n", msg)
		return cliio.ExitUsage
	}
	switch {
	case o.purge:
		return refuse("--purge applies to uninstall only")
	case o.family:
		return refuse("--family applies to uninstall only")
	case o.toBind != "":
		return refuse("--to-bind applies to migrate-storage only")
	case o.mapForeign:
		return refuse("--map-foreign-to-operator applies to migrate-storage only")
	case o.abandon:
		return refuse("--abandon applies to restore only")
	}
	if len(o.products) == 0 {
		fmt.Fprintf(stderr, "mythical-ctl: %s needs at least one product\n\n", verb)
		fmt.Fprint(stderr, usage)
		return cliio.ExitUsage
	}
	// --image and --force-install are install-only AND single-product: a batch would apply one
	// override to all of them, which is never what an operator means. The refusals are ordered as
	// the reference orders them — the single-product rule is asked first, so `start p1 p2 --image X`
	// reports the arity, and `start p1 --image X` reports the verb.
	extra := o.image != "" || o.forced
	if extra && len(o.products) > 1 {
		return refuse("--image/--force-install take exactly one product")
	}
	if extra && verb != "install" {
		return refuse("--image/--force-install apply to install only")
	}

	d, err := deps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	ctx := context.Background()
	if extra {
		return verbs.Install(ctx, d, verbs.InstallOpts{
			Product:  o.products[0],
			Image:    o.image,
			ImageSet: o.image != "",
			Force:    o.forced,
		})
	}
	// One product with no per-product option goes through the batch driver too — the reference
	// does exactly this, so the per-product report and the aggregate are the same code for one
	// product as for five.
	return verbs.Batch(ctx, d, verb, o.products)
}

// status dispatches the read-only report.
//
// IT READS, so a stray MUTATING option is a usage error rather than something to accept and ignore:
// `status p1 --purge` must not be answered with a report that quietly did nothing destructive this
// time. --index/--policy/--manifest-dir are the document locators every verb shares and are
// accepted here exactly as the frozen dispatcher accepts them.
func status(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if o.image != "" || o.forced || o.purge || o.family || o.toBind != "" || o.mapForeign || o.abandon {
		fmt.Fprintln(stderr, "mythical-ctl: status takes no options other than --index")
		return cliio.ExitUsage
	}
	d, err := statusDeps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	return verbs.Status(context.Background(), d, o.products)
}

// statusDeps assembles the report's dependencies WITHOUT letting a runtime that cannot be LOCATED
// gate the report.
//
// Endpoint resolution is fail-closed on purpose — a remote DOCKER_HOST, a Windows named pipe and an
// unreadable docker context all refuse rather than fall back to a default socket — and every
// MUTATING verb must inherit that refusal. status must not: it is the command an operator runs to
// find out why the others are refusing, and the frozen dispatcher resolves no endpoint for it at
// all (each runtime call resolves its own and fails on its own), so there a misconfigured context
// still produced the ledger half of the report and exit 0. Here the refusal is REPORTED and the
// verb is handed no runtime, which it already renders as "unobservable" rather than inventing.
//
// The family HOME is the one thing the report cannot do without — there is no ledger to read
// without it — so that failure still refuses. STATED DIVERGENCE: the reference returned 0 there
// too, printing "installation: UNREADABLE"; claiming an identity is recorded on a machine whose
// home could not even be located is a worse answer than saying why.
func statusDeps(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) (verbs.Deps, error) {
	d, err := deps(o, env, stdin, stdout, stderr)
	if err == nil {
		return d, nil
	}
	home, herr := layout.Home(env)
	if herr != nil {
		return verbs.Deps{}, herr
	}
	fmt.Fprintln(stderr, err.Error())
	fmt.Fprintln(stderr, "mythical-ctl: the container runtime could not be located, so nothing below is observed live.")
	stateDir := filepath.Join(home, ".state")
	return verbs.Deps{
		Home:        home,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		Env:         env,
		IndexPath:   or(o.index, filepath.Join(stateDir, "index")),
		PolicyPath:  or(o.policy, filepath.Join(stateDir, "policy")),
		ManifestDir: or(o.manifestDir, stateDir),
	}, nil
}

// uninstall dispatches the two scopes.
//
// `uninstall <product> --family` IS A USAGE ERROR, and refusing it is the whole point of checking:
// --family removes the WHOLE family, so silently honouring the flag while dropping the product
// argument runs a materially MORE destructive operation than the one written. It is refused FIRST,
// before anything is opened — a confirmation cannot rescue an operator from a wipe they never asked
// for, because the prompt they answer would be about the wipe.
func uninstall(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if o.image != "" || o.forced || o.toBind != "" || o.mapForeign || o.abandon {
		fmt.Fprintln(stderr, "mythical-ctl: --image/--force-install/--to-bind/--map-foreign-to-operator/--abandon apply elsewhere")
		return cliio.ExitUsage
	}
	if o.family && len(o.products) != 0 {
		fmt.Fprintln(stderr, "mythical-ctl: uninstall --family takes no product")
		return cliio.ExitUsage
	}
	if !o.family && len(o.products) != 1 {
		fmt.Fprintln(stderr, "mythical-ctl: uninstall takes exactly one product")
		return cliio.ExitUsage
	}
	d, err := deps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	if o.family {
		return verbs.UninstallFamily(context.Background(), d, o.purge)
	}
	return verbs.Uninstall(context.Background(), d, o.products[0], o.purge)
}

// stateVerb dispatches `state repair` and `state abandon-intent`.
//
// THE ARITY IS THE GATE ON BOTH, and it is checked BEFORE anything is attempted. `state repair`
// takes at most one further operand (the chosen identity) and `state abandon-intent` exactly two —
// a surplus operand must not be silently dropped and the command run anyway on "the first words,
// whatever came after them": both confirm and then perform a state-deleting action, so a malformed
// invocation is a usage error with NOTHING attempted.
//
// `--reinitialize` is deliberately NOT reachable from here. It begins with `-`, so the option loop
// refuses it as an unknown option before this dispatcher runs — exactly as the frozen reference's
// own loop does. The library verb accepts it; the CLI does not offer it.
func stateVerb(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	refuse := func(msg string) int {
		fmt.Fprintf(stderr, "mythical-ctl: %s\n", msg)
		return cliio.ExitUsage
	}
	sub := ""
	if len(o.products) > 0 {
		sub = o.products[0]
	}
	switch sub {
	case "repair":
		if len(o.products) > 2 {
			return refuse("state repair takes at most one identity (or --reinitialize)")
		}
	case "abandon-intent":
		if len(o.products) != 3 {
			return refuse("state abandon-intent needs exactly <class> <name>")
		}
	default:
		return refuse(`state takes "repair" or "abandon-intent"`)
	}
	d, err := deps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	ctx := context.Background()
	if sub == "repair" {
		// The chosen identity is THREADED THROUGH. The reference parsed it and then called the
		// library verb without it, so the library saw no choice at all and printed its "choose one
		// explicitly" refusal even though the operator DID choose — the one documented safe recovery
		// path was unusable from the CLI.
		return verbs.StateRepair(ctx, d, o.products[1:])
	}
	return verbs.AbandonIntent(ctx, d, o.products[1], o.products[2])
}

// netVerb dispatches `net rebind`.
//
// EXACTLY ONE OPERAND, for the same reason: with confirmation granted non-interactively (a script,
// or an operator who set it), this moves the whole fleet's network attachment, so a malformed
// invocation does nothing at all.
func netVerb(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	refuse := func(msg string) int {
		fmt.Fprintf(stderr, "mythical-ctl: %s\n", msg)
		return cliio.ExitUsage
	}
	if len(o.products) == 0 || o.products[0] != "rebind" {
		return refuse(`net takes "rebind"`)
	}
	if len(o.products) != 1 {
		return refuse("net rebind takes no further operands")
	}
	d, err := deps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	return verbs.NetRebind(context.Background(), d)
}

// deps assembles the verb layer's dependencies: the daemon connection, the family home, the
// streams and the located documents.
//
// THE DEFAULTS ARE RESOLVED AFTER PARSING, so an explicit flag always wins — the same ordering the
// frozen dispatcher uses, and the reason a `--index` given anywhere on the line is honoured.
func deps(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) (verbs.Deps, error) {
	home, err := layout.Home(env)
	if err != nil {
		return verbs.Deps{}, err
	}
	// The OPERATING user's home, not the family home: this is where the docker CLI keeps the
	// endpoint and the registry credentials whose daemon and identity we must match.
	userHome := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			userHome = v
		}
	}
	socket, serr := engine.ResolveEndpoint(env, userHome)
	if serr != nil {
		return verbs.Deps{}, serr
	}
	c := engine.Dial(socket)
	c.SetDockerConfig(env, userHome)

	stateDir := filepath.Join(home, ".state")
	return verbs.Deps{
		Engine:      c,
		Home:        home,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		Env:         env,
		IndexPath:   or(o.index, filepath.Join(stateDir, "index")),
		PolicyPath:  or(o.policy, filepath.Join(stateDir, "policy")),
		ManifestDir: or(o.manifestDir, stateDir),
	}, nil
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
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
