package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/backup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/migrate"
	"mythicalos.ai/ctl/internal/preflight"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
)

// The backup and restore verbs, ported from the frozen dispatcher's own two arms.
//
// THE OPTION MATRIX IS PART OF THE VERB, not decoration around it. A misplaced option is
// REFUSED, not ignored: `backup DIR --purge` silently ignoring `--purge` is how an operator
// ends up believing they ran something other than what they wrote, and `restore DIR --abandon`
// means two contradictory things at once — restore FROM this directory, and abandon whatever
// is in progress. Both are usage errors with nothing attempted.

// newCopier is the seam onto the pinned copy container — the host cannot read a named volume
// at all (D54), so every question about a volume's contents is asked through it.
//
// IT IS WIRED (see copyseam.go): an adapter satisfying backup.Copier over internal/copyfill's
// own functions, carrying the transcript across unread. It stays a VARIABLE rather than a
// direct call because the nil-seam refusal below is a real contract — a build assembled without
// it must report a missing capability rather than dereference nothing — and because a test must
// be able to prove that refusal still fires.
//
// The identity is the installation the helper containers belong to; the writers are the verb's
// own streams, so the copier's narration and the helper's stderr reach whoever invoked it rather
// than the process globals.
var newCopier = buildCopier

// safeChain is the ownership-safety check for the operator-named backup/restore directory —
// the ONLY authentication a backup gets, since there is no secret to sign a tree with.
//
// IT IS migrate-storage's OWN HARDENED PRIMITIVE, reached here rather than reimplemented: a
// second, hand-written copy of a security check is exactly the drift the "one implementation"
// rule exists to prevent, and this is the check that stands in for a signature. A nil one
// refuses every operation rather than defaulting to permissive.
var safeChain backup.SafeChain = migrate.VerifyChainOwnerSafe

// unavailable reports a capability this build does not carry yet. It is an OPERATIONAL
// failure, not a usage error: the invocation was well formed.
func unavailable(stderr io.Writer, what string) int {
	fmt.Fprintf(stderr, "mythical-ctl: %s is not available in this build yet\n", what)
	return cliio.ExitFail
}

// runBackup is the `backup` arm: exactly one operand (the output directory) and only the three
// document options.
func runBackup(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if o.purge || o.family || o.image != "" || o.forced || o.toBind != "" || o.mapForeign || o.abandon {
		fmt.Fprintln(stderr, "mythical-ctl: backup takes only --index/--policy/--manifest-dir and an output directory")
		return cliio.ExitUsage
	}
	if len(o.products) != 1 {
		fmt.Fprintln(stderr, "mythical-ctl: backup needs exactly <output-directory>")
		return cliio.ExitUsage
	}
	if newCopier == nil || safeChain == nil {
		return unavailable(stderr, "backup")
	}
	d, rc, done := openBackupDeps(o, env, stdin, stdout, stderr)
	if rc != cliio.ExitOK {
		return rc
	}
	defer done()
	if err := backup.Run(context.Background(), d, o.products[0]); err != nil {
		return cliio.ExitFail
	}
	return cliio.ExitOK
}

// runRestore is the `restore` arm: EITHER exactly one operand (the backup directory) OR
// --abandon on its own — never both, never neither.
func runRestore(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if o.purge || o.family || o.image != "" || o.forced || o.toBind != "" || o.mapForeign {
		fmt.Fprintln(stderr, "mythical-ctl: restore takes only --index/--policy/--manifest-dir, --abandon, and a backup directory")
		return cliio.ExitUsage
	}
	if o.abandon {
		if len(o.products) != 0 {
			fmt.Fprintln(stderr, "mythical-ctl: restore --abandon takes no directory")
			return cliio.ExitUsage
		}
	} else if len(o.products) != 1 {
		fmt.Fprintln(stderr, "mythical-ctl: restore needs exactly <backup-directory> (or --abandon)")
		return cliio.ExitUsage
	}
	if newCopier == nil || safeChain == nil {
		return unavailable(stderr, "restore")
	}
	d, rc, done := openBackupDeps(o, env, stdin, stdout, stderr)
	if rc != cliio.ExitOK {
		return rc
	}
	defer done()
	var err error
	if o.abandon {
		err = backup.Abandon(context.Background(), d)
	} else {
		err = backup.Restore(context.Background(), d, o.products[0])
	}
	if err != nil {
		return cliio.ExitFail
	}
	return cliio.ExitOK
}

// openBackupDeps assembles what both verbs need — the layout, the daemon preflight, the family
// lock, the runtime facade — and hands back a release function. The refusal PROSE is written
// by the module itself, exactly as the reference's verbs print and return a status; the caller
// maps the error to an exit code and prints nothing further.
//
// THE ENVIRONMENT IS THREADED, not read from the process. Every other verb here takes the
// environment its caller was given (that is what runEnv exists for), and a verb that reached for
// os.Environ() instead would ignore a caller that supplied one — silently running against a
// different family home, a different daemon and a different confirmation setting than the one it
// was asked about. Nothing here may be the exception, least of all the two verbs that move data.
func openBackupDeps(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) (backup.Deps, int, func()) {
	home, err := layout.Home(env)
	if err != nil {
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	if err := layout.Ensure(home); err != nil {
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	// THE OPERATING USER'S HOME, NOT THE FAMILY HOME — the same distinction the lifecycle verbs
	// draw. The docker context store and the registry credentials live under $HOME; resolving them
	// against ~/.mythical instead finds neither, so a copy image behind an authenticated registry
	// would be pulled anonymously and fail with a denial the operator has already logged in past.
	client, err := engine.Connect(env, userHome(env))
	if err != nil {
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	if err := preflight.Daemon(context.Background(), client); err != nil {
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	h, err := famlock.Acquire(home)
	if err != nil {
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	release := func() { _ = famlock.Release(h) }
	rt, err := runtime.New(h, client)
	if err != nil {
		release()
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	// Defaults resolved AFTER parsing, so an explicit flag always wins.
	idx, pol, mdir := o.index, o.policy, o.manifestDir
	if idx == "" {
		idx = filepath.Join(home, ".state", "index")
	}
	if pol == "" {
		pol = filepath.Join(home, ".state", "policy")
	}
	if mdir == "" {
		mdir = filepath.Join(home, ".state")
	}
	ident, err := copierIdent(h)
	if err != nil {
		release()
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	cop, err := newCopier(rt, ident, stdout, stderr)
	if err != nil {
		release()
		cliio.Warnf(stderr, "%v", err)
		return backup.Deps{}, cliio.ExitFail, nil
	}
	return backup.Deps{
		Lock: h, Home: home, RT: rt, Objs: prov.Engine(client),
		Copier: cop, Safe: safeChain,
		Confirm: func(prompt string) bool { return cliio.Confirm(env, stdin, stderr, prompt) },
		Out:     stdout, Err: stderr,
		Index: idx, Policy: pol, ManifestDir: mdir,
		// THE EFFECTIVE uid, which is what `id -u` reports and what every other consumer of "the
		// operator" in this tree uses — the migration's own operator uid, and the ownership-chain
		// check this verb now shares with it, both read the effective one. Two different answers
		// to "who is the operator" inside one verb is a contract nobody could satisfy.
		OperatorUID: strconv.Itoa(os.Geteuid()),
	}, cliio.ExitOK, release
}

// userHome is the OPERATING user's home directory as the environment reports it — where the
// docker CLI keeps its context store and registry credentials. Empty when HOME is unset, which
// the endpoint resolver already treats as "no config to read" rather than guessing.
func userHome(env []string) string {
	home := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	return home
}
