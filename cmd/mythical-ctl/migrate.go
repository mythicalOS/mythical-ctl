package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/migrate"
	"mythicalos.ai/ctl/internal/verbs"
)

// migrateStorage is the `migrate-storage` dispatch, ported from the frozen entrypoint's own case.
//
// A MALFORMED INVOCATION IS A USAGE ERROR WITH NOTHING ATTEMPTED. This verb mutates the fleet, the
// host and mythical.conf, so a missing or surplus operand must not be silently dropped and acted on
// anyway, and an option belonging to a different verb is REFUSED, not ignored — silently honouring
// `migrate-storage p1 state --to-bind /x --purge` would run something other than what was written.
// Every refusal below happens before any machinery is reached.
func migrateStorage(o opts, env []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if o.purge || o.family || o.image != "" || o.forced || o.abandon {
		fmt.Fprintln(stderr, "mythical-ctl: migrate-storage takes only --to-bind and --map-foreign-to-operator")
		return cliio.ExitUsage
	}
	if o.toBind == "" {
		fmt.Fprintln(stderr, "mythical-ctl: migrate-storage needs --to-bind <path>")
		return cliio.ExitUsage
	}
	// EXACTLY <product> <role>.
	if len(o.products) != 2 {
		fmt.Fprintln(stderr, "mythical-ctl: migrate-storage needs exactly <product> <role> --to-bind <path>")
		return cliio.ExitUsage
	}
	// AN ABSOLUTE PATH, judged HERE. Every path comparison the migration makes is on absolute
	// paths, and a relative operand would be resolved against whatever directory the process
	// happens to be in — a location the operator did not name. It is a MALFORMED INVOCATION, so it
	// carries the usage code; reporting it as anything else classifies a malformed call as a
	// well-formed one that merely could not proceed.
	if !filepath.IsAbs(o.toBind) {
		fmt.Fprintln(stderr, "mythical-ctl: --to-bind needs an absolute path")
		return cliio.ExitUsage
	}
	// THE MACHINE IS internal/migrate AND ITS RUNTIME WIRING IS internal/verbs — the one layer that
	// holds the lock, the store, the ledger, the authenticated documents, the runtime facade and the
	// bring-up sequence at the same time, which is what the phase machine's copy and rebuild seams
	// need. Assembling that here would be a second copy of the session preamble every other verb
	// already goes through, so the dispatcher does what it does for every other verb: judge the
	// invocation, then hand it over.
	d, err := deps(o, env, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return cliio.ExitFail
	}
	return verbs.MigrateStorage(context.Background(), d, o.products[0], o.products[1],
		migrate.Options{ToBind: o.toBind, MapForeign: o.mapForeign})
}
