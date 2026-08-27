package main

import (
	"fmt"
	"io"

	"mythicalos.ai/ctl/internal/cliio"
)

// migrateStorage is the `migrate-storage` dispatch, ported from the frozen entrypoint's own case.
//
// A MALFORMED INVOCATION IS A USAGE ERROR WITH NOTHING ATTEMPTED. This verb mutates the fleet, the
// host and mythical.conf, so a missing or surplus operand must not be silently dropped and acted on
// anyway, and an option belonging to a different verb is REFUSED, not ignored — silently honouring
// `migrate-storage p1 state --to-bind /x --purge` would run something other than what was written.
// Every refusal below happens before any machinery is reached.
func migrateStorage(o opts, stderr io.Writer) int {
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
	// THE MACHINE IS internal/migrate; WHAT IS NOT HERE YET IS ITS RUNTIME WIRING. MigrateStorage
	// takes a Deps carrying the copy-helper seam (the volume fill/copy/verify module) and the
	// rebuild seam (product bring-up), neither of which this build composes yet. Reporting that
	// plainly — and exiting with the OPERATIONAL failure code, not the usage code, because the
	// invocation itself was well formed — is what the frozen entrypoint does for a verb whose
	// mechanism is present and whose CLI wrapper is not. It degrades cleanly instead of pretending.
	fmt.Fprintln(stderr, "mythical-ctl: migrate-storage is not available in this build yet")
	return cliio.ExitFail
}
