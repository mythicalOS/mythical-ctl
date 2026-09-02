package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"mythicalos.ai/ctl/internal/ui"
	"mythicalos.ai/ctl/internal/verbs"
)

// drive runs ONE verb, through the terminal interface when this invocation is interactive and
// through the plain path otherwise.
//
// THE CHOICE IS MADE HERE AND NOWHERE ELSE, once per invocation, and it changes nothing about the
// verb: a verb is synchronous and returns an exit code in both worlds, and the two seams it uses to
// talk to a human — Confirm and Progress — are supplied either by the plain-CLI defaults or by the
// interface's bridge. The refusal semantics are cliio.Confirm's in both, so a destructive verb is
// exactly as hard to confirm at a terminal as it is in a script.
//
// Read-only and non-lifecycle verbs are deliberately NOT routed through here: status has its own
// live view (driveStatus, which reaches driveWith below with ui.RunStatus), and backup/restore
// print reports a capture is entitled to see unchanged.
func drive(ctx context.Context, d verbs.Deps, stdin io.Reader, stdout io.Writer, fn ui.VerbFunc) int {
	return driveWith(ctx, d, fn, ui.Interactive(d.Env, stdin, stdout), ui.Run)
}

// driveWith is drive with the decision and the runner injected, so both branches — and the
// never-started fallback, which is the one that must not run an operation twice — are testable in
// process.
func driveWith(
	ctx context.Context,
	d verbs.Deps,
	fn ui.VerbFunc,
	interactive bool,
	runUI func(context.Context, verbs.Deps, ui.VerbFunc) (int, error),
) int {
	if !interactive {
		return fn(ctx, d)
	}
	code, err := runUI(ctx, d, fn)
	if errors.Is(err, ui.ErrNotStarted) {
		// The interface never came up, so the verb was never invoked and nothing was attempted.
		// Running it plainly here is the ONLY safe reading of that error — treating it as a failure
		// would report an outcome for an operation that never started, and retrying under a second
		// interface would be the same gamble again.
		return fn(ctx, d)
	}
	if err != nil {
		// The verb DID run; the interface ended badly on top of it. The code is still the verb's,
		// and the reason is said out loud rather than folded into the exit status.
		fmt.Fprintf(errOrDiscard(d), "mythical-ctl: the terminal interface ended early: %v\n", err)
	}
	return code
}

func errOrDiscard(d verbs.Deps) io.Writer {
	if d.Stderr == nil {
		return io.Discard
	}
	return d.Stderr
}
