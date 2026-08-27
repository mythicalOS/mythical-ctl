package main

import (
	"context"
	"io"

	"mythicalos.ai/ctl/internal/ui"
	"mythicalos.ai/ctl/internal/verbs"
)

// statusIsInteractive is ui.Interactive, reached through a variable.
//
// The indirection exists for ONE reason and it is a testing one that matters: a test process
// cannot turn a pipe into a terminal, so ui.Interactive is false in every test no matter what is
// passed to it — and "--plain wins" asserted against a decision that is already false asserts
// nothing. With the seam, the terminal branch can be made true and the override actually
// exercised.
var statusIsInteractive = ui.Interactive

// statusInteractive decides whether this `status` invocation gets the dashboard.
//
// --plain DECIDES THE OTHER WAY AND IS ASKED FIRST. An operator who asked for the plain report
// at a terminal must get the same bytes a pipe gets; a flag that only applied when it happened
// to agree with the terminal test would be a flag that silently does nothing.
func statusInteractive(plain bool, env []string, stdin io.Reader, stdout io.Writer) bool {
	if plain {
		return false
	}
	return statusIsInteractive(env, stdin, stdout)
}

// driveStatus runs the report through the dashboard at a terminal and through the plain path
// otherwise.
//
// IT IS THE SAME VERB EITHER WAY. verbs.Status is synchronous and returns an exit code in both
// worlds; the dashboard is handed the report's own lines through the two seams the plain path
// also uses, and it renders them. Nothing about what the report SAYS depends on which of the two
// is driving — which is what makes "scripts see no change ever" a property of the arrangement
// rather than a claim about the renderer.
//
// The never-started fallback is driveWith's, unchanged: ui.ErrNotStarted means the report was
// never invoked, so it is run plainly — once.
func driveStatus(ctx context.Context, d verbs.Deps, plain bool, stdin io.Reader, stdout io.Writer, fn ui.VerbFunc) int {
	return driveWith(ctx, d, fn, statusInteractive(plain, d.Env, stdin, stdout), ui.RunStatus)
}
