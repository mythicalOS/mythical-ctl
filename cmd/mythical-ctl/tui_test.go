// NO BATS INVENTORY. The dispatcher's choice between the terminal interface and the plain path has
// no counterpart in the frozen reference, which has only the plain path; no bats test describes it
// and none is claimed here. The dispatcher's option and arity matrices remain claimed by their own
// tasks' inventories and are not re-asserted below.
package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"mythicalos.ai/ctl/internal/ui"
	"mythicalos.ai/ctl/internal/verbs"
)

func neverRun(t *testing.T) func(context.Context, verbs.Deps, ui.VerbFunc) (int, error) {
	t.Helper()
	return func(context.Context, verbs.Deps, ui.VerbFunc) (int, error) {
		t.Fatal("the interface was started for a non-interactive invocation")
		return 0, nil
	}
}

// TestDrivePlainPathRunsTheVerbDirectly — a non-interactive invocation must reach the verb with no
// interface between, so a script sees exactly what it always saw.
func TestDrivePlainPathRunsTheVerbDirectly(t *testing.T) {
	ran := 0
	code := driveWith(context.Background(), verbs.Deps{}, func(context.Context, verbs.Deps) int {
		ran++
		return 3
	}, false, neverRun(t))
	if ran != 1 || code != 3 {
		t.Fatalf("ran %d times, code %d", ran, code)
	}
}

// TestDriveInteractiveRunsTheVerbThroughTheInterface, exactly once, and reports the interface's
// code.
func TestDriveInteractiveRunsTheVerbThroughTheInterface(t *testing.T) {
	ran := 0
	started := 0
	code := driveWith(context.Background(), verbs.Deps{}, func(ctx context.Context, d verbs.Deps) int {
		ran++
		return 1
	}, true, func(ctx context.Context, d verbs.Deps, fn ui.VerbFunc) (int, error) {
		started++
		return fn(ctx, d), nil
	})
	if ran != 1 || started != 1 || code != 1 {
		t.Fatalf("ran %d, started %d, code %d", ran, started, code)
	}
}

// TestDriveFallsBackWhenTheInterfaceNeverStarted. ErrNotStarted means NOTHING WAS ATTEMPTED, so the
// verb must run — once — on the plain path. Reporting the returned code instead would announce an
// outcome for an operation that never began.
func TestDriveFallsBackWhenTheInterfaceNeverStarted(t *testing.T) {
	ran := 0
	code := driveWith(context.Background(), verbs.Deps{}, func(context.Context, verbs.Deps) int {
		ran++
		return 2
	}, true, func(context.Context, verbs.Deps, ui.VerbFunc) (int, error) {
		return 0, errors.New("wrapped: " + ui.ErrNotStarted.Error())
	})
	if ran != 0 {
		t.Fatal("an error that merely reads like ErrNotStarted must not trigger the fallback")
	}
	if code != 0 {
		t.Fatalf("code %d", code)
	}

	ran = 0
	code = driveWith(context.Background(), verbs.Deps{}, func(context.Context, verbs.Deps) int {
		ran++
		return 2
	}, true, func(context.Context, verbs.Deps, ui.VerbFunc) (int, error) {
		return 0, ui.ErrNotStarted
	})
	if ran != 1 {
		t.Fatalf("the verb ran %d times on the fallback path — it must run exactly once", ran)
	}
	if code != 2 {
		t.Fatalf("code %d, want the verb's own", code)
	}
}

// TestDriveDoesNotRerunAVerbThatDidRun. Any other error means the verb DID run; running it again
// would repeat a mutation that already happened.
func TestDriveDoesNotRerunAVerbThatDidRun(t *testing.T) {
	var errb bytes.Buffer
	ran := 0
	code := driveWith(context.Background(), verbs.Deps{Stderr: &errb}, func(context.Context, verbs.Deps) int {
		ran++
		return 1
	}, true, func(ctx context.Context, d verbs.Deps, fn ui.VerbFunc) (int, error) {
		c := fn(ctx, d)
		return c, errors.New("the renderer died")
	})
	if ran != 1 {
		t.Fatalf("the verb ran %d times", ran)
	}
	if code != 1 {
		t.Fatalf("code %d, want the verb's own", code)
	}
	if got := errb.String(); got == "" || !bytes.Contains([]byte(got), []byte("the renderer died")) {
		t.Fatalf("the reason was folded into the exit status instead of being said: %q", got)
	}
}

// TestDriveTolerantOfMissingStreams — Deps with no Stderr must not panic on the diagnostic path.
func TestDriveTolerantOfMissingStreams(t *testing.T) {
	code := driveWith(context.Background(), verbs.Deps{}, func(context.Context, verbs.Deps) int {
		return 7
	}, true, func(ctx context.Context, d verbs.Deps, fn ui.VerbFunc) (int, error) {
		return fn(ctx, d), errors.New("boom")
	})
	if code != 7 {
		t.Fatalf("code %d", code)
	}
}

// TestDriveChoosesThePlainPathForInProcessStreams — the real entry point, over the buffers every
// dispatcher test uses. If this ever chose the interface, every one of those tests would be driving
// a renderer instead of a verb.
func TestDriveChoosesThePlainPathForInProcessStreams(t *testing.T) {
	var in, out, errb bytes.Buffer
	d := verbs.Deps{Stdin: &in, Stdout: &out, Stderr: &errb}
	ran := 0
	code := drive(context.Background(), d, &in, &out, func(context.Context, verbs.Deps) int {
		ran++
		return 0
	})
	if ran != 1 || code != 0 {
		t.Fatalf("ran %d, code %d", ran, code)
	}
	if out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("the plain path wrote something of its own: %q / %q", out.String(), errb.String())
	}
}
