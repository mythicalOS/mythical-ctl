package verbs

import (
	"context"
	"fmt"

	"mythicalos.ai/ctl/internal/cliio"
)

// The batchable verbs, and the only ones. A verb outside this set is a usage error with nothing
// attempted — never a silent no-op over the whole product list.
var batchable = map[string]bool{
	"install": true, "start": true, "stop": true, "restart": true, "recreate": true,
}

// Batchable reports whether a verb name may be handed to Batch. The dispatcher asks so it can
// refuse before it takes a lock or touches a document.
func Batchable(verb string) bool { return batchable[verb] }

// ExitName is the exit-code contract's own vocabulary, used for the per-product batch report.
func ExitName(code int) string {
	switch code {
	case cliio.ExitOK:
		return "completed"
	case cliio.ExitFail:
		return "failed"
	case cliio.ExitUsage:
		return "usage error"
	case cliio.ExitNotLaunched:
		return "not launched yet"
	}
	return fmt.Sprintf("unknown exit code %d", code)
}

// Batch runs one verb over several products and aggregates the outcomes WORST WINS.
//
// FAILING ONE PRODUCT MUST NOT ABORT THE OTHERS — that is the whole reason this function exists.
// Every product is attempted, its outcome recorded and reported, and only then is the aggregate
// computed.
//
// A USAGE ERROR FROM ONE PRODUCT is that product's operational failure from the batch's point of
// view: the batch itself was invoked correctly. Mapping it to a failure keeps the aggregate's
// contract (usage is never a batch outcome) without losing the failure.
func Batch(ctx context.Context, d Deps, verb string, products []string) int {
	if !batchable[verb] {
		d.warn("verbs: %q is not a batchable verb", verb)
		return cliio.ExitUsage
	}
	if len(products) == 0 {
		d.warn("verbs: %s needs at least one product", verb)
		return cliio.ExitUsage
	}
	codes := make([]int, 0, len(products))
	for _, p := range products {
		rc := runOne(ctx, d, verb, p)
		if rc == cliio.ExitUsage {
			rc = cliio.ExitFail
		}
		d.say("batch", "%s: %s", p, ExitName(rc))
		codes = append(codes, rc)
	}
	agg, err := Worst(codes)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	return agg
}

func runOne(ctx context.Context, d Deps, verb, product string) int {
	switch verb {
	case "install":
		return Install(ctx, d, InstallOpts{Product: product})
	case "recreate":
		return Recreate(ctx, d, product)
	case "start":
		return Start(ctx, d, product)
	case "stop":
		return Stop(ctx, d, product)
	case "restart":
		return Restart(ctx, d, product)
	}
	// Unreachable: Batch gates on batchable first. Kept as a refusal rather than a default verb,
	// because a batch that silently picked one would run the wrong thing over every product.
	d.warn("verbs: %q is not a batchable verb", verb)
	return cliio.ExitUsage
}

// Worst aggregates per-product outcomes:
//
//	every product succeeded                        → 0
//	some succeeded, some not-launched, no failures → 3
//	any product failed operationally               → 1
//
// So 0 means EVERYTHING you asked for is running — a caller can branch on it without inspecting
// anything else. 3 means nothing went wrong but you did not get everything. 1 means something
// genuinely failed even if other products installed fine.
//
// USAGE (2) IS DELIBERATELY NOT AGGREGATABLE, and that is not pedantry: usage means nothing was
// attempted, so it cannot be one product's outcome inside a batch that attempted others. A caller
// passing it has a bug, and mapping it silently onto a failure would hide the bug and misreport the
// batch.
//
// EVERY ARGUMENT IS VALIDATED BEFORE ANYTHING IS AGGREGATED, so the loop never returns early on a
// failure. An earlier version did — a failure is the worst code, so there was nothing left to learn
// — and the shortcut made both refusals depend on POSITION: {2,1} refused as intended while {1,2}
// and {1,7} answered 1 with the forbidden or undefined code never looked at. Which is the precise
// failure the refusals were written to prevent, arriving through the door they were meant to close.
// Scanning the whole list costs one pass over a handful of integers; agreeing with a malformed call
// costs the caller the bug.
func Worst(codes []int) (int, error) {
	if len(codes) == 0 {
		return 0, fmt.Errorf("exit: Worst needs at least one per-product outcome")
	}
	sawFail, sawNotLaunched := false, false
	for _, c := range codes {
		switch c {
		case cliio.ExitOK:
		case cliio.ExitFail:
			sawFail = true
		case cliio.ExitNotLaunched:
			sawNotLaunched = true
		case cliio.ExitUsage:
			return 0, fmt.Errorf("exit: usage errors are not batch outcomes — nothing was attempted for one product")
		default:
			return 0, fmt.Errorf("exit: %d is not an exit code this contract defines", c)
		}
	}
	switch {
	case sawFail:
		return cliio.ExitFail, nil
	case sawNotLaunched:
		return cliio.ExitNotLaunched, nil
	}
	return cliio.ExitOK, nil
}
