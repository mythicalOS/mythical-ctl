package main

import (
	"bytes"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
)

// Inventory — NONE. The PORTED:/N/A: syntax claims @tests from the frozen bats corpus, and these
// assert a STATED DIVERGENCE from it: the frozen dispatcher took the next argument as an option's
// value whatever it was, and collected an empty operand and passed it on. Both were measured
// producing an exit code that says the wrong thing about what happened, so this tree refuses
// more than the reference did — and a divergence is pinned where it is made, not claimed against
// a corpus that does not contain it.

// --- an option is never a value -----------------------------------------------------------------

// TestOptionValueIsNeverAnotherOption closes a hole whose cost is DURABLE STATE, not a bad message.
//
// Measured before the fix: `install p1 --image --purge` exited 1, having taken `--purge` as the
// image and ENTERED INSTALLATION — and a live install persists trust floors, an installation
// identity and network state well before a bogus image reference fails to pull. So a malformed
// command line wrote state to the machine. `--version --index --bogus` exited 0, swallowing an
// unknown option whose refusal is the entire job of the option loop.
//
// The exit code is the assertion because it is the difference between "you typed something wrong"
// (2, nothing attempted) and "the tool tried and failed" (1, something may have happened).
func TestOptionValueIsNeverAnotherOption(t *testing.T) {
	// Every value-taking option, against every shape of thing that is not a value.
	for _, opt := range []string{"--index", "--policy", "--manifest-dir", "--image", "--to-bind"} {
		for _, notAValue := range []string{"--purge", "--bogus", "-x", "-", "--"} {
			args := []string{"install", "p1", opt, notAValue}
			var out, errb bytes.Buffer
			rc := run(args, strings.NewReader(""), &out, &errb)
			if rc != cliio.ExitUsage {
				t.Fatalf("%v: rc = %d, want %d (usage) — %q was taken as the value of %s",
					args, rc, cliio.ExitUsage, notAValue, opt)
			}
			if out.Len() != 0 {
				t.Fatalf("%v: a usage error leaked to stdout: %q", args, out.String())
			}
			if !strings.Contains(errb.String(), "is another option") {
				t.Fatalf("%v: stderr does not say why: %q", args, errb.String())
			}
		}
	}
	// AND A REAL VALUE STILL WORKS — including one that merely CONTAINS a dash, and one that is a
	// relative path an operator would write for a file whose name starts with one. A fix that
	// refused those would be refusing legitimate invocations, which no exit-2 assertion can see.
	for _, v := range []string{"foo", "some-file", "./-dashed", "/tmp/x-y"} {
		var out, errb bytes.Buffer
		if rc := run([]string{"--version", "--index", v}, strings.NewReader(""), &out, &errb); rc != 0 {
			t.Fatalf("--index %q: rc = %d, want 0 — a legitimate value was refused: %s", v, rc, errb.String())
		}
	}
}

// --- an empty operand is a usage error ----------------------------------------------------------

// TestEmptyOperandIsAUsageErrorForEveryVerb is the operand half of the same hole. An empty VALUE
// was already a usage error; an empty OPERAND was collected and passed on, so `status "" --plain`
// exited 0 — a malformed invocation reported as a SUCCESSFUL QUERY — while `install ""` and
// `backup ""` exited 1, reporting a typing mistake as work the tool attempted.
//
// EVERY VERB, not the three that were measured: the fix is central (one refusal in the option
// loop), so the matrix that proves it has to be central too. A per-verb fix would pass a
// three-verb test and leave the other nine.
func TestEmptyOperandIsAUsageErrorForEveryVerb(t *testing.T) {
	for _, v := range cliVerbs {
		for _, args := range [][]string{{v, ""}, {v, "", "--plain"}, {v, "p1", ""}} {
			var out, errb bytes.Buffer
			rc := run(args, strings.NewReader(""), &out, &errb)
			if rc != cliio.ExitUsage {
				t.Fatalf("%q: rc = %d, want %d (usage) — an empty operand was passed to the verb",
					args, rc, cliio.ExitUsage)
			}
			if out.Len() != 0 {
				t.Fatalf("%q: a usage error leaked to stdout: %q", args, out.String())
			}
			if !strings.Contains(errb.String(), "empty operand") {
				t.Fatalf("%q: stderr does not say why: %q", args, errb.String())
			}
		}
	}
	// The bare verb — no operand at all — is NOT this error. Several verbs are complete without
	// one, and turning "you gave nothing" into "you gave an empty string" would be a different
	// wrong answer.
	var out, errb bytes.Buffer
	if rc := run([]string{"status"}, strings.NewReader(""), &out, &errb); rc == cliio.ExitUsage {
		t.Fatalf("a bare verb was refused as an empty operand: %s", errb.String())
	}
}

// --- the same matrix, through the BUILT BINARY --------------------------------------------------

// TestBuiltBinaryReportsUsageErrorsAsExitTwo runs the measured invocations through the real
// artifact, over the rig's world (its DOCKER_HOST points at the in-process fake, so nothing here
// can reach an operator's real daemon).
//
// WHY A SECOND LANE. The in-process cases above read run()'s RETURN VALUE, which is the exit code
// only because main() passes it to os.Exit; what a script or CI observes is the PROCESS status.
// And it is how these defects must be re-measured: `go run` collapses every non-zero status to 1,
// so a reviewer checking `go run . install p1 --image --purge` sees 1 whether the dispatcher
// refused it (2) or the install ran and failed (1) — which is precisely the difference.
func TestBuiltBinaryReportsUsageErrorsAsExitTwo(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"install", "p1", "--image", "--purge"}, "is another option"},
		{[]string{"--version", "--index", "--bogus"}, "is another option"},
		{[]string{"install", ""}, "empty operand"},
		{[]string{"status", "", "--plain"}, "empty operand"},
		{[]string{"backup", ""}, "empty operand"},
	} {
		r := newCLIRig(t)
		rc, said := runBuilt(t, r, tc.args...)
		if rc != cliio.ExitUsage {
			t.Fatalf("%v: the BINARY exited %d, want %d (usage):\n%s", tc.args, rc, cliio.ExitUsage, said)
		}
		// EXITING 2 IS NOT ENOUGH — it must be 2 for THIS reason. Without the diagnostic check a
		// case that exited 2 down some other path (an unknown verb, a refused flag matrix) would
		// pass while asserting nothing about the hole under test.
		if !strings.Contains(said, tc.want) {
			t.Fatalf("%v: the binary exited 2 but not for this reason — %q is not in:\n%s", tc.args, tc.want, said)
		}
	}
	// THE LANE'S OWN LIVENESS. If the binary refused everything, every assertion above would be
	// vacuous — so an invocation that must SUCCEED is driven through the same binary and world.
	r := newCLIRig(t)
	rc, said := runBuilt(t, r, "--version")
	if rc != 0 || !strings.HasPrefix(said, "mythical-ctl ") {
		t.Fatalf("--version through the binary: rc=%d out=%q", rc, said)
	}
}
