// NO BATS INVENTORY. --plain and the status dashboard have no counterpart in the frozen
// reference, which has only the plain report; no bats test describes either and none is claimed
// here. status's own option and arity matrices remain claimed by internal/verbs/status_test.go and are not
// re-asserted below.
package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
)

// withTerminal makes the terminal test answer yes for the duration of one test, so the --plain
// override is asserted against a decision that would otherwise have been true. A test process
// has no terminal, and without this the override would be asserted against a false that was
// already false.
func withTerminal(t *testing.T, answer bool) {
	t.Helper()
	prev := statusIsInteractive
	statusIsInteractive = func([]string, io.Reader, io.Writer) bool { return answer }
	t.Cleanup(func() { statusIsInteractive = prev })
}

// TestPlainWinsOverATerminal — an operator who asked for the plain report at a terminal must get
// the same bytes a pipe gets.
func TestPlainWinsOverATerminal(t *testing.T) {
	withTerminal(t, true)
	if statusInteractive(true, nil, nil, nil) {
		t.Fatal("--plain did not force the plain report at a terminal")
	}
}

// TestATerminalWithoutPlainGetsTheDashboard.
func TestATerminalWithoutPlainGetsTheDashboard(t *testing.T) {
	withTerminal(t, true)
	if !statusInteractive(false, nil, nil, nil) {
		t.Fatal("a terminal did not get the dashboard")
	}
}

// TestAPipeGetsThePlainReportWithOrWithoutTheFlag — the flag is an override, not the only way to
// reach the plain path.
func TestAPipeGetsThePlainReportWithOrWithoutTheFlag(t *testing.T) {
	withTerminal(t, false)
	for _, plain := range []bool{false, true} {
		if statusInteractive(plain, nil, nil, nil) {
			t.Fatalf("plain=%v: a pipe was given the dashboard", plain)
		}
	}
}

// TestPlainIsRefusedForEveryOtherVerb. An option a verb takes without honouring is an option
// whose next reader assumes it worked — so it is a usage error, with nothing attempted.
func TestPlainIsRefusedForEveryOtherVerb(t *testing.T) {
	for _, args := range [][]string{
		{"install", "brokkr", "--plain"},
		{"start", "brokkr", "--plain"},
		{"uninstall", "brokkr", "--plain"},
		{"backup", "/tmp/out", "--plain"},
		{"restore", "/tmp/in", "--plain"},
	} {
		var out, errb bytes.Buffer
		rc := runEnv(args, nil, strings.NewReader(""), &out, &errb)
		if rc != cliio.ExitUsage {
			t.Fatalf("%v: rc %d, want %d", args, rc, cliio.ExitUsage)
		}
		if !strings.Contains(errb.String(), "--plain applies to status only") {
			t.Fatalf("%v: stderr %q", args, errb.String())
		}
	}
}

// TestPlainIsAcceptedByStatus — it must not be swept up by the refusal above, and status's own
// "no options other than" matrix must not reject it either.
func TestPlainIsAcceptedByStatus(t *testing.T) {
	var out, errb bytes.Buffer
	// The environment is empty, so this gets no further than locating the family home; what is
	// asserted is that it was NOT stopped as a usage error before that.
	rc := runEnv([]string{"status", "--plain"}, nil, strings.NewReader(""), &out, &errb)
	if rc == cliio.ExitUsage {
		t.Fatalf("status --plain was refused as a usage error: %q", errb.String())
	}
	if strings.Contains(errb.String(), "--plain applies to status only") {
		t.Fatalf("status refused its own flag: %q", errb.String())
	}
	if strings.Contains(errb.String(), "status takes no options") {
		t.Fatalf("status's option matrix rejected --plain: %q", errb.String())
	}
}

// TestStatusActuallyRoutesThroughTheDashboardDecision. Without this, the whole routing could be
// removed — status calling the verb directly again — and every other test here would still pass:
// they exercise the decision function, not the fact that `status` consults it.
//
// The seam is what makes the assertion possible without a terminal: it is consulted exactly once
// per status invocation, and a status that did not route through driveStatus would not consult it
// at all.
func TestStatusActuallyRoutesThroughTheDashboardDecision(t *testing.T) {
	consulted := 0
	prev := statusIsInteractive
	statusIsInteractive = func([]string, io.Reader, io.Writer) bool {
		consulted++
		return false
	}
	t.Cleanup(func() { statusIsInteractive = prev })

	var out, errb bytes.Buffer
	// A real family home, so the report gets past locating it and actually runs. There is no
	// container runtime here, which is the "unobservable" path the report is built to survive.
	env := []string{"MYTHICAL_HOME=" + t.TempDir(), "DOCKER_HOST=tcp://127.0.0.1:1"}
	runEnv([]string{"status"}, env, strings.NewReader(""), &out, &errb)
	if consulted != 1 {
		t.Fatalf("the terminal decision was consulted %d times; status is not routed through\n"+
			"  driveStatus, so at a terminal it would print instead of drawing", consulted)
	}
}

// TestPlainIsDocumented — a flag the help does not mention is a flag nobody finds.
func TestPlainIsDocumented(t *testing.T) {
	if !strings.Contains(usage, "--plain") {
		t.Fatal("--plain is not in the usage text")
	}
}

// TestAnUnknownOptionIsStillAUsageError — the new case in the option loop must not have widened
// what the loop accepts.
func TestAnUnknownOptionIsStillAUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runEnv([]string{"status", "--plainly"}, nil, strings.NewReader(""), &out, &errb); rc != cliio.ExitUsage {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(errb.String(), "unknown option: --plainly") {
		t.Fatalf("stderr %q", errb.String())
	}
}
