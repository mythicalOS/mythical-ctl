package main

import (
	"bytes"
	"strings"
	"testing"
)

// Inventory — the backup/restore CLI surface.
//
// PORTED: tests/acceptance/restore.bats: "CLI: backup needs exactly one operand (the output directory)" -> TestBackupOperandMatrix
// PORTED: tests/acceptance/restore.bats: "CLI: restore needs exactly one operand, or --abandon alone, never both" -> TestRestoreOperandMatrix
// PORTED: tests/acceptance/restore.bats: "CLI: backup refuses options that belong to other verbs" -> TestBackupRefusesOtherVerbsOptions
// PORTED: tests/acceptance/restore.bats: "CLI: restore refuses options that belong to other verbs" -> TestRestoreRefusesOtherVerbsOptions
// PORTED: tests/acceptance/restore.bats: "mi_verb_backup/mi_verb_restore reject the wrong number of arguments as a usage error" -> TestBackupOperandMatrix, TestRestoreOperandMatrix
// PORTED: tests/unit/backup.bats: "mi_verb_backup and mi_verb_restore reject bad arity as a USAGE error (rc 2)" -> TestBackupOperandMatrix, TestRestoreOperandMatrix
//
// N/A: tests/acceptance/restore.bats: "backup then restore: through the actual CLI (bin/mythical-ctl)" -- an end-to-end round trip through the CLI needs the PRODUCTION copy seam, and the copy module is its own port task: newCopier is nil in this build, so the CLI's own run path stops at the capability check (TestWellFormedInvocationReachesTheCapabilitySeam pins that it stops there and nowhere earlier). The round trip itself is covered at the library level by internal/backup's TestFullRoundTripPassesEveryIdentityCheck; when the copy module lands, this row becomes a CLI-level test.
// N/A: tests/acceptance/restore.bats: "CLI: --abandon on other verbs is refused, not silently ignored" -- the verb it names (install) is not wired in this build; refusing --abandon there belongs to that verb's own option matrix, which lands with it. Asserting exit 2 for `install p1 --abandon` today would pass on "unknown command", not on the refusal — a test that cannot fail for the reason it claims. The half of the rule this build CAN prove — that --abandon is refused by a verb that does not take it — is asserted by TestBackupRefusesOtherVerbsOptions.

// rcOf runs the entrypoint in process and returns its exit code and both streams.
func rcOf(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	rc := run(args, strings.NewReader(""), &out, &errb)
	return rc, out.String(), errb.String()
}

func TestBackupOperandMatrix(t *testing.T) {
	// EXACTLY ONE operand. Neither a missing nor a surplus one may be silently dropped and
	// acted on anyway: this writes a whole tree somewhere the operator named, so a malformed
	// invocation is a usage error with NOTHING attempted.
	for _, args := range [][]string{
		{"backup"},
		{"backup", "--index", "/tmp/i"},
		{"backup", "/tmp/bk", "extra"},
		{"backup", "/tmp/bk", "extra", "--policy", "/tmp/p"},
	} {
		rc, out, errb := rcOf(args...)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", args, rc)
		}
		if out != "" {
			t.Fatalf("%v: usage error leaked to stdout: %q", args, out)
		}
		if !strings.Contains(errb, "backup needs exactly") {
			t.Fatalf("%v: stderr %q lacks the diagnostic", args, errb)
		}
	}
}

func TestRestoreOperandMatrix(t *testing.T) {
	// EITHER exactly one operand OR --abandon alone — never both, never neither.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"restore"}, "restore needs exactly"},
		{[]string{"restore", "--index", "/tmp/i"}, "restore needs exactly"},
		{[]string{"restore", "/tmp/bk", "extra"}, "restore needs exactly"},
		{[]string{"restore", "/tmp/bk", "--abandon"}, "--abandon takes no directory"},
		{[]string{"restore", "--abandon", "/tmp/bk"}, "--abandon takes no directory"},
		{[]string{"restore", "--abandon", "/tmp/bk", "extra"}, "--abandon takes no directory"},
	} {
		rc, out, errb := rcOf(tc.args...)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", tc.args, rc)
		}
		if out != "" {
			t.Fatalf("%v: usage error leaked to stdout: %q", tc.args, out)
		}
		if !strings.Contains(errb, tc.want) {
			t.Fatalf("%v: stderr %q lacks %q", tc.args, errb, tc.want)
		}
	}
}

func TestBackupRefusesOtherVerbsOptions(t *testing.T) {
	// Every option that belongs to a different verb is REFUSED, not ignored. `backup DIR
	// --purge` returning 0 having quietly done something other than what was written is the
	// failure mode this matrix exists to prevent.
	for _, extra := range [][]string{
		{"--purge"},
		{"--family"},
		{"--force-install"},
		{"--abandon"},
		{"--map-foreign-to-operator"},
		{"--to-bind", "/tmp/x"},
		{"--image", "ghcr.io/x/y@sha256:0"},
	} {
		args := append([]string{"backup", "/tmp/bk"}, extra...)
		rc, out, errb := rcOf(args...)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", args, rc)
		}
		if out != "" {
			t.Fatalf("%v: leaked to stdout: %q", args, out)
		}
		if !strings.Contains(errb, "backup takes only") {
			t.Fatalf("%v: stderr %q lacks the diagnostic", args, errb)
		}
	}
}

func TestRestoreRefusesOtherVerbsOptions(t *testing.T) {
	for _, extra := range [][]string{
		{"--purge"},
		{"--family"},
		{"--force-install"},
		{"--map-foreign-to-operator"},
		{"--to-bind", "/tmp/x"},
		{"--image", "ghcr.io/x/y@sha256:0"},
	} {
		args := append([]string{"restore", "/tmp/bk"}, extra...)
		rc, out, errb := rcOf(args...)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", args, rc)
		}
		if out != "" {
			t.Fatalf("%v: leaked to stdout: %q", args, out)
		}
		if !strings.Contains(errb, "restore takes only") {
			t.Fatalf("%v: stderr %q lacks the diagnostic", args, errb)
		}
	}
}

// TestWellFormedInvocationReachesTheCapabilitySeam pins the ORDER: the option and operand
// matrices are judged FIRST, and only a well-formed invocation reaches the capability check.
// If that order inverted, every usage error on these two verbs would report "not available"
// (exit 1) and the whole matrix above would stop being reachable at all.
//
// It also pins that a build with no copy module attempts NOTHING — no daemon connection, no
// lock, no filesystem — rather than calling a seam that does not exist.
func TestWellFormedInvocationReachesTheCapabilitySeam(t *testing.T) {
	if newCopier != nil || safeChain != nil {
		t.Skip("the copy/location seams are wired in this build; this test pins the unwired one")
	}
	for _, args := range [][]string{
		{"backup", "/tmp/bk"},
		{"restore", "/tmp/bk"},
		{"restore", "--abandon"},
	} {
		rc, out, errb := rcOf(args...)
		if rc != 1 {
			t.Fatalf("%v: rc = %d, want 1 (operational failure — the invocation was well formed)", args, rc)
		}
		if out != "" {
			t.Fatalf("%v: leaked to stdout: %q", args, out)
		}
		if !strings.Contains(errb, "not available in this build yet") {
			t.Fatalf("%v: stderr %q lacks the diagnostic", args, errb)
		}
	}
}

func TestHelpAdvertisesBackupAndRestore(t *testing.T) {
	// A verb appears in the usage text only once its implementation lands, and the options it
	// takes appear with it — a help surface that names a flag the dispatcher refuses, or omits
	// one it requires, is worse than no help.
	rc, out, _ := rcOf("--help")
	if rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	for _, want := range []string{
		"backup <output-directory>", "restore <backup-directory>", "--abandon",
		"--index PATH", "--policy PATH", "--manifest-dir PATH",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the help surface lacks %q", want)
		}
	}
	if strings.Contains(out, "carries no lifecycle verbs yet") {
		t.Fatal("the help still claims this build carries no verbs")
	}
}
