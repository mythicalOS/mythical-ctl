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
// (restore.bats' "backup then restore: through the actual CLI" row is claimed in roundtrip_test.go,
// which owns the wired copy seam. It carries no N/A here: two claims on one row is how the wrong
// one of a pair hides behind the right one, so this is prose, not a second claim.)
// (restore.bats' "CLI: --abandon on other verbs is refused" row was N/A here while install was
// unwired. Install is wired, so the row is portable and is claimed in lifecycle_test.go by
// TestCLIInstallRejectsAbandon. The half this file still owns — that --abandon is refused by a verb
// which does not take it — stays asserted by TestBackupRefusesOtherVerbsOptions.)

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
// IT ALSO PINS THE NIL-SEAM REFUSAL ITSELF, which is still a live contract now that the seams are
// wired. A build assembled without them must report a missing capability and attempt NOTHING — no
// daemon connection, no lock, no filesystem — rather than dereferencing a seam that is not there,
// and the two seams are refused SEPARATELY, because a check that only looked at one of them would
// let a build with no location gate run a backup whose only authentication is that gate.
//
// The seams are package variables precisely so this remains measurable; they are restored on every
// path out, and nothing here runs in parallel.
func TestWellFormedInvocationReachesTheCapabilitySeam(t *testing.T) {
	origCopier, origSafe := newCopier, safeChain
	t.Cleanup(func() { newCopier, safeChain = origCopier, origSafe })
	for _, missing := range []string{"the copy seam", "the location seam", "both"} {
		newCopier, safeChain = origCopier, origSafe
		switch missing {
		case "the copy seam":
			newCopier = nil
		case "the location seam":
			safeChain = nil
		default:
			newCopier, safeChain = nil, nil
		}
		for _, args := range [][]string{
			{"backup", "/tmp/bk"},
			{"restore", "/tmp/bk"},
			{"restore", "--abandon"},
		} {
			rc, out, errb := rcOf(args...)
			if rc != 1 {
				t.Fatalf("%s missing, %v: rc = %d, want 1 (operational failure — the invocation was well formed)", missing, args, rc)
			}
			if out != "" {
				t.Fatalf("%s missing, %v: leaked to stdout: %q", missing, args, out)
			}
			if !strings.Contains(errb, "not available in this build yet") {
				t.Fatalf("%s missing, %v: stderr %q lacks the diagnostic", missing, args, errb)
			}
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
