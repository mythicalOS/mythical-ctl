package main

import (
	"bytes"
	"strings"
	"testing"
)

// Inventory — NONE. The PORTED:/N/A: syntax is reserved for the bats corpus, which is the thing
// the cutover deletes and therefore the only thing needing a claim; tests/smoke.sh SURVIVES the
// cutover and keeps running against the built artifact, so a machine-readable claim on it would
// look audited without being auditable — and was in fact wrong three ways when it was one (two
// names paraphrased, one invented). What is true, in prose: the tests below assert in-process the
// same four contracts smoke.sh asserts against the binary — the "mythical-ctl <semver>" version
// shape (TestVersionFlag), an unknown command exiting 2 with nothing on stdout
// (TestUnknownVerbIsUsageErrorOnStderr), and no-args printing usage and exiting 0
// (TestNoArgsPrintsUsageAndExitsZero). Two lanes on one contract, deliberately.

func TestVersionFlag(t *testing.T) {
	for _, flag := range []string{"--version", "-v"} {
		var out, errb bytes.Buffer
		rc := run([]string{flag}, strings.NewReader(""), &out, &errb)
		if rc != 0 {
			t.Fatalf("%s: rc = %d, want 0", flag, rc)
		}
		if !strings.HasPrefix(out.String(), "mythical-ctl ") {
			t.Fatalf("%s: output %q lacks the 'mythical-ctl <semver>' shape", flag, out.String())
		}
		if errb.Len() != 0 {
			t.Fatalf("%s: wrote to stderr: %q", flag, errb.String())
		}
	}
}

func TestUnknownVerbIsUsageErrorOnStderr(t *testing.T) {
	var out, errb bytes.Buffer
	rc := run([]string{"frobnicate"}, strings.NewReader(""), &out, &errb)
	if rc != 2 {
		t.Fatalf("rc = %d, want 2 (usage)", rc)
	}
	if out.Len() != 0 {
		t.Fatalf("usage error leaked to stdout: %q", out.String())
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Fatalf("stderr %q lacks the diagnostic", errb.String())
	}
}

func TestNoArgsPrintsUsageAndExitsZero(t *testing.T) {
	var out, errb bytes.Buffer
	rc := run(nil, strings.NewReader(""), &out, &errb)
	if rc != 0 || !strings.Contains(out.String(), "USAGE") {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
}

// MEASURED against the frozen dispatcher: a trailing OPTION after a global flag exits 2
// (`--version --bogus`); a trailing bare OPERAND is collected then ignored, exiting 0
// (`--version product`). Both halves are parity, so both are pinned.
func TestGlobalFlagsTrailingArgParity(t *testing.T) {
	for _, args := range [][]string{{"--version", "--bogus"}, {"-v", "-x"}, {"--help", "--y"}} {
		var out, errb bytes.Buffer
		rc := run(args, strings.NewReader(""), &out, &errb)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", args, rc)
		}
		if out.Len() != 0 {
			t.Fatalf("%v: leaked to stdout: %q", args, out.String())
		}
	}
	for _, args := range [][]string{{"--version", "product"}, {"--help", "product"},
		{"--version", "--index", "foo"}, {"--version", "--purge"}} {
		var out, errb bytes.Buffer
		if rc := run(args, strings.NewReader(""), &out, &errb); rc != 0 {
			t.Fatalf("%v: rc = %d, want 0 (bash consumes known options and ignores them here)", args, rc)
		}
	}
	// A value-taking option with no value is a usage error with nothing attempted — bash's
	// _need_val, measured: `--version --index` exits 2.
	var out, errb bytes.Buffer
	if rc := run([]string{"--version", "--index"}, strings.NewReader(""), &out, &errb); rc != 2 {
		t.Fatalf("--version --index: rc = %d, want 2", rc)
	}
	if !strings.Contains(errb.String(), "requires a value") {
		t.Fatalf("missing-value diagnostic absent: %q", errb.String())
	}
}

func TestHelpFlag(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		var out, errb bytes.Buffer
		rc := run([]string{flag}, strings.NewReader(""), &out, &errb)
		if rc != 0 || !strings.Contains(out.String(), "EXIT CODES") {
			t.Fatalf("%s: rc=%d out=%q", flag, rc, out.String())
		}
	}
}
