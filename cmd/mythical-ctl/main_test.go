package main

import (
	"bytes"
	"strings"
	"testing"
)

// PORTED: tests/smoke.sh: "--version format is \"mythical-ctl <semver>\"" -> TestVersionFlag
// PORTED: tests/smoke.sh: "unknown command exits 2" -> TestUnknownVerbIsUsageErrorOnStderr
// PORTED: tests/smoke.sh: "usage errors go to stderr, not stdout" -> TestUnknownVerbIsUsageErrorOnStderr
// PORTED: tests/smoke.sh: "no arguments prints usage and exits 0" -> TestNoArgsPrintsUsageAndExitsZero
// (smoke.sh remains live against the built artifact; these are the same contracts in-process.)

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

// The bash dispatcher parses the whole argv before acting, so a trailing operand after a
// global flag is a usage error there — and must be here (`--version --bogus` exits 2).
func TestGlobalFlagsRefuseTrailingArgs(t *testing.T) {
	for _, args := range [][]string{{"--version", "--bogus"}, {"-v", "x"}, {"--help", "y"}} {
		var out, errb bytes.Buffer
		rc := run(args, strings.NewReader(""), &out, &errb)
		if rc != 2 {
			t.Fatalf("%v: rc = %d, want 2", args, rc)
		}
		if out.Len() != 0 {
			t.Fatalf("%v: leaked to stdout: %q", args, out.String())
		}
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
