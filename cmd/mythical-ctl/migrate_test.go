package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Inventory — tests/acceptance/migrate.bats (the CLI rows). The library rows are claimed in
// internal/migrate; these three are the dispatcher's own.
//
// PORTED: tests/acceptance/migrate.bats: "CLI: migrate-storage with no role is a usage error (2) and attempts nothing" -> TestMigrateStorageDispatchRefusals
// PORTED: tests/acceptance/migrate.bats: "CLI: migrate-storage with no --to-bind is a usage error (2) and attempts nothing" -> TestMigrateStorageDispatchRefusals
// PORTED: tests/acceptance/migrate.bats: "CLI: migrate-storage with a surplus operand is a usage error (2) and attempts nothing" -> TestMigrateStorageDispatchRefusals

// TestMigrateStorageDispatchRefusals is the refusal matrix: EVERY malformed invocation is a usage
// error (2) with NOTHING attempted, and every option this verb does not own is REFUSED rather than
// ignored. Silently honouring a misplaced option runs something other than what was written, and
// this verb mutates the fleet, the host and mythical.conf.
//
// "ATTEMPTS NOTHING" IS ASSERTED, NOT ASSUMED: each case runs against a family home that exists and
// is empty, and the home must still be empty afterwards. A refusal that had already taken the lock,
// read the ledger or created the state directory would leave a trace there.
func TestMigrateStorageDispatchRefusals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no role", []string{"migrate-storage", "p1", "--to-bind", "/data/p1"},
			"needs exactly <product> <role>"},
		{"no --to-bind", []string{"migrate-storage", "p1", "state"},
			"needs --to-bind"},
		{"surplus operand", []string{"migrate-storage", "p1", "state", "extra", "--to-bind", "/data/p1"},
			"needs exactly <product> <role>"},
		{"no operands at all", []string{"migrate-storage", "--to-bind", "/data/p1"},
			"needs exactly <product> <role>"},
		// Options belonging to other verbs: refused, not ignored.
		{"--purge", []string{"migrate-storage", "p1", "state", "--to-bind", "/d", "--purge"},
			"takes only --to-bind"},
		{"--family", []string{"migrate-storage", "p1", "state", "--to-bind", "/d", "--family"},
			"takes only --to-bind"},
		{"--image", []string{"migrate-storage", "p1", "state", "--to-bind", "/d", "--image", "x@sha256:0"},
			"takes only --to-bind"},
		{"--force-install", []string{"migrate-storage", "p1", "state", "--to-bind", "/d", "--force-install"},
			"takes only --to-bind"},
		{"--abandon", []string{"migrate-storage", "p1", "state", "--to-bind", "/d", "--abandon"},
			"takes only --to-bind"},
		// A value-taking option with no value is a usage error with nothing attempted — never the
		// operational failure an unchecked shift produces.
		{"--to-bind with no value", []string{"migrate-storage", "p1", "state", "--to-bind"},
			"requires a value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("MYTHICAL_HOME", home)
			var out, errb bytes.Buffer
			rc := run(tc.args, strings.NewReader(""), &out, &errb)
			if rc != 2 {
				t.Fatalf("rc = %d, want 2 (usage); stderr=%q", rc, errb.String())
			}
			if out.Len() != 0 {
				t.Fatalf("a usage error leaked to stdout: %q", out.String())
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("stderr %q does not name the fault (%q)", errb.String(), tc.want)
			}
			ents, err := os.ReadDir(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != 0 {
				t.Fatalf("the refusal touched the family home: %v", ents)
			}
		})
	}
}

// A WELL-FORMED invocation is NOT a usage error. Reporting one would hide a real dispatch defect
// behind the same exit code every malformed call produces, and would make the matrix above pass no
// matter what it did.
func TestMigrateStorageWellFormedIsNotAUsageError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MYTHICAL_HOME", home)
	var out, errb bytes.Buffer
	rc := run([]string{"migrate-storage", "p1", "state", "--to-bind", "/data/p1"},
		strings.NewReader(""), &out, &errb)
	if rc == 2 {
		t.Fatalf("a well-formed invocation reported a usage error: %q", errb.String())
	}
	if rc != 1 {
		t.Fatalf("rc = %d, want 1 (operational) while the runtime seams are unwired", rc)
	}
	if out.Len() != 0 {
		t.Fatalf("leaked to stdout: %q", out.String())
	}
}

// The verb appears in the help surface exactly once it is dispatched — --help never advertises what
// does not exist, and never omits what does.
func TestMigrateStorageIsInTheHelp(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"--help"}, strings.NewReader(""), &out, &errb); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	for _, want := range []string{"migrate-storage <product> <role> --to-bind PATH", "--map-foreign-to-operator"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the help surface does not carry %q", want)
		}
	}
}

// A RELATIVE --to-bind IS A MALFORMED INVOCATION, not a well-formed one that could not proceed.
// Every path comparison the migration makes is on absolute paths, and a relative operand resolves
// against whatever directory the process happens to be in — a location the operator did not name.
func TestMigrateStorageRefusesARelativeToBind(t *testing.T) {
	for _, rel := range []string{"relative/dest", "./dest", "dest", "../dest"} {
		home := t.TempDir()
		t.Setenv("MYTHICAL_HOME", home)
		var out, errb bytes.Buffer
		rc := run([]string{"migrate-storage", "p1", "state", "--to-bind", rel},
			strings.NewReader(""), &out, &errb)
		if rc != 2 {
			t.Fatalf("--to-bind %q: rc = %d, want 2 (usage); stderr=%q", rel, rc, errb.String())
		}
		if !strings.Contains(errb.String(), "absolute path") {
			t.Fatalf("--to-bind %q: stderr %q does not name the fault", rel, errb.String())
		}
		if ents, _ := os.ReadDir(home); len(ents) != 0 {
			t.Fatalf("the refusal touched the family home: %v", ents)
		}
	}
}
