package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — NONE. The PORTED:/N/A: syntax claims @tests from the frozen bats corpus, and this
// asserts something the corpus never asserted about either half: that a diagnostic's prescribed
// recovery command is a command the dispatcher will actually accept.

// quoted finds every single-quoted run in a diagnostic. It is deliberately NOT
// `'mythical-ctl ...'`: a prescription written as 'restore --abandon', without the binary name,
// would then not be found at all and would sail through this test unexecuted — which is exactly
// how the un-runnable one shipped. Everything quoted is looked at; what to do with each is
// decided below.
var quoted = regexp.MustCompile(`'([^']+)'`)

// cliVerbs is every verb the dispatcher accepts. A quoted string starting with one of these but
// NOT with the binary name is a prescription this test cannot execute, and it is refused rather
// than skipped. verbsAreReal keeps the list from drifting into fiction.
var cliVerbs = []string{
	"install", "start", "stop", "restart", "recreate",
	"status", "uninstall", "backup", "restore", "migrate-storage", "state", "net",
}

// TestCLIVerbsAreReal pins the list above to the dispatcher, so a verb that is renamed or
// removed cannot leave TestStagingDiagnosticPrescribesRunnableCommands quietly checking a name
// nothing answers to.
func TestCLIVerbsAreReal(t *testing.T) {
	r := newCLIRig(t)
	for _, v := range cliVerbs {
		r.run(v)
		if strings.Contains(r.said(), "unknown command") {
			t.Fatalf("cliVerbs names %q, which the dispatcher does not know:\n%s", v, r.said())
		}
	}
}

// TestStagingDiagnosticPrescribesRunnableCommands closes the gap that let the in-progress-restore
// diagnostic ship prescribing `mythical-ctl restore --resume` for as long as it did.
//
// A DIAGNOSTIC'S RECOVERY INSTRUCTION IS A CONTRACT WITH THE DISPATCHER, and nothing was holding
// the two together: the prose lived in internal/prov, the option matrix in this package, and no
// test in either place ever ran one against the other. `--resume` is not a flag the CLI has, so
// the option loop refused it as an unknown option (exit 2) — and it did so at the one moment the
// operator is following instructions literally because their restore was interrupted.
//
// So this test does not check for a string. It takes the diagnostic the real classifier
// produces, extracts every command it tells the operator to run, and RUNS each one through the
// real dispatcher, requiring that none of them is a usage error. A renamed verb, a renamed flag,
// or a new prescription for something that does not exist all redden here.
func TestStagingDiagnosticPrescribesRunnableCommands(t *testing.T) {
	r := newCLIRig(t).confirming()
	staging := filepath.Join(r.home, ".state", "ledger.staging")
	if err := os.WriteFile(staging, []byte("an interrupted restore left this\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// objs is nil deliberately: the staging classification is answered before FirstUse ever
	// reaches the runtime, so this is the diagnostic on its own terms.
	err := prov.FirstUse(context.Background(), r.home, nil)
	if err == nil || !strings.Contains(err.Error(), "restore is in progress") {
		t.Fatalf("the staging state was not classified: %v", err)
	}

	// The placeholders the prose is allowed to contain, and what each stands for. An unlisted
	// one fails rather than being passed to the dispatcher verbatim — a new placeholder is a new
	// claim about what the operator should type, and it must be looked at.
	placeholders := map[string]string{
		"<the same backup directory>": t.TempDir(),
	}

	var found [][]string
	for _, m := range quoted.FindAllStringSubmatch(err.Error(), -1) {
		switch {
		case strings.HasPrefix(m[1], "mythical-ctl "):
			found = append(found, []string{m[0], strings.TrimPrefix(m[1], "mythical-ctl ")})
		default:
			// A bare verb in quotes is a prescription that names no binary. It is REFUSED, not
			// skipped: skipping it is how a prescription escapes this test entirely.
			for _, v := range cliVerbs {
				if m[1] == v || strings.HasPrefix(m[1], v+" ") {
					t.Fatalf("the diagnostic prescribes %s without naming the binary, so nothing can "+
						"run it as written — write it as 'mythical-ctl %s'", m[0], m[1])
				}
			}
		}
	}
	if len(found) < 2 {
		t.Fatalf("the diagnostic prescribes %d commands, want at least the resume and the abandon:\n%v", len(found), err)
	}
	var ran []string
	for _, m := range found {
		line := m[1]
		for ph, real := range placeholders {
			line = strings.ReplaceAll(line, ph, real)
		}
		if i := strings.IndexByte(line, '<'); i >= 0 {
			t.Fatalf("the diagnostic prescribes %q, which carries a placeholder this test does not know how to fill", m[0])
		}
		args := strings.Fields(line)
		if len(args) == 0 {
			t.Fatalf("the diagnostic prescribes an empty command: %q", m[0])
		}
		rc := r.run(args...)
		if rc == cliio.ExitUsage {
			t.Fatalf("the diagnostic prescribes %q, which the dispatcher refuses as a usage error:\n%s",
				m[0], r.said())
		}
		ran = append(ran, args[0]+" "+strings.Join(args[1:], " "))
	}

	// And the two we expect are among them — so a diagnostic rewritten to prescribe only
	// something harmless (or nothing at all) cannot pass this test by having nothing to run.
	joined := strings.Join(ran, "\n")
	for _, want := range []string{"restore --abandon", "restore " + placeholders["<the same backup directory>"]} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the diagnostic no longer prescribes %q; it prescribes:\n%s", want, joined)
		}
	}
}
