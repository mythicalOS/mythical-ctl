package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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

// stagingShapes is every shape the staging path can take that FirstUse says something about.
//
// THE SHAPE IS THE WHOLE POINT OF THE TABLE. The single-case version of this test used one regular
// file with invalid bytes, and that one case is the ONLY one for which the resume-or-abandon
// prescription was ever true: internal/backup refuses a staging path that is not a regular file
// before it classifies anything, so a directory, a device node or a symlink got a diagnostic
// naming two commands whose only possible outcome is a second refusal. One case cannot notice
// that; four can.
var stagingShapes = []struct {
	name string
	make func(t *testing.T, p string)
	// resumable — does FirstUse call this an in-progress restore, and therefore prescribe the
	// resume and abandon commands? Exactly one shape may.
	resumable bool
}{
	{"a regular staging ledger", func(t *testing.T, p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("an interrupted restore left this\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}, true},
	{"a directory", func(t *testing.T, p string) {
		t.Helper()
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}, false},
	{"a dangling symlink", func(t *testing.T, p string) {
		t.Helper()
		if err := os.Symlink(p+".gone", p); err != nil {
			t.Fatal(err)
		}
	}, false},
	{"a named pipe", func(t *testing.T, p string) {
		t.Helper()
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}, false},
}

// contradictions are the refusals that mean THE VERB CANNOT ACT ON THE STATE THE DIAGNOSTIC
// DESCRIBED. A prescribed command that produces one of these is not a recovery instruction: the
// diagnostic said "a restore is in progress, finish it or give it up" and the verb it named
// answers "there is nothing here I can classify" or "there is no restore to abandon". Exit status
// cannot see this — both are ordinary operational failures, exit 1 — which is why the earlier
// version of this test, accepting any failure that was not a usage error, could not catch it.
var contradictions = []string{
	"is present but is not a regular file",
	"there is no in-progress restore to abandon",
	"there is no restore in progress",
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
	for _, shape := range stagingShapes {
		t.Run(shape.name, func(t *testing.T) {
			// EACH PRESCRIPTION GETS ITS OWN MACHINE, and that is not a convenience. The
			// diagnostic offers ALTERNATIVES — resume it, or give it up — so running them one
			// after another in a single home asks the second command about the world the first one
			// left, which is a state no operator following the instruction is ever in.
			fresh := func(t *testing.T) *cliRig {
				t.Helper()
				r := newCLIRig(t).confirming()
				shape.make(t, filepath.Join(r.home, ".state", "ledger.staging"))
				return r
			}
			r := fresh(t)

			// objs is nil deliberately: the staging classification is answered before FirstUse ever
			// reaches the runtime, so this is the diagnostic on its own terms.
			err := prov.FirstUse(context.Background(), r.home, nil)
			if err == nil {
				t.Fatalf("%s at the staging path was classified as a first install", shape.name)
			}
			if strings.Contains(err.Error(), "restore is in progress") != shape.resumable {
				t.Fatalf("%s was%s called an in-progress restore:\n%v", shape.name,
					map[bool]string{true: "", false: " not"}[shape.resumable], err)
			}

			// The placeholders the prose is allowed to contain, and what each stands for. An
			// unlisted one fails rather than being passed to the dispatcher verbatim — a new
			// placeholder is a new claim about what the operator should type, and it must be
			// looked at.
			placeholders := map[string]string{
				"<the same backup directory>": t.TempDir(),
			}

			var found [][]string
			for _, m := range quoted.FindAllStringSubmatch(err.Error(), -1) {
				switch {
				case strings.HasPrefix(m[1], "mythical-ctl "):
					found = append(found, []string{m[0], strings.TrimPrefix(m[1], "mythical-ctl ")})
				default:
					// A bare verb in quotes is a prescription that names no binary. It is
					// REFUSED, not skipped: skipping it is how a prescription escapes this test
					// entirely.
					for _, v := range cliVerbs {
						if m[1] == v || strings.HasPrefix(m[1], v+" ") {
							t.Fatalf("the diagnostic prescribes %s without naming the binary, so nothing can "+
								"run it as written — write it as 'mythical-ctl %s'", m[0], m[1])
						}
					}
				}
			}
			if len(found) == 0 {
				t.Fatalf("the diagnostic prescribes nothing runnable:\n%v", err)
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
				one := fresh(t)
				rc := one.run(args...)
				if rc == cliio.ExitUsage {
					t.Fatalf("the diagnostic prescribes %q, which the dispatcher refuses as a usage error:\n%s",
						m[0], one.said())
				}
				// AND IT IS NOT CONTRADICTED BY THE VERB IT NAMES. This is the assertion the
				// earlier version did not make, and the whole reason a mis-classified staging
				// path could ship a prescription nothing could carry out.
				for _, c := range contradictions {
					if strings.Contains(one.said(), c) {
						t.Fatalf("with %s at the staging path the diagnostic prescribes %q, and running it answers\n"+
							"%q — the verb cannot act on the state the diagnostic described:\n%s",
							shape.name, m[0], c, one.said())
					}
				}
				ran = append(ran, args[0]+" "+strings.Join(args[1:], " "))
			}

			// And the commands appropriate to THIS shape are the ones prescribed — so a diagnostic
			// rewritten to prescribe only something harmless cannot pass by having nothing to run,
			// and one that keeps prescribing a resume for a path no resume can touch cannot pass by
			// having its prescription merely not blow up.
			joined := strings.Join(ran, "\n")
			resume := []string{"restore --abandon", "restore " + placeholders["<the same backup directory>"]}
			for _, want := range resume {
				if shape.resumable && !strings.Contains(joined, want) {
					t.Fatalf("the diagnostic no longer prescribes %q; it prescribes:\n%s", want, joined)
				}
				if !shape.resumable && strings.Contains(joined, want) {
					t.Fatalf("with %s at the staging path the diagnostic still prescribes %q:\n%s",
						shape.name, want, joined)
				}
			}
			if !shape.resumable && !strings.Contains(joined, "state repair") {
				t.Fatalf("with %s at the staging path the diagnostic prescribes no repair:\n%s", shape.name, joined)
			}
		})
	}
}
