package main

import (
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
)

// identityRecorded reports whether the installer state ledger still records an installation — the
// single fact a family reset destroys, and therefore the one a refused family reset must preserve.
func (r *cliRig) identityRecorded() bool {
	r.t.Helper()
	h, err := famlock.Acquire(r.home)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, serr := ledger.Live(h)
	if serr != nil {
		r.t.Fatal(serr)
	}
	l, rerr := ledger.Read(st)
	if rerr != nil {
		return false
	}
	_, ierr := l.IdentGet()
	return ierr == nil
}

// Inventory — the one CLI-surface test in the status/uninstall share of tests/acceptance/lifecycle.bats, as
// internal/verbs/owners.go partitions them. What it pins is the DISPATCHER: `--family` and a
// product argument are contradictory, and the contradiction is refused before anything opens.
// That share's other forty-six owned tests are claimed in internal/verbs/status_test.go and
// internal/verbs/uninstall_test.go.
//
// PORTED: tests/acceptance/lifecycle.bats: "CLI: uninstall <product> --family is a usage error, not a silent family wipe that drops the product" -> TestCLIUninstallProductWithFamilyIsAUsageError

func TestCLIUninstallProductWithFamilyIsAUsageError(t *testing.T) {
	// Before the fix, --family was honoured and the product argument ignored — a materially MORE
	// destructive operation than the one written. A confirmation cannot rescue an operator from
	// that, because the prompt they answer is about the wipe: MI_CONFIRM=yes would have let it run
	// to completion. It must be refused as a usage error FIRST, leaving the installation intact.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d, want 0\n%s", rc, r.said())
	}
	if !r.isMember("p1") {
		t.Fatal("the fixture install did not complete")
	}

	r.env = append(r.env, "MI_CONFIRM=yes")
	if rc := r.run("uninstall", "p1", "--family"); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "uninstall --family takes no product") {
		t.Fatalf("not the dispatcher's own refusal:\n%s", r.said())
	}
	if !r.identityRecorded() {
		t.Fatal("the identity was wiped — the family uninstall ran anyway")
	}
	if !r.isMember("p1") {
		t.Fatal("p1 was dropped")
	}
}

// --- the rest of the dispatcher's uninstall/status surface -------------------------------------
//
// The bats suite tests these through the LIBRARY, where the two scopes are two functions and the
// contradiction above cannot be expressed at all. What only the dispatcher can get wrong is the
// mapping from an argument line onto those two functions, so that is what is pinned here.

func TestCLIUninstallTakesExactlyOneProduct(t *testing.T) {
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.env = append(r.env, "MI_CONFIRM=yes")
	// Neither zero nor two: a family-scoped wipe is spelled --family, and a second product is an
	// operand this verb has nowhere to put — dropping it silently would uninstall something other
	// than what was written.
	for _, args := range [][]string{{"uninstall"}, {"uninstall", "p1", "p2"}} {
		if rc := r.run(args...); rc != cliio.ExitUsage {
			t.Fatalf("%v: rc = %d, want 2\n%s", args, rc, r.said())
		}
		if !strings.Contains(r.said(), "uninstall takes exactly one product") {
			t.Fatalf("%v: no refusal diagnostic:\n%s", args, r.said())
		}
	}
	if !r.isMember("p1") {
		t.Fatal("a refused invocation uninstalled the product anyway")
	}
}

func TestCLIUninstallRejectsInstallOnlyOptions(t *testing.T) {
	// uninstall does not install and does not migrate storage: those options are refused, not
	// ignored — the same discipline the lifecycle verbs apply to --purge and --family.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	r.env = append(r.env, "MI_CONFIRM=yes")
	for _, extra := range [][]string{
		{"--image", cliDigestRef("other")},
		{"--force-install"},
		{"--to-bind", "/tmp/x"},
		{"--map-foreign-to-operator"},
		{"--abandon"},
	} {
		args := append([]string{"uninstall", "p1"}, extra...)
		if rc := r.run(args...); rc != cliio.ExitUsage {
			t.Fatalf("%v: rc = %d, want 2\n%s", extra, rc, r.said())
		}
		if !strings.Contains(r.said(), "apply elsewhere") {
			t.Fatalf("%v: no refusal diagnostic:\n%s", extra, r.said())
		}
	}
	if !r.isMember("p1") {
		t.Fatal("a refused invocation uninstalled the product anyway")
	}
}

func TestCLIStatusRejectsMutatingOptions(t *testing.T) {
	// status READS. A stray mutating option is a usage error, not something to accept and ignore:
	// `status p1 --purge` must not be answered with a report that merely happened to destroy
	// nothing this time.
	r := newCLIRig(t)
	r.writeProduct("p1")
	for _, extra := range [][]string{
		{"--purge"}, {"--family"}, {"--force-install"},
		{"--image", cliDigestRef("other")}, {"--to-bind", "/tmp/x"},
		{"--map-foreign-to-operator"}, {"--abandon"},
	} {
		args := append([]string{"status"}, extra...)
		if rc := r.run(args...); rc != cliio.ExitUsage {
			t.Fatalf("%v: rc = %d, want 2\n%s", extra, rc, r.said())
		}
		if !strings.Contains(r.said(), "status takes no options other than --index") {
			t.Fatalf("%v: no refusal diagnostic:\n%s", extra, r.said())
		}
	}
	if len(r.fake.RequestLog()) != 0 {
		t.Fatalf("a refused status reached the daemon: %v", r.fake.RequestLog())
	}
}

func TestCLIStatusReportsAndExitsZero(t *testing.T) {
	// The dispatcher reaches the report, hands it the product filter, and relays its exit code —
	// which is 0 even with bad news, because a monitoring wrapper needs it to succeed in order to
	// read the output.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	if rc := r.run("status", "p1", "--index", filepath.Join(r.home, "index")); rc != cliio.ExitOK {
		t.Fatalf("status rc = %d, want 0\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "p1: desired=running") {
		t.Fatalf("the report did not reach the dispatcher's streams:\n%s", r.said())
	}
	if !strings.Contains(r.said(), "volume mythical-") {
		t.Fatalf("the report named no volumes:\n%s", r.said())
	}
}

func TestCLIUninstallDrivesTheProductScope(t *testing.T) {
	// The plain product scope, end to end through the dispatcher: the container goes, the volume
	// stays, and the operator is told so per volume.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}
	if rc := r.run("uninstall", "p1"); rc != cliio.ExitOK {
		t.Fatalf("uninstall rc = %d, want 0\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "keeping volume") {
		t.Fatalf("no per-volume statement:\n%s", r.said())
	}
	if !r.isMember("p1") {
		t.Fatal("a product uninstall dropped membership")
	}
}

func TestCLIStatusReportsWhenTheRuntimeCannotEvenBeLocated(t *testing.T) {
	// Endpoint resolution is fail-closed on purpose, and every MUTATING verb must inherit that
	// refusal. status must not: it is the command an operator runs to find out why the others are
	// refusing, and routing it through the same door made the one diagnostic a broken installation
	// reaches for the one command a broken installation cannot run.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d\n%s", rc, r.said())
	}

	// A remote DOCKER_HOST: local-only by contract, so resolution REFUSES rather than falling back.
	var env []string
	for _, kv := range r.env {
		if strings.HasPrefix(kv, "DOCKER_HOST=") {
			continue
		}
		env = append(env, kv)
	}
	r.env = append(env, "DOCKER_HOST=tcp://example.invalid:2375")

	if rc := r.run("status"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 — status is never gated by its own findings\n%s", rc, r.said())
	}
	// The refusal is REPORTED, and the ledger half of the report is still produced.
	if !strings.Contains(r.said(), "could not be located") {
		t.Fatalf("the runtime refusal was swallowed:\n%s", r.said())
	}
	if !strings.Contains(r.said(), "installation: ") {
		t.Fatalf("the ledger half of the report is missing:\n%s", r.said())
	}
	if !strings.Contains(r.said(), "runtime:      UNAVAILABLE") {
		t.Fatalf("the report did not name the live half as unobservable:\n%s", r.said())
	}
	if !strings.Contains(r.said(), "volume mythical-") {
		t.Fatalf("the recorded volumes were not reported:\n%s", r.said())
	}
}
