package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — NONE, and the reason matters. The PORTED:/N/A: syntax claims @tests from the
// frozen bats corpus, and there is no row here to claim: the frozen dispatcher's `state)` and
// `net)` arms carry NO flag-refusal checks at all (verified against the deleted
// bin/mythical-ctl), so the corpus has no test asserting that they refuse, and porting it
// "exactly" reproduces the hole. What is below is therefore a DELIBERATE, STATED DIVERGENCE
// from the reference, in the same direction as every other divergence in this tree: strictly
// more refusing, never more permissive.
//
// WHY DIVERGE. `state repair` rebuilds installer state from runtime labels and `net rebind`
// moves the whole fleet's network attachment; both confirm and then mutate. The matrix the
// other seven verbs implement exists because "an option a verb takes without honouring is an
// option whose next reader assumes it worked" — and measured against the built binary before
// this change, `state repair --purge`, `state repair --family`, `net rebind --purge` and
// `net rebind --to-bind /tmp/x` all entered their verb with the flag silently dropped.

// misplacedForStateAndNet is every option neither verb takes. --plain is not in it because
// runEnv refuses it centrally for every verb but status, and asserting it here would pin the
// wrong refusal.
var misplacedForStateAndNet = [][]string{
	{"--purge"},
	{"--family"},
	{"--force-install"},
	{"--map-foreign-to-operator"},
	{"--abandon"},
	{"--image", "some/image:tag"},
	{"--to-bind", "/tmp/somewhere"},
}

// TestCLIStateRefusesOptionsThatBelongToOtherVerbs — with NOTHING attempted. The repair is set
// up to be POSSIBLE (a labelled volume to adopt, an identity to choose, confirmation granted),
// so "no identity was recorded" distinguishes a dispatcher that stopped the verb from one that
// merely could not have succeeded anyway.
func TestCLIStateRefusesOptionsThatBelongToOtherVerbs(t *testing.T) {
	for _, flag := range misplacedForStateAndNet {
		t.Run(strings.Join(flag, " "), func(t *testing.T) {
			r := newCLIRig(t).confirming()
			r.writeProduct("p1")
			r.labelledVolume("v1", "n1", "insta")

			args := append([]string{"state", "repair", "insta"}, r.docArgs()...)
			args = append(args, flag...)
			if rc := r.run(args...); rc != cliio.ExitUsage {
				t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
			}
			if !strings.Contains(r.said(), "state takes no options") {
				t.Fatalf("the refusal does not say which option matrix rejected it:\n%s", r.said())
			}
			if id, err := r.ledgerNow().IdentGet(); err == nil && id == "insta" {
				t.Fatal("the repair ran with the misplaced option silently ignored")
			}
		})
	}
}

// TestCLIStateAbandonIntentRefusesOptionsThatBelongToOtherVerbs — the other `state` subverb,
// which DELETES a write-ahead intent. Same gate, and it must fire before the subverb is even
// resolved.
func TestCLIStateAbandonIntentRefusesOptionsThatBelongToOtherVerbs(t *testing.T) {
	for _, flag := range misplacedForStateAndNet {
		t.Run(strings.Join(flag, " "), func(t *testing.T) {
			r := newCLIRig(t).confirming()
			r.env = append(r.env, "MI_INTENT_GRACE=0")
			r.writeProduct("p1")
			r.openIntent("net1")

			args := append([]string{"state", "abandon-intent", "network", "net1"}, r.docArgs()...)
			args = append(args, flag...)
			if rc := r.run(args...); rc != cliio.ExitUsage {
				t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
			}
			if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); err != nil {
				t.Fatalf("the intent was abandoned with the misplaced option silently ignored: %v", err)
			}
		})
	}
}

// openIntent records a live write-ahead intent — the thing `state abandon-intent` deletes, and
// therefore the evidence that a refused invocation deleted nothing.
func (r *cliRig) openIntent(name string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l, err := ledger.Read(st)
		if err != nil {
			r.t.Fatal(err)
		}
		if _, ierr := l.IdentEnsure(); ierr != nil {
			r.t.Fatal(ierr)
		}
		nonce, nerr := intent.NonceNew()
		if nerr != nil {
			r.t.Fatal(nerr)
		}
		if oerr := intent.Open(l, prov.ClassNetwork, name, nonce, time.Now()); oerr != nil {
			r.t.Fatal(oerr)
		}
		if werr := ledger.Write(h, st, l); werr != nil {
			r.t.Fatal(werr)
		}
	})
}

// TestCLINetRefusesOptionsThatBelongToOtherVerbs — with NOTHING attempted. As in
// TestCLINetRebindSurplusOperandIsUsage, the rebind is made POSSIBLE first: without a resolvable
// MYTHICAL_NET the verb refuses on its own and "no reference was recorded" would hold whether
// the dispatcher stopped the call or ran it.
func TestCLINetRefusesOptionsThatBelongToOtherVerbs(t *testing.T) {
	for _, flag := range misplacedForStateAndNet {
		t.Run(strings.Join(flag, " "), func(t *testing.T) {
			r := newCLIRig(t).confirming()
			r.writeProduct("p1")
			r.operatorNetwork("opnet")
			r.writeFamilyConf("MYTHICAL_NET=opnet\n")

			args := append([]string{"net", "rebind"}, r.docArgs()...)
			args = append(args, flag...)
			if rc := r.run(args...); rc != cliio.ExitUsage {
				t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
			}
			if !strings.Contains(r.said(), "net takes no options") {
				t.Fatalf("the refusal does not say which option matrix rejected it:\n%s", r.said())
			}
			if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
				t.Fatalf("a network reference was recorded with the misplaced option silently ignored: %v", err)
			}
		})
	}
}

// --- the same contract, against a BUILT BINARY -----------------------------------------------
//
// WHY A SECOND LANE FOR ONE ASSERTION. The in-process tests above read runEnv's RETURN VALUE,
// which is the exit code only because main() passes it to os.Exit. What a caller — a script, a
// package's postinstall, CI — actually observes is the PROCESS status, and the split between 2
// (usage error) and 1 (operational failure) is a contract those callers depend on. Nothing
// in-process can prove os.Exit is wired to it.
//
// It is also how this defect was found and how it must be re-measured: `go run` collapses every
// non-zero status to 1, so a reviewer checking `go run . state repair --purge` sees 1 whether
// the dispatcher refused or the verb failed. Only a built binary distinguishes them.

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error
)

// builtBinary builds cmd/mythical-ctl once for this package's test run and returns its path.
func builtBinary(t *testing.T) string {
	t.Helper()
	builtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mctl-exit-code-")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "mythical-ctl")
		// GOFLAGS/GOENV owned by the invocation, as everywhere else in this tree: an inherited
		// -tags would build something other than the shipped dispatcher.
		cmd := exec.Command("go", "build", "-o", builtPath, ".")
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOENV=off")
		if out, berr := cmd.CombinedOutput(); berr != nil {
			builtErr = errors.New("building the CLI under test: " + berr.Error() + "\n" + string(out))
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtPath
}

// runBuilt runs the built binary IN THE RIG'S WORLD and returns its PROCESS exit status plus
// both streams joined.
//
// THE ENVIRONMENT IS THE RIG'S, NOT THE MACHINE'S, and that is not tidiness. A subprocess handed
// a bare environment resolves the DEFAULT container-runtime socket — so on a developer's laptop
// these tests would drive the operator's REAL daemon, and in CI they would fail to reach one at
// all; the exit status would then be answering a different question on every machine that ran
// them. The rig's DOCKER_HOST points at its own in-process fake, which the subprocess reaches
// over that fake's unix socket, so what is measured here is the dispatcher and nothing else.
func runBuilt(t *testing.T, r *cliRig, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(builtBinary(t), args...)
	cmd.Env = append(append([]string{}, r.env...), "PATH="+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("running the built CLI: %v\n%s", err, out)
	}
	return ee.ExitCode(), string(out)
}

func TestBuiltBinaryRefusesMisplacedOptionsWithExitTwo(t *testing.T) {
	r := newCLIRig(t)
	// The verbs must be reachable for the exit status to mean anything: with no options at all
	// each of these exits 1 (an operational failure — no runtime objects, no MYTHICAL_NET), which
	// is exactly the status a silently-ignored option produced before this change. Asserting 2
	// therefore asserts the dispatcher stopped, not that the machine happens to be empty. The
	// control block below re-measures that per verb rather than assuming it.
	for _, verb := range [][]string{{"state", "repair"}, {"state", "abandon-intent", "network", "n1"}, {"net", "rebind"}} {
		for _, flag := range misplacedForStateAndNet {
			args := append(append([]string{}, verb...), flag...)
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				rc, said := runBuilt(t, r, args...)
				if rc != 2 {
					t.Fatalf("exit status %d, want 2 (usage error) — the option was accepted and the verb ran\n%s", rc, said)
				}
				if !strings.Contains(said, "takes no options") {
					t.Fatalf("exit 2 for some other reason than the option matrix:\n%s", said)
				}
			})
		}
	}
	// The control: the SAME verbs with no misplaced option are NOT usage errors. Without this the
	// assertions above are satisfied by a dispatcher that refuses `state` and `net` outright.
	for _, verb := range [][]string{{"state", "repair"}, {"state", "abandon-intent", "network", "n1"}, {"net", "rebind"}} {
		t.Run(strings.Join(verb, " ")+" (control)", func(t *testing.T) {
			rc, said := runBuilt(t, r, verb...)
			if rc == 2 {
				t.Fatalf("%v is itself a usage error, so the refusals above prove nothing:\n%s", verb, said)
			}
		})
	}
}

// TestBuiltBinaryDistinguishesUsageFromFailure pins the property the lane above depends on: the
// process really does exit 2 for a usage error and 1 for an operational one. If os.Exit ever
// stopped carrying run()'s return value, every exit-status assertion in this file would pass
// vacuously against whatever constant it started returning.
func TestBuiltBinaryDistinguishesUsageFromFailure(t *testing.T) {
	r := newCLIRig(t)
	if rc, said := runBuilt(t, r, "not-a-real-command"); rc != 2 {
		t.Fatalf("an unknown command exits %d, want 2\n%s", rc, said)
	}
	if rc, said := runBuilt(t, r, "--version"); rc != 0 {
		t.Fatalf("--version exits %d, want 0\n%s", rc, said)
	}
	if rc, said := runBuilt(t, r, "net", "rebind"); rc != 1 {
		t.Fatalf("a well-formed verb that cannot proceed exits %d, want 1 (operational failure)\n%s", rc, said)
	}
}
