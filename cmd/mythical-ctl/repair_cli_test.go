package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
)

// Inventory — the CLI-surface part of Task 24's share of tests/unit/repair.bats. The other
// forty-four owned tests are claimed in internal/verbs/repair_test.go; these three are here because
// what they pin is the DISPATCHER: an operand threaded through to the library, and the two arity
// gates that must refuse before anything is attempted.
//
// PORTED: tests/unit/repair.bats: "CLI: 'state repair <identity>' threads the chosen identity through to the library" -> TestCLIStateRepairThreadsTheIdentity
// PORTED: tests/unit/repair.bats: "CLI: 'state abandon-intent <class> <name> <extra>' is a usage error, nothing attempted" -> TestCLIAbandonIntentSurplusOperandIsUsage
// PORTED: tests/unit/repair.bats: "CLI: 'net rebind <extra>' is a usage error, nothing done" -> TestCLINetRebindSurplusOperandIsUsage

// confirming adds MI_CONFIRM=yes, so a confirmation gate resolves without a tty — the shell suite's
// setup() does the same for every repair test.
func (r *cliRig) confirming() *cliRig {
	r.env = append(r.env, "MI_CONFIRM=yes")
	return r
}

func (r *cliRig) withLock(fn func(famlock.Held, ledger.Store)) {
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
	fn(h, st)
}

func (r *cliRig) ledgerNow() *ledger.Ledger {
	r.t.Helper()
	l, err := ledger.Read(ledger.LiveRead(r.home))
	if err != nil {
		r.t.Fatalf("reading the ledger: %v", err)
	}
	return l
}

// labelledVolume stands a volume carrying an arbitrary installation identity — a candidate repair
// can be asked to adopt.
func (r *cliRig) labelledVolume(name, nonce, ident string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.fake.Client())
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, nonce)
		if perr != nil {
			r.t.Fatal(perr)
		}
		if err := rt.VolumeCreate(context.Background(), name, p); err != nil {
			r.t.Fatal(err)
		}
	})
}

func TestCLIStateRepairThreadsTheIdentity(t *testing.T) {
	// The reference parsed the identity operand and then called the library verb WITHOUT it, so the
	// library saw no choice and printed the "choose one explicitly" refusal even though the operator
	// DID choose — the one documented safe recovery path was unusable from the CLI.
	r := newCLIRig(t).confirming()
	r.writeProduct("p1")
	r.labelledVolume("v1", "n1", "insta")

	args := append([]string{"state", "repair", "insta"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	id, err := r.ledgerNow().IdentGet()
	if err != nil || id != "insta" {
		t.Fatalf("identity = %q (%v), want insta — the chosen identity did not reach the library", id, err)
	}
}

func TestCLIAbandonIntentSurplusOperandIsUsage(t *testing.T) {
	// The reference read only the first two operands and silently dropped a third, so this ran
	// exactly as `state abandon-intent network net1` — a malformed invocation that still confirmed
	// and performed the state-deleting action.
	r := newCLIRig(t).confirming()
	r.env = append(r.env, "MI_INTENT_GRACE=0")
	r.writeProduct("p1")
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l, err := ledger.Read(st)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.IdentEnsure(); err != nil {
			t.Fatal(err)
		}
		nonce, nerr := intent.NonceNew()
		if nerr != nil {
			t.Fatal(nerr)
		}
		if err := intent.Open(l, prov.ClassNetwork, "net1", nonce, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := ledger.Write(h, st, l); err != nil {
			t.Fatal(err)
		}
	})

	args := append([]string{"state", "abandon-intent", "network", "net1", "extra-garbage"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
	}
	if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); err != nil {
		t.Fatalf("the intent was abandoned by a malformed invocation: %v", err)
	}
}

func TestCLINetRebindSurplusOperandIsUsage(t *testing.T) {
	// The reference checked only that the first operand was "rebind" and never the count, so a
	// surplus one was silently dropped and the rebind performed anyway — which, with confirmation
	// granted non-interactively, moves the whole fleet's network attachment on a malformed
	// invocation.
	r := newCLIRig(t).confirming()
	r.writeProduct("p1")

	args := append([]string{"net", "rebind", "extra-garbage"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
	}
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a network reference was recorded by a malformed invocation: %v", err)
	}
}
