package intent

import (
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
)

// ProbeAccounting has no bats ancestor: it is the DURABLE implementation of the seam Wave 3
// defined (internal/probe's Accounting) and stood an in-test fake behind. The probe behaviors
// themselves are covered by internal/probe's own suite against that fake; what is asserted here is
// that this implementation satisfies the contract that suite assumes — write-ahead, durable, and
// refusing what it cannot read.

func heldFor(t *testing.T) famlock.Held {
	t.Helper()
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	return h
}

func TestProbeAccountingSatisfiesTheSeam(t *testing.T) {
	var _ probe.Accounting = (*ProbeAccounting)(nil)

	h := heldFor(t)
	a, err := NewProbeAccounting(h, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	// A ledger that does not exist yet is an EMPTY list — first use, nothing of ours can exist.
	got, err := a.ProbeIntents()
	if err != nil {
		t.Fatalf("first use is not an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("first use listed %d intents", len(got))
	}
	// WRITE-AHEAD AND DURABLE: the record survives into a freshly-read ledger.
	if err := a.OpenProbe("mythical-i0123456789-probe", "n1"); err != nil {
		t.Fatal(err)
	}
	got, err = a.ProbeIntents()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "mythical-i0123456789-probe" || got[0].Nonce != "n1" {
		t.Fatalf("intents = %+v", got)
	}
	// It is an ordinary intent of class `probe` — visible to the rest of this module.
	st, _ := ledger.Live(h)
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := Find(l, prov.ClassProbe, "mythical-i0123456789-probe"); ferr != nil {
		t.Fatalf("the probe intent is not an intent: %v", ferr)
	}
	// DROP retires it.
	if err := a.DropProbe("mythical-i0123456789-probe"); err != nil {
		t.Fatal(err)
	}
	got, _ = a.ProbeIntents()
	if len(got) != 0 {
		t.Fatalf("drop left %d intents", len(got))
	}
}

func TestProbeAccountingNeedsTheLock(t *testing.T) {
	// The token is asserted UP FRONT, so a caller cannot build one from a lock it does not hold
	// and discover that only at the first probe — by which point the container exists.
	h, err := famlock.Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := famlock.Release(h); err != nil {
		t.Fatal(err)
	}
	// THE FAILURE IDENTITY, not merely that it failed. ledger.Live's own HomeOf shares the exact
	// same token check, so a released token is refused either way — what the up-front assertion
	// buys is the DOMAIN message ("refusing to record probe intents without holding the family
	// lock") in place of a bare "no valid token", and that difference is the only thing a test can
	// see. Asserting the wording is therefore what makes the assertion load-bearing rather than
	// decorative; measured, without it this case passes with the assertion deleted.
	_, err = NewProbeAccounting(h, nil)
	if err == nil {
		t.Fatal("accounting was built on a released lock")
	}
	if !strings.Contains(err.Error(), "family lock") || !strings.Contains(err.Error(), "record probe intents") {
		t.Fatalf("refused without naming what was refused or why: %v", err)
	}
}

func TestProbeIntentsReportsWhatItCannotRead(t *testing.T) {
	// A record whose nonce this module refuses to read is REPORTED, not skipped: the prober's reap
	// would otherwise walk past exactly the record that needs a human.
	h := heldFor(t)
	a, err := NewProbeAccounting(h, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ledger.Live(h)
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{"intent\tkey=probe:p1\tclass=probe\tname=p1\tnonce=\tcreated=1700000000"})
	if err := ledger.Write(h, st, l); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ProbeIntents(); err == nil {
		t.Fatal("an empty nonce was listed as a probe intent")
	}
	// And a record with no NAME loses the same way, one field earlier.
	l2 := &ledger.Ledger{}
	l2.ReplaceLines([]string{"intent\tkey=probe:p1\tclass=probe\tnonce=n1\tcreated=1700000000"})
	if err := ledger.Write(h, st, l2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ProbeIntents(); err == nil {
		t.Fatal("a nameless probe intent was listed")
	}
	// A non-probe intent is not a probe intent — the class is what selects, not the kind alone.
	l3 := &ledger.Ledger{}
	if err := Open(l3, prov.ClassVolume, "v1", "n1", fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(h, st, l3); err != nil {
		t.Fatal(err)
	}
	got, err := a.ProbeIntents()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a volume intent was listed as a probe: %+v", got)
	}
}
