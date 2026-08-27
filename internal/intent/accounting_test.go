package intent

import (
	"errors"
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

// PROBE INTENTS ARE SELECTED FROM A LISTING, so the two questions a keyed lookup asks — does this
// row describe what it is filed under, and is there exactly one of it — are never asked for them.
// And this is the listing whose rows become RUNTIME MUTATIONS: the caller removes the container
// each row names and then drops the record by key. Both questions are therefore asked here, over
// the whole listing, before any of it is handed back.
func TestProbeIntentsRefusesRowsThatDisagreeWithTheirKey(t *testing.T) {
	h := heldFor(t)
	a, err := NewProbeAccounting(h, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ledger.Live(h)
	write := func(lines ...string) {
		t.Helper()
		l := &ledger.Ledger{}
		l.ReplaceLines(lines)
		if err := ledger.Write(h, st, l); err != nil {
			t.Fatal(err)
		}
	}

	// THE KEY AND THE NAME DISAGREE. `name` is what gets removed; `key` is what gets dropped. This
	// row would have had container "b" removed and the record for "a" dropped — the wrong
	// container gone, and its own record left standing to say it is still there.
	write("intent\tkey=probe:a\tclass=probe\tname=b\tnonce=n1\tcreated=1700000000")
	_, err = a.ProbeIntents()
	if err == nil || !strings.Contains(err.Error(), "filed under") {
		t.Fatalf("a probe intent naming one object and keyed for another was listed: %v", err)
	}

	// THE OTHER DIRECTION: keyed in the probe namespace, describing a class that is not a probe.
	// Skipping it (as a class filter alone does) hides a probe container from every reap, and the
	// stray container then wedges the installation as an unrecorded same-identity object — which
	// is precisely what reaping exists to prevent.
	write("intent\tkey=probe:a\tclass=volume\tname=a\tnonce=n1\tcreated=1700000000")
	_, err = a.ProbeIntents()
	if err == nil || !strings.Contains(err.Error(), "filed under") {
		t.Fatalf("a probe-keyed row describing another class was skipped rather than reported: %v", err)
	}

	// TWO ROWS ANSWERING ONE KEY. The listing used to return both, so the caller reaped the
	// container on the first and only THEN did the keyed Drop refuse ErrAmbiguous — the runtime
	// mutated on evidence that contradicts itself, by a refusal that arrived one step too late.
	// Nothing is handed back at all, which is what makes the refusal arrive in time.
	write(
		"intent\tkey=probe:p1\tclass=probe\tname=p1\tnonce=n1\tcreated=1700000000",
		"intent\tkey=probe:p1\tclass=probe\tname=p1\tnonce=n2\tcreated=1700000000",
	)
	got, err := a.ProbeIntents()
	if err == nil || !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("two intents for one probe were both listed: %v", err)
	}
	if got != nil {
		t.Fatalf("a refused listing still handed back rows to act on: %+v", got)
	}

	// AND A WELL-FORMED SET STILL LISTS. The guard refuses disagreement, not probes.
	write(
		"intent\tkey=probe:p1\tclass=probe\tname=p1\tnonce=n1\tcreated=1700000000",
		"intent\tkey=probe:p2\tclass=probe\tname=p2\tnonce=n2\tcreated=1700000000",
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n3\tcreated=1700000000",
	)
	got, err = a.ProbeIntents()
	if err != nil {
		t.Fatalf("a well-formed probe listing was refused: %v", err)
	}
	if len(got) != 2 || got[0].Name != "p1" || got[1].Name != "p2" {
		t.Fatalf("intents = %+v", got)
	}
}
