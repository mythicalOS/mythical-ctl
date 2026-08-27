package intent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — tests/unit/intent.bats.
//
// PORTED: tests/unit/intent.bats: "a nonce is unique across calls and is a safe label value" -> TestNonceNew
// PORTED: tests/unit/intent.bats: "nonces do not repeat across many calls in one run" -> TestNonceNew
// PORTED: tests/unit/intent.bats: "an intent is recorded BEFORE the object and carries its creation time" -> TestOpenRecordsAhead
// PORTED: tests/unit/intent.bats: "an intent with no nonce is refused — it could never be reconciled" -> TestOpenRefusesEmptyNonce
// PORTED: tests/unit/intent.bats: "confirm records provenance and drops the intent, in ONE ledger write" -> TestConfirm
// PORTED: tests/unit/intent.bats: "confirm is ONE ledger write — the count is the crash-window guarantee, so the count is pinned" -> TestConfirmIsOneWrite
// PORTED: tests/unit/intent.bats: "confirm REFUSES when there is no intent for it to be the second half of" -> TestConfirmRefusals
// PORTED: tests/unit/intent.bats: "confirm REFUSES a nonce that is not the durable intent's, and consumes nothing" -> TestConfirmRefusals
// PORTED: tests/unit/intent.bats: "confirm REFUSES an intent row whose class and name describe something else" -> TestConfirmRefusals
// PORTED: tests/unit/intent.bats: "confirm PRESERVES two intents answering for one key rather than collapsing them" -> TestConfirmPreservesContradictions
// PORTED: tests/unit/intent.bats: "confirm PRESERVES a second tombstone for the name it is re-creating" -> TestConfirmPreservesContradictions
// PORTED: tests/unit/intent.bats: "reconcile adopts EXACTLY ONE label match" -> TestReconcileAdoptsOne
// PORTED: tests/unit/intent.bats: "reconcile with ZERO matches REISSUES a volume, then re-inspects the nonce" -> TestReconcileReissuesVolume
// PORTED: tests/unit/intent.bats: "a reissue that meets an EXISTING same-name volume is NOT adopted — the nonce differs" -> TestReconcileReissuesVolume
// PORTED: tests/unit/intent.bats: "a reissued volume that vanishes before its nonce is read is retained, not refused" -> TestReconcileReissuesVolume
// PORTED: tests/unit/intent.bats: "reconcile NEVER reissues a network (D38) — the intent is retained" -> TestReconcileNeverReissuesNetwork
// PORTED: tests/unit/intent.bats: "MORE THAN ONE match stops and reports every candidate — never deletes to disambiguate" -> TestReconcileMultipleMatches
// PORTED: tests/unit/intent.bats: "the multiple-match report NAMES every candidate" -> TestReconcileMultipleMatches
// PORTED: tests/unit/intent.bats: "reconcile RETAINS the intent when the runtime cannot be asked — zero is not an answer" -> TestReconcileRetainsWhenUnasked
// PORTED: tests/unit/intent.bats: "reconcile does NOT adopt an object labelled for ANOTHER installation" -> TestReconcileOwnershipRefusals
// PORTED: tests/unit/intent.bats: "reconcile does NOT adopt an object carrying our nonce and NO installation label" -> TestReconcileOwnershipRefusals
// PORTED: tests/unit/intent.bats: "reconcile does NOT adopt an object of ours standing under a DIFFERENT name" -> TestReconcileOwnershipRefusals
// PORTED: tests/unit/intent.bats: "an inspect that could not be answered is NOT an adoption" -> TestReconcileOwnershipRefusals
// PORTED: tests/unit/intent.bats: "an object listed and then removed is retained, not adopted" -> TestReconcileOwnershipRefusals
// PORTED: tests/unit/intent.bats: "a network that vanishes between the label and the id is retained, not adopted" -> TestReconcileNetworkID
// PORTED: tests/unit/intent.bats: "an id that could not be read after the labels answered is not an adoption" -> TestReconcileNetworkID
// PORTED: tests/unit/intent.bats: "reconcile REFUSES a container intent and keeps it" -> TestReconcileRefusesContainer
// PORTED: tests/unit/intent.bats: "the container refusal does not stop the classes reconcile is right for" -> TestReconcileRefusesContainer
// PORTED: tests/unit/intent.bats: "a retained network intent is not abandonable before the grace period" -> TestAbandonGracePeriod
// PORTED: tests/unit/intent.bats: "after the grace period with still zero matches it becomes abandonable" -> TestAbandonGracePeriod
// PORTED: tests/unit/intent.bats: "abandonment is not possible while the daemon is unreachable" -> TestAbandonNeedsAnAnsweringDaemon
// PORTED: tests/unit/intent.bats: "abandonment clears the intent and says it does NOT guarantee convergence" -> TestAbandonClearsTheIntent
// PORTED: tests/unit/intent.bats: "an intent whose creation time is not a number is never aged out" -> TestAbandonRefusesUnreadableAge
// PORTED: tests/unit/intent.bats: "a grace period that is not a number refuses rather than ageing everything out" -> TestAbandonRefusesUnreadableAge (a Duration cannot be non-numeric; the surviving half is the NEGATIVE grace, which fails open in the same direction)
// PORTED: tests/unit/intent.bats: "a FOREIGN object carrying our nonce is not our object appearing, and does not wedge abandonment" -> TestAbandonOwnershipCases
// PORTED: tests/unit/intent.bats: "an object of OURS carrying this nonce under another name refuses abandonment" -> TestAbandonOwnershipCases
// PORTED: tests/unit/intent.bats: "an abandoned intent's object surfacing later is UNRECORDED SAME-IDENTITY, and stops" -> TestGateUnrecorded
// PORTED: tests/unit/intent.bats: "a TOMBSTONED object that still exists is unrecorded, and stops" -> TestGateUnrecorded
// PORTED: tests/unit/intent.bats: "a FOREIGN-identity object is reported as unattributed and never stops an operation" -> TestGateUnattributedNeverStops
// PORTED: tests/unit/intent.bats: "the unattributed listing NEVER proposes removal" -> TestGateUnattributedNeverStops
// PORTED: tests/unit/intent.bats: "an UNLABELLED object holding a name we would create BLOCKS creation" -> TestGateColliding
// PORTED: tests/unit/intent.bats: "an unlabelled object NOT holding one of our names is ignored entirely" -> TestGateColliding
// PORTED: tests/unit/intent.bats: "a confirmed object is NOT unrecorded — the gate passes once provenance exists" -> TestGateAccountedFor
// PORTED: tests/unit/intent.bats: "an object with a LIVE intent is not unrecorded — the intent accounts for it" -> TestGateAccountedFor
// PORTED: tests/unit/intent.bats: "a record does NOT account for a DIFFERENT object standing at the name it records" -> TestGateAccountsRules
// PORTED: tests/unit/intent.bats: "an INTENT does not account for an object carrying a different nonce either" -> TestGateAccountsRules
// PORTED: tests/unit/intent.bats: "a record describing something ELSE accounts for nothing, even with a matching nonce" -> TestGateAccountsRules
// PORTED: tests/unit/intent.bats: "an EMPTY nonce on both sides is not a match — a record with no identity accounts for nothing" -> TestGateAccountsRules
// PORTED: tests/unit/intent.bats: "the gate STOPS when the runtime cannot be listed — an empty answer is not no answer" -> TestGateUnasked
// PORTED: tests/unit/intent.bats: "an object whose label could not be read STOPS the gate instead of being ignored" -> TestGateUnasked
// PORTED: tests/unit/intent.bats: "an object whose NONCE could not be read is not accounted for by a record that names it" -> TestGateUnasked
// PORTED: tests/unit/intent.bats: "an object the LEDGER cannot answer for stops the gate as UNASKED, not as unrecorded" -> TestGateUnasked
// PORTED: tests/unit/intent.bats: "two INTENT rows answering for one key stop the gate as unasked, like two records do" -> TestGateUnasked
// PORTED: tests/unit/intent.bats: "an object removed between the listing and the question about it is not reported as unlabelled" -> TestGateGoneBetweenListingAndQuestion
// N/A: tests/unit/intent.bats: "a clock that cannot be read REFUSES, instead of recording created=0" -- the caller supplies `now`, so there is no read that can fail. The half that ports is that a value which would fail the age comparison OPEN is refused: TestOpenRefusesUnusableTimestamp asserts a zero or negative creation time is never recorded.
// N/A: tests/unit/intent.bats: "a clock that cannot be read also refuses to AGE an intent, rather than aging it out" -- same reason; the unreadable-threshold half ports as the negative-grace refusal in TestAbandonRefusesUnreadableAge.

// --- fakes ---------------------------------------------------------------------------------------

type fakeObjs struct {
	obj       map[string]map[string]string // "class:name" -> labels
	list      map[prov.Class][]string
	listFail  map[prov.Class]bool
	nonceFail map[prov.Class]bool
	labelErr  map[string]error // "class:name" -> transport failure
	pingErr   error
	netID     map[string]string
	netIDErr  error
	// answerNonce makes an object FINDABLE by the nonce it is indexed under while ANSWERING with
	// a different one when asked directly — the shape a reassigned name produces, where the search
	// index and the object's own answer disagree.
	answerNonce map[string]string
	// nonceErr fails the NONCE label while the INSTALL label still answers.
	nonceErr map[string]bool
}

func newFake() *fakeObjs {
	return &fakeObjs{
		obj: map[string]map[string]string{}, list: map[prov.Class][]string{},
		listFail: map[prov.Class]bool{}, nonceFail: map[prov.Class]bool{},
		labelErr: map[string]error{}, netID: map[string]string{},
	}
}

func (f *fakeObjs) put(class prov.Class, name string, labels map[string]string) {
	f.obj[string(class)+":"+name] = labels
	f.list[class] = append(f.list[class], name)
}

func (f *fakeObjs) Label(_ context.Context, class prov.Class, name, label string) (string, error) {
	k := string(class) + ":" + name
	if err := f.labelErr[k]; err != nil {
		return "", err
	}
	m, ok := f.obj[k]
	if !ok {
		return "", engine.ErrAbsent
	}
	if label == prov.LabelNonce {
		if f.nonceErr[k] {
			return "", errors.New("the container runtime did not answer")
		}
		if v, override := f.answerNonce[k]; override {
			return v, nil
		}
	}
	return m[label], nil
}

func (f *fakeObjs) Names(_ context.Context, class prov.Class) ([]string, error) {
	if f.listFail[class] {
		return nil, errors.New("the container runtime did not answer")
	}
	return f.list[class], nil
}

func (f *fakeObjs) Ping(context.Context) error { return f.pingErr }

func (f *fakeObjs) FindByNonce(_ context.Context, class prov.Class, nonce string) ([]string, error) {
	if f.nonceFail[class] {
		return nil, errors.New("the container runtime did not answer")
	}
	var out []string
	for k, labels := range f.obj {
		pfx := string(class) + ":"
		if !strings.HasPrefix(k, pfx) {
			continue
		}
		if labels[prov.LabelNonce] == nonce {
			out = append(out, strings.TrimPrefix(k, pfx))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeObjs) NetworkID(_ context.Context, name string) (string, error) {
	if f.netIDErr != nil {
		return "", f.netIDErr
	}
	if _, ok := f.obj["network:"+name]; !ok {
		return "", engine.ErrAbsent
	}
	return f.netID[name], nil
}

type fakeReissuer struct {
	err   error
	calls int
	made  func()
}

func (r *fakeReissuer) VolumeCreate(_ context.Context, _ string, _ engine.Provenance) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	if r.made != nil {
		r.made()
	}
	return nil
}

func identLedger(t *testing.T) (*ledger.Ledger, string) {
	t.Helper()
	l := &ledger.Ledger{}
	id, err := l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	return l, id
}

var fixedNow = time.Unix(1_700_000_000, 0)

// --- nonces and opening --------------------------------------------------------------------------

func TestNonceNew(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := NonceNew()
		if err != nil {
			t.Fatal(err)
		}
		// A SAFE LABEL VALUE and the reference's shape: `n` + 16 lowercase hex.
		if len(n) != 17 || n[0] != 'n' {
			t.Fatalf("shape: %q", n)
		}
		for i := 1; i < len(n); i++ {
			if !(n[i] >= '0' && n[i] <= '9' || n[i] >= 'a' && n[i] <= 'f') {
				t.Fatalf("not lowercase hex: %q", n)
			}
		}
		if !ledger.FieldOK(ledger.Field{Key: "nonce", Value: n}) {
			t.Fatalf("not a safe field value: %q", n)
		}
		if seen[n] {
			t.Fatalf("repeated within one run: %q", n)
		}
		seen[n] = true
	}
}

func TestOpenRecordsAhead(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Open(l, prov.ClassVolume, "v1", "n1", fixedNow, ledger.Field{Key: "product", Value: "brokkr"}); err != nil {
		t.Fatal(err)
	}
	// THE RECORD EXISTS BEFORE THE OBJECT — and nothing has been recorded as provenance yet.
	if _, err := prov.Find(l, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("opening an intent wrote provenance: %v", err)
	}
	rec, err := Find(l, prov.ClassVolume, "v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ k, v string }{
		{"key", "volume:v1"}, {"class", "volume"}, {"name", "v1"}, {"nonce", "n1"},
		{"created", "1700000000"}, {"product", "brokkr"},
	} {
		if got, ok := ledger.FieldOf(rec, w.k); !ok || got != w.v {
			t.Errorf("%s = %q (present=%v), want %q", w.k, got, ok, w.v)
		}
	}
}

func TestOpenRefusesEmptyNonce(t *testing.T) {
	// REFUSED ON THE WAY IN AS WELL AS ON THE WAY OUT: an intent that names no object can never be
	// reconciled and would sit in the ledger forever.
	l := &ledger.Ledger{}
	if err := Open(l, prov.ClassVolume, "v1", "", fixedNow); err == nil {
		t.Fatal("an empty nonce was recorded")
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused open still wrote")
	}
	// And on the way OUT: a restored ledger can carry one, and every reader must refuse it rather
	// than run a label query that matches nothing and looks like a clean zero.
	l2 := &ledger.Ledger{}
	l2.ReplaceLines([]string{"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=\tcreated=1700000000"})
	rec, err := Find(l2, prov.ClassVolume, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nonceOf(rec, "v1"); err == nil || !strings.Contains(err.Error(), "EMPTY nonce") {
		t.Fatalf("an empty nonce was read as a nonce: %v", err)
	}
	// A record with no nonce FIELD AT ALL loses the same way, one step earlier.
	l3 := &ledger.Ledger{}
	l3.ReplaceLines([]string{"intent\tkey=volume:v1\tclass=volume\tname=v1\tcreated=1700000000"})
	rec3, _ := Find(l3, prov.ClassVolume, "v1")
	if _, err := nonceOf(rec3, "v1"); err == nil || !strings.Contains(err.Error(), "carries no nonce") {
		t.Fatalf("a missing nonce was read as a nonce: %v", err)
	}
}

func TestOpenRefusesUnusableTimestamp(t *testing.T) {
	// The reference refused when it could not READ the clock, because its fallback `created=0`
	// made an intent older than any grace period the moment it was written — a delayed create
	// could then surface after abandonment. The caller supplies the clock here, so what is refused
	// is the VALUE that fails the age comparison open.
	l := &ledger.Ledger{}
	for _, ts := range []time.Time{time.Unix(0, 0), time.Unix(-1, 0)} {
		if err := Open(l, prov.ClassVolume, "v1", "n1", ts); err == nil {
			t.Errorf("a creation time of %d was recorded", ts.Unix())
		}
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused open still wrote")
	}
}

// --- confirmation --------------------------------------------------------------------------------

func TestConfirm(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Open(l, prov.ClassVolume, "v1", "n1", fixedNow, ledger.Field{Key: "role", Value: "state"}); err != nil {
		t.Fatal(err)
	}
	if err := Confirm(l, prov.ClassVolume, "v1", "n1", ledger.Field{Key: "role", Value: "state"}); err != nil {
		t.Fatal(err)
	}
	// PROVENANCE IN, INTENT OUT.
	rec, err := prov.Find(l, prov.ClassVolume, "v1")
	if err != nil {
		t.Fatalf("no provenance after confirm: %v", err)
	}
	if n, _ := ledger.FieldOf(rec, "nonce"); n != "n1" {
		t.Fatalf("nonce = %q", n)
	}
	if _, err := Find(l, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the intent survived the confirmation: %v", err)
	}
	// A tombstone from an earlier removal is dropped: the object is standing again, so the record
	// of its removal is no longer the surviving account of it.
	l2 := &ledger.Ledger{}
	if err := prov.Record(l2, prov.ClassVolume, "v1", "old"); err != nil {
		t.Fatal(err)
	}
	if err := prov.Tombstone(l2, prov.ClassVolume, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := Open(l2, prov.ClassVolume, "v1", "n2", fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := Confirm(l2, prov.ClassVolume, "v1", "n2"); err != nil {
		t.Fatal(err)
	}
	if _, err := prov.TombstoneFind(l2, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("a tombstone survived beside a live object record: %v", err)
	}
}

func TestConfirmIsOneWrite(t *testing.T) {
	// THE COUNT IS THE CRASH-WINDOW GUARANTEE. In the Go shape the ledger is mutated in memory and
	// the CALLER persists, so "one write" is structural — what is pinned here is that the pair is
	// atomic in the only sense available: at no point between the two edits is the ledger
	// observable, and either both land or neither does.
	l := &ledger.Ledger{}
	if err := Open(l, prov.ClassVolume, "v1", "n1", fixedNow); err != nil {
		t.Fatal(err)
	}
	before := len(l.Lines())
	// A confirmation that REFUSES leaves the ledger byte-identical: no provenance written, no
	// intent dropped, nothing half-done for a crash to freeze.
	if err := Confirm(l, prov.ClassVolume, "v1", "wrong-nonce"); err == nil {
		t.Fatal("a mismatched nonce was confirmed")
	}
	if got := l.Lines(); len(got) != before {
		t.Fatalf("a refused confirmation changed the ledger: %v", got)
	}
	if _, err := prov.Find(l, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("a refused confirmation wrote provenance")
	}
	if _, err := Find(l, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("a refused confirmation consumed the intent: %v", err)
	}
}

func TestConfirmRefusals(t *testing.T) {
	// NOTHING TO BE THE SECOND HALF OF: provenance is written for an object this installer
	// recorded that it was about to create, never on its own.
	l := &ledger.Ledger{}
	err := Confirm(l, prov.ClassVolume, "v1", "n1")
	if err == nil || !strings.Contains(err.Error(), "nothing this") {
		t.Fatalf("confirm without an intent: %v", err)
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused confirmation wrote")
	}
	// A NONCE THAT IS NOT THE DURABLE INTENT'S: two different objects. Recording one while
	// dropping the record of the other leaves whatever is standing there accounted for by nothing.
	l2 := &ledger.Ledger{}
	if err := Open(l2, prov.ClassVolume, "v1", "n1", fixedNow); err != nil {
		t.Fatal(err)
	}
	err = Confirm(l2, prov.ClassVolume, "v1", "n2")
	if err == nil || !strings.Contains(err.Error(), "two different objects") {
		t.Fatalf("mismatched nonce: %v", err)
	}
	if _, ferr := Find(l2, prov.ClassVolume, "v1"); ferr != nil {
		t.Fatal("the intent was consumed by a refused confirmation")
	}
	// AN INTENT ROW DESCRIBING SOMETHING ELSE is conflicting evidence: consuming it would record
	// one object's identity under another's name.
	l3 := &ledger.Ledger{}
	l3.ReplaceLines([]string{"intent\tkey=volume:v1\tclass=container\tname=other\tnonce=n1\tcreated=1700000000"})
	err = Confirm(l3, prov.ClassVolume, "v1", "n1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("an intent about something else was consumed: %v", err)
	}
	if len(l3.Lines()) != 1 {
		t.Fatal("evidence destroyed")
	}
}

func TestConfirmPreservesContradictions(t *testing.T) {
	// TWO INTENTS answering one key: nothing is read from them and nothing replaces them.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tcreated=1700000000",
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n2\tcreated=1700000000",
	})
	if err := Confirm(l, prov.ClassVolume, "v1", "n1"); !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("two intents were collapsed: %v", err)
	}
	if len(l.Lines()) != 2 {
		t.Fatalf("evidence destroyed: %v", l.Lines())
	}
	// TWO TOMBSTONES for the name being re-created: the confirmation drops the tombstone, so its
	// cardinality question is the confirmation's too — and it must refuse BEFORE the object record
	// has been rewritten, not after.
	l2 := &ledger.Ledger{}
	l2.ReplaceLines([]string{
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tcreated=1700000000",
		"tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=a\tgen=1",
		"tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=b\tgen=1",
	})
	if err := Confirm(l2, prov.ClassVolume, "v1", "n1"); !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("contradictory tombstones were collapsed: %v", err)
	}
	if len(l2.Lines()) != 3 {
		t.Fatalf("evidence destroyed: %v", l2.Lines())
	}
	if _, err := prov.Find(l2, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("the object record was rewritten before the tombstone question was asked")
	}
}

func mustOpen(t *testing.T, l *ledger.Ledger, class prov.Class, name, nonce string) {
	t.Helper()
	if err := Open(l, class, name, nonce, fixedNow); err != nil {
		t.Fatal(err)
	}
}

// --- reconciliation ------------------------------------------------------------------------------

func TestReconcileAdoptsOne(t *testing.T) {
	ctx := context.Background()
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	if err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("a provable match was not adopted: %v", err)
	}
	if _, err := prov.Find(l, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("adoption wrote no provenance: %v", err)
	}
	if _, err := Find(l, prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("the intent survived adoption")
	}
	// A network is adopted by its ID (§6a rejects names as reassignable).
	l2, id2 := identLedger(t)
	mustOpen(t, l2, prov.ClassNetwork, "net", "n2")
	f2 := newFake()
	f2.put(prov.ClassNetwork, "net", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "n2"})
	f2.netID["net"] = "netid123"
	if err := Reconcile(ctx, l2, f2, nil, prov.ClassNetwork, "net"); err != nil {
		t.Fatal(err)
	}
	rec, err := prov.Find(l2, prov.ClassNetwork, "net")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ledger.FieldOf(rec, "id"); v != "netid123" {
		t.Fatalf("network id = %q", v)
	}
}

func TestReconcileReissuesVolume(t *testing.T) {
	ctx := context.Background()
	// ZERO matches: a volume is reissued, and the reissue is NOT the proof — what it returned is
	// asked the same ownership question as anything else.
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	r := &fakeReissuer{made: func() {
		f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	}}
	if err := Reconcile(ctx, l, f, r, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("reissue+adopt: %v", err)
	}
	if r.calls != 1 {
		t.Fatalf("reissue calls = %d", r.calls)
	}
	if _, err := prov.Find(l, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("no provenance after reissue: %v", err)
	}

	// A reissue that MEETS AN EXISTING same-name volume: `volume create` against an existing name
	// SUCCEEDS and returns whatever already holds it, without applying our labels. The nonce
	// differs, so it is NOT adopted.
	l2, id2 := identLedger(t)
	mustOpen(t, l2, prov.ClassVolume, "v1", "n1")
	f2 := newFake()
	r2 := &fakeReissuer{made: func() {
		f2.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "someone-elses"})
	}}
	err := Reconcile(ctx, l2, f2, r2, prov.ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("an existing same-name volume was adopted: %v", err)
	}
	// AND IT IS A REFUSAL, NOT A RETENTION. ErrRetained tells a caller "nothing is wrong, carry on
	// and try again later" — which is exactly what must NOT happen here: no number of later runs
	// turns someone else's volume into ours. The reference draws the same line (rc 1, not rc 4).
	if errors.Is(err, ErrRetained) {
		t.Fatal("contradictory ownership evidence was reported as a benign retention")
	}
	if _, ferr := Find(l2, prov.ClassVolume, "v1"); ferr != nil {
		t.Fatal("the intent was dropped despite not adopting")
	}
	if _, ferr := prov.Find(l2, prov.ClassVolume, "v1"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("provenance was written for an object that was not adopted")
	}

	// A reissued volume that VANISHES before its nonce is read is RETAINED, not refused: nothing
	// is wrong, there is simply nothing to adopt on this run.
	l3, _ := identLedger(t)
	mustOpen(t, l3, prov.ClassVolume, "v1", "n1")
	f3 := newFake()
	r3 := &fakeReissuer{} // creates nothing the fake can see
	err = Reconcile(ctx, l3, f3, r3, prov.ClassVolume, "v1")
	if !errors.Is(err, ErrRetained) {
		t.Fatalf("a vanished reissue was not retained: %v", err)
	}
	if _, ferr := Find(l3, prov.ClassVolume, "v1"); ferr != nil {
		t.Fatal("the intent was dropped")
	}

	// A reissue that FAILS retains the intent for the next run.
	l4, _ := identLedger(t)
	mustOpen(t, l4, prov.ClassVolume, "v1", "n1")
	r4 := &fakeReissuer{err: errors.New("daemon refused")}
	err = Reconcile(ctx, l4, newFake(), r4, prov.ClassVolume, "v1")
	if !errors.Is(err, ErrRetained) {
		t.Fatalf("a failed reissue was not retained: %v", err)
	}
}

func TestReconcileNeverReissuesNetwork(t *testing.T) {
	ctx := context.Background()
	// D38: a network is NEVER reissued — two networks answering one name is the failure this
	// refusal exists to prevent. The intent is retained and the operator is offered abandonment.
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	r := &fakeReissuer{}
	err := Reconcile(ctx, l, newFake(), r, prov.ClassNetwork, "net")
	if !errors.Is(err, ErrRetained) || !strings.Contains(err.Error(), "never reissued") {
		t.Fatalf("network reissue: %v", err)
	}
	if r.calls != 0 {
		t.Fatal("a network was reissued")
	}
	if _, ferr := Find(l, prov.ClassNetwork, "net"); ferr != nil {
		t.Fatal("the network intent was dropped")
	}
}

func TestReconcileMultipleMatches(t *testing.T) {
	ctx := context.Background()
	// MORE THAN ONE match cannot be safely disambiguated — and every candidate is NAMED. The
	// reference's report stopped correctly and named none of them.
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	f.put(prov.ClassVolume, "v-other", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("duplicate matches were disambiguated: %v", err)
	}
	for _, want := range []string{"v1", "v-other"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("candidate %q not named: %v", want, err)
		}
	}
	// Never deletes to disambiguate, and never adopts one of them.
	if _, ferr := prov.Find(l, prov.ClassVolume, "v1"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("one of two candidates was adopted")
	}
	if _, ferr := Find(l, prov.ClassVolume, "v1"); ferr != nil {
		t.Fatal("the intent was dropped")
	}
}

func TestReconcileRetainsWhenUnasked(t *testing.T) {
	ctx := context.Background()
	// ZERO IS NOT AN ANSWER when the question could not be asked: reissuing, adopting and
	// abandoning would all be decided from a search that never ran.
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	f.nonceFail[prov.ClassVolume] = true
	r := &fakeReissuer{}
	err := Reconcile(ctx, l, f, r, prov.ClassVolume, "v1")
	if !errors.Is(err, ErrRetained) {
		t.Fatalf("an unasked search was not retained: %v", err)
	}
	if r.calls != 0 {
		t.Fatal("a volume was reissued on the strength of a search that never ran")
	}
	if _, ferr := Find(l, prov.ClassVolume, "v1"); ferr != nil {
		t.Fatal("the intent was dropped")
	}
}

func TestReconcileOwnershipRefusals(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		labels map[string]string
		as     string // the name the object stands at, when different
		want   string
	}{
		{"another installation", map[string]string{prov.LabelInstall: "i9999999999", prov.LabelNonce: "n1"}, "v1", "another installation's object"},
		{"no installation label", map[string]string{prov.LabelNonce: "n1"}, "v1", "NO installation label"},
		{"a different name", nil, "v-other", "the intent is for"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, id := identLedger(t)
			mustOpen(t, l, prov.ClassVolume, "v1", "n1")
			f := newFake()
			labels := tc.labels
			if labels == nil {
				labels = map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"}
			}
			f.put(prov.ClassVolume, tc.as, labels)
			err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("adopted or refused wrongly: %v", err)
			}
			// CONTRADICTORY OWNERSHIP EVIDENCE IS A REFUSAL. All three of these — labelled for
			// another installation, carrying no label, standing under a different name — are facts
			// that contradict the record, and a later run does not resolve them. Reporting them as
			// ErrRetained would tell an ErrRetained-aware caller to carry on.
			if errors.Is(err, ErrRetained) {
				t.Fatal("contradictory ownership evidence was reported as a benign retention")
			}
			if _, ferr := prov.Find(l, prov.ClassVolume, "v1"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
				t.Fatal("provenance was written")
			}
			if _, ferr := Find(l, prov.ClassVolume, "v1"); ferr != nil {
				t.Fatal("the intent was dropped")
			}
		})
	}

	// AN INSPECT THAT COULD NOT BE ANSWERED IS NOT AN ADOPTION.
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	f.labelErr["volume:v1"] = errors.New("daemon down")
	if err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1"); !errors.Is(err, ErrRetained) {
		t.Fatalf("an unanswerable inspect: %v", err)
	}

	// LISTED AND THEN REMOVED: retained, not adopted — and not an error either.
	l2, _ := identLedger(t)
	mustOpen(t, l2, prov.ClassVolume, "v1", "n1")
	f2 := newFake()
	f2.put(prov.ClassVolume, "v1", map[string]string{prov.LabelNonce: "n1"})
	delete(f2.obj, "volume:v1") // gone between the listing and the question
	f2.obj["volume:v1"] = nil
	delete(f2.obj, "volume:v1")
	if err := Reconcile(ctx, l2, f2, &fakeReissuer{}, prov.ClassVolume, "v1"); !errors.Is(err, ErrRetained) {
		t.Fatalf("a vanished candidate: %v", err)
	}
}

func TestReconcileNetworkID(t *testing.T) {
	ctx := context.Background()
	// A network that VANISHES between the label and the id: retained, not adopted.
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	f := newFake()
	f.put(prov.ClassNetwork, "net", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	f.netIDErr = engine.ErrAbsent
	err := Reconcile(ctx, l, f, nil, prov.ClassNetwork, "net")
	if !errors.Is(err, ErrRetained) || !strings.Contains(err.Error(), "already gone") {
		t.Fatalf("vanished network: %v", err)
	}
	// An id that COULD NOT BE READ after the labels answered is not an adoption.
	f.netIDErr = errors.New("daemon down")
	err = Reconcile(ctx, l, f, nil, prov.ClassNetwork, "net")
	if !errors.Is(err, ErrRetained) {
		t.Fatalf("unreadable id: %v", err)
	}
	// An EMPTY id is nothing to record: a network is recorded by its id.
	f.netIDErr = nil
	f.netID["net"] = ""
	err = Reconcile(ctx, l, f, nil, prov.ClassNetwork, "net")
	if !errors.Is(err, ErrRetained) || !strings.Contains(err.Error(), "no id") {
		t.Fatalf("empty id: %v", err)
	}
	if _, ferr := prov.Find(l, prov.ClassNetwork, "net"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a network was recorded with no id")
	}
}

func TestReconcileRefusesContainer(t *testing.T) {
	ctx := context.Background()
	// A container intent records the desired state and the check its bring-up owes. Confirming it
	// here would leave the container accounted for, with no desired state, never started and never
	// verified.
	l, id := identLedger(t)
	mustOpen(t, l, prov.ClassContainer, "c1", "n1")
	f := newFake()
	f.put(prov.ClassContainer, "c1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	err := Reconcile(ctx, l, f, nil, prov.ClassContainer, "c1")
	if err == nil || !strings.Contains(err.Error(), "bring-up recovery path") {
		t.Fatalf("a container intent was reconciled: %v", err)
	}
	if errors.Is(err, ErrRetained) {
		t.Fatal("a container refusal was reported as an ordinary retention")
	}
	if _, ferr := Find(l, prov.ClassContainer, "c1"); ferr != nil {
		t.Fatal("the container intent was dropped")
	}
	// AND IT DOES NOT STOP THE CLASSES RECONCILE IS RIGHT FOR: a volume intent in the same ledger
	// still reconciles.
	mustOpen(t, l, prov.ClassVolume, "v1", "n2")
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n2"})
	if err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1"); err != nil {
		t.Fatalf("the container refusal blocked a volume: %v", err)
	}
}

// --- bounded retention ---------------------------------------------------------------------------

func TestAbandonGracePeriod(t *testing.T) {
	ctx := context.Background()
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	f := newFake()
	// BEFORE the grace period: not abandonable, and the message says how long is left.
	err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Minute), DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "grace period") {
		t.Fatalf("abandonable too early: %v", err)
	}
	// AFTER it, with still zero matches: abandonable.
	if err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(6*time.Minute), DefaultGrace); err != nil {
		t.Fatalf("not abandonable after the grace period: %v", err)
	}
	// DATED IN THE FUTURE: refused rather than aged out.
	err = Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(-time.Hour), DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future-dated: %v", err)
	}
}

func TestAbandonNeedsAnAnsweringDaemon(t *testing.T) {
	ctx := context.Background()
	// ZERO MATCHES PROVES NOTHING from a daemon that is not answering, and everything here turns
	// on a zero.
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	f := newFake()
	f.pingErr = errors.New("connection refused")
	err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Hour), DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("abandonable with an unreachable daemon: %v", err)
	}
}

func TestAbandonClearsTheIntent(t *testing.T) {
	ctx := context.Background()
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	f := newFake()
	advisory, err := Abandon(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Hour), DefaultGrace)
	if err != nil {
		t.Fatal(err)
	}
	// AND IT SAYS SO. Abandonment does NOT guarantee convergence, and the operator is told: the
	// installer cannot distinguish "never created" from "not yet visible". This is a SUCCESS-path
	// statement, so it travels as a return value — an error has no channel for one, and a warning
	// written into the void could not be asserted at all.
	if !strings.Contains(advisory, "may still appear") {
		t.Fatalf("a successful abandonment said nothing about convergence: %q", advisory)
	}
	if _, err := Find(l, prov.ClassNetwork, "net"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the intent survived abandonment: %v", err)
	}
	// Abandonment records NO provenance: it does not guarantee convergence, and the object
	// surfacing later must be caught as unrecorded rather than silently accounted for.
	if _, err := prov.Find(l, prov.ClassNetwork, "net"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("abandonment wrote provenance")
	}
	// And a refused abandonment consumes nothing.
	l2, _ := identLedger(t)
	mustOpen(t, l2, prov.ClassNetwork, "net", "n1")
	advisory, err = Abandon(ctx, l2, f, prov.ClassNetwork, "net", fixedNow, DefaultGrace)
	if err == nil {
		t.Fatal("abandoned inside the grace period")
	}
	if advisory != "" {
		t.Fatalf("a refused abandonment still advised the operator: %q", advisory)
	}
	if _, err := Find(l2, prov.ClassNetwork, "net"); err != nil {
		t.Fatal("a refused abandonment dropped the intent")
	}
}

func TestAbandonRefusesUnreadableAge(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	// A CREATION TIME THAT IS NOT A NUMBER is never aged out. The ledger is checksummed, which
	// proves it was not altered — not that this installation wrote it.
	for _, bad := range []string{"", "later", "-5", "17e8", "1234567890123456789"} {
		l, _ := identLedger(t)
		l.ReplaceLines(append(l.Lines(),
			"intent\tkey=network:net\tclass=network\tname=net\tnonce=n1\tcreated="+bad))
		err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Hour), DefaultGrace)
		if err == nil || !strings.Contains(err.Error(), "not a number") {
			t.Errorf("created=%q was aged out: %v", bad, err)
		}
	}
	// AN UNREADABLE THRESHOLD DOES NOT FAIL THE COMPARISON, IT FAILS IT OPEN. A Duration cannot be
	// non-numeric, so the surviving case is a NEGATIVE grace, which makes every intent read as
	// older than the threshold.
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow, -time.Second)
	if err == nil || !strings.Contains(err.Error(), "fails it OPEN") {
		t.Fatalf("a negative grace period aged an intent out: %v", err)
	}
}

func TestAbandonOwnershipCases(t *testing.T) {
	ctx := context.Background()
	late := fixedNow.Add(time.Hour)
	// A FOREIGN object carrying our nonce is NOT our object appearing — a nonce says WHICH, never
	// WHOSE — so it must not wedge abandonment forever.
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassNetwork, "net", "n1")
	f := newFake()
	f.put(prov.ClassNetwork, "net-theirs", map[string]string{prov.LabelInstall: "i9999999999", prov.LabelNonce: "n1"})
	if err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", late, DefaultGrace); err != nil {
		t.Fatalf("a foreign object wedged abandonment: %v", err)
	}
	// AN OBJECT OF OURS carrying this nonce under ANOTHER NAME refuses abandonment: it is ours and
	// it is real, and aging the intent out would lose the only record of it.
	l2, id2 := identLedger(t)
	mustOpen(t, l2, prov.ClassNetwork, "net", "n1")
	f2 := newFake()
	f2.put(prov.ClassNetwork, "net-elsewhere", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "n1"})
	err := Abandonable(ctx, l2, f2, prov.ClassNetwork, "net", late, DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "carries its nonce") {
		t.Fatalf("an object of ours under another name was aged out: %v", err)
	}
	// THE OBJECT HAS APPEARED at its own name: reconcile it instead of abandoning it.
	l3, id3 := identLedger(t)
	mustOpen(t, l3, prov.ClassNetwork, "net", "n1")
	f3 := newFake()
	f3.put(prov.ClassNetwork, "net", map[string]string{prov.LabelInstall: id3, prov.LabelNonce: "n1"})
	err = Abandonable(ctx, l3, f3, prov.ClassNetwork, "net", late, DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "reconcile it instead") {
		t.Fatalf("an appeared object was aged out: %v", err)
	}
	// AN OBJECT STANDING AT THE NAME with a DIFFERENT nonce refuses too.
	l4, id4 := identLedger(t)
	mustOpen(t, l4, prov.ClassNetwork, "net", "n1")
	f4 := newFake()
	f4.put(prov.ClassNetwork, "net", map[string]string{prov.LabelInstall: id4, prov.LabelNonce: "n1"})
	f4.answersNonce("network:net", "other") // found by n1, but answers "other" when asked directly
	err = Abandonable(ctx, l4, f4, prov.ClassNetwork, "net", late, DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "stands at its name") {
		t.Fatalf("a nonce-mismatched object at the name was aged out: %v", err)
	}
}

func (f *fakeObjs) answersNonce(key, answer string) {
	if f.answerNonce == nil {
		f.answerNonce = map[string]string{}
	}
	f.answerNonce[key] = answer
}

// --- §6b.2: objects the ledger does not account for -----------------------------------------------

func gateFixture(t *testing.T) (*ledger.Ledger, string, *fakeObjs) {
	t.Helper()
	l, id := identLedger(t)
	return l, id, newFake()
}

func TestGateUnrecorded(t *testing.T) {
	ctx := context.Background()
	// AN ABANDONED INTENT'S OBJECT SURFACING LATER. Abandonment does not guarantee convergence,
	// and this is the catch: ours by its label, and the ledger has no record of it.
	l, id, f := gateFixture(t)
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	err := UnaccountedGate(ctx, l, f)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "unrecorded same-identity") {
		t.Fatalf("a surfaced object did not stop the gate: %v", err)
	}
	// It is never silently adopted and never automatically deleted — the report says so and
	// nothing in the ledger changed.
	if strings.Contains(err.Error(), "remov") && !strings.Contains(err.Error(), "with the container runtime directly") {
		t.Fatal("the report proposed an automatic removal")
	}
	if _, ferr := prov.Find(l, prov.ClassVolume, "v1"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("the gate adopted the object")
	}

	// A TOMBSTONED object that STILL EXISTS is unrecorded: the tombstone says it was removed, and
	// it is standing there.
	l2, id2, f2 := gateFixture(t)
	if err := prov.Record(l2, prov.ClassVolume, "v2", "n2"); err != nil {
		t.Fatal(err)
	}
	if err := prov.Tombstone(l2, prov.ClassVolume, "v2"); err != nil {
		t.Fatal(err)
	}
	f2.put(prov.ClassVolume, "v2", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "n2"})
	err = UnaccountedGate(ctx, l2, f2)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "unrecorded same-identity") {
		t.Fatalf("a tombstoned-but-live object did not stop the gate: %v", err)
	}
}

func TestGateUnattributedNeverStops(t *testing.T) {
	ctx := context.Background()
	// ANOTHER USER'S OBJECT on the same daemon: reported, left untouched, and it does NOT stop an
	// operation — it is not this installation's business.
	l, _, f := gateFixture(t)
	f.put(prov.ClassVolume, "theirs", map[string]string{prov.LabelInstall: "i9999999999", prov.LabelNonce: "x"})
	if err := UnaccountedGate(ctx, l, f); err != nil {
		t.Fatalf("a foreign object stopped the gate: %v", err)
	}
	found := UnaccountedScan(ctx, l, f)
	if len(found) != 1 || found[0].Kind != FindingUnattributed || found[0].Name != "theirs" {
		t.Fatalf("scan = %+v", found)
	}
	// THE UNATTRIBUTED LISTING NEVER PROPOSES REMOVAL.
	l2, _, f2 := gateFixture(t)
	f2.put(prov.ClassVolume, "theirs", map[string]string{prov.LabelInstall: "i9999999999"})
	f2.put(prov.ClassVolume, "mine-unrecorded", map[string]string{prov.LabelInstall: "unused"})
	// Force a stop so the note is rendered alongside it, and read what the note says.
	f2.listFail[prov.ClassNetwork] = true
	err := UnaccountedGate(ctx, l2, f2)
	if err == nil {
		t.Fatal("expected a stop from the failed listing")
	}
	note := err.Error()
	if !strings.Contains(note, "left untouched") {
		t.Fatalf("the unattributed note does not say it is left untouched: %v", note)
	}
	for _, forbidden := range []string{"remove it", "Rename or remove"} {
		idx := strings.Index(note, "may belong to another user")
		if idx >= 0 && strings.Contains(note[idx:idx+200], forbidden) {
			t.Fatalf("the unattributed note proposed %q", forbidden)
		}
	}
}

func TestGateColliding(t *testing.T) {
	ctx := context.Background()
	l, id, f := gateFixture(t)
	// AN UNLABELLED OBJECT HOLDING A NAME WE WOULD CREATE blocks creation: no label proves it is
	// ours, and no provenance proves it is not someone else's.
	f.put(prov.ClassVolume, manifest.NamePrefix+"-"+id+"-brokkr-state", map[string]string{})
	err := UnaccountedGate(ctx, l, f)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "holds a name this installer would create") {
		t.Fatalf("a colliding name did not stop the gate: %v", err)
	}
	// AN UNLABELLED OBJECT NOT HOLDING ONE OF OUR NAMES IS IGNORED ENTIRELY — the daemon is full of
	// other people's things.
	l2, _, f2 := gateFixture(t)
	f2.put(prov.ClassVolume, "postgres-data", map[string]string{})
	f2.put(prov.ClassVolume, manifest.NamePrefix+"-i0000000009-brokkr-state", map[string]string{}) // another identity's name
	if err := UnaccountedGate(ctx, l2, f2); err != nil {
		t.Fatalf("an unrelated unlabelled object stopped the gate: %v", err)
	}
	if found := UnaccountedScan(ctx, l2, f2); len(found) != 0 {
		t.Fatalf("scan reported unrelated objects: %+v", found)
	}
}

func TestGateAccountedFor(t *testing.T) {
	ctx := context.Background()
	// A CONFIRMED object is not unrecorded — the gate passes once provenance exists.
	l, id, f := gateFixture(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	if err := Confirm(l, prov.ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "n1"})
	if err := UnaccountedGate(ctx, l, f); err != nil {
		t.Fatalf("a confirmed object stopped the gate: %v", err)
	}
	// AN OBJECT WITH A LIVE INTENT is not unrecorded either — an object mid-creation is accounted
	// for by the record that says it was about to be created.
	l2, id2, f2 := gateFixture(t)
	mustOpen(t, l2, prov.ClassVolume, "v2", "n2")
	f2.put(prov.ClassVolume, "v2", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "n2"})
	if err := UnaccountedGate(ctx, l2, f2); err != nil {
		t.Fatalf("an object with a live intent stopped the gate: %v", err)
	}
}

func TestGateAccountsRules(t *testing.T) {
	ctx := context.Background()
	// A RECORD DOES NOT ACCOUNT FOR A DIFFERENT OBJECT STANDING AT THE NAME IT RECORDS: a name can
	// be reassigned, and the new object inherits nothing from the record of the one that is gone.
	l, id, f := gateFixture(t)
	if err := prov.Record(l, prov.ClassVolume, "v1", "recorded-nonce"); err != nil {
		t.Fatal(err)
	}
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id, prov.LabelNonce: "different-nonce"})
	if err := UnaccountedGate(ctx, l, f); !errors.Is(err, ErrUnaccounted) {
		t.Fatalf("a reassigned name was accounted for: %v", err)
	}

	// AN INTENT DOES NOT ACCOUNT FOR AN OBJECT CARRYING A DIFFERENT NONCE EITHER.
	l2, id2, f2 := gateFixture(t)
	mustOpen(t, l2, prov.ClassVolume, "v1", "intended-nonce")
	f2.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id2, prov.LabelNonce: "different"})
	if err := UnaccountedGate(ctx, l2, f2); !errors.Is(err, ErrUnaccounted) {
		t.Fatalf("an intent accounted for a different object: %v", err)
	}

	// A RECORD DESCRIBING SOMETHING ELSE ACCOUNTS FOR NOTHING, EVEN WITH A MATCHING NONCE — and it
	// is reported as the ANSWER it is. The lookup refuses such a row now, so the kind reported is
	// the property this asserts rather than a detail: folded into "could not be asked" it would
	// still stop the gate, and would tell the operator the installer state was unreadable and to
	// start their container runtime. It was read, it is contradictory, and it needs repair.
	l3, id3, f3 := gateFixture(t)
	l3.ReplaceLines(append(l3.Lines(),
		"object\tkey=volume:v1\tclass=container\tname=other\tnonce=n1\tgen=1"))
	f3.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id3, prov.LabelNonce: "n1"})
	err3 := UnaccountedGate(ctx, l3, f3)
	if !errors.Is(err3, ErrUnaccounted) {
		t.Fatalf("a record about something else accounted for an object: %v", err3)
	}
	if !strings.Contains(err3.Error(), "unrecorded same-identity") {
		t.Fatalf("a contradictory record was not reported as an unrecorded object: %v", err3)
	}
	if strings.Contains(err3.Error(), "could not be asked") {
		t.Fatalf("a record that WAS read was reported as a question that could not be asked: %v", err3)
	}
	// The same for an INTENT describing something else — the other lookup, same fold.
	l3b, id3b, f3b := gateFixture(t)
	l3b.ReplaceLines(append(l3b.Lines(),
		"intent\tkey=volume:v1\tclass=volume\tname=other\tnonce=n1\tcreated=1700000000"))
	f3b.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id3b, prov.LabelNonce: "n1"})
	err3b := UnaccountedGate(ctx, l3b, f3b)
	if !errors.Is(err3b, ErrUnaccounted) || !strings.Contains(err3b.Error(), "unrecorded same-identity") {
		t.Fatalf("an intent about something else was not reported as unrecorded: %v", err3b)
	}
	if strings.Contains(err3b.Error(), "could not be asked") {
		t.Fatalf("an intent that WAS read was reported as a question that could not be asked: %v", err3b)
	}

	// AN EMPTY NONCE ON BOTH SIDES IS NOT A MATCH — a record with no identity accounts for nothing,
	// and an empty value is the one that would otherwise match everything by looking like nothing.
	l4, id4, f4 := gateFixture(t)
	l4.ReplaceLines(append(l4.Lines(),
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=\tgen=1"))
	f4.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id4})
	if err := UnaccountedGate(ctx, l4, f4); !errors.Is(err, ErrUnaccounted) {
		t.Fatalf("two empty nonces were read as a match: %v", err)
	}
}

func TestGateUnasked(t *testing.T) {
	ctx := context.Background()
	// A LISTING THAT COULD NOT BE MADE: an empty answer is not no answer.
	l, _, f := gateFixture(t)
	f.listFail[prov.ClassVolume] = true
	err := UnaccountedGate(ctx, l, f)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "could not be asked for") {
		t.Fatalf("a failed listing did not stop the gate: %v", err)
	}

	// AN OBJECT WHOSE LABEL COULD NOT BE READ stops the gate rather than being ignored.
	l2, _, f2 := gateFixture(t)
	f2.put(prov.ClassVolume, "v1", map[string]string{})
	f2.labelErr["volume:v1"] = errors.New("daemon down")
	err = UnaccountedGate(ctx, l2, f2)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "could not be asked about") {
		t.Fatalf("an unreadable label was ignored: %v", err)
	}

	// AN OBJECT WHOSE NONCE COULD NOT BE READ is not accounted for by a record that names it: the
	// install label answered, the nonce did not, and the record cannot be checked against nothing.
	l3, id3, f3 := gateFixture(t)
	if err := prov.Record(l3, prov.ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	f3.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id3, prov.LabelNonce: "n1"})
	f3.answersNonceErr("volume:v1")
	err = UnaccountedGate(ctx, l3, f3)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "could not be asked about") {
		t.Fatalf("an unreadable nonce was accounted for: %v", err)
	}

	// AN OBJECT THE LEDGER CANNOT ANSWER FOR stops the gate as UNASKED, not as unrecorded — two
	// provenance records answering one key is a question the ledger cannot settle, and calling it
	// "unrecorded" would send an operator to remove an object that IS recorded, twice.
	l4, id4, f4 := gateFixture(t)
	l4.ReplaceLines(append(l4.Lines(),
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=a\tgen=1",
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=b\tgen=1"))
	f4.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id4, prov.LabelNonce: "a"})
	err = UnaccountedGate(ctx, l4, f4)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "could not be asked about") {
		t.Fatalf("two records read as unrecorded: %v", err)
	}
	if strings.Contains(err.Error(), "unrecorded same-identity") {
		t.Fatal("an ambiguous ledger was reported as an unrecorded object")
	}

	// TWO INTENT ROWS answering one key stop the gate the same way records do.
	l5, id5, f5 := gateFixture(t)
	l5.ReplaceLines(append(l5.Lines(),
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=a\tcreated=1700000000",
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=b\tcreated=1700000000"))
	f5.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: id5, prov.LabelNonce: "a"})
	err = UnaccountedGate(ctx, l5, f5)
	if !errors.Is(err, ErrUnaccounted) || !strings.Contains(err.Error(), "could not be asked about") {
		t.Fatalf("two intents read as unrecorded: %v", err)
	}
}

func TestGateGoneBetweenListingAndQuestion(t *testing.T) {
	ctx := context.Background()
	// AN OBJECT REMOVED BETWEEN THE LISTING AND THE QUESTION ABOUT IT is not reported as
	// unlabelled: it is not there at all, and "no labels" is a claim about an object that exists.
	l, _, f := gateFixture(t)
	f.list[prov.ClassVolume] = []string{manifest.NamePrefix + "-gone"} // listed, never in obj
	if err := UnaccountedGate(ctx, l, f); err != nil {
		t.Fatalf("a vanished object stopped the gate: %v", err)
	}
	if found := UnaccountedScan(ctx, l, f); len(found) != 0 {
		t.Fatalf("a vanished object was reported: %+v", found)
	}
}

// answersNonceErr makes the INSTALL label answer while the NONCE label fails — the split the
// reference's `|| true` collapsed, turning "I could not ask" into "it carries no such label".
func (f *fakeObjs) answersNonceErr(key string) {
	if f.nonceErr == nil {
		f.nonceErr = map[string]bool{}
	}
	f.nonceErr[key] = true
}

func TestGateNormalizesAbsentLabels(t *testing.T) {
	ctx := context.Background()
	// A LABEL MEANING ABSENT MUST READ AS ABSENT. The reference routes every label read through one
	// normalizing reader, so `<no value>` — the spelling its template produced for a missing key —
	// is absence everywhere. Skipping it here classifies an object at one of OUR OWN derived names
	// as another installation's (unattributed, which the gate lets past) instead of the unlabelled
	// COLLISION that must block creation.
	l, id, f := gateFixture(t)
	name := manifest.NamePrefix + "-" + id + "-brokkr-state"
	f.put(prov.ClassVolume, name, map[string]string{prov.LabelInstall: "<no value>"})
	err := UnaccountedGate(ctx, l, f)
	if err == nil {
		t.Fatal("an object at one of our own names with an absent-meaning label did not stop the gate")
	}
	if !strings.Contains(err.Error(), "holds a name this installer would create") {
		t.Fatalf("classified as something other than a collision: %v", err)
	}
}

func TestReconcileNormalizesAbsentLabels(t *testing.T) {
	ctx := context.Background()
	// The same rule on the ownership question: `<no value>` is NOT another installation's identity,
	// it is no identity at all — so the refusal must be "carries no label", not "belongs to
	// installation <no value>".
	l, _ := identLedger(t)
	mustOpen(t, l, prov.ClassVolume, "v1", "n1")
	f := newFake()
	f.put(prov.ClassVolume, "v1", map[string]string{prov.LabelInstall: "<no value>", prov.LabelNonce: "n1"})
	err := Reconcile(ctx, l, f, nil, prov.ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "NO installation label") {
		t.Fatalf("an absent-meaning label read as a real identity: %v", err)
	}
}

// --- an intent selected by key must describe what was asked for -----------------------------------

// AN INTENT IS PROVED TO DESCRIBE THE OBJECT AT THE LOOKUP. `key`, `class` and `name` are three
// independent fields; a row keyed `volume:v1` that describes something else answers this lookup
// and is then consumed as v1's intent. What that costs is a runtime mutation and a lost record,
// not a wrong report — which is why it is asserted against the reissuer and the ledger body rather
// than against the message alone.
func TestReconcileRefusesAnIntentAboutSomethingElse(t *testing.T) {
	ctx := context.Background()
	l, _ := identLedger(t)
	// Well-formed and checksum-valid: only the agreement between the key and what the row
	// describes is wrong, which is the case no field-level check can see.
	l.ReplaceLines(append(l.Lines(),
		"intent\tkey=volume:v1\tclass=container\tname=other\tnonce=n9\tcreated=1700000000"))
	before := strings.Join(l.Lines(), "\n")
	f := newFake()
	r := &fakeReissuer{}

	err := Reconcile(ctx, l, f, r, prov.ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("an intent about something else was reconciled: %v", err)
	}
	// IT IS A REFUSAL, NOT A RETENTION. ErrRetained tells a caller nothing is wrong and to carry
	// on; a contradictory record is the opposite case and no later run resolves it.
	if errors.Is(err, ErrRetained) {
		t.Fatalf("a contradictory intent was reported as a benign retention: %v", err)
	}
	// NOTHING WAS CREATED. This is the half that matters: reissuing on the other object's nonce
	// leaves a volume nothing accounts for, and the confirmation that would have caught it refuses
	// afterwards — so the object outlives the run that made it and stops every later operation.
	if r.calls != 0 {
		t.Fatalf("a volume was reissued from an intent about another object: %d calls", r.calls)
	}
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the contradictory intent was not preserved.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestAbandonRefusesAnIntentAboutSomethingElse(t *testing.T) {
	ctx := context.Background()
	l, _ := identLedger(t)
	l.ReplaceLines(append(l.Lines(),
		"intent\tkey=network:net\tclass=volume\tname=other\tnonce=n9\tcreated=1700000000"))
	before := strings.Join(l.Lines(), "\n")
	f := newFake()

	// Aged well past the grace period and with zero matches — every OTHER reason to refuse is
	// absent, so the agreement question is the only thing standing between this row and deletion.
	err := Abandonable(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Hour), DefaultGrace)
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("an intent about something else was declared abandonable: %v", err)
	}
	advisory, aerr := Abandon(ctx, l, f, prov.ClassNetwork, "net", fixedNow.Add(time.Hour), DefaultGrace)
	if aerr == nil {
		t.Fatal("an intent about something else was abandoned")
	}
	if advisory != "" {
		t.Fatalf("a refused abandonment still advised the operator: %q", advisory)
	}
	// THE ROW SURVIVES. It is the only record of whatever it actually described; dropping it here
	// would destroy that on behalf of an object it has nothing to do with.
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the contradictory intent was dropped.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// A CONFIRMATION DROPS THE TOMBSTONE FOR THE NAME IT CONFIRMS. A tombstone keyed for this object
// while describing another is that other object's only surviving account — §6b's whole point is
// that provenance outlives what it describes — and dropping it is not tidying, it is the one act
// this module may never perform on conflicting evidence. Asked BEFORE the object record is
// rewritten, like the cardinality question beside it.
func TestConfirmRefusesToDropATombstoneAboutSomethingElse(t *testing.T) {
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"intent\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tcreated=1700000000",
		"tombstone\tkey=volume:v1\tclass=container\tname=other\tnonce=n9\tgen=3",
	})
	before := strings.Join(l.Lines(), "\n")
	err := Confirm(l, prov.ClassVolume, "v1", "n1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a tombstone about something else was dropped by a confirmation: %v", err)
	}
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the confirmation wrote before the tombstone question was answered.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
