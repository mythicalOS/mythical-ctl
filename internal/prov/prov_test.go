package prov

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
)

// Inventory — tests/unit/prov.bats. internal/ledger owns the generalized-editor,
// identity and membership rows; this package owns the PROVENANCE-SEMANTICS remainder, and the two
// sets together cover the file exactly once.
//
// PORTED: tests/unit/prov.bats: "provenance records an object by name AND nonce, and finds it by both" -> TestRecordAndFind
// PORTED: tests/unit/prov.bats: "a re-record SUPERSEDES the prior generation rather than appending beside it" -> TestRecordSupersedes
// PORTED: tests/unit/prov.bats: "CLASS AND NAME together key a record — a container and a volume can derive the same name" -> TestClassAndNameKeyTheRecord
// PORTED: tests/unit/prov.bats: "removal writes a tombstone and drops the object record" -> TestTombstoneReplacesRecord
// PORTED: tests/unit/prov.bats: "deletion authority requires the RECORDED nonce to match what is actually there" -> TestAuthorityNonceMustMatch
// PORTED: tests/unit/prov.bats: "a REUSED volume name fails the nonce check and is NOT authorized for deletion" -> TestAuthorityNonceMustMatch
// PORTED: tests/unit/prov.bats: "an object with NO record is never authorized — it is preserved and reported" -> TestAuthorityNoRecord
// PORTED: tests/unit/prov.bats: "an object that is GONE reports 3, distinctly from a mismatch" -> TestAuthorityGoneIsDistinct
// PORTED: tests/unit/prov.bats: "images are recorded by DIGEST and mi_prov_authority refuses them outright (D37)" -> TestImageRecordAndRefusal
// PORTED: tests/unit/prov.bats: "first use is ledger-absent AND every other trace absent" -> TestFirstUseClean
// PORTED: tests/unit/prov.bats: "no ledger BESIDE a product conf is INCONSISTENT, not first use" -> TestFirstUseTraces
// PORTED: tests/unit/prov.bats: "no ledger BESIDE a product directory is inconsistent" -> TestFirstUseTraces
// PORTED: tests/unit/prov.bats: "no ledger BESIDE a labelled runtime object is inconsistent" -> TestFirstUseRuntimeObjects
// PORTED: tests/unit/prov.bats: "a product directory holding NOTHING BUT the host-tool slot is not a trace" -> TestHostToolSlotExemption
// PORTED: tests/unit/prov.bats: "the host-tool slot BESIDE a generated artifact is still a trace" -> TestHostToolSlotExemption
// PORTED: tests/unit/prov.bats: "a HIDDEN entry beside the host-tool slot is still a trace — a bare * would not see it" -> TestHostToolSlotExemption
// PORTED: tests/unit/prov.bats: "an EMPTY product directory is STILL a trace — the slot must be present, not merely unopposed" -> TestHostToolSlotExemption
// PORTED: tests/unit/prov.bats: "a DIRECTORY at the slot's name is a trace, not the slot" -> TestHostToolSlotShape
// PORTED: tests/unit/prov.bats: "a SYMLINK at the slot's name is a trace — the contract requires a regular file" -> TestHostToolSlotShape
// PORTED: tests/unit/prov.bats: "a SYMLINK standing where the product directory should be is a trace, whatever it holds" -> TestHostToolSlotShape
// PORTED: tests/unit/prov.bats: "an UNREADABLE product directory is a trace — 'I could not look' is not 'nothing is there'" -> TestHostToolSlotUnreadable
// N/A: tests/unit/prov.bats: "GLOBIGNORE cannot hide a generated artifact from the exemption's own sweep" -- no glob: the sweep is a directory READ, which no ambient variable can filter. The behavior it protected (a hidden artifact is still a trace) is asserted by TestHostToolSlotExemption's hidden-entry case.
// N/A: tests/unit/prov.bats: "the exemption helper clears GLOBIGNORE for ITSELF, not only via its caller" -- same reason: there is no GLOBIGNORE and no glob in either sweep.
// N/A: tests/unit/prov.bats: "GLOBIGNORE cannot hide the product DIRECTORY from the outer sweep either" -- same reason; the outer sweep is os.ReadDir, which returns every entry including dotfiles and dangling links.
// PORTED: tests/unit/prov.bats: "a directory whose NAME is not a legal product is a trace, slot or no slot" -> TestHostToolSlotNameGrammar
// PORTED: tests/unit/prov.bats: "a name that is illegal only PAST its first character is a trace too" -> TestHostToolSlotNameGrammar
// PORTED: tests/unit/prov.bats: "the RESERVED name 'mythical' is a trace even holding nothing but a slot" -> TestHostToolSlotNameGrammar
// PORTED: tests/unit/prov.bats: "the exemption is per-directory: an exempt product does not excuse a second product's trace" -> TestHostToolSlotNameGrammar
// PORTED: tests/unit/prov.bats: "a ledger that EXISTS is not first use" -> TestFirstUseLedgerPresent
// PORTED: tests/unit/prov.bats: "a runtime that CANNOT BE ASKED is not evidence of a fresh machine" -> TestFirstUseRuntimeUnasked
// PORTED: tests/unit/prov.bats: "an unlistable object kind is a listing FAILURE, not an empty listing" -> TestUnlistableKind
// PORTED: tests/unit/prov.bats: "a tombstone cannot forge a record through the object NAME it serializes" -> TestTombstoneCannotForge
// PORTED: tests/unit/prov.bats: "a ledger path that is a DIRECTORY is inconsistent, not a fresh machine" -> TestFirstUseLedgerNotRegular
// PORTED: tests/unit/prov.bats: "a DANGLING SYMLINK at the ledger path is inconsistent, not a fresh machine" -> TestFirstUseLedgerNotRegular
// PORTED: tests/unit/prov.bats: "a STAGING ledger that is not a regular file still blocks first use" -> TestFirstUseStagingNotRegular
// PORTED: tests/unit/prov.bats: "a DANGLING SYMLINK product conf is a trace too — presence is the test, not readability" -> TestFirstUseTraces
// PORTED: tests/unit/prov.bats: "a product DIRECTORY entry is a trace whether it is real, a link, or a dangling link" -> TestFirstUseTraces
// PORTED: tests/unit/prov.bats: "a GENERATION out of the ledger is DIGITS before arithmetic — it is never EVALUATED" -> TestGenerationMustBeDigits
// PORTED: tests/unit/prov.bats: "a generation this module refuses to READ is never carried into a tombstone either" -> TestGenerationMustBeDigits
// PORTED: tests/unit/prov.bats: "authority checks that the record it found DESCRIBES the object it was asked about" -> TestAuthorityRecordMustDescribe
// PORTED: tests/unit/prov.bats: "a record ill-formed in a field OTHER than the selector is never authority, and is preserved" -> TestAuthorityRecordMustDescribe
// PORTED: tests/unit/prov.bats: "a tombstone consumes only a record that DESCRIBES the object it is tombstoning" -> TestTombstoneRecordMustDescribe
// PORTED: tests/unit/prov.bats: "a REPEATED tombstone keeps the identity the tombstone exists to preserve" -> TestRepeatedTombstoneKeepsIdentity
// PORTED: tests/unit/prov.bats: "a contradiction among TOMBSTONES is preserved too, even when the object record reads fine" -> TestTombstoneAmbiguityPreserved
// PORTED: tests/unit/prov.bats: "deletion authority requires the object to carry THIS installation's label" -> TestAuthorityInstallationLabel
// PORTED: tests/unit/prov.bats: "authority refuses when this installation's OWN identity cannot be read" -> TestAuthorityOwnIdentityUnreadable
// PORTED: tests/unit/prov.bats: "an ABSENT installation label is refused as absent however the runtime spells it" -> TestAuthorityInstallationLabel
// PORTED: tests/unit/prov.bats: "a record ALREADY carrying a duplicate selector matches nothing — not even its own key" -> TestDuplicateSelectorMatchesNothing
// PORTED: tests/unit/prov.bats: "a record with an EMPTY field is ill-formed — the walk sees what IFS splitting collapsed" -> TestEmptyFieldIsIllFormed
// PORTED: tests/unit/prov.bats: "a field VALUE that is a glob is compared LITERALLY — the cwd cannot manufacture a nonce" -> TestGlobValueComparedLiterally

// --- the runtime fake ---------------------------------------------------------------------------
// Labels a real daemon would carry, and the two failure shapes that must never be folded together:
// engine.ErrAbsent (the object is GONE — an answer) and a transport error (the question could not
// be asked — never an answer).

type fakeObjs struct {
	obj      map[string]map[string]string // "class:name" -> label -> value
	list     map[Class][]string
	listFail map[Class]bool
	askErr   error
	// askErrOn narrows askErr to ONE label. Authority reads two of them in a fixed order, and the
	// second read is unreachable while the first fails — so proving the second one's own
	// classification needs a fake that can fail exactly it. Empty means every label fails, which
	// is what askErr alone always meant.
	askErrOn string
}

func newFakeObjs() *fakeObjs {
	return &fakeObjs{obj: map[string]map[string]string{}, list: map[Class][]string{}, listFail: map[Class]bool{}}
}

func (f *fakeObjs) put(class Class, name string, labels map[string]string) {
	f.obj[string(class)+":"+name] = labels
}

func (f *fakeObjs) Label(_ context.Context, class Class, name, label string) (string, error) {
	if f.askErr != nil && (f.askErrOn == "" || f.askErrOn == label) {
		return "", f.askErr
	}
	m, ok := f.obj[string(class)+":"+name]
	if !ok {
		return "", engine.ErrAbsent
	}
	return m[label], nil
}

func (f *fakeObjs) Names(_ context.Context, class Class) ([]string, error) {
	if f.listFail[class] {
		return nil, errors.New("the container runtime did not answer")
	}
	if !ClassOK(class) || class == ClassProbe {
		return nil, errors.New("prov: not a listable object kind")
	}
	return f.list[class], nil
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

// --- records ------------------------------------------------------------------------------------

func TestRecordAndFind(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Record(l, ClassVolume, "v1", "n1", ledger.Field{Key: "role", Value: "state"}); err != nil {
		t.Fatal(err)
	}
	fields, err := Find(l, ClassVolume, "v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ k, v string }{
		{"key", "volume:v1"}, {"class", "volume"}, {"name", "v1"}, {"nonce", "n1"},
		{"gen", "1"}, {"role", "state"},
	} {
		if got, ok := ledger.FieldOf(fields, want.k); !ok || got != want.v {
			t.Errorf("%s = %q (present=%v), want %q", want.k, got, ok, want.v)
		}
	}
	// Absence is an ANSWER, never a refusal.
	if _, err := Find(l, ClassVolume, "nope"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("absent record: %v", err)
	}
}

func TestRecordSupersedes(t *testing.T) {
	l := &ledger.Ledger{}
	for i, nonce := range []string{"n1", "n2", "n3"} {
		if err := Record(l, ClassVolume, "v1", nonce); err != nil {
			t.Fatal(err)
		}
		g, err := Gen(l, ClassVolume, "v1")
		if err != nil {
			t.Fatal(err)
		}
		if g != uint64(i+1) {
			t.Fatalf("generation %d, want %d", g, i+1)
		}
	}
	// ONE record, not three claims about one object.
	rows, err := l.All("object")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("a re-record appended beside instead of superseding: %d rows", len(rows))
	}
	fields, _ := Find(l, ClassVolume, "v1")
	if n, _ := ledger.FieldOf(fields, "nonce"); n != "n3" {
		t.Fatalf("newest record did not win: nonce=%q", n)
	}
}

func TestClassAndNameKeyTheRecord(t *testing.T) {
	// The reachable collision: a container and a volume deriving the SAME name. Recording either
	// must not delete the other's record.
	const shared = "mythical-i0123456789-p1-state"
	l := &ledger.Ledger{}
	if err := Record(l, ClassContainer, shared, "cn"); err != nil {
		t.Fatal(err)
	}
	if err := Record(l, ClassVolume, shared, "vn"); err != nil {
		t.Fatal(err)
	}
	cf, err := Find(l, ClassContainer, shared)
	if err != nil {
		t.Fatalf("the container record was destroyed by the volume's: %v", err)
	}
	vf, err := Find(l, ClassVolume, shared)
	if err != nil {
		t.Fatal(err)
	}
	if cn, _ := ledger.FieldOf(cf, "nonce"); cn != "cn" {
		t.Fatalf("container nonce = %q", cn)
	}
	if vn, _ := ledger.FieldOf(vf, "nonce"); vn != "vn" {
		t.Fatalf("volume nonce = %q", vn)
	}
	// And tombstoning one leaves the other's provenance intact.
	if err := Tombstone(l, ClassVolume, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(l, ClassContainer, shared); err != nil {
		t.Fatalf("tombstoning the volume erased the container's record: %v", err)
	}
}

func TestGenerationMustBeDigits(t *testing.T) {
	// A `gen=` that is not a number is REFUSED, never reset to 0 — a silent reset is how a
	// tampered record erases the history that would show it had been tampered with. The reference
	// warned about arithmetic EVALUATION; Go has no evaluator to reach, so what is asserted here
	// is the surviving half of the rule: refusal, in both readers.
	for _, bad := range []string{"a[$(touch pwned)]", "1e3", "", "-1", "0x10", "1234567890123456789"} {
		l := &ledger.Ledger{}
		if err := l.Put("object", "key", "volume:v1", []ledger.Field{
			{Key: "key", Value: "volume:v1"}, {Key: "class", Value: "volume"},
			{Key: "name", Value: "v1"}, {Key: "nonce", Value: "n"}, {Key: "gen", Value: bad},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := Gen(l, ClassVolume, "v1"); err == nil {
			t.Errorf("gen %q was read as a number", bad)
		}
		// Recording over it refuses too — it must compute from a generation it can read.
		if err := Record(l, ClassVolume, "v1", "n2"); err == nil {
			t.Errorf("gen %q was superseded on the strength of an unreadable generation", bad)
		}
		// AND IT IS NEVER CARRIED INTO A TOMBSTONE: a module that will not read a value must not
		// write it back either, or the next reader gets it preserved instead of reported.
		if err := Tombstone(l, ClassVolume, "v1"); err == nil {
			t.Errorf("gen %q was carried into a tombstone", bad)
		}
		// The evidence is still there, untouched.
		if _, err := Find(l, ClassVolume, "v1"); err != nil {
			t.Errorf("evidence destroyed for gen %q: %v", bad, err)
		}
	}
}

// --- tombstones ---------------------------------------------------------------------------------

func TestTombstoneReplacesRecord(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Record(l, ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := Tombstone(l, ClassVolume, "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(l, ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the object record survived the tombstone: %v", err)
	}
	tomb, err := TombstoneFind(l, ClassVolume, "v1")
	if err != nil {
		t.Fatal(err)
	}
	// §6b: provenance SURVIVES what it describes — the identity is what a later --purge needs.
	if n, _ := ledger.FieldOf(tomb, "nonce"); n != "n1" {
		t.Fatalf("tombstone nonce = %q, want n1", n)
	}
	if g, _ := ledger.FieldOf(tomb, "gen"); g != "1" {
		t.Fatalf("tombstone gen = %q, want 1", g)
	}
}

func TestRepeatedTombstoneKeepsIdentity(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Record(l, ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := Tombstone(l, ClassVolume, "v1"); err != nil {
		t.Fatal(err)
	}
	// The object record is gone, so the SECOND removal must read the tombstone it wrote a moment
	// ago and copy it forward — reading only the object record left the retry with nothing, and it
	// replaced a good tombstone with an empty one.
	if err := Tombstone(l, ClassVolume, "v1"); err != nil {
		t.Fatal(err)
	}
	tomb, err := TombstoneFind(l, ClassVolume, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := ledger.FieldOf(tomb, "nonce"); n != "n1" {
		t.Fatalf("a repeat removal erased the identity it exists to preserve: nonce=%q", n)
	}
	if g, _ := ledger.FieldOf(tomb, "gen"); g != "1" {
		t.Fatalf("a repeat removal erased the generation: gen=%q", g)
	}
	// And it SUPERSEDES rather than appending beside: a reinstall/uninstall cycle must not
	// accumulate one tombstone per generation.
	rows, err := l.All("tombstone")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d tombstones for one object", len(rows))
	}
}

func TestTombstoneRecordMustDescribe(t *testing.T) {
	// A record keyed `volume:v1` that describes something else is CONFLICTING EVIDENCE: consuming
	// it would copy another object's identity into this object's tombstone and drop the record.
	l := &ledger.Ledger{}
	if err := l.Put("object", "key", "volume:v1", []ledger.Field{
		{Key: "key", Value: "volume:v1"}, {Key: "class", Value: "container"},
		{Key: "name", Value: "other"}, {Key: "nonce", Value: "n1"}, {Key: "gen", Value: "1"},
	}); err != nil {
		t.Fatal(err)
	}
	before := strings.Join(l.Lines(), "\n")
	err := Tombstone(l, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a record about something else was consumed: %v", err)
	}
	// PRESERVATION IS ASSERTED ON THE LEDGER BODY, not by looking the record up again. Find is
	// where the agreement question is now asked, so it REFUSES this row — asking it "is the row
	// still there?" is asking a question it no longer answers, and a test that used it that way
	// would report the refusal as destruction. The body is the stronger assertion anyway: it
	// catches a row silently rewritten as well as one dropped.
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the conflicting record was not preserved byte-for-byte.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// A record with NO nonce loses the same way: an empty tombstone is indistinguishable
	// afterwards from the honest one written for an object that never had provenance.
	l2 := &ledger.Ledger{}
	if err := l2.Put("object", "key", "volume:v2", []ledger.Field{
		{Key: "key", Value: "volume:v2"}, {Key: "class", Value: "volume"},
		{Key: "name", Value: "v2"}, {Key: "gen", Value: "1"},
	}); err != nil {
		t.Fatal(err)
	}
	before2 := strings.Join(l2.Lines(), "\n")
	if err := Tombstone(l2, ClassVolume, "v2"); err == nil || !strings.Contains(err.Error(), "carries no nonce") {
		t.Fatalf("a record with no nonce was consumed: %v", err)
	}
	if after := strings.Join(l2.Lines(), "\n"); after != before2 {
		t.Fatalf("evidence destroyed.\nbefore:\n%s\nafter:\n%s", before2, after)
	}
}

func TestTombstoneAmbiguityPreserved(t *testing.T) {
	// BOTH cardinality questions are asked BEFORE anything is read or dropped. When the object
	// record is present and fine, the tombstone lookup is never reached by a naive port — and the
	// rewrite would still have replaced every tombstone row for this key.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tgen=1",
		"tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=old-a\tgen=1",
		"tombstone\tkey=volume:v1\tclass=volume\tname=v1\tnonce=old-b\tgen=1",
	})
	err := Tombstone(l, ClassVolume, "v1")
	if err == nil || !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("contradictory tombstones were collapsed: %v", err)
	}
	if got := l.Lines(); len(got) != 3 {
		t.Fatalf("evidence destroyed: %v", got)
	}
}

func TestTombstoneCannotForge(t *testing.T) {
	// A newline or TAB in the object NAME would forge a whole record. The reference needed its own
	// copy of the field rule to stop that, because its tombstone serialized the record itself;
	// this one hands a field list to the same typed editor as every other write, so what is
	// asserted here is the END-TO-END property — a forged name is refused and NOTHING is written.
	//
	// MUTATION-ANCHORING NOTE: no single mutation reddens this, and that is a fact about the
	// ledger rather than a weakness here — the selector gate (argsOK) and the field-list gate
	// (fieldsOK) each refuse it independently, so disabling either leaves the other standing.
	// Measured: with BOTH disabled the case fails on its own two messages and the ledger is left
	// holding the forged record, which is what makes this an integration assertion over those two
	// gates rather than the sole proof of either.
	l := &ledger.Ledger{}
	for _, bad := range []string{"v1\nobject\tkey=volume:forged", "v1\tnonce=forged"} {
		if err := Tombstone(l, ClassVolume, bad); err == nil {
			t.Errorf("a name containing a separator was serialized: %q", bad)
		}
	}
	if got := l.Lines(); len(got) != 0 {
		t.Fatalf("a refused tombstone still wrote: %v", got)
	}
}

// --- deletion authority -------------------------------------------------------------------------

func authorityFixture(t *testing.T) (*ledger.Ledger, *fakeObjs, string) {
	t.Helper()
	l, id := identLedger(t)
	if err := Record(l, ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	f := newFakeObjs()
	f.put(ClassVolume, "v1", map[string]string{LabelInstall: id, LabelNonce: "n1"})
	return l, f, id
}

func TestAuthorityNonceMustMatch(t *testing.T) {
	ctx := context.Background()
	l, f, _ := authorityFixture(t)
	if err := Authority(ctx, l, f, ClassVolume, "v1"); err != nil {
		t.Fatalf("a matching record and object was refused: %v", err)
	}
	// A REUSED name: same name, same installation, DIFFERENT object. `docker volume create`
	// against an existing name succeeds, so this is reachable by accident.
	f.obj["volume:v1"][LabelNonce] = "someone-elses"
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a reused name was authorized for deletion: %v", err)
	}
	if errors.Is(err, ErrGone) {
		t.Fatal("a mismatch was reported as already-gone")
	}
}

func TestAuthorityNoRecord(t *testing.T) {
	ctx := context.Background()
	l, _ := identLedger(t)
	f := newFakeObjs()
	// PRESENT but unattributed: preserved and reported, never assumed ours on no evidence.
	f.put(ClassVolume, "v1", map[string]string{})
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "no provenance record") {
		t.Fatalf("an unattributed object was authorized: %v", err)
	}
	if errors.Is(err, ErrGone) {
		t.Fatal("an unattributed present object was reported as already-gone")
	}
	// COULD NOT BE ASKED: fail closed — authorizing "already gone" on a question that could not be
	// asked is the refusal-into-answer fold this module exists to prevent.
	f.askErr = errors.New("daemon down")
	err = Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || errors.Is(err, ErrGone) || !strings.Contains(err.Error(), "could not be") {
		t.Fatalf("a down daemon was folded into an answer: %v", err)
	}
}

func TestAuthorityGoneIsDistinct(t *testing.T) {
	ctx := context.Background()
	// GONE with no record: this installer's own prior removal already tombstoned it. Nothing to
	// authorize and nothing to fear — an ANSWER, distinct from "cannot prove ownership".
	l, _ := identLedger(t)
	f := newFakeObjs()
	if err := Authority(ctx, l, f, ClassVolume, "v1"); !errors.Is(err, ErrGone) {
		t.Fatalf("gone-with-no-record: %v", err)
	}
	// GONE with a record: same answer, reached through the label lookups.
	l2, f2, _ := authorityFixture(t)
	delete(f2.obj, "volume:v1")
	if err := Authority(ctx, l2, f2, ClassVolume, "v1"); !errors.Is(err, ErrGone) {
		t.Fatalf("gone-with-record: %v", err)
	}
}

func TestAuthorityInstallationLabel(t *testing.T) {
	ctx := context.Background()
	// WHOSE IS IT — the half the nonce does not answer. A foreign installation's object with a
	// MATCHING nonce (a restored or foreign ledger supplies both) must still be refused.
	l, f, _ := authorityFixture(t)
	f.obj["volume:v1"][LabelInstall] = "i9999999999"
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "another installation") {
		t.Fatalf("another installation's object was authorized: %v", err)
	}
	// UNLABELLED: neither adopted nor removed. And absence is refused as absence however the
	// runtime spells it — an absent key and the template-era `<no value>` fold to one answer.
	for _, spelling := range []string{"", "<no value>"} {
		l2, f2, _ := authorityFixture(t)
		f2.obj["volume:v1"][LabelInstall] = spelling
		err := Authority(ctx, l2, f2, ClassVolume, "v1")
		if err == nil || !strings.Contains(err.Error(), "no installation label") {
			t.Fatalf("unlabelled (%q) was authorized: %v", spelling, err)
		}
	}
}

func TestAuthorityOwnIdentityUnreadable(t *testing.T) {
	ctx := context.Background()
	// Two identity records: the ledger cannot answer for its own identity, so nothing can be shown
	// to belong to it and no removal is authorized.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"identity\tid=i0000000001",
		"identity\tid=i0000000002",
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tgen=1",
	})
	f := newFakeObjs()
	f.put(ClassVolume, "v1", map[string]string{LabelInstall: "i0000000001", LabelNonce: "n1"})
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "own identity cannot be read") {
		t.Fatalf("authority proceeded without an identity: %v", err)
	}
}

// TestAuthorityMarksTheRefusalsNobodyAnswered: "not ours" and "nothing was established" both refuse
// and neither authorizes anything, so most callers correctly treat them alike — but the callers
// whose NEXT step differs need to tell them apart, and only Authority knows which it gave.
//
// Abandonment is the case that forced the distinction: a volume that is not ours is nothing for an
// in-progress restore to clean up and the abandonment completes, while a volume whose ownership
// could not be established must leave the staging ledger in place — that ledger being the only
// record of which partial volumes exist. Folding the two either wedges an operator between a
// survivor refusal and a cleanup that never finishes, or destroys that record on the strength of a
// question nobody answered.
//
// EVERY unanswered path is asserted, not a sample: the marker is applied per return statement, so a
// path that is missed carries no sign of it and reads, downstream, as a settled "no".
func TestAuthorityMarksTheRefusalsNobodyAnswered(t *testing.T) {
	ctx := context.Background()
	down := errors.New("the container runtime did not answer")

	unanswered := map[string]func() error{
		// The runtime could not be asked WHOSE it is.
		"the installation label could not be read": func() error {
			l, f, _ := authorityFixture(t)
			f.askErr, f.askErrOn = down, LabelInstall
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		// ...nor WHICH object it is. Reachable only once the first read has answered.
		"the nonce label could not be read": func() error {
			l, f, _ := authorityFixture(t)
			f.askErr, f.askErrOn = down, LabelNonce
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		// No record, and whether the object even exists could not be established either.
		"no record, and existence could not be established": func() error {
			l, _ := identLedger(t)
			f := newFakeObjs()
			f.put(ClassVolume, "v1", map[string]string{})
			f.askErr = down
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		// No runtime seam at all: nothing was asked of anything. Only a programming error reaches
		// this, and the classification is still about WHAT WAS ESTABLISHED — which is nothing.
		"there is no runtime to ask": func() error {
			l, _ := identLedger(t)
			return Authority(ctx, l, nil, ClassVolume, "v1")
		},
		// A class that is not a provenance class: the question has no meaning, so it established
		// nothing about any object either.
		"the class is not a provenance class": func() error {
			l, _ := identLedger(t)
			return Authority(ctx, l, newFakeObjs(), Class("teapot"), "v1")
		},
		// The record LOOKUP failed — ambiguous or unreadable, as opposed to ErrMismatch, which is
		// the selector's ANSWER that the row describes something else.
		"the provenance record could not be looked up": func() error {
			l := &ledger.Ledger{}
			l.ReplaceLines([]string{
				"identity\tid=i0000000001",
				"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tgen=1",
				"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n2\tgen=2",
			})
			f := newFakeObjs()
			f.put(ClassVolume, "v1", map[string]string{LabelInstall: "i0000000001", LabelNonce: "n1"})
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		// The ledger cannot answer for its OWN identity, so nothing can be shown to belong to it.
		"this installation's own identity is unreadable": func() error {
			l := &ledger.Ledger{}
			l.ReplaceLines([]string{
				"identity\tid=i0000000001",
				"identity\tid=i0000000002",
				"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tgen=1",
			})
			f := newFakeObjs()
			f.put(ClassVolume, "v1", map[string]string{LabelInstall: "i0000000001", LabelNonce: "n1"})
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
	}
	for what, run := range unanswered {
		err := run()
		if err == nil {
			t.Fatalf("%s: authorized a removal", what)
		}
		if !errors.Is(err, ErrCannotAsk) {
			t.Fatalf("%s: a refusal nobody answered is not marked as one, so a caller that must keep\n"+
				"state until the question CAN be answered reads it as a settled \"not ours\": %v", what, err)
		}
		if errors.Is(err, ErrGone) {
			t.Fatalf("%s: an unanswered question was reported as an answer: %v", what, err)
		}
	}

	// AND THE ANSWERED REFUSALS ARE NOT MARKED. A marker on everything is a marker on nothing: the
	// caller that keeps its staging ledger on ErrCannotAsk would then never complete an
	// abandonment while any foreign volume stood at one of its names.
	answered := map[string]func() error{
		"a foreign installation's object": func() error {
			l, f, _ := authorityFixture(t)
			f.obj["volume:v1"][LabelInstall] = "i9999999999"
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		"an unlabelled object": func() error {
			l, f, _ := authorityFixture(t)
			f.obj["volume:v1"][LabelInstall] = ""
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		"a reused name": func() error {
			l, f, _ := authorityFixture(t)
			f.obj["volume:v1"][LabelNonce] = "someone-elses"
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		"a present object with no provenance record": func() error {
			l, _ := identLedger(t)
			f := newFakeObjs()
			f.put(ClassVolume, "v1", map[string]string{})
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
		// A SETTLED POLICY, not a question that failed: images are never removed automatically, and
		// asking again will never change that. A caller that keeps state until a question CAN be
		// answered would keep it forever.
		"an image": func() error {
			l, _ := identLedger(t)
			return Authority(ctx, l, newFakeObjs(), Class("image"), "img")
		},
		// The selector's own ANSWER that the row describes something else — spelled as a sentinel
		// precisely so it can be told apart from a lookup that failed.
		"a record that describes another object": func() error {
			l, id := identLedger(t)
			if perr := l.Put("object", "key", "volume:v1", []ledger.Field{
				{Key: "key", Value: "volume:v1"}, {Key: "class", Value: "container"},
				{Key: "name", Value: "other"}, {Key: "nonce", Value: "n1"}, {Key: "gen", Value: "1"},
			}); perr != nil {
				t.Fatal(perr)
			}
			f := newFakeObjs()
			f.put(ClassVolume, "v1", map[string]string{LabelInstall: id, LabelNonce: "n1"})
			return Authority(ctx, l, f, ClassVolume, "v1")
		},
	}
	for what, run := range answered {
		err := run()
		if err == nil {
			t.Fatalf("%s: authorized a removal", what)
		}
		if errors.Is(err, ErrCannotAsk) {
			t.Fatalf("%s: an ANSWERED refusal is marked as one nobody answered: %v", what, err)
		}
	}
}

func TestAuthorityRecordMustDescribe(t *testing.T) {
	ctx := context.Background()
	l, id := identLedger(t)
	// Keyed `volume:v1`, describing something else: it answers the lookup and then hands authority
	// the OTHER object's nonce, compared against THIS object's label.
	if err := l.Put("object", "key", "volume:v1", []ledger.Field{
		{Key: "key", Value: "volume:v1"}, {Key: "class", Value: "container"},
		{Key: "name", Value: "other"}, {Key: "nonce", Value: "n1"}, {Key: "gen", Value: "1"},
	}); err != nil {
		t.Fatal(err)
	}
	f := newFakeObjs()
	f.put(ClassVolume, "v1", map[string]string{LabelInstall: id, LabelNonce: "n1"})
	before := strings.Join(l.Lines(), "\n")
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a record about another object granted authority: %v", err)
	}
	// On the ledger body rather than through Find — see TestTombstoneRecordMustDescribe: Find is
	// the selector that now refuses this row, so it cannot double as a presence probe.
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the conflicting record was not preserved.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// Ill-formed in a field OTHER than the selector: it matches nothing, so it is never authority,
	// and an ordinary operation must not destroy it.
	l2, _ := identLedger(t)
	l2.ReplaceLines(append(l2.Lines(),
		"object\tkey=volume:v2\tclass=volume\tname=v2\tnonce=n1\tgen=1\tnot-a-field"))
	f2 := newFakeObjs()
	f2.put(ClassVolume, "v2", map[string]string{LabelInstall: "i0000000001", LabelNonce: "n1"})
	if err := Authority(ctx, l2, f2, ClassVolume, "v2"); err == nil {
		t.Fatal("an ill-formed record granted authority")
	}
	if !strings.Contains(strings.Join(l2.Lines(), "\n"), "not-a-field") {
		t.Fatal("the ill-formed record was destroyed")
	}
}

func TestImageRecordAndRefusal(t *testing.T) {
	ctx := context.Background()
	l := &ledger.Ledger{}
	const ref = "ghcr.io/x/brokkr@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := ImageRecord(l, ref, "brokkr"); err != nil {
		t.Fatal(err)
	}
	fields, err := l.Find("image", "ref", ref)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := ledger.FieldOf(fields, "product"); p != "brokkr" {
		t.Fatalf("product = %q", p)
	}
	// D37: images are NEVER removed automatically — the ledger proves acquisition, not ownership.
	err = Authority(ctx, l, newFakeObjs(), "image", ref)
	if err == nil || !strings.Contains(err.Error(), "never removed automatically") {
		t.Fatalf("image authority: %v", err)
	}
	if errors.Is(err, ErrGone) {
		t.Fatal("an image refusal was reported as already-gone")
	}
}

func TestUnlistableKind(t *testing.T) {
	// A listing FAILURE, not an empty listing: the reference's missing default arm let an unknown
	// kind fall through to "answered, nothing there" — the same fail-open, from a typo.
	if _, err := Engine(nil).Names(context.Background(), Class("nonsense")); err == nil {
		t.Fatal("an unknown kind was listed as empty")
	}
	if _, err := Engine(nil).Names(context.Background(), ClassProbe); err == nil {
		t.Fatal("probe was listed as its own kind, double-counting the container listing")
	}
}

// --- first use ----------------------------------------------------------------------------------

func homeWith(t *testing.T, build func(home string)) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if build != nil {
		build(home)
	}
	return home
}

func TestFirstUseClean(t *testing.T) {
	// Genuinely first use: no ledger, no trace, and the runtime ANSWERED that it holds none of
	// ours. The installer's own scaffolding is exempt, or no machine would ever read as fresh.
	home := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "bin"))
		mustMkdir(t, filepath.Join(h, "logs"))
		mustMkdir(t, filepath.Join(h, "transcripts"))
		mustWrite(t, filepath.Join(h, "mythical.conf"), "")
	})
	f := newFakeObjs()
	f.list[ClassContainer] = []string{"unrelated"}
	if err := FirstUse(context.Background(), home, f); err != nil {
		t.Fatalf("a genuinely fresh machine was refused: %v", err)
	}
}

func TestFirstUseLedgerPresent(t *testing.T) {
	home := homeWith(t, func(h string) {
		mustWrite(t, filepath.Join(h, ".state", "ledger"), "#mythical-ctl-ledger schema=1\n")
	})
	if err := FirstUse(context.Background(), home, newFakeObjs()); !errors.Is(err, ErrNotFirstUse) {
		t.Fatalf("a ledger that exists is not first use: %v", err)
	}
}

func TestFirstUseLedgerNotRegular(t *testing.T) {
	// A failed or partial restore leaves the ledger path as a DIRECTORY or a dangling symlink;
	// a regular-file test is false for both, and a fresh machine is one this installer
	// initialises over.
	dir := homeWith(t, func(h string) { mustMkdir(t, filepath.Join(h, ".state", "ledger")) })
	err := FirstUse(context.Background(), dir, newFakeObjs())
	if err == nil || errors.Is(err, ErrNotFirstUse) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory at the ledger path: %v", err)
	}
	dangling := homeWith(t, func(h string) {
		if serr := os.Symlink(filepath.Join(h, "gone"), filepath.Join(h, ".state", "ledger")); serr != nil {
			t.Fatal(serr)
		}
	})
	err = FirstUse(context.Background(), dangling, newFakeObjs())
	if err == nil || errors.Is(err, ErrNotFirstUse) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a dangling symlink at the ledger path: %v", err)
	}
}

// resumePrescriptions are the two commands the in-progress-restore diagnostic tells the operator
// to run, byte for byte. This diagnostic must not name `restore --resume`, which the CLI does not
// have: the option loop refuses any unknown `-*` before the verb runs, so an operator recovering an
// interrupted restore was handed "unknown option: --resume", exit 2. A recovery instruction that
// cannot be executed is worse than none, and the only thing that keeps one honest is a test that
// breaks when somebody renames the verb or the flag. The cmd package drives these strings through
// the real dispatcher (TestStagingDiagnosticPrescribesRunnableCommands); this half pins the words.
var resumePrescriptions = []string{
	"'mythical-ctl restore <the same backup directory>'",
	"'mythical-ctl restore --abandon'",
}

// checksummedLedger builds a ledger body at an arbitrary schema whose checksum is genuinely correct
// over its own bytes. A fixture with a wrong checksum reads as CORRUPT, which is a different case.
func checksummedLedger(schema string, rows ...string) string {
	body := "#mythical-ctl-ledger schema=" + schema + "\n"
	for _, r := range rows {
		body += r + "\n"
	}
	return body + "#sha256=" + cliio.SHA256Hex([]byte(body)) + "\n"
}

// TestFirstUseStaging: a regular staging ledger is the in-progress restore — but WHICH diagnostic
// it earns depends on what is INSIDE it, and that is the point.
//
// Presence used to be the whole test, so every regular file was called resumable and prescribed
// resume-or-abandon. internal/backup classifies the CONTENTS before either verb acts: a staging
// ledger whose checksum fails authorizes neither, so both prescriptions named an outcome that
// could not happen. The two modules must give ONE answer about one path.
func TestFirstUseStaging(t *testing.T) {
	// THE TWO PROMISES ARE INDEPENDENT, and collapsing them into one boolean is how a message that
	// keeps one and breaks the other slips through. `resumes` is the claim that re-running
	// CONTINUES the attempt from a directory recorded in the file; `abandonRemoves` is the claim
	// that abandoning REMOVES the partial volumes that attempt created. A state can offer the
	// second without the first.
	for _, tc := range []struct {
		name           string
		body           string
		wants          []string
		resumes        bool
		abandonRemoves bool
	}{
		{"a valid ledger with a resumable intent",
			checksummedLedger(ledger.Schema, "restore\tkey=restore\tphase=2\tsource=/backups/one"),
			[]string{"restore is in progress"}, true, true},
		{"a valid ledger whose intent names no source",
			checksummedLedger(ledger.Schema, "restore\tkey=restore\tphase=2"),
			[]string{"NO source directory", "Re-running cannot continue it", "'mythical-ctl restore --abandon'"}, false, true},
		{"a valid ledger with no intent at all — a COMPLETED restore",
			checksummedLedger(ledger.Schema, "identity\tid=i0123456789"),
			[]string{"COMPLETED restore", "ready to be", "activate it"}, false, false},
		{"one that does not validate", "an interrupted restore left this\n",
			[]string{"does NOT validate", "neither resumed nor abandoned", "'mythical-ctl restore --abandon'"}, false, false},
		{"one a newer build wrote", checksummedLedger("2", "restore\tkey=restore"),
			[]string{"NEWER", "checksum-VALID", "Upgrade mythical-ctl"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := homeWith(t, func(h string) {
				mustWrite(t, filepath.Join(h, ".state", "ledger.staging"), tc.body)
			})
			err := FirstUse(context.Background(), home, newFakeObjs())
			if err == nil || errors.Is(err, ErrNotFirstUse) {
				t.Fatalf("a regular staging ledger did not block first use: %v", err)
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("the diagnostic does not say %q:\n%v", w, err)
				}
			}
			// THE PROMISES, NOT THE COMMAND NAMES. A corrupt staging ledger DOES have something
			// worth running — `restore --abandon` preserves it aside and names what may be
			// blocking — so the command may appear. What may not appear is either promise that
			// state cannot keep: that re-running RESUMES the attempt, and that abandoning REMOVES
			// the partial volumes.
			for _, promise := range []struct {
				claim string
				want  bool
			}{
				{"the source\n  directory is recorded inside the staging ledger", tc.resumes},
				{"removes the partial volumes", tc.abandonRemoves},
			} {
				if got := strings.Contains(err.Error(), promise.claim); got != promise.want {
					t.Fatalf("promises %q = %v, want %v — a prescription is a claim about what the named\n"+
						"verb will DO, and this state cannot deliver it:\n%v", promise.claim, got, promise.want, err)
				}
			}
			if strings.Contains(err.Error(), "--resume") {
				t.Fatalf("the diagnostic prescribes a --resume flag the CLI does not have:\n%v", err)
			}
		})
	}
}

// TestFirstUseStagingAmbiguousIntent: an intent read that FAILED is not "the intent is gone".
//
// Two rows answering for the same key make Find return an ambiguity error, and folding that into
// "no intent" reported the staged restore as COMPLETED and ready to activate — while
// internal/backup Activate asks the same question at the point of action and REFUSES on exactly
// that error. The diagnostic would be promising an outcome the verb will not produce.
func TestFirstUseStagingAmbiguousIntent(t *testing.T) {
	home := homeWith(t, func(h string) {
		mustWrite(t, filepath.Join(h, ".state", "ledger.staging"), checksummedLedger(ledger.Schema,
			"restore\tkey=restore\tphase=2\tsource=/backups/one",
			"restore\tkey=restore\tphase=2\tsource=/backups/two"))
	})
	err := FirstUse(context.Background(), home, newFakeObjs())
	if err == nil || errors.Is(err, ErrNotFirstUse) {
		t.Fatalf("an unreadable restore intent was read as an answer: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be\n  established") {
		t.Fatalf("the refusal does not say the question failed:\n%v", err)
	}
	if strings.Contains(err.Error(), "COMPLETED restore") {
		t.Fatalf("an ambiguous intent was reported as a completed restore:\n%v", err)
	}
	for _, cmd := range resumePrescriptions {
		if strings.Contains(err.Error(), cmd) {
			t.Fatalf("a recovery was prescribed for a state nobody could determine: %s\n%v", cmd, err)
		}
	}
}

// TestFirstUseStagingUnreadable: a staging file that cannot be READ says nothing about whether a
// restore can be resumed, so no recovery is prescribed for it.
func TestFirstUseStagingUnreadable(t *testing.T) {
	home := homeWith(t, func(h string) {
		mustWrite(t, filepath.Join(h, ".state", "ledger.staging"), "x")
	})
	sf := filepath.Join(home, ".state", "ledger.staging")
	if err := os.Chmod(sf, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sf, 0o600) })
	// The premise is MEASURED: a user that bypasses the mode bit leaves the read succeeding, and
	// the assertion below would then be about a different branch entirely.
	if _, err := os.ReadFile(sf); err == nil {
		t.Skipf("this user can still read %s — the unreadable branch is not reachable here", sf)
	}
	err := FirstUse(context.Background(), home, newFakeObjs())
	if err == nil || errors.Is(err, ErrNotFirstUse) {
		t.Fatalf("an unreadable staging ledger was read as an answer: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be READ") || !strings.Contains(err.Error(), "never established") {
		t.Fatalf("the refusal does not say the question failed:\n%v", err)
	}
	for _, cmd := range resumePrescriptions {
		if strings.Contains(err.Error(), cmd) {
			t.Fatalf("a recovery was prescribed for a state nobody could determine: %s\n%v", cmd, err)
		}
	}
}

// TestFirstUseStagingNotRegular: a staging path that is NOT a regular file still BLOCKS first use —
// a restore that failed while creating it is exactly the case that leaves a directory or a
// dangling symlink there, and a machine with one is not fresh.
//
// BUT IT IS NOT A RESUMABLE RESTORE, AND SAYING IT IS WAS THE DEFECT. These shapes got the
// in-progress diagnostic and its two prescribed commands — and internal/backup's own classifier
// REFUSES a staging path that is not a regular file, so both commands could only produce a second
// refusal. Prescribing a recovery the tool will not perform is an ANSWER given where the truth is
// a refusal, and it is handed to the operator at the one moment they are following instructions
// literally.
func TestFirstUseStagingNotRegular(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, h string)
	}{
		{"directory", func(t *testing.T, h string) { mustMkdir(t, filepath.Join(h, ".state", "ledger.staging")) }},
		{"dangling symlink", func(t *testing.T, h string) {
			if err := os.Symlink(filepath.Join(h, "gone"), filepath.Join(h, ".state", "ledger.staging")); err != nil {
				t.Fatal(err)
			}
		}},
		{"named pipe", func(t *testing.T, h string) {
			if err := syscall.Mkfifo(filepath.Join(h, ".state", "ledger.staging"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := homeWith(t, func(h string) { tc.make(t, h) })
			err := FirstUse(context.Background(), home, newFakeObjs())
			// STILL BLOCKS: present is present, and a present staging path is not a fresh machine.
			if err == nil || errors.Is(err, ErrNotFirstUse) {
				t.Fatalf("a %s at the staging path did not block first use: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("the refusal does not say what is wrong with the path:\n%v", err)
			}
			if !strings.Contains(err.Error(), "'mythical-ctl state repair'") {
				t.Fatalf("the refusal prescribes nothing runnable:\n%v", err)
			}
			// AND IT DOES NOT PRESCRIBE A RECOVERY THE RESTORE VERB WILL REFUSE.
			for _, cmd := range resumePrescriptions {
				if strings.Contains(err.Error(), cmd) {
					t.Fatalf("a %s at the staging path was prescribed %s, which the restore verb refuses for\n"+
						"this exact path:\n%v", tc.name, cmd, err)
				}
			}
		})
	}
}

// TestFirstUseStagingUnexaminable covers the fourth fact the single `err == nil` test folded away,
// and it is the fail-open one: an Lstat that failed for anything other than ENOENT fell THROUGH,
// past the staging state entirely, toward "genuinely first use" — the one answer that authorizes
// initialising over this machine.
//
// REACHING IT NEEDS THE STAGING PATH TO FAIL WHILE THE ACTIVE ONE ANSWERS CLEANLY, and the two
// live in the same directory, so no permission bit can separate them — an unsearchable `.state`
// stops the ACTIVE ledger's own Lstat first and asserts nothing about this branch. What does
// separate them is their LENGTH: `ledger.staging` is seven bytes longer than `ledger`, so a home
// can be grown until the active path still fits under the path limit and the staging path does
// not. That window is exactly seven bytes wide, so it is found by measurement, one byte at a time,
// and the premise is re-measured before the assertion rather than assumed.
func TestFirstUseStagingUnexaminable(t *testing.T) {
	home := homeTooLongForTheStagingPathOnly(t)
	err := FirstUse(context.Background(), home, newFakeObjs())
	if err == nil || errors.Is(err, ErrNotFirstUse) {
		t.Fatalf("a staging path nobody could examine was read as an answer: %v", err)
	}
	// The two halves are asserted separately because the message wraps between them.
	if !strings.Contains(err.Error(), "staging ledger path could not be examined") ||
		!strings.Contains(err.Error(), "absence cannot be") ||
		!strings.Contains(err.Error(), "established — refusing rather than treating this as a fresh machine") {
		t.Fatalf("the refusal does not say the STAGING question failed:\n%v", err)
	}
}

// homeTooLongForTheStagingPathOnly grows a directory until `<home>/.state/ledger` still answers a
// clean ENOENT while `<home>/.state/ledger.staging` answers something else — ENAMETOOLONG in
// practice. It returns a home whose ReadDir still works, so every step of FirstUse before the
// staging question runs normally.
func homeTooLongForTheStagingPathOnly(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for i := 0; i < 5000; i++ {
		led := filepath.Join(home, ".state", "ledger")
		_, lerr := os.Lstat(led)
		_, serr := os.Lstat(led + ".staging")
		if errors.Is(lerr, fs.ErrNotExist) && serr != nil && !errors.Is(serr, fs.ErrNotExist) {
			// Measured, not assumed: this is the state the branch under test needs.
			return home
		}
		next := filepath.Join(home, "a")
		if err := os.Mkdir(next, 0o755); err != nil {
			t.Skipf("this filesystem does not reach a path-length limit that separates the two ledger "+
				"paths (%v) — the unexaminable-staging branch is not reachable here", err)
		}
		home = next
	}
	t.Skip("no path length separated the active and staging ledger paths — the branch is not reachable here")
	return ""
}

func TestFirstUseTraces(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, h string)
		want  string
	}{
		{"product conf", func(t *testing.T, h string) { mustWrite(t, filepath.Join(h, "brokkr.conf"), "") }, "brokkr.conf"},
		{"dangling conf", func(t *testing.T, h string) {
			// PRESENCE is the test, not readability.
			if err := os.Symlink(filepath.Join(h, "gone"), filepath.Join(h, "brokkr.conf")); err != nil {
				t.Fatal(err)
			}
		}, "brokkr.conf"},
		{"product dir", func(t *testing.T, h string) {
			mustMkdir(t, filepath.Join(h, "brokkr"))
			mustWrite(t, filepath.Join(h, "brokkr", "compose.yaml"), "")
		}, "brokkr/"},
		{"link to a live dir", func(t *testing.T, h string) {
			mustMkdir(t, filepath.Join(h, "elsewhere"))
			if err := os.Symlink(filepath.Join(h, "elsewhere"), filepath.Join(h, "brokkr")); err != nil {
				t.Fatal(err)
			}
		}, "brokkr/"},
		{"dangling product dir", func(t *testing.T, h string) {
			if err := os.Symlink(filepath.Join(h, "gone"), filepath.Join(h, "brokkr")); err != nil {
				t.Fatal(err)
			}
		}, "brokkr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := homeWith(t, func(h string) { tc.build(t, h) })
			err := FirstUse(context.Background(), home, newFakeObjs())
			if err == nil || !strings.Contains(err.Error(), "already holds") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("trace not reported (want %q): %v", tc.want, err)
			}
		})
	}
}

func TestFirstUseRuntimeObjects(t *testing.T) {
	// Labelled objects survive removing the home entirely, so a clean home is not enough.
	home := homeWith(t, nil)
	f := newFakeObjs()
	f.list[ClassVolume] = []string{"unrelated", "mythical-i0123456789-brokkr-state"}
	err := FirstUse(context.Background(), home, f)
	if err == nil || !strings.Contains(err.Error(), "mythical-i0123456789-brokkr-state") {
		t.Fatalf("a family-named object was not reported: %v", err)
	}
}

func TestFirstUseRuntimeUnasked(t *testing.T) {
	// AN EMPTY ANSWER IS NOT THE SAME FACT AS NO ANSWER. Three swallowed failures produced three
	// empty listings and "genuinely first use" off a question never asked.
	home := homeWith(t, nil)
	f := newFakeObjs()
	f.listFail[ClassNetwork] = true
	err := FirstUse(context.Background(), home, f)
	if err == nil || !strings.Contains(err.Error(), "could not be asked") || !strings.Contains(err.Error(), "network") {
		t.Fatalf("a down runtime read as a fresh machine: %v", err)
	}
}

// --- the host-tool slot exemption ---------------------------------------------------------------

func TestHostToolSlotExemption(t *testing.T) {
	// A REAL product directory holding nothing but the slot is not evidence of a previous
	// INSTALLATION: an operator can install and configure a product's host-side tool before this
	// installer has ever run here.
	home := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr"))
		mustWrite(t, filepath.Join(h, "brokkr", "cli.toml"), "")
	})
	if err := FirstUse(context.Background(), home, newFakeObjs()); err != nil {
		t.Fatalf("the host-tool slot alone was counted as a trace: %v", err)
	}
	// BESIDE a generated artifact it is still a trace — the exemption is "nothing that is not one".
	home2 := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr"))
		mustWrite(t, filepath.Join(h, "brokkr", "cli.toml"), "")
		mustWrite(t, filepath.Join(h, "brokkr", "compose.yaml"), "")
	})
	if err := FirstUse(context.Background(), home2, newFakeObjs()); err == nil {
		t.Fatal("a generated artifact beside the slot was excused")
	}
	// A HIDDEN entry beside it is still a trace — a sweep that cannot see dotfiles is a sweep with
	// a blind spot exactly where a hidden artifact would sit.
	home3 := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr"))
		mustWrite(t, filepath.Join(h, "brokkr", "cli.toml"), "")
		mustWrite(t, filepath.Join(h, "brokkr", ".generated"), "")
	})
	if err := FirstUse(context.Background(), home3, newFakeObjs()); err == nil {
		t.Fatal("a hidden artifact beside the slot was excused")
	}
	// An EMPTY product directory is STILL a trace: the slot must be PRESENT, not merely unopposed.
	home4 := homeWith(t, func(h string) { mustMkdir(t, filepath.Join(h, "brokkr")) })
	if err := FirstUse(context.Background(), home4, newFakeObjs()); err == nil {
		t.Fatal("an empty product directory was excused")
	}
}

func TestHostToolSlotShape(t *testing.T) {
	// The slot must be a plain regular file: exempting a DIRECTORY called cli.toml would hide a
	// whole generated subtree behind a reserved name.
	home := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr", "cli.toml"))
	})
	if err := FirstUse(context.Background(), home, newFakeObjs()); err == nil {
		t.Fatal("a directory at the slot's name was excused")
	}
	// A SYMLINK at the slot's name is not the slot either.
	home2 := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr"))
		mustWrite(t, filepath.Join(h, "real.toml"), "")
		if err := os.Symlink(filepath.Join(h, "real.toml"), filepath.Join(h, "brokkr", "cli.toml")); err != nil {
			t.Fatal(err)
		}
	})
	if err := FirstUse(context.Background(), home2, newFakeObjs()); err == nil {
		t.Fatal("a symlink at the slot's name was excused")
	}
	// A SYMLINK standing where the product DIRECTORY should be is a trace whatever it holds: the
	// exemption is about a directory this layout owns, and the classifier classifies home-relative
	// paths, not link targets somewhere else on the disk.
	home3 := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "elsewhere"))
		mustWrite(t, filepath.Join(h, "elsewhere", "cli.toml"), "")
		if err := os.Symlink(filepath.Join(h, "elsewhere"), filepath.Join(h, "brokkr")); err != nil {
			t.Fatal(err)
		}
	})
	if err := FirstUse(context.Background(), home3, newFakeObjs()); err == nil {
		t.Fatal("a symlinked product directory was excused")
	}
}

func TestHostToolSlotUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this case turns on")
	}
	// "I could not look" is not "there is nothing there".
	home := homeWith(t, func(h string) {
		d := filepath.Join(h, "brokkr")
		mustMkdir(t, d)
		mustWrite(t, filepath.Join(d, "cli.toml"), "")
		if err := os.Chmod(d, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
	})
	if err := FirstUse(context.Background(), home, newFakeObjs()); err == nil {
		t.Fatal("an unreadable product directory was excused")
	}
}

func TestHostToolSlotNameGrammar(t *testing.T) {
	// THE NAME IS VALIDATED IN THE ZONE CLASSIFIER, ONCE. A directory whose name is not a legal
	// product carries no slot, so it is a trace however it is spelled — including a name that is
	// illegal only PAST its first character, which an early-exit classifier would have accepted.
	for _, bad := range []string{"Brokkr", "fooBAR", "9lives", "mythical"} {
		home := homeWith(t, func(h string) {
			mustMkdir(t, filepath.Join(h, bad))
			mustWrite(t, filepath.Join(h, bad, "cli.toml"), "")
		})
		err := FirstUse(context.Background(), home, newFakeObjs())
		if err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("%q was excused by the slot exemption: %v", bad, err)
		}
	}
	// THE EXEMPTION IS PER-DIRECTORY: an exempt product does not excuse a second product's trace.
	home := homeWith(t, func(h string) {
		mustMkdir(t, filepath.Join(h, "brokkr"))
		mustWrite(t, filepath.Join(h, "brokkr", "cli.toml"), "")
		mustMkdir(t, filepath.Join(h, "saga"))
		mustWrite(t, filepath.Join(h, "saga", "compose.yaml"), "")
	})
	err := FirstUse(context.Background(), home, newFakeObjs())
	if err == nil || !strings.Contains(err.Error(), "saga/") {
		t.Fatalf("an exempt product excused another product's trace: %v", err)
	}
	if strings.Contains(errString(err), "brokkr") {
		t.Fatalf("the exempt product was itself reported: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- records this module refuses to READ ---------------------------------------------------------

func TestDuplicateSelectorMatchesNothing(t *testing.T) {
	// The writer refuses to WRITE this record, so it arrives the way a RESTORE puts it there:
	// through the ledger writer, checksum and all. A checksum proves the bytes were not altered
	// after they were written; it does not prove this installation wrote them. So the reader has
	// to refuse the record independently of the writer, or the writer's rule is only a rule for
	// well-behaved ledgers.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"object\tkey=volume:mine\tclass=volume\tname=mine\tnonce=n1\tgen=1\tkey=volume:target",
	})
	// It answers for NEITHER key — not even its own first one.
	for _, name := range []string{"target", "mine"} {
		if _, err := Find(l, ClassVolume, name); !errors.Is(err, ledger.ErrAbsentRecord) {
			t.Errorf("the record answered for %q: %v", name, err)
		}
	}
	// Inert, not deleted — any mismatch preserves. And the REPORTING half is the listing's: a
	// keyed lookup answers absent, a listing refuses rather than omitting what it cannot read.
	if _, err := l.All("object"); err == nil {
		t.Fatal("a listing silently omitted the record it could not read")
	}
	if got := l.Lines(); len(got) != 1 || !strings.Contains(got[0], "key=volume:target") {
		t.Fatalf("the ambiguous record was not preserved: %v", got)
	}
}

func TestEmptyFieldIsIllFormed(t *testing.T) {
	// THE EMPTY FIELD THE REFERENCE'S SPLITTER COULD NOT SEE. `IFS=$'\t'; set -- $record` is IFS
	// word-splitting, and TAB is IFS *whitespace*, so ADJACENT SEPARATORS COLLAPSE: a record with
	// an empty field passed the well-formedness gate as though the empty field were not there, and
	// a checksum-valid ledger carrying one matched, read back, and AUTHORISED DELETION of a live
	// volume. No writer can emit that record — so the read rule accepted what the write rule
	// cannot produce, which is exactly the drift between the two directions the gate exists to
	// make impossible. Here the empty token is one token like any other, and it is not a field.
	ctx := context.Background()
	l, id := identLedger(t)
	l.ReplaceLines(append(l.Lines(),
		"object\tkey=volume:v1\t\tclass=volume\tname=v1\tnonce=actual\tgen=1"))
	f := newFakeObjs()
	f.put(ClassVolume, "v1", map[string]string{LabelInstall: id, LabelNonce: "actual"})
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil {
		t.Fatal("a record with an empty field authorised deletion of a live volume")
	}
	if !strings.Contains(err.Error(), "no provenance record") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if !strings.Contains(strings.Join(l.Lines(), "\n"), "\t\tclass=volume") {
		t.Fatal("the ill-formed record was destroyed rather than preserved")
	}
}

func TestGlobValueComparedLiterally(t *testing.T) {
	// THE WORKING DIRECTORY COULD MANUFACTURE THE NONCE THAT AUTHORISES A DELETION. The
	// reference's unquoted expansion made every field a PATHNAME PATTERN: `*` contains neither a
	// TAB nor a newline, so `nonce=*` is a LEGAL field its own editor writes verbatim and a
	// restored ledger can carry. It then expanded against whatever directory the CLI happened to
	// be invoked from — measured, with a file named `nonce=live-nonce` there, the field BECAME
	// `nonce=live-nonce` and deletion of a volume labelled `live-nonce` was authorised while the
	// ledger literally recorded `*`.
	//
	// Go performs no expansion anywhere, so this asserts the property rather than a defence: the
	// comparison is literal, and the cwd is set up exactly as the reference's was to prove the
	// vector is inert.
	ctx := context.Background()
	t.Chdir(t.TempDir())
	if err := os.WriteFile("nonce=live-nonce", []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	l, id := identLedger(t)
	if err := Record(l, ClassVolume, "v1", "*"); err != nil {
		t.Fatal(err)
	}
	f := newFakeObjs()
	f.put(ClassVolume, "v1", map[string]string{LabelInstall: id, LabelNonce: "live-nonce"})
	err := Authority(ctx, l, f, ClassVolume, "v1")
	if err == nil {
		t.Fatal("the working directory manufactured a nonce that authorised deletion")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// And the literal value still matches ITSELF — the comparison is literal in both directions,
	// not merely broken for globs.
	f.obj["volume:v1"][LabelNonce] = "*"
	if err := Authority(ctx, l, f, ClassVolume, "v1"); err != nil {
		t.Fatalf("a literal '*' did not match itself: %v", err)
	}
}

// --- a row selected by key must describe what was asked for ---------------------------------------

// THE RECORD IS PROVED TO DESCRIBE THE OBJECT AT THE LOOKUP, so no consumer can be the one that
// forgot. `key`, `class` and `name` are three independent fields; a row keyed `volume:v1` that
// describes a network called something else answers this lookup and is then read as v1's record —
// its generation incremented, and the row itself replaced by the keyed put that follows.
func TestRecordRefusesToOverwriteARecordAboutSomethingElse(t *testing.T) {
	l := &ledger.Ledger{}
	// Checksum-valid and well-formed. Nothing about the LINE is wrong — only that it answers for
	// one object while speaking about another, which is the case a field-level check cannot see.
	l.ReplaceLines([]string{"object\tkey=volume:v1\tclass=network\tname=other\tnonce=n9\tgen=1"})
	before := strings.Join(l.Lines(), "\n")

	// The generation read refuses, which is what stops the put: Record's first act is to ask what
	// generation it is superseding.
	if _, err := Gen(l, ClassVolume, "v1"); err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a generation was read off a record about something else: %v", err)
	}
	err := Record(l, ClassVolume, "v1", "n1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a record about something else was overwritten: %v", err)
	}
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("the refusal does not carry ErrMismatch, which is how the classifier tells it from an unreadable ledger: %v", err)
	}
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("the conflicting record was not preserved.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// AND SUPERSEDING STILL WORKS for a record that IS about this object — the guard refuses
	// conflicting evidence, not a newer claim about the same thing.
	l2 := &ledger.Ledger{}
	if err := Record(l2, ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := Record(l2, ClassVolume, "v1", "n2"); err != nil {
		t.Fatalf("a legitimate re-record was refused: %v", err)
	}
	rows, err := l2.All("object")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("a re-record appended beside instead of superseding: %d rows", len(rows))
	}
	if g, _ := ledger.FieldOf(rows[0], "gen"); g != "2" {
		t.Fatalf("gen = %q, want 2", g)
	}
}

// THE TOMBSTONE ROW IS ASKED THE SAME QUESTION AS THE OBJECT ROW. With a good object record
// present the tombstone is never CONSUMED — so a check on the record this function reads its
// identity from never looks at it — and the keyed put below replaces it anyway. That row is the
// only surviving account of whatever it actually described.
func TestTombstoneRefusesToReplaceATombstoneAboutSomethingElse(t *testing.T) {
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n1\tgen=1",
		"tombstone\tkey=volume:v1\tclass=container\tname=other\tnonce=n9\tgen=3",
	})
	before := strings.Join(l.Lines(), "\n")
	err := Tombstone(l, ClassVolume, "v1")
	if err == nil || !strings.Contains(err.Error(), "does not describe it") {
		t.Fatalf("a tombstone about something else was replaced: %v", err)
	}
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("evidence destroyed.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// TombstoneFind refuses it too, and by the same route — it is the selector, not a second copy.
	if _, ferr := TombstoneFind(l, ClassVolume, "v1"); !errors.Is(ferr, ErrMismatch) {
		t.Fatalf("the tombstone lookup handed back a record about something else: %v", ferr)
	}
}
