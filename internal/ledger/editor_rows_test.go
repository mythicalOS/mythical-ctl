package ledger

import (
	"errors"
	"strings"
	"testing"
)

// Inventory — tests/unit/prov.bats, the editor/identity rows ledger_test.go does not claim.
// Written alongside internal/prov to close the file's coverage: the BEHAVIOR under test is
// this package's, so the tests live here rather than reaching through the provenance module.
//
// PORTED: tests/unit/prov.bats: "the key SELECTOR is validated too — it is one field split in two" -> TestSelectorIsValidated
// PORTED: tests/unit/prov.bats: "the record KIND is validated too — it is serialized exactly like a field is" -> TestFieldGrammar -- the forged-kind case
// PORTED: tests/unit/prov.bats: "a record carrying one field name TWICE is refused — it would answer for two objects" -> TestFieldGrammar -- the dup case
// PORTED: tests/unit/prov.bats: "neither editor deletes or supersedes a record it refuses to read" -> TestEditorsPreserveWhatTheyCannotRead
// PORTED: tests/unit/prov.bats: "mi_led_field refuses to read a field out of a record that is not well-formed" -> TestNoFieldsWithoutTheGate
// PORTED: tests/unit/prov.bats: "a listing refuses rather than silently omitting a record it cannot read" -> TestAmbiguityPreserves -- the All case
// PORTED: tests/unit/prov.bats: "an identity the ledger cannot answer for is refused, not read as a fresh machine" -> TestIdentityCannotAnswer
// PORTED: tests/unit/prov.bats: "two records answering one selector are ambiguous — nothing is read from them" -> TestAmbiguityPreserves
// PORTED: tests/unit/prov.bats: "neither editor collapses a contradiction into one record" -> TestAmbiguityPreserves
// PORTED: tests/unit/prov.bats: "a keyed replacement must carry its key — a put never drops one record while writing another" -> TestEditorPutReplacesKeyed
// PORTED: tests/unit/prov.bats: "the editor drops exactly ONE row, even when the ledger holds that row twice" -> TestWithoutDropsExactlyOneRow
// PORTED: tests/unit/prov.bats: "an identity record that answers nothing is not a fresh machine" -> TestIdentityCannotAnswer
// PORTED: tests/unit/prov.bats: "a row that is only its KIND is a malformed record, not an absent one" -> TestBareKindRow
// PORTED: tests/unit/prov.bats: "the bare-kind blind spot was in how a kind is RECOGNISED, so it was in every kind at once" -> TestBareKindRow
// PORTED: tests/unit/prov.bats: "a blank body row is preserved by an editor rewrite, and reported" -> TestAmbiguityPreserves -- the blank-row case
// PORTED: tests/unit/prov.bats: "an EMPTY ledger body is not a blank row — the first write neither reports one nor makes one" -> TestEmptyBodyIsNotABlankRow

func TestSelectorIsValidated(t *testing.T) {
	// ASKED OF THE TWO ENTRY POINTS THAT TAKE NO REPLACEMENT LIST, which is where this rule is the
	// only thing that can refuse. Through Put the same inputs are refused twice over and neither
	// refusal is this one — a selector no field can ever equal cannot be present in a valid field
	// list, so "a replacement carries its key" answers first. Measured in the reference: with this
	// rule deleted the Put calls still refused, leaving the test green over a missing guard.
	l := &Ledger{}
	for _, sel := range []struct{ kf, kv string }{
		{"na\tme", "x"},  // a TAB forges a field boundary
		{"name", "a\nb"}, // a newline forges a whole record
		{"Name", "x"},    // the key half obeys the key grammar: a selector must equal a serialized
		//                   field BYTE FOR BYTE, and one no field can equal supersedes nothing
	} {
		if err := l.Del("object", sel.kf, sel.kv); err == nil {
			t.Errorf("Del accepted selector %q=%q", sel.kf, sel.kv)
		} else if !strings.Contains(err.Error(), "key selector") {
			t.Errorf("Del(%q=%q) refused for the wrong reason: %v", sel.kf, sel.kv, err)
		}
		if _, err := l.Find("object", sel.kf, sel.kv); err == nil {
			t.Errorf("Find accepted selector %q=%q", sel.kf, sel.kv)
		} else if !strings.Contains(err.Error(), "key selector") {
			t.Errorf("Find(%q=%q) refused for the wrong reason: %v", sel.kf, sel.kv, err)
		}
		// The control: the put path must still refuse them, whichever rule reaches them first.
		if err := l.Put("object", sel.kf, sel.kv, []Field{{"class", "container"}}); err == nil {
			t.Errorf("Put accepted selector %q=%q", sel.kf, sel.kv)
		}
	}
}

func TestEditorsPreserveWhatTheyCannotRead(t *testing.T) {
	// An ill-formed record matches nothing — so neither editor may reach it. The reference's
	// weakness ran both ways: the editors matched the single well-formed `key=` and removed or
	// superseded such a record, destroying the evidence that a ledger needs repairing at the first
	// ordinary operation that touched that key.
	const illFormed = "object\tkey=volume:v1\tclass=volume\tname=v1\tnonce=n\tgen=1\tnot-a-field"
	l := &Ledger{}
	l.ReplaceLines([]string{illFormed, "object\tkey=volume:v2\tclass=volume\tname=v2\tnonce=n\tgen=1"})

	// Del SUCCEEDS on what it cannot find — a deletion that finds nothing has achieved its purpose
	// — so the assertion that matters is what it left behind, not its error.
	if err := l.Del("object", "key", "volume:v1"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if !strings.Contains(strings.Join(l.Lines(), "\n"), illFormed) {
		t.Fatalf("Del removed an ill-formed record: %v", l.Lines())
	}
	if err := l.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}, {"gen", "9"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	body := strings.Join(l.Lines(), "\n")
	if !strings.Contains(body, illFormed) {
		t.Fatalf("the ill-formed record was superseded away: %v", l.Lines())
	}
	// The unrelated record is untouched, and the put INSERTED beside rather than replacing what it
	// could not read.
	if _, err := l.Find("object", "key", "volume:v2"); err != nil {
		t.Fatalf("an unrelated record was disturbed: %v", err)
	}
}

func TestNoFieldsWithoutTheGate(t *testing.T) {
	// THE ONLY WAY TO OBTAIN A RECORD'S FIELDS IS THROUGH THE GATE. The reference had a separate
	// field reader that took the FIRST `nonce=` and silently ignored a second, so a record
	// contradicting itself granted deletion. Here there is no second door: Find refuses and All
	// refuses, so no caller can hold fields the gate did not judge.
	l := &Ledger{}
	l.ReplaceLines([]string{"object\tkey=volume:v1\tnonce=a\tnonce=b"})
	if _, err := l.Find("object", "key", "volume:v1"); !errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("a self-contradicting record answered a lookup: %v", err)
	}
	if _, err := l.All("object"); err == nil {
		t.Fatal("a listing handed back a record it could not read")
	}
	if len(l.Lines()) != 1 {
		t.Fatal("evidence destroyed")
	}
}

func TestIdentityCannotAnswer(t *testing.T) {
	// ONE record, well-formed, and the value it carries is EMPTY — the lookup resolves to one
	// record and ZERO answers. Reported as "none recorded" that means first use, and a fresh
	// identity was minted BESIDE a record already there, leaving two and wedging every later read.
	l := &Ledger{}
	l.ReplaceLines([]string{"identity\tid="})
	if _, err := l.IdentGet(); err == nil || errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("an empty id read as absent: %v", err)
	}
	if _, err := l.IdentEnsure(); err == nil {
		t.Fatal("minted over an identity record already on disk")
	}
	if got := l.Lines(); len(got) != 1 || got[0] != "identity\tid=" {
		t.Fatalf("the identity record set changed: %v", got)
	}
	// TWO identity records: which one this installation is cannot be guessed — every runtime name
	// is scoped by it, so guessing would adopt or delete another installation's objects.
	l2 := &Ledger{}
	l2.ReplaceLines([]string{"identity\tid=i0000000001", "identity\tid=i0000000002"})
	if _, err := l2.IdentGet(); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two identities: %v", err)
	}
	if _, err := l2.IdentEnsure(); err == nil {
		t.Fatal("minted a third identity beside two")
	}
}

func TestBareKindRow(t *testing.T) {
	// `identity` alone: no TAB, no fields. Every reference reader matched `<kind><TAB>*`, so this
	// row was a record of NO kind — skipped in silence by all of them. The identity reader counted
	// zero, reported "none recorded" (which means first use), and minted a fresh identity BESIDE
	// the row already on disk. Closed where the KIND is recognised, which closes it for every kind
	// at once: the row IS a record of that kind, its field list is empty, and an empty field list
	// is what the record gate already refuses.
	l := &Ledger{}
	l.ReplaceLines([]string{"identity"})
	if _, err := l.IdentGet(); err == nil || errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("a bare-kind row read as absent: %v", err)
	}
	if _, err := l.IdentEnsure(); err == nil {
		t.Fatal("minted beside a row already on disk")
	}
	if got := l.Lines(); len(got) != 1 || got[0] != "identity" {
		t.Fatalf("the row set changed: %v", got)
	}

	// AND IT WAS IN EVERY KIND AT ONCE — the blind spot was in recognition, not in any one reader.
	// On a lookup such a row matches nothing; on a LISTING it is a reported refusal, never dropped.
	for _, kind := range []string{"object", "tombstone", "image", "product", "identity"} {
		l2 := &Ledger{}
		l2.ReplaceLines([]string{kind})
		if _, err := l2.Find(kind, "key", "anything"); !errors.Is(err, ErrAbsentRecord) {
			t.Errorf("%s: a bare-kind row answered a lookup: %v", kind, err)
		}
		if _, err := l2.All(kind); err == nil {
			t.Errorf("%s: a listing silently omitted a bare-kind row", kind)
		}
		if err := l2.Put(kind, "key", "k", []Field{{"key", "k"}}); err != nil {
			t.Errorf("%s: put: %v", kind, err)
		}
		if !strings.Contains(strings.Join(l2.Lines(), "\n"), kind+"\n") && l2.Lines()[0] != kind {
			t.Errorf("%s: the bare-kind row was tidied away: %v", kind, l2.Lines())
		}
	}
}

func TestWithoutDropsExactlyOneRow(t *testing.T) {
	// THE HELPER IS ASKED DIRECTLY, AND DELIBERATELY SO. Its argument is the ONE row the selector
	// resolved to, and its contract is to drop THAT row — not "every row that looks like it". No
	// public path can hand it two identical rows, because the selector refuses two of anything
	// before this is reached, so nothing above it can pin the contract: measured in the reference,
	// removing the drop-one belt left the whole suite green. A helper whose arity is only
	// incidentally right is one a later caller — a repair verb, holding duplicates on purpose —
	// turns into a double deletion.
	l := &Ledger{}
	l.ReplaceLines([]string{"object\tkey=a", "object\tkey=a", "object\tkey=b"})
	out := l.without("object", "key=a")
	a, b := 0, 0
	for _, line := range out {
		switch line {
		case "object\tkey=a":
			a++
		case "object\tkey=b":
			b++
		}
	}
	if a != 1 {
		t.Fatalf("both identical rows went (kept %d): %v", a, out)
	}
	if b != 1 {
		t.Fatalf("an unrelated row went: %v", out)
	}
}

func TestEmptyBodyIsNotABlankRow(t *testing.T) {
	// The reference read the body through a here-string, which supplies a newline of its own, so
	// an empty body arrived as one empty line. Preserving that as a blank row would invent one on
	// the very first write of every installation, and report it on every write after.
	l := &Ledger{}
	if err := l.Put("product", "name", "q1", []Field{{"name", "q1"}}); err != nil {
		t.Fatalf("the first write failed: %v", err)
	}
	for _, line := range l.Lines() {
		if line == "" {
			t.Fatalf("the first write created a blank row: %v", l.Lines())
		}
	}
	rows, err := l.All("product")
	if err != nil {
		t.Fatalf("a listing reported a blank row that is not there: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if v, _ := FieldOf(rows[0], "name"); v != "q1" {
		t.Fatalf("name = %q", v)
	}
}
