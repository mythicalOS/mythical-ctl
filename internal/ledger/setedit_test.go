package ledger

import (
	"strings"
	"testing"
)

// The SET editors (Select / DelAll / Append) have no bats ancestor: the reference reached the same
// three-field outstanding records through a hand-rolled body rewrite in lib/state.sh, which is the
// shape this package exists to make unnecessary. What is asserted here is that they carry the SAME
// rules the keyed editors do — because state.bats's guarantees rest on them.

func TestSetSelectorRules(t *testing.T) {
	l := &Ledger{}
	l.ReplaceLines([]string{"outstanding\tcontainer=c1\tkind=alias\tparam=net"})
	// A selector with NO fields matches every record of its kind — refused rather than acted on.
	if _, err := l.Select("outstanding", nil); err == nil {
		t.Fatal("an empty set selector was accepted")
	}
	if _, err := l.DelAll("outstanding", nil); err == nil {
		t.Fatal("an empty set selector reached a deletion")
	}
	// Each match field is judged by the FIELD rule: it has to equal a serialized field byte for
	// byte, so one no field could ever equal matches nothing SILENTLY unless it is refused.
	for _, bad := range []Field{{"kind", "a\tb"}, {"kind", "a\nb"}, {"Kind", "alias"}, {"", "x"}} {
		if _, err := l.Select("outstanding", []Field{bad}); err == nil {
			t.Errorf("Select accepted selector %q=%q", bad.Key, bad.Value)
		}
		if _, err := l.DelAll("outstanding", []Field{bad}); err == nil {
			t.Errorf("DelAll accepted selector %q=%q", bad.Key, bad.Value)
		}
	}
	// One name, one field — a selector naming the same field twice is a contradiction.
	if _, err := l.Select("outstanding", []Field{{"kind", "alias"}, {"kind", "other"}}); err == nil {
		t.Fatal("a selector naming one field twice was accepted")
	}
	// And the kind obeys the kind grammar, as it does everywhere else.
	if _, err := l.Select("Outstanding", []Field{{"kind", "alias"}}); err == nil {
		t.Fatal("a forged kind was accepted")
	}
}

func TestSetSelectRefusesRatherThanShortening(t *testing.T) {
	// COMPLETENESS IS THE CONTRACT: a short list of outstanding checks reads as a container that
	// owes fewer than it does.
	l := &Ledger{}
	l.ReplaceLines([]string{
		"outstanding\tcontainer=c1\tkind=alias\tparam=a",
		"outstanding\tcontainer=c1\tnot-a-field",
	})
	if _, err := l.Select("outstanding", []Field{{"container", "c1"}}); err == nil {
		t.Fatal("a listing silently omitted what it could not read")
	}
	// DelAll refuses BEFORE removing anything: deleting around evidence leaves a ledger that looks
	// tidy and is still wrong.
	if _, err := l.DelAll("outstanding", []Field{{"container", "c1"}}); err == nil {
		t.Fatal("a deletion acted around a record it could not read")
	}
	if len(l.Lines()) != 2 {
		t.Fatalf("evidence destroyed: %v", l.Lines())
	}
}

func TestSetDelAllScopeAndPreservation(t *testing.T) {
	l := &Ledger{}
	l.ReplaceLines([]string{
		"",
		"outstanding\tcontainer=c1\tkind=alias\tparam=a",
		"outstanding\tcontainer=c1\tkind=alias\tparam=b",
		"outstanding\tcontainer=c2\tkind=alias\tparam=a",
		"desired\tcontainer=c1\tstate=running\tverify=owed",
		"",
	})
	// EVERY matching record goes — the whole set for a container, not one row a selector resolves
	// to — and the count is reported.
	n, err := l.DelAll("outstanding", []Field{{"container", "c1"}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("dropped %d, want 2", n)
	}
	body := strings.Join(l.Lines(), "\n")
	// Another container's record, another KIND's record, and both blank rows survive.
	for _, want := range []string{"container=c2", "desired\tcontainer=c1"} {
		if !strings.Contains(body, want) {
			t.Errorf("DelAll removed %q", want)
		}
	}
	blanks := 0
	for _, line := range l.Lines() {
		if line == "" {
			blanks++
		}
	}
	if blanks != 2 {
		t.Fatalf("blank rows were tidied away: %v", l.Lines())
	}
	// Deleting what is absent succeeds with a count of zero.
	n, err = l.DelAll("outstanding", []Field{{"container", "c1"}})
	if err != nil || n != 0 {
		t.Fatalf("second delete = %d, %v", n, err)
	}
}

func TestSetAppendRules(t *testing.T) {
	l := &Ledger{}
	// A SET MEMBER, no selector — there is deliberately no keyed replacement, because replacing by
	// one field is what would collapse a container's several same-kind checks into the last one.
	if err := l.Append("outstanding", []Field{{"container", "c1"}, {"kind", "alias"}, {"param", "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("outstanding", []Field{{"container", "c1"}, {"kind", "alias"}, {"param", "b"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := l.Select("outstanding", []Field{{"container", "c1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("Append replaced instead of adding: %d rows", len(rows))
	}
	// THE SERIALIZER'S OWN RULE, at the primitive rather than only at its callers: a forged field
	// or a forged kind is refused here, so no caller can reach the serializer around it.
	for _, bad := range [][]Field{
		{{"container", "c\tforged"}},
		{{"container", "c\nforged\toutstanding"}},
		{{"CONTAINER", "c1"}},
		{{"container", "c1"}, {"container", "c2"}},
	} {
		if err := l.Append("outstanding", bad); err == nil {
			t.Errorf("Append accepted %v", bad)
		}
	}
	if err := l.Append("Outstanding", []Field{{"container", "c1"}}); err == nil {
		t.Fatal("Append accepted a forged kind")
	}
	// A record with no fields describes nothing.
	if err := l.Append("outstanding", nil); err == nil {
		t.Fatal("Append accepted a record with no fields")
	}
	if len(l.Lines()) != 2 {
		t.Fatalf("a refused Append wrote: %v", l.Lines())
	}
}
