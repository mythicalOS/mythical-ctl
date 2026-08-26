package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

// Inventory — tests/unit/state.bats.
//
// PORTED: tests/unit/state.bats: "desired state and the outstanding set commit in ONE ledger write" -> TestCommitIsOneWrite
// PORTED: tests/unit/state.bats: "the desired row has exactly ONE writer, and it is the atomic one" -> TestCommitIsOneWrite
// PORTED: tests/unit/state.bats: "desired state defaults to NOTHING, not to running" -> TestDesiredDefaultsToNothing
// PORTED: tests/unit/state.bats: "desired state accepts only running or stopped" -> TestDesiredAcceptsOnlyTwo
// PORTED: tests/unit/state.bats: "a desired state the reconciler has no row for is refused on READ, not planned around" -> TestDesiredRefusedOnRead
// PORTED: tests/unit/state.bats: "a running row that does not say what it owes is refused on READ" -> TestDesiredRefusedOnRead
// PORTED: tests/unit/state.bats: "a verify value this core has no meaning for is refused, not planned around" -> TestDesiredRefusedOnRead
// PORTED: tests/unit/state.bats: "two contradicting desired rows are PRESERVED, not replaced by one" -> TestContradictingDesiredRowsPreserved
// PORTED: tests/unit/state.bats: "a container name that would forge a record is refused, never serialized" -> TestForgedContainerNameRefused
// PORTED: tests/unit/state.bats: "clearing an outstanding kind clears ONLY that kind" -> TestClearOnlyWhatWasVerified
// PORTED: tests/unit/state.bats: "clearing names the PARAMETER — a same-kind check nobody verified survives" -> TestClearOnlyWhatWasVerified
// PORTED: tests/unit/state.bats: "a check of a kind this core does not know is not retired by clearing another" -> TestClearOnlyWhatWasVerified
// PORTED: tests/unit/state.bats: "clearing a kind this core does not define is REFUSED, not a silent no-op" -> TestClearRefusals
// PORTED: tests/unit/state.bats: "a clear that does not name WHICH check was verified is refused" -> TestClearRefusals
// PORTED: tests/unit/state.bats: "a clear whose parameter could not be a field is refused, not a silent no-op" -> TestClearRefusals
// PORTED: tests/unit/state.bats: "observed state is read from the runtime, never from the ledger" -> TestObservedComesFromTheRuntime
// PORTED: tests/unit/state.bats: "observed state reports absent for a container that is gone" -> TestObservedComesFromTheRuntime
// PORTED: tests/unit/state.bats: "a runtime answer that is neither true nor false is refused, never read as stopped" -> TestObservedRefusesAnUnknownAnswer
// PORTED: tests/unit/state.bats: "an outstanding flag makes a container NOT reconciled even when actual==desired==running" -> TestReconciled
// PORTED: tests/unit/state.bats: "desired=stopped with the container stopped IS reconciled" -> TestReconciled
// PORTED: tests/unit/state.bats: "the plan for desired=running, stopped, no outstanding, is start-then-verify" -> TestPlanTable
// PORTED: tests/unit/state.bats: "the plan for desired=running, RUNNING, outstanding alias, is verify NOW — not at a future start" -> TestPlanTable
// PORTED: tests/unit/state.bats: "the plan for desired=stopped, still running, is stop — reconciliation runs BOTH ways" -> TestPlanTable
// PORTED: tests/unit/state.bats: "the plan for desired=stopped, not running, is nothing — a completed stop is not a crash" -> TestPlanTable
// PORTED: tests/unit/state.bats: "a STOPPED container with an outstanding alias check DEFERS — it has no address to verify" -> TestPlanTable
// PORTED: tests/unit/state.bats: "an absent container with desired=running plans a rebuild, never a bare start" -> TestPlanTable
// PORTED: tests/unit/state.bats: "a recorded storage-migration intent SUSPENDS reconciliation for that container" -> TestPlanSuspends
// PORTED: tests/unit/state.bats: "an unconfirmed CONTAINER intent also suspends — a half-built container is not reconcilable" -> TestPlanSuspends
// PORTED: tests/unit/state.bats: "an intent lookup that cannot answer refuses the plan — that is not 'there is no intent'" -> TestPlanRefusesUnanswerableLookups
// PORTED: tests/unit/state.bats: "a storage-migration lookup that cannot answer refuses the plan" -> TestPlanRefusesUnanswerableLookups
// PORTED: tests/unit/state.bats: "forget removes both records, for a family uninstall" -> TestForget
// PORTED: tests/unit/state.bats: "forget removes the outstanding SET, not just the one row a selector resolves to" -> TestForget
// PORTED: tests/unit/state.bats: "forget and clear touch only the container they name" -> TestForget
// PORTED: tests/unit/state.bats: "forget drops the attempt record too, and only for the container it names" -> TestForget
// PORTED: tests/unit/state.bats: "a ledger that cannot be READ refuses the outstanding set — it never reports an empty one" -> TestOutstandingRefusesRatherThanShortens
// PORTED: tests/unit/state.bats: "an outstanding entry that does not say what check is owed refuses the whole set" -> TestOutstandingRefusesRatherThanShortens
// PORTED: tests/unit/state.bats: "an outstanding entry that does not say WHAT to verify refuses the whole set" -> TestOutstandingRefusesRatherThanShortens
// PORTED: tests/unit/state.bats: "an outstanding entry whose parameter is EMPTY refuses the set too" -> TestOutstandingRefusesRatherThanShortens
// PORTED: tests/unit/state.bats: "an outstanding check with no parameter is refused — that is the boolean D52 replaced" -> TestCommitRefusesUntypedChecks
// PORTED: tests/unit/state.bats: "a blank row survives a commit and a clear, rather than being tidied away by them" -> TestBlankRowSurvives
// PORTED: tests/unit/state.bats: "an outstanding check SURVIVES a commit that does not mention it" -> TestCommitPreservesTheSet
// PORTED: tests/unit/state.bats: "a later commit ADDS to the outstanding set rather than replacing it" -> TestCommitPreservesTheSet
// PORTED: tests/unit/state.bats: "recording the same check twice records it once, and ONE clear retires it" -> TestCommitPreservesTheSet
// PORTED: tests/unit/state.bats: "a running intent that owes NO live verification must SAY so — silence is refused" -> TestVerifyMustBeDeclared
// PORTED: tests/unit/state.bats: "an intent that owes nothing RECORDS that it owes nothing" -> TestVerifyMustBeDeclared
// PORTED: tests/unit/state.bats: "declaring nothing is owed while a check IS owed is a contradiction, and refused" -> TestVerifyMustBeDeclared
// PORTED: tests/unit/state.bats: "the row says WHICH of the two answers this intent gave" -> TestVerifyMustBeDeclared
// PORTED: tests/unit/state.bats: "a container that does not stay up is resumed ONCE, then reported" -> TestResumeAttempt
// PORTED: tests/unit/state.bats: "a fresh statement of intent grants a fresh attempt" -> TestResumeAttempt
// PORTED: tests/unit/state.bats: "the attempt record is retired by the verification that proves the container came up" -> TestResumeAttempt
// PORTED: tests/unit/state.bats: "recording the same attempt twice records it once" -> TestResumeAttempt
// PORTED: tests/unit/state.bats: "an attempt record that cannot be read refuses the plan, never reads as 'not tried yet'" -> TestResumeAttemptUnreadable

// --- the runtime fake ----------------------------------------------------------------------------

type fakeObjs struct {
	running map[string]bool
	status  map[string]string
	err     map[string]error
}

func newFake() *fakeObjs {
	return &fakeObjs{running: map[string]bool{}, status: map[string]string{}, err: map[string]error{}}
}

func (f *fakeObjs) up(name string)   { f.running[name] = true; f.status[name] = "running" }
func (f *fakeObjs) down(name string) { f.running[name] = false; f.status[name] = "exited" }

func (f *fakeObjs) State(_ context.Context, container string) (bool, string, error) {
	if err := f.err[container]; err != nil {
		return false, "", err
	}
	st, ok := f.status[container]
	if !ok {
		return false, "", engine.ErrAbsent
	}
	return f.running[container], st, nil
}

const c1 = "mythical-i0123456789-brokkr"

func identLedger(t *testing.T) (*ledger.Ledger, string) {
	t.Helper()
	l := &ledger.Ledger{}
	id, err := l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	return l, id
}

// --- desired state -------------------------------------------------------------------------------

func TestDesiredDefaultsToNothing(t *testing.T) {
	// NOTHING RECORDED IS NOT "RUNNING". A default of running would start containers nobody asked
	// for on the first reconcile of any machine.
	l := &ledger.Ledger{}
	_, err := DesiredGet(l, c1)
	if !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("absent desired state: %v", err)
	}
	p, perr := PlanFor(context.Background(), l, newFake(), c1)
	if perr != nil {
		t.Fatal(perr)
	}
	if p != PlanNone {
		t.Fatalf("plan with nothing recorded = %q, want none", p)
	}
}

func TestDesiredAcceptsOnlyTwo(t *testing.T) {
	l := &ledger.Ledger{}
	for _, bad := range []Desired{"", "Running", "paused", "up", "RUNNING"} {
		if err := Commit(l, c1, bad, nil, true); err == nil {
			t.Errorf("desired %q accepted", bad)
		}
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused commit wrote")
	}
}

func TestDesiredRefusedOnRead(t *testing.T) {
	// The value is on DISK. A checksum proves the bytes were not altered after they were written,
	// not that this installation wrote them — so both fields are judged on READ.
	cases := []struct {
		name, row, want string
	}{
		{"no state field", "desired\tcontainer=" + c1 + "\tverify=none", "does not say which state is wanted"},
		{"a state with no row in the table", "desired\tcontainer=" + c1 + "\tstate=paused\tverify=none", "must be running or stopped"},
		{"no verify field", "desired\tcontainer=" + c1 + "\tstate=running", "whether a live verification is"},
		{"a verify value with no meaning", "desired\tcontainer=" + c1 + "\tstate=running\tverify=maybe", "must be 'owed' or 'none'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &ledger.Ledger{}
			l.ReplaceLines([]string{tc.row})
			_, err := DesiredGet(l, c1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal: %v", err)
			}
			if errors.Is(err, ledger.ErrAbsentRecord) {
				t.Fatal("an unreadable row was reported as nothing recorded")
			}
			// NOT PLANNED AROUND: the plan refuses too, rather than printing an empty verdict.
			if _, perr := PlanFor(context.Background(), l, newFake(), c1); perr == nil {
				t.Fatal("the plan proceeded past an unreadable desired row")
			}
			if len(l.Lines()) != 1 {
				t.Fatal("evidence destroyed")
			}
		})
	}
}

func TestContradictingDesiredRowsPreserved(t *testing.T) {
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{
		"desired\tcontainer=" + c1 + "\tstate=running\tverify=none",
		"desired\tcontainer=" + c1 + "\tstate=stopped\tverify=none",
	})
	if _, err := DesiredGet(l, c1); !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("two desired rows: %v", err)
	}
	// A commit must not collapse them either.
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "net"}}, false); !errors.Is(err, ledger.ErrAmbiguous) {
		t.Fatalf("a commit collapsed a contradiction: %v", err)
	}
	if len(l.Lines()) != 2 {
		t.Fatalf("evidence destroyed: %v", l.Lines())
	}
}

func TestForgedContainerNameRefused(t *testing.T) {
	l := &ledger.Ledger{}
	for _, bad := range []string{"c\nDesired\tcontainer=x", "c\tstate=running"} {
		if err := Commit(l, bad, Stopped, nil, true); err == nil {
			t.Errorf("a forged container name was serialized: %q", bad)
		}
		if err := ResumeRecord(l, bad); err == nil {
			t.Errorf("a forged name was recorded as an attempt: %q", bad)
		}
		if err := Forget(l, bad); err == nil {
			t.Errorf("a forged name reached forget: %q", bad)
		}
		if _, err := Outstanding(l, bad); err == nil {
			t.Errorf("a forged name reached the outstanding set: %q", bad)
		}
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused call wrote")
	}
}

// --- the outstanding set -------------------------------------------------------------------------

func TestCommitIsOneWrite(t *testing.T) {
	// In the Go shape the ledger is mutated in memory and the CALLER persists, so "one write" is
	// structural. What is pinned is the property that made it matter: a commit either lands whole
	// or leaves the ledger untouched, so no crash can freeze a half-commit — desired state
	// recorded with the check it owed missing, which is indistinguishable afterwards from a
	// container that owes nothing.
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	want, err := DesiredGet(l, c1)
	if err != nil || want != Running {
		t.Fatalf("desired = %q, %v", want, err)
	}
	out, err := Outstanding(l, c1)
	if err != nil || len(out) != 1 || out[0] != (Check{CheckAlias, "family"}) {
		t.Fatalf("outstanding = %+v, %v", out, err)
	}
	// A REFUSED commit leaves nothing behind — asserted on the branch that refuses LAST, after the
	// set has been read and the additions computed.
	before := l.Lines()
	if err := Commit(l, c1, Running, nil, true); err == nil {
		t.Fatal("declaring nothing owed while a check is owed was accepted")
	}
	after := l.Lines()
	if len(before) != len(after) {
		t.Fatalf("a refused commit changed the ledger: %v -> %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("a refused commit rewrote a row: %q -> %q", before[i], after[i])
		}
	}
	// EXACTLY ONE desired row exists, whatever the commit history.
	if err := Commit(l, c1, Stopped, nil, false); err != nil {
		t.Fatal(err)
	}
	rows, err := l.Select("desired", []ledger.Field{{Key: "container", Value: c1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d desired rows for one container", len(rows))
	}
}

func TestCommitRefusesUntypedChecks(t *testing.T) {
	// D52 replaced a BOOLEAN with a typed set precisely because a flag records no kind and no
	// parameter: an entry carrying nothing can never be matched and so can never be cleared.
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, ""}}, false); err == nil {
		t.Fatal("a check with no parameter was recorded")
	}
	if err := Commit(l, c1, Running, []Check{{"reachable", "x"}}, false); err == nil {
		t.Fatal("a check of an undefined kind was recorded")
	}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "a\tb"}}, false); err == nil {
		t.Fatal("a parameter that would forge a field was recorded")
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused commit wrote")
	}
}

func TestCommitPreservesTheSet(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	// A COMMIT PRESERVES THE SET: it verifies nothing, so a check it does not mention survives.
	if err := Commit(l, c1, Running, nil, false); err != nil {
		t.Fatal(err)
	}
	out, _ := Outstanding(l, c1)
	if len(out) != 1 {
		t.Fatalf("a commit that mentioned nothing dropped the set: %+v", out)
	}
	// A LATER COMMIT ADDS rather than replacing.
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "second"}}, false); err != nil {
		t.Fatal(err)
	}
	out, _ = Outstanding(l, c1)
	if len(out) != 2 {
		t.Fatalf("a later commit replaced the set: %+v", out)
	}
	// THE SAME CHECK TWICE RECORDS ONCE, and ONE clear retires it — recording it twice would need
	// two clears to retire what one verification proved.
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	out, _ = Outstanding(l, c1)
	if len(out) != 2 {
		t.Fatalf("a repeated check was recorded twice: %+v", out)
	}
	if err := OutstandingClear(l, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	out, _ = Outstanding(l, c1)
	if len(out) != 1 || out[0].Param != "second" {
		t.Fatalf("one clear did not retire the repeated check: %+v", out)
	}
}

func TestVerifyMustBeDeclared(t *testing.T) {
	// SILENCE IS REFUSED for a running intent that owes nothing: an empty outstanding set is
	// exactly what a crash between recording the intent and recording the check leaves behind, and
	// the two cannot be told apart afterwards.
	l := &ledger.Ledger{}
	err := Commit(l, c1, Running, nil, false)
	if err == nil || !strings.Contains(err.Error(), "does not say so") {
		t.Fatalf("silence was accepted: %v", err)
	}
	if len(l.Lines()) != 0 {
		t.Fatal("a refused commit wrote")
	}
	// AN INTENT THAT OWES NOTHING RECORDS THAT IT OWES NOTHING — and the row says WHICH of the two
	// answers it gave.
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	rows, _ := l.Select("desired", []ledger.Field{{Key: "container", Value: c1}})
	if v, _ := ledger.FieldOf(rows[0], "verify"); v != "none" {
		t.Fatalf("verify = %q, want none", v)
	}
	// And with a check owed, the row says `owed` — the other of the two answers.
	l2 := &ledger.Ledger{}
	if err := Commit(l2, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	rows2, _ := l2.Select("desired", []ledger.Field{{Key: "container", Value: c1}})
	if v, _ := ledger.FieldOf(rows2[0], "verify"); v != "owed" {
		t.Fatalf("verify = %q, want owed", v)
	}
	// DECLARING NOTHING IS OWED WHILE A CHECK IS OWED is a contradiction, not a shorthand — both
	// when the check comes with the commit, and when it is already in the set.
	// The ONE-CALL contradiction gets its own message. verifyOf would refuse it too, but its
	// wording tells the caller to clear the check with OutstandingClear — misleading advice when
	// the check is the one they just supplied in this very call. Asserting the WORDING is what
	// makes the earlier, better-targeted refusal load-bearing; measured, without this the
	// mutation that deletes it survives.
	err = Commit(l2, c1, Running, []Check{{CheckAlias, "x"}}, true)
	if err == nil || !strings.Contains(err.Error(), "beside a") {
		t.Fatalf("a contradiction in one call: %v", err)
	}
	if strings.Contains(err.Error(), "OutstandingClear") {
		t.Fatal("the one-call contradiction told the caller to clear the check they just supplied")
	}
	// The contradiction against the EXISTING set is the other one, and it IS the clear-it case.
	err = Commit(l2, c1, Running, nil, true)
	if err == nil || !strings.Contains(err.Error(), "OutstandingClear") {
		t.Fatalf("a contradiction against the existing set: %v", err)
	}
	// A STOPPED intent needs no declaration: nothing about a stop implies a live check.
	l3 := &ledger.Ledger{}
	if err := Commit(l3, c1, Stopped, nil, false); err != nil {
		t.Fatalf("a stop was refused for not declaring: %v", err)
	}
}

func TestOutstandingRefusesRatherThanShortens(t *testing.T) {
	// LEAVING AN UNREADABLE ENTRY OUT WOULD MAKE THE CONTAINER LOOK FULLY RECONCILED, so the whole
	// set refuses.
	cases := []struct{ name, row, want string }{
		{"no kind", "outstanding\tcontainer=" + c1 + "\tparam=net", "what KIND of check"},
		{"empty kind", "outstanding\tcontainer=" + c1 + "\tkind=\tparam=net", "EMPTY kind"},
		{"no param", "outstanding\tcontainer=" + c1 + "\tkind=alias", "does not say WHAT it must verify"},
		{"empty param", "outstanding\tcontainer=" + c1 + "\tkind=alias\tparam=", "EMPTY parameter"},
		{"unreadable record", "outstanding\tcontainer=" + c1 + "\tkind=alias\tnot-a-field", "cannot be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &ledger.Ledger{}
			// A desired row too: the plan answers "none" for a container with nothing recorded
			// BEFORE it ever reads the set, so without one the second assertion below would pass
			// for the wrong reason.
			l.ReplaceLines([]string{"desired\tcontainer=" + c1 + "\tstate=running\tverify=owed", tc.row})
			_, err := Outstanding(l, c1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal: %v", err)
			}
			// It never reports an EMPTY set for a ledger it could not read.
			f := newFake()
			f.up(c1)
			if _, perr := PlanFor(context.Background(), l, f, c1); perr == nil {
				t.Fatal("the plan proceeded past an unreadable outstanding set")
			}
			if len(l.Lines()) != 2 {
				t.Fatal("evidence destroyed")
			}
		})
	}
}

func TestClearOnlyWhatWasVerified(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}, {CheckAlias, "second"}}, false); err != nil {
		t.Fatal(err)
	}
	// A same-kind check nobody verified SURVIVES: the clear names the PARAMETER.
	if err := OutstandingClear(l, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	out, err := Outstanding(l, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Param != "second" {
		t.Fatalf("clear retired the wrong entries: %+v", out)
	}
	// A check of a kind this core does not know is not retired by clearing another. It cannot be
	// written through Commit, so it arrives the way a restore puts it there.
	l2 := &ledger.Ledger{}
	if err := Commit(l2, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	l2.ReplaceLines(append(l2.Lines(), "outstanding\tcontainer="+c1+"\tkind=reachable\tparam=family"))
	if err := OutstandingClear(l2, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(l2.Lines(), "\n"), "kind=reachable") {
		t.Fatalf("clearing 'alias' retired a 'reachable' check: %v", l2.Lines())
	}
}

func TestClearRefusals(t *testing.T) {
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	before := strings.Join(l.Lines(), "\n")
	// A KIND THIS CORE DOES NOT DEFINE is refused, not a silent no-op: a silent no-op reads as
	// "that check is retired" to every caller.
	if err := OutstandingClear(l, c1, "reachable", "family"); err == nil {
		t.Fatal("clearing an undefined kind succeeded")
	}
	// A CLEAR THAT DOES NOT NAME WHICH check was verified retires checks nobody performed.
	if err := OutstandingClear(l, c1, CheckAlias, ""); err == nil {
		t.Fatal("clearing without a parameter succeeded")
	}
	// A PARAMETER THAT COULD NOT BE A FIELD could never have matched one, so it is refused rather
	// than reported as a successful clear.
	if err := OutstandingClear(l, c1, CheckAlias, "a\tb"); err == nil {
		t.Fatal("clearing with a forged parameter succeeded")
	}
	if strings.Join(l.Lines(), "\n") != before {
		t.Fatal("a refused clear changed the ledger")
	}
}

func TestBlankRowSurvives(t *testing.T) {
	// A blank row grants nothing and answers nothing, and it is EVIDENCE that a ledger needs
	// repairing — so it is kept exactly where it is rather than tidied away by an ordinary write.
	l := &ledger.Ledger{}
	l.ReplaceLines([]string{"", "product\tname=brokkr", ""})
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	blanks := 0
	for _, line := range l.Lines() {
		if line == "" {
			blanks++
		}
	}
	if blanks != 2 {
		t.Fatalf("a commit tidied away blank rows: %v", l.Lines())
	}
	if err := OutstandingClear(l, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	blanks = 0
	for _, line := range l.Lines() {
		if line == "" {
			blanks++
		}
	}
	if blanks != 2 {
		t.Fatalf("a clear tidied away blank rows: %v", l.Lines())
	}
}

func TestForget(t *testing.T) {
	l := &ledger.Ledger{}
	const other = "mythical-i0123456789-saga"
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "a"}, {CheckAlias, "b"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := ResumeRecord(l, c1); err != nil {
		t.Fatal(err)
	}
	if err := Commit(l, other, Running, []Check{{CheckAlias, "a"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := ResumeRecord(l, other); err != nil {
		t.Fatal(err)
	}
	if err := Forget(l, c1); err != nil {
		t.Fatal(err)
	}
	// BOTH records, and the WHOLE outstanding set — not just the one row a selector resolves to.
	if _, err := DesiredGet(l, c1); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("desired state survived forget: %v", err)
	}
	out, err := Outstanding(l, c1)
	if err != nil || len(out) != 0 {
		t.Fatalf("outstanding survived forget: %+v %v", out, err)
	}
	if tried, _ := resumedFor(l, c1); tried {
		t.Fatal("the attempt record survived forget")
	}
	// AND ONLY THE CONTAINER IT NAMES.
	if _, err := DesiredGet(l, other); err != nil {
		t.Fatalf("forget touched another container's desired state: %v", err)
	}
	oout, _ := Outstanding(l, other)
	if len(oout) != 1 {
		t.Fatalf("forget touched another container's set: %+v", oout)
	}
	if tried, _ := resumedFor(l, other); !tried {
		t.Fatal("forget dropped another container's attempt record")
	}
	// A clear is scoped the same way.
	if err := OutstandingClear(l, other, CheckAlias, "a"); err != nil {
		t.Fatal(err)
	}
	// Forgetting what is not there succeeds — a deletion that finds nothing has achieved its
	// purpose.
	if err := Forget(l, "mythical-i0123456789-none"); err != nil {
		t.Fatalf("forgetting an unknown container: %v", err)
	}
}

// --- observed state ------------------------------------------------------------------------------

func TestObservedComesFromTheRuntime(t *testing.T) {
	ctx := context.Background()
	// NEVER FROM THE LEDGER: the ledger says running, the runtime says stopped, and observed
	// follows the runtime.
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.down(c1)
	obs, err := Observe(ctx, f, c1)
	if err != nil {
		t.Fatal(err)
	}
	if obs != ObsStopped {
		t.Fatalf("observed = %q, want stopped", obs)
	}
	f.up(c1)
	if obs, _ = Observe(ctx, f, c1); obs != ObsRunning {
		t.Fatalf("observed = %q, want running", obs)
	}
	// ABSENT for a container that is gone — and it is an ANSWER, not a refusal.
	if obs, err = Observe(ctx, newFake(), c1); err != nil || obs != ObsAbsent {
		t.Fatalf("observed = %q, %v", obs, err)
	}
	// A question that could not be asked is neither.
	f2 := newFake()
	f2.err[c1] = errors.New("daemon down")
	if _, err := Observe(ctx, f2, c1); err == nil {
		t.Fatal("a down daemon produced an observed state")
	}
}

func TestObservedRefusesAnUnknownAnswer(t *testing.T) {
	ctx := context.Background()
	// The reference read a boolean template and refused an answer that was "neither true nor
	// false". A typed bool has no third value, so the same refusal lands one field along: a STATUS
	// WORD this core has no meaning for. Reading it as 'stopped' would plan a start against a
	// container whose state was never established.
	f := newFake()
	f.status[c1] = "wedged"
	f.running[c1] = false
	if _, err := Observe(ctx, f, c1); err == nil {
		t.Fatal("an unknown status was read as stopped")
	}
	// And every status the daemon really uses IS handled — the refusal must not over-refuse.
	for _, st := range []string{"created", "running", "paused", "restarting", "removing", "exited", "dead"} {
		f2 := newFake()
		f2.status[c1] = st
		f2.running[c1] = st == "running" || st == "paused"
		if _, err := Observe(ctx, f2, c1); err != nil {
			t.Errorf("status %q refused: %v", st, err)
		}
	}
}

// --- reconciled and the plan ---------------------------------------------------------------------

func TestReconciled(t *testing.T) {
	ctx := context.Background()
	// AN OUTSTANDING CHECK MAKES A CONTAINER NOT RECONCILED even when observed equals desired:
	// "it started" is not evidence that its alias resolves.
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.up(c1)
	ok, err := Reconciled(ctx, l, f, c1)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a container owing a check reported as reconciled")
	}
	if err := OutstandingClear(l, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	if ok, _ = Reconciled(ctx, l, f, c1); !ok {
		t.Fatal("running, desired running, nothing owed: not reconciled")
	}
	// DESIRED=STOPPED WITH THE CONTAINER STOPPED IS RECONCILED — reconciliation is not "is it up".
	l2 := &ledger.Ledger{}
	if err := Commit(l2, c1, Stopped, nil, false); err != nil {
		t.Fatal(err)
	}
	f2 := newFake()
	f2.down(c1)
	if ok, err = Reconciled(ctx, l2, f2, c1); err != nil || !ok {
		t.Fatalf("stopped/stopped: %v %v", ok, err)
	}
}

func TestPlanTable(t *testing.T) {
	ctx := context.Background()
	type setup struct {
		want   Desired
		checks []Check
		none   bool
		state  string // "up", "down", "absent"
	}
	cases := []struct {
		name string
		s    setup
		want Plan
	}{
		{"running/absent rebuilds, never a bare start", setup{Running, nil, true, "absent"}, PlanRebuild},
		{"running/stopped starts then verifies", setup{Running, nil, true, "down"}, PlanStartVerify},
		{"running/running with a check verifies NOW", setup{Running, []Check{{CheckAlias, "family"}}, false, "up"}, PlanVerify},
		{"running/running with nothing owed is done", setup{Running, nil, true, "up"}, PlanNone},
		{"stopped/running stops — both ways", setup{Stopped, nil, false, "up"}, PlanStop},
		{"stopped/stopped is nothing — a completed stop is not a crash", setup{Stopped, nil, false, "down"}, PlanNone},
		{"stopped/stopped with a check DEFERS — no address to verify", setup{Stopped, []Check{{CheckAlias, "family"}}, false, "down"}, PlanDefer},
		{"stopped/absent is nothing", setup{Stopped, nil, false, "absent"}, PlanNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &ledger.Ledger{}
			if err := Commit(l, c1, tc.s.want, tc.s.checks, tc.s.none); err != nil {
				t.Fatal(err)
			}
			f := newFake()
			switch tc.s.state {
			case "up":
				f.up(c1)
			case "down":
				f.down(c1)
			}
			got, err := PlanFor(ctx, l, f, c1)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("plan = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPlanSuspends(t *testing.T) {
	ctx := context.Background()
	// AN UNCONFIRMED CONTAINER INTENT SUSPENDS: a half-built container is not reconcilable.
	l, _ := identLedger(t)
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := intent.Open(l, prov.ClassContainer, c1, "n1", time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.up(c1)
	got, err := PlanFor(ctx, l, f, c1)
	if err != nil {
		t.Fatal(err)
	}
	if got != PlanSuspended {
		t.Fatalf("plan = %q, want suspended", got)
	}

	// A RECORDED STORAGE MIGRATION SUSPENDS: acting here would act on a container the migration
	// may have stopped on purpose.
	l2, id := identLedger(t)
	container := "mythical-" + id + "-brokkr"
	if err := Commit(l2, container, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := prov.Record(l2, prov.ClassContainer, container, "n1"); err != nil {
		t.Fatal(err)
	}
	l2.ReplaceLines(append(l2.Lines(), "storagemig\tproduct=brokkr\tphase=copy"))
	f2 := newFake()
	f2.up(container)
	got, err = PlanFor(ctx, l2, f2, container)
	if err != nil {
		t.Fatal(err)
	}
	if got != PlanSuspended {
		t.Fatalf("plan = %q, want suspended", got)
	}
	// A migration for ANOTHER product does not suspend this one.
	l3, id3 := identLedger(t)
	container3 := "mythical-" + id3 + "-brokkr"
	if err := Commit(l3, container3, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := prov.Record(l3, prov.ClassContainer, container3, "n1"); err != nil {
		t.Fatal(err)
	}
	l3.ReplaceLines(append(l3.Lines(), "storagemig\tproduct=saga\tphase=copy"))
	f3 := newFake()
	f3.up(container3)
	if got, err = PlanFor(ctx, l3, f3, container3); err != nil || got != PlanNone {
		t.Fatalf("another product's migration suspended this one: %q %v", got, err)
	}
}

func TestPlanRefusesUnanswerableLookups(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.up(c1)
	// TWO INTENT ROWS: "the question failed" is not "there is no intent".
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	l.ReplaceLines(append(l.Lines(),
		"intent\tkey=container:"+c1+"\tclass=container\tname="+c1+"\tnonce=a\tcreated=1700000000",
		"intent\tkey=container:"+c1+"\tclass=container\tname="+c1+"\tnonce=b\tcreated=1700000000"))
	_, err := PlanFor(ctx, l, f, c1)
	if err == nil || !strings.Contains(err.Error(), "unconfirmed intent governs") {
		t.Fatalf("an unanswerable intent lookup produced a plan: %v", err)
	}

	// A STORAGE-MIGRATION LOOKUP THAT CANNOT ANSWER refuses too — here because the provenance
	// record the lookup starts from is ambiguous.
	l2, id := identLedger(t)
	container := "mythical-" + id + "-brokkr"
	if err := Commit(l2, container, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	l2.ReplaceLines(append(l2.Lines(),
		"object\tkey=container:"+container+"\tclass=container\tname="+container+"\tnonce=a\tgen=1",
		"object\tkey=container:"+container+"\tclass=container\tname="+container+"\tnonce=b\tgen=1"))
	f2 := newFake()
	f2.up(container)
	_, err = PlanFor(ctx, l2, f2, container)
	if err == nil || !strings.Contains(err.Error(), "storage migration governs") {
		t.Fatalf("an unanswerable migration lookup produced a plan: %v", err)
	}
}

func TestResumeAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.down(c1)
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	// FIRST pass: start and verify.
	got, err := PlanFor(ctx, l, f, c1)
	if err != nil || got != PlanStartVerify {
		t.Fatalf("first pass = %q %v", got, err)
	}
	if err := ResumeRecord(l, c1); err != nil {
		t.Fatal(err)
	}
	// SECOND pass, still down: REPORTED, not started again. Starting a container that does not
	// stay up, on every pass, for ever, is the loop the attempt record exists to stop.
	got, err = PlanFor(ctx, l, f, c1)
	if err != nil || got != PlanExited {
		t.Fatalf("second pass = %q %v", got, err)
	}
	// RECORDING THE SAME ATTEMPT TWICE RECORDS ONCE — it is a marker, not a counter.
	if err := ResumeRecord(l, c1); err != nil {
		t.Fatal(err)
	}
	rows, err := l.Select("resumed", []ledger.Field{{Key: "container", Value: c1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d attempt records", len(rows))
	}
	// A FRESH STATEMENT OF INTENT GRANTS A FRESH ATTEMPT, or a container that failed to stay up
	// once could never be started again.
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	got, err = PlanFor(ctx, l, f, c1)
	if err != nil || got != PlanStartVerify {
		t.Fatalf("after a fresh commit = %q %v", got, err)
	}
	// THE ATTEMPT RECORD IS RETIRED BY THE VERIFICATION that proves the container came up.
	l2 := &ledger.Ledger{}
	if err := Commit(l2, c1, Running, []Check{{CheckAlias, "family"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := ResumeRecord(l2, c1); err != nil {
		t.Fatal(err)
	}
	if tried, _ := resumedFor(l2, c1); !tried {
		t.Fatal("the attempt was not recorded")
	}
	if err := OutstandingClear(l2, c1, CheckAlias, "family"); err != nil {
		t.Fatal(err)
	}
	if tried, _ := resumedFor(l2, c1); tried {
		t.Fatal("the verification did not retire the attempt record")
	}
}

func TestResumeAttemptUnreadable(t *testing.T) {
	ctx := context.Background()
	// NEVER READS AS 'NOT TRIED YET': that would start it again, which is the loop the record
	// exists to stop.
	l := &ledger.Ledger{}
	if err := Commit(l, c1, Running, nil, true); err != nil {
		t.Fatal(err)
	}
	l.ReplaceLines(append(l.Lines(), "resumed\tcontainer="+c1+"\tnot-a-field"))
	f := newFake()
	f.down(c1)
	_, err := PlanFor(ctx, l, f, c1)
	if err == nil || !strings.Contains(err.Error(), "already resumed") {
		t.Fatalf("an unreadable attempt record produced a plan: %v", err)
	}
	if len(l.Lines()) != 2 {
		t.Fatal("evidence destroyed")
	}
}
