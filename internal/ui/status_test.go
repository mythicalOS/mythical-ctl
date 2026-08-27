// NO BATS INVENTORY. This task ports no bats test and claims none: the frozen reference is a
// shell CLI with no terminal interface, so there is no test of a status DASHBOARD to port. The
// report's own behaviour — what it says, and the answer/refusal distinction it says it with — is
// tested where it is implemented, in internal/verbs, whose share of tests/unit/verbs.bats is
// claimed by Task 23. Nothing below re-asserts it. What is asserted below is that this view
// SHOWS what that verb produced, including every refusal, and invents nothing the verb refused
// to invent.
package ui

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"mythicalos.ai/ctl/internal/verbs"
)

// --- helpers ------------------------------------------------------------------------------------

// sstep drives one message through the dashboard.
func sstep(m StatusModel, msg tea.Msg) (StatusModel, tea.Cmd) { return m.update(msg) }

// say feeds one report line, the way the bridge does for a d.say().
func say(m StatusModel, line string) StatusModel {
	m, _ = sstep(m, ProgressMsg{Event: verbs.ProgressEvent{Stage: "status", Detail: line}})
	return m
}

// warn feeds one stderr line, the way the bridge does for a d.warnErr().
func warn(m StatusModel, line string) StatusModel {
	m, _ = sstep(m, OutputMsg{Line: line, Stderr: true})
	return m
}

// sized gives the model a terminal, since most of the view's behaviour is width- and
// height-dependent.
func sized(m StatusModel, w, h int) StatusModel {
	m, _ = sstep(m, tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

// plain is the view with styling removed. lipgloss decides whether to emit escape sequences from
// the process's own stdout, which a test does not control, so every assertion is made on the text.
func plain(m StatusModel) string { return ansi.Strip(m.View()) }

// sampleReport is a transcription of the lines internal/verbs/status.go emits, one per branch.
//
// IT IS A FIXTURE, NOT A LIVE COUPLING, and that is a deliberate, stated residual: if the verb
// rewords a line, this fixture keeps passing and the classifier goes stale. What that costs is
// bounded by design — an unrecognised line is rendered VERBATIM (TestUnrecognisedLinesAreShown-
// Verbatim), never dropped and never mislabelled — so the failure mode of staleness is a line
// that appears under the "did not recognise" heading instead of in a table. The alternative,
// reaching into a sibling package's source text to extract its format strings, buys a louder
// failure for a test that would break on every legitimate rewording.
var sampleReport = []string{
	"installation: 4f2ab9c1",
	"network:      br-1a2b (mythical-4f2ab9c1, created by this installer)",
	"brokkr: desired=running observed=running outstanding=none next=none",
	"volume mythical-4f2ab9c1-brokkr-data: role=data data=UNREGENERABLE product=brokkr — present, created by this installation",
	"PENDING: volume mythical-4f2ab9c1-saga-data — created and not yet confirmed",
	"unattributed container: someone-elses-thing",
	"note:         the override / force-install annotations could not be read — repair advised.",
	"NETWORK MIGRATION IN PROGRESS — phase 2",
}

// --- classification and completeness --------------------------------------------------------------

// kindSamples is one real report line per kind. The map is REQUIRED to be total: a kind added to
// the classifier with no sample here fails the test below rather than quietly going unrendered.
var kindSamples = map[statusKind]struct {
	line   string
	stderr bool
}{
	kindUnrecognised: {line: "zzunclassifiable line"},
	kindRuntime:      {line: "runtime:      UNAVAILABLE — there is no zzruntime connection, so nothing below can"},
	kindInstallation: {line: "installation: zzident"},
	kindMigration:    {line: "NETWORK MIGRATION IN PROGRESS — phase zzphase"},
	kindProduct:      {line: "zzproduct: desired=running observed=running outstanding=none next=none"},
	kindVolume:       {line: "volume zzvol: role=data data=UNREGENERABLE product=p — present, created by this installation"},
	kindPending:      {line: "PENDING: volume zzpending — created and not yet confirmed"},
	kindUnaccounted:  {line: "unattributed container: zzunaccounted"},
	kindNote:         {line: "note:         zznote could not be read — repair advised."},
	kindDiagnostic:   {line: "ledger: zzdiagnostic", stderr: true},
}

// TestEveryKindIsRendered is the completeness proof this view rests on.
//
// IT DRIVES A LINE OF EVERY KIND THROUGH THE MODEL AND LOOKS FOR IT ON SCREEN. Checking instead
// that every kind appears in the statusSections table proves only that a kind was ASSIGNED a
// heading — it says nothing about whether anything draws it, and the runtime kind is deliberately
// drawn by the banner rather than by the section loop, so a membership check kept passing with
// the banner deleted. Exactly once, too: a kind claimed by two sections would be drawn twice, and
// a report that showed one volume as two rows is its own kind of wrong answer.
func TestEveryKindIsRendered(t *testing.T) {
	for k := statusKind(0); k < kindCount; k++ {
		sample, ok := kindSamples[k]
		if !ok {
			t.Fatalf("kind %d has no sample line: a kind the classifier can produce and this test\n"+
				"  has never seen is a kind nothing here proves is drawn", k)
		}
		if got := classify(sample.line, sample.stderr).kind; got != k {
			t.Fatalf("kind %d's sample %q classifies as %d", k, sample.line, got)
		}
		m := sized(NewStatusModel(nil), 200, 200)
		if sample.stderr {
			m = warn(m, sample.line)
		} else {
			m = say(m, sample.line)
		}
		m, _ = sstep(m, statusDoneMsg{})
		token := distinctToken(t, sample.line)
		if n := strings.Count(plain(m), token); n != 1 {
			t.Fatalf("kind %d: %q appears %d times on screen, want exactly 1 — a line of that kind\n"+
				"  is either not drawn at all or drawn by two sections:\n%s", k, token, n, plain(m))
		}
	}
}

// distinctToken picks the zz-prefixed marker out of a sample line.
func distinctToken(t *testing.T, line string) string {
	t.Helper()
	for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '=' || r == ':' }) {
		if strings.HasPrefix(f, "zz") {
			return f
		}
	}
	t.Fatalf("sample %q carries no zz-marker to look for", line)
	return ""
}

// TestNoKindIsClaimedByTwoSections — the sections table is still checked for a double claim,
// which the rendering test above would only catch for the kinds whose sample lands in both.
func TestNoKindIsClaimedByTwoSections(t *testing.T) {
	seen := map[statusKind]string{}
	for _, sec := range statusSections {
		for _, k := range sec.kinds {
			if prev, dup := seen[k]; dup {
				t.Fatalf("kind %d is claimed by both %q and %q", k, prev, sec.title)
			}
			seen[k] = sec.title
		}
	}
}

// TestTheDiagnosticsAreDrawnAboveTheRefusalsThatPointAtThem. The report writes a warning and then,
// on the next line, a refusal that says "(see the warning above)". A view that gathered the
// warnings into a section BELOW those refusals would make the report's own cross-reference point
// at nothing.
func TestTheDiagnosticsAreDrawnAboveTheRefusalsThatPointAtThem(t *testing.T) {
	m := sized(NewStatusModel(nil), 200, 200)
	m = warn(m, "ledger: the identity record is ambiguous")
	m = say(m, "installation: UNREADABLE — an identity is recorded but could not be read (see the warning")
	m = say(m, "  above). This is NOT 'nothing installed'; objects this installation named may be orphaned.")
	m = warn(m, "prov: the volume could not be inspected")
	m = say(m, "volume v1: role=data data=UNREGENERABLE product=p — provenance NOT established (see above); 'uninstall --purge' will preserve it")
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	warning := strings.Index(v, "ledger: the identity record is ambiguous")
	second := strings.Index(v, "prov: the volume could not be inspected")
	refusal := strings.Index(v, "installation: UNREADABLE")
	volume := strings.Index(v, "UNPROVEN")
	if warning < 0 || second < 0 || refusal < 0 || volume < 0 {
		t.Fatalf("something is missing from:\n%s", v)
	}
	if warning > refusal || second > refusal {
		t.Fatalf("a warning is drawn below the refusal that says to look above it:\n%s", v)
	}
	if warning > volume || second > volume {
		t.Fatalf("a warning is drawn below the volume row that says to look above it:\n%s", v)
	}
	// And they keep the report's own order, so several of them can still be told apart.
	if warning > second {
		t.Fatalf("the warnings are not in the order the report wrote them:\n%s", v)
	}
}

// TestEveryLineOfTheReportIsClassified — none of the report's own lines falls through to the
// verbatim section. The fallback exists for wordings this view has not been taught, not for the
// ones it has.
func TestEveryLineOfTheReportIsClassified(t *testing.T) {
	for _, line := range sampleReport {
		if e := classify(line, false); e.kind == kindUnrecognised {
			t.Errorf("unclassified: %q", line)
		}
	}
}

// TestUnrecognisedLinesAreShownVerbatim. A line this view cannot place must still reach the
// operator, exactly as the report wrote it. Dropping it would turn a fact into an absence.
func TestUnrecognisedLinesAreShownVerbatim(t *testing.T) {
	m := say(NewStatusModel(nil), "something the report says that this view has never seen")
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	if !strings.Contains(v, "something the report says that this view has never seen") {
		t.Fatalf("the line is not on screen:\n%s", v)
	}
	if !strings.Contains(v, "DID NOT RECOGNISE") {
		t.Fatalf("the line is shown without saying it was not understood:\n%s", v)
	}
}

// TestContinuationLinesStayWithTheirHead. The report puts the headline on the first line and the
// REASON on the indented ones; a view that kept heads and dropped continuations would print
// every refusal with its explanation removed.
func TestContinuationLinesStayWithTheirHead(t *testing.T) {
	m := NewStatusModel(nil)
	m = say(m, "installation: UNREADABLE — an identity is recorded but could not be read (see the warning")
	m = say(m, "  above). This is NOT 'nothing installed'; objects this installation named may be orphaned.")
	m = say(m, "  Run 'mythical-ctl state repair'.")
	if m.Entries() != 1 {
		t.Fatalf("the continuations became %d separate entries", m.Entries())
	}
	v := plain(m)
	for _, want := range []string{"This is NOT 'nothing installed'", "Run 'mythical-ctl state repair'."} {
		if !strings.Contains(v, want) {
			t.Fatalf("the reason %q is not on screen:\n%s", want, v)
		}
	}
}

// TestAContinuationAttachesOnlyWithinItsOwnStream — the two streams interleave, and an indented
// line continues the entry above it ONLY if that entry came from the same stream. Both
// directions are asserted, because the guard is one condition and either direction alone leaves
// it half-tested: a report line must not adopt a warning's second line, and a warning must not
// adopt an indented report line filed under a different section.
func TestAContinuationAttachesOnlyWithinItsOwnStream(t *testing.T) {
	// A warning's own second line goes to the warning, not to the report line before it.
	m := NewStatusModel(nil)
	m = say(m, "installation: 4f2ab9c1")
	m = warn(m, "ledger: the records could not be read")
	m = warn(m, "  Run 'mythical-ctl state repair'.")
	if m.Entries() != 2 {
		t.Fatalf("entries: %d, want 2 (one report line, one warning with its continuation)", m.Entries())
	}
	if got := m.entries[0].cont; len(got) != 0 {
		t.Fatalf("the warning's continuation was adopted by the report line: %q", got)
	}
	if got := m.entries[1].cont; len(got) != 1 {
		t.Fatalf("the warning lost its own continuation: %q", got)
	}

	// And the other way: an indented REPORT line arriving after a warning is its own entry. The
	// warning is filed under the diagnostics and the report line is not; folding one into the
	// other would move a report line into a section it does not belong to, and hide it there.
	m2 := NewStatusModel(nil)
	m2 = warn(m2, "ledger: the records could not be read")
	m2 = say(m2, "  an indented line the report wrote")
	if m2.Entries() != 2 {
		t.Fatalf("entries: %d, want 2 — an indented report line was adopted by a warning", m2.Entries())
	}
	if got := m2.entries[0].cont; len(got) != 0 {
		t.Fatalf("the warning adopted a line from the other stream: %q", got)
	}
	if m2.entries[1].stderr {
		t.Fatal("the report line was filed as a diagnostic")
	}
}

// TestAnIndentedFirstLineIsNotDropped. There is nothing above it to continue; it must still be
// shown rather than discarded for having no head.
func TestAnIndentedFirstLineIsNotDropped(t *testing.T) {
	m := say(NewStatusModel(nil), "  an indented line with nothing above it")
	if m.Entries() != 1 {
		t.Fatalf("entries: %d", m.Entries())
	}
	if v := plain(m); !strings.Contains(v, "an indented line with nothing above it") {
		t.Fatalf("dropped:\n%s", v)
	}
}

// TestEveryIngestedLineReachesTheView is the end-to-end form of the completeness property: every
// line fed in is readable on screen, either verbatim or — for the lines this view lays out as a
// table — with every field the LINE carried.
//
// IT CHECKS THE LINE'S OWN CAPTURES, NOT THE STRUCT'S FIELDS. Checking the fields the row type
// happens to keep is circular: a capture dropped on the way into the struct is then dropped from
// the assertion too, and the test passes while the fact is gone from the screen. That is exactly
// how the volume's `product=` was lost — including the `product=?` the report prints precisely so
// that an unattributable volume cannot hide.
func TestEveryIngestedLineReachesTheView(t *testing.T) {
	m := NewStatusModel(nil)
	for _, l := range sampleReport {
		m = say(m, l)
	}
	m = say(m, "  installed with --force-install (the manifest said not launched)")
	// EVERY FIELD A DISTINCT TOKEN. With the realistic lines alone, a dropped capture goes
	// unnoticed because its value occurs somewhere else on screen anyway — a volume's
	// `product=brokkr` is satisfied by the product table's own "brokkr" row, and a plan of "none"
	// by an outstanding of "none". Three separate dropped-field mutations survived on exactly
	// that coincidence before these two lines were added.
	m = say(m, "zzprod: desired=zzdesired observed=zzobserved outstanding=zzoutstanding next=zznext plan")
	m = say(m, "volume zzvolname: role=zzrole data=zzdata class product=zzproduct — recorded but GONE from the runtime")
	m = warn(m, "ledger: something went wrong")
	m = say(m, "a line no classifier knows")
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	for _, e := range m.entries {
		switch {
		case e.hasProduct:
			for i, capture := range productLineRe.FindStringSubmatch(e.head)[1:] {
				if !strings.Contains(v, capture) {
					t.Errorf("field %d of %q — %q — is not on screen", i+1, e.head, capture)
				}
			}
		case e.hasVolume:
			for i, capture := range volumeLineRe.FindStringSubmatch(e.head)[1:] {
				// The state phrase is shown as a short token with the phrase itself in the
				// legend beneath the table, so it is checked there rather than in the row.
				if !strings.Contains(v, capture) {
					t.Errorf("field %d of %q — %q — is not on screen", i+1, e.head, capture)
				}
			}
		default:
			if !strings.Contains(v, sanitize(e.head)) {
				t.Errorf("line %q is not on screen", e.head)
			}
		}
		for _, c := range e.cont {
			if !strings.Contains(v, sanitize(c)) {
				t.Errorf("continuation %q is not on screen", c)
			}
		}
	}
	if t.Failed() {
		t.Logf("view:\n%s", v)
	}
}

// --- the broken installation ------------------------------------------------------------------

// unobservableReport is what the report produces when the container runtime cannot be reached at
// all: the runtime is named unobservable, and the ledger half is still read and still printed.
var unobservableReport = []string{
	"runtime:      UNAVAILABLE — there is no container runtime connection, so nothing below can",
	"  be observed. Live answers are reported as unknown rather than invented.",
	"installation: 4f2ab9c1",
	"network:      br-1a2b (mythical-4f2ab9c1, created by this installer)",
	"brokkr: desired=running observed=(unknown) outstanding=none next=?",
	"volume mythical-4f2ab9c1-brokkr-data: role=data data=UNREGENERABLE product=brokkr — recorded but GONE from the runtime",
}

// TestABrokenRuntimeStillShowsTheLedgerHalf. This is the defect Task 23 fixed, guarded at the
// presentation layer: status is the one diagnostic a broken installation can run, and a
// dashboard that went blank — or that showed only the refusal — would take it away again.
func TestABrokenRuntimeStillShowsTheLedgerHalf(t *testing.T) {
	m := sized(NewStatusModel(nil), 120, 40)
	for _, l := range unobservableReport {
		m = say(m, l)
	}
	m, _ = sstep(m, statusDoneMsg{})
	if !m.NotObservedLive() {
		t.Fatal("the model did not notice that nothing is observed live")
	}
	v := plain(m)
	if !strings.Contains(v, "NOT OBSERVED LIVE") {
		t.Fatalf("the report is not marked as unobserved:\n%s", v)
	}
	// The ledger half — identity, network, the product row, the volume row — is all still there.
	for _, want := range []string{"4f2ab9c1", "br-1a2b", "brokkr", "INSTALLATION", "PRODUCTS", "VOLUMES"} {
		if !strings.Contains(v, want) {
			t.Fatalf("the ledger half lost %q:\n%s", want, v)
		}
	}
	// And the verb's own words about what could not be observed are reproduced, not paraphrased.
	if !strings.Contains(v, "Live answers are reported as unknown rather than invented.") {
		t.Fatalf("the reason is not on screen:\n%s", v)
	}
}

// TestUnknownColumnsAreLabelledAsNotAnObservation — "(unknown)" and "?" are the verb's words for
// a question that could not be asked. The legend says so, because a column of "(unknown)" that
// looked like a measured value is the reassuring misreading.
func TestUnknownColumnsAreLabelledAsNotAnObservation(t *testing.T) {
	m := sized(NewStatusModel(nil), 120, 40)
	m = say(m, "brokkr: desired=running observed=(unknown) outstanding=none next=?")
	v := plain(m)
	if !strings.Contains(v, "not an observation of absence") {
		t.Fatalf("no legend for the unanswered columns:\n%s", v)
	}
	// And it is absent when everything WAS answered — a legend that always shows teaches nothing.
	m2 := sized(NewStatusModel(nil), 120, 40)
	m2 = say(m2, "brokkr: desired=running observed=running outstanding=none next=none")
	if v2 := plain(m2); strings.Contains(v2, "not an observation of absence") {
		t.Fatalf("the legend shows when every column was answered:\n%s", v2)
	}
}

// TestUnreadableIsNotRenderedAsNothingInstalled. The report's own distinction — a recorded
// identity that cannot be READ is not an absent one — must survive on screen.
func TestUnreadableIsNotRenderedAsNothingInstalled(t *testing.T) {
	m := sized(NewStatusModel(nil), 100, 30)
	m = warn(m, "ledger: the identity record is ambiguous")
	m = say(m, "installation: UNREADABLE — an identity is recorded but could not be read (see the warning")
	m = say(m, "  above). This is NOT 'nothing installed'; objects this installation named may be orphaned.")
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	if !strings.Contains(v, "UNREADABLE") {
		t.Fatalf("the refusal is not on screen:\n%s", v)
	}
	if !strings.Contains(v, "ledger: the identity record is ambiguous") {
		t.Fatalf("the warning the report refers to is not on screen:\n%s", v)
	}
	if !strings.Contains(v, "DIAGNOSTICS") {
		t.Fatalf("the warnings are not gathered where the report's 'see above' can find them:\n%s", v)
	}
}

// TestAReportWithNoLinesIsNotShownAsAnEmptyInstallation. The verb always says at least one
// thing, so no lines means the report did not arrive — which must not render as a clean machine.
func TestAReportWithNoLinesIsNotShownAsAnEmptyInstallation(t *testing.T) {
	m := sized(NewStatusModel(nil), 80, 24)
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	if !strings.Contains(v, "The report produced no output.") {
		t.Fatalf("an empty report renders as nothing at all:\n%s", v)
	}
	if strings.TrimSpace(v) == "" {
		t.Fatal("the view is blank")
	}
}

// --- no volume size -------------------------------------------------------------------------

// TestVolumeRowCarriesNoSizeField. The host cannot read a named volume's contents and the
// runtime reports no size for one, so any number would have to be invented — and a table is
// exactly where an empty-looking column invites one. The field set is asserted EXACTLY, so a
// field added for any reason has to come through this test.
func TestVolumeRowCarriesNoSizeField(t *testing.T) {
	want := []string{"Name", "Role", "Data", "Product", "State"}
	rt := reflect.TypeOf(volumeRow{})
	var got []string
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, rt.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("volumeRow fields are %v, want exactly %v.\n"+
			"  A volume's SIZE is not among the facts this report has: the host cannot read a named\n"+
			"  volume's contents and the runtime reports no size for one, so any number here would\n"+
			"  have to be invented or obtained by starting a container — and status starts nothing.", got, want)
	}
}

// sizeish matches anything that would read as a volume size in a report an operator consults
// before deciding whether to purge.
var sizeish = regexp.MustCompile(`(?i)\bsize\b|\bbytes\b|\b[0-9.]+\s?(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)\b`)

// headerOf returns the fields of the table header line containing the given column name.
func headerOf(t *testing.T, view, col string) []string {
	t.Helper()
	for _, line := range strings.Split(view, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == col {
			return f
		}
	}
	t.Fatalf("no table header starting with %q in:\n%s", col, view)
	return nil
}

// TestEachTableNamesExactlyTheFactsTheReportGives. The column set is the contract: every field
// the report's line carries has a heading, nothing else does, and a value therefore never appears
// under a neighbouring column's name. A heading dropped from the header does not shorten the
// table — it shifts every value after it one column left, silently.
func TestEachTableNamesExactlyTheFactsTheReportGives(t *testing.T) {
	m := sized(NewStatusModel(nil), 200, 60)
	m = say(m, "brokkr: desired=running observed=running outstanding=none next=none")
	m = say(m, "volume v1: role=data data=UNREGENERABLE product=brokkr — present, created by this installation")
	v := plain(m)
	if got, want := headerOf(t, v, "PRODUCT"), []string{"PRODUCT", "DESIRED", "OBSERVED", "OUTSTANDING", "NEXT"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("product table columns %v, want %v", got, want)
	}
	if got, want := headerOf(t, v, "VOLUME"), []string{"VOLUME", "ROLE", "DATA", "PRODUCT", "STATE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("volume table columns %v, want %v.\n"+
			"  A volume has no SIZE among these facts, and every fact it does have must have a\n"+
			"  heading of its own or its value is drawn under the next column's name.", got, want)
	}
}

// TestEachTableDrawsEveryValueUnderItsOwnHeading. Naming the columns is only half the contract:
// the values have to line up with them. Two row cells swapped leaves both the header check and
// the every-capture-is-on-screen check passing while the report reads wrong — a role shown as a
// data class, a desired state shown as an observed one.
func TestEachTableDrawsEveryValueUnderItsOwnHeading(t *testing.T) {
	m := sized(NewStatusModel(nil), 200, 60)
	m = say(m, "zzprod: desired=zzdesired observed=zzobserved outstanding=zzoutstanding next=zznext")
	m = say(m, "volume zzname: role=zzrole data=zzdata product=zzproduct — present, created by this installation")
	v := plain(m)
	for _, c := range []struct {
		first string
		head  []string
		row   []string
	}{
		{"PRODUCT", []string{"PRODUCT", "DESIRED", "OBSERVED", "OUTSTANDING", "NEXT"},
			[]string{"zzprod", "zzdesired", "zzobserved", "zzoutstanding", "zznext"}},
		{"VOLUME", []string{"VOLUME", "ROLE", "DATA", "PRODUCT", "STATE"},
			[]string{"zzname", "zzrole", "zzdata", "zzproduct", "present"}},
	} {
		head := headerOf(t, v, c.first)
		row := rowStartingWith(t, v, c.row[0])
		if !reflect.DeepEqual(head, c.head) {
			t.Fatalf("%s header %v, want %v", c.first, head, c.head)
		}
		if len(row) != len(head) {
			t.Fatalf("%s row %v has %d cells under %d headings", c.first, row, len(row), len(head))
		}
		for i := range head {
			if row[i] != c.row[i] {
				t.Fatalf("under heading %q the row shows %q, want %q — the cells and the headings\n"+
					"  are not in the same order:\n    %v\n    %v", head[i], row[i], c.row[i], head, row)
			}
		}
	}
}

// rowStartingWith returns the fields of the table row whose first cell is the given value.
func rowStartingWith(t *testing.T, view, first string) []string {
	t.Helper()
	for _, line := range strings.Split(view, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == first {
			return f
		}
	}
	t.Fatalf("no table row starting with %q in:\n%s", first, view)
	return nil
}

// TestNoHeightOverflowsTheTerminalAtAnyScrollPosition.
//
// AT EVERY HEIGHT AND EVERY SCROLL POSITION, not just at the top. The view draws no more rows than
// the terminal has, and it is never entirely blank. Checking only the opening view misses both of
// the ways a short terminal goes wrong: the opening view is the one that carries the title, so it
// is never blank by accident, and the report has blank lines between its sections that a one-row
// viewport can land squarely on.
func TestNoHeightOverflowsTheTerminalAtAnyScrollPosition(t *testing.T) {
	for h := 1; h <= 20; h++ {
		m := narrowReport(100)
		m = sized(m, 100, h)
		total := len(m.render())
		for off := 0; off <= total+2; off++ {
			m.offset = off
			m = m.clamp()
			v := m.View()
			if got := len(strings.Split(v, "\n")); got > h {
				t.Fatalf("height %d offset %d: the view drew %d rows", h, off, got)
			}
			if strings.TrimSpace(ansi.Strip(v)) == "" {
				t.Fatalf("height %d offset %d: the view is entirely blank — a dashboard showing\n"+
					"  nothing is how 'could not be read' must never be rendered", h, off)
			}
		}
	}
}

// TestTheReportDoesNotOpenWithABlankLine. A separator belongs BETWEEN sections; one before the
// first is a row of nothing at the top of every viewport, and on a short terminal it is the whole
// viewport. The blank-run correction hides it — which is exactly why it needs its own assertion.
func TestTheReportDoesNotOpenWithABlankLine(t *testing.T) {
	for _, m := range []StatusModel{
		narrowReport(100),
		func() StatusModel {
			m := sized(NewStatusModel(nil), 100, 40)
			m = say(m, "installation: zzident")
			m, _ = sstep(m, statusDoneMsg{})
			return m
		}(),
	} {
		lines := m.render()
		if len(lines) == 0 {
			t.Fatal("no report")
		}
		if blank(lines[0]) {
			t.Fatalf("the report opens with a blank line:\n%q", lines[:min(4, len(lines))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestTheStoredOffsetAlwaysShowsSomething. The offset the MODEL holds — not merely the one the
// renderer corrects to — must be a position that shows something. Letting the two differ is what
// made keystrokes inert, and a correction that lives only in the renderer hides every mutation to
// the ones that move the stored offset.
func TestTheStoredOffsetAlwaysShowsSomething(t *testing.T) {
	check := func(t *testing.T, m StatusModel, what string) {
		t.Helper()
		body := m.body()
		if body == 0 {
			return
		}
		if windowBlank(m.render(), m.Offset(), body) {
			t.Fatalf("%s: the stored offset %d shows nothing", what, m.Offset())
		}
		// AND IT IS A POSITION THE MODEL AGREES EXISTS. An offset past its own maximum is one the
		// scroll loop reads as "nowhere further to go", so the next press moves backwards.
		if m.Offset() > m.maxOffset() {
			t.Fatalf("%s: the stored offset %d is past the last position %d", what, m.Offset(), m.maxOffset())
		}
	}
	// TWO REPORT SHAPES, and the second is the one that took a round of review to find. A blank
	// run followed by a FINAL non-blank line puts the nearest visible line past the last legal
	// offset, and a correction that did not clamp stored it there — a position the model itself
	// considers to be beyond its own end.
	shapes := map[string][]string{
		"a blank tail": {
			"installation: zzident", "unattributed container: zzthing",
			"zzfirst unclassifiable", "", "", "", "", "zzlast unclassifiable", "", "",
		},
		"a blank run before the last line": {
			"installation: zzident", "unattributed container: zzthing",
			"zzfirst unclassifiable", "", "", "", "", "zzlast unclassifiable",
		},
	}
	for shape, lines := range shapes {
		for _, h := range []int{1, 2, 3, 4, 5, 6, 7} {
			m := sized(NewStatusModel(nil), 100, h)
			for _, l := range lines {
				m = say(m, l)
			}
			m, _ = sstep(m, statusDoneMsg{})
			check(t, m, fmt.Sprintf("%s, height %d, opening", shape, h))
			m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyEnd})
			check(t, m, fmt.Sprintf("%s, height %d, after End", shape, h))
			m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyHome})
			check(t, m, fmt.Sprintf("%s, height %d, after Home", shape, h))
			for i := 0; i < 30; i++ {
				m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyDown})
				check(t, m, fmt.Sprintf("%s, height %d, down %d", shape, h, i+1))
			}
			for i := 0; i < 30; i++ {
				m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyUp})
				check(t, m, fmt.Sprintf("%s, height %d, up %d", shape, h, i+1))
			}
			// A RESIZE can strand it too, and that is the path the keys do not cover: an offset whose
			// window shows plenty at seven rows can show one blank line at one row, and the terminal
			// changes size without the operator pressing anything.
			for k := range m.render() {
				shrunk := m
				shrunk.offset = k
				check(t, sized(shrunk, 100, 1), fmt.Sprintf("%s, height %d, offset %d resized to one row", shape, h, k))
				check(t, sized(shrunk, 40, 3), fmt.Sprintf("%s, height %d, offset %d resized to three rows", shape, h, k))
			}
		}
	}
}

// TestAReportGrowingUnderTheViewportKeepsTheStoredOffsetHonest.
//
// A line does not simply append to the end of what is on screen. The sections are laid out in a
// fixed order, so a warning arriving late inserts rows ABOVE everything but the banner and pushes
// every later line down — and an offset that showed a heading a moment ago is then pointing at a
// separator. This is the one path that does not go through a key or a resize, so it was the one
// place the stored and the drawn offset could still part company.
func TestAReportGrowingUnderTheViewportKeepsTheStoredOffsetHonest(t *testing.T) {
	for _, h := range []int{1, 2, 4} {
		m := sized(NewStatusModel(nil), 100, h)
		m = say(m, "installation: zzident")
		m = say(m, "unattributed container: zzthing")
		m = say(m, "zztail unclassifiable")
		// The operator scrolls while the report is still arriving.
		for i := 0; i < 4; i++ {
			m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyDown})
		}
		for i := 0; i < 8; i++ {
			// A warning is filed FIRST, so every one of these inserts rows above where the
			// viewport is sitting.
			m = warn(m, fmt.Sprintf("ledger: zzwarning %d", i))
			if body := m.body(); body > 0 {
				if windowBlank(m.render(), m.Offset(), body) {
					t.Fatalf("height %d, after %d late warnings: the stored offset %d shows nothing",
						h, i+1, m.Offset())
				}
				if m.Offset() > m.maxOffset() {
					t.Fatalf("height %d, after %d late warnings: the stored offset %d is past the\n"+
						"  last position %d", h, i+1, m.Offset(), m.maxOffset())
				}
			}
		}
	}
}

// TestNoScrollKeystrokeIsInert. A key the operator presses must move the report, every time,
// until there is no more report to move. The failure this pins is subtle and reads as a frozen
// dashboard: the correction that keeps a viewport off a blank run used to be applied when
// RENDERING and thrown away, so the stored offset lagged behind the drawn one and the first press
// or two only caught it up while the screen sat still.
func TestNoScrollKeystrokeIsInert(t *testing.T) {
	fixtures := map[string]func(int) StatusModel{
		"a report of every shape": func(h int) StatusModel { return sized(narrowReport(100), 100, h) },
		// A report ending in blank lines is the awkward one: the last index is not the last
		// position the viewport settles at, and a maximum that ignored that left one dead press
		// at the bottom.
		"a report with a blank tail": func(h int) StatusModel {
			m := sized(NewStatusModel(nil), 100, h)
			m = say(m, "installation: zzident")
			m = say(m, "unattributed container: zzthing")
			m = say(m, "  a continuation of it")
			m = say(m, "")
			m = say(m, "")
			m, _ = sstep(m, statusDoneMsg{})
			return m
		},
	}
	for name, build := range fixtures {
		for _, h := range []int{1, 2, 3, 5, 9} {
			runInertScrollCase(t, name, h, build(h))
		}
	}
}

func runInertScrollCase(t *testing.T, name string, h int, m StatusModel) {
	t.Helper()
	{
		m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyHome})
		seen := plain(m)
		for press := 0; press < 200; press++ {
			at := m.Offset()
			if at >= m.maxOffset() {
				break
			}
			next, _ := sstep(m, tea.KeyMsg{Type: tea.KeyDown})
			if v := plain(next); v == seen {
				t.Fatalf("%s, height %d, press %d at offset %d (max %d): the screen did not move",
					name, h, press+1, at, m.maxOffset())
			} else {
				seen = v
			}
			if next.Offset() <= at {
				t.Fatalf("%s, height %d, press %d: the offset went from %d to %d", name, h, press+1, at, next.Offset())
			}
			m = next
		}
		// And back up again, the same way.
		for press := 0; press < 200; press++ {
			at := m.Offset()
			if at == 0 {
				break
			}
			next, _ := sstep(m, tea.KeyMsg{Type: tea.KeyUp})
			if next.Offset() >= at {
				t.Fatalf("%s, height %d: scrolling up from offset %d went to %d — a blank run it\n"+
					"  cannot get past", name, h, at, next.Offset())
			}
			m = next
		}
		if m.Offset() != 0 {
			t.Fatalf("%s, height %d: scrolling up stopped at offset %d", name, h, m.Offset())
		}
		// End lands exactly where "there is nothing further down" is decided, so one more press
		// down from there is legitimately inert and everything before it was not.
		m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyEnd})
		if m.Offset() != m.maxOffset() {
			t.Fatalf("%s, height %d: End went to %d, the last reachable position is %d",
				name, h, m.Offset(), m.maxOffset())
		}
	}
}

// TestAReportEndingInBlankLinesStillShowsSomething. A report line CAN be empty — an error whose
// text ends in a newline is split into a last, empty line — so the end of the laid-out report can
// be blank. Scrolled to the bottom of one on a one-row terminal, the viewport lands on the blank
// and there is nothing after it to move to; it has to look back instead.
func TestAReportEndingInBlankLinesStillShowsSomething(t *testing.T) {
	m := sized(NewStatusModel(nil), 100, 1)
	m = say(m, "installation: zzident")
	m = say(m, "")
	m = say(m, "")
	m, _ = sstep(m, statusDoneMsg{})
	m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyEnd})
	if v := m.View(); strings.TrimSpace(ansi.Strip(v)) == "" {
		t.Fatalf("scrolled to a blank tail, the view shows nothing at all: %q", v)
	}
}

// TestAOneRowTerminalSpendsItsRowOnTheReport. Every row this view spends on ITSELF is a row of
// report the operator does not see, and at one row the title alone filled the whole terminal: a
// dashboard whose entire content was its own name, with the report unreachable behind it. The row
// goes to the report now — its first line is that section's heading, which is where a pager opens
// and is one keystroke from the line under it.
func TestAOneRowTerminalSpendsItsRowOnTheReport(t *testing.T) {
	m := sized(NewStatusModel(nil), 100, 1)
	m = say(m, "installation: zzident")
	m, _ = sstep(m, statusDoneMsg{})
	if v := plain(m); strings.Contains(v, "mythical-ctl status") {
		t.Fatalf("the one row went to the view's own title:\n%q", v)
	}
	// And the report line is ONE keystroke away — the opening row is its section's heading, and
	// the line sits directly under it. "Reachable in a few presses" is what an inert keystroke
	// looks like from the outside, so the count is the assertion.
	m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyDown})
	if v := plain(m); !strings.Contains(v, "zzident") {
		t.Fatalf("one press down and the report line is still not on screen: %q", v)
	}
	// At two rows the footer earns its place back; at three, the title.
	if v := plain(sized(m, 100, 2)); !strings.Contains(v, "closes") || strings.Contains(v, "mythical-ctl status") {
		t.Fatalf("two rows: %q", v)
	}
	if v := plain(sized(m, 100, 3)); !strings.Contains(v, "mythical-ctl status") || !strings.Contains(v, "closes") {
		t.Fatalf("three rows: %q", v)
	}
}

// TestATableWhoseHeaderDoesNotNameEveryCellIsNotDrawn// TestATableWhoseHeaderDoesNotNameEveryCellIsNotDrawn// TestATableWhoseHeaderDoesNotNameEveryCellIsNotDrawn — the fail-safe behind the assertion above:
// a mismatch degrades to the report's own lines rather than to values under wrong headings.
func TestATableWhoseHeaderDoesNotNameEveryCellIsNotDrawn(t *testing.T) {
	tb := table{head: []string{"A", "B"}, rows: []tableRow{{cells: []string{"1", "2", "3"}}}}
	if lines, laidOut := tb.render(80); laidOut {
		t.Fatalf("a table with 2 headings drew a 3-cell row:\n%s", strings.Join(lines, "\n"))
	}
}

// TestTheVolumeTableShowsNoSize — the rendered table, header and rows, carries nothing that
// reads as a size.
func TestTheVolumeTableShowsNoSize(t *testing.T) {
	m := sized(NewStatusModel(nil), 140, 40)
	m = say(m, "volume mythical-4f2ab9c1-brokkr-data: role=data data=UNREGENERABLE product=brokkr — present, created by this installation")
	m = say(m, "volume mythical-4f2ab9c1-saga-cache: role=cache data=regenerable product=saga — recorded but GONE from the runtime")
	m, _ = sstep(m, statusDoneMsg{})
	for _, line := range strings.Split(plain(m), "\n") {
		if sizeish.MatchString(line) {
			t.Fatalf("this line reads as a volume size, which this report does not have: %q", line)
		}
	}
}

// TestVolumeStateUsesTheReportsOwnPhrases — the short token in the column is only ever a
// stand-in for a phrase the report actually wrote, and that phrase is reproduced beneath the
// table so the token never has to be interpreted.
func TestVolumeStateUsesTheReportsOwnPhrases(t *testing.T) {
	m := sized(NewStatusModel(nil), 160, 40)
	m = say(m, "volume v1: role=data data=UNREGENERABLE product=brokkr — recorded but GONE from the runtime")
	v := plain(m)
	if !strings.Contains(v, "GONE") {
		t.Fatalf("no state token:\n%s", v)
	}
	if !strings.Contains(v, "recorded but GONE from the runtime") {
		t.Fatalf("the report's own phrase is not reproduced:\n%s", v)
	}
}

// TestAnUnknownVolumeStateIsNotSqueezedIntoTheTable. If the report's wording changes, this view
// must not label the row with the nearest token it knows — it must show the line as written.
func TestAnUnknownVolumeStateIsNotSqueezedIntoTheTable(t *testing.T) {
	line := "volume v1: role=data data=UNREGENERABLE product=brokkr — some phrase this view has never been taught"
	e := classify(line, false)
	if e.hasVolume {
		t.Fatalf("an unknown state phrase was parsed into a row: %+v", e.volume)
	}
	m := sized(NewStatusModel(nil), 160, 40)
	m = say(m, line)
	if v := plain(m); !strings.Contains(v, "some phrase this view has never been taught") {
		t.Fatalf("the line is not shown as written:\n%s", v)
	}
}

// --- parsing --------------------------------------------------------------------------------

// TestAPlanWithASpaceIsStillATableRow. "start verify" is a plan, and it is the plan on the row
// an operator most wants to see; a pattern that assumed plans have no spaces would push exactly
// that row out of the table.
func TestAPlanWithASpaceIsStillATableRow(t *testing.T) {
	e := classify("brokkr: desired=running observed=stopped outstanding=alias next=start verify", false)
	if !e.hasProduct {
		t.Fatal("the row did not parse")
	}
	if e.product.Next != "start verify" {
		t.Fatalf("next=%q", e.product.Next)
	}
}

// TestADataClassWithASpaceIsStillATableRow. "UNREGENERABLE (unclassified)" is the data class of
// a volume whose record does not say — the one that must never read as regenerable.
func TestADataClassWithASpaceIsStillATableRow(t *testing.T) {
	e := classify("volume v1: role=data data=UNREGENERABLE (unclassified) product=brokkr — present, created by this installation", false)
	if !e.hasVolume {
		t.Fatal("the row did not parse")
	}
	if e.volume.Data != "UNREGENERABLE (unclassified)" {
		t.Fatalf("data=%q", e.volume.Data)
	}
	if e.volume.Role != "data" || e.volume.Name != "v1" {
		t.Fatalf("row: %+v", e.volume)
	}
}

// TestTheUnreadableHeadlinesAreNotMistakenForRows — "products: UNREADABLE" and "volume:
// UNREADABLE" are refusals, not records, and they must reach their sections as text.
func TestTheUnreadableHeadlinesAreNotMistakenForRows(t *testing.T) {
	for line, want := range map[string]statusKind{
		"products:     UNREADABLE — the installed-object records could not be fully read, so this":          kindProduct,
		"product:      UNREADABLE — an installed-container record carries no name. Run 'mythical-ctl":       kindProduct,
		"volume:       UNREADABLE — a volume record carries no name. Run 'mythical-ctl state repair'.":      kindVolume,
		"PENDING:      UNREADABLE — the intent records could not be read. Run 'mythical-ctl state repair'.": kindPending,
		"UNACCOUNTED SCAN INCOMPLETE — the container listing could not be asked for, so nothing here":       kindUnaccounted,
	} {
		e := classify(line, false)
		if e.kind != want {
			t.Errorf("%q classified %d, want %d", line, e.kind, want)
		}
		if e.hasProduct || e.hasVolume {
			t.Errorf("%q was parsed as a table row", line)
		}
	}
}

// --- width, truncation, sanitising ---------------------------------------------------------------

// TestANarrowTerminalTruncatesAndSaysSo. Cutting a cell is acceptable; cutting it silently is
// not — the operator is told, and told which invocation prints the report whole.
func TestANarrowTerminalTruncatesAndSaysSo(t *testing.T) {
	m := sized(NewStatusModel(nil), 40, 40)
	m = say(m, "a-very-long-product-name-indeed: desired=running observed=running outstanding=alias,alias,alias next=start verify")
	v := plain(m)
	if !strings.Contains(v, "truncated") {
		t.Fatalf("a truncated table does not say so:\n%s", v)
	}
	// The notice is prose and wraps like prose, so the flag can land across a line break at this
	// width; what matters is that it is there to be read.
	if !strings.Contains(strings.Join(strings.Fields(v), ""), "--plain") {
		t.Fatalf("the truncated table does not name the way to see it whole:\n%s", v)
	}
	for _, line := range strings.Split(v, "\n") {
		if w := ansi.StringWidth(line); w > 40 {
			t.Fatalf("line is %d cells wide in a 40-cell terminal: %q", w, line)
		}
	}
}

// TestAWideTerminalDoesNotClaimTruncation — the notice means something only if it is absent when
// nothing was cut.
func TestAWideTerminalDoesNotClaimTruncation(t *testing.T) {
	m := sized(NewStatusModel(nil), 200, 40)
	m = say(m, "brokkr: desired=running observed=running outstanding=none next=none")
	if v := plain(m); strings.Contains(v, "truncated") {
		t.Fatalf("truncation claimed where nothing was cut:\n%s", v)
	}
}

// TestWidthIsMeasuredInTheUnitItIsCutIn. A name of wide runes occupies two cells each; measuring
// in runes and cutting in cells (or the reverse) is how one row overflows a table every other row
// fits in.
func TestWidthIsMeasuredInTheUnitItIsCutIn(t *testing.T) {
	m := sized(NewStatusModel(nil), 48, 40)
	m = say(m, "volume 名前名前名前名前名前名前名前: role=data data=UNREGENERABLE product=brokkr — present, created by this installation")
	for _, line := range strings.Split(plain(m), "\n") {
		if w := ansi.StringWidth(line); w > 48 {
			t.Fatalf("line is %d cells wide in a 48-cell terminal: %q", w, line)
		}
	}
}

// TestColumnsStartAtTheSameCellInEveryRow. Padding is counted in the same unit the widths are —
// terminal cells. Counted in bytes, a row with a multibyte cell is padded short and every column
// after it slides left, so a value can be read under a neighbouring column's heading.
func TestColumnsStartAtTheSameCellInEveryRow(t *testing.T) {
	widths := []int{10, 6}
	ascii := padRow([]string{"abc", "xx"}, widths, 2)
	wide := padRow([]string{"名前名", "yy"}, widths, 2)
	at := func(row, cell string) int {
		i := strings.Index(row, cell)
		if i < 0 {
			t.Fatalf("%q is not in %q", cell, row)
		}
		return ansi.StringWidth(row[:i])
	}
	if got, want := at(wide, "yy"), at(ascii, "xx"); got != want {
		t.Fatalf("the second column starts at cell %d on a row with wide runes and cell %d on an\n"+
			"  ASCII row — the columns do not line up:\n  %q\n  %q", got, want, ascii, wide)
	}
}

// TestControlCharactersNeverReachTheDrawnFrame. A ledger record's fields end up in this table; an
// escape sequence or a bidi override in one of them can make a refusing line render as a
// reassuring one INSIDE THE PANE, or corrupt the whole rendering.
//
// THE FRAME, NOT "THE SCREEN" — the name matters. runStatus replays the report to the real
// streams byte-for-byte when the dashboard closes, exactly as --plain and a pipe and the frozen
// shell original deliver it, so control bytes in the report's own text do reach the terminal
// there. This test does not and cannot cover that path; the reasoning for leaving it byte-exact
// is at the Flush call in status.go.
func TestControlCharactersNeverReachTheDrawnFrame(t *testing.T) {
	m := sized(NewStatusModel(nil), 200, 60)
	// One in a table cell and one in prose, because they are laid out by different code and a
	// sanitiser applied to only one of them would leave the other open.
	m = say(m, "volume v\x1b[31m1\u202e: role=data data=UNREGENERABLE product=brokkr — present, created by this installation")
	m = say(m, "an unrecognised line with \x1b]0;title\x07 in it")

	// ASSERTED ON THE RAW VIEW, NOT ON A STRIPPED ONE. Stripping escape sequences and then
	// checking that none is present tests the stripper, not the view; the sequence the operator's
	// terminal would act on is the one in View()'s own bytes.
	v := m.View()
	// The escape INTRODUCER is what a terminal acts on; the printable tail of a broken sequence
	// ("[31m") is just text once the ESC is gone, which is exactly what sanitising achieves.
	for _, bad := range []string{"\x1b]", "\x1b[31m", "\x07", "\u202e"} {
		if strings.Contains(v, bad) {
			t.Fatalf("%q reached the screen:\n%q", bad, v)
		}
	}
	// Replaced, not deleted: a rune silently dropped would make a name render as a different,
	// legitimate-looking name.
	if n := strings.Count(v, "\ufffd"); n != 4 {
		t.Fatalf("%d replacement runes on screen, want 4 (ESC and RLO in the cell, ESC and BEL in\n"+
			"  the prose) — the offending runes were dropped rather than shown as replaced:\n%s", n, plain(m))
	}
}

// TestATerminalTooNarrowForTheTableStillShowsEveryRow. Below the width at which the columns can
// all reach their minimum, no table is drawn: the rows are shown as the report wrote them, and
// prose wraps, so every fact survives however narrow the terminal is. Drawing anyway would put
// rows wider than the terminal on screen, wrapped by the terminal itself in the middle of a
// cell, with nothing to say so.
func TestATerminalTooNarrowForTheTableStillShowsEveryRow(t *testing.T) {
	// All of these are narrower than either table's minimum, so both fall back to the report's
	// own lines and nothing is cut.
	for _, w := range []int{4, 6, 10, 14, 18, 22} {
		m := narrowReport(w)
		// Asserted on the whole laid-out report rather than on the viewport: at these widths it
		// wraps to more lines than any terminal shows, and where the window sits is what the
		// scrolling tests are for. Whitespace is removed because the wrapper hard-breaks tokens
		// here — ugly, and LOSSLESS, which is the trade this report wants.
		flat := strings.Join(strings.Fields(strings.Join(m.render(), "\n")), "")
		// One fact from EVERY section, and each one distinctive enough that another section
		// cannot satisfy it: a bare "brokkr" is also in the volume line's product= field, so a
		// products section that vanished entirely would go unnoticed.
		for _, want := range []string{
			"NOTOBSERVEDLIVE",
			"installation:4f2ab9c1",
			"brokkr:desired=runningobserved=running",
			"volumevol-a:role=datadata=UNREGENERABLE",
			"GONEfromtheruntime",
			"PENDING:volumevol-b",
			"alinenoclassifierknows",
			"ledger:awarning",
		} {
			if !strings.Contains(flat, want) {
				t.Fatalf("width %d: %q is not in the report:\n%s", w, want, strings.Join(m.render(), "\n"))
			}
		}
	}
}

// TestNoWidthOverflowsTheTerminal. Every line the view draws — the title, a heading, a table row,
// a wrapped sentence, the footer — fits the terminal it was told about. A row that overflows is
// wrapped by the terminal in the middle of a cell, which is the one way this view could lose
// something without saying so.
func TestNoWidthOverflowsTheTerminal(t *testing.T) {
	for w := 4; w <= 120; w++ {
		m := narrowReport(w)
		for _, line := range strings.Split(plain(m), "\n") {
			if got := ansi.StringWidth(line); got > w {
				t.Fatalf("width %d: a line is %d cells wide: %q", w, got, line)
			}
		}
		for _, line := range m.render() {
			if got := ansi.StringWidth(ansi.Strip(line)); got > w {
				t.Fatalf("width %d: a laid-out line is %d cells wide: %q", w, got, line)
			}
		}
	}
}

// narrowReport is one small report of every shape, laid out for a terminal w cells wide.
func narrowReport(w int) StatusModel {
	m := sized(NewStatusModel(func() {}), w, 60)
	m = say(m, "runtime:      UNAVAILABLE — there is no container runtime connection, so nothing below can")
	m = say(m, "  be observed. Live answers are reported as unknown rather than invented.")
	m = say(m, "installation: 4f2ab9c1")
	m = say(m, "brokkr: desired=running observed=running outstanding=none next=none")
	m = say(m, "volume vol-a: role=data data=UNREGENERABLE product=brokkr — recorded but GONE from the runtime")
	m = say(m, "PENDING: volume vol-b — created and not yet confirmed")
	m = say(m, "a line no classifier knows")
	m = warn(m, "ledger: a warning")
	m, _ = sstep(m, statusDoneMsg{})
	return m
}

// TestAQuestionReachingTheDashboardIsRefusedRatherThanParked. This view has no overlay because
// the report asks nothing. A request that arrived anyway must be answered — with a refusal —
// rather than dropped, or the verb behind it waits for an answer that can only come when the
// operator closes a dashboard that looks finished.
func TestAQuestionReachingTheDashboardIsRefusedRatherThanParked(t *testing.T) {
	r := NewReply()
	m, _ := sstep(NewStatusModel(nil), ConfirmRequestMsg{Prompt: "destroy everything?", Reply: r})
	select {
	case ok := <-r.C():
		if ok {
			t.Fatal("a question no one was shown was answered yes")
		}
	case <-time.After(time.Second):
		t.Fatal("the question was dropped: the asker is still waiting on an answer that cannot come")
	}
	if v := plain(m); strings.Contains(v, "destroy everything?") {
		t.Fatalf("the question was put on screen by a view that cannot take an answer:\n%s", v)
	}
}

// TestTheViewIsNotWindowedBeforeASizeArrives. Guessing a width would cut the report against a
// number nobody supplied.
func TestTheViewIsNotWindowedBeforeASizeArrives(t *testing.T) {
	m := NewStatusModel(nil)
	for i := 0; i < 100; i++ {
		m = say(m, fmt.Sprintf("a line number %d that no classifier knows", i))
	}
	v := plain(m)
	if !strings.Contains(v, "a line number 99 that no classifier knows") {
		t.Fatalf("the tail was cut without a terminal size to cut it against")
	}
}

// --- scrolling ---------------------------------------------------------------------------------

// TestALongReportIsScrollableAndSaysWhereYouAre. A report that does not fit must never simply
// end: the footer reports the position, so a cut tail is visible as a cut tail.
func TestALongReportIsScrollableAndSaysWhereYouAre(t *testing.T) {
	m := sized(NewStatusModel(nil), 100, 10)
	for i := 0; i < 60; i++ {
		m = say(m, fmt.Sprintf("unclassifiable line %d", i))
	}
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	if !strings.Contains(v, " of ") {
		t.Fatalf("a report that does not fit does not say so:\n%s", v)
	}
	if strings.Contains(v, "unclassifiable line 59") {
		t.Fatalf("the tail is on screen at offset 0 in a 10-line terminal:\n%s", v)
	}
	// End scrolls to the bottom and the tail becomes readable.
	m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyEnd})
	if v := plain(m); !strings.Contains(v, "unclassifiable line 59") {
		t.Fatalf("End did not reach the end of the report:\n%s", v)
	}
	// Home comes back.
	m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyHome})
	if m.Offset() != 0 {
		t.Fatalf("Home left the offset at %d", m.Offset())
	}
	// The viewport never runs past the report.
	for i := 0; i < 200; i++ {
		m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyDown})
	}
	if v := plain(m); !strings.Contains(v, "unclassifiable line 59") {
		t.Fatalf("scrolling past the end lost the report:\n%s", v)
	}
}

// TestAShorterReportDoesNotOpenScrolledPastItsOwnEnd — a refresh that returns fewer lines must
// not leave the viewport indexing the previous report's length.
func TestAShorterReportDoesNotOpenScrolledPastItsOwnEnd(t *testing.T) {
	m := sized(NewStatusModel(nil), 100, 10)
	for i := 0; i < 60; i++ {
		m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: ProgressMsg{Event: verbs.ProgressEvent{Detail: fmt.Sprintf("line %d", i)}}})
	}
	m, _ = sstep(m, tea.KeyMsg{Type: tea.KeyEnd})
	if m.Offset() == 0 {
		t.Fatal("the test did not scroll")
	}
	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: statusStartMsg{}})
	if m.Offset() != 0 {
		t.Fatalf("the new report opened at offset %d", m.Offset())
	}
}

// --- generations ------------------------------------------------------------------------------

// TestARefreshReplacesThePreviousReportRatherThanAppendingToIt. Two runs' lines shown as one
// report is a screen that is wrong in a way the operator cannot see — a stale "present" beside a
// fresh "GONE" for the same volume.
func TestARefreshReplacesThePreviousReportRatherThanAppendingToIt(t *testing.T) {
	m := sized(NewStatusModel(func() {}), 140, 40)
	m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: statusStartMsg{}})
	m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: ProgressMsg{Event: verbs.ProgressEvent{
		Detail: "volume v1: role=data data=UNREGENERABLE product=brokkr — present, created by this installation"}}})
	m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: statusDoneMsg{}})

	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: statusStartMsg{}})
	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: ProgressMsg{Event: verbs.ProgressEvent{
		Detail: "volume v1: role=data data=UNREGENERABLE product=brokkr — recorded but GONE from the runtime"}}})
	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: statusDoneMsg{}})

	if m.Entries() != 1 {
		t.Fatalf("entries: %d — the two runs were shown as one report", m.Entries())
	}
	v := plain(m)
	if !strings.Contains(v, "GONE") {
		t.Fatalf("the fresh answer is missing:\n%s", v)
	}
	if strings.Contains(v, "present, created by this installation") {
		t.Fatalf("the superseded answer is still on screen:\n%s", v)
	}
}

// TestASupersededRunsLinesAreDropped. A late line from the run that has been replaced must not
// be folded into the current report.
func TestASupersededRunsLinesAreDropped(t *testing.T) {
	m := NewStatusModel(func() {})
	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: ProgressMsg{Event: verbs.ProgressEvent{Detail: "fresh"}}})
	m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: ProgressMsg{Event: verbs.ProgressEvent{Detail: "stale"}}})
	if m.Entries() != 1 {
		t.Fatalf("entries: %d", m.Entries())
	}
	if v := plain(m); strings.Contains(v, "stale") {
		t.Fatalf("a superseded run's line is on screen:\n%s", v)
	}
	if m.Generation() != 2 {
		t.Fatalf("generation %d", m.Generation())
	}
}

// TestTheNotObservedBannerIsClearedByARefresh — a runtime that has come back must not keep the
// previous run's banner.
func TestTheNotObservedBannerIsClearedByARefresh(t *testing.T) {
	m := sized(NewStatusModel(func() {}), 120, 40)
	m, _ = sstep(m, statusRunMsg{Gen: 1, Msg: ProgressMsg{Event: verbs.ProgressEvent{
		Detail: "runtime:      UNAVAILABLE — there is no container runtime connection, so nothing below can"}}})
	if !m.NotObservedLive() {
		t.Fatal("the banner did not arm")
	}
	m, _ = sstep(m, statusRunMsg{Gen: 2, Msg: statusStartMsg{}})
	if m.NotObservedLive() {
		t.Fatal("the banner survived the refresh")
	}
}

// --- keys ---------------------------------------------------------------------------------------

// TestTheDashboardDoesNotQuitWhenTheReportFinishes. A report is read, not glimpsed: a model that
// quit with the verb would show the whole dashboard for the few milliseconds a read takes.
func TestTheDashboardDoesNotQuitWhenTheReportFinishes(t *testing.T) {
	m := say(NewStatusModel(nil), "installation: 4f2ab9c1")
	m, cmd := sstep(m, statusDoneMsg{Code: 0})
	if isQuit(cmd) {
		t.Fatal("the dashboard quit when the report finished")
	}
	if m.Quitting() {
		t.Fatal("the dashboard marked itself as quitting")
	}
	if !m.Done() {
		t.Fatal("the dashboard did not record that the report finished")
	}
	if v := plain(m); !strings.Contains(v, "4f2ab9c1") {
		t.Fatalf("the report is not on screen after it finished:\n%s", v)
	}
}

// TestEveryCloseKeyQuits.
func TestEveryCloseKeyQuits(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'q'}},
		{Type: tea.KeyEsc},
		{Type: tea.KeyCtrlC},
	} {
		m, cmd := sstep(sized(NewStatusModel(nil), 80, 24), key)
		if !isQuit(cmd) {
			t.Fatalf("%v did not quit", key)
		}
		if !m.Quitting() {
			t.Fatalf("%v did not mark the model as quitting", key)
		}
		if m.View() != "" {
			t.Fatalf("%v left a frame behind: %q", key, m.View())
		}
	}
}

// TestRefreshAsksTheRunnerAndIsInertWithoutOne.
func TestRefreshAsksTheRunnerAndIsInertWithoutOne(t *testing.T) {
	asked := 0
	m := sized(NewStatusModel(func() { asked++ }), 80, 24)
	_, cmd := sstep(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if cmd == nil {
		t.Fatal("r produced no command")
	}
	cmd()
	if asked != 1 {
		t.Fatalf("the runner was asked %d times", asked)
	}
	// With no runner behind it the key does nothing and the footer does not advertise it.
	m2 := sized(NewStatusModel(nil), 80, 24)
	if _, cmd := sstep(m2, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}}); cmd != nil {
		t.Fatal("r produced a command with no runner to serve it")
	}
	if v := plain(m2); strings.Contains(v, "r refreshes") {
		t.Fatalf("the footer advertises a refresh nothing can serve:\n%s", v)
	}
}

// --- the runner ---------------------------------------------------------------------------------

// fakeStatusProgram drives the StatusModel the way bubbletea would, without a terminal.
type fakeStatusProgram struct {
	msgs   chan tea.Msg
	ctx    context.Context
	cancel context.CancelFunc

	model      StatusModel
	neverStart bool
	// endAfterInit dispatches the start command and then returns, WITHOUT running the message
	// loop — the shape in which "the interface is live" and "the interface is gone" become true
	// at the same moment.
	endAfterInit bool
	runErr       error

	onUpdate func(m StatusModel, p *fakeStatusProgram)

	mu    sync.Mutex
	final StatusModel
}

func newFakeStatusProgram() *fakeStatusProgram {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeStatusProgram{msgs: make(chan tea.Msg, 256), ctx: ctx, cancel: cancel}
}

func (p *fakeStatusProgram) make(m StatusModel) program {
	p.model = m
	return p
}

func (p *fakeStatusProgram) Send(msg tea.Msg) {
	select {
	case <-p.ctx.Done():
	case p.msgs <- msg:
	}
}

func (p *fakeStatusProgram) kill() { p.cancel() }

func (p *fakeStatusProgram) Final() StatusModel {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.final
}

func (p *fakeStatusProgram) Run() (tea.Model, error) {
	defer p.cancel()
	m := p.model
	if p.neverStart {
		return m, p.runErr
	}
	if p.exec(m.Init()) {
		return m, p.runErr
	}
	if p.endAfterInit {
		return m, p.runErr
	}
	for {
		select {
		case <-p.ctx.Done():
			return m, p.runErr
		case msg := <-p.msgs:
			next, cmd := m.Update(msg)
			m = next.(StatusModel)
			p.mu.Lock()
			p.final = m
			p.mu.Unlock()
			if p.onUpdate != nil {
				p.onUpdate(m, p)
			}
			if p.exec(cmd) {
				return m, p.runErr
			}
		}
	}
}

func (p *fakeStatusProgram) exec(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	switch msg := cmd().(type) {
	case nil:
		return false
	case tea.QuitMsg:
		return true
	case tea.BatchMsg:
		quit := false
		for _, c := range msg {
			if p.exec(c) {
				quit = true
			}
		}
		return quit
	default:
		p.Send(msg)
		return false
	}
}

// quitWhenDone closes the dashboard as soon as the report has finished — an operator pressing q.
func quitWhenDone(p *fakeStatusProgram) {
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) {
		if m.Done() {
			p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		}
	}
}

// TestRunStatusReportsTheReportsExitCode — the code is the verb's, taken from the verb, never
// from the model.
func TestRunStatusReportsTheReportsExitCode(t *testing.T) {
	for _, want := range []int{0, 1, 2, 3} {
		p := newFakeStatusProgram()
		quitWhenDone(p)
		d, _, _ := baseDeps()
		code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			return want
		}, p.make, time.Second)
		if err != nil {
			t.Fatalf("code %d: %v", want, err)
		}
		if code != want {
			t.Fatalf("runStatus returned %d, the report returned %d", code, want)
		}
	}
}

// TestRunStatusLeavesTheReportInTheTerminal. The frame is erased on quit; what stays behind must
// be the report itself — the same lines, in the same order, the plain path would have printed.
func TestRunStatusLeavesTheReportInTheTerminal(t *testing.T) {
	p := newFakeStatusProgram()
	quitWhenDone(p)
	d, out, errb := baseDeps()
	_, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "installation: 4f2ab9c1"})
		fmt.Fprintln(d.Stderr, "ledger: a warning")
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "network:      not created yet"})
		return 0
	}, p.make, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "installation: 4f2ab9c1\nnetwork:      not created yet\n" {
		t.Fatalf("stdout record:\n%q", got)
	}
	if got := errb.String(); got != "ledger: a warning\n" {
		t.Fatalf("stderr record:\n%q", got)
	}
}

// TestRunStatusReachesTheDashboard — the report's lines are on screen, not merely recorded.
func TestRunStatusReachesTheDashboard(t *testing.T) {
	p := newFakeStatusProgram()
	quitWhenDone(p)
	d, _, _ := baseDeps()
	if _, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "installation: 4f2ab9c1"})
		return 0
	}, p.make, time.Second); err != nil {
		t.Fatal(err)
	}
	if n := p.Final().Entries(); n != 1 {
		t.Fatalf("the dashboard holds %d entries", n)
	}
}

// TestRunStatusNeverStartedMeansTheReportNeverRan. ErrNotStarted is what tells the dispatcher it
// may run the report plainly; if the report had already run, that fallback would run it twice.
func TestRunStatusNeverStartedMeansTheReportNeverRan(t *testing.T) {
	p := newFakeStatusProgram()
	p.neverStart = true
	p.runErr = errors.New("no terminal")
	ran := 0
	d, _, _ := baseDeps()
	code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		ran++
		return 1
	}, p.make, time.Second)
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("err %v, want ErrNotStarted", err)
	}
	if ran != 0 {
		t.Fatalf("the report ran %d times into an interface that never came up", ran)
	}
	if code != 0 {
		t.Fatalf("code %d — an outcome was reported for a report that never ran", code)
	}
}

// TestTheLaunchDecisionIsMadeExactlyOnceAndTheAnswerAgreesWithIt.
//
// The runtime can end AFTER dispatching the model's start command but BEFORE the goroutine that
// runs the report has been scheduled, and it does not wait for that goroutine. Both "the
// interface is live" and "the interface is gone" are then true at once. Whichever way the
// decision falls, the runner's ANSWER must agree with it: a report that ran reports its own exit
// code and NOT ErrNotStarted, and a report that did not run reports ErrNotStarted and code 0 —
// because ErrNotStarted is exactly what licenses the dispatcher to run it again on the plain
// path. A runner that said "never started" about a report that ran would run it twice; one that
// returned a code for a report that never ran would announce an outcome it never had.
//
// WHAT THIS DOES NOT ASSERT, and why: it does not assert which way the decision falls. The gate
// in runStatus makes it deterministic ONCE Run has returned and barred is set, but a goroutine
// that reaches the gate first legitimately runs; that is a scheduling window, not a coin flip,
// and pinning a distribution is how a test becomes flaky. It was flaky, exactly once in 200
// attempts under -race, before this was written down.
func TestTheLaunchDecisionIsMadeExactlyOnceAndTheAnswerAgreesWithIt(t *testing.T) {
	for i := 0; i < 200; i++ {
		p := newFakeStatusProgram()
		p.endAfterInit = true
		ran := 0
		d, out, _ := baseDeps()
		code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			ran++
			d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "installation: 4f2ab9c1"})
			return 3
		}, p.make, time.Second)
		switch {
		case ran > 1:
			t.Fatalf("attempt %d: the report ran %d times", i, ran)
		case ran == 1:
			if errors.Is(err, ErrNotStarted) {
				t.Fatalf("attempt %d: the report RAN and the runner said it never started — the\n"+
					"  dispatcher would take that as licence to run it a second time", i)
			}
			if code != 3 {
				t.Fatalf("attempt %d: the report returned 3 and the runner returned %d", i, code)
			}
			if !strings.Contains(out.String(), "installation: 4f2ab9c1") {
				t.Fatalf("attempt %d: the report ran and its output reached neither the screen nor\n"+
					"  the terminal: %q", i, out.String())
			}
		default:
			if !errors.Is(err, ErrNotStarted) {
				t.Fatalf("attempt %d: the report never ran and err is %v, not ErrNotStarted", i, err)
			}
			if code != 0 {
				t.Fatalf("attempt %d: code %d for a report that never ran", i, code)
			}
			if out.String() != "" {
				t.Fatalf("attempt %d: a report that never ran left output behind: %q", i, out.String())
			}
		}
	}
}

// TestTheLaunchGateKeepsTheReportOutOfADeadInterface.
//
// THIS IS A STATISTICAL ASSERTION AND SAYS SO, because the thing it measures is a race and there
// is no honest deterministic form of it. When the runtime ends right after dispatching the start
// command, "the interface is live" and "the interface is gone" are true at the same moment; a
// select over the two then picks the live branch essentially always, and the report is launched
// into a program that has already returned. The gate is what turns that into a decision.
//
// MEASURED, on this code, over 500 attempts under -race: with the gate, 5 launched; with the gate
// removed, 500 launched. The threshold below sits an order of magnitude above the first and far
// below the second, which is the only reason a statistical test is defensible here. An earlier
// version of this test asserted ZERO launches and failed roughly once in 200 — the residual
// window in which the goroutine reaches the gate before the teardown sets it is real, and
// pretending otherwise is what made that version flaky.
func TestTheLaunchGateKeepsTheReportOutOfADeadInterface(t *testing.T) {
	const attempts = 300
	// THE CEILING IS DELIBERATELY FAR ABOVE THE MEASURED RATE. A threshold near it would be
	// measuring the scheduler rather than the gate, and would fail a correct implementation on a
	// machine that schedules differently. Measured on this code under -race: 5 of 500 launched
	// with the gate, 500 of 500 with it removed. Half is an enormous margin over the first and
	// still catches the second, which is the only reason a statistical assertion is defensible
	// here at all — what the gate is FOR has no deterministic test, because the two signals it
	// arbitrates become true at the same moment by construction.
	const ceiling = attempts / 2
	launched := 0
	for i := 0; i < attempts; i++ {
		p := newFakeStatusProgram()
		p.endAfterInit = true
		d, _, _ := baseDeps()
		ran := false
		if _, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			ran = true
			return 0
		}, p.make, time.Second); err == nil && !ran {
			t.Fatalf("attempt %d: no error and no run", i)
		}
		if ran {
			launched++
		}
	}
	if launched > ceiling {
		t.Fatalf("%d of %d reports were launched into an interface that had already returned\n"+
			"  (ceiling %d) — the launch gate is not being consulted", launched, attempts, ceiling)
	}
}

// TestRunStatusRefreshRunsTheReportAgain, and the terminal keeps only the LAST COMPLETED run's
// record — a replay of every run's lines would read as one enormous report.
//
// THE HOOK ACTS ONCE PER GENERATION. Acting on every message that finds the model finished is not
// the same thing: the model stays finished until the next run's first message arrives, so a hook
// keyed on "is it done" fires again on the keystroke it just sent and queues a SECOND refresh.
// That started a third run which the quit then tore off, and the assertion below — written when
// the runner replayed whichever run was last — became flaky the moment a torn run stopped
// replacing a completed one.
func TestRunStatusRefreshRunsTheReportAgain(t *testing.T) {
	p := newFakeStatusProgram()
	var mu sync.Mutex
	runs := 0
	acted := map[int]bool{}
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) {
		if !m.Done() || acted[m.Generation()] {
			return
		}
		acted[m.Generation()] = true
		if m.Generation() < 2 {
			p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
			return
		}
		p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	}
	d, out, _ := baseDeps()
	code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		mu.Lock()
		runs++
		n := runs
		mu.Unlock()
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: fmt.Sprintf("run %d", n)})
		return 0
	}, p.make, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n != 2 {
		t.Fatalf("the report ran %d times, want 2 — one refresh, acted on once", n)
	}
	if got := out.String(); got != "run 2\n" {
		t.Fatalf("the terminal kept %q, want only the last completed run's record", got)
	}
}

// TestACancelledRefreshDoesNotReplaceTheReportTheOperatorSaw.
//
// Cancellation makes the report DEGRADE rather than stop: its reads fail, and a failed read is
// rendered "(unknown)" or "UNREADABLE" — the report's words for a question that could NOT BE
// ASKED, not for one that was interrupted. So a run torn off by the dashboard closing must not
// become the record replayed to the terminal: the operator would be left holding a diagnostic
// that reads like a diagnosis. The last run that actually finished is what stays.
func TestACancelledRefreshDoesNotReplaceTheReportTheOperatorSaw(t *testing.T) {
	p := newFakeStatusProgram()
	var mu sync.Mutex
	runs := 0
	secondStarted := make(chan struct{})
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) {
		if !m.Done() {
			return
		}
		// The first report has finished and is on screen. Ask for another one.
		p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	}
	go func() {
		// Close the dashboard once the second run is under way, which is what cancels it.
		<-secondStarted
		p.kill()
	}()
	d, out, _ := baseDeps()
	code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		mu.Lock()
		runs++
		n := runs
		mu.Unlock()
		if n == 1 {
			d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "the whole report"})
			return 0
		}
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "half a report"})
		close(secondStarted)
		<-ctx.Done()
		return 0
	}, p.make, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if got := out.String(); got != "the whole report\n" {
		t.Fatalf("the terminal was left holding %q — a run the dashboard tore off replaced the\n"+
			"  report the operator actually saw", got)
	}
}

// TestACancelledFIRSTReportIsStillPublished — the guard above must not withhold the only report
// there is. Withholding it would leave the runner saying the report never ran, which is exactly
// what licenses the dispatcher to run the whole thing a second time.
func TestACancelledFIRSTReportIsStillPublished(t *testing.T) {
	p := newFakeStatusProgram()
	started := make(chan struct{})
	go func() {
		<-started
		p.kill()
	}()
	d, out, _ := baseDeps()
	code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "as far as it got"})
		close(started)
		<-ctx.Done()
		return 5
	}, p.make, 5*time.Second)
	if errors.Is(err, ErrNotStarted) {
		t.Fatal("a report that ran and was cancelled was reported as never having started — the\n" +
			"  dispatcher would run it a second time")
	}
	if code != 5 {
		t.Fatalf("code %d, want the report's own 5", code)
	}
	if got := out.String(); got != "as far as it got\n" {
		t.Fatalf("the partial report was withheld: %q", got)
	}
}

// TestRunStatusDoesNotRunTheReportAfterTheInterfaceIsGone. A refresh queued at the moment the
// dashboard closes must not start a run with nothing to show it on.
func TestRunStatusDoesNotRunTheReportAfterTheInterfaceIsGone(t *testing.T) {
	p := newFakeStatusProgram()
	var mu sync.Mutex
	runs := 0
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) {
		if !m.Done() {
			return
		}
		// Ask for a refresh and tear the interface down in the same breath.
		p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
		p.kill()
	}
	d, _, _ := baseDeps()
	if _, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		mu.Lock()
		runs++
		mu.Unlock()
		return 0
	}, p.make, time.Second); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the report ran %d times; a refresh outlived the interface", n)
	}
}

// TestRunStatusReleasesAReportBlockedOnAQuestion. status asks nothing today, but the seam it is
// handed is the blocking one; a report that ever asked and was left waiting would hold nothing
// but would never return, and the dashboard would never close.
func TestRunStatusReleasesAReportBlockedOnAQuestion(t *testing.T) {
	p := newFakeStatusProgram()
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) { p.kill() }
	answered := make(chan bool, 1)
	d, _, _ := baseDeps()

	// runStatus is driven from a goroutine and waited on with THIS TEST'S OWN deadline. If it
	// were called inline, a runner that failed to release the blocked report would hang here and
	// the failure would arrive as go test's timeout — a panic naming no cause. The deadline below
	// is what turns that into a sentence.
	type result struct {
		code int
		err  error
	}
	finished := make(chan result, 1)
	go func() {
		code, err := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
			answered <- d.Confirm("really?")
			return 7
		}, p.make, 500*time.Millisecond)
		finished <- result{code, err}
	}()

	select {
	case ok := <-answered:
		if ok {
			t.Fatal("a question nobody could answer was answered yes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the report is still blocked on a question the interface can no longer show — a\n" +
			"  report parked on an unanswerable question never returns and never releases what it holds")
	}
	select {
	case r := <-finished:
		if r.code != 7 {
			t.Fatalf("code %d", r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runStatus never returned after the interface went away")
	}
}

// TestRunStatusReportsAnInterfaceThatOutlivesNothing — a report still in flight when the
// interface goes is waited for and said out loud, rather than leaving a terminal that never
// comes back with nothing to explain it.
func TestRunStatusSaysWhenItIsWaitingForAReportInFlight(t *testing.T) {
	p := newFakeStatusProgram()
	release := make(chan struct{})
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) { p.kill() }
	d, _, errb := baseDeps()
	go func() {
		time.Sleep(150 * time.Millisecond)
		close(release)
	}()
	code, _ := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		d.Progress(verbs.ProgressEvent{Stage: "status", Detail: "working"})
		<-release
		return 0
	}, p.make, 10*time.Millisecond)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errb.String(), "waiting for the report still in flight") {
		t.Fatalf("nothing was said about the wait:\n%q", errb.String())
	}
}
