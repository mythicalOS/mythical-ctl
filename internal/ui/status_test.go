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

// TestEveryKindIsRenderedBySomeSection is the completeness proof this view rests on: a line is
// filed under exactly one kind, and every kind has a section that draws it. A kind that no
// section names would be a line ingested and then silently never shown — which is precisely the
// "nothing shown means could not be read" failure, moved to the last step.
func TestEveryKindIsRenderedBySomeSection(t *testing.T) {
	seen := map[statusKind]string{}
	for _, sec := range statusSections {
		for _, k := range sec.kinds {
			if prev, dup := seen[k]; dup {
				t.Fatalf("kind %d is claimed by both %q and %q", k, prev, sec.title)
			}
			seen[k] = sec.title
		}
	}
	for k := statusKind(0); k < kindCount; k++ {
		if _, ok := seen[k]; !ok {
			t.Fatalf("kind %d is filed by the classifier and drawn by no section — a line of that\n"+
				"kind would be ingested and never shown", k)
		}
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

// TestAWarningsOwnSecondLineDoesNotAttachToAReportLine — the two streams interleave, and an
// indented stderr line must continue the stderr entry above it, not adopt the report line that
// happens to precede it.
func TestAWarningsOwnSecondLineDoesNotAttachToAReportLine(t *testing.T) {
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
// table — as its parsed cells.
func TestEveryIngestedLineReachesTheView(t *testing.T) {
	m := NewStatusModel(nil)
	for _, l := range sampleReport {
		m = say(m, l)
	}
	m = say(m, "  installed with --force-install (the manifest said not launched)")
	m = warn(m, "ledger: something went wrong")
	m = say(m, "a line no classifier knows")
	m, _ = sstep(m, statusDoneMsg{})
	v := plain(m)
	for _, e := range m.entries {
		switch {
		case e.hasProduct:
			p := e.product
			for _, cell := range []string{p.Product, p.Desired, p.Observed, p.Outstanding, p.Next} {
				if !strings.Contains(v, cell) {
					t.Errorf("product cell %q is not on screen", cell)
				}
			}
		case e.hasVolume:
			vol := e.volume
			for _, cell := range []string{vol.Name, vol.Role, vol.Data, vol.State} {
				if !strings.Contains(v, cell) {
					t.Errorf("volume cell %q is not on screen", cell)
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
	want := []string{"Name", "Role", "Data", "State"}
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
	if !strings.Contains(v, "--plain") {
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

// TestControlCharactersNeverReachTheScreen. A ledger record's fields end up in this table; an
// escape sequence or a bidi override in one of them can make a refusing line render as a
// reassuring one.
func TestControlCharactersNeverReachTheScreen(t *testing.T) {
	m := sized(NewStatusModel(nil), 160, 40)
	m = say(m, "volume v\x1b[31m1\u202e: role=data data=UNREGENERABLE product=brokkr — present, created by this installation")
	m = say(m, "an unrecognised line with \x1b]0;title\x07 in it")
	v := m.View()
	for _, bad := range []string{"\x1b", "\u202e", "\x07"} {
		if strings.Contains(ansi.Strip(strings.ReplaceAll(v, "\x1b[0m", "")), bad) {
			t.Fatalf("%q reached the screen:\n%q", bad, v)
		}
	}
	if !strings.Contains(plain(m), "\ufffd") {
		t.Fatalf("the offending runes were dropped rather than shown as replaced:\n%s", plain(m))
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
	runErr     error

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

// TestRunStatusRefreshRunsTheReportAgain, and the terminal keeps only the LAST run's record — a
// replay of every run's lines would read as one enormous report.
func TestRunStatusRefreshRunsTheReportAgain(t *testing.T) {
	p := newFakeStatusProgram()
	var runs int
	var mu sync.Mutex
	p.onUpdate = func(m StatusModel, p *fakeStatusProgram) {
		if !m.Done() {
			return
		}
		mu.Lock()
		n := runs
		mu.Unlock()
		if n < 2 {
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
	}, p.make, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n < 2 {
		t.Fatalf("the report ran %d times; the refresh did not reach the runner", n)
	}
	if got := out.String(); strings.Count(got, "run ") != 1 {
		t.Fatalf("the terminal kept more than the last run's record:\n%q", got)
	}
	if !strings.Contains(out.String(), fmt.Sprintf("run %d", n)) {
		t.Fatalf("the terminal kept a superseded run's record:\n%q", out.String())
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
	code, _ := runStatus(context.Background(), d, func(ctx context.Context, d verbs.Deps) int {
		answered <- d.Confirm("really?")
		return 7
	}, p.make, 2*time.Second)
	select {
	case ok := <-answered:
		if ok {
			t.Fatal("a question nobody could answer was answered yes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the report is still blocked on a question the interface can no longer show")
	}
	if code != 7 {
		t.Fatalf("code %d", code)
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
