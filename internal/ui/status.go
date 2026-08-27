package ui

// The status dashboard.
//
// IT IS A VIEW OF THE REPORT, NOT A SECOND REPORT. Every fact on screen is a line
// verbs.Status produced, reaching this model through the same two seams the plain path uses;
// nothing here reads the ledger, asks the runtime, or decides what is true. That is the only
// arrangement in which the plan's "scripts see no change ever" is structural rather than
// promised: there is one producer of the report and this is a renderer of its output.
//
// THREE PROPERTIES THIS FILE EXISTS TO KEEP, all of them properties the verb had to fight for:
//
//  1. NOTHING SHOWN IS NEVER HOW A REFUSAL IS RENDERED. The verb distinguishes an ANSWER
//     ("absent", "not created yet") from a REFUSAL ("could not be read") in every one of its
//     branches. A classifier that dropped a line it did not recognise would collapse that
//     distinction at the last step, and it would collapse it in the reassuring direction. So
//     every ingested line lands in exactly one section, the section table is asserted to cover
//     every kind, and a line this view cannot classify is rendered VERBATIM rather than
//     discarded. When a parse half-succeeds — a volume line whose state phrase this view has
//     not been taught — the whole line falls back to verbatim rather than being squeezed into
//     a column under a label that might be wrong.
//
//  2. A BROKEN INSTALLATION STILL GETS ITS REPORT. status is the command an operator reaches
//     for when the others are refusing, and it is handed no runtime at all when the endpoint
//     cannot be resolved. The verb renders that as "unobservable"; this view renders the
//     ledger half in full and marks it NOT OBSERVED LIVE. A dashboard that went blank there
//     would put the defect back at the presentation layer.
//
//  3. NO VOLUME SIZE. The host cannot read a named volume's contents and the runtime reports
//     no size for one, so any number would have to be invented or obtained by starting a
//     container — and status starts nothing. A table is exactly where an empty-looking column
//     invites one. There is no size column, volumeRow has no size field, and both facts are
//     asserted rather than left to intent.
//
// TRUNCATION IS MEASURED IN THE UNIT IT IS APPLIED IN. Widths come from ansi.StringWidth and
// cuts from ansi.Truncate — both counting terminal cells over grapheme clusters — so a wide
// rune cannot make a row overflow the column that was measured for it. And truncation is never
// silent: a table that had to cut a cell says so and names the flag that prints the report
// whole.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"mythicalos.ai/ctl/internal/verbs"
)

// --- the report's shape ---------------------------------------------------------------------

// statusKind is which part of the report one line belongs to.
//
// kindUnrecognised is FIRST and is the zero value on purpose: a classifier arm that forgets to
// set a kind falls into the section that renders its line verbatim, which is the harmless
// failure. A zero value that meant "installation" would file an unreadable line under a
// heading that lends it credibility.
type statusKind int

const (
	kindUnrecognised statusKind = iota
	kindRuntime
	kindInstallation
	kindMigration
	kindProduct
	kindVolume
	kindPending
	kindUnaccounted
	kindNote
	kindDiagnostic
	// kindCount bounds the enumeration so the section-coverage test can iterate every kind
	// rather than a list someone has to remember to extend.
	kindCount
)

// productRow is one product's line split into the columns the table draws. Every value is the
// verb's own word — "(unknown)", "(unreadable)", "UNREADABLE", "?" — carried through unchanged,
// because each of them is a distinction the verb makes on purpose.
type productRow struct{ Product, Desired, Observed, Outstanding, Next string }

// volumeRow is one volume's line.
//
// THE FIELD SET IS THE WHOLE CONTRACT AND IT IS ASSERTED. There is no size, and there is no
// field that could become one: see TestVolumeRowCarriesNoSizeField, which fails on any field
// this list does not name.
type volumeRow struct{ Name, Role, Data, State string }

// statusEntry is one line of the report, plus the indented lines that continue it.
//
// THE CONTINUATIONS ARE PART OF THE ENTRY, NOT SEPARATE LINES. The verb puts the headline on
// the first line and the REASON on the indented ones — "this is NOT 'nothing installed'",
// "objects this installation named may be orphaned", "run state repair". A view that rendered
// heads and dropped continuations would print every refusal without its explanation.
type statusEntry struct {
	kind statusKind
	head string
	cont []string
	// stderr records which stream the line came from. It decides both the section a line is
	// filed under and whether an indented line may attach to the entry above it: a warning's
	// own second line must not become a continuation of a report line that happens to precede
	// it on the other stream.
	stderr bool

	// product is the head parsed into columns, valid only when hasProduct. Same for volume.
	product    productRow
	hasProduct bool
	volume     volumeRow
	hasVolume  bool
}

// lines returns the entry's raw text, head first.
func (e statusEntry) lines() []string {
	out := make([]string, 0, 1+len(e.cont))
	out = append(out, e.head)
	out = append(out, e.cont...)
	return out
}

// --- classification -------------------------------------------------------------------------

// productLineRe matches the per-product line: `<product>: desired=… observed=… outstanding=… next=…`.
//
// `next` is matched to END OF LINE rather than as a non-space run because a plan legitimately
// contains a space ("start verify"). A pattern that assumed otherwise would fail to parse the
// single most interesting row in the report — and would then, correctly but uselessly, render
// it verbatim instead of in the table.
var productLineRe = regexp.MustCompile(`^(.*?): desired=(\S+) observed=(\S+) outstanding=(\S+) next=(.+)$`)

// volumeLineRe matches `volume <name>: role=… data=… product=… — <state phrase>`.
//
// `data` is non-greedy because a data class legitimately contains a space
// ("UNREGENERABLE (unclassified)") and the field that follows it is what ends it.
var volumeLineRe = regexp.MustCompile(`^volume (.+?): role=(\S+) data=(.+?) product=(\S+) — (.+)$`)

// volumeStates maps the verb's state phrase to the short token the table shows, EXACTLY.
//
// There is no prefix matching and no fuzzy fallback. A phrase this table does not know is not
// guessed at: the whole line is rendered verbatim instead, so a wording change on the verb's
// side shows up as an unclassified line rather than as a volume silently mislabelled
// "present". The full phrase is reproduced in the legend under the table, in the verb's words,
// so the short token never has to be interpreted.
var volumeStates = map[string]string{
	"present, created by this installation":                                        "present",
	"recorded but GONE from the runtime":                                           "GONE",
	"provenance NOT established (see above); 'uninstall --purge' will preserve it": "UNPROVEN",
}

// volumeStateOrder fixes the legend's order so the view does not depend on map iteration.
var volumeStateOrder = []string{"present", "GONE", "UNPROVEN"}

// classify files one line. It never fails: an unrecognised line becomes an entry that is
// rendered verbatim.
func classify(line string, stderr bool) statusEntry {
	e := statusEntry{head: line, stderr: stderr}
	if stderr {
		// Everything on stderr is a diagnostic the report REFERS TO ("see the warning above").
		// It is kept as one section rather than distributed, so those references resolve.
		e.kind = kindDiagnostic
		return e
	}
	if m := productLineRe.FindStringSubmatch(line); m != nil {
		e.kind, e.hasProduct = kindProduct, true
		e.product = productRow{Product: m[1], Desired: m[2], Observed: m[3], Outstanding: m[4], Next: m[5]}
		return e
	}
	if m := volumeLineRe.FindStringSubmatch(line); m != nil {
		e.kind = kindVolume
		if short, ok := volumeStates[m[5]]; ok {
			e.hasVolume = true
			e.volume = volumeRow{Name: m[1], Role: m[2], Data: m[3], State: short}
		}
		// The product this volume belongs to is already the row's scope in the products table
		// and is repeated in the verbatim line; it is not a column here. When the phrase is
		// unknown, hasVolume stays false and the whole line is rendered as it came.
		return e
	}
	switch {
	case strings.HasPrefix(line, "runtime:"):
		e.kind = kindRuntime
	case strings.HasPrefix(line, "installation:"),
		strings.HasPrefix(line, "No installation state found"),
		strings.HasPrefix(line, "network:"):
		e.kind = kindInstallation
	case strings.HasPrefix(line, "NETWORK MIGRATION"):
		e.kind = kindMigration
	case strings.HasPrefix(line, "products:"), strings.HasPrefix(line, "product:"):
		e.kind = kindProduct
	case strings.HasPrefix(line, "volume:"), strings.HasPrefix(line, "volume "):
		e.kind = kindVolume
	case strings.HasPrefix(line, "PENDING"):
		e.kind = kindPending
	case strings.HasPrefix(line, "unattributed "), strings.HasPrefix(line, "unrecorded "),
		strings.HasPrefix(line, "name collision, "), strings.HasPrefix(line, "UNACCOUNTED SCAN"):
		e.kind = kindUnaccounted
	case strings.HasPrefix(line, "note:"):
		e.kind = kindNote
	}
	return e
}

// --- the model ------------------------------------------------------------------------------

// StatusModel is the dashboard: the report, grouped, scrollable, refreshable.
//
// IT DOES NOT QUIT WHEN THE REPORT FINISHES. A report is something an operator READS; a model
// that ended with the verb would put the whole dashboard on screen for the few milliseconds a
// read takes. It stays up until the operator closes it, and the runner then writes the report
// to the real streams exactly as the plain path would have — so what is left in the terminal
// is the report itself, not a rendering of it.
type StatusModel struct {
	entries []statusEntry

	// notObserved records that the verb said it has no runtime connection. It is set from the
	// verb's OWN line rather than from anything this view infers, and it drives the banner.
	notObserved bool

	// gen is the run whose output is on screen. Messages from an older run are dropped and a
	// newer one clears first — see update.
	gen     int
	running bool
	done    bool
	code    int

	width, height int
	// hasSize distinguishes "the terminal told us its size" from "the size is zero". Before a
	// size arrives the view renders whole: guessing a width would truncate the report against
	// a number nobody supplied.
	hasSize bool
	offset  int

	quitting bool

	// onRefresh asks the runner to run the report again. nil ⇒ there is nothing to refresh and
	// the key is inert rather than advertised.
	onRefresh func()
	// onStart is called from Init, i.e. once the event loop is actually running. The runner
	// uses it as the gate that keeps the verb from being launched into an interface that never
	// came up.
	onStart func()
}

var _ tea.Model = StatusModel{}

// NewStatusModel builds the dashboard. refresh may be nil.
func NewStatusModel(refresh func()) StatusModel {
	return StatusModel{onRefresh: refresh}
}

// withStartHook returns a copy that calls hook from Init — the same copy-returning shape Root
// uses, for the same reason: a model handed to tea.NewProgram is never mutated afterwards.
func (m StatusModel) withStartHook(hook func()) StatusModel {
	m.onStart = hook
	return m
}

// Entries is how many report lines (heads, not continuations) are retained.
func (m StatusModel) Entries() int { return len(m.entries) }

// NotObservedLive reports that the verb said it has no runtime connection.
func (m StatusModel) NotObservedLive() bool { return m.notObserved }

// Done reports that the current run has returned, and Code is what it returned.
func (m StatusModel) Done() bool { return m.done }
func (m StatusModel) Code() int  { return m.code }

// Generation is the run whose output is on screen.
func (m StatusModel) Generation() int { return m.gen }

// Quitting reports whether the model has issued tea.Quit.
func (m StatusModel) Quitting() bool { return m.quitting }

// Offset is the first rendered line the viewport shows.
func (m StatusModel) Offset() int { return m.offset }

// Init announces that the loop is running.
func (m StatusModel) Init() tea.Cmd {
	if m.onStart == nil {
		return nil
	}
	hook := m.onStart
	return func() tea.Msg {
		hook()
		return nil
	}
}

// Update implements tea.Model.
func (m StatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	return next, cmd
}

func (m StatusModel) update(msg tea.Msg) (StatusModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height, m.hasSize = msg.Width, msg.Height, true
		return m.clamp(), nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case statusRunMsg:
		// THE GENERATION GATE. A refresh runs the report again, and the two runs' lines must
		// never be shown as one report: a stale "volume X — present" beside a fresh "volume X
		// — GONE" is a screen that is wrong in a way the operator cannot see. An older run's
		// messages are dropped; a newer run's first message clears what is on screen.
		if msg.Gen < m.gen {
			return m, nil
		}
		if msg.Gen > m.gen {
			m = m.begin(msg.Gen)
		}
		return m.update(msg.Msg)

	case statusStartMsg:
		m.running = true
		return m, nil

	case ProgressMsg:
		// NOT CLAMPED HERE. Clamping asks for maxOffset, which lays the whole report out, and
		// doing that once per ingested line makes a long report quadratic in its own length.
		// It is not needed either: appending lines only ever RAISES the maximum offset, so a
		// position that was valid before the line stays valid after it.
		return m.ingest(msg.Event.Detail, false), nil

	case OutputMsg:
		return m.ingest(msg.Line, msg.Stderr), nil

	case statusDoneMsg:
		m.done, m.code, m.running = true, msg.Code, false
		return m.clamp(), nil

	case ConfirmRequestMsg:
		// REFUSED WITHOUT BEING SHOWN, and refused rather than ignored. This view has no
		// overlay: the report is read-only and asks nothing today. If one ever did, ignoring
		// the request would park it on an answer that can only arrive when the operator closes
		// the dashboard — a report that appears to have finished while the verb behind it is
		// still blocked. Refusing is the same answer an empty stdin gives the plain path.
		msg.Reply.Resolve(false)
		return m, nil
	}
	return m, nil
}

// begin starts a generation: the previous run's lines are dropped as a unit.
func (m StatusModel) begin(gen int) StatusModel {
	m.gen = gen
	m.entries = nil
	m.notObserved = false
	m.done, m.code = false, 0
	m.running = true
	// The scroll position is NOT carried over. It indexes the previous report's lines, and a
	// report that is now shorter would open scrolled past its own end.
	m.offset = 0
	return m
}

// ingest files one line of the report.
func (m StatusModel) ingest(line string, stderr bool) StatusModel {
	// An indented line CONTINUES the one above it, on the same stream. Attaching it is what
	// keeps a refusal's reason with its headline; the same-stream test keeps a warning's second
	// line from being adopted by an unrelated report line.
	if strings.HasPrefix(line, "  ") && len(m.entries) > 0 {
		last := len(m.entries) - 1
		if m.entries[last].stderr == stderr {
			next := make([]statusEntry, len(m.entries))
			copy(next, m.entries)
			e := next[last]
			e.cont = append(append([]string(nil), e.cont...), line)
			next[last] = e
			m.entries = next
			return m
		}
	}
	e := classify(line, stderr)
	if e.kind == kindRuntime && strings.Contains(line, "UNAVAILABLE") {
		m.notObserved = true
	}
	// Copied before growing: the receiver is a value whose slice header is shared with every
	// earlier copy of this model.
	next := make([]statusEntry, 0, len(m.entries)+1)
	next = append(next, m.entries...)
	m.entries = append(next, e)
	return m
	// THERE IS NO CAP HERE, deliberately, and it is not an oversight: the progress pane bounds
	// its transcript because a PULL emits a record per layer per tick, chosen by the registry.
	// A report emits one line per object, once, and is cleared on every refresh. A cap would
	// buy a bounded slice at the cost of a path that drops report lines — the one thing this
	// view must not do.
}

// handleKey is the keymap: scroll, refresh, close.
func (m StatusModel) handleKey(msg tea.KeyMsg) (StatusModel, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q", "esc":
		m.quitting = true
		return m, tea.Quit
	case "r":
		if m.onRefresh == nil {
			return m, nil
		}
		hook := m.onRefresh
		return m, func() tea.Msg {
			hook()
			return nil
		}
	case "up", "k":
		return m.scroll(-1), nil
	case "down", "j":
		return m.scroll(1), nil
	case "pgup":
		return m.scroll(-m.page()), nil
	case "pgdown", " ":
		return m.scroll(m.page()), nil
	case "home", "g":
		m.offset = 0
		return m, nil
	case "end", "G":
		m.offset = m.maxOffset()
		return m, nil
	}
	return m, nil
}

func (m StatusModel) page() int {
	if p := m.body(); p > 1 {
		return p - 1
	}
	return 1
}

func (m StatusModel) scroll(by int) StatusModel {
	m.offset += by
	return m.clamp()
}

func (m StatusModel) clamp() StatusModel {
	if max := m.maxOffset(); m.offset > max {
		m.offset = max
	}
	if m.offset < 0 {
		m.offset = 0
	}
	return m
}

// body is how many lines the viewport shows, the footer excluded. Zero means "no windowing" —
// the size is not known yet, and cutting the report against a guess is worse than a long frame.
func (m StatusModel) body() int {
	if !m.hasSize || m.height <= 1 {
		return 0
	}
	return m.height - 1
}

func (m StatusModel) maxOffset() int {
	body := m.body()
	if body == 0 {
		return 0
	}
	if n := len(m.render()) - body; n > 0 {
		return n
	}
	return 0
}

// --- rendering --------------------------------------------------------------------------------

var (
	titleStyle   = lipgloss.NewStyle().Bold(true)
	headingStyle = lipgloss.NewStyle().Bold(true)
	alarmStyle   = lipgloss.NewStyle().Bold(true)
	dimStyle     = lipgloss.NewStyle().Faint(true)
)

// section is one heading and the kinds filed under it.
//
// THE TABLE IS THE COMPLETENESS PROOF. Every statusKind appears in exactly one section, and
// that is asserted (TestEveryKindIsRenderedBySomeSection) rather than trusted — which is what
// makes "a line this view cannot classify is still shown" a property of the structure instead
// of a promise about the classifier.
var statusSections = []struct {
	title string
	kinds []statusKind
}{
	{"INSTALLATION", []statusKind{kindInstallation}},
	{"NETWORK MIGRATION", []statusKind{kindMigration}},
	{"PRODUCTS", []statusKind{kindProduct, kindNote}},
	{"VOLUMES", []statusKind{kindVolume}},
	{"PENDING", []statusKind{kindPending}},
	{"UNACCOUNTED OBJECTS", []statusKind{kindUnaccounted}},
	{"DIAGNOSTICS — the warnings this report refers to", []statusKind{kindDiagnostic}},
	{"LINES THIS VIEW DID NOT RECOGNISE — shown as the report wrote them", []statusKind{kindUnrecognised}},
	// kindRuntime is rendered by the banner, ABOVE every section, because it is the one fact
	// that qualifies all the others. It is listed here so the coverage assertion sees it.
	{"", []statusKind{kindRuntime}},
}

// View renders the current screen.
func (m StatusModel) View() string {
	if m.quitting {
		// The frame is erased on the way out; the runner then writes the report to the real
		// streams — the same lines, in the same order, the plain path would have printed — so
		// what stays in the terminal is the report, not a windowed pane of it.
		return ""
	}
	lines := m.render()
	body := m.body()
	if body == 0 {
		return strings.Join(lines, "\n")
	}
	off := m.offset
	if max := len(lines) - body; off > max {
		off = max
	}
	if off < 0 {
		off = 0
	}
	end := off + body
	if end > len(lines) {
		end = len(lines)
	}
	window := append([]string(nil), lines[off:end]...)
	for len(window) < body {
		window = append(window, "")
	}
	return strings.Join(append(window, m.footer(len(lines), off, end)), "\n")
}

// footer says where the operator is in the report and what the keys do. IT ALWAYS REPORTS THE
// POSITION when the report does not fit: a view that cut the tail without saying so would be
// the "nothing shown" failure wearing a different hat.
func (m StatusModel) footer(total, off, end int) string {
	keys := "↑/↓ scroll · r refreshes · q closes"
	if m.onRefresh == nil {
		keys = "↑/↓ scroll · q closes"
	}
	line := keys
	if total > m.body() {
		// THE POSITION COMES FIRST so that on a terminal too narrow for the whole footer it is
		// the keymap that is cut, not the fact that there is more report below.
		line = fmt.Sprintf("lines %d-%d of %d · %s", off+1, end, total, keys)
	}
	return dimStyle.Render(fit(line, m.width))
}

// fit cuts one already-composed line to the terminal. It is for the view's OWN furniture — the
// title, the section headings, the footer — none of which is a fact from the report; the report's
// own lines are wrapped instead, because cutting a sentence drops the half that says what to do.
func fit(s string, width int) string {
	if width <= 0 || ansi.StringWidth(s) <= width {
		return s
	}
	return ansi.Truncate(s, width, "…")
}

// render lays the whole report out, unwindowed.
func (m StatusModel) render() []string {
	avail := m.avail()
	width := 0
	if m.hasSize {
		width = m.width
	}
	out := []string{titleStyle.Render(fit("mythical-ctl status", width))}

	if len(m.entries) == 0 {
		if m.done {
			// A REPORT WITH NO LINES IS NOT AN EMPTY INSTALLATION. The verb always says
			// something — at minimum "No installation state found" — so an empty screen here
			// means the report did not reach this view, and saying so is the whole point.
			out = append(out, "")
			out = append(out, styleAll(alarmStyle, wrapAt("The report produced no output.", "", avail))...)
			out = append(out, wrapAt("This is not an empty installation: the report always says at least one thing.", "", avail)...)
			return append(out, wrapAt("Run 'mythical-ctl status --plain' to see what the report writes.", "", avail)...)
		}
		return append(out, wrapAt("reading the installation state…", "", avail)...)
	}

	// The banner first: it qualifies everything below it.
	if runtimeEntries := m.of(kindRuntime); len(runtimeEntries) > 0 {
		out = append(out, "")
		if m.notObserved {
			out = append(out, styleAll(alarmStyle, wrapAt("NOT OBSERVED LIVE", "", avail))...)
		}
		for _, e := range runtimeEntries {
			out = append(out, indentAll(e.lines(), "  ", avail)...)
		}
	}

	for _, sec := range statusSections {
		if sec.title == "" {
			continue
		}
		entries := m.of(sec.kinds...)
		if len(entries) == 0 {
			continue
		}
		out = append(out, "", headingStyle.Render(fit(sec.title, width)))
		out = append(out, m.renderSection(sec.title, entries, avail)...)
	}
	return out
}

// avail is the line budget: the whole terminal. Every layout below deducts its own indent from
// it. Zero means the width is not known, and then nothing is wrapped or cut — guessing a width
// would lay the report out against a number nobody supplied.
func (m StatusModel) avail() int {
	if !m.hasSize || m.width <= 0 {
		return 0
	}
	return m.width
}

// of collects the entries of the given kinds, in the order the report produced them.
func (m StatusModel) of(kinds ...statusKind) []statusEntry {
	var out []statusEntry
	for _, e := range m.entries {
		for _, k := range kinds {
			if e.kind == k {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// renderSection draws one section: its parsed rows as a table, everything else verbatim.
func (m StatusModel) renderSection(title string, entries []statusEntry, avail int) []string {
	switch title {
	case "PRODUCTS":
		return renderProducts(entries, avail)
	case "VOLUMES":
		return renderVolumes(entries, avail)
	}
	return verbatim(entries, avail)
}

// verbatim renders entries as the report wrote them.
func verbatim(entries []statusEntry, avail int) []string {
	var out []string
	for _, e := range entries {
		out = append(out, indentAll(e.lines(), "  ", avail)...)
	}
	return out
}

// renderProducts draws the product table, each row followed by the annotations the report
// attached to it, and then any product line that did not parse — verbatim.
func renderProducts(entries []statusEntry, avail int) []string {
	t := table{head: []string{"PRODUCT", "DESIRED", "OBSERVED", "OUTSTANDING", "NEXT"}}
	var rest []statusEntry
	for _, e := range entries {
		if !e.hasProduct {
			rest = append(rest, e)
			continue
		}
		p := e.product
		t.rows = append(t.rows, tableRow{
			cells: []string{p.Product, p.Desired, p.Observed, p.Outstanding, p.Next},
			notes: e.cont,
		})
	}
	out, laidOut := t.render(avail)
	if !laidOut {
		return verbatim(entries, avail)
	}
	if t.hasUnknown() {
		out = append(out, styleAll(dimStyle, wrapAt(
			"(unknown) / ? — the runtime did not answer; not an observation of absence.", "  ", avail))...)
	}
	for _, e := range rest {
		out = append(out, indentAll(e.lines(), "  ", avail)...)
	}
	return out
}

// renderVolumes draws the volume table.
//
// FIVE FACTS, NONE OF THEM A SIZE — see the file header. The state column carries a short
// token and the legend under it reproduces the report's own phrase, so the token never has to
// be interpreted and a phrase this view does not know is never squeezed into it.
func renderVolumes(entries []statusEntry, avail int) []string {
	t := table{head: []string{"VOLUME", "ROLE", "DATA", "STATE"}}
	var rest []statusEntry
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.hasVolume {
			rest = append(rest, e)
			continue
		}
		v := e.volume
		seen[v.State] = true
		t.rows = append(t.rows, tableRow{cells: []string{v.Name, v.Role, v.Data, v.State}, notes: e.cont})
	}
	out, laidOut := t.render(avail)
	if !laidOut {
		return verbatim(entries, avail)
	}
	for _, short := range volumeStateOrder {
		if !seen[short] {
			continue
		}
		for phrase, s := range volumeStates {
			if s == short {
				out = append(out, styleAll(dimStyle, wrapAt(fmt.Sprintf("%-8s — %s", short, phrase), "  ", avail))...)
			}
		}
	}
	for _, e := range rest {
		out = append(out, indentAll(e.lines(), "  ", avail)...)
	}
	return out
}

// --- the hand-rolled table ----------------------------------------------------------------------

type tableRow struct {
	cells []string
	notes []string
}

type table struct {
	head []string
	rows []tableRow
}

// hasUnknown reports whether any cell carries one of the verb's "the runtime did not answer"
// tokens, which is what the legend under the products table is for.
func (t table) hasUnknown() bool {
	for _, r := range t.rows {
		for _, c := range r.cells {
			if c == "(unknown)" || c == "?" {
				return true
			}
		}
	}
	return false
}

// render lays the table out at the given width. avail == 0 means unlimited.
//
// WIDTHS ARE MEASURED AND CUT IN THE SAME UNIT — terminal cells, over grapheme clusters, via
// ansi.StringWidth and ansi.Truncate. Measuring in bytes or runes and cutting in cells (or the
// reverse) is how a table with an East-Asian name in it wraps every row.
func (t table) render(avail int) ([]string, bool) {
	if len(t.rows) == 0 {
		return nil, true
	}
	cols := len(t.head)
	const gap = 2
	const indent = 2
	// A TERMINAL TOO NARROW FOR THE TABLE GETS NO TABLE. Below this the columns cannot all reach
	// their minimum, and drawing anyway would put rows wider than the terminal on screen — every
	// one of them wrapped by the terminal itself, in the middle of a cell, with no ellipsis to
	// say so. The caller falls back to the lines as the report wrote them, which always fit
	// because prose wraps.
	if avail > 0 && avail-indent-gap*(cols-1) < cols*minColumn {
		return nil, false
	}
	widths := make([]int, cols)
	for i, h := range t.head {
		widths[i] = ansi.StringWidth(h)
	}
	for _, r := range t.rows {
		for i := 0; i < cols && i < len(r.cells); i++ {
			if w := ansi.StringWidth(sanitize(r.cells[i])); w > widths[i] {
				widths[i] = w
			}
		}
	}
	truncated := false
	if avail > 0 {
		widths, truncated = fitColumns(widths, avail-indent-gap*(cols-1))
	}
	out := []string{"  " + headingStyle.Render(padRow(t.head, widths, gap))}
	for _, r := range t.rows {
		out = append(out, "  "+padRow(sanitizeAll(r.cells), widths, gap))
		for _, n := range r.notes {
			out = append(out, indentAll([]string{n}, "    ", avail)...)
		}
	}
	if truncated {
		out = append(out, styleAll(alarmStyle, wrapAt(
			"some columns are truncated to fit this terminal — 'mythical-ctl status --plain' prints the report whole.",
			"  ", avail))...)
	}
	return out, true
}

// minColumn is the narrowest a column may become. Below it a cell is the ellipsis and nothing
// else, which conveys less than the line the report wrote.
const minColumn = 4

// fitColumns shrinks the widest column until the row fits, and reports whether anything had to
// give. A minimum is kept so a column never collapses to the ellipsis alone.
func fitColumns(widths []int, avail int) ([]int, bool) {
	const min = minColumn
	if avail <= 0 {
		return widths, false
	}
	out := append([]int(nil), widths...)
	total := 0
	for _, w := range out {
		total += w
	}
	shrunk := false
	for total > avail {
		widest, at := 0, -1
		for i, w := range out {
			if w > widest && w > min {
				widest, at = w, i
			}
		}
		if at < 0 {
			// Unreachable given render's precondition (the budget is at least cols*min, so
			// shrinking every column to min always fits). Kept because the alternative failure
			// mode of a wrong precondition is a loop that never ends.
			return out, true
		}
		out[at]--
		total--
		shrunk = true
	}
	return out, shrunk
}

// padRow lays one row out at the given column widths.
func padRow(cells []string, widths []int, gap int) string {
	var b strings.Builder
	for i, w := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		if ansi.StringWidth(cell) > w {
			cell = ansi.Truncate(cell, w, "…")
		}
		b.WriteString(cell)
		if i == len(widths)-1 {
			break
		}
		for pad := w - ansi.StringWidth(cell) + gap; pad > 0; pad-- {
			b.WriteString(" ")
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// styleAll applies one style to every line of an already-laid-out block. The style is added
// AFTER the width work, never before: an escape sequence inside a string that is then measured
// or cut is how a styled table starts wrapping.
func styleAll(st lipgloss.Style, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = st.Render(l)
	}
	return out
}

func sanitizeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = sanitize(s)
	}
	return out
}

// wrapAt lays one line of prose out at the given width, prefixing every line it becomes.
//
// PROSE WRAPS; ONLY TABLE CELLS ARE CUT. A report line is a sentence — "this is NOT 'nothing
// installed'", "run state repair" — and truncating one drops the half that says what to do. A
// table cell cannot wrap without the table ceasing to be one, which is why cutting there is
// allowed and is announced. avail == 0 means the terminal size is not known and nothing is done.
func wrapAt(text, prefix string, avail int) []string {
	s := sanitize(text)
	if avail <= 0 {
		return []string{prefix + s}
	}
	limit := avail - ansi.StringWidth(prefix)
	if limit < 1 {
		// The terminal is no wider than the indent. Cutting is all that is left, and the
		// ellipsis is what says it happened.
		return []string{ansi.Truncate(prefix+s, avail, "…")}
	}
	// SPACE IS THE ONLY BREAKPOINT. Volume and container names are full of hyphens, and a name
	// broken at one reads as two names. A token wider than the limit is hard-broken by the
	// wrapper, which is ugly and lossless — the right trade for a report whose whole point is
	// that nothing goes missing.
	var out []string
	for _, l := range strings.Split(ansi.Wrap(s, limit, " "), "\n") {
		line := prefix + l
		// A belt over the wrapper's braces: a single unbreakable token wider than the limit
		// would otherwise leave one row of the frame overflowing the terminal.
		if ansi.StringWidth(line) > avail {
			line = ansi.Truncate(line, avail, "…")
		}
		out = append(out, line)
	}
	return out
}

// indentAll renders raw report lines: sanitised, indented and wrapped. The report already indents
// its own continuations, so the prefix is added to what the report wrote rather than replacing it.
func indentAll(lines []string, prefix string, avail int) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, wrapAt(l, prefix, avail)...)
	}
	return out
}

// --- the runner ---------------------------------------------------------------------------------

// statusRunMsg is the generation envelope: every message a run produces is wrapped in one, so
// the model can tell a fresh run's lines from a superseded run's without the message types
// themselves having to carry a run id.
type statusRunMsg struct {
	Gen int
	Msg tea.Msg
}

// statusStartMsg marks a run beginning. It is the first message of its generation, which is
// what makes the previous report's lines disappear as a unit rather than one at a time.
type statusStartMsg struct{}

// statusDoneMsg reports that the run returned Code. Unlike VerbDoneMsg it does NOT end the
// program: the report is there to be read.
type statusDoneMsg struct{ Code int }

// genSender stamps every message a run's bridge posts with that run's generation.
type genSender struct {
	send Sender
	gen  int
}

func (g genSender) Send(msg tea.Msg) { g.send.Send(statusRunMsg{Gen: g.gen, Msg: msg}) }

// RunStatus drives the report under the dashboard and returns the report's exit code.
//
// It has Run's signature and Run's contract, including ErrNotStarted — which means THE VERB WAS
// NEVER INVOKED, so the caller must fall back to the plain path. Reporting anything else there
// would announce an outcome for a report that never ran.
func RunStatus(ctx context.Context, d verbs.Deps, fn VerbFunc) (int, error) {
	return runStatus(ctx, d, fn, func(m StatusModel) program {
		opts := []tea.ProgramOption{}
		if d.Stdin != nil {
			opts = append(opts, tea.WithInput(d.Stdin))
		}
		if d.Stdout != nil {
			opts = append(opts, tea.WithOutput(d.Stdout))
		}
		return tea.NewProgram(m, opts...)
	}, waitForVerbGrace)
}

// runStatus is RunStatus with the program construction and the grace period injected.
func runStatus(ctx context.Context, base verbs.Deps, fn VerbFunc, mk func(StatusModel) program, grace time.Duration) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	vctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := make(chan struct{})
	refresh := make(chan struct{}, 1)
	model := NewStatusModel(func() {
		// Non-blocking: a refresh asked for while one is already queued is the same request.
		select {
		case refresh <- struct{}{}:
		default:
		}
	}).withStartHook(func() { close(started) })
	p := mk(model)

	type outcome struct {
		code int
		ran  bool
		b    *Bridge
	}
	done := make(chan outcome, 1)
	uiDone := make(chan struct{})

	go func() {
		// THE REPORT DOES NOT START UNTIL THE INTERFACE IS LIVE, for the same reason Run waits:
		// a report run into an interface that never came up is a report nobody sees, reported
		// as an outcome.
		select {
		case <-started:
		case <-uiDone:
			done <- outcome{}
			return
		}
		var last outcome
		for gen := 1; ; gen++ {
			// A FRESH BRIDGE PER RUN. Its record is what the runner replays on the way out, and
			// a bridge reused across refreshes would accumulate every run's lines and replay
			// all of them as if they were one report.
			b := NewBridge(vctx, genSender{send: p, gen: gen})
			outW, errW := b.Writer(false), b.Writer(true)
			d := base
			d.Confirm = b.Confirm
			d.Progress = b.Progress
			d.Stdout, d.Stderr = outW, errW

			p.Send(statusRunMsg{Gen: gen, Msg: statusStartMsg{}})
			code := fn(vctx, d)
			// Trailing partial lines join the record before the run is published.
			_ = outW.Close()
			_ = errW.Close()
			b.Close()
			last = outcome{code: code, ran: true, b: b}
			p.Send(statusRunMsg{Gen: gen, Msg: statusDoneMsg{Code: code}})

			select {
			case <-refresh:
				// A refresh can be QUEUED at the moment the interface goes away, and a plain
				// three-way select would then pick it at random and run the report again with
				// nothing to show it on. Re-asked here, deterministically.
				if stopped(vctx, uiDone) {
					done <- last
					return
				}
			case <-uiDone:
				done <- last
				return
			case <-vctx.Done():
				done <- last
				return
			}
		}
	}()

	_, runErr := p.Run()
	close(uiDone)
	cancel()

	res, waited := waitOutcome(done, grace)
	if waited {
		fmt.Fprintln(realErr(base), "mythical-ctl: the interface has closed; waiting for the report still in flight to finish.")
		res = <-done
	}
	if !res.ran {
		return 0, fmt.Errorf("%w: %v", ErrNotStarted, runErr)
	}
	// The LAST COMPLETED run's record, replayed to the real streams. That is what leaves the
	// operator with the report itself in their terminal rather than an erased frame, and it is
	// what makes this view's classification a viewing aid rather than a filter.
	res.b.Flush(base.Stdout, base.Stderr)
	return res.code, runErr
}

// stopped reports that the interface has gone or the context has been cancelled.
func stopped(ctx context.Context, uiDone <-chan struct{}) bool {
	select {
	case <-uiDone:
		return true
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
