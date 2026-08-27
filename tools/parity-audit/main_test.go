package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE AUDIT'S OWN GUARD. An audit that cannot fail is worse than no audit: it manufactures
// confidence. Every check in main.go has a case here that trips it, and each case asserts the
// FAILURE IDENTITY (the message names the thing that is wrong), not merely that something failed —
// a test satisfied by any red is a test that a later, different bug also satisfies.
//
// FIXTURE DISCIPLINE, and it is load-bearing. Inventory-line fixtures are built as slices of
// QUOTED strings joined with newlines, never as multi-line raw literals, so no line of THIS file
// begins with `//` followed by PORTED:/N/A:. If one did, the real audit over this repository would
// scan it as a claim naming a bats test that does not exist and go red naming this file — so the
// discipline is self-proving rather than a rule somebody has to remember.

func lines(l ...string) []byte { return []byte(strings.Join(l, "\n") + "\n") }

// ---------------------------------------------------------------------------------------------
// The bats parser and the manifest round trip
// ---------------------------------------------------------------------------------------------

func TestParseBats(t *testing.T) {
	names, err := parseBats("tests/unit/x.bats", lines(
		`#!/usr/bin/env bats`,
		`load '../lib/test_helper'`,
		``,
		`@test "first" {`,
		`  true`,
		`}`,
		`# @test "commented out" {`,
		`@test "second: with, punctuation — and a dash" {`,
		`}`,
	))
	if err != nil {
		t.Fatalf("parseBats: %v", err)
	}
	if len(names) != 2 || names[0] != "first" || names[1] != "second: with, punctuation — and a dash" {
		t.Fatalf("parsed %q", names)
	}
}

// A @test line the parser cannot read must be an ERROR, not a silent skip: a skipped definition is
// a test that leaves the corpus without anybody noticing, which is exactly what the count
// assertions exist to catch and exactly what would defeat them.
func TestParseBatsRefusesUnreadableTestLine(t *testing.T) {
	_, err := parseBats("tests/unit/x.bats", lines(
		`@test "ok" {`,
		`}`,
		"@test 'single quoted' {",
	))
	if err == nil || !strings.Contains(err.Error(), "does not match the parsed grammar") {
		t.Fatalf("err = %v, want a refusal naming the grammar", err)
	}
}

// A TAB in a test name would split into two manifest fields on the way back in, so a name carrying
// one is refused at generation rather than written and misread later.
func TestParseBatsRefusesTabInName(t *testing.T) {
	_, err := parseBats("tests/unit/x.bats", lines("@test \"a\tb\" {", `}`))
	if err == nil || !strings.Contains(err.Error(), "TAB") {
		t.Fatalf("err = %v, want a refusal naming the TAB", err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	in := []batsPair{
		{"tests/unit/a.bats", "one"},
		{"tests/unit/a.bats", "two: with a # hash and a -- dash"},
		{"tests/acceptance/b.bats", "three"},
	}
	out, err := parseManifest(renderManifest(in))
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round trip: %d rows in, %d out", len(in), len(out))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("row %d: %+v, want %+v", i, out[i], in[i])
		}
	}
}

func TestParseManifestRefusesARowWithNoTab(t *testing.T) {
	_, err := parseManifest([]byte("# a comment\ntests/unit/a.bats no tab here\n"))
	if err == nil || !strings.Contains(err.Error(), "not a <file>TAB<name> row") {
		t.Fatalf("err = %v, want a refusal naming the row shape", err)
	}
}

// ---------------------------------------------------------------------------------------------
// The inventory parser
// ---------------------------------------------------------------------------------------------

func TestParseInventory(t *testing.T) {
	claims, bad, _, err := parseInventory("internal/x/x_test.go", lines(
		`package x`,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A:    tests/unit/a.bats: "two" -- structurally impossible in Go: no such seam exists`,
		"\t// PORTED: tests/unit/a.bats: \"three\" -> TestThree (an aside naming TestFour too)",
		`// PORTED: tests/unit/a.bats: "four" -> TestFive, TestSix`,
		`func f() { _ = "// PORTED: tests/unit/a.bats: \"nope\" -> TestNope" }`,
	))
	if err != nil {
		t.Fatalf("parseInventory: %v", err)
	}
	if len(bad) != 0 {
		t.Fatalf("unexpected malformed lines: %+v", bad)
	}
	if len(claims) != 4 {
		t.Fatalf("parsed %d claims, want 4: %+v", len(claims), claims)
	}
	if claims[0].Kind != claimPorted || claims[0].Pair.Name != "one" || len(claims[0].Targets) != 1 {
		t.Fatalf("claim 0: %+v", claims[0])
	}
	if claims[1].Kind != claimNA {
		t.Fatalf("claim 1 should be N/A: %+v", claims[1])
	}
	// An aside inside the target expression still names a real test, so it is resolved too — the
	// alternative is a claim that mentions a function nobody checks exists.
	if len(claims[2].Targets) != 2 || claims[2].Targets[1] != "TestFour" {
		t.Fatalf("claim 2 targets: %+v", claims[2].Targets)
	}
	if len(claims[3].Targets) != 2 {
		t.Fatalf("claim 3 targets: %+v", claims[3].Targets)
	}
}

// A line that opens like a claim but does not parse must be REPORTED. Skipping it would leave a
// bats test unclaimed while the file looks, to a reader, like it claims it.
func TestParseInventoryReportsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"no arrow", `// PORTED: tests/unit/a.bats: "one"`},
		{"no target", `// PORTED: tests/unit/a.bats: "one" -> `},
		{"prose target with no test name", `// PORTED: tests/unit/a.bats: "one" -> (structural, nothing to name)`},
		{"no reason", `// N/A: tests/unit/a.bats: "one" -- `},
		{"reason argues nothing", `// N/A: tests/unit/a.bats: "one" -- same`},
		// A DEFERRAL IS NOT AN ARGUMENT. Measured on this tree: four rows rested on "the verb it
		// names is not wired in this build" and "re-claim once that verb lands", every premise had
		// expired a wave earlier, and nothing noticed — the audit checked that a row was CLAIMED,
		// never that its claim still held.
		{"defers to a verb landing", `// N/A: tests/unit/a.bats: "one" -- the verb it names is not wired in this build; re-claim once that verb lands`},
		{"defers with a TODO", `// N/A: tests/unit/a.bats: "one" -- TODO: needs the copy seam, which is not built here`},
		{"unquoted name", `// PORTED: tests/unit/a.bats: one -> TestOne`},
	} {
		claims, bad, _, err := parseInventory("x_test.go", lines(tc.line))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(bad) != 1 || len(claims) != 0 {
			t.Fatalf("%s: %d malformed, %d claims — want 1 and 0", tc.name, len(bad), len(claims))
		}
	}
}

// The deferral list itself: it must fire on a promise and NOT on prose that merely contains a word
// from it. A check that reddens on arguments nobody can rewrite is a check somebody turns off.
func TestDeferralIsPhraseLevelNotWordLevel(t *testing.T) {
	for _, yes := range []string{
		"the verb it names is not wired in this build",
		"re-claim against install once that verb lands",
		"TODO: port this when the seam exists",
		"lands with internal/verbs in a later task",
	} {
		if deferral(yes) == "" {
			t.Errorf("a deferral went undetected: %q", yes)
		}
	}
	for _, no := range []string{
		"structural in Go: each acceptor performs exactly one snapshot and every later step consumes that byte slice",
		"compile-time arity; there is no set -u to abort under",
		"the mode is a bool on the typed Bind; an unrecognised third field is unrepresentable",
		"bash bundle-mode artifact; Go links the surface at compile time",
	} {
		if d := deferral(no); d != "" {
			t.Errorf("a real argument was read as a deferral (%q): %q", d, no)
		}
	}
}

func TestParseGoTestList(t *testing.T) {
	got := parseGoTestList(lines(
		`TestOne`,
		`TestTwo`,
		`BenchmarkThing`,
		`ExampleThing`,
		`ok  	mythicalos.ai/ctl/internal/x	0.004s`,
		`?   	mythicalos.ai/ctl/internal/y	[no test files]`,
		`TestingNotATest`,
	))
	if !got["TestOne"] || !got["TestTwo"] || !got["TestingNotATest"] {
		t.Fatalf("missing a name: %v", got)
	}
	if got["BenchmarkThing"] || got["ExampleThing"] || len(got) != 3 {
		t.Fatalf("picked up something that is not a test: %v", got)
	}
}

// ---------------------------------------------------------------------------------------------
// assertCorpus — the vacuity guard, and the reason it runs first
// ---------------------------------------------------------------------------------------------

// corpusOfSize builds a pinned-size corpus: exactly the lane counts and the file count the audit
// requires, so a test can then break ONE thing about it and watch the right guard fire.
func corpusOfSize(t *testing.T) []batsPair {
	t.Helper()
	// The file budget, split across the lanes the way the real corpus is (most files in the unit
	// lane). Only the TOTAL has to equal wantBatsFiles.
	perLane := []int{wantBatsFiles - 3, 3}
	if len(perLane) != len(lanes) {
		t.Fatalf("the file budget has %d entries but there are %d lanes", len(perLane), len(lanes))
	}
	var pairs []batsPair
	for i, lane := range lanes {
		files := perLane[i]
		if files > lane.want {
			t.Fatalf("lane %s: %d files cannot each hold a test out of %d", lane.prefix, files, lane.want)
		}
		for n := 0; n < lane.want; n++ {
			file := fmt.Sprintf("%sf%02d.bats", lane.prefix, n%files)
			pairs = append(pairs, batsPair{File: file, Name: fmt.Sprintf("t%04d", n)})
		}
	}
	return pairs
}

func uniqueFiles(pairs []batsPair) map[string]bool {
	s := map[string]bool{}
	for _, p := range pairs {
		s[p.File] = true
	}
	return s
}

func TestAssertCorpusAcceptsThePinnedCorpus(t *testing.T) {
	r := &report{}
	if !assertCorpus(r, corpusOfSize(t)) {
		t.Fatalf("the pinned corpus was rejected: %v", r.Problems)
	}
	if r.Tests != wantUnitTests+wantAcceptanceTests {
		t.Fatalf("Tests = %d", r.Tests)
	}
}

// THIS IS THE TEST THE WHOLE PROGRAM IS BUILT AROUND. A parser that matched nothing would make
// every coverage loop vacuously true and the audit a green no-op. The size is therefore pinned to
// exact literals and checked before anything else.
func TestAssertCorpusRefusesAShortLane(t *testing.T) {
	pairs := corpusOfSize(t)
	r := &report{}
	if assertCorpus(r, pairs[:len(pairs)-1]) {
		t.Fatal("a corpus one test short was accepted")
	}
	if !hasProblem(r, "@test rows, expected exactly") {
		t.Fatalf("problems did not name the count: %v", r.Problems)
	}
}

func TestAssertCorpusRefusesAnEmptyCorpus(t *testing.T) {
	r := &report{}
	if assertCorpus(r, nil) {
		t.Fatal("an EMPTY corpus was accepted — every coverage loop below it would be vacuous")
	}
	if !hasProblem(r, "expected exactly") {
		t.Fatalf("problems did not name the count: %v", r.Problems)
	}
}

func TestAssertCorpusRefusesAWrongFileCount(t *testing.T) {
	pairs := corpusOfSize(t)
	// Fold one file into another: the lane totals still match, the file count no longer does.
	victim, into := pairs[0].File, ""
	for _, p := range pairs {
		if p.File != victim {
			into = p.File
			break
		}
	}
	for i := range pairs {
		if pairs[i].File == victim {
			pairs[i] = batsPair{File: into, Name: victim + "/" + pairs[i].Name}
		}
	}
	r := &report{}
	if assertCorpus(r, pairs) {
		t.Fatal("a corpus with a vanished file was accepted")
	}
	if !hasProblem(r, "bats files, expected exactly") {
		t.Fatalf("problems did not name the file count: %v", r.Problems)
	}
}

func TestAssertCorpusRefusesADuplicateRow(t *testing.T) {
	pairs := corpusOfSize(t)
	pairs[1] = pairs[0]
	r := &report{}
	if assertCorpus(r, pairs) {
		t.Fatal("a corpus with the same (file, name) twice was accepted")
	}
	if !hasProblem(r, "twice") {
		t.Fatalf("problems did not name the duplicate: %v", r.Problems)
	}
}

func TestAssertCorpusRefusesAFileOutsideBothLanes(t *testing.T) {
	pairs := corpusOfSize(t)
	pairs[0] = batsPair{File: "tests/elsewhere/x.bats", Name: pairs[0].Name}
	r := &report{}
	assertCorpus(r, pairs)
	if !hasProblem(r, "is in neither lane") {
		t.Fatalf("problems did not name the stray lane: %v", r.Problems)
	}
}

// ---------------------------------------------------------------------------------------------
// auditCoverage — the claim itself
// ---------------------------------------------------------------------------------------------

// tiny is a corpus small enough to reason about, used for the coverage checks. The SIZE checks
// above are what keep a real run from ever reaching these loops with a corpus like this one.
var tiny = []batsPair{
	{"tests/unit/a.bats", "one"},
	{"tests/unit/a.bats", "two"},
	{"tests/unit/b.bats", "one"}, // the same NAME in another file: the identity is the PAIR
}

var tinyGoTests = map[string]bool{"TestOne": true, "TestTwo": true, "TestThree": true}

// The whole-file N/A pre-declaration is a PARAMETER of the audit, not a global it reads, so these
// tests can put a file in it and take one out. The real map is asserted separately, below.
var (
	noPreDeclared   = map[string]string{}
	tinyPreDeclared = map[string]string{"tests/unit/waived.bats": "a fixture stand-in for a pre-declared whole-file N/A"}
)

func claimsFrom(t *testing.T, l ...string) ([]claim, []malformed, []stray) {
	t.Helper()
	c, b, st, err := parseInventory("internal/x/x_test.go", lines(l...))
	if err != nil {
		t.Fatal(err)
	}
	return c, b, st
}

func hasProblem(r *report, substr string) bool {
	for _, p := range r.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

func TestAuditCoverageAcceptsACompleteInventory(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "two" -- bash-only: guards a source-time hazard Go does not have`,
		`// PORTED: tests/unit/b.bats: "one" -> TestTwo`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("a complete inventory was rejected: %v", r.Problems)
	}
	if r.Ported != 2 || r.NA != 1 {
		t.Fatalf("tally: %d PORTED, %d N/A", r.Ported, r.NA)
	}
}

func TestAuditCoverageCatchesAnUnclaimedTest(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/b.bats: "one" -> TestTwo`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, `"two" is claimed by NO inventory line`) {
		t.Fatalf("the unclaimed test was not reported: %v", r.Problems)
	}
}

// EXACTLY once, not at least once. Two claims on one row means one of them is wrong, and the wrong
// one is invisible while the right one keeps the row covered — which is how a stale N/A survives
// the landing of the test that retired it.
func TestAuditCoverageCatchesADoubleClaim(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "one" -- claimed elsewhere, and this line was never removed`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "is claimed 2 times") {
		t.Fatalf("the double claim was not reported: %v", r.Problems)
	}
}

// A paraphrased or truncated test name is the most common way a claim goes wrong, and the most
// dangerous: the line reads as coverage while the real row it meant is left unclaimed.
func TestAuditCoverageCatchesAClaimOnNoSuchTest(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two, roughly" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "no such test in the corpus") {
		t.Fatalf("the phantom claim was not reported: %v", r.Problems)
	}
	if !hasProblem(r, `"two" is claimed by NO inventory line`) {
		t.Fatalf("the row the phantom was meant to cover was not reported unclaimed: %v", r.Problems)
	}
}

// The identity is the (file, name) PAIR. Six descriptions recur across different bats files in the
// real corpus, so a name-keyed inventory would let one line silently satisfy several rows.
func TestAuditCoverageDoesNotLetOneNameSatisfyTwoFiles(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, `tests/unit/b.bats: "one" is claimed by NO inventory line`) {
		t.Fatalf("b.bats' same-named row was treated as covered by a.bats' claim: %v", r.Problems)
	}
}

// A checklist comment with no live test behind it is the failure the inventory exists to prevent,
// wearing the inventory's own clothes.
func TestAuditCoverageCatchesADanglingPortedTarget(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestGoneAway`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "PORTED target TestGoneAway does not exist") {
		t.Fatalf("the dangling target was not reported: %v", r.Problems)
	}
}

// Every named target, not just the first: a claim naming two tests is claiming both.
func TestAuditCoverageResolvesEverySecondaryTarget(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne, TestVanished`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "PORTED target TestVanished does not exist") {
		t.Fatalf("a secondary target was not resolved: %v", r.Problems)
	}
}

func TestAuditCoverageReportsMalformedLines(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "two" -- x`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "inventory line does not parse") {
		t.Fatalf("the malformed line was not reported: %v", r.Problems)
	}
}

// A file waved away wholesale is the largest hole this inventory can have. Exactly the
// pre-declared files may be, and their arguments are printed on every run.
func TestAuditCoverageCatchesAnUndeclaredWholesaleNA(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// N/A: tests/unit/a.bats: "one" -- not portable, and this reason is long enough to pass`,
		`// N/A: tests/unit/a.bats: "two" -- not portable either, for reasons of comparable length`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "all 2 tests are N/A") {
		t.Fatalf("the wholesale-N/A file was not reported: %v", r.Problems)
	}
}

func TestAuditCoverageAcceptsAPreDeclaredWholeFileNA(t *testing.T) {
	corpus := append([]batsPair(nil), tiny...)
	corpus = append(corpus,
		batsPair{"tests/unit/waived.bats", "x"},
		batsPair{"tests/unit/waived.bats", "y"},
	)
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, corpus, c, b, st, tinyGoTests, tinyPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("the pre-declared whole-file N/A was rejected: %v", r.Problems)
	}
	if r.WholeFileNA != 2 {
		t.Fatalf("WholeFileNA = %d, want 2", r.WholeFileNA)
	}
}

// A per-test claim on a pre-declared file is not extra diligence — the two statements disagree,
// and one of them is wrong.
func TestAuditCoverageCatchesAClaimOnAPreDeclaredFile(t *testing.T) {
	corpus := append([]batsPair(nil), tiny...)
	corpus = append(corpus, batsPair{"tests/unit/waived.bats", "x"})
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`// PORTED: tests/unit/waived.bats: "x" -> TestOne`,
	)
	r := &report{}
	auditCoverage(r, corpus, c, b, st, tinyGoTests, tinyPreDeclared)
	if !hasProblem(r, "pre-declared N/A in tools/parity-audit") {
		t.Fatalf("the contradiction was not reported: %v", r.Problems)
	}
}

// A pre-declaration for a file the corpus does not have is an argument protecting nothing — and
// after the cutover it is the shape a stale exemption would take.
func TestAuditCoverageCatchesAPreDeclarationWithNoFile(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, map[string]string{"tests/unit/gone.bats": "a file the corpus does not have"})
	if !hasProblem(r, "but the corpus has no such file") {
		t.Fatalf("the empty pre-declaration was not reported: %v", r.Problems)
	}
}

// The real pre-declaration, asserted rather than trusted. It is the audit's only sanctioned hole,
// and the plan names exactly these two files; a third appearing is a decision, and a decision has
// to break a test rather than pass one.
func TestTheOnlyWholeFileNAsAreTheTwoPreDeclaredOnes(t *testing.T) {
	want := map[string]bool{"tests/unit/bundle.bats": true, "tests/unit/test_hygiene.bats": true}
	if len(wholeFileNA) != len(want) {
		t.Fatalf("wholeFileNA holds %d files, want %d: %v", len(wholeFileNA), len(want), wholeFileNA)
	}
	for f, reason := range wholeFileNA {
		if !want[f] {
			t.Fatalf("%s is waved away wholesale and was not one of the two pre-declared files", f)
		}
		if len(reason) < 60 {
			t.Fatalf("%s: the argument for waving away a whole file is %d characters — that is not an argument", f, len(reason))
		}
	}
}

// ---------------------------------------------------------------------------------------------
// End to end — because the pieces above can all be right while the program still exits 0
// ---------------------------------------------------------------------------------------------

// THE MUTATION THAT MOTIVATED THIS SECTION. Every check above collects a problem into report; one
// function turns that collection into a non-zero exit. Making THAT function return nil left every
// unit test above green — an audit that prints its findings and exits 0 is the "audit that cannot
// fail" in its purest form, and only a whole-program test sees it. So run() is driven here over a
// synthetic tree, and what is asserted is the EXIT, not the printout.

// The pinned numbers, asserted rather than assumed. The tests below shrink them; this is what says
// what the shipped values are.
func TestPinnedCorpusSizeIsThePlansNumbers(t *testing.T) {
	if wantBatsFiles != 34 {
		t.Fatalf("wantBatsFiles = %d, want 34", wantBatsFiles)
	}
	want := []lane{{"tests/unit/", 1122}, {"tests/acceptance/", 56}}
	if len(lanes) != len(want) {
		t.Fatalf("lanes = %+v", lanes)
	}
	for i := range want {
		if lanes[i] != want[i] {
			t.Fatalf("lane %d = %+v, want %+v", i, lanes[i], want[i])
		}
	}
}

func TestProblemsIsWhatTurnsAFindingIntoAFailure(t *testing.T) {
	if err := problems(&report{}, 0); err != nil {
		t.Fatalf("a clean report returned %v", err)
	}
	err := problems(&report{Problems: []string{"a", "b"}}, 0)
	if err == nil || !strings.Contains(err.Error(), "2 parity problem(s)") {
		t.Fatalf("err = %v, want it to name the two problems", err)
	}
}

// tinyLanes shrinks the pinned corpus for the duration of one test, and restores it. Without this
// every end-to-end case would need a 1,178-row fixture, and the cases that matter most — the ones
// where the audit must FAIL — would be the hardest to write.
func tinyLanes(t *testing.T, unit, acceptance, files int) {
	t.Helper()
	oldLanes, oldFiles, oldNA := lanes, wantBatsFiles, wholeFileNA
	t.Cleanup(func() { lanes, wantBatsFiles, wholeFileNA = oldLanes, oldFiles, oldNA })
	lanes = []lane{{"tests/unit/", unit}, {"tests/acceptance/", acceptance}}
	wantBatsFiles = files
	// The real pre-declaration names two files this synthetic corpus does not have, and the audit
	// correctly refuses a pre-declaration protecting nothing — so the synthetic run gets a
	// synthetic (empty) one. TestTheOnlyWholeFileNAsAreTheTwoPreDeclaredOnes holds the real map.
	wholeFileNA = map[string]string{}
}

// e2eTree writes a complete, PASSING tree, so each case can break exactly one thing about it.
func e2eTree(t *testing.T) (root, goList string) {
	t.Helper()
	root = t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tests/unit/a.bats", strings.Join([]string{
		`@test "one" {`, `}`, `@test "two" {`, `}`, ``}, "\n"))
	write("tests/acceptance/b.bats", strings.Join([]string{
		`@test "three" {`, `}`, ``}, "\n"))
	write("internal/x/x_test.go", string(lines(
		`package x`,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "two" -- bash-only: a source-time hazard Go does not have`,
		`// PORTED: tests/acceptance/b.bats: "three" -> TestThree`,
	)))
	pairs, err := collectBats(root)
	if err != nil {
		t.Fatal(err)
	}
	write("tests/parity-manifest.tsv", string(renderManifest(pairs)))
	goList = filepath.Join(root, "golist.txt")
	if err := os.WriteFile(goList, lines(`TestOne`, `TestThree`, `ok  	pkg	0.1s`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, goList
}

func e2eRun(root, goList string) error {
	return run(root, "tests/parity-manifest.tsv", false, []string{goList}, 0)
}

func TestEndToEndAcceptsACompleteTree(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	if err := e2eRun(root, goList); err != nil {
		t.Fatalf("a complete tree failed the audit: %v", err)
	}
}

func TestEndToEndFailsOnAnUnclaimedTest(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	// Drop one claim. The corpus is unchanged, so the counts still pass and only the coverage
	// check can catch this.
	p := filepath.Join(root, "internal", "x", "x_test.go")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cut := strings.Replace(string(b), `: "two" -- bash-only: a source-time hazard Go does not have`, `: "two-ish" -- bash-only: a source-time hazard Go does not have`, 1)
	if cut == string(b) {
		t.Fatal("fixture did not change — the test is not testing what it says")
	}
	if err := os.WriteFile(p, []byte(cut), 0o644); err != nil {
		t.Fatal(err)
	}
	err = e2eRun(root, goList)
	if err == nil {
		t.Fatal("the audit EXITED CLEAN with a bats test claimed by nobody")
	}
	if !strings.Contains(err.Error(), "parity problem") {
		t.Fatalf("err = %v, want it to report parity problems", err)
	}
}

func TestEndToEndFailsWhenTheManifestDriftedFromTheTrees(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	p := filepath.Join(root, "tests", "parity-manifest.tsv")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite one row's NAME. The row count is unchanged, so nothing but the byte-compare sees it.
	edited := strings.Replace(string(b), "\tone\n", "\tone (edited)\n", 1)
	if edited == string(b) {
		t.Fatal("fixture did not change")
	}
	if err := os.WriteFile(p, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	err = e2eRun(root, goList)
	if err == nil || !strings.Contains(err.Error(), "does not match the bats trees") {
		t.Fatalf("err = %v, want a refusal naming the manifest/tree mismatch", err)
	}
}

// THE POST-CUTOVER PROPERTY, and the reason the manifest is committed at all: with the bats trees
// deleted the audit still runs, still resolves every claim, and still FAILS on a hole.
func TestEndToEndStillAuditsAfterTheBatsTreesAreDeleted(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	for _, d := range []string{"tests/unit", "tests/acceptance"} {
		if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(d))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e2eRun(root, goList); err != nil {
		t.Fatalf("the audit stopped working once the bats trees were deleted: %v", err)
	}
	// ...and it is still an audit, not a formality.
	p := filepath.Join(root, "internal", "x", "x_test.go")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `-> TestThree`, `-> TestNotBuiltAnyMore`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e2eRun(root, goList); err == nil {
		t.Fatal("post-cutover, a PORTED line naming a test that does not exist was accepted")
	}
}

// A half-deleted bash tree is neither state, and guessing which one it is would either regenerate a
// short manifest or silently skip the byte-compare.
func TestEndToEndRefusesAHalfPresentBashTree(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	if err := os.RemoveAll(filepath.Join(root, "tests", "acceptance")); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil || !strings.Contains(err.Error(), "bats lanes exist") {
		t.Fatalf("err = %v, want a refusal naming the half-present tree", err)
	}
}

// With no Go test names loaded, EVERY PORTED target is unresolvable — a red for a reason that has
// nothing to do with the port. Say so up front instead of emitting a thousand false findings.
func TestEndToEndRefusesWithNoGoTestList(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, _ := e2eTree(t)
	err := run(root, "tests/parity-manifest.tsv", false, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "no Go test names were loaded") {
		t.Fatalf("err = %v, want a refusal naming the missing list", err)
	}
}

// The corpus-size assertion runs FIRST, before the coverage loops. A tree whose corpus is the wrong
// size must fail on the SIZE, never pass because its (equally wrong) inventory happens to agree.
func TestEndToEndFailsOnCountsBeforeCoverage(t *testing.T) {
	tinyLanes(t, 3, 1, 2) // the tree holds 2 unit tests; the pin says 3
	root, goList := e2eTree(t)
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("a corpus of the wrong size was audited as if it were the right one")
	}
	if !strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("err = %v, want the count assertion to be what fails", err)
	}
}

// The inventory scan's own liveness. A walk that finds no Go source would report every bats test
// unclaimed — loud, but loud about the wrong thing, and the fix a reader would reach for is to
// weaken the coverage check rather than to fix the path.
func TestEndToEndRefusesWhenNoGoSourceIsScanned(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	if err := os.RemoveAll(filepath.Join(root, "internal")); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil || !strings.Contains(err.Error(), "scanned 0 Go files") {
		t.Fatalf("err = %v, want a refusal naming the empty scan", err)
	}
}

// The stray-claim check, and the defect that motivated it: a PORTED: line wrapped into the middle
// of a paragraph, naming rows another file had marked N/A. Two statements about one row, and only
// the invisible one was right.
func TestAuditCoverageCatchesAClaimWrittenMidLine(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`// some prose about secrets — PORTED: tests/unit/a.bats: "one" -> TestOne (again, unseen)`,
		// A BLOCK COMMENT IS THE OTHER HIDING PLACE, and it is a better one: nothing on the line
		// looks like a line comment at all. The exactly-once guarantee is worth exactly as much as
		// its least-visible hiding place.
		`/* PORTED: tests/unit/b.bats: "one" -> TestThree */`,
		// AND THE THIRD: a claim SPLIT ACROSS LINES parses as neither line, so requiring the claim
		// words and the row on one line left the continuation as a place to hide. The continuation
		// is what carries the identity, so that is what is recognised.
		`// prose that says PORTED: and then continues`,
		`// tests/unit/a.bats: "two" -> TestTwo, invisibly claiming it a second time`,
		// A NON-CORPUS PATH EARLIER ON THE LINE must not shadow a real one after it.
		`// see tests/unit/nowhere.bats and also PORTED: tests/unit/b.bats: "one"`,
	)
	if len(st) != 5 {
		t.Fatalf("a mid-line claim went undetected (%d found): %+v", len(st), st)
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "where the inventory parser does not read it") {
		t.Fatalf("the mid-line claim was not reported: %v", r.Problems)
	}
}

// ...and it stays narrow. A mid-line mention naming a file the corpus does not hold is this
// program's own documentation, or prose about the convention, and must not fail the audit.
func TestAuditCoverageIgnoresAMidLineMentionOfANonCorpusFile(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`// the convention is: PORTED: tests/unit/<file>.bats: "<name>" -> TestGoFunc`,
		`// and a fixture may say PORTED: tests/unit/nowhere.bats: "z" -> TestZ`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("a mention of a non-corpus file was reported: %v", r.Problems)
	}
}

// CODE THAT QUOTES A ROW NAME IS NOT A CLAIM, and the tree has 144 lines of it: the Wave 5 owner map
// is keyed by (file, name) pairs by design. The quoted-row-name signal is therefore scoped to
// COMMENT lines — a claim, split or not, is written in a comment. Without this the check fires on
// 144 legitimate lines, which is how a check gets switched off.
func TestStrayDetectionDoesNotFireOnCodeThatQuotesARowName(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		"\t{\"tests/unit/a.bats\", \"two\"}: 22,",
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("a map entry keyed by (file, name) was read as a hidden claim: %v", r.Problems)
	}
}

// ...but claim SYNTAX beside a real corpus path is never innocent, wherever it sits — including in
// code, where a documentation example naming a REAL row is indistinguishable from a claim somebody
// meant. Fixtures name files the corpus does not hold, deliberately.
func TestStrayDetectionFiresOnClaimSyntaxEvenOutsideAComment(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		"\texample := \"PORTED: tests/unit/b.bats: ...\"",
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "claim syntax") {
		t.Fatalf("claim syntax naming a real corpus row went unreported: %v", r.Problems)
	}
}

// TestAuditCoverageCatchesAClaimSplitAcrossLines isolates the second stray signal.
//
// The line carrying the claim WORDS and the line carrying the ROW can be different lines, and
// neither parses as a claim. Requiring both on one line left that split as a hiding place, so the
// continuation — the line that carries the row's identity — is recognised on its own. This fixture
// deliberately contains NO claim-syntax stray, so only the quoted-row-name signal can report it.
func TestAuditCoverageCatchesAClaimSplitAcrossLines(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`// and the continuation line, carrying the row and nothing that looks like a claim:`,
		`// tests/unit/a.bats: "two" -> TestTwo, claiming it a second time where nothing reads it`,
	)
	if len(st) != 1 {
		t.Fatalf("the continuation line was not detected: %+v", st)
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, tinyGoTests, noPreDeclared)
	if !hasProblem(r, "which is a real @test in that file") {
		t.Fatalf("the split claim was not reported: %v", r.Problems)
	}
}
