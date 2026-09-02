package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
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

// invFixture parses an inventory fixture THE WAY THE REAL AUDIT DOES — through go/parser, as a file
// the toolchain selected. A fixture written as bare inventory lines is not a compilable Go file, so
// it is given the `package` clause it needs and the resulting line numbers are shifted back: the
// assertions read the FIXTURE's lines, not the scaffolding's.
//
// It exists so no test can accidentally exercise a claim path the shipped audit no longer has. A
// fixture that is not valid Go fails HERE, loudly, rather than quietly taking the ineligible-file
// branch and proving nothing.
func invFixture(t *testing.T, rel string, content []byte) ([]claim, []malformed, []stray) {
	t.Helper()
	src, shift := content, 0
	if !strings.HasPrefix(string(content), "package ") {
		src = append([]byte("package x\n"), content...)
		shift = 1
	}
	v, err := parseGoComments(rel, src)
	if err != nil {
		t.Fatalf("the fixture is not valid Go, so it could never be a toolchain-selected file: %v", err)
	}
	c, b, st, perr := parseInventory(rel, content, v.shifted(-shift))
	if perr != nil {
		t.Fatal(perr)
	}
	return c, b, st
}

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
	claims, bad, _ := invFixture(t, "internal/x/x_test.go", lines(
		`package x`,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A:    tests/unit/a.bats: "two" -- structurally impossible in Go: no such seam exists`,
		"\t// PORTED: tests/unit/a.bats: \"three\" -> TestThree -- an aside naming TestFour, which is commentary and binds nothing",
		`// PORTED: tests/unit/a.bats: "four" -> TestFive, TestSix`,
		`func f() { _ = "// PORTED: tests/unit/a.bats: \"nope\" -> TestNope" }`,
	))
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
	// AN ASIDE BINDS NOTHING. It sits behind the ` -- ` delimiter, where nothing reads it — so the
	// TestFour it mentions is not a target, and no sentence written there can become one.
	if len(claims[2].Targets) != 1 || claims[2].Targets[0].Name != "TestThree" {
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
		claims, bad, _ := invFixture(t, "x_test.go", lines(tc.line))
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

// TEST NAMES ARE NOT UNIQUE ACROSS PACKAGES — six collide in this tree — so the list is read PER
// PACKAGE. A global set would let a package's whole share of claims survive the DELETION of the test
// they name, because a namesake elsewhere keeps supplying it.
func TestParseGoTestList(t *testing.T) {
	got := parseGoTestList(lines(
		`TestOne`,
		`TestShared`,
		`BenchmarkThing`,
		`ExampleThing`,
		`ok  	mythicalos.ai/ctl/internal/x	0.004s`,
		`TestShared`,
		`TestOnlyHere`,
		// NOT a test Go would run: the character after `Test` is lower-case. It is here because an
		// earlier fixture treated it as one, which is the same mistake the grammar fix corrects.
		`TestingNotATest`,
		`ok  	mythicalos.ai/ctl/internal/y	0.002s`,
		`?   	mythicalos.ai/ctl/internal/z	[no test files]`,
	))
	x, y := "mythicalos.ai/ctl/internal/x", "mythicalos.ai/ctl/internal/y"
	if got[x]["TestOne"] != 1 || got[x]["TestShared"] != 1 {
		t.Fatalf("package x: %v", got[x])
	}
	if got[x]["TestOnlyHere"] != 0 {
		t.Fatalf("a later package's name leaked into an earlier one: %v", got[x])
	}
	if got[y]["TestShared"] != 1 || got[y]["TestOnlyHere"] != 1 || got[y]["TestOne"] != 0 {
		t.Fatalf("package y: %v", got[y])
	}
	if got[y]["TestingNotATest"] != 0 {
		t.Fatalf("a name Go would never run was read as a test: %v", got[y])
	}
	if got[x]["BenchmarkThing"] != 0 || got[x]["ExampleThing"] != 0 {
		t.Fatalf("picked up something that is not a test: %v", got[x])
	}
	if len(got["mythicalos.ai/ctl/internal/z"]) != 0 {
		t.Fatalf("a package with no test files has names: %v", got["mythicalos.ai/ctl/internal/z"])
	}

	// THE STREAM PRINTS ONE LINE PER REGISTERED TEST, and `package w` and `package w_test` may each
	// declare one of the same name — so the listing really does carry a name TWICE for one package.
	// A boolean read that as a repetition; it is two tests, and the count is the only place that
	// fact survives to be compared against the declarations.
	two := parseGoTestList(lines(
		`TestSame`,
		`TestSame`,
		`TestOnce`,
		`ok  	mythicalos.ai/ctl/internal/w	0.004s`,
	))
	w := "mythicalos.ai/ctl/internal/w"
	if two[w]["TestSame"] != 2 {
		t.Fatalf("two registered tests of one name were collapsed to %d: %v", two[w]["TestSame"], two[w])
	}
	if two[w]["TestOnce"] != 1 {
		t.Fatalf("a name printed once counted %d: %v", two[w]["TestOnce"], two[w])
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

// The fixtures' claims all live in internal/x/x_test.go, so their targets resolve in package x.
// TestElsewhere exists ONLY in another package: a claim naming it without saying so must fail.
//
// COUNTS, because the listing prints one line per registered test and two same-named tests in one
// package (one internal, one external) really are two lines.
var tinyGoTests = map[string]map[string]int{
	"mythicalos.ai/ctl/internal/x": {"TestOne": 1, "TestTwo": 1, "TestThree": 1},
	"mythicalos.ai/ctl/internal/w": {"TestElsewhere": 1, "TestOne": 1},
}

// The SOURCE half of target resolution, keyed by COMPILED TEST PACKAGE — one key finer than the
// list half, because `x` and `x_test` are two packages and a name in one is not a name in the other.
// A target must appear in BOTH witnesses: `go test -list` proves the lane registers it, the lane's
// compiled test files prove that package declares it.
var tinySrcTests = srcOf(map[testPkg][]string{
	{Path: "mythicalos.ai/ctl/internal/x"}: {"TestOne", "TestTwo", "TestThree"},
	{Path: "mythicalos.ai/ctl/internal/w"}: {"TestElsewhere", "TestOne"},
})

// listOf builds a LIST witness from names alone: each name registered once, which is the ordinary
// world. The internal/external cases spell out their own counts.
func listOf(m map[string][]string) map[string]map[string]int {
	out := map[string]map[string]int{}
	for pkg, names := range m {
		out[pkg] = map[string]int{}
		for _, n := range names {
			out[pkg][n]++
		}
	}
	return out
}

// srcOf builds a source witness from names alone, for the tests that do not care WHERE each
// declaration is. The ones that do — the internal/external cases — spell out testDecl themselves.
func srcOf(m map[testPkg][]string) declSet {
	out := declSet{}
	for pkg, names := range m {
		clause := path.Base(pkg.Path)
		if pkg.External {
			clause += "_test"
		}
		for i, n := range names {
			out.add(pkg, n, testDecl{File: path.Base(pkg.Path) + "_test.go", Line: i + 1, PkgName: clause})
		}
	}
	return out
}

// oneLane is the fixture as ONE lane whose three witnesses agree — the ordinary world. The tests
// that care about the pairing build their own disagreeing lanes.
func oneLane() []testLane {
	return withExecAll([]testLane{{name: "default", list: tinyGoTests, src: tinySrcTests}})
}

// withExec completes a fixture lane's EXECUTION witness from its own SOURCE declarations: every test
// this lane compiles is a test this lane ran, once per declaration, which is the ordinary world.
//
// DERIVED FROM THE SOURCE HALF AND NOT FROM THE LIST HALF, deliberately. The list half is the one a
// package can write, so deriving from it would make every fixture agree with the weakest witness in
// the program — and a fixture whose exec map is a restatement of its list map proves nothing about
// the check that holds those two apart. Fixtures whose SUBJECT is execution spell their own exec
// map out and do not come through here.
func withExec(ln testLane) testLane {
	ln.exec = map[string]map[string]int{}
	for pkg, names := range ln.src {
		if ln.exec[pkg.Path] == nil {
			ln.exec[pkg.Path] = map[string]int{}
		}
		for n, ds := range names {
			ln.exec[pkg.Path][n] += len(ds)
		}
	}
	ln.executed = true
	return ln
}

func withExecAll(ls []testLane) []testLane {
	out := make([]testLane, 0, len(ls))
	for _, ln := range ls {
		out = append(out, withExec(ln))
	}
	return out
}

// The whole-file N/A pre-declaration is a PARAMETER of the audit, not a global it reads, so these
// tests can put a file in it and take one out. The real map is asserted separately, below.
var (
	noPreDeclared   = map[string]string{}
	tinyPreDeclared = map[string]string{"tests/unit/waived.bats": "a fixture stand-in for a pre-declared whole-file N/A"}
)

func claimsFrom(t *testing.T, l ...string) ([]claim, []malformed, []stray) {
	t.Helper()
	return invFixture(t, "internal/x/x_test.go", lines(l...))
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "PORTED target TestVanished does not exist") {
		t.Fatalf("a secondary target was not resolved: %v", r.Problems)
	}
}

// A TARGET WHOSE FIRST RUNE IS NOT ASCII must not resolve to the ASCII test whose name it merely
// ENDS WITH. This is the false-green this test was written for, reproduced end to end on the real
// tree before it was fixed: a claim retargeted from `TestVerifyDigest` to `ÉTestVerifyDigest` — a
// Go test that does not exist and never has — passed `bash check.sh parity` with exit 0 and the
// line "every PORTED target resolves".
//
// THE MECHANISM was the `\b` anchoring the identifier pattern. RE2's `\b` is ASCII-ONLY: between
// `É` and `T` it sees a non-word/word transition and reports a boundary, so the scan STARTED at
// the `T` and returned the ASCII tail. `É` is a legal Go identifier start (Go identifiers are
// Unicode), which is precisely why the boundary sat in the wrong place. Identifier runs are now
// scanned rune by rune and judged whole; see goIdentsIn.
//
// WHY THIS IS THE WORST PLACE FOR IT: the bats trees are deleted, tests/parity-manifest.tsv IS
// the corpus, and this program is the only thing that reads it. A claim that resolves to nothing
// while the audit certifies it is the entire failure mode the audit exists to prevent.
func TestANonASCIIIdentifierStartCannotResolveToADifferentTest(t *testing.T) {
	// The extractor, first: the run is returned WHOLE or not at all.
	if got := goIdentsIn("ÉTestByteGate"); len(got) != 1 || got[0] != "ÉTestByteGate" {
		t.Fatalf("goIdentsIn(%q) = %q — a leading non-ASCII rune was skipped and the ASCII tail returned as an identifier", "ÉTestByteGate", got)
	}
	// ...so the TOKEN PARSER refuses it, rather than resolving the real name it ends with.
	if _, why := parseTargetToken("ÉTestVerifyDigest"); why == "" {
		t.Fatal("a token that is not a Go TEST name was accepted as a target")
	}
	// ...and the whole-token rule cuts the other way too: a legitimate Unicode name survives intact.
	if tg, why := parseTargetToken("TestAlphaÉ"); why != "" || tg.Name != "TestAlphaÉ" {
		t.Fatalf("a Unicode test name was refused or truncated: %+v %s", tg, why)
	}
	// A run that cannot START an identifier yields nothing either, rather than its own tail: the
	// defect being fixed is truncation, and it must not reappear at the other end.
	if got := goIdentsIn("1TestOne"); len(got) != 0 {
		t.Fatalf("goIdentsIn(%q) = %q — an identifier-shaped run beginning with a digit was truncated to a legal tail", "1TestOne", got)
	}
	// And the whole audit refuses it. Under the old pattern this inventory was CLEAN: `ÉTestOne`
	// resolved to `TestOne`, which exists in both witnesses, and every row read as covered.
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> ÉTestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if len(r.Problems) == 0 {
		t.Fatal(`the audit certified a PORTED claim naming ÉTestOne, which is not a Go test that exists — it resolved to TestOne, a DIFFERENT test, and the row read as covered`)
	}
	if !hasProblem(r, "inventory line does not parse") {
		t.Fatalf("the unreadable claim was not reported as such: %v", r.Problems)
	}
	if !hasProblem(r, `tests/unit/a.bats: "one" is claimed by NO inventory line`) {
		t.Fatalf("the row the bogus target was meant to cover was not reported unclaimed: %v", r.Problems)
	}
}

func TestAuditCoverageReportsMalformedLines(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "two" -- x`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, corpus, c, b, st, oneLane(), tinyPreDeclared)
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
	auditCoverage(r, corpus, c, b, st, oneLane(), tinyPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), map[string]string{"tests/unit/gone.bats": "a file the corpus does not have"})
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
	// The corpus digest is pinned by CONTENT, and the pin ships as a literal so changing the manifest
	// is a two-place edit somebody reads a diff for.
	if len(manifestSHA256) != 64 {
		t.Fatalf("manifestSHA256 = %q, which is not a sha256 hex digest", manifestSHA256)
	}
	if wantBatsFiles != 35 {
		t.Fatalf("wantBatsFiles = %d, want 35", wantBatsFiles)
	}
	want := []lane{{"tests/unit/", 1145}, {"tests/acceptance/", 56}}
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
// every end-to-end case would need a 1,201-row fixture, and the cases that matter most — the ones
// where the audit must FAIL — would be the hardest to write.
func tinyLanes(t *testing.T, unit, acceptance, files int) {
	t.Helper()
	oldLanes, oldFiles, oldNA, oldDigest := lanes, wantBatsFiles, wholeFileNA, manifestSHA256
	t.Cleanup(func() {
		lanes, wantBatsFiles, wholeFileNA, manifestSHA256 = oldLanes, oldFiles, oldNA, oldDigest
	})
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
	// The fixture declares the functions it claims: target resolution needs BOTH witnesses — the
	// go-test list AND the source — so a fixture of comments alone would fail for a reason that has
	// nothing to do with what each case is testing.
	write("internal/x/x_test.go", string(lines(
		`package x`,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// N/A: tests/unit/a.bats: "two" -- bash-only: a source-time hazard Go does not have`,
		`// PORTED: tests/acceptance/b.bats: "three" -> TestThree`,
		`func TestOne(t *testing.T)   {}`,
		`func TestThree(t *testing.T) {}`,
	)))
	pairs, err := collectBats(root)
	if err != nil {
		t.Fatal(err)
	}
	body := renderManifest(pairs)
	write("tests/parity-manifest.tsv", string(body))
	manifestSHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
	goList = filepath.Join(root, "golist.txt")
	if err := os.WriteFile(goList, lines(`TestOne`, `TestThree`, "ok  \tmythicalos.ai/ctl/internal/x\t0.1s"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The SECOND witness for the same lane: the test files go would compile for it. Written by
	// hand here for the same reason the list is — these tests drive the grader, not the toolchain.
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(root, "internal", "x")+"\t\tx_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	// The THIRD witness: what this lane actually RAN. Real `go test -json` events, so the reader
	// under test is the one the shipped script feeds.
	e2eExec(t, root, "TestOne", "TestThree")
	return root, goList
}

func goFilesPath(root string) string { return filepath.Join(root, "gofiles.txt") }
func goExecPath(root string) string  { return filepath.Join(root, "goexec.json") }

// e2eExec writes an execution witness in which each named test of internal/x started exactly once.
func e2eExec(t *testing.T, root string, ran ...string) {
	t.Helper()
	const pkg = "mythicalos.ai/ctl/internal/x"
	var l []string
	l = append(l, `{"Action":"start","Package":"`+pkg+`"}`)
	for _, n := range ran {
		l = append(l, `{"Action":"run","Package":"`+pkg+`","Test":"`+n+`"}`)
		l = append(l, `{"Action":"pass","Package":"`+pkg+`","Test":"`+n+`","Elapsed":0}`)
	}
	l = append(l, `{"Action":"pass","Package":"`+pkg+`","Elapsed":0.1}`)
	if err := os.WriteFile(goExecPath(root), lines(l...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func e2eRun(root, goList string) error {
	return run(root, "tests/parity-manifest.tsv", false, []string{goList}, []string{goFilesPath(root)}, []string{goExecPath(root)}, 0)
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
	// Rewrite one row's NAME, and RE-PIN the digest — so the identity check is satisfied and the
	// byte-compare against the trees is the only thing left that can notice. Without the re-pin this
	// test would pass on the digest refusal and prove nothing about the regeneration compare.
	edited := strings.Replace(string(b), "\tone\n", "\tone (edited)\n", 1)
	if edited == string(b) {
		t.Fatal("fixture did not change")
	}
	if err := os.WriteFile(p, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(edited)))
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
	err := run(root, "tests/parity-manifest.tsv", false, nil, nil, nil, 0)
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
//
// THE WIRING FAILURE IT IS ABOUT is `-root` naming the wrong directory while the toolchain
// witnesses name the right one, so the fixture moves the Go source OUT of root and leaves the
// witnesses pointing at it: the lanes still load, still parse, still resolve — and the walk finds
// nothing at all.
func TestEndToEndRefusesWhenNoGoSourceIsScanned(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	away := t.TempDir()
	if err := os.Rename(filepath.Join(root, "internal"), filepath.Join(away, "internal")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(away, "internal", "x")+"\t\tx_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil || !strings.Contains(err.Error(), "scanned 0 Go files") {
		t.Fatalf("err = %v, want a refusal naming the empty scan", err)
	}
}

// ...and the guard one level in from it: the walk DOES find Go source, but not the files the
// toolchain named. Keyed differently, pruned, or moved — whatever the cause, every claim in the
// missing files becomes invisible, and the symptom is a pile of unclaimed rows that names nothing.
// The fixture puts a selected package under a directory the walk deliberately prunes.
func TestEndToEndRefusesWhenASelectedFileIsNeverWalked(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	gen := filepath.Join(root, "dist", "gen")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "g_test.go"), lines(`package gen`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(root, "internal", "x")+"\t\tx_test.go\t",
		"mythicalos.ai/ctl/dist/gen\t"+gen+"\t\tg_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("a file the toolchain selected was never reached by the walk and the audit said nothing")
	}
	if !strings.Contains(err.Error(), "the toolchain selected") {
		t.Fatalf("err = %v, want the walk/selection disagreement named", err)
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
	// The COUNT is not the assertion — the window pairs signals across lines, so one hidden claim
	// can surface as more than one piece of evidence. What matters is that each hiding shape below
	// is REPORTED, which auditCoverage decides.
	if len(st) == 0 {
		t.Fatal("no mid-line claim was detected at all")
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("a mention of a non-corpus file was reported: %v", r.Problems)
	}
}

// CODE THAT QUOTES A ROW NAME IS NOT A CLAIM, and the tree has 144 lines of it: the verbs owner map
// is keyed by (file, name) pairs by design. The quoted-row-name signal is therefore scoped to
// COMMENT lines — a claim, split or not, is written in a comment. Without this the check fires on
// 144 legitimate lines, which is how a check gets switched off.
func TestStrayDetectionDoesNotFireOnCodeThatQuotesARowName(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`var owners = map[batsPair]int{`,
		"\t{\"tests/unit/a.bats\", \"two\"}: 22,",
		`}`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
		`func f() {`,
		"\texample := \"PORTED: tests/unit/b.bats: ...\"",
		"\t_ = example",
		`}`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
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
	if len(st) == 0 {
		t.Fatal("the continuation line was not detected")
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "which is a real @test in that file") {
		t.Fatalf("the split claim was not reported: %v", r.Problems)
	}
}

// A PORTED target that exists ONLY in another package, with the claim not saying so, must fail.
//
// Go test names are not unique across packages — six collide in this tree, TestSchemaRefusals among
// them. Resolving against a global name set lets a package's whole share of claims stay green after
// the test they name is DELETED, because a namesake somewhere else keeps supplying the name. That is
// a parity hole that exits 0, which is the only kind that matters.
func TestAuditCoverageCatchesAPortedTargetInAnotherPackage(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestElsewhere`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "namesake") {
		t.Fatalf("a target that lives only in another package was accepted: %v", r.Problems)
	}
}

// ...and a claim that names the other package EXPLICITLY, attached to the target, resolves.
// `internal/w.TestElsewhere` points at one package for one test and can be read exactly one way;
// prose that merely mentions a package cannot, which is what
// TestProseCannotSupplyAPackageBecauseProseIsNotRead holds. The aside rides behind the delimiter,
// where it is commentary.
func TestAuditCoverageAcceptsACrossPackageTargetThatNamesItsPackage(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestElsewhere -- recorded here for the audit`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if len(r.Problems) != 0 {
		t.Fatalf("a cross-package claim that names its package was rejected: %v", r.Problems)
	}
}

// A claim inside a /* */ block, on a CONTINUATION line that opens with nothing at all. This is the
// shape the round-2 split-claim guard still missed: matching on the line's own first characters
// cannot see it, so the block depth is tracked instead.
func TestAuditCoverageCatchesAClaimInABlockCommentContinuation(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`/* PORTED:`,
		`   tests/unit/a.bats: "two" -> TestTwo, a second claim nothing reads`,
		`*/`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "which is a real @test in that file") {
		t.Fatalf("the block-comment continuation was not reported: %v", r.Problems)
	}
}

// A CLAIM MOVED INSIDE A MULTILINE RAW STRING IS INERT DATA, NOT COVERAGE. Round 4 measured it:
// a valid `// PORTED:` line relocated into a raw literal still counted, so a fixture could satisfy a
// row nothing actually covers. Lexical context is tracked now — and the row it names is reported as
// a claim the parser cannot read, rather than silently accepted or silently dropped.
func TestParseInventoryDoesNotCountAClaimInsideARawString(t *testing.T) {
	claims, _, st := invFixture(t, "internal/x/x_test.go", lines(
		"const fixture = `",
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		"`",
	))
	if len(claims) != 0 {
		t.Fatalf("a claim inside a raw string was counted as coverage: %+v", claims)
	}
	if len(st) == 0 {
		t.Fatal("...and it was not reported either, so it is invisible rather than inert")
	}
}

// THE THREE-LINE HIDDEN CLAIM. The claim words, the path and the quoted row on three separate lines
// of one comment block: no line is a claim and no two share a line, so every same-line signal misses
// it. The comment block is the window instead.
func TestAuditCoverageCatchesAClaimSpreadOverThreeLines(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`func f() {}`,
		`/*`,
		`   PORTED:`,
		`   tests/unit/a.bats`,
		`   "two" -> TestTwo, a second claim in three pieces`,
		`*/`,
	)
	if len(st) == 0 {
		t.Fatal("the three-line claim was not detected")
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "where the inventory parser does not read it") {
		t.Fatalf("the three-line claim was not reported: %v", r.Problems)
	}
}

// candidatePackages must not collapse packages onto their last segment: cmd/probe and
// internal/probe are different packages, and letting a claim naming one resolve against the other
// puts back the namesake hole per-package resolution exists to close.
func TestCandidatePackagesDoesNotConfuseTwoPackagesSharingABasename(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/probe": {"TestInternal": true},
		"mythicalos.ai/ctl/cmd/probe":      {"TestCmd": true},
		"mythicalos.ai/ctl/internal/x":     {"TestOne": true},
	}
	got, _ := candidatePackages(goTests, "internal/x/x_test.go", fileInternalTest, target{"cmd/probe", "TestOne"})
	if !got["mythicalos.ai/ctl/cmd/probe"] {
		t.Fatalf("a full path did not resolve: %v", got)
	}
	if got["mythicalos.ai/ctl/internal/probe"] {
		t.Fatalf("cmd/probe resolved against internal/probe: %v", got)
	}
	// A BARE, AMBIGUOUS segment must widen nothing — an ambiguous reference is not a licence to
	// accept either answer.
	amb, _ := candidatePackages(goTests, "internal/x/x_test.go", fileInternalTest, target{"probe", "TestInternal"})
	if amb["mythicalos.ai/ctl/internal/probe"] || amb["mythicalos.ai/ctl/cmd/probe"] {
		t.Fatalf("a bare ambiguous segment widened the candidate set: %v", amb)
	}
}

// ---------------------------------------------------------------------------------------------
// THE TARGET COLUMN IS A CLOSED TOKEN LIST. These four replace the tests that used to pin how the
// reader MINED prose. There is no prose left to mine: the questions those tests asked — which
// mention wins, which boundary counts, which occurrence decides — have no answers now because they
// have no subject. What replaces them is the property that made them unnecessary.
// ---------------------------------------------------------------------------------------------

// cands is candidatePackages' PACKAGE half, for the tests that are about path resolution rather
// than about which of a package's two compiled test packages a claim binds to. Those cases pass the
// file kind themselves.
func cands(all map[string]map[string]bool, goFile string, tg target) map[string]bool {
	out, _ := candidatePackages(all, goFile, fileInternalTest, tg)
	return out
}

func targetsOf(t *testing.T, region string) []target {
	t.Helper()
	tgs, why := parseTargetColumn(region)
	if why != "" {
		t.Fatalf("a well-formed target column was refused: %s", why)
	}
	return tgs
}

func refuseColumn(t *testing.T, region, want string) {
	t.Helper()
	tgs, why := parseTargetColumn(region)
	if why == "" {
		t.Fatalf("%q was accepted as a target list: %+v", region, tgs)
	}
	if !strings.Contains(why, want) {
		t.Fatalf("the refusal of %q does not name the defect (want %q): %s", region, want, why)
	}
}

func refuseToken(t *testing.T, tok, want string) {
	t.Helper()
	tg, why := parseTargetToken(tok)
	if why == "" {
		t.Fatalf("%q was accepted as a target: %+v", tok, tg)
	}
	if !strings.Contains(why, want) {
		t.Fatalf("the refusal of %q does not name the defect (want %q): %s", tok, want, why)
	}
}

// PROSE CANNOT SUPPLY A PACKAGE, because prose is not read. Every path-like token anywhere in a
// claim used to be offered as a candidate, so a claim saying the target is NOT in some package
// supplied that package anyway — and the claim then resolved against a namesake there, and kept
// resolving after the local test it was really about was DELETED. A sentence has no polarity a
// scanner can see; the fix is not a better scanner but no scanner.
func TestProseCannotSupplyAPackageBecauseProseIsNotRead(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestShared": true, "TestQualified": true, "TestBare": true},
		"mythicalos.ai/ctl/internal/x": {"TestOne": true},
	}
	// The sentence that started this is not a target column at all.
	refuseColumn(t, "TestShared (not internal/w; it is local)", "is not a target token")
	// Written where the grammar puts it, the same sentence binds nothing.
	tgs := targetsOf(t, "TestShared -- not internal/w; it is local")
	if len(tgs) != 1 || tgs[0].Pkg != "" || tgs[0].Name != "TestShared" {
		t.Fatalf("commentary leaked into the target: %+v", tgs)
	}
	c := cands(goTests, "internal/x/x_test.go", tgs[0])
	if c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("a package named in commentary was offered as a candidate: %v", c)
	}
	if !c["mythicalos.ai/ctl/internal/x"] || len(c) != 1 {
		t.Fatalf("the claiming file's own package is the only candidate for an unqualified target: %v", c)
	}
	// A QUALIFICATION IS PER TARGET AND RIDES ITS OWN TOKEN: two targets in one column decide
	// independently, and the unqualified one cannot borrow the qualified one's package.
	pair := targetsOf(t, "internal/w.TestQualified + TestBare")
	if len(pair) != 2 || pair[0].Pkg != "internal/w" || pair[1].Pkg != "" {
		t.Fatalf("the two targets did not parse independently: %+v", pair)
	}
	if q := cands(goTests, "internal/x/x_test.go", pair[0]); !q["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("an explicitly qualified target did not resolve: %v", q)
	}
	if b := cands(goTests, "internal/x/x_test.go", pair[1]); b["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("an unqualified target borrowed another target's package: %v", b)
	}
}

// THE TOKEN GRAMMAR IS GO'S, NOT ASCII'S. Go identifiers are Unicode, and this program already owns
// that rule (isGoTestName, identRune). An ASCII spelling of the name half truncates `TestAlphaÉ`,
// and a truncated name is a DIFFERENT test — which is how a claim on a name that does not exist
// once resolved against a real one and the audit exited 0.
func TestTheTargetTokenGrammarIsGosNameGrammarNotASCII(t *testing.T) {
	if tg, why := parseTargetToken("internal/w.TestAlphaÉ"); why != "" || tg.Pkg != "internal/w" || tg.Name != "TestAlphaÉ" {
		t.Fatalf("a Unicode test name was refused or truncated: %+v (%s)", tg, why)
	}
	// A DOT WITH NO PACKAGE BEFORE IT is not a qualification and is not an unqualified name either
	// — it is a token nobody meant, and it is refused rather than quietly read as one or the other.
	refuseToken(t, ".TestFooBar", "names no package before it")
	// A PACKAGE PATH IS NON-EMPTY SEGMENTS, never a dot-path that could climb out of the module.
	refuseToken(t, "internal//w.TestFoo", "is not one")
	refuseToken(t, "../w.TestFoo", "is not one")
	// A NAME THAT GO WOULD NOT RUN is refused where it is written. `Testfoo` is not a test — the
	// testing package ignores it in silence — so a claim resting on it rests on nothing.
	refuseToken(t, "internal/w.Testfoo", "not a Go TEST name")
	refuseToken(t, "internal/w.helper", "not a Go TEST name")
}

// NO SENTENCE BESIDE A TARGET CAN QUALIFY OR CONTRADICT IT. This is the property that made the
// "which occurrence decides" question obsolete: there is one place a target's package can come
// from — the target's own token — and the commentary field is read by nothing at all.
func TestNoSentenceBesideATargetCanQualifyOrContradictIt(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestShared": true, "TestFoo": true},
		"mythicalos.ai/ctl/internal/x": {"TestShared": true},
		"mythicalos.ai/ctl/internal/y": {"TestFoo": true},
	}
	// THE POLARITY CASE: a claim saying its target is local while spelling another package's
	// qualified name. In the target column it is refused; behind the delimiter it binds nothing.
	refuseColumn(t, "TestShared (not internal/w.TestShared; it is local)", "is not a target token")
	local := targetsOf(t, "TestShared -- not internal/w.TestShared; it is local")
	if c := cands(goTests, "internal/x/x_test.go", local[0]); len(c) != 1 || !c["mythicalos.ai/ctl/internal/x"] {
		t.Fatalf("a bare target did not resolve locally and only locally: %v", c)
	}
	// QUALIFIED: that package, and no sentence after it can widen or contradict the choice.
	cross := targetsOf(t, "internal/w.TestShared -- formerly internal/x.TestShared, and see internal/y too")
	if c := cands(goTests, "internal/x/x_test.go", cross[0]); len(c) != 1 || !c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("a qualified target was widened or contradicted by its commentary: %v", c)
	}
	// PER TARGET, not per claim.
	two := targetsOf(t, "internal/w.TestShared + TestFoo -- the sibling, then the local one")
	if len(two) != 2 {
		t.Fatalf("two targets did not parse as two: %+v", two)
	}
	if c := cands(goTests, "internal/x/x_test.go", two[1]); len(c) != 1 || !c["mythicalos.ai/ctl/internal/x"] {
		t.Fatalf("an unqualified target borrowed the other target's package: %v", c)
	}
}

// A TARGET IS A WHOLE TOKEN, never an identifier found inside one. `NotTestFoo` ends in a real
// target's name, and a reader that searched text for `TestFoo` found it there — a spurious
// occurrence that decided the claim. As a token it is simply not a test name, and it is refused
// where it is written.
func TestATargetIsAWholeTokenNotAnIdentifierFoundInsideOne(t *testing.T) {
	refuseToken(t, "NotTestFoo", "not a Go TEST name")
	refuseColumn(t, "(helper NotTestFoo) internal/w.TestFoo", "is not a target token")
	// ...and a LONGER name is its own target, never a qualification of its prefix.
	if tg, why := parseTargetToken("internal/w.TestFooBar"); why != "" || tg.Name != "TestFooBar" {
		t.Fatalf("a longer name did not parse as itself: %+v (%s)", tg, why)
	}
	// A COLUMN THAT NAMES NO TARGET IS REFUSED, rather than resolving to whatever the claiming
	// file's own package happens to hold.
	refuseColumn(t, "-- only commentary, no target", "names no target at all")
	refuseColumn(t, "TestOne --", "commentary field is empty")
}

// TestAQualificationConstrainsRatherThanWidens: saying where a target lives must NARROW resolution
// to that package, not add it beside the local one.
//
// The first version of this fix added the qualified package and KEPT the claiming file's own, which
// left the false-green facing the other way: `internal/w.TestShared` written in internal/x stayed
// green after internal/w.TestShared was DELETED, because a namesake in internal/x answered for it.
// A claim that names where its target is must be answered by THAT package or by nothing — otherwise
// the qualification is decoration and the claim still survives the deletion of the thing it claims.
func TestAQualificationConstrainsRatherThanWidens(t *testing.T) {
	// internal/w no longer has TestShared (it was deleted); internal/x has a namesake.
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestOther": true},
		"mythicalos.ai/ctl/internal/x": {"TestShared": true},
	}
	got := cands(goTests, "internal/x/x_test.go", target{"internal/w", "TestShared"})
	if got["mythicalos.ai/ctl/internal/x"] {
		t.Fatalf("a claim naming internal/w was offered its own package as well: %v", got)
	}
	if !got["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("the named package was not offered: %v", got)
	}
	// AND THE AUDIT SAYS SO END TO END: the claim must FAIL, not be satisfied by the namesake.
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	names := map[string][]string{
		"mythicalos.ai/ctl/internal/w": {"TestOther"},
		"mythicalos.ai/ctl/internal/x": {"TestOne", "TestThree", "TestShared"},
	}
	lanes := withExecAll([]testLane{{name: "default", list: listOf(names), src: srcOf(map[testPkg][]string{
		{Path: "mythicalos.ai/ctl/internal/w"}: {"TestOther"},
		{Path: "mythicalos.ai/ctl/internal/x"}: {"TestOne", "TestThree", "TestShared"},
	})}})
	r := &report{}
	auditCoverage(r, tiny, c, b, st, lanes, noPreDeclared)
	if !hasProblem(r, "TestShared") {
		t.Fatalf("a deleted cross-package target was satisfied by a local namesake: %v", r.Problems)
	}
}

// TestAnAmbiguousQualifierResolvesToNothing: a multi-segment qualifier was matched as a PATH
// SUFFIX against every known package, and a suffix can name MORE THAN ONE. `internal/w` is a
// suffix of both mythicalos.ai/ctl/internal/w and mythicalos.ai/ctl/nested/internal/w, so the
// claim `internal/w.TestShared` was answered by BOTH — delete the test the claim is actually
// about and a namesake in the nested package keeps the audit green. That is exactly the false
// green a BARE segment has always been refused for: the single-segment branch requires the token
// to name one package and one only, and the multi-segment branch did not.
//
// The rule is the same one, spelled once: an exact match on the whole import path wins outright;
// otherwise a suffix is accepted only when it is UNIQUE; ambiguity resolves to NOTHING, so the
// claim becomes unresolvable and the audit fails closed rather than picking a winner.
func TestAnAmbiguousQualifierResolvesToNothing(t *testing.T) {
	// internal/w no longer declares TestShared — it was deleted. The nested namesake does.
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w":        {"TestOther": true},
		"mythicalos.ai/ctl/nested/internal/w": {"TestShared": true},
		"mythicalos.ai/ctl/internal/x":        {"TestOne": true},
	}
	got := cands(goTests, "internal/x/x_test.go", target{"internal/w", "TestShared"})
	if got["mythicalos.ai/ctl/nested/internal/w"] {
		t.Fatalf("the qualifier internal/w resolved against nested/internal/w: a suffix that names two packages let a namesake answer a claim about a DELETED test: %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("an ambiguous qualifier must resolve to NOTHING so the claim fails closed; it resolved to %v", got)
	}

	// AND THE AUDIT SAYS SO END TO END: the claim must FAIL, not be satisfied by the namesake.
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	names := map[string][]string{
		"mythicalos.ai/ctl/internal/w":        {"TestOther"},
		"mythicalos.ai/ctl/nested/internal/w": {"TestShared"},
		"mythicalos.ai/ctl/internal/x":        {"TestOne", "TestThree"},
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, withExecAll([]testLane{{name: "default", list: listOf(names), src: srcOf(map[testPkg][]string{
		{Path: "mythicalos.ai/ctl/internal/w"}:        {"TestOther"},
		{Path: "mythicalos.ai/ctl/nested/internal/w"}: {"TestShared"},
		{Path: "mythicalos.ai/ctl/internal/x"}:        {"TestOne", "TestThree"},
	})}}), noPreDeclared)
	if !hasProblem(r, "TestShared") {
		t.Fatalf("the audit stayed green after internal/w.TestShared was deleted, because a namesake in nested/internal/w answered the qualifier: %v", r.Problems)
	}

	// THE UNAMBIGUOUS CASES STILL RESOLVE. The rule is a uniqueness requirement, not a narrowing:
	// widening is the defect here and refusing everything is not the fix for it.
	if u := cands(goTests, "internal/x/x_test.go", target{"internal/x", "TestOne"}); !u["mythicalos.ai/ctl/internal/x"] || len(u) != 1 {
		t.Fatalf("a UNIQUE suffix qualifier stopped resolving: %v", u)
	}
	// AN EXACT MATCH ON THE WHOLE PATH WINS OUTRIGHT, even where it is also a suffix of another
	// package. Without that, a token that names one package exactly would be refused as ambiguous.
	exact := map[string]map[string]bool{
		"internal/w":        {"TestShared": true},
		"nested/internal/w": {"TestShared": true},
	}
	if e := cands(exact, "internal/x/x_test.go", target{"internal/w", "TestShared"}); !e["internal/w"] || len(e) != 1 {
		t.Fatalf("an exact match on the whole package path did not win outright over a suffix match: %v", e)
	}
}

// TestAnAmbiguousOwnPackageResolvesToNothing: THE SAME SUFFIX AMBIGUITY ON THE BRANCH THAT CARRIES
// NEARLY EVERY CLAIM IN THE TREE — the unqualified one. An unqualified claim resolves against "the
// claiming file's own package", derived from the file's directory (`internal/x`) and matched
// against import paths as a suffix, because this tool does not know the module path. With a nested
// `nested/internal/x` in the module that suffix names two packages, and a namesake there answers a
// claim whose own package no longer declares the target — the audit certifies a test that is gone.
//
// This is the same defect as the qualifier one and it is fixed by the same rule, which is why both
// branches now call one resolver: fixing one of them and not the other is how this class recurs.
func TestAnAmbiguousOwnPackageResolvesToNothing(t *testing.T) {
	// internal/x no longer declares TestOne — it was deleted. The nested namesake does.
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/x":        {"TestOther": true},
		"mythicalos.ai/ctl/nested/internal/x": {"TestOne": true},
	}
	got := cands(goTests, "internal/x/x_test.go", target{"", "TestOne"})
	if got["mythicalos.ai/ctl/nested/internal/x"] {
		t.Fatalf("an unqualified claim in internal/x resolved against nested/internal/x: a namesake in a nested package answered a claim about a DELETED test: %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("an ambiguous own package must resolve to NOTHING so the claim fails closed; it resolved to %v", got)
	}

	// AND THE AUDIT SAYS SO END TO END.
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	names := map[string][]string{
		"mythicalos.ai/ctl/internal/x":        {"TestTwo", "TestThree"},
		"mythicalos.ai/ctl/nested/internal/x": {"TestOne"},
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, withExecAll([]testLane{{name: "default", list: listOf(names), src: srcOf(map[testPkg][]string{
		{Path: "mythicalos.ai/ctl/internal/x"}:        {"TestTwo", "TestThree"},
		{Path: "mythicalos.ai/ctl/nested/internal/x"}: {"TestOne"},
	})}}), noPreDeclared)
	if !hasProblem(r, "TestOne") {
		t.Fatalf("the audit stayed green after internal/x.TestOne was deleted, because a namesake in nested/internal/x answered the unqualified claim: %v", r.Problems)
	}

	// AN UNAMBIGUOUS OWN PACKAGE STILL RESOLVES.
	plain := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/x": {"TestOne": true},
		"mythicalos.ai/ctl/internal/w": {"TestOne": true},
	}
	if u := cands(plain, "internal/x/x_test.go", target{"", "TestOne"}); !u["mythicalos.ai/ctl/internal/x"] || len(u) != 1 {
		t.Fatalf("an unambiguous own package stopped resolving: %v", u)
	}
}

// TestASubtestTargetIsRefusedRatherThanResolvedToItsParent: `go test -list` enumerates test
// FUNCTIONS. A subtest is a runtime construct — it exists only while its parent is running, and no
// listing can see it. So a target written `TestOne/deletes_the_socket` was resolved against
// `TestOne` and the audit reported that the claim resolved: delete the subtest the inventory line
// actually names and nothing goes red, because the name that was checked was never the name that
// was written.
//
// That is the same shape as every other false green found in this reader — the claim says one
// thing, the resolver answers about another and calls it the same. The rule is not another
// heuristic about the target column: it is that a name this program CANNOT resolve is refused,
// loudly, instead of being silently narrowed to one it can.
func TestASubtestTargetIsRefusedRatherThanResolvedToItsParent(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne/deletes_the_socket`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "subtest") {
		t.Fatalf("a claim naming TestOne/deletes_the_socket was satisfied by TestOne: the audit certified a name it never resolved, and deleting that subtest leaves the claim green: %v", r.Problems)
	}

	// A PACKAGE QUALIFICATION IS NOT A SUBTEST, and the difference is which side of the name the
	// slash is on. This is the nearest legitimate neighbour and it must still resolve.
	c2, b2, st2 := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> internal/w.TestElsewhere`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r2 := &report{}
	auditCoverage(r2, tiny, c2, b2, st2, oneLane(), noPreDeclared)
	if len(r2.Problems) != 0 {
		t.Fatalf("a package-qualified cross-package target was refused as a subtest: %v", r2.Problems)
	}
}

// THE DIGEST PIN IS THE POST-CUTOVER GUARD, and this is the failure it exists for: with the bats
// trees gone there is nothing to regenerate from, so a row could be REPLACED — an original
// requirement deleted, an invented one of the same shape put in its place, and a claim written
// beside it. Every count still adds up and every row is still claimed. Only the content says so.
func TestEndToEndCatchesASwappedManifestRowAfterTheCutover(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	for _, d := range []string{"tests/unit", "tests/acceptance"} {
		if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(d))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e2eRun(root, goList); err != nil {
		t.Fatalf("the post-cutover baseline does not pass: %v", err)
	}
	// Swap one row for an invented one of the same shape, and claim the invention. Counts unchanged,
	// coverage unchanged, an original requirement gone.
	mp := filepath.Join(root, "tests", "parity-manifest.tsv")
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, []byte(strings.Replace(string(b), "\ttwo\n", "\tinvented\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	gp := filepath.Join(root, "internal", "x", "x_test.go")
	g, err := os.ReadFile(gp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gp, []byte(strings.Replace(string(g), `: "two" --`, `: "invented" --`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	err = e2eRun(root, goList)
	if err == nil {
		t.Fatal("a manifest row was replaced by an invented one and the audit exited 0")
	}
	if !strings.Contains(err.Error(), "pinned corpus digest") {
		t.Fatalf("err = %v, want the digest pin to be what refuses", err)
	}
}

// lexAfter is a small Go lexer, not a pattern match, and round 5 is why: it used to treat any `//`
// as a line comment and stop scanning, so a `//` inside an ORDINARY string hid the backtick after it
// and a raw literal on the next line was never entered. A real claim could then be moved into that
// literal and still count as coverage.
func TestLexAfterIsNotFooledByASlashInsideAString(t *testing.T) {
	for _, tc := range []struct {
		name           string
		line           string
		inBlock, inRaw bool
	}{
		{"a URL in a string does not end the line", `const s = "http://" + ` + "`", false, true},
		{"a plain raw-string opener", "x := `", false, true},
		{"a raw string opened and closed", "x := `abc`", false, false},
		{"a backtick inside an ordinary string is not a raw opener", `x := "a ` + "`" + ` b"`, false, false},
		{"a real line comment stops the scan", "x := 1 // `", false, false},
		{"a block comment opens", "/* hello", true, false},
		{"an escaped quote does not end the string", `x := "a\" ` + "`" + ` b"`, false, false},
		{"a rune literal holding a quote", `x := '"'` + " + `", false, true},
	} {
		gotBlock, gotRaw := lexAfter(false, false, tc.line)
		if gotBlock != tc.inBlock || gotRaw != tc.inRaw {
			t.Errorf("%s: lexAfter(%q) = block %v raw %v, want block %v raw %v",
				tc.name, tc.line, gotBlock, gotRaw, tc.inBlock, tc.inRaw)
		}
	}
	// ...and a raw string that opened on an earlier line stays open until its own backtick, whatever
	// looks like a comment inside it.
	if b, rr := lexAfter(false, true, `// PORTED: tests/unit/a.bats: "one" -> TestOne`); b || !rr {
		t.Fatalf("a line inside a raw string closed it: block %v raw %v", b, rr)
	}
}

// A claim whose PATH is itself split across lines: `tests/unit/` on one, `a.bats: "row"` on the
// next. Neither line carries a whole path, so the path signal saw nothing to pair. Every corpus
// basename is unique, so a bare `<name>.bats` identifies its file — and the corpus still has to
// HOLD it, which keeps this from firing on prose about somebody else's suite.
func TestAuditCoverageCatchesAClaimNamedByBareFilename(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
		`func f() {}`,
		// NO claim words anywhere in this block, and the file mention and the row name on DIFFERENT
		// lines — so only the REGION search can find it. Line-local matching would see a filename on
		// one line and a sentence on the next, and neither alone says anything.
		`/* a note about`,
		`   tests/unit/`,
		`   a.bats, and separately about the row`,
		`   two, which is claimed again here where nothing reads it`,
		`*/`,
	)
	if len(st) == 0 {
		t.Fatal("the bare-filename claim was not detected")
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, oneLane(), noPreDeclared)
	if !hasProblem(r, "which is a real @test in that file") {
		t.Fatalf("the bare-filename claim was not reported: %v", r.Problems)
	}
}

// TARGET RESOLUTION NEEDS TWO WITNESSES. `go test -list` stdout is unstructured: anything a package
// prints while initialising lands in the same stream, so a DELETED test's identifier printed by a
// TestMain would read back as a test that exists and a PORTED claim on it would stay green. The
// source is the second witness, and neither can be forged by the other's blind spot.
func TestAPortedTargetNeedsBothTheListAndTheSource(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	// The list says the package registers TestTwo; the SOURCE does not declare it — the shape a
	// printed identifier produces.
	//
	// THE EXECUTION WITNESS IS SET TO THE MOST PERMISSIVE THING IT COULD SAY — it agrees with the
	// LIST, so it claims TestTwo ran — precisely so that it cannot be what reddens this case. The
	// fixture helper would have derived it from the source instead, which would have made the
	// execution witness dissent too and left this test unable to say WHICH witness caught the
	// defect it is named for.
	srcMissing := srcOf(map[testPkg][]string{
		{Path: "mythicalos.ai/ctl/internal/x"}: {"TestOne", "TestThree"},
	})
	r := &report{}
	auditCoverage(r, tiny, c, b, st, []testLane{{name: "default", list: tinyGoTests, src: srcMissing,
		executed: true, exec: tinyGoTests}}, noPreDeclared)
	if !hasProblem(r, "TestTwo") {
		t.Fatalf("a target the source does not declare was accepted: %v", r.Problems)
	}

	// ...and the other direction: declared in source but not registered by the package (it does not
	// compile into the test binary, or lives behind a build tag nothing enables).
	listMissing := listOf(map[string][]string{
		"mythicalos.ai/ctl/internal/x": {"TestOne", "TestThree"},
	})
	// Same posture on this side: the execution witness says TestTwo ran, so only the LIST half can
	// be what refuses it.
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, []testLane{{name: "default", list: listMissing, src: tinySrcTests,
		executed: true, exec: tinyGoTests}}, noPreDeclared)
	if !hasProblem(r2, "TestTwo") {
		t.Fatalf("a target the package does not register was accepted: %v", r2.Problems)
	}
}

// TestTheTwoWitnessesMustAgreeWithinONELane: two witnesses that are allowed to come from DIFFERENT
// lanes are not two witnesses.
//
// The source half used to be one global walk of every *_test.go on disk with build constraints
// deliberately not applied, and the list half is per-lane stdout. So a file tagged out of every lane
// could declare TestClaimed while an ACTIVE init() in another lane merely PRINTED "TestClaimed" —
// list ✓, source ✓, and no lane anywhere registers a test by that name. Each half is satisfied by
// the other's blind spot, which is precisely what having two witnesses was supposed to rule out.
func TestTheTwoWitnessesMustAgreeWithinONELane(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	const pkg = "mythicalos.ai/ctl/internal/x"
	// LANE A registers the name (its init printed it) but compiles no file declaring it.
	// LANE B compiles a file declaring it (tagged for this lane) but registers nothing by that name.
	//
	// BOTH LANES SAY TestTwo RAN, so the execution witness cannot be what refuses it here — this
	// case is about the LANE PAIRING, and a fixture whose third witness also dissented would pass
	// without ever exercising it.
	allRan := listOf(map[string][]string{pkg: {"TestOne", "TestTwo", "TestThree"}})
	split := []testLane{
		{name: "a", list: listOf(map[string][]string{pkg: {"TestOne", "TestTwo", "TestThree"}}),
			src:      srcOf(map[testPkg][]string{{Path: pkg}: {"TestOne", "TestThree"}}),
			executed: true, exec: allRan},
		{name: "b", list: listOf(map[string][]string{pkg: {"TestOne", "TestThree"}}),
			src:      srcOf(map[testPkg][]string{{Path: pkg}: {"TestOne", "TestTwo", "TestThree"}}),
			executed: true, exec: allRan},
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, split, noPreDeclared)
	if !hasProblem(r, "TestTwo") {
		t.Fatalf("a target satisfied by two DIFFERENT lanes was accepted — the witnesses were not\n"+
			"required to agree within one lane: %v", r.Problems)
	}
	// AND THE ORDINARY CASE STILL PASSES: one lane in which both halves agree resolves it, even
	// though the other lane knows nothing about it. A fix that demanded every lane agree would
	// refuse every acceptance-tagged test.
	ok := []testLane{
		split[0],
		{name: "b", list: listOf(map[string][]string{pkg: {"TestOne", "TestTwo", "TestThree"}}),
			src:      srcOf(map[testPkg][]string{{Path: pkg}: {"TestOne", "TestTwo", "TestThree"}}),
			executed: true, exec: allRan},
	}
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, ok, noPreDeclared)
	if hasProblem(r2, "TestTwo") {
		t.Fatalf("a target both halves of ONE lane agree on was refused: %v", r2.Problems)
	}
}

// THE THIRD WITNESS, AND THE HOLE IT CLOSES: a test can be LISTED without ever RUNNING.
//
// `func TestMain(m *testing.M)` is the package's own entry point. It can parse `-test.list`, print
// `TestClaimed`, and exit 0 — then, on a normal run, set `-test.run` to something else and call
// m.Run. MEASURED with a real probe on go1.26.5: `go test -list '.*'` printed only TestClaimed, a
// normal `go test -v` ran only TestOther, and the SOURCE witness corroborated the declaration
// because TestClaimed really is declared in a file the lane compiles. Both of the existing witnesses
// answer "does this test EXIST"; neither answers "does it RUN", and the audit's whole promise is the
// second question.
func TestATargetThatIsListedAndDeclaredButNeverRanCannotSatisfyAClaim(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	// Both existing witnesses are complete and agree. Only the execution witness dissents: the
	// package started TestOne and TestThree, and never started TestTwo.
	ln := testLane{
		name:     "default",
		list:     tinyGoTests,
		src:      tinySrcTests,
		executed: true,
		exec: map[string]map[string]int{
			"mythicalos.ai/ctl/internal/x": {"TestOne": 1, "TestThree": 1},
			"mythicalos.ai/ctl/internal/w": {"TestElsewhere": 1, "TestOne": 1},
		},
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, []testLane{ln}, noPreDeclared)
	if !hasProblem(r, "TestTwo") {
		t.Fatalf("a PORTED claim was satisfied by a test that is listed and declared but NEVER RAN — a\n"+
			"TestMain that prints a name during a listing run and filters it out of the real run defeats\n"+
			"both of the other witnesses, and this is the one that is supposed to notice: %v", r.Problems)
	}
	if !hasProblem(r, "NEVER RAN") {
		t.Fatalf("the refusal does not say the target never ran, so its reader is sent looking for a\n"+
			"missing declaration that is not missing: %v", r.Problems)
	}
	// AND THE ORDINARY WORLD STILL RESOLVES. A guard that refused every target would satisfy the
	// assertion above while destroying the audit.
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, oneLane(), noPreDeclared)
	if hasProblem(r2, "TestTwo") {
		t.Fatalf("a target all three witnesses agree on was refused: %v", r2.Problems)
	}
}

// ...and the same property END TO END, through run(), on the reviewer's exact probe shape: the list
// stream names TestOne, the compiled test file declares it, and the `go test -json` events show only
// TestThree having started.
func TestEndToEndRefusesATargetTheExecutionWitnessNeverSawRun(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	if err := e2eRun(root, goList); err != nil {
		t.Fatalf("the fixture must pass before it is broken: %v", err)
	}
	e2eExec(t, root, "TestThree") // TestOne is listed and declared, and never starts
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("the audit EXITED CLEAN over a PORTED target that never ran")
	}
	if !strings.Contains(err.Error(), "NEVER RAN") {
		t.Fatalf("err = %v, want the refusal to name the target that never ran", err)
	}
}

// EVERY DECLARATION MUST HAVE STARTED — a FLOOR on the count, not an equality.
//
// `x` and `x_test` may each declare a test of one name, and `go test -json` reports both under the
// one package. If two are declared and one starts, this lane cannot say which one the claim is about,
// and the one that did not start is exactly the one a claim would be hiding. That is the check.
//
// It must NOT be an equality, which is how it was first written. Go supports `TestMain` calling
// `m.Run()` more than once and -count=1 does not prevent it — MEASURED, a probe declaring ONE test
// emitted TWO run events — so `ran > declared` is a state a correct package reaches, and refusing it
// is a false red about the very thing this witness confirms. Both directions are asserted below.
func TestEveryDeclarationOfANameMustHaveStarted(t *testing.T) {
	const x = "mythicalos.ai/ctl/internal/x"
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/x_test.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	// TestShared is declared twice under internal/x — once internally, once externally — and the
	// listing prints it twice. Only ONE of them ran.
	ln := testLane{
		name: "default",
		list: listOf(map[string][]string{x: {"TestOne", "TestThree", "TestShared", "TestShared"}}),
		src: srcOf(map[testPkg][]string{
			{Path: x}:                 {"TestOne", "TestThree", "TestShared"},
			{Path: x, External: true}: {"TestShared"},
		}),
		executed: true,
		exec:     map[string]map[string]int{x: {"TestOne": 1, "TestThree": 1, "TestShared": 1}},
	}
	r := &report{}
	auditCoverage(r, tiny, sited(c, fileInternalTest), b, st, []testLane{ln}, noPreDeclared)
	if !hasProblem(r, "TestShared") {
		t.Fatalf("two same-named tests were declared and listed, only ONE started, and the claim on the\n"+
			"external one was accepted anyway: %v", r.Problems)
	}
	// ...and when both start, it resolves.
	ln.exec = map[string]map[string]int{x: {"TestOne": 1, "TestThree": 1, "TestShared": 2}}
	r2 := &report{}
	auditCoverage(r2, tiny, sited(c, fileInternalTest), b, st, []testLane{ln}, noPreDeclared)
	if hasProblem(r2, "TestShared") {
		t.Fatalf("both declarations ran and the claim was still refused: %v", r2.Problems)
	}
	// AND MORE STARTS THAN DECLARATIONS IS NOT A DEFECT. A `TestMain` that calls `m.Run()` twice —
	// which Go supports, and which -count=1 does not prevent — starts every test in its package
	// twice. Measured with a probe: one declaration, two run events. Those tests unambiguously RUN,
	// so a claim on one of them must resolve; an equality check refused it, which is a false red
	// about the one property this witness exists to establish.
	ln.exec = map[string]map[string]int{x: {"TestOne": 2, "TestThree": 2, "TestShared": 4}}
	r3 := &report{}
	auditCoverage(r3, tiny, sited(c, fileInternalTest), b, st, []testLane{ln}, noPreDeclared)
	if len(r3.Problems) != 0 {
		t.Fatalf("a package whose TestMain ran its suite twice had every claim refused, though every\n"+
			"declaration demonstrably started: %v", r3.Problems)
	}
}

// A LANE THAT WAS NOT EXECUTED CONFIRMS NOTHING, AND SAYS SO IN THOSE WORDS.
//
// The acceptance lane is the real case: its one tagged test needs a live daemon, so this audit
// cannot witness it running. That is an argued exception, not a silent one — the lane still loads,
// still parses, still contributes its packages, and simply cannot answer a PORTED claim. The
// alternative would be to let a target resolve on existence alone in exactly the lane where nothing
// is ever run, which is the promise quietly weakened for whoever needed it weakened.
func TestALaneThatIsNotExecutedCanConfirmNoTarget(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	ln := testLane{name: "acceptance", list: tinyGoTests, src: tinySrcTests,
		execWhy: "it needs a live daemon"}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, []testLane{ln}, noPreDeclared)
	if !hasProblem(r, "TestOne") {
		t.Fatalf("a lane that ran nothing resolved a PORTED target on existence alone: %v", r.Problems)
	}
	if !hasProblem(r, "it needs a live daemon") {
		t.Fatalf("the refusal does not quote the argument for not executing the lane, so the exception is\n"+
			"invisible at the only place a reader meets it: %v", r.Problems)
	}
	// AND AN EXECUTED LANE BESIDE IT STILL ANSWERS. This is how the real tree works: the acceptance
	// lane is a superset of the default one, so every claim is resolved by the lane that ran.
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, append(oneLane(), ln), noPreDeclared)
	if len(r2.Problems) != 0 {
		t.Fatalf("a target the EXECUTED lane confirms was refused because another lane could not: %v", r2.Problems)
	}
}

// A BASENAME CAN BE AMBIGUOUS, and round 6 asserted it could not: migrate.bats is BOTH
// tests/unit/migrate.bats and tests/acceptance/migrate.bats in the real corpus. Keeping one entry
// per basename attributed an acceptance row to the unit file — the audit still failed, but named
// the wrong file, which is a worse kind of right answer.
func TestAmbiguousBasenamesAreAttributedToTheFileThatHoldsTheRow(t *testing.T) {
	corpus := []batsPair{
		{"tests/unit/dup.bats", "a unit row"},
		{"tests/acceptance/dup.bats", "an acceptance row"},
		{"tests/unit/a.bats", "one"},
	}
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/dup.bats: "a unit row" -> TestOne`,
		`// PORTED: tests/acceptance/dup.bats: "an acceptance row" -> TestTwo`,
		`// PORTED: tests/unit/a.bats: "one" -> TestThree`,
		`// and a hidden second claim naming only the basename:`,
		`// dup.bats: "an acceptance row" -> TestTwo`,
		`func g() {}`,
		`// and another, naming the other file's row by the same basename:`,
		`// dup.bats: "a unit row" -> TestOne`,
	)
	r := &report{}
	auditCoverage(r, corpus, c, b, st, oneLane(), noPreDeclared)
	// BOTH must be attributed to the file that actually holds the row. Keeping one corpus file per
	// basename would leave whichever lost the race unreported — and map iteration decides which, so
	// asserting only one of the two would pass or fail by luck.
	for _, want := range []string{"tests/acceptance/dup.bats", "tests/unit/dup.bats"} {
		if !hasProblem(r, "this names "+want) {
			t.Fatalf("no stray attributed to %s: %v", want, r.Problems)
		}
	}
}

// THE SOURCE WITNESS READS CODE, NOT TEXT. A declaration written inside a block comment or a raw
// string is not a declaration — and counting it would put, inside the tool that audits for exactly
// this mistake, the mistake it audits for.
func TestSourceWitnessIgnoresDeclarationsThatAreNotCode(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "internal", "x")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		`package x`,
		``,
		`import "testing"`,
		``,
		`/*`,
		`func TestInAComment(t *testing.T) {}`,
		`*/`,
		``,
		"const s = `",
		`func TestInARawString(t *testing.T) {}`,
		"`",
		``,
		`type rig struct{}`,
		``,
		`func (r rig) TestAMethod(t *testing.T) {}`,
		``,
		`func TestReal(t *testing.T) { _ = s }`,
		``,
	}, "\n")
	if err := os.WriteFile(filepath.Join(pkg, "x_test.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	files := map[string]pkgFiles{"mythicalos.ai/ctl/internal/x": {Dir: pkg, Test: []string{filepath.Join(pkg, "x_test.go")}}}
	got, err := collectLaneSource(files)
	if err != nil {
		t.Fatal(err)
	}
	names := got[testPkg{Path: "mythicalos.ai/ctl/internal/x"}]
	if len(names["TestReal"]) != 1 {
		t.Fatalf("the real declaration was missed: %v", names)
	}
	for _, no := range []string{"TestInAComment", "TestInARawString", "TestAMethod"} {
		if len(names[no]) != 0 {
			t.Errorf("%s counted as a source declaration: %v", no, names)
		}
	}

	// A FILE THAT DOES NOT PARSE IS A HARD ERROR, never a silent zero. Swallowing it would leave the
	// package with no source witness at all, and every claim on it would then fail for a reason that
	// has nothing to do with the port — or, worse, the package's map would be empty and a reader
	// would go looking for deleted tests that are all still there.
	if err := os.WriteFile(filepath.Join(pkg, "broken_test.go"), []byte("package x\nfunc ("), 0o644); err != nil {
		t.Fatal(err)
	}
	files["mythicalos.ai/ctl/internal/x"] = pkgFiles{Dir: pkg, Test: append(files["mythicalos.ai/ctl/internal/x"].Test, filepath.Join(pkg, "broken_test.go"))}
	if _, err := collectLaneSource(files); err == nil {
		t.Fatal("an unparseable _test.go was skipped rather than refused")
	} else if !strings.Contains(err.Error(), "broken_test.go") {
		t.Fatalf("the refusal does not name the file: %v", err)
	}
	_ = dir
}

// TestTheHarnessEntryPointIsNotATest: `TestMain(m *testing.M)` is the test binary's ENTRY POINT,
// not a test. The toolchain never registers it and `go test -list` never prints it — so the source
// witness must not testify that a package declares a test by that name.
//
// WHY IT MATTERS, and it is the same hole the lane pairing was built to close, one name wide. The
// list witness is `go test -list` STDOUT, which anything a package prints during startup lands in
// — and TestMain is the one function that runs during a listing run. So a TestMain that prints its
// own name supplies the list half, and a source witness that counted the declaration supplied the
// other: both agree, and a claim resolves against a name that no test registers. Measured on Go:
// with `func TestMain(m *testing.M) { fmt.Println("TestMain"); os.Exit(m.Run()) }`, the string
// TestMain appears in `go test -list '.*'` output for that package. This repository already has a
// TestMain of exactly that signature, so the surface is live, not hypothetical.
//
// AND THE RULE IS THE TOOLCHAIN'S, NOT THE NAME. `func TestMain(t *testing.T)` IS a real,
// registered, runnable test — measured: it is listed by `go test -list '.*'` with nothing printing
// it. Excluding the NAME would refuse a legitimate claim on a legitimate test, which is the
// false-red mirror of the defect. The signature decides, exactly as cmd/go decides it.
func TestTheHarnessEntryPointIsNotATest(t *testing.T) {
	dir := t.TempDir()
	write := func(pkgdir, body string) string {
		p := filepath.Join(dir, pkgdir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(p, "x_test.go")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}
	entry := write("entry", strings.Join([]string{
		`package x`,
		``,
		`import (`,
		`	"fmt"`,
		`	"os"`,
		`	"testing"`,
		`)`,
		``,
		`func TestMain(m *testing.M) {`,
		`	fmt.Println("TestMain")`,
		`	os.Exit(m.Run())`,
		`}`,
		``,
		`func TestReal(t *testing.T) {}`,
		``,
	}, "\n"))
	// The other spelling, which the toolchain DOES register as a test.
	real := write("real", strings.Join([]string{
		`package y`,
		``,
		`import "testing"`,
		``,
		`func TestMain(t *testing.T) {}`,
		``,
	}, "\n"))
	// An alias for the testing import: the entry point is still the entry point.
	aliased := write("aliased", strings.Join([]string{
		`package z`,
		``,
		`import tt "testing"`,
		``,
		`func TestMain(m *tt.M) { m.Run() }`,
		``,
	}, "\n"))

	got, err := collectLaneSource(map[string]pkgFiles{
		"mythicalos.ai/ctl/internal/entry":   {Dir: filepath.Dir(entry), Test: []string{entry}},
		"mythicalos.ai/ctl/internal/real":    {Dir: filepath.Dir(real), Test: []string{real}},
		"mythicalos.ai/ctl/internal/aliased": {Dir: filepath.Dir(aliased), Test: []string{aliased}},
	})
	if err != nil {
		t.Fatal(err)
	}
	entryPkg := got[testPkg{Path: "mythicalos.ai/ctl/internal/entry"}]
	aliasedPkg := got[testPkg{Path: "mythicalos.ai/ctl/internal/aliased"}]
	realPkg := got[testPkg{Path: "mythicalos.ai/ctl/internal/real"}]
	if len(entryPkg["TestMain"]) != 0 {
		t.Fatalf("the source witness testified that a `func TestMain(m *testing.M)` entry point is a declared test — paired with the name it prints during a listing run, a claim resolves against a test that does not exist: %v", entryPkg)
	}
	if len(aliasedPkg["TestMain"]) != 0 {
		t.Fatalf("an aliased `*tt.M` entry point was counted as a declared test: %v", aliasedPkg)
	}
	if len(entryPkg["TestReal"]) != 1 {
		t.Fatalf("an ordinary test beside the entry point was lost: %v", entryPkg)
	}
	if len(realPkg["TestMain"]) != 1 {
		t.Fatalf("`func TestMain(t *testing.T)` is a REGISTERED test and a claim on it is legitimate; excluding the name refuses it: %v", realPkg)
	}
}

// TestGoFileListIsTheToolchainsOwnSelection: the source witness is built from the files GO says
// this lane compiles, so a file the lane does not build cannot testify about it.
func TestGoFileListIsTheToolchainsOwnSelection(t *testing.T) {
	got, err := parseGoFileList([]byte(
		"mythicalos.ai/ctl/internal/x\t/abs/internal/x\tx.go\ta_test.go b_test.go\tx_ext_test.go\n" +
			"mythicalos.ai/ctl/internal/y\t/abs/internal/y\t\t\t\n"))
	if err != nil {
		t.Fatal(err)
	}
	// THE TWO TEST FILE LISTS STAY APART. They used to be appended into one, which merged `x` and
	// `x_test` into a single namespace — a name declared in both then had ONE target, and deleting
	// either declaration left every claim on it green.
	wantInternal := []string{
		filepath.Join("/abs/internal/x", "a_test.go"),
		filepath.Join("/abs/internal/x", "b_test.go"),
	}
	wantExternal := []string{filepath.Join("/abs/internal/x", "x_ext_test.go")}
	if fmt.Sprint(got["mythicalos.ai/ctl/internal/x"].Test) != fmt.Sprint(wantInternal) {
		t.Fatalf("in-package test files: got %v, want %v", got["mythicalos.ai/ctl/internal/x"].Test, wantInternal)
	}
	if fmt.Sprint(got["mythicalos.ai/ctl/internal/x"].XTest) != fmt.Sprint(wantExternal) {
		t.Fatalf("external test files: got %v, want %v", got["mythicalos.ai/ctl/internal/x"].XTest, wantExternal)
	}
	// ...and both are still reachable as one list where the question really is "may this file carry
	// a claim", which does not care which package compiles it.
	if fmt.Sprint(got["mythicalos.ai/ctl/internal/x"].AllTest()) != fmt.Sprint(append(append([]string{}, wantInternal...), wantExternal...)) {
		t.Fatalf("AllTest: got %v", got["mythicalos.ai/ctl/internal/x"].AllTest())
	}
	// ORDINARY SOURCE IS CARRIED TOO, and separately. It cannot DECLARE a test, but it is compiled
	// — so it is a file a claim may legitimately be written in, and the eligibility set needs it.
	if fmt.Sprint(got["mythicalos.ai/ctl/internal/x"].Go) != fmt.Sprint([]string{filepath.Join("/abs/internal/x", "x.go")}) {
		t.Fatalf("GoFiles: got %v", got["mythicalos.ai/ctl/internal/x"].Go)
	}
	// A package with NO files at all contributes no entry — it declares nothing and must not be
	// invented as an empty witness that quietly satisfies nothing.
	if _, ok := got["mythicalos.ai/ctl/internal/y"]; ok {
		t.Fatalf("a package with no files produced an entry: %v", got)
	}
	// A MALFORMED LINE IS REFUSED, never partially read: silently dropping a package would empty
	// that lane's source witness for it, and every claim on it would then fail for a reason that
	// has nothing to do with the port.
	if _, err := parseGoFileList([]byte("only\ttwo\n")); err == nil {
		t.Fatal("a line with the wrong field count was accepted")
	}
	// FOUR FIELDS WAS THE OLD SHAPE, and it must not be silently accepted as if GoFiles were empty:
	// that would make every ordinary source file ineligible and every claim in one invisible.
	if _, err := parseGoFileList([]byte("p\t/abs/p\ta_test.go\tx_ext_test.go\n")); err == nil {
		t.Fatal("the pre-GoFiles four-field shape was accepted")
	}
}

// TestPairedWitnessFlagsAreRefusedUnpaired: the three lists are ONE witness TRIPLE per lane. An
// unpaired call would reintroduce the independence the pairing removes, and it would do so
// silently — so it is refused up front rather than resolved against whatever happened to line up.
func TestPairedWitnessFlagsAreRefusedUnpaired(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	for _, c := range []struct {
		name         string
		files, execs []string
	}{
		{"no --go-files", nil, []string{goExecPath(root)}},
		// AND THE EXECUTION HALF IS PART OF THE TRIPLE, not an optional extra. If a missing
		// --go-exec meant "do not check that anything runs", the strongest witness in this program
		// would be switched off by leaving a flag out — which is the shape of every defect this
		// program has ever had.
		{"no --go-exec", []string{goFilesPath(root)}, nil},
	} {
		err := run(root, "tests/parity-manifest.tsv", false, []string{goList}, c.files, c.execs, 0)
		if err == nil || !strings.Contains(err.Error(), "must be given in the same number") {
			t.Fatalf("%s: err = %v, want a refusal naming the unpaired witnesses", c.name, err)
		}
	}
}

// THE EXECUTION WITNESS GETS THE LIVENESS CHECK THE OTHER TWO HALVES GET, and it is what stops an
// empty, truncated or failed-to-build stream from silently turning the strongest evidence in this
// program back into the weakest. The witness-producing command's exit status is deliberately not
// propagated by tools/parity-audit.sh — a FAILING test still proves its target runs — so this is
// the check that stands where that status would have.
func TestAnExecutionWitnessThatRecordsNoRunIsRefused(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	// A stream that parses perfectly and testifies to nothing: the shape a build failure, or a run
	// that died before the first test started, leaves behind.
	if err := os.WriteFile(goExecPath(root), lines(
		`{"Action":"start","Package":"mythicalos.ai/ctl/internal/x"}`,
		`{"Action":"fail","Package":"mythicalos.ai/ctl/internal/x","Elapsed":0}`,
	), 0o644); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil || !strings.Contains(err.Error(), "records no test as having RUN") {
		t.Fatalf("err = %v, want a refusal naming the empty execution witness", err)
	}
}

// A LANE MAY DECLARE ITSELF NOT EXECUTED — AND MUST SAY WHY. The reason is not decoration: it is
// quoted back inside the refusal any claim needing that lane receives, so it is the only place a
// reader meets the exception. An opt-out with no argument is the quiet special case this whole
// witness was added to forbid, so it is refused rather than accepted with an empty string.
func TestALaneMayNotOptOutOfExecutionWithoutAnArgument(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	for _, v := range []string{notExecutedPrefix, notExecutedPrefix + "   "} {
		err := run(root, "tests/parity-manifest.tsv", false,
			[]string{goList}, []string{goFilesPath(root)}, []string{v}, 0)
		if err == nil || !strings.Contains(err.Error(), "gives no reason") {
			t.Fatalf("--go-exec %q: err = %v, want a refusal naming the missing argument", v, err)
		}
	}
	// ...and with an argument it is accepted as a lane that can confirm nothing — which, since this
	// fixture has only the one lane, means the audit refuses UP FRONT rather than reporting every
	// PORTED target dangling, which would be loud about the wrong thing.
	err := run(root, "tests/parity-manifest.tsv", false,
		[]string{goList}, []string{goFilesPath(root)}, []string{notExecutedPrefix + "a fixture lane with no runner"}, 0)
	if err == nil || !strings.Contains(err.Error(), "no lane was executed") {
		t.Fatalf("err = %v, want the up-front refusal naming the unexecuted audit", err)
	}
}

// THE EXECUTION WITNESS READER, and the two things it must get right.
//
// A SUBTEST IS NOT ITS PARENT. `t.Run` emits `"Test":"TestFoo/case"`, and this reader drops it.
// BEWARE THE PLAUSIBLE REASON THAT IS NOT THE REAL ONE: an earlier version of this comment said
// keeping subtests would push the run count above the declaration count and make the check refuse
// everything. That is false twice over. `TestFoo/case` is a DIFFERENT map key from `TestFoo`, so a
// subtest never touches its parent's count at all (measured both ways: with the drop
// `map[TestOne:1]`, without it `map[TestOne:1 TestOne/case:1]`); and the count check is a FLOOR,
// `ran < declared`, so excess starts are accepted anyway. The event counts that sentence cited
// (1662 against 1369) were real; the conclusion drawn from them was not.
//
// What the drop actually does is keep the witness keyed to the thing a claim can name. A PORTED
// target is a top-level test, so a subtest key could never satisfy one, and admitting them would
// only put unmatchable keys in the map.
//
// AND A LINE THAT IS NOT JSON IS A HARD ERROR (valid JSON carrying no run is skipped — see the
// reader's own note on why that bar is not "not a run event"). A reader that shrugged at unparseable lines would
// report a half-empty witness for a stream it had not understood, and every PORTED target would go
// dangling for a reason that has nothing to do with the port.
func TestParseGoTestExecReadsStartsAndNotSubtestsOrProse(t *testing.T) {
	const pkg = "mythicalos.ai/ctl/internal/x"
	got, err := parseGoTestExec("witness", lines(
		`{"Action":"start","Package":"`+pkg+`"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestOne"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestOne/case-a"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestOne/case-b"}`,
		`{"Action":"output","Package":"`+pkg+`","Test":"TestTwo","Output":"=== RUN   TestTwo\n"}`,
		`{"Action":"pass","Package":"`+pkg+`","Test":"TestOne","Elapsed":0}`,
		``,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestSame"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestSame"}`,
		// A START, NOT AN OUTCOME. A test that is invoked and then declines — t.Skip, or a failure —
		// still STARTED, and that is what this witness is about. internal/conf's
		// TestForeignOwnedRefused is a real PORTED target of exactly this shape (it needs root), and
		// its inventory line carries the residual in writing and names an unprivileged target beside
		// it. Refusing a start that ends in a skip would redden that claim on every machine that is
		// not root, with no way to make it green.
		`{"Action":"run","Package":"`+pkg+`","Test":"TestSkipping"}`,
		`{"Action":"skip","Package":"`+pkg+`","Test":"TestSkipping","Elapsed":0}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestFailing"}`,
		`{"Action":"fail","Package":"`+pkg+`","Test":"TestFailing","Elapsed":0}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"TestSkipping", "TestFailing"} {
		if got[pkg][n] != 1 {
			t.Fatalf("%s was INVOKED and its start was not counted — the witness is about invocation, not outcome: %v", n, got[pkg])
		}
	}
	if got[pkg]["TestOne"] != 1 {
		t.Fatalf("TestOne started once and its two subtests are not it: got %d", got[pkg]["TestOne"])
	}
	// AND THE SUBTESTS LEAVE NO ENTRY OF THEIR OWN. The assertion above passes whether or not they
	// are dropped — they land under their own keys, not their parent's, which is why the mutation on
	// the drop SURVIVED the first time this was written. THIS is the assertion that holds the line:
	// the witness is keyed by exactly the names a target can be written as, so `laneRan` counts tests
	// rather than tests-and-subtest-names.
	for k := range got[pkg] {
		if strings.Contains(k, "/") {
			t.Fatalf("a subtest was kept as an entry of its own (%q) — the execution witness is no longer keyed by the names a target can name, and the lane's run count is counting subtests: %v", k, got[pkg])
		}
	}
	// TWO STARTS ARE TWO STARTS. What they MEAN is decided at resolution, not here: they may be a
	// package's internal and external test of one name, or one test whose TestMain called m.Run()
	// twice. The reader's job is to report the number faithfully either way — an earlier version of
	// this line asserted they were "two tests, not a repetition", which is simply not true.
	if got[pkg]["TestSame"] != 2 {
		t.Fatalf("the reader did not report both starts of one name: got %d", got[pkg]["TestSame"])
	}
	// An `output` event is not a start. Only `run` says a test began.
	if _, ok := got[pkg]["TestTwo"]; ok {
		t.Fatalf("an output event was read as a start: %v", got[pkg])
	}
	if _, err := parseGoTestExec("witness", lines(
		`{"Action":"run","Package":"`+pkg+`","Test":"TestOne"}`,
		`ok  	`+pkg+`	0.1s`,
	)); err == nil {
		t.Fatal("a line that is not a go test -json event was skipped in silence")
	}
}

// VALID JSON CARRYING NO RUN IS SKIPPED, AND THAT IS THE CONTRACT, NOT AN OVERSIGHT.
//
// A real `go test -json` stream is mostly non-run events, so the reader's bar is "is this JSON",
// not "is this a run". A reader who takes the neighbouring comment's "not an event is a hard
// error" literally would report the skip as a contract violation; that wording overstates, the code is
// right. This test pins the real shape in both directions so the next reader gets the code's answer
// rather than the comment's: junk-but-valid JSON is skipped rather than refused, AND it buys
// nothing — the target it fails to vouch for stays unvouched.
func TestValidJSONCarryingNoRunIsSkippedAndVouchesForNothing(t *testing.T) {
	const pkg = "mythicalos.ai/ctl/internal/x"
	got, err := parseGoTestExec("witness", lines(
		`{}`,
		`null`,
		`{"Action":"bogus","Package":"`+pkg+`","Test":"TestOne"}`,
		`{"Action":"run","Package":"`+pkg+`"}`,
		`{"Action":"output","Package":"`+pkg+`","Test":"TestOne"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestReal"}`,
	))
	if err != nil {
		t.Fatalf("valid JSON carrying no run was refused, but a real witness is mostly such lines: %v", err)
	}
	if got[pkg]["TestReal"] != 1 {
		t.Fatalf("the one genuine run event was lost among the non-events: %v", got)
	}
	// The point of the skip is that it vouches for NOTHING. A target named only by a non-event
	// must be exactly as unvouched as one never mentioned at all.
	if _, ok := got[pkg]["TestOne"]; ok {
		t.Fatalf("a target named only by a non-run event was credited with a run: %v", got)
	}
	if len(got[pkg]) != 1 {
		t.Fatalf("non-events added keys to the witness: %v", got[pkg])
	}
}

// WHAT THE EXECUTION WITNESS CANNOT DO, PINNED SO NOBODY LATER BELIEVES OTHERWISE.
//
// `go test -json` is test2json, a parser of the test binary's STDOUT, and it still honours the
// unmarked framework line format. MEASURED on go1.26.5 with a real probe: a package that prints
// `=== RUN   TestClaimed` and `--- PASS: TestClaimed (0.00s)` produces a genuine
// `{"Action":"run",...,"Test":"TestClaimed"}` event, indistinguishable from a real one. (Go prefixes
// its OWN lines with \x16 under -test.v=test2json, but the marker is stripped before the JSON is
// emitted, and a package can print that byte too.) So no stdout-derived evidence is proof against a
// package that sets out to lie — what the third witness closes is the accident and the shortcut, not
// forgery. This test states the limit in code so that a later reader who assumes the opposite is
// contradicted by a green test rather than by nothing.
func TestTheExecutionWitnessIsStdoutAndThereforeNotUnforgeable(t *testing.T) {
	const pkg = "mythicalos.ai/ctl/internal/x"
	// This is the JSON test2json emits for the forged lines above; the reader cannot tell it from
	// the real thing, and it must not pretend it can.
	got, err := parseGoTestExec("witness", lines(
		`{"Action":"run","Package":"`+pkg+`","Test":"TestClaimed"}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if got[pkg]["TestClaimed"] != 1 {
		t.Fatalf("the reader is not reading run events as run events: %v", got)
	}
}

// GO'S TEST-NAME GRAMMAR, applied at all three places a name is read. `func Testfoo()` is NOT a
// test — the testing package requires the character after `Test` to be something other than a
// lower-case letter, and it ignores the rest in silence. Accepting it would let a PORTED claim rest
// on a function that exists in source, can be printed into a `go test -list` stream, and is never
// executed: a parity hole satisfying both witnesses at once.
func TestOnlyRealGoTestNamesCount(t *testing.T) {
	// UNICODE, not ASCII. Go identifiers are Unicode and the testing package's rule is about a
	// rune's CATEGORY, so an ASCII-only pattern truncates `TestAlphaÉ` to `TestAlpha` — and a claim
	// on the former would then be satisfied by the latter, which is a different test.
	for _, yes := range []string{"Test", "TestX", "Test_foo", "Test9", "TestABC_def", "TestÉ", "TestAlphaÉ"} {
		if !isGoTestName(yes) {
			t.Errorf("%q is a real test name and was not recognised", yes)
		}
	}
	for _, no := range []string{"Testfoo", "Testing", "TestingNotATest", "Testé", "NotATest", "Tes"} {
		if isGoTestName(no) {
			t.Errorf("%q is NOT a test Go would run, and was accepted", no)
		}
	}
	// ...and the target-column parser applies it too, on the WHOLE token rather than its ASCII
	// prefix: `TestAlphaÉ` is one target, and `Testfoo` is refused where it is written.
	if tgs := targetsOf(t, "TestAlphaÉ, TestBeta"); len(tgs) != 2 || tgs[0].Name != "TestAlphaÉ" || tgs[1].Name != "TestBeta" {
		t.Fatalf("the target column truncated or dropped a target: %+v", tgs)
	}
	refuseToken(t, "Testfoo", "not a Go TEST name")
	// The list reader applies it too...
	got := parseGoTestList(lines(
		`TestReal`,
		`Testfoo`,
		`ok  	mythicalos.ai/ctl/internal/x	0.001s`,
	))
	x := got["mythicalos.ai/ctl/internal/x"]
	if x["TestReal"] != 1 {
		t.Fatalf("the real name was dropped: %v", x)
	}
	if x["Testfoo"] != 0 {
		t.Fatalf("a printed non-test was read as a registered test: %v", x)
	}
	// ...and so does the source witness.
	dir := t.TempDir()
	pkg := filepath.Join(dir, "internal", "x")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	src := strings.Join([]string{
		`package x`, ``, `import "testing"`, ``,
		`func TestReal(t *testing.T) {}`,
		`func Testfoo(t *testing.T) {}`, ``,
	}, "\n")
	if err := os.WriteFile(filepath.Join(pkg, "x_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	const xpkg = "mythicalos.ai/ctl/internal/x"
	sf, err := collectLaneSource(map[string]pkgFiles{xpkg: {Dir: pkg, Test: []string{filepath.Join(pkg, "x_test.go")}}})
	if err != nil {
		t.Fatal(err)
	}
	sx := sf[testPkg{Path: xpkg}]
	if len(sx["TestReal"]) != 1 || len(sx["Testfoo"]) != 0 {
		t.Fatalf("the source witness does not apply Go's grammar: %v", sx)
	}
	_ = dir
}

// ---------------------------------------------------------------------------------------------
// Round 12: the DEMONSTRATED false greens. Each was constructed against the shipped audit by a
// reviewer and made `bash check.sh parity` exit 0 while the parity evidence was false. They are
// written as reds first, because a defect that was only argued about comes back and a defect with
// a test does not.
// ---------------------------------------------------------------------------------------------

// DEMONSTRATION 3 — a manifest row with a third tab-separated field.
//
// `strings.Cut` splits on the FIRST tab, so `<file>TAB<name>TABEXTRA` parsed as a two-field row
// whose NAME CONTAINS A TAB. A claim written to match that name resolved, the digest was re-pinned,
// and the full parity stage passed over a corpus row that is not the shape the manifest declares.
func TestParseManifestRefusesARowWithAnExtraField(t *testing.T) {
	for _, tc := range []struct{ name, row, want string }{
		{"three fields", "tests/acceptance/lifecycle.bats\tCLI: an unknown verb exits 2\tEXTRA", "3 tab-separated fields"},
		{"a trailing empty third field", "tests/unit/a.bats\tone\t", "3 tab-separated fields"},
		{"an empty name between two tabs", "tests/unit/a.bats\t\tone", "3 tab-separated fields"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pairs, err := parseManifest([]byte(tc.row + "\n"))
			if err == nil {
				t.Fatalf("a malformed row was accepted as %+v — its name carries a TAB the manifest grammar cannot express", pairs)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal naming the field count", err)
			}
		})
	}
}

// DEMONSTRATION 2 — a claim in a file the toolchain never compiles was credited.
//
// The reviewer moved a real claim into `cmd/mythical-ctl/testdata/broken.go`, preceded by the line
// `this is not valid Go`, and the audit credited it: `go test -list ./...` ignores testdata, but the
// inventory scan was a raw filesystem walk that reads bytes. Valid Go behind `//go:build never` did
// the same. Claim discovery must come from TOOLCHAIN-SELECTED package files.
func TestEndToEndRefusesAClaimInAFileNoLaneCompiles(t *testing.T) {
	for _, tc := range []struct{ name, rel, prelude string }{
		{"under testdata, and not even valid Go", "internal/x/testdata/broken.go", "this is not valid Go\n"},
		{"valid Go, excluded by a build constraint", "internal/x/never_test.go", "//go:build never\n\npackage x\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tinyLanes(t, 2, 1, 2)
			root, goList := e2eTree(t)
			// Take the claim OUT of the file the lane compiles...
			p := filepath.Join(root, "internal", "x", "x_test.go")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			naLine := `// N/A: tests/unit/a.bats: "two" -- bash-only: a source-time hazard Go does not have` + "\n"
			cut := strings.Replace(string(b), naLine, "", 1)
			if cut == string(b) {
				t.Fatal("fixture did not change — the test is not testing what it says")
			}
			if err := os.WriteFile(p, []byte(cut), 0o644); err != nil {
				t.Fatal(err)
			}
			// ...and put it somewhere no lane's file selection can reach.
			q := filepath.Join(root, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(q), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(q, []byte(tc.prelude+naLine), 0o644); err != nil {
				t.Fatal(err)
			}
			err, stderr := e2eRunCapturingProblems(t, root, goList)
			if err == nil {
				t.Fatal("the audit EXITED CLEAN crediting a claim from a file no lane compiles")
			}
			if !strings.Contains(stderr, `"two" is claimed by NO inventory line`) {
				t.Fatalf("the row was not reported unclaimed; audit said:\n%s", stderr)
			}
			// ...and the claim is reported WHERE IT SITS. Leaving only the unclaimed row would name
			// the wrong file: a reader would go looking in the test file that no longer holds the
			// claim, not in the one that does.
			if !strings.Contains(stderr, "in NO audited lane's file selection") {
				t.Fatalf("the off-lane claim was not reported at its own location; audit said:\n%s", stderr)
			}
		})
	}
}

// e2eRunCapturingProblems runs the audit and returns its error TOGETHER with everything it printed
// to stderr, which is where the full problem list goes. The error value carries only the FIRST
// problem after a sort, and a case that must assert one specific problem cannot depend on the sort
// order having put it there.
func e2eRunCapturingProblems(t *testing.T, root, goList string) (error, string) {
	t.Helper()
	old := os.Stderr
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wr
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, rd)
		done <- b.String()
	}()
	runErr := e2eRun(root, goList)
	_ = wr.Close()
	os.Stderr = old
	out := <-done
	_ = rd.Close()
	return runErr, out
}

// A MALFORMED ELIGIBLE FILE REFUSES, and it is a different file class from the one above. This
// file IS in the toolchain's selection — it compiles — so its claims are the ones that count. A
// parse error that merely skipped it would be indistinguishable from a file that had no claims,
// which is the shape of every false green found in this program.
//
// It is separate from collectLaneSource's own refusal on purpose: that one only ever parses
// _test.go files, so a broken ORDINARY source file in the selection would slip past it.
func TestEndToEndRefusesAMalformedFileTheToolchainSelected(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	if err := os.WriteFile(filepath.Join(root, "internal", "x", "helper.go"), []byte("package x\nfunc ("), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(root, "internal", "x")+"\thelper.go\tx_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("a file the toolchain compiles could not be parsed and the audit read it as having no claims")
	}
	if !strings.Contains(err.Error(), "helper.go") || !strings.Contains(err.Error(), "inventory comments") {
		t.Fatalf("err = %v, want a refusal naming the unparseable selected file", err)
	}
}

// A LANE THAT CAN CONFIRM NOTHING IS REFUSED, and "nothing" is counted in NAMES rather than in
// package entries. Both witnesses manufacture an entry with no test in it — `? <pkg> [no test
// files]` is a terminator line, so the list half records the package with an empty name set, and a
// compiled `_test.go` holding only its `package` clause did the same on the source side. A lane in
// exactly that state registered no test and declared no test, and passed both checks; the guard's
// own comment said it could not.
//
// WHY THE GUARD MATTERS: target resolution requires BOTH halves to agree WITHIN one lane. A lane
// that has arrived empty for a wiring reason cannot confirm anything, so the other lane silently
// answers for it — and the pairing that the whole two-witness design rests on is gone with nothing
// saying so.
//
// THREE SHAPES, because each defeats a different one of the two counts.
func TestALaneThatCanConfirmNothingIsRefused(t *testing.T) {
	xdirOf := func(root string) string { return filepath.Join(root, "internal", "x") }

	t.Run("no compiled test files at all", func(t *testing.T) {
		tinyLanes(t, 2, 1, 2)
		root, goList := e2eTree(t)
		// The same file, moved from the TestGoFiles column into the GoFiles column: compiled, so
		// eligible to carry a claim — and unable to declare a test.
		if err := os.WriteFile(goFilesPath(root), lines(
			"mythicalos.ai/ctl/internal/x\t"+xdirOf(root)+"\tx_test.go\t\t",
		), 0o644); err != nil {
			t.Fatal(err)
		}
		err := e2eRun(root, goList)
		if err == nil || !strings.Contains(err.Error(), "DECLARE no test") {
			t.Fatalf("err = %v, want the empty source witness to be what refuses", err)
		}
	})

	t.Run("a compiled test file that declares no test", func(t *testing.T) {
		tinyLanes(t, 2, 1, 2)
		root, goList := e2eTree(t)
		// THE SHAPE A PACKAGE-ENTRY COUNT CANNOT SEE: the lane really does compile a _test.go, so
		// an entry exists for its package — and the file declares nothing, so the entry is empty.
		if err := os.WriteFile(filepath.Join(xdirOf(root), "empty_test.go"), lines(`package x`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goFilesPath(root), lines(
			"mythicalos.ai/ctl/internal/x\t"+xdirOf(root)+"\tx_test.go\tempty_test.go\t",
		), 0o644); err != nil {
			t.Fatal(err)
		}
		err := e2eRun(root, goList)
		if err == nil {
			t.Fatal("a lane whose only compiled test file declares no test was accepted: it can confirm no target, and the other lane answers for it")
		}
		if !strings.Contains(err.Error(), "DECLARE no test") {
			t.Fatalf("err = %v, want the empty source witness to be what refuses", err)
		}
	})

	t.Run("a listing that registers no test name", func(t *testing.T) {
		tinyLanes(t, 2, 1, 2)
		root, goList := e2eTree(t)
		// THE SAME SHAPE ON THE LIST HALF: a terminator line alone creates the package entry.
		if err := os.WriteFile(goList, lines("?   \tmythicalos.ai/ctl/internal/x\t[no test files]"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := e2eRun(root, goList)
		if err == nil {
			t.Fatal("a lane whose listing registers no test name was accepted: `? pkg [no test files]` is a package entry with nothing in it")
		}
		if !strings.Contains(err.Error(), "lists no test names") {
			t.Fatalf("err = %v, want the empty list witness to be what refuses", err)
		}
	})
}

// DEMONSTRATION 1 — the target column was free prose, and prose has no polarity.
//
// The reviewer rewrote a REAL claim's target to a sentence DENYING the port and the audit still
// reported all 1,201 rows covered, because a `TestFoo` mentioned anywhere in that sentence was
// mined as the target. The same reader resolved a NEGATED package qualifier against the very
// package the sentence said the target was not in, and silently narrowed a generic instantiation
// and a `t.Run` subtest spelling to their parent function name.
//
// The class closes only one way: the region after `->` is a CLOSED, PROSE-FREE list of
// `[<pkgpath>.]<TestName>` tokens, and anything else is a REFUSAL. Commentary moves to its own
// non-semantic field behind the `--` delimiter the N/A lines already use.
func TestAPortedTargetIsAClosedTokenListNotProse(t *testing.T) {
	for _, tc := range []struct{ name, line, want string }{
		{
			"prose that DENIES the port, with a real test name inside it",
			`// PORTED: tests/unit/a.bats: "one" -> this behavior is not implemented; TestOne is only an unrelated neighboring test`,
			"is not a target token",
		},
		{
			"a NEGATED qualifier, resolved against the package it negates",
			`// PORTED: tests/unit/a.bats: "one" -> not internal/w.TestOne; the local TestOne is intended`,
			"is not a target token",
		},
		{
			"a generic instantiation, silently narrowed to the parent name",
			`// PORTED: tests/unit/a.bats: "one" -> TestOne[int]`,
			"generic instantiation",
		},
		{
			"a t.Run subtest spelling, silently narrowed to the parent name",
			`// PORTED: tests/unit/a.bats: "one" -> TestOne via t.Run("required subtest")`,
			"is not a target token",
		},
		{
			"an ordinary parenthetical aside — the shape every case above wears",
			`// PORTED: tests/unit/a.bats: "one" -> TestOne (the aside that made every case above reachable)`,
			"is not a target token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, bad, _ := invFixture(t, "internal/x/x_test.go", lines(tc.line))
			if len(claims) != 0 {
				t.Fatalf("the target column was read as prose and yielded %d claim(s) with targets %v — a sentence must never satisfy a claim", len(claims), claims[0].Targets)
			}
			if len(bad) != 1 {
				t.Fatalf("%d malformed lines, want exactly 1", len(bad))
			}
			if !strings.Contains(bad[0].Text, tc.want) {
				t.Fatalf("refusal did not name the defect (want %q): %s", tc.want, bad[0].Text)
			}
		})
	}
}

// The other half of the same grammar: a claim that spells its targets as tokens and puts its
// commentary behind `--` still parses, and the commentary is NOT scanned for targets. If it were,
// the whole exercise would have moved the prose one field to the right.
func TestAPortedClaimKeepsItsCommentaryInANonSemanticField(t *testing.T) {
	claims, bad, _ := invFixture(t, "internal/x/x_test.go", lines(
		`// PORTED: tests/unit/a.bats: "one" -> TestOne -- the aside, which names TestTwo and internal/w.TestElsewhere and must bind neither`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestElsewhere + TestTwo`,
	))
	if len(bad) != 0 {
		t.Fatalf("a well-formed claim was refused: %+v", bad)
	}
	if len(claims) != 2 {
		t.Fatalf("parsed %d claims, want 2", len(claims))
	}
	if len(claims[0].Targets) != 1 || claims[0].Targets[0].Name != "TestOne" {
		t.Fatalf("commentary leaked into the target list: %v", claims[0].Targets)
	}
	if len(claims[1].Targets) != 2 {
		t.Fatalf("a two-token target list parsed as %v", claims[1].Targets)
	}
}

// THE RECONCILIATION IS A SET, NOT A COUNT, and this is the false green a count allowed. Round 12,
// found by review after the fix that introduced it.
//
// Two walked paths can canonicalize onto ONE selected file — a symlink beside the file it points at
// is enough, and `canonPath` resolves both to the same key by design. A COUNTER then records two
// hits for one file, and those two hits are exactly enough to balance a DIFFERENT selected file the
// walk never reached. The arithmetic agrees, the guard stays silent, and the audit exits 0 having
// never read a file the toolchain compiles — which is the same class of hole the eligibility set was
// built to close, wearing the closing guard's own clothes.
func TestTheWalkSelectionReconciliationCountsFilesNotVisits(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	xdir := filepath.Join(root, "internal", "x")
	// A claim-free selected source file, and a symlink beside it: two walk entries, one canonical
	// path, and the symlink is NOT itself in the toolchain's selection.
	if err := os.WriteFile(filepath.Join(xdir, "helper.go"), lines(`package x`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(xdir, "helper.go"), filepath.Join(xdir, "alias.go")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}
	// ...and a selected file under a directory the walk deliberately prunes, which must be noticed.
	//
	// UNDER third_party AND NOT dist, DELIBERATELY: it has to sort AFTER the files that ARE reached,
	// so that a message naming an arbitrary selected file names a DIFFERENT one. With the unreached
	// file sorting first, "name the missing file" and "name any file" are indistinguishable and the
	// assertion below passes either way — which is a test that cannot see the defect it is for.
	gen := filepath.Join(root, "third_party", "gen")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "g_test.go"), lines(`package gen`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+xdir+"\thelper.go\tx_test.go\t",
		"mythicalos.ai/ctl/third_party/gen\t"+gen+"\t\tg_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("a selected file was never walked and the extra visit to a symlinked one balanced the books: the audit exited 0 having never read a file the toolchain compiles")
	}
	if !strings.Contains(err.Error(), "the toolchain selected") {
		t.Fatalf("err = %v, want the walk/selection disagreement named", err)
	}
	// ...and the message names the file that is actually missing, not an arbitrary selected one.
	if !strings.Contains(err.Error(), "g_test.go") {
		t.Fatalf("err = %v, want the UNREACHED file named", err)
	}
}

// THE ROW NAME ENDS AT THE FIRST CLOSING QUOTE. With a greedy capture the boundary was settled by
// backtracking against the REST of the line, so a quoted phrase in the commentary offered the
// engine a second `" -> ` to close on and the row name it produced swallowed the target column.
// Three claims in this tree carry a quoted phrase in their commentary, so the shape is live.
//
// It was never a false green — no @test name in this corpus contains a quote, so the misparse
// always failed corpus membership — but that is the CORPUS holding the parser up. The boundary is
// structural now, and this pins it.
func TestTheRowNameEndsAtTheFirstQuoteNotAtWhicheverOneBacktracksBest(t *testing.T) {
	claims, bad, _ := invFixture(t, "internal/x/x_test.go", lines(
		`// PORTED: tests/unit/a.bats: "one" -> TestOne -- the "b" case, and see "c" -> TestTwo`,
		`// N/A: tests/unit/a.bats: "two" -- bash-only, and the "c" spelling has no Go analogue at all`,
	))
	if len(bad) != 0 {
		t.Fatalf("a claim with a quoted phrase in its commentary was refused: %+v", bad)
	}
	if len(claims) != 2 {
		t.Fatalf("parsed %d claims, want 2: %+v", len(claims), claims)
	}
	if claims[0].Pair.Name != "one" {
		t.Fatalf("the PORTED row name ran past the first closing quote: %q", claims[0].Pair.Name)
	}
	if len(claims[0].Targets) != 1 || claims[0].Targets[0].Name != "TestOne" {
		t.Fatalf("the target column was not the one after the FIRST arrow: %+v", claims[0].Targets)
	}
	if claims[1].Pair.Name != "two" {
		t.Fatalf("the N/A row name ran past the first closing quote: %q", claims[1].Pair.Name)
	}
}

// ---------------------------------------------------------------------------------------------
// `x` AND `x_test` ARE TWO PACKAGES, AND THIS AUDIT MUST NOT SEE ONE.
//
// TestGoFiles and XTestGoFiles were merged into a single per-import-path name set on both witness
// halves, so an internal `package x` declaration and an external `package x_test` declaration of
// the same name became ONE target. Delete the external test, keep its claim, and the claim still
// resolved — through the internal namesake. That is this program's own defining failure (a claim
// surviving the deletion of the thing it claims) reappearing across the one package boundary the
// keying could not see, and it is the fifth of its family: every one of them was an approximated
// identity rather than a resolved one.
// ---------------------------------------------------------------------------------------------

// e2eWrite writes one file into an end-to-end fixture tree.
func e2eWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// e2eWitnesses rewrites ALL THREE witness halves of the single fixture lane: what `go test -list`
// printed, which files the toolchain compiles for the package — internal test files and external
// ones kept apart, as `go list` reports them — and what ran.
//
// THE EXECUTION HALF MIRRORS `listed` HERE, and that is right for these cases rather than lazy:
// their subject is the internal/external package IDENTITY, so execution is what they hold constant.
// A case whose subject IS execution writes its own e2eExec and does not come through here.
func e2eWitnesses(t *testing.T, root, goList string, listed []string, internal, external string) {
	t.Helper()
	e2eExec(t, root, listed...)
	body := append(append([]string{}, listed...), "ok  \tmythicalos.ai/ctl/internal/x\t0.1s")
	if err := os.WriteFile(goList, lines(body...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goFilesPath(root), lines(
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(root, "internal", "x")+"\t\t"+internal+"\t"+external,
	), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAnExternalTestPackageIsNotThePackageUnderTest(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)

	// The package under test declares TestSame. So does its external test package — legal Go, and
	// `go test -list` prints the name once for each, which is how two tests present themselves.
	e2eWrite(t, root, "internal/x/x_test.go", string(lines(
		`package x`,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/acceptance/b.bats: "three" -> TestThree`,
		`func TestOne(t *testing.T)   {}`,
		`func TestThree(t *testing.T) {}`,
		`func TestSame(t *testing.T)  {}`,
	)))
	e2eWrite(t, root, "internal/x/ext_test.go", string(lines(
		`package x_test`,
		`// PORTED: tests/unit/a.bats: "two" -> TestSame`,
		`func TestSame(t *testing.T) {}`,
	)))
	e2eWitnesses(t, root, goList,
		[]string{"TestOne", "TestThree", "TestSame", "TestSame"}, "x_test.go", "ext_test.go")
	if err := e2eRun(root, goList); err != nil {
		t.Fatalf("a tree whose external test package declares its own TestSame failed the audit: %v", err)
	}

	// NOW DELETE THE EXTERNAL DECLARATION AND KEEP ITS CLAIM. Row "two" is covered by nothing:
	// what remains is a namesake in a DIFFERENT package, which no claim in x_test ever named.
	e2eWrite(t, root, "internal/x/ext_test.go", string(lines(
		`package x_test`,
		`// PORTED: tests/unit/a.bats: "two" -> TestSame`,
	)))
	e2eWitnesses(t, root, goList,
		[]string{"TestOne", "TestThree", "TestSame"}, "x_test.go", "ext_test.go")
	err := e2eRun(root, goList)
	if err == nil {
		t.Fatal("the audit passed after the claimed EXTERNAL TestSame was deleted — the internal namesake answered for it, so a bats row is now covered by nothing and the parity gate exits 0")
	}
	if !strings.Contains(err.Error(), "TestSame") {
		t.Fatalf("the failure does not name the target that stopped existing: %v", err)
	}
}

// sited stamps every claim with the compiled-test-package kind of the file it is written in — what
// collectInventory does from the toolchain's own file selection. The fixtures build claims directly,
// so they say it directly.
func sited(cs []claim, k fileKind) []claim {
	for i := range cs {
		cs[i].Site = k
	}
	return cs
}

// TWO SAME-NAMED DECLARATIONS REFUSE; THEY DO NOT ELECT ONE. `x` and `x_test` may each declare
// TestShared, and a claim that names neither cannot be about one of them — accepting either is how
// the deleted one keeps its claim green, which is the whole family of defects this program exists
// to prevent, reappearing inside the program.
func TestSameNamedInternalAndExternalDeclarationsRefuseRatherThanPickOne(t *testing.T) {
	const w = "mythicalos.ai/ctl/internal/w"
	both := func() testLane {
		src := srcOf(map[testPkg][]string{
			{Path: "mythicalos.ai/ctl/internal/x"}: {"TestOne", "TestThree"},
			{Path: w}:                              {"TestShared"},
			{Path: w, External: true}:              {"TestShared"},
		})
		// The listing prints it TWICE for that package, because two tests really are registered.
		list := listOf(map[string][]string{
			"mythicalos.ai/ctl/internal/x": {"TestOne", "TestThree"},
			w:                              {"TestShared", "TestShared"},
		})
		return withExec(testLane{name: "default", list: list, src: src})
	}

	// A BARE PATH QUALIFIER NAMES THE IMPORT PATH AND NOT A HALF OF IT, so with a namesake in each
	// half it is ambiguous — and ambiguity refuses.
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r := &report{}
	auditCoverage(r, tiny, sited(c, fileInternalTest), b, st, withExecAll([]testLane{both()}), noPreDeclared)
	if !hasProblem(r, "is declared 2 times") {
		t.Fatalf("a target declared in BOTH the package and its external test package was resolved against one of them: %v", r.Problems)
	}

	// AND THERE IS A SPELLING THAT SAYS WHICH: `x_test` is the external test package's real path,
	// so a refusal is a question the author can answer rather than a dead end.
	ext, b2, st2 := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w_test.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r2 := &report{}
	auditCoverage(r2, tiny, sited(ext, fileInternalTest), b2, st2, withExecAll([]testLane{both()}), noPreDeclared)
	if hasProblem(r2, "TestShared") {
		t.Fatalf("the external half named by its own path did not resolve: %v", r2.Problems)
	}

	// ...AND IT RESOLVES AGAINST THAT HALF ONLY. Delete the external declaration — leaving the
	// internal namesake, exactly the arrangement that used to keep the claim green — and the claim
	// must fail.
	gone := withExec(testLane{name: "default",
		list: listOf(map[string][]string{
			"mythicalos.ai/ctl/internal/x": {"TestOne", "TestThree"},
			w:                              {"TestShared"},
		}),
		src: srcOf(map[testPkg][]string{
			{Path: "mythicalos.ai/ctl/internal/x"}: {"TestOne", "TestThree"},
			{Path: w}:                              {"TestShared"},
		})})
	ext2, b3, st3 := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w_test.TestShared`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	)
	r3 := &report{}
	auditCoverage(r3, tiny, sited(ext2, fileInternalTest), b3, st3, withExecAll([]testLane{gone}), noPreDeclared)
	if !hasProblem(r3, "TestShared") {
		t.Fatalf("a claim on the EXTERNAL TestShared stayed green after it was deleted, answered by the internal namesake: %v", r3.Problems)
	}
}

// AN UNQUALIFIED CLAIM BINDS TO THE COMPILED TEST PACKAGE IT IS WRITTEN IN. The same claim text, in
// the same directory, resolves differently depending on which of the directory's two test packages
// its file belongs to — because those are two packages, and a test in one is invisible to the other.
func TestAnUnqualifiedClaimBindsToTheTestPackageItIsWrittenIn(t *testing.T) {
	const x = "mythicalos.ai/ctl/internal/x"
	// Only the EXTERNAL half declares TestTwo.
	ln := withExec(testLane{name: "default",
		list: listOf(map[string][]string{x: {"TestOne", "TestTwo", "TestThree"}}),
		src: srcOf(map[testPkg][]string{
			{Path: x}:                 {"TestOne", "TestThree"},
			{Path: x, External: true}: {"TestTwo"},
		})})
	body := []string{
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	}

	// Written in the EXTERNAL test file: TestTwo is its own package's, and resolves.
	c, b, st := claimsFrom(t, body...)
	r := &report{}
	auditCoverage(r, tiny, sited(c, fileExternalTest), b, st, withExecAll([]testLane{ln}), noPreDeclared)
	if hasProblem(r, "TestTwo") {
		t.Fatalf("a claim in the external test file did not resolve against its OWN package: %v", r.Problems)
	}

	// Written in the IN-PACKAGE test file: the same text names a test that package does not have.
	c2, b2, st2 := claimsFrom(t, body...)
	r2 := &report{}
	auditCoverage(r2, tiny, sited(c2, fileInternalTest), b2, st2, withExecAll([]testLane{ln}), noPreDeclared)
	if !hasProblem(r2, "which is a DIFFERENT package") {
		t.Fatalf("a claim in `package x` was answered by a declaration in `package x_test`: %v", r2.Problems)
	}
}

// THE TWO WITNESSES MUST AGREE ON HOW MANY, not merely on whether. The listing prints one line per
// registered test, so a count that does not match the declarations means one half is describing a
// world the other does not — an extra line is something a package PRINTED during the listing run
// (the list witness is stdout), a missing one is a declaration the toolchain never registered.
// Either way no lane can say which test a claim is about.
func TestTheTwoWitnessesMustAgreeOnHowManyTestsCarryAName(t *testing.T) {
	const x = "mythicalos.ai/ctl/internal/x"
	body := []string{
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> TestTwo`,
		`// PORTED: tests/unit/b.bats: "one" -> TestThree`,
	}
	// One declaration, TWO listed lines: something printed the name.
	printed := withExec(testLane{name: "default",
		list: listOf(map[string][]string{x: {"TestOne", "TestTwo", "TestTwo", "TestThree"}}),
		src:  srcOf(map[testPkg][]string{{Path: x}: {"TestOne", "TestTwo", "TestThree"}})})
	c, b, st := claimsFrom(t, body...)
	r := &report{}
	auditCoverage(r, tiny, sited(c, fileInternalTest), b, st, withExecAll([]testLane{printed}), noPreDeclared)
	if !hasProblem(r, "disagree about how many") {
		t.Fatalf("a name listed more times than it is declared resolved anyway: %v", r.Problems)
	}

	// TWO declarations, ONE listed line: the toolchain registered one of them and this program
	// cannot know which — so a claim that binds to one of the two is a guess.
	half := withExec(testLane{name: "default",
		list: listOf(map[string][]string{x: {"TestOne", "TestTwo", "TestThree"}}),
		src: srcOf(map[testPkg][]string{
			{Path: x}:                 {"TestOne", "TestTwo", "TestThree"},
			{Path: x, External: true}: {"TestTwo"},
		})})
	c2, b2, st2 := claimsFrom(t, body...)
	r2 := &report{}
	auditCoverage(r2, tiny, sited(c2, fileInternalTest), b2, st2, withExecAll([]testLane{half}), noPreDeclared)
	if !hasProblem(r2, "disagree about how many") {
		t.Fatalf("a name declared twice but listed once resolved anyway: %v", r2.Problems)
	}
}

// A TEST FILE IS CROSS-CHECKED AGAINST ITS OWN `package` CLAUSE. `go list` sorts a test file into
// TestGoFiles or XTestGoFiles by exactly that clause, so the file can be asked independently — and
// reading the two fields in the wrong order, the single likeliest way to merge the two test packages
// again while every count in this program still balances, stops being silent.
func TestATestFileIsHeldAgainstItsOwnPackageClause(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "internal", "x")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, clause string) string {
		p := filepath.Join(pkg, name)
		if err := os.WriteFile(p, lines("package "+clause, "", `import "testing"`, "", "func TestReal(t *testing.T) {}"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	internal, external := write("x_test.go", "x"), write("ext_test.go", "x_test")
	const x = "mythicalos.ai/ctl/internal/x"

	// The right way round is accepted, and the two halves stay apart.
	got, err := collectLaneSource(map[string]pkgFiles{x: {Dir: pkg, Test: []string{internal}, XTest: []string{external}}})
	if err != nil {
		t.Fatalf("a correctly-sorted package was refused: %v", err)
	}
	in := got[testPkg{Path: x}]["TestReal"]
	ex := got[testPkg{Path: x, External: true}]["TestReal"]
	if len(in) != 1 || len(ex) != 1 {
		t.Fatalf("two same-named declarations did not survive as two: internal %v, external %v", in, ex)
	}
	if in[0].PkgName != "x" || ex[0].PkgName != "x_test" {
		t.Fatalf("the parsed package clause was not kept: internal %q, external %q", in[0].PkgName, ex[0].PkgName)
	}
	if in[0].File != internal || ex[0].File != external {
		t.Fatalf("a declaration did not keep its own location: internal %q, external %q", in[0].File, ex[0].File)
	}

	// THE TWO LISTS READ IN THE WRONG ORDER. Every count still balances — one declaration in each
	// half, both names listed — and the clauses say it is wrong.
	_, err = collectLaneSource(map[string]pkgFiles{x: {Dir: pkg, Test: []string{external}, XTest: []string{internal}}})
	if err == nil {
		t.Fatal("the two test file lists were read in the wrong order and nothing noticed — which merges `x` and `x_test` back into one namespace")
	}
	if !strings.Contains(err.Error(), "wrong order") {
		t.Fatalf("the refusal does not name the defect: %v", err)
	}
}
