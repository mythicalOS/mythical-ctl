package main

import (
	"crypto/sha256"
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
	if !got[x]["TestOne"] || !got[x]["TestShared"] {
		t.Fatalf("package x: %v", got[x])
	}
	if got[x]["TestOnlyHere"] {
		t.Fatalf("a later package's name leaked into an earlier one: %v", got[x])
	}
	if !got[y]["TestShared"] || !got[y]["TestOnlyHere"] || got[y]["TestOne"] {
		t.Fatalf("package y: %v", got[y])
	}
	if got[y]["TestingNotATest"] {
		t.Fatalf("a name Go would never run was read as a test: %v", got[y])
	}
	if got[x]["BenchmarkThing"] || got[x]["ExampleThing"] {
		t.Fatalf("picked up something that is not a test: %v", got[x])
	}
	if len(got["mythicalos.ai/ctl/internal/z"]) != 0 {
		t.Fatalf("a package with no test files has names: %v", got["mythicalos.ai/ctl/internal/z"])
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
var tinyGoTests = map[string]map[string]bool{
	"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestTwo": true, "TestThree": true},
	"mythicalos.ai/ctl/internal/w": {"TestElsewhere": true, "TestOne": true},
}

// The SOURCE half of target resolution, keyed by IMPORT PATH — the same key as the list half, so
// the two can be compared within one lane. A target must appear in BOTH: `go test -list` proves the
// lane registers it, the lane's compiled test files prove that package declares it.
var tinySrcTests = map[string]map[string]bool{
	"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestTwo": true, "TestThree": true},
	"mythicalos.ai/ctl/internal/w": {"TestElsewhere": true, "TestOne": true},
}

// oneLane is the fixture as ONE lane whose two witnesses agree — the ordinary world. The tests
// that care about the pairing build their own disagreeing lanes.
func oneLane() []testLane {
	return []testLane{{name: "default", list: tinyGoTests, src: tinySrcTests}}
}

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
	// ...so it names NO Go test, rather than the real one it ends with.
	if got := testNamesIn("-> ÉTestVerifyDigest"); len(got) != 0 {
		t.Fatalf("testNamesIn(%q) = %q — a target that is not a Go test name was read as one", "-> ÉTestVerifyDigest", got)
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
		"mythicalos.ai/ctl/internal/x\t"+filepath.Join(root, "internal", "x")+"\tx_test.go\t",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, goList
}

func goFilesPath(root string) string { return filepath.Join(root, "gofiles.txt") }

func e2eRun(root, goList string) error {
	return run(root, "tests/parity-manifest.tsv", false, []string{goList}, []string{goFilesPath(root)}, 0)
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
	err := run(root, "tests/parity-manifest.tsv", false, nil, nil, 0)
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
		"\texample := \"PORTED: tests/unit/b.bats: ...\"",
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
// prose that merely mentions a package cannot, which is what TestCandidatePackagesDoesNotMineProse
// holds.
func TestAuditCoverageAcceptsACrossPackageTargetThatNamesItsPackage(t *testing.T) {
	c, b, st := claimsFrom(t,
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		`// PORTED: tests/unit/a.bats: "two" -> internal/w.TestElsewhere (recorded here for the audit)`,
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
	claims, _, st, err := parseInventory("internal/x/x_test.go", lines(
		"const fixture = `",
		`// PORTED: tests/unit/a.bats: "one" -> TestOne`,
		"`",
	))
	if err != nil {
		t.Fatal(err)
	}
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
	got := candidatePackages(goTests, "internal/x/x_test.go", "cmd/probe.TestOne", "TestOne")
	if !got["mythicalos.ai/ctl/cmd/probe"] {
		t.Fatalf("a full path did not resolve: %v", got)
	}
	if got["mythicalos.ai/ctl/internal/probe"] {
		t.Fatalf("cmd/probe resolved against internal/probe: %v", got)
	}
	// A BARE, AMBIGUOUS segment must widen nothing — an ambiguous reference is not a licence to
	// accept either answer.
	amb := candidatePackages(goTests, "internal/x/x_test.go", "probe.TestInternal", "TestInternal")
	if amb["mythicalos.ai/ctl/internal/probe"] || amb["mythicalos.ai/ctl/cmd/probe"] {
		t.Fatalf("a bare ambiguous segment widened the candidate set: %v", amb)
	}
}

// TestCandidatePackagesDoesNotMineProse: a package named in a claim's PROSE is not a reference to
// that package, and treating it as one is a false-green generator.
//
// Every path-like token anywhere in a claim was offered as a candidate, so a claim that says the
// target is NOT in some package supplied that package anyway — prose has no polarity a token regexp
// can read. The claim then resolved against a namesake there, and kept resolving after the local
// test it was really about was DELETED: the claim survives the deletion of the thing it claims,
// which is the whole failure this audit exists to prevent.
func TestCandidatePackagesDoesNotMineProse(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestShared": true},
		"mythicalos.ai/ctl/internal/x": {"TestOne": true},
	}
	// The claim's own package no longer declares TestShared (it was deleted); the prose merely
	// MENTIONS internal/w, and says the target is not there.
	got := candidatePackages(goTests, "internal/x/x_test.go", "TestShared (not internal/w; it is local)", "TestShared")
	if got["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("prose naming a package was read as a reference to it: %v", got)
	}
	if !got["mythicalos.ai/ctl/internal/x"] {
		t.Fatalf("the claiming file's own package is always a candidate: %v", got)
	}
	// A QUALIFICATION IS PER TARGET. A claim naming two tests may qualify one and not the other,
	// and the unqualified one must not borrow the qualified one's package.
	two := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestQualified": true, "TestBare": true},
		"mythicalos.ai/ctl/internal/x": {},
	}
	if c := candidatePackages(two, "internal/x/x_test.go", "internal/w.TestQualified and TestBare", "TestBare"); c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("an unqualified target borrowed another target's package: %v", c)
	}
	if c := candidatePackages(two, "internal/x/x_test.go", "internal/w.TestQualified and TestBare", "TestQualified"); !c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("an explicitly qualified target did not resolve: %v", c)
	}
}

// TestQualificationUsesGosNameGrammarNotASCII: Go test names are UNICODE, and the audit already
// owns that grammar (isGoTestName, identRune). An ASCII spelling of the name half truncates
// `TestAlphaÉ` to `TestAlpha` — the target it is compared against is the full name, so a
// legitimately qualified claim resolves against nothing and fails for a reason that has nothing to
// do with the port. The same rule the other direction: a qualifier must not match a PREFIX of a
// longer name.
func TestQualificationUsesGosNameGrammarNotASCII(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestAlphaÉ": true, "TestFooBar": true},
		"mythicalos.ai/ctl/internal/x": {},
	}
	if c := candidatePackages(goTests, "internal/x/x_test.go", "internal/w.TestAlphaÉ", "TestAlphaÉ"); !c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("a Unicode test name was not recognised as qualified: %v", c)
	}
	// A QUALIFIED LONGER NAME DOES NOT QUALIFY ITS PREFIX.
	if c := candidatePackages(goTests, "internal/x/x_test.go", "internal/w.TestFooBar", "TestFoo"); c["mythicalos.ai/ctl/internal/w"] {
		t.Fatalf("a qualification of TestFooBar was read as one of TestFoo: %v", c)
	}
	// A DOT WITH NO PACKAGE BEFORE IT QUALIFIES NOTHING — a sentence ending before the target.
	if c := candidatePackages(goTests, "internal/x/x_test.go", ".TestFooBar", "TestFooBar"); len(c) != 1 || !c["mythicalos.ai/ctl/internal/x"] {
		t.Fatalf("a bare dot supplied a package: %v", c)
	}
}

// TestTwoQualificationsOfOneTargetResolveToNothing: a claim that names TWO packages for the same
// test has said something ambiguous, and an ambiguous reference must not be answered by picking
// either. Unioning them restores the exact hole the qualification exists to close —
// `internal/w.TestShared (formerly internal/x.TestShared)` would survive the deletion of the
// internal/w test as long as internal/x still has a namesake.
func TestTwoQualificationsOfOneTargetResolveToNothing(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestShared": true},
		"mythicalos.ai/ctl/internal/x": {"TestShared": true},
	}
	got := candidatePackages(goTests, "internal/y/y_test.go",
		"internal/w.TestShared (formerly internal/x.TestShared)", "TestShared")
	if len(got) != 0 {
		t.Fatalf("two qualifications of one target were unioned into a candidate set: %v", got)
	}
	// THE SAME PACKAGE NAMED TWICE IS NOT AMBIGUOUS — it is one reference, written twice.
	same := candidatePackages(goTests, "internal/y/y_test.go",
		"internal/w.TestShared (and again internal/w.TestShared)", "TestShared")
	if !same["mythicalos.ai/ctl/internal/w"] || len(same) != 1 {
		t.Fatalf("one package named twice was treated as ambiguous: %v", same)
	}
	// TWO SPELLINGS OF ONE PACKAGE ARE ONE REFERENCE. A raw string comparison calls these
	// ambiguous and fails a legitimate claim; they must be compared as RESOLVED packages.
	spellings := candidatePackages(goTests, "internal/y/y_test.go",
		"internal/w.TestShared (that is mythicalos.ai/ctl/internal/w.TestShared)", "TestShared")
	if !spellings["mythicalos.ai/ctl/internal/w"] || len(spellings) != 1 {
		t.Fatalf("two spellings of one package were treated as ambiguous: %v", spellings)
	}
}

// TestAClaimThatWritesTheTargetBothWaysResolvesToNothing: prose has no polarity, so a claim that
// says its target is LOCAL and also spells a qualification of it has said two things, and no
// scanner can tell which was meant.
//
// `TestShared (not internal/w.TestShared; it is local)` is the shape: once a qualification
// CONSTRAINS, that sentence pins resolution to internal/w — where a namesake keeps the claim green
// after the local test it was really about is deleted. Refusing to resolve is the only honest
// answer, and it is loud: the audit reports the claim as unresolvable.
func TestAClaimThatWritesTheTargetBothWaysResolvesToNothing(t *testing.T) {
	goTests := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/w": {"TestShared": true},
		"mythicalos.ai/ctl/internal/x": {"TestShared": true},
	}
	got := candidatePackages(goTests, "internal/x/x_test.go",
		"TestShared (not internal/w.TestShared; it is local)", "TestShared")
	if len(got) != 0 {
		t.Fatalf("a claim that writes its target both bare and qualified resolved anyway: %v", got)
	}
	// A CLAIM THAT ONLY QUALIFIES IS NOT CONTRADICTORY — every real cross-package claim in this
	// tree is written that way, and this must not refuse them.
	ok := candidatePackages(goTests, "internal/x/x_test.go",
		"internal/w.TestShared (recorded here for the audit)", "TestShared")
	if !ok["mythicalos.ai/ctl/internal/w"] || len(ok) != 1 {
		t.Fatalf("an ordinary qualified claim was refused: %v", ok)
	}
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
	got := candidatePackages(goTests, "internal/x/x_test.go", "internal/w.TestShared", "TestShared")
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
	lanes := []testLane{{name: "default",
		list: map[string]map[string]bool{
			"mythicalos.ai/ctl/internal/w": {"TestOther": true},
			"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestThree": true, "TestShared": true},
		},
		src: map[string]map[string]bool{
			"mythicalos.ai/ctl/internal/w": {"TestOther": true},
			"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestThree": true, "TestShared": true},
		}}}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, lanes, noPreDeclared)
	if !hasProblem(r, "TestShared") {
		t.Fatalf("a deleted cross-package target was satisfied by a local namesake: %v", r.Problems)
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
	srcMissing := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestThree": true},
	}
	r := &report{}
	auditCoverage(r, tiny, c, b, st, []testLane{{name: "default", list: tinyGoTests, src: srcMissing}}, noPreDeclared)
	if !hasProblem(r, "TestTwo") {
		t.Fatalf("a target the source does not declare was accepted: %v", r.Problems)
	}

	// ...and the other direction: declared in source but not registered by the package (it does not
	// compile into the test binary, or lives behind a build tag nothing enables).
	listMissing := map[string]map[string]bool{
		"mythicalos.ai/ctl/internal/x": {"TestOne": true, "TestThree": true},
	}
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, []testLane{{name: "default", list: listMissing, src: tinySrcTests}}, noPreDeclared)
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
	split := []testLane{
		{name: "a", list: map[string]map[string]bool{pkg: {"TestOne": true, "TestTwo": true, "TestThree": true}},
			src: map[string]map[string]bool{pkg: {"TestOne": true, "TestThree": true}}},
		{name: "b", list: map[string]map[string]bool{pkg: {"TestOne": true, "TestThree": true}},
			src: map[string]map[string]bool{pkg: {"TestOne": true, "TestTwo": true, "TestThree": true}}},
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
		{name: "b", list: map[string]map[string]bool{pkg: {"TestOne": true, "TestTwo": true, "TestThree": true}},
			src: map[string]map[string]bool{pkg: {"TestOne": true, "TestTwo": true, "TestThree": true}}},
	}
	r2 := &report{}
	auditCoverage(r2, tiny, c, b, st, ok, noPreDeclared)
	if hasProblem(r2, "TestTwo") {
		t.Fatalf("a target both halves of ONE lane agree on was refused: %v", r2.Problems)
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
	files := map[string][]string{"mythicalos.ai/ctl/internal/x": {filepath.Join(pkg, "x_test.go")}}
	got, err := collectLaneSource(files)
	if err != nil {
		t.Fatal(err)
	}
	names := got["mythicalos.ai/ctl/internal/x"]
	if !names["TestReal"] {
		t.Fatalf("the real declaration was missed: %v", names)
	}
	for _, no := range []string{"TestInAComment", "TestInARawString", "TestAMethod"} {
		if names[no] {
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
	files["mythicalos.ai/ctl/internal/x"] = append(files["mythicalos.ai/ctl/internal/x"], filepath.Join(pkg, "broken_test.go"))
	if _, err := collectLaneSource(files); err == nil {
		t.Fatal("an unparseable _test.go was skipped rather than refused")
	} else if !strings.Contains(err.Error(), "broken_test.go") {
		t.Fatalf("the refusal does not name the file: %v", err)
	}
	_ = dir
}

// TestGoFileListIsTheToolchainsOwnSelection: the source witness is built from the files GO says
// this lane compiles, so a file the lane does not build cannot testify about it.
func TestGoFileListIsTheToolchainsOwnSelection(t *testing.T) {
	got, err := parseGoFileList([]byte(
		"mythicalos.ai/ctl/internal/x\t/abs/internal/x\ta_test.go b_test.go\tx_ext_test.go\n" +
			"mythicalos.ai/ctl/internal/y\t/abs/internal/y\t\t\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join("/abs/internal/x", "a_test.go"),
		filepath.Join("/abs/internal/x", "b_test.go"),
		filepath.Join("/abs/internal/x", "x_ext_test.go"),
	}
	if fmt.Sprint(got["mythicalos.ai/ctl/internal/x"]) != fmt.Sprint(want) {
		t.Fatalf("in-package and external test files: got %v, want %v", got["mythicalos.ai/ctl/internal/x"], want)
	}
	// A package with no test files contributes no entry — it declares nothing and must not be
	// invented as an empty witness that quietly satisfies nothing.
	if _, ok := got["mythicalos.ai/ctl/internal/y"]; ok {
		t.Fatalf("a package with no test files produced an entry: %v", got)
	}
	// A MALFORMED LINE IS REFUSED, never partially read: silently dropping a package would empty
	// that lane's source witness for it, and every claim on it would then fail for a reason that
	// has nothing to do with the port.
	if _, err := parseGoFileList([]byte("only\ttwo\n")); err == nil {
		t.Fatal("a line with the wrong field count was accepted")
	}
}

// TestPairedWitnessFlagsAreRefusedUnpaired: the two lists are ONE witness pair per lane. An
// unpaired call would reintroduce the independence the pairing removes, and it would do so
// silently — so it is refused up front rather than resolved against whatever happened to line up.
func TestPairedWitnessFlagsAreRefusedUnpaired(t *testing.T) {
	tinyLanes(t, 2, 1, 2)
	root, goList := e2eTree(t)
	err := run(root, "tests/parity-manifest.tsv", false, []string{goList}, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "must be given in the same number") {
		t.Fatalf("err = %v, want a refusal naming the unpaired witnesses", err)
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
	// ...and extraction keeps the WHOLE identifier rather than its ASCII prefix.
	if got := testNamesIn("-> TestAlphaÉ (and TestBeta)"); len(got) != 2 || got[0] != "TestAlphaÉ" || got[1] != "TestBeta" {
		t.Fatalf("testNamesIn truncated or dropped a target: %q", got)
	}
	// The list reader applies it too...
	got := parseGoTestList(lines(
		`TestReal`,
		`Testfoo`,
		`ok  	mythicalos.ai/ctl/internal/x	0.001s`,
	))
	x := got["mythicalos.ai/ctl/internal/x"]
	if !x["TestReal"] {
		t.Fatalf("the real name was dropped: %v", x)
	}
	if x["Testfoo"] {
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
	sf, err := collectLaneSource(map[string][]string{xpkg: {filepath.Join(pkg, "x_test.go")}})
	if err != nil {
		t.Fatal(err)
	}
	if !sf[xpkg]["TestReal"] || sf[xpkg]["Testfoo"] {
		t.Fatalf("the source witness does not apply Go's grammar: %v", sf[xpkg])
	}
	_ = dir
}
