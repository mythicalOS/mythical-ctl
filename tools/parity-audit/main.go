// parity-audit — the machine half of the bash→Go port parity proof.
//
// WHAT THIS PROGRAM IS FOR. The bash tree is the SPECIFICATION of this CLI, and the port is
// finished by DELETING it. The only evidence that the deletion loses nothing is that every
// behaviour the bash suite pinned is accounted for in the Go suite — so every Go test file carries
// an inventory line per bats test it accounts for:
//
//	// PORTED: tests/unit/<file>.bats: "<exact test name>" -> TestGoFunc
//	// N/A:    tests/unit/<file>.bats: "<exact test name>" -- <why this cannot/need not port>
//
// and this program checks that those lines cover the corpus EXACTLY ONCE each, and that every
// PORTED target names a Go test that really exists.
//
// WHY IT IS A PROGRAM AND NOT A REPORT. A one-time audit protects nothing after the day it runs.
// This one is a check.sh stage (`bash check.sh parity`), in CI, so the claim is re-proved on every
// change rather than asserted once in a commit message.
//
// WHY IT SURVIVES THE THING IT AUDITS. After the cutover the bats trees are gone, so there is
// nothing left to regenerate from — which is exactly why tests/parity-manifest.tsv is COMMITTED.
// While the trees exist the manifest is regenerated and byte-compared against the committed copy
// (so neither the frozen tree nor the manifest can drift without a red); once they are gone the
// committed manifest IS the corpus, and every other check still runs against it unchanged.
//
// THE COUNTS ARE ASSERTED BEFORE ANYTHING ELSE, AND THAT ORDER IS THE POINT. A parser that matches
// nothing makes every "all claimed" loop vacuously true and turns the whole audit into a green
// no-op — this family has shipped that exact failure before. So the corpus size is pinned to exact
// literals, per lane and per file count, and checked FIRST; a coverage loop only ever runs over a
// corpus whose size has already been proved.
//
// A NOTE ON READING THIS PROGRAM'S OWN TEST. main_test.go builds inventory-line fixtures as slices
// of QUOTED strings, never as multi-line raw literals, so no line of it begins with `//` followed
// by PORTED:/N/A: and the scanner below cannot mistake a fixture for a real claim. That constraint
// is self-proving: a fixture written the other way would be scanned as a claim naming a bats test
// that does not exist, and the audit over this repository would go red naming the file.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// The pinned corpus size. Exact literals, not floors: the bash tree is FROZEN for the whole port,
// so a changed count means either the freeze was broken or the parser stopped seeing tests it used
// to see. Both are worth a red, and both are invisible without a number to disagree with.
// ---------------------------------------------------------------------------------------------

const (
	wantUnitTests       = 1122
	wantAcceptanceTests = 56
	batsFilesInCorpus   = 34
)

type lane struct {
	prefix string
	want   int
}

// The lanes, in the order they are reported. A bats file outside these two prefixes is a corpus
// the audit does not know how to count, and is refused rather than silently ignored.
//
// VARIABLES, NOT CONSTANTS, FOR ONE REASON: the end-to-end tests drive run() over a synthetic tree
// of three tests, and a run() that could only ever be exercised against the real 1,178 could not be
// shown to FAIL at all — which is the property that matters most about an audit. They are restored
// by t.Cleanup, and TestPinnedCorpusSizeIsThePlansNumbers asserts the shipped values, so the pin is
// still a pin.
var (
	lanes         = []lane{{"tests/unit/", wantUnitTests}, {"tests/acceptance/", wantAcceptanceTests}}
	wantBatsFiles = batsFilesInCorpus
)

// THE TWO PRE-DECLARED WHOLE-FILE N/A FILES, with the argument each rests on. Recorded here rather
// than in a commit message because the audit PRINTS them on every run: a whole file waved away is
// the largest single hole this inventory can have, so it is stated out loud every time, and any
// OTHER file that ends up entirely N/A fails the audit.
//
// A file listed here needs no per-test inventory line — its argument is about the FILE, not about
// each test in it, and 11 copies of one argument would only make the argument look like eleven
// facts. The other direction is enforced instead: a per-test claim naming one of these files is a
// contradiction (someone ported a row from a file declared un-portable), and it fails.
//
// It is a var only so the end-to-end tests can drive run() over a synthetic corpus that has neither
// of these files; the shipped contents are asserted by TestTheOnlyWholeFileNAsAreTheTwoPreDeclaredOnes.
var wholeFileNA = map[string]string{
	"tests/unit/bundle.bats": "it tests tools/bundle.sh's inline-the-modules mechanism, which retires with the bundler; " +
		"the successor property is the release lane's build-twice byte-identical digest comparison (bash check.sh release)",
	"tests/unit/test_hygiene.bats": "it polices the bats harness's own conventions; the Go suite's equivalent police is " +
		"check.sh go's package-count and tested-package floors plus its gofmt and vet stages",
}

// ---------------------------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------------------------

// batsPair identifies ONE bats test: the file that defines it and its exact name. The identity is
// the PAIR, never the name alone — six test descriptions recur across different bats files, so a
// name-keyed inventory would let one line silently satisfy several distinct tests.
type batsPair struct {
	File string
	Name string
}

// batsTestLine is the bats grammar this corpus actually uses, anchored on both sides. Every @test
// line in the frozen tree matches it (verified); a line that does not is reported rather than
// skipped, because a skipped definition is a test that vanishes from the corpus silently.
var batsTestLine = regexp.MustCompile(`^@test "(.*)" \{$`)

var batsAnyTestLine = regexp.MustCompile(`^@test\b`)

// parseBats extracts the test names defined in one bats file, in file order. A line that starts a
// test but does not match the exact grammar is returned as an error: the corpus count is a load
// bearing number, and a name this parser cannot read is a name the inventory cannot claim.
func parseBats(rel string, content []byte) ([]string, error) {
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		m := batsTestLine.FindStringSubmatch(text)
		if m == nil {
			if batsAnyTestLine.MatchString(text) {
				return nil, fmt.Errorf("%s:%d: @test line does not match the parsed grammar: %s", rel, line, text)
			}
			continue
		}
		if strings.ContainsAny(m[1], "\t") {
			return nil, fmt.Errorf("%s:%d: test name contains a TAB, which the manifest uses as its field separator", rel, line)
		}
		names = append(names, m[1])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return names, nil
}

// collectBats walks the two lanes and returns the corpus in manifest order: files sorted by path,
// tests in the order the file defines them.
func collectBats(root string) ([]batsPair, error) {
	var files []string
	for _, lane := range lanes {
		dir := filepath.Join(root, filepath.FromSlash(lane.prefix))
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".bats") {
				return nil
			}
			r, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			files = append(files, filepath.ToSlash(r))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	var pairs []batsPair
	for _, rel := range files {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		names, err := parseBats(rel, content)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			pairs = append(pairs, batsPair{File: rel, Name: n})
		}
	}
	return pairs, nil
}

// manifestHeader is emitted verbatim by renderManifest, so a regeneration reproduces the committed
// file byte for byte. Comment lines are ignored on read.
const manifestHeader = `# mythical-ctl bats parity manifest — GENERATED by tools/parity-audit, do not hand-edit.
#
# One line per @test in the frozen bats corpus: <bats file><TAB><exact test name>. Files sorted by
# path; tests in the order their file defines them.
#
# WHY THIS FILE IS COMMITTED. The cutover deletes the bats trees. Everything that proves the port
# lost nothing is keyed on these pairs, so the corpus has to outlive its source: after the deletion
# this file IS the corpus the audit resolves the Go tree's PORTED:/N/A: inventory lines against.
# While the trees still exist the audit regenerates this listing and requires it to match this file
# byte for byte, so neither the frozen tree nor this manifest can drift without a red.
`

func renderManifest(pairs []batsPair) []byte {
	var b bytes.Buffer
	b.WriteString(manifestHeader)
	for _, p := range pairs {
		fmt.Fprintf(&b, "%s\t%s\n", p.File, p.Name)
	}
	return b.Bytes()
}

func parseManifest(content []byte) ([]batsPair, error) {
	var pairs []batsPair
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		file, name, ok := strings.Cut(text, "\t")
		if !ok || file == "" || name == "" {
			return nil, fmt.Errorf("manifest:%d: not a <file>TAB<name> row: %q", line, text)
		}
		pairs = append(pairs, batsPair{File: file, Name: name})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pairs, nil
}

// ---------------------------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------------------------

type claimKind int

const (
	claimPorted claimKind = iota
	claimNA
)

func (k claimKind) String() string {
	if k == claimPorted {
		return "PORTED"
	}
	return "N/A"
}

type claim struct {
	Kind    claimKind
	Pair    batsPair
	Detail  string // the Go target expression (PORTED) or the argument (N/A)
	GoFile  string
	GoLine  int
	Targets []string // PORTED only: the Go test function names named by Detail
}

// The inventory grammar. Leading whitespace is tolerated (one claim in the tree sits indented
// beside the test it describes) but the comment marker must open the line: a `// PORTED:` inside a
// Go string literal is not a claim, and anchoring here is what keeps it from being read as one.
var (
	invAny = regexp.MustCompile(`^[ \t]*//[ \t]*(PORTED|N/A):`)
	// A claim written where the parser does not look. Found once for real: a PORTED: line wrapped
	// into the middle of a paragraph, naming rows that another file had meanwhile marked N/A — two
	// statements about the same row, one of them invisible to every gate. Deliberately narrow: it
	// fires only when the mention names a bats file the CORPUS actually holds, so this program's
	// own documentation and fixtures (which name tests/unit/<file>.bats and tests/unit/a.bats) are
	// not swept up, and neither is prose about the convention.
	invStray  = regexp.MustCompile(`(PORTED|N/A):[ \t]+(tests/[A-Za-z0-9_./-]+\.bats)`)
	invPorted = regexp.MustCompile(`^[ \t]*// PORTED:[ \t]+(\S+):[ \t]+"(.+)"[ \t]+->[ \t]+(.*\S)[ \t]*$`)
	invNA     = regexp.MustCompile(`^[ \t]*// N/A:[ \t]+(\S+):[ \t]+"(.+)"[ \t]+--[ \t]+(.*\S)[ \t]*$`)
	goTestID  = regexp.MustCompile(`\bTest[A-Za-z0-9_]*`)
)

// minNAReason is a substance floor, not a style rule. "N/A -- n/a" satisfies a syntax check and
// argues nothing; the protocol requires a real reason, and a reason shorter than this cannot be
// one. It is deliberately low — the judgement of whether a reason is TRUE is a reviewer's, and no
// program can make it.
const minNAReason = 16

// AN N/A THAT DEFERS TO A FUTURE EVENT IS A TODO, NOT AN ARGUMENT — and it is the one thing about a
// rationale a program CAN check. Measured on this tree: four N/A rows rested on "the verb it names
// is not wired in this build" and "re-claim once that verb lands". Every one of those premises had
// expired — the verbs landed a wave earlier — and nothing noticed, because the audit was checking
// that each row was CLAIMED, never that its claim still held. A deferral is a promise with no
// expiry date attached; refusing the phrasing forces the promise to be an argument that is true
// now, or an unclaimed row that fails loudly the moment the reason stops being true.
//
// Deliberately phrase-level, not word-level: "later" appears innocently inside real arguments
// ("every later step consumes that byte slice"), and a check that fires on prose nobody can rewrite
// is a check somebody turns off.
var naDeferrals = []string{
	"re-claim",
	"reclaim once",
	"not wired",
	"once that verb lands",
	"once the verb lands",
	"once it lands",
	"once that lands",
	"when that lands",
	"lands with",
	"not yet wired",
	"not yet landed",
	"does not exist yet",
	"not available yet",
	"in a later wave",
	"a future wave",
	"a future task",
	"todo",
	"tbd",
}

// deferral reports the first future-tense promise in an N/A argument, or "".
func deferral(reason string) string {
	low := strings.ToLower(reason)
	for _, p := range naDeferrals {
		if strings.Contains(low, p) {
			return p
		}
	}
	return ""
}

type malformed struct {
	GoFile string
	GoLine int
	Text   string
}

// stray is a claim-shaped mention the parser cannot read because of where it sits.
type stray struct {
	GoFile   string
	GoLine   int
	BatsFile string
	Text     string
}

// parseInventory reads one Go file's claims. Anything that opens like an inventory line but does
// not parse is returned as malformed rather than skipped — a claim the audit cannot read is a
// claim nobody is checking, which is the same as no claim at all but looks like coverage.
func parseInventory(rel string, content []byte) ([]claim, []malformed, []stray, error) {
	var claims []claim
	var bad []malformed
	var strays []stray
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if !invAny.MatchString(text) {
			// Not in claim position. If it nevertheless names a real corpus file in claim syntax,
			// somebody wrote a claim the audit cannot see — record it and let auditCoverage decide,
			// since only it knows what the corpus holds.
			//
			// NO COMMENT-MARKER PRECONDITION, DELIBERATELY. An earlier version required `//` on the
			// line, which left a block comment — `/* PORTED: <a real corpus row> -> TestX */` — as a
			// place a second claim on an already-claimed row could sit permanently invisible, and the
			// exactly-once guarantee is worth exactly as much as its least-visible hiding place. The
			// corpus-file scoping below is what keeps this narrow: a mention naming a bats file the
			// corpus does not hold (this program's own `tests/unit/<file>.bats` documentation, its
			// fixtures' `tests/unit/a.bats`) is not swept up, whatever syntax surrounds it.
			if m := invStray.FindStringSubmatch(text); m != nil {
				strays = append(strays, stray{rel, line, m[2], text})
			}
			continue
		}
		if m := invPorted.FindStringSubmatch(text); m != nil {
			targets := goTestID.FindAllString(m[3], -1)
			if len(targets) == 0 {
				bad = append(bad, malformed{rel, line, text})
				continue
			}
			claims = append(claims, claim{
				Kind: claimPorted, Pair: batsPair{File: m[1], Name: m[2]},
				Detail: m[3], GoFile: rel, GoLine: line, Targets: targets,
			})
			continue
		}
		if m := invNA.FindStringSubmatch(text); m != nil {
			if len(strings.TrimSpace(m[3])) < minNAReason {
				bad = append(bad, malformed{rel, line, text})
				continue
			}
			if d := deferral(m[3]); d != "" {
				bad = append(bad, malformed{rel, line,
					fmt.Sprintf("its argument defers to a future event (%q) — an N/A that waits for something to land is a TODO, not an argument: it expires silently the moment the blocker lands and nothing notices. Port the row, or argue why it can never be ported. || %s", d, text)})
				continue
			}
			claims = append(claims, claim{
				Kind: claimNA, Pair: batsPair{File: m[1], Name: m[2]},
				Detail: m[3], GoFile: rel, GoLine: line,
			})
			continue
		}
		bad = append(bad, malformed{rel, line, text})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", rel, err)
	}
	return claims, bad, strays, nil
}

// skipDirs are not part of this module's source. third_party is a vendored submodule; dist is
// build output. Neither can carry a claim, and walking them only creates ways to be wrong.
var skipDirs = map[string]bool{".git": true, "third_party": true, "dist": true, "node_modules": true}

func collectInventory(root string) ([]claim, []malformed, []stray, int, error) {
	var claims []claim
	var bad []malformed
	var strays []stray
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		content, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		scanned++
		c, b, st, perr := parseInventory(filepath.ToSlash(rel), content)
		if perr != nil {
			return perr
		}
		claims = append(claims, c...)
		bad = append(bad, b...)
		strays = append(strays, st...)
		return nil
	})
	return claims, bad, strays, scanned, err
}

// parseGoTestList reads `go test -list '.*' ./...` output. Only bare Test identifiers count: the
// stream also carries `ok  <pkg>  0.001s`, `?  <pkg> [no test files]`, Benchmark/Fuzz/Example
// names, and build chatter.
func parseGoTestList(content []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		t := strings.TrimRight(sc.Text(), "\r")
		if m := goTestID.FindString(t); m == t && t != "" {
			out[t] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------------------------

type report struct {
	Problems    []string
	Files       int
	Tests       int
	Ported      int
	NA          int
	WholeFileNA int
	Lanes       map[string]int
}

func (r *report) fail(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// assertCorpus pins the size of the corpus BEFORE anything is checked about its coverage. It
// returns false when the corpus is not the one this audit was written against, and every caller
// stops there: a coverage loop over a corpus of unknown size proves nothing, and proves it green.
func assertCorpus(r *report, pairs []batsPair) bool {
	fileSet := map[string]bool{}
	laneCount := map[string]int{}
	for _, p := range pairs {
		fileSet[p.File] = true
		matched := false
		for _, lane := range lanes {
			if strings.HasPrefix(p.File, lane.prefix) {
				laneCount[lane.prefix]++
				matched = true
				break
			}
		}
		if !matched {
			r.fail("corpus: %s is in neither lane (%s) — the audit cannot count it", p.File, laneNames())
		}
	}
	r.Files = len(fileSet)
	r.Tests = len(pairs)
	r.Lanes = laneCount

	ok := true
	for _, lane := range lanes {
		if laneCount[lane.prefix] != lane.want {
			r.fail("corpus: %s holds %d @test rows, expected exactly %d — the frozen tree changed, or the parser stopped matching",
				lane.prefix, laneCount[lane.prefix], lane.want)
			ok = false
		}
	}
	if len(fileSet) != wantBatsFiles {
		r.fail("corpus: %d bats files, expected exactly %d — a whole file appearing or vanishing changes what 'fully claimed' means",
			len(fileSet), wantBatsFiles)
		ok = false
	}
	// Duplicate rows would let one claim satisfy two corpus entries and inflate coverage.
	seen := map[batsPair]bool{}
	for _, p := range pairs {
		if seen[p] {
			r.fail("corpus: %s defines %q twice — the inventory cannot address the two separately", p.File, p.Name)
			ok = false
		}
		seen[p] = true
	}
	return ok
}

func laneNames() string {
	var n []string
	for _, lane := range lanes {
		n = append(n, lane.prefix)
	}
	return strings.Join(n, ", ")
}

// auditCoverage is the whole claim under audit: every bats test is accounted for EXACTLY ONCE, no
// claim names a test that does not exist, every PORTED target is a Go test that really runs, and
// no file is waved away wholesale except the two that were pre-declared with an argument.
func auditCoverage(r *report, pairs []batsPair, claims []claim, bad []malformed, strays []stray, goTests map[string]bool, preDeclared map[string]string) {
	for _, b := range bad {
		r.fail("%s:%d: inventory line does not parse (or its N/A argues nothing): %s", b.GoFile, b.GoLine, strings.TrimSpace(b.Text))
	}

	corpus := map[batsPair]bool{}
	perFile := map[string][]batsPair{}
	for _, p := range pairs {
		corpus[p] = true
		perFile[p.File] = append(perFile[p.File], p)
	}

	// A claim about a real corpus file, written somewhere the parser does not read. It states
	// something about a row that some OTHER line is meanwhile claiming, and the two can disagree
	// forever because only one of them is checked.
	for _, s := range strays {
		if len(perFile[s.BatsFile]) == 0 {
			continue
		}
		r.fail("%s:%d: a PORTED:/N/A: claim about %s is written mid-line, where the inventory parser does not read it — put it at the start of its own comment line, or say it in prose that does not use the claim syntax: %s",
			s.GoFile, s.GoLine, s.BatsFile, strings.TrimSpace(s.Text))
	}

	byPair := map[batsPair][]claim{}
	for _, c := range claims {
		switch c.Kind {
		case claimPorted:
			r.Ported++
		case claimNA:
			r.NA++
		}
		byPair[c.Pair] = append(byPair[c.Pair], c)
	}

	// A claim naming something outside the corpus. Two shapes, both fatal: a test name that was
	// paraphrased or truncated instead of copied byte-exactly (so the real test is left unclaimed
	// while the line LOOKS like coverage), and a claim against a file the corpus does not hold.
	for _, c := range claims {
		if !corpus[c.Pair] {
			r.fail("%s:%d: %s claims %s: %q — no such test in the corpus (copy the @test name byte-exactly; a claim outside the bats corpus is not machine-checkable and must not use this syntax)",
				c.GoFile, c.GoLine, c.Kind, c.Pair.File, c.Pair.Name)
		}
	}

	// Exactly once. Not at least once: a test claimed twice usually means one of the two claims is
	// wrong, and the wrong one is invisible while the right one keeps the pair covered.
	for _, p := range pairs {
		cs := byPair[p]
		if _, pre := preDeclared[p.File]; pre {
			// The file is declared un-portable as a whole. A per-test claim on it is not extra
			// diligence, it is a disagreement with the declaration — one of the two is wrong.
			if len(cs) > 0 {
				r.fail("%s:%d: %s claims %s: %q, but that whole file is pre-declared N/A in tools/parity-audit — the claim and the pre-declaration cannot both be right",
					cs[0].GoFile, cs[0].GoLine, cs[0].Kind, p.File, p.Name)
			}
			r.WholeFileNA++
			continue
		}
		switch {
		case len(cs) == 0:
			r.fail("%s: %q is claimed by NO inventory line", p.File, p.Name)
		case len(cs) > 1:
			var where []string
			for _, c := range cs {
				where = append(where, fmt.Sprintf("%s:%d (%s)", c.GoFile, c.GoLine, c.Kind))
			}
			r.fail("%s: %q is claimed %d times: %s", p.File, p.Name, len(cs), strings.Join(where, ", "))
		}
	}

	// Every PORTED target must be a test that actually runs. A checklist comment with no live test
	// behind it is the failure this whole inventory exists to prevent, wearing the inventory's own
	// clothes.
	for _, c := range claims {
		if c.Kind != claimPorted {
			continue
		}
		for _, t := range c.Targets {
			if !goTests[t] {
				r.fail("%s:%d: PORTED target %s does not exist — no such test in `go test -list` output (claim: %s: %q)",
					c.GoFile, c.GoLine, t, c.Pair.File, c.Pair.Name)
			}
		}
	}

	// A whole file waved away. Allowed for exactly the pre-declared files, each with its argument
	// printed on every run; anywhere else it is the largest hole this inventory can have, and it
	// fails.
	for file, ps := range perFile {
		if _, pre := preDeclared[file]; pre {
			continue // already excluded from the exactly-once check above
		}
		allNA := true
		for _, p := range ps {
			cs := byPair[p]
			if len(cs) != 1 || cs[0].Kind != claimNA {
				allNA = false
				break
			}
		}
		if allNA {
			r.fail("%s: all %d tests are N/A — a wholesale-N/A file needs a pre-declared argument in tools/parity-audit", file, len(ps))
		}
	}
	// ...and the pre-declaration may not name a file the corpus does not have, or the argument
	// would be protecting nothing.
	for file := range preDeclared {
		if len(perFile[file]) == 0 {
			r.fail("tools/parity-audit pre-declares %s as N/A in full, but the corpus has no such file", file)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var (
		root      = flag.String("root", ".", "repository root")
		manifest  = flag.String("manifest", "tests/parity-manifest.tsv", "the committed corpus manifest, relative to -root")
		writeMan  = flag.Bool("write-manifest", false, "regenerate the manifest from the bats trees and write it, instead of auditing")
		goLists   listFlag
		failFirst = flag.Int("max-problems", 0, "print at most this many problems (0 = all)")
	)
	flag.Var(&goLists, "go-list", "file holding `go test -list` output; repeatable (once per build-tag lane)")
	flag.Parse()

	if err := run(*root, *manifest, *writeMan, goLists, *failFirst); err != nil {
		fmt.Fprintf(os.Stderr, "parity-audit: %v\n", err)
		os.Exit(1)
	}
}

func run(root, manifestRel string, writeMan bool, goLists []string, maxProblems int) error {
	manifestPath := filepath.Join(root, filepath.FromSlash(manifestRel))

	// Is the bash tree still here? Both lanes or neither. A half-deleted tree would regenerate a
	// short manifest, and "half the corpus" is exactly the state a byte-compare must not be asked
	// to interpret.
	present := 0
	for _, lane := range lanes {
		if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(lane.prefix))); err == nil && st.IsDir() {
			present++
		}
	}
	if present != 0 && present != len(lanes) {
		return fmt.Errorf("%d of %d bats lanes exist (%s) — a half-present bash tree is neither the pre-cutover nor the post-cutover state; refusing to guess",
			present, len(lanes), laneNames())
	}
	live := present == len(lanes)

	if writeMan {
		if !live {
			return fmt.Errorf("--write-manifest needs the bats trees, and they are gone; the committed manifest IS the corpus now")
		}
		pairs, err := collectBats(root)
		if err != nil {
			return err
		}
		r := &report{}
		if !assertCorpus(r, pairs) {
			return fmt.Errorf("refusing to write a manifest for a corpus that is not the pinned one:\n  %s", strings.Join(r.Problems, "\n  "))
		}
		if err := os.WriteFile(manifestPath, renderManifest(pairs), 0o644); err != nil {
			return err
		}
		fmt.Printf("parity-audit: wrote %s (%d tests across %d files)\n", manifestRel, r.Tests, r.Files)
		return nil
	}

	committed, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading the committed manifest: %w", err)
	}
	pairs, err := parseManifest(committed)
	if err != nil {
		return err
	}

	r := &report{}
	// COUNTS FIRST. Everything below is a loop over this corpus; a loop over a corpus of the wrong
	// size is a loop that reports green for the wrong reason.
	if !assertCorpus(r, pairs) {
		return problems(r, maxProblems)
	}

	if live {
		fresh, err := collectBats(root)
		if err != nil {
			return err
		}
		if !bytes.Equal(renderManifest(fresh), committed) {
			return fmt.Errorf("%s does not match the bats trees it was generated from.\n"+
				"   Regenerate it (go run ./tools/parity-audit --write-manifest) and read the diff: either the FROZEN bash tree changed, or the manifest was hand-edited.",
				manifestRel)
		}
		fmt.Printf("corpus: regenerated from the bats trees and byte-identical to %s\n", manifestRel)
	} else {
		fmt.Printf("corpus: bats trees absent (post-cutover) — auditing against the committed %s\n", manifestRel)
	}

	claims, bad, strays, scanned, err := collectInventory(root)
	if err != nil {
		return err
	}
	// The scan's own liveness. Zero Go files means the walk is pointed somewhere with no source in
	// it, and every claim below would be missing for a reason that has nothing to do with the port.
	if scanned == 0 {
		return fmt.Errorf("scanned 0 Go files under %s — the inventory scan is pointed at the wrong tree", root)
	}

	goTests := map[string]bool{}
	for _, p := range goLists {
		content, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading go-test list: %w", err)
		}
		for t := range parseGoTestList(content) {
			goTests[t] = true
		}
	}
	// Same liveness argument one level down: an empty set of known tests would make every PORTED
	// target unresolvable, which is loud — but an empty set arriving because nobody passed a list
	// would make it loud for the wrong reason, and the fix would be to add the flag rather than to
	// look at the port. Say so up front.
	if len(goTests) == 0 {
		return fmt.Errorf("no Go test names were loaded (pass --go-list <file> with `go test -list '.*' ./...` output) — PORTED targets cannot be resolved")
	}

	auditCoverage(r, pairs, claims, bad, strays, goTests, wholeFileNA)

	fmt.Printf("go tree: %d files scanned, %d PORTED, %d N/A, %d Go test names known\n", scanned, r.Ported, r.NA, len(goTests))
	fmt.Printf("corpus: %d tests covered by a pre-declared whole-file N/A argument\n", r.WholeFileNA)
	for _, lane := range lanes {
		fmt.Printf("corpus: %-20s %4d tests\n", lane.prefix, r.Lanes[lane.prefix])
	}
	fmt.Printf("corpus: %d bats files, %d tests total\n", r.Files, r.Tests)
	files := make([]string, 0, len(wholeFileNA))
	for f := range wholeFileNA {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		fmt.Printf("whole-file N/A (pre-declared): %s — %s\n", f, wholeFileNA[f])
	}

	if err := problems(r, maxProblems); err != nil {
		return err
	}
	fmt.Printf("parity-audit: every one of the %d bats tests is accounted for exactly once (%d PORTED, %d N/A, %d under a whole-file argument), and every PORTED target resolves\n",
		r.Tests, r.Ported, r.NA, r.WholeFileNA)
	return nil
}

func problems(r *report, maxProblems int) error {
	if len(r.Problems) == 0 {
		return nil
	}
	sort.Strings(r.Problems)
	shown := r.Problems
	if maxProblems > 0 && len(shown) > maxProblems {
		shown = shown[:maxProblems]
	}
	for _, p := range shown {
		fmt.Fprintf(os.Stderr, "  PARITY: %s\n", p)
	}
	if len(shown) < len(r.Problems) {
		fmt.Fprintf(os.Stderr, "  PARITY: ... and %d more\n", len(r.Problems)-len(shown))
	}
	// The first problem travels IN the error, not only on stderr: the caller that fails a CI job
	// often shows one line, and "N parity problem(s)" with no identity is a failure nobody can act
	// on without re-running.
	return fmt.Errorf("%d parity problem(s); first: %s", len(r.Problems), r.Problems[0])
}
