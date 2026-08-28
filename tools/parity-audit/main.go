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
	"crypto/sha256"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
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

// THE MANIFEST'S IDENTITY, NOT ONLY ITS SIZE.
//
// Counts and coverage together are not enough once the bats trees are gone. With nothing to
// regenerate from, a row could be REPLACED — an original requirement deleted and an invented one of
// the same shape put in its place, with a matching claim written beside it — and every count would
// still add up and every row would still be claimed. The audit would exit 0 over a corpus that had
// quietly lost a requirement, which is precisely the failure the whole task exists to prevent, one
// step further along.
//
// So the corpus is pinned by CONTENT. Changing tests/parity-manifest.tsv now requires changing this
// literal too — a two-place edit a reviewer sees, exactly like the owner map's prose counts. Before
// the cutover the tree itself is the second witness (the regeneration byte-compare); after it, this
// is the only one, which is why it is here rather than derived.
//
// A var only so the end-to-end tests can drive run() over a synthetic manifest; the shipped value is
// asserted by TestPinnedCorpusSizeIsThePlansNumbers, and the tests restore it with t.Cleanup.
var manifestSHA256 = "fe06341d4145d4686eaeeddb4984c6edea9fd88b2c4a967d0432354f5a187cb4"

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
// beside the test it describes) but the comment marker must OPEN the line — that anchoring is what
// makes a claim a claim, and it is why the stray rules below exist: anything that looks like a claim
// and is not in that position is text no gate reads, so it is REPORTED rather than trusted. That
// includes inventory syntax inside a string literal. This program cannot tell a documentation
// example from a claim somebody meant, so it refuses both when they name a REAL corpus row and
// ignores both when they do not — which is why its own fixtures name files the corpus does not hold.
var (
	invAny = regexp.MustCompile(`^[ \t]*//[ \t]*(PORTED|N/A):`)
	// A claim written where the parser does not look. Found once for real: a PORTED: line wrapped
	// into the middle of a paragraph, naming rows that another file had meanwhile marked N/A — two
	// statements about the same row, one of them invisible to every gate.
	//
	// TWO SIGNALS, NOT ONE, because a claim can be SPLIT ACROSS LINES: `PORTED:` on one line and the
	// row on the next parses as neither, and requiring both on one line left that split as a hiding
	// place. So a line is suspicious if it mentions a corpus bats file AND EITHER carries claim syntax
	// anywhere on it, OR quotes a string that is a real @test name in that same file. The second
	// signal catches the continuation line, which is the one carrying the row's identity.
	//
	// Narrow by CORPUS MEMBERSHIP, checked later where the corpus is known: a mention of a bats file
	// the corpus does not hold is this program's own documentation or one of its fixtures, and is
	// ignored whatever syntax surrounds it.
	invStrayClaim = regexp.MustCompile(`(PORTED|N/A):`)
	invStrayPath  = regexp.MustCompile(`tests/[A-Za-z0-9_./-]+\.bats`)
	// A BARE FILENAME, because a full path can itself be split across lines. Round 6: `tests/unit/`
	// on one line and `foo.bats: "row"` on the next produced no path match at all, so the window had
	// nothing to pair. Every corpus file's basename is unique (34 files, verified), so a bare
	// `<name>.bats` identifies one file unambiguously — and auditCoverage still requires the corpus
	// to HOLD it, which is what keeps this from firing on prose about some other project's suite.
	invStrayBase = regexp.MustCompile(`\b[A-Za-z0-9_.-]+\.bats\b`)
	// EVERY quoted string, at any length. A length floor here was a silent hole: it only ever costs
	// a map lookup to consider one more candidate, and the signal fires only on an EXACT match with
	// a real @test name, so a short quoted word can never be a false positive.
	invQuoted = regexp.MustCompile(`"([^"]*)"`)
	// The quoted-row-name signal fires on COMMENT lines only. A claim — split across lines or not —
	// is written in a comment; CODE that quotes a row name is a different thing entirely, and the
	// tree has 144 lines of it: internal/verbs/owners.go's partition map is keyed by (file, name)
	// pairs by design, is guarded by its own test, and is not an inventory claim. Sweeping it up
	// would make this check fire on 144 legitimate lines, which is how a check gets switched off.
	// The claim-syntax signal below has no such restriction: PORTED:/N/A: beside a REAL corpus path
	// is never innocent, wherever it sits.
	invCommentLine = regexp.MustCompile(`^[ \t]*(//|/\*|\*)`)
	invPorted      = regexp.MustCompile(`^[ \t]*// PORTED:[ \t]+(\S+):[ \t]+"(.+)"[ \t]+->[ \t]+(.*\S)[ \t]*$`)
	invNA          = regexp.MustCompile(`^[ \t]*// N/A:[ \t]+(\S+):[ \t]+"(.+)"[ \t]+--[ \t]+(.*\S)[ \t]*$`)
)

// isGoTestName applies the testing package's OWN rule, in Go rather than in a regular expression
// because the rule is about a rune's Unicode category and RE2 cannot subtract one class from
// another: a test is `Test` followed by nothing, or by a rune that is not a lower-case letter. So
// `func Testfoo()` is not a test — Go never runs it and says nothing about it — while `Test_x`,
// `Test9` and `TestÉ` all are.
func isGoTestName(s string) bool {
	rest, ok := strings.CutPrefix(s, "Test")
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return !unicode.IsLower(r)
}

// identRune reports the runes a Go identifier may CONTAIN. The Go spec: a letter (any Unicode
// Letter, plus `_`) or a Unicode decimal digit (category Nd, which is what unicode.IsDigit tests).
func identRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

// goIdentsIn returns the MAXIMAL identifier-shaped rune runs in s that are legal Go identifiers.
//
// SCANNED RUNE BY RUNE RATHER THAN MATCHED BY A REGEXP, and that is the whole point of it. The
// pattern this replaced anchored on `\b`, and RE2's `\b` is ASCII-ONLY: between a non-ASCII letter
// and an ASCII one it sees a non-word/word transition and reports a boundary. So `ÉTestByteGate`
// matched starting at the `T` and yielded `TestByteGate` — and a PORTED claim naming a test that
// does not exist RESOLVED against a real one with a different name while the audit exited 0.
// Reproduced end to end on this tree: a claim retargeted to `ÉTestVerifyDigest` passed
// `check.sh parity` clean. Go identifiers are Unicode, so `É` is a legal identifier START; that is
// exactly why the boundary sat in the wrong place, and why no `\b`-anchored pattern can be right
// here.
//
// MAXIMAL, SO EACH RUN IS JUDGED WHOLE. Everything identifier-shaped is consumed first and only
// then asked whether it can legally BEGIN an identifier, so `1TestOne` is one run starting with a
// digit and yields nothing — never the `TestOne` inside it. Truncating a run and keeping a legal
// tail is the defect being fixed; it must not come back at the other end.
//
// THIS IS ABOUT WHERE AN IDENTIFIER STARTS AND ENDS, and nothing else. That a target expression is
// free text, so a `TestFoo` written in an English aside beside the name is extracted too, is a
// separate and deliberate property of the column's grammar — a different question from this one,
// and not changed here.
func goIdentsIn(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !identRune(r) {
			i += size
			continue
		}
		start, first := i, r
		for i < len(s) {
			r2, sz := utf8.DecodeRuneInString(s[i:])
			if !identRune(r2) {
				break
			}
			i += sz
		}
		if unicode.IsLetter(first) || first == '_' {
			out = append(out, s[start:i])
		}
	}
	return out
}

// isGoIdent reports whether s is one Go identifier and nothing besides — no surrounding text, no
// second token. Used where a WHOLE LINE must be a bare identifier to count.
func isGoIdent(s string) bool {
	ids := goIdentsIn(s)
	return len(ids) == 1 && ids[0] == s
}

// testNamesIn returns the Go test names appearing in a claim's target expression.
func testNamesIn(expr string) []string {
	var out []string
	for _, id := range goIdentsIn(expr) {
		if isGoTestName(id) {
			out = append(out, id)
		}
	}
	return out
}

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
// expiry date attached, and this list catches the phrasings that ACTUALLY OCCURRED here.
//
// STATED RESIDUAL, because the honest version of this comment matters more than the guard: THIS IS A
// TRIPWIRE, NOT A PROOF. It is a finite list of substrings, so a deferral spelled some other way
// ("this case will be ported after the Windows backend ships") passes it. No lexical rule can decide
// whether a sentence is an argument, and pretending otherwise is worse than the gap — a reader who
// believes this cannot be evaded stops reading N/A rationales, which is the only thing that actually
// catches them. It exists because the four expired premises found on this tree were all spelled in
// one of these ways, so it makes the cheapest recurrence loud; judging the rest is a reviewer's job
// and is written down as such in the task's report.
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
	"will be ported",
	"once ported",
	"when it ships",
	"after the",
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

// stray is a claim-shaped mention the parser cannot read because of where it sits. Whether it is a
// PROBLEM depends on the corpus, which parseInventory does not have — so everything needed to decide
// travels with it and auditCoverage judges.
type stray struct {
	GoFile     string
	GoLine     int
	BatsFile   string // the corpus path, or a bare basename auditCoverage must resolve
	Text       string // the mentioning line, for the message
	Region     string // the WHOLE contiguous comment region, for the row-name search
	ClaimWords bool   // the region carries PORTED:/N/A: somewhere
	InComment  bool   // the mention is in a comment (the only place a claim can be written)
}

// parseInventory reads one Go file's claims. Anything that opens like an inventory line but does
// not parse is returned as malformed rather than skipped — a claim the audit cannot read is a
// claim nobody is checking, which is the same as no claim at all but looks like coverage.
func parseInventory(rel string, content []byte) ([]claim, []malformed, []stray, error) {
	var claims []claim
	var bad []malformed
	var strays []stray
	inBlock, inRaw := false, false
	// THE COMMENT-BLOCK WINDOW. A hidden claim can be spread over THREE lines — the claim words,
	// the bats path, and the quoted row — none of which is a claim and no two of which need share a
	// line. Requiring the signals to coincide on one physical line left that shape invisible. So the
	// paths and quoted strings of the CURRENT contiguous comment region are accumulated, and any
	// pairing inside it is reported. The window resets at the first line that is not a comment,
	// which is what keeps it from spanning unrelated prose.
	type seenPath struct {
		file string
		line int
		text string
	}
	var region []string
	var regionFiles []seenPath
	regionClaim := false
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		// Lexical context BEFORE classification. A `// PORTED:` line that has been moved inside a
		// multiline raw string is inert data, not a claim — counting it would let a fixture satisfy
		// a row nothing actually covers. Block depth is tracked for the same reason in reverse: a
		// continuation line inside /* */ opens with nothing and must still count as a comment.
		openedInBlock, openedInRaw := inBlock, inRaw
		inBlock, inRaw = lexAfter(inBlock, inRaw, text)
		isComment := openedInBlock || inBlock || invCommentLine.MatchString(text)
		if !isComment {
			region, regionFiles, regionClaim = nil, nil, false
		}

		claimable := !openedInRaw && !openedInBlock && invAny.MatchString(text)
		if claimable {
			if m := invPorted.FindStringSubmatch(text); m != nil {
				targets := testNamesIn(m[3])
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
			continue
		}

		// NOT A CLAIM. If it nevertheless names a corpus file, and this comment REGION also carries
		// claim syntax or one of that file's row names, somebody wrote a claim the audit cannot read
		// — record it and let auditCoverage decide, since only it knows the corpus.
		//
		// THE WHOLE REGION IS THE UNIT, not the line, and round 7 is why: a quoted row name can be
		// split across lines too (the opening quote on one, the closing on the next), so extracting
		// quoted STRINGS could not see it. The region's text is searched for row names instead,
		// which covers a claim broken at any of the places one is naturally broken — after the claim
		// words, inside the path, around the quotes.
		//
		// STATED RESIDUAL, and it is a real limit rather than a gap worth closing: a row name or the
		// claim words BROKEN MID-TOKEN across lines ("POR" / "TED:") defeat both signals, because
		// the region is searched as text and nothing joins a word to its continuation. Closing that
		// would mean reconstructing prose, and the result would fire on ordinary comments. This
		// guard is aimed at a claim somebody WROTE and a later reader would read as a claim, not at
		// one deliberately obfuscated by a committer who also controls the review — that person can
		// simply delete the row from the manifest, which the digest pin catches instead.
		//
		// EVERY path on the line, not the first: a mention of a file the corpus does not hold,
		// earlier on the same line, would otherwise shadow a real one after it. Bare `<name>.bats`
		// counts too, because the PATH can be split as well.
		paths := invStrayPath.FindAllString(text, -1)
		paths = append(paths, invStrayBase.FindAllString(text, -1)...)
		claimWords := invStrayClaim.MatchString(text)
		if isComment {
			region = append(region, text)
			if claimWords {
				regionClaim = true
			}
			for _, p := range paths {
				regionFiles = append(regionFiles, seenPath{p, line, text})
			}
		}
		if !isComment {
			for _, p := range paths {
				strays = append(strays, stray{rel, line, p, text, text, claimWords, false})
			}
			continue
		}
		// One stray per (file, mentioning line) for the region SO FAR, re-emitted as the region
		// grows: auditCoverage dedupes by line and only the evidence it can act on survives.
		joined := strings.Join(region, "\n")
		seenHere := map[string]bool{}
		for _, sp := range regionFiles {
			if seenHere[sp.file] {
				continue
			}
			seenHere[sp.file] = true
			strays = append(strays, stray{rel, sp.line, sp.file, sp.text, joined, regionClaim, true})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", rel, err)
	}
	return claims, bad, strays, nil
}

// lexAfter reports the block-comment and raw-string state after consuming one line.
//
// IT IS A SMALL GO LEXER, not a pattern match, and round 5 is why. The previous version treated any
// `//` as a line comment and stopped scanning the line — so `const fixture = "http://" + ` + "`" + `
// left inRaw false, and a `// PORTED:` line inside the raw literal that followed counted as real
// coverage. A claim could be moved into data without changing any count or target and the audit
// still exited 0.
//
// So the four contexts that can swallow a `//` are all tracked: interpreted strings, rune literals,
// raw strings and block comments, with backslash escapes honoured in the two that have them. Where
// it is still approximate it errs toward "inside something", which WIDENS the stray check and
// NARROWS what counts as a claim — the safe direction, since a claim wrongly treated as data is
// reported as a hidden claim rather than accepted.
func lexAfter(inBlock, inRaw bool, line string) (bool, bool) {
	inStr, inRune, esc := false, false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case esc:
			esc = false
		case inStr || inRune:
			switch c {
			case '\\':
				esc = true
			case '"':
				if inStr {
					inStr = false
				}
			case '\'':
				if inRune {
					inRune = false
				}
			}
		case inRaw:
			if c == '`' {
				inRaw = false
			}
		case inBlock:
			if i+1 < len(line) && c == '*' && line[i+1] == '/' {
				inBlock = false
				i++
			}
		case c == '`':
			inRaw = true
		case c == '"':
			inStr = true
		case c == '\'':
			inRune = true
		case i+1 < len(line) && c == '/' && line[i+1] == '*':
			inBlock = true
			i++
		case i+1 < len(line) && c == '/' && line[i+1] == '/':
			// A REAL line comment: nothing after it can open a block or a raw string. Reached only
			// in code context, which is the whole point — inside a string this branch is
			// unreachable, and that is the defect this shape closes.
			return inBlock, inRaw
		}
	}
	// An interpreted string or rune literal cannot span lines in Go; only raw strings and block
	// comments carry over, so the other two states are deliberately not returned.
	return inBlock, inRaw
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

// parseGoTestList reads `go test -list '.*' ./...` output, KEYED BY PACKAGE. Only bare Test
// identifiers count: the stream also carries `ok  <pkg>  0.001s`, `?  <pkg> [no test files]`,
// Benchmark/Fuzz/Example names, and build chatter. The names for a package precede its own
// terminator line, which is what associates them.
//
// PER PACKAGE, NOT A GLOBAL NAME SET, and that is not tidiness. Go test names are not unique across
// packages — six collide in this tree (TestSchemaRefusals is defined in both internal/manifest and
// internal/policy) — so a global set lets a package's whole share of claims stay green after its
// test is DELETED, because a namesake somewhere else keeps supplying the name. That is a parity
// hole that exits 0, which is the only kind that matters.
func parseGoTestList(content []byte) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var cur []string
	for sc.Scan() {
		t := strings.TrimRight(sc.Text(), "\r")
		if isGoTestName(t) && isGoIdent(t) {
			cur = append(cur, t)
			continue
		}
		// A package terminator: `ok <pkg> <time>`, `? <pkg> [no test files]`, `FAIL <pkg> ...`.
		// ONLY a terminator flushes and resets. Benchmark, Fuzz and Example names sit BETWEEN the
		// test names of one package, so resetting on every non-test line would discard the names
		// before them — the whole package would arrive empty and every claim on it would report as
		// dangling, which is loud but about the wrong thing.
		f := strings.Fields(t)
		if len(f) >= 2 && (f[0] == "ok" || f[0] == "?" || f[0] == "FAIL" || f[0] == "---") {
			if out[f[1]] == nil {
				out[f[1]] = map[string]bool{}
			}
			for _, n := range cur {
				out[f[1]][n] = true
			}
			cur = nil
		}
	}
	return out
}

// testLane is ONE build-tag lane of the GO suite, and it carries BOTH witnesses — paired,
// deliberately. (Not to be confused with the corpus `lane` above, which is a bats directory.)
//
// WHY PAIRING IS THE FIX. The two witnesses were global and independent, and that let them agree
// about a test no lane runs. The SOURCE witness walked every `_test.go` on disk with build
// constraints DELIBERATELY NOT APPLIED, so a file tagged out of every lane still counted as a
// declaration; the LIST witness parses `go test -list` stdout, which is unstructured text anything
// a package prints during initialisation lands in. So a tagged-out file declaring TestClaimed, plus
// an active init() that merely PRINTS "TestClaimed", satisfied both halves while nothing anywhere
// registered a test by that name. Requiring the two to agree WITHIN ONE LANE closes it: the source
// half is now built from exactly the files that lane compiles.
type testLane struct {
	name string
	// list — what `go test -list` printed for this lane, per package.
	list map[string]map[string]bool
	// src — what the ACTIVE test files of this lane declare, per package (same key as list).
	src map[string]map[string]bool
}

// parseGoFileList reads `go list -f '{{.ImportPath}}\t{{.Dir}}\t{{join .TestGoFiles " "}}\t{{join
// .XTestGoFiles " "}}'` output and returns, per package import path, the absolute paths of the test
// files THAT LANE COMPILES. TestGoFiles and XTestGoFiles are the in-package and external test files
// go itself selected after applying build constraints — which is the whole point: the selection is
// made by the toolchain for the lane, not re-derived here from a walk that ignores tags.
func parseGoFileList(content []byte) (map[string][]string, error) {
	out := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		t := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(t) == "" {
			continue
		}
		f := strings.Split(t, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("go-files line is not the 4 tab-separated fields this reader expects: %q", t)
		}
		pkg, dir := f[0], f[1]
		if pkg == "" || dir == "" {
			return nil, fmt.Errorf("go-files line names no package or no directory: %q", t)
		}
		for _, group := range f[2:] {
			for _, name := range strings.Fields(group) {
				out[pkg] = append(out[pkg], filepath.Join(dir, name))
			}
		}
	}
	return out, sc.Err()
}

// collectLaneSource parses the named files and returns the test functions each package DECLARES.
//
// THROUGH THE GO PARSER, NOT A LINE MATCH. An earlier version matched `^func Test…(` textually,
// which counted a declaration written inside a block comment or a raw string as source evidence —
// the same class of defect the inventory scanner had, in the tool that was fixing it. go/parser
// knows what is code, and a file that does not parse is a hard error rather than a silent zero.
func collectLaneSource(files map[string][]string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for pkg, paths := range files {
		if out[pkg] == nil {
			out[pkg] = map[string]bool{}
		}
		for _, p := range paths {
			f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if perr != nil {
				return nil, fmt.Errorf("parsing %s for its test declarations: %w", p, perr)
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				// A METHOD IS NOT A TEST. `func (r *rig) TestX()` is never run by the testing
				// package, so a receiver disqualifies the declaration however the name reads.
				if !ok || fn.Recv != nil || fn.Name == nil {
					continue
				}
				// The same grammar the testing package applies: `Test` alone, or `Test` followed
				// by a character that is not a lower-case letter.
				if n := fn.Name.Name; isGoTestName(n) {
					out[pkg][n] = true
				}
			}
		}
	}
	return out, nil
}

// candidatePackages is where ONE PORTED target may legitimately live: the package of the file
// making the claim, plus any package the claim names EXPLICITLY AND FOR THAT TARGET, by writing it
// as `<package path>.<TestName>`.
//
// IT USED TO MINE FREE PROSE, AND THAT IS A FALSE-GREEN GENERATOR. Every path-like token anywhere
// in a claim's text was treated as a positive package reference, so a claim reading
// `TestShared (not internal/w; it is local)` offered `internal/w` as a candidate — and would then
// resolve against `internal/w.TestShared`, INCLUDING after the local test it was really about was
// deleted. A sentence saying a package is NOT where the target lives cannot be distinguished from
// one saying it is, because the reader is a token regexp and prose has no polarity. It is the same
// class as a namesake in another package satisfying a claim: the claim survives the deletion of the
// thing it claims.
//
// So a cross-package reference must be ATTACHED TO THE TARGET. `internal/docfmt.TestDocTypes` names
// a package for TestDocTypes and for nothing else; no arrangement of prose can supply one by
// accident, and a claim that means to point across a boundary says so in a form that cannot be read
// two ways.
//
// A BASENAME IS NOT A PACKAGE. `cmd/probe` and `internal/probe` must never collapse onto whichever
// was seen last, so a multi-segment token must match a real path SUFFIX, and a bare segment matches
// only when it is unambiguous across the whole module.
func candidatePackages(all map[string]map[string]bool, goFile, detail, target string) map[string]bool {
	bySeg := map[string][]string{}
	for p := range all {
		bySeg[path.Base(p)] = append(bySeg[path.Base(p)], p)
	}
	out := map[string]bool{}
	own := path.Dir(filepath.ToSlash(goFile))
	for p := range all {
		if p == own || strings.HasSuffix(p, "/"+own) {
			out[p] = true
		}
	}
	add := func(tok string) {
		tok = strings.Trim(tok, "/")
		if tok == "" {
			return
		}
		if strings.Contains(tok, "/") {
			for p := range all {
				if p == tok || strings.HasSuffix(p, "/"+tok) {
					out[p] = true
				}
			}
			return
		}
		if ps := bySeg[tok]; len(ps) == 1 {
			out[ps[0]] = true
		}
	}
	for _, m := range qualifiedTarget.FindAllStringSubmatch(detail, -1) {
		// FOR THIS TARGET ONLY. A claim naming two tests may qualify one of them and not the
		// other, and the unqualified one must not borrow the qualified one's package.
		if m[2] != target {
			continue
		}
		add(m[1])
	}
	return out
}

// qualifiedTarget matches `<package path>.<TestName>` — the ONLY cross-package reference this audit
// reads. The name half must satisfy the testing package's own grammar, so `enginetest/fake_test.go`
// offers nothing (its suffix is `go`, not a test name) and neither does ordinary prose.
var qualifiedTarget = regexp.MustCompile(`([A-Za-z0-9_./-]+)\.(Test[^a-z][A-Za-z0-9_]*|Test)\b`)

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
func auditCoverage(r *report, pairs []batsPair, claims []claim, bad []malformed, strays []stray, testLanes []testLane, preDeclared map[string]string) {
	// The union of what every lane REGISTERS — used to offer candidate packages and to say where a
	// target does exist. Resolution itself never uses it: that must agree within ONE lane.
	goTests := map[string]map[string]bool{}
	for _, ln := range testLanes {
		for pkg, ns := range ln.list {
			if goTests[pkg] == nil {
				goTests[pkg] = map[string]bool{}
			}
			for n := range ns {
				goTests[pkg][n] = true
			}
		}
	}
	for _, b := range bad {
		r.fail("%s:%d: inventory line does not parse (or its N/A argues nothing): %s", b.GoFile, b.GoLine, strings.TrimSpace(b.Text))
	}

	corpus := map[batsPair]bool{}
	perFile := map[string][]batsPair{}
	for _, p := range pairs {
		corpus[p] = true
		perFile[p.File] = append(perFile[p.File], p)
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

	// A claim about a real corpus file, written somewhere the parser does not read. It states
	// something about a row that some OTHER line is meanwhile claiming, and the two can disagree
	// forever because only one of them is checked.
	//
	// Row names keyed by corpus PATH, plus the set of corpus files each BASENAME can mean. The
	// basename map is a LIST, not one entry: round 6 asserted every basename was unique and it is
	// not — migrate.bats is both tests/unit/migrate.bats and tests/acceptance/migrate.bats. Keeping
	// one entry silently attributed an acceptance row to the unit file.
	namesOf := map[string]map[string]bool{}
	byBase := map[string][]string{}
	for _, p := range pairs {
		if namesOf[p.File] == nil {
			namesOf[p.File] = map[string]bool{}
		}
		namesOf[p.File][p.Name] = true
	}
	for f := range namesOf {
		byBase[path.Base(f)] = append(byBase[path.Base(f)], f)
	}
	for b := range byBase {
		sort.Strings(byBase[b])
	}

	// A mention is reported when it names a corpus file AND the comment region it sits in either
	// carries claim syntax or contains one of that file's row names. The REGION is the unit, not the
	// line: a claim can be broken across lines at any point — the claim words, the path, even the
	// quoted row name itself — and searching the region's text covers all of those at once.
	type where struct {
		file string
		line int
	}
	reported := map[where]bool{}
	for _, s := range strays {
		// Resolve the mention to the corpus file(s) it can mean.
		var cands []string
		if len(namesOf[s.BatsFile]) > 0 {
			cands = []string{s.BatsFile}
		} else {
			cands = byBase[s.BatsFile]
		}
		if len(cands) == 0 {
			continue
		}
		for _, cand := range cands {
			why := ""
			// THE ROW-NAME SIGNAL IS COMMENT-ONLY. Code that carries a row name is not a claim, and
			// the tree has 144 lines of it: the Wave 5 owner map is keyed by (file, name) pairs by
			// design. Sweeping it up would fire on 144 legitimate lines, which is how a check gets
			// switched off. Claim SYNTAX beside a corpus path is never innocent, wherever it sits.
			if s.InComment {
				for name := range namesOf[cand] {
					if strings.Contains(s.Region, name) {
						why = fmt.Sprintf("it carries %q, which is a real @test in that file", name)
						break
					}
				}
			}
			if why == "" && s.ClaimWords {
				why = "it carries PORTED:/N/A: claim syntax"
			}
			if why == "" {
				continue
			}
			if reported[where{s.GoFile, s.GoLine}] {
				break
			}
			reported[where{s.GoFile, s.GoLine}] = true
			r.fail("%s:%d: this names %s where the inventory parser does not read it (%s) — a claim here is invisible to every gate, so it can contradict the real one forever. Put it at the start of its own comment line, or reword it so it neither uses the claim syntax nor carries a row name: %s",
				s.GoFile, s.GoLine, cand, why, strings.TrimSpace(s.Text))
			break
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
			cands := candidatePackages(goTests, c.GoFile, c.Detail, t)
			found := false
			for p := range cands {
				// BOTH WITNESSES, WITHIN ONE LANE. `go test -list` says that lane registers the
				// name (so it compiles and runs there); the lane's ACTIVE test files say that
				// package really declares it. Agreement ACROSS lanes proves nothing: a name
				// printed by one lane's init and declared in a file only another lane compiles
				// satisfies both halves while no lane runs a test by that name.
				for _, ln := range testLanes {
					if ln.list[p][t] && ln.src[p][t] {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				continue
			}
			var elsewhere []string
			for p, names := range goTests {
				if names[t] {
					elsewhere = append(elsewhere, p)
				}
			}
			sort.Strings(elsewhere)
			switch len(elsewhere) {
			case 0:
				r.fail("%s:%d: PORTED target %s does not exist — no such test in `go test -list` output (claim: %s: %q)",
					c.GoFile, c.GoLine, t, c.Pair.File, c.Pair.Name)
			default:
				// It exists, but not where this claim can be pointing. Go test names are not unique
				// across packages, so accepting a namesake would let the intended test be deleted
				// with every claim on it still green.
				r.fail("%s:%d: PORTED target %s is not in this file's package and the claim does not name where it is — it exists in %s. Say which package it is in, so deleting it cannot leave this claim satisfied by a namesake (claim: %s: %q)",
					c.GoFile, c.GoLine, t, strings.Join(elsewhere, ", "), c.Pair.File, c.Pair.Name)
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
		goFiles   listFlag
		failFirst = flag.Int("max-problems", 0, "print at most this many problems (0 = all)")
	)
	flag.Var(&goLists, "go-list", "file holding `go test -list` output; repeatable (once per build-tag lane)")
	flag.Var(&goFiles, "go-files", "file holding `go list -f '{{.ImportPath}}\\t{{.Dir}}\\t{{join .TestGoFiles \" \"}}\\t{{join .XTestGoFiles \" \"}}'` output for the SAME lane, in the SAME order as --go-list")
	flag.Parse()

	if err := run(*root, *manifest, *writeMan, goLists, goFiles, *failFirst); err != nil {
		fmt.Fprintf(os.Stderr, "parity-audit: %v\n", err)
		os.Exit(1)
	}
}

func run(root, manifestRel string, writeMan bool, goLists, goFiles []string, maxProblems int) error {
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
		body := renderManifest(pairs)
		if err := os.WriteFile(manifestPath, body, 0o644); err != nil {
			return err
		}
		fmt.Printf("parity-audit: wrote %s (%d tests across %d files)\n", manifestRel, r.Tests, r.Files)
		// The digest is PRINTED rather than written back into the source, so updating the pin stays a
		// deliberate edit somebody reads a diff for. A tool that silently re-pinned itself would make
		// the pin decorative.
		fmt.Printf("parity-audit: its digest is %x\n", sha256.Sum256(body))
		fmt.Printf("parity-audit: if this differs from manifestSHA256 in tools/parity-audit/main.go, READ THE DIFF\n")
		fmt.Printf("parity-audit: and update that constant in the same commit — the pin is what stops a row being\n")
		fmt.Printf("parity-audit: replaced by an invented one of the same shape once the bats trees are gone.\n")
		return nil
	}

	committed, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading the committed manifest: %w", err)
	}
	// IDENTITY BEFORE ANYTHING IS READ OUT OF IT. A manifest whose CONTENT changed is a different
	// corpus, whatever its row count says.
	if got := fmt.Sprintf("%x", sha256.Sum256(committed)); got != manifestSHA256 {
		return fmt.Errorf("%s does not match the pinned corpus digest.\n"+
			"   have %s\n   want %s\n"+
			"   The corpus is pinned by CONTENT, not only by row count: a row REPLACED by an invented one of\n"+
			"   the same shape, with a claim written beside it, keeps every count and every coverage loop\n"+
			"   happy while an original requirement is gone. If this change is deliberate, regenerate the\n"+
			"   manifest, read the diff, and update manifestSHA256 in tools/parity-audit in the same commit.",
			manifestRel, got, manifestSHA256)
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

	// THE TWO WITNESSES ARRIVE PAIRED, ONE PAIR PER LANE, and the pairing is checked rather than
	// assumed: an unpaired list would silently reintroduce the very independence the pairing
	// removes — a lane whose source half is empty resolves nothing, and one whose list half is
	// empty would be skipped without anybody noticing which lane went missing.
	if len(goFiles) != len(goLists) {
		return fmt.Errorf("--go-list was given %d time(s) and --go-files %d — they are ONE witness pair per\n"+
			"   build-tag lane and must be given in the same number and the same order: the source half\n"+
			"   of target resolution is built from the files THAT LANE compiles",
			len(goLists), len(goFiles))
	}
	var testLanes []testLane
	names := 0
	for i, p := range goLists {
		content, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading go-test list: %w", err)
		}
		fcontent, ferr := os.ReadFile(goFiles[i])
		if ferr != nil {
			return fmt.Errorf("reading go-files list: %w", ferr)
		}
		files, perr := parseGoFileList(fcontent)
		if perr != nil {
			return fmt.Errorf("reading %s: %w", goFiles[i], perr)
		}
		src, serr := collectLaneSource(files)
		if serr != nil {
			return serr
		}
		ln := testLane{name: p, list: parseGoTestList(content), src: src}
		// EACH LANE'S OWN LIVENESS, not the union's. A lane that registers nothing, or whose
		// compiled test files declare nothing, resolves no target — and a union check would hide
		// that behind the other lane.
		if len(ln.list) == 0 {
			return fmt.Errorf("%s lists no packages — `go test -list` produced nothing for this lane", p)
		}
		if len(src) == 0 {
			return fmt.Errorf("%s names no compiled test files — the source half of target resolution has\n"+
				"   nothing to check against for this lane", goFiles[i])
		}
		for _, ns := range ln.list {
			names += len(ns)
		}
		testLanes = append(testLanes, ln)
	}
	// Same liveness argument one level down: an empty set of known tests would make every PORTED
	// target unresolvable, which is loud — but an empty set arriving because nobody passed a list
	// would make it loud for the wrong reason, and the fix would be to add the flag rather than to
	// look at the port. Say so up front.
	if names == 0 {
		return fmt.Errorf("no Go test names were loaded (pass --go-list <file> with `go test -list '.*' ./...` output) — PORTED targets cannot be resolved")
	}
	goTests := map[string]map[string]bool{}
	for _, ln := range testLanes {
		for pkg, ns := range ln.list {
			if goTests[pkg] == nil {
				goTests[pkg] = map[string]bool{}
			}
			for n := range ns {
				goTests[pkg][n] = true
			}
		}
	}

	auditCoverage(r, pairs, claims, bad, strays, testLanes, wholeFileNA)

	fmt.Printf("go tree: %d files scanned, %d PORTED, %d N/A, %d Go test names known across %d packages\n", scanned, r.Ported, r.NA, names, len(goTests))
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
