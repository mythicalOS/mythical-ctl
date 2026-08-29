// parity-audit — the machine half of the bash→Go port parity proof.
//
// WHAT THIS PROGRAM IS FOR. The bash tree is the SPECIFICATION of this CLI, and the port is
// finished by DELETING it. The only evidence that the deletion loses nothing is that every
// behaviour the bash suite pinned is accounted for in the Go suite — so every Go test file carries
// an inventory line per bats test it accounts for:
//
//	// PORTED: tests/unit/<file>.bats: "<exact test name>" -> <targets> [-- <commentary>]
//	// N/A:    tests/unit/<file>.bats: "<exact test name>" -- <why this cannot/need not port>
//
// and this program checks that those lines cover the corpus EXACTLY ONCE each, and that every
// PORTED target names a Go test that really exists.
//
// THE TARGET COLUMN IS A CLOSED LIST, NOT A SENTENCE. `<targets>` is one or more
// `[<pkgpath>.]<TestName>` tokens separated by whitespace, `+` or `,`, and NOTHING else parses.
// Anything a claim wants to SAY goes after ` -- `, where this program does not read it — which is
// what makes a sentence beside a target unable to satisfy, qualify or contradict it. A claim in
// a file the toolchain does not compile is not a claim at all. Both rules exist because their
// absence was demonstrated, end to end, as a green audit over false evidence; the sections below
// carry the demonstrations.
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
	"encoding/json"
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
	wantUnitTests       = 1145
	wantAcceptanceTests = 56
	batsFilesInCorpus   = 35
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
var manifestSHA256 = "9b4179c038c7d258baf1f702ffd8c1394e22e62ad6691dc964ace38cdce93ca5"

type lane struct {
	prefix string
	want   int
}

// The lanes, in the order they are reported. A bats file outside these two prefixes is a corpus
// the audit does not know how to count, and is refused rather than silently ignored.
//
// VARIABLES, NOT CONSTANTS, FOR ONE REASON: the end-to-end tests drive run() over a synthetic tree
// of three tests, and a run() that could only ever be exercised against the real 1,201 could not be
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
		// SPLIT ON EVERY TAB, NOT THE FIRST ONE. `strings.Cut` splits once, so
		// `<file>TAB<name>TABEXTRA` arrived as a two-field row whose NAME CONTAINED A TAB — and a
		// claim written to match that name resolved against it, so a row that is not the shape this
		// file declares passed the whole parity stage. Demonstrated end to end on this tree. The
		// separator is a TAB precisely because no @test name may contain one (parseBats refuses
		// that at the source), which means a third field can never be part of a name and there is
		// nothing to interpret: the row is refused.
		fields := strings.Split(text, "\t")
		if len(fields) != 2 {
			return nil, fmt.Errorf("manifest:%d: not a <file>TAB<name> row — it splits into %d tab-separated fields and a row is exactly 2. A bats test name cannot contain a TAB, so an extra field is not part of one: %q", line, len(fields), text)
		}
		file, name := fields[0], fields[1]
		if file == "" || name == "" {
			return nil, fmt.Errorf("manifest:%d: not a <file>TAB<name> row — one of its two fields is empty: %q", line, text)
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

// target is ONE resolvable PORTED target: a Go test FUNCTION name, plus the package token the
// claim wrote before it, if it wrote one. Both halves come from the token the claim spelled — never
// from a sentence beside it, which is the whole point of the grammar below.
type target struct {
	Pkg  string // the package path token written before the name, or "" when the claim wrote none
	Name string
}

func (t target) String() string {
	if t.Pkg == "" {
		return t.Name
	}
	return t.Pkg + "." + t.Name
}

type claim struct {
	Kind   claimKind
	Pair   batsPair
	Detail string // the raw target column (PORTED) or the argument (N/A) — for messages only
	GoFile string
	GoLine int
	// Site — which of its package's compiled file sets the CLAIMING file is in. It is what an
	// unqualified target resolves against: a claim written in an external test file is written in
	// `x_test`, and a namesake in `x` is a different test that no claim in `x_test` ever named.
	// Stamped by collectInventory from the toolchain's own file selection.
	Site    fileKind
	Targets []target // PORTED only: the targets the column NAMES, parsed as tokens
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
	// THE ROW NAME ENDS AT THE FIRST CLOSING QUOTE, and that is structural rather than a
	// consequence of backtracking. With a greedy `(.+)` the boundary was decided by whatever came
	// LATER on the line: a quoted phrase in the commentary offered the engine a second, further
	// `" -> ` to close on, and the row name it produced ran through the target column. It always
	// failed corpus membership afterwards — no @test name in this corpus contains a quote, verified
	// — so it was loud rather than a false green. But that is a property of the CORPUS holding the
	// parser up, not of the parser, and a rule that depends on data nobody re-checks is one bad day
	// from being wrong. A row name cannot contain a quote, so the pattern says so.
	invPorted = regexp.MustCompile(`^[ \t]*// PORTED:[ \t]+(\S+):[ \t]+"([^"]+)"[ \t]+->[ \t]+(.*\S)[ \t]*$`)
	invNA     = regexp.MustCompile(`^[ \t]*// N/A:[ \t]+(\S+):[ \t]+"([^"]+)"[ \t]+--[ \t]+(.*\S)[ \t]*$`)
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

// ---------------------------------------------------------------------------------------------
// THE TARGET COLUMN IS A CLOSED, PROSE-FREE LIST. This is the smallest change that closes a whole
// FAMILY of false greens rather than the three instances of it that were found.
//
// WHAT THE COLUMN USED TO BE. Free text, with every `TestFoo`-shaped identifier in it mined as a
// target and every `pkg/path.` before one mined as a qualifier. Three demonstrations, all the same
// shape and all made `bash check.sh parity` exit 0:
//
//   -> this behavior is not implemented; TestCLIUnknownVerbExitsTwo is only an unrelated
//      neighboring test                       — a sentence DENYING the port satisfied the claim
//   -> not internal/w.TestShared; the local TestShared is intended
//                                             — a NEGATED qualifier resolved against what it negates
//   -> TestOne[int] / TestOne via t.Run("...")— narrowed to `TestOne` and reported as resolved
//
// Prose has no polarity a scanner can read, and every rule invented to give it one (union the
// qualifiers, reject contradictory ones, read only the first occurrence) was another rule ABOUT
// prose waiting for a fourth shape. The reader therefore stops reading prose entirely: after `->`
// comes a list of tokens and nothing else, and commentary moves behind the `--` delimiter the N/A
// lines already use, where NOTHING reads it. A sentence can then neither satisfy, constrain nor
// contradict a claim — the family is unreachable rather than individually ruled out.
//
// AND A NAME THIS PROGRAM CANNOT RESOLVE IS REFUSED, NEVER NARROWED. A generic instantiation and a
// subtest spelling both name something `go test -list` does not enumerate; answering about the
// parent function is the claim saying one thing and the resolver answering about another.
// ---------------------------------------------------------------------------------------------

// targetRune is what a target TOKEN may contain: identifier runes (Unicode letters, digits, `_`),
// and the three bytes a package path adds. Deliberately rune-based, not an ASCII class: Go
// identifiers are Unicode, and `TestAlphaÉ` must survive as one token rather than be cut at the É.
func targetRune(r rune) bool { return identRune(r) || r == '.' || r == '/' || r == '-' }

func isTargetSep(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '+' }

// splitNote divides the region after `->` at the first STANDALONE `--` field: everything before it
// is the target list, everything after is commentary that nothing reads. Standalone, because `-` is
// a legal package-path byte and a `--` glued to a token is a typo in a token, not a delimiter.
func splitNote(region string) (list, note string, has bool) {
	i := 0
	for i < len(region) {
		for i < len(region) && (region[i] == ' ' || region[i] == '\t') {
			i++
		}
		start := i
		for i < len(region) && region[i] != ' ' && region[i] != '\t' {
			i++
		}
		if start == i {
			break
		}
		if region[start:i] == "--" {
			return region[:start], region[i:], true
		}
	}
	return region, "", false
}

// isPackagePathToken reports whether p can be a package path: non-empty segments separated by `/`,
// none of them a dot-path. The RUNE set is already guaranteed by the caller.
func isPackagePathToken(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// wantTarget is the one sentence every refusal below ends with, so the author is told the shape
// rather than only that theirs was wrong.
const wantTarget = "a target is `TestName` or `pkg/path.TestName`; put anything else — an aside, a file name, a sentence — after a ` -- ` delimiter, where it is commentary and nothing resolves it"

// parseTargetToken turns ONE token into a target, or explains why it is not one.
func parseTargetToken(tok string) (target, string) {
	if strings.ContainsAny(tok, "[]") {
		return target{}, fmt.Sprintf("%q is a generic instantiation, and `go test -list` enumerates the FUNCTION — so this audit could only ever resolve the function name while the claim named the instantiation, which is the claim saying one thing and the resolver answering about another. Name the function. %s", tok, wantTarget)
	}
	for _, r := range tok {
		if !targetRune(r) {
			return target{}, fmt.Sprintf("%q is not a target token. %s", tok, wantTarget)
		}
	}
	pkg, name := "", tok
	if i := strings.LastIndexByte(tok, '.'); i >= 0 {
		pkg, name = tok[:i], tok[i+1:]
		if pkg == "" {
			return target{}, fmt.Sprintf("%q opens with a dot and names no package before it. %s", tok, wantTarget)
		}
		if !isPackagePathToken(pkg) {
			return target{}, fmt.Sprintf("%q does not qualify a name with a package path (%q is not one). %s", tok, pkg, wantTarget)
		}
	}
	if strings.Contains(name, "/") {
		if parent, _, _ := strings.Cut(name, "/"); isGoIdent(parent) && isGoTestName(parent) {
			return target{}, fmt.Sprintf("%q names the SUBTEST %q — `go test -list` enumerates test FUNCTIONS, and a subtest exists only while its parent runs, so this audit could only ever resolve %q and report the claim as satisfied. Deleting that subtest would leave the line green. Name the test function. %s", tok, name, parent, wantTarget)
		}
		return target{}, fmt.Sprintf("%q is not a target token. %s", tok, wantTarget)
	}
	if !isGoIdent(name) {
		return target{}, fmt.Sprintf("%q does not end in a Go identifier. %s", tok, wantTarget)
	}
	if !isGoTestName(name) {
		// ONE MESSAGE FOR BOTH READERS. A prose word landing here ("this", "not", "via") needs to
		// hear that the COLUMN takes tokens; a near-miss like `Testfoo` needs to hear Go's actual
		// rule. Saying both costs a clause and stops the refusal reading as a non-sequitur to
		// whichever author hit it.
		return target{}, fmt.Sprintf("%q is not a target token: it is not a Go TEST name — the testing package requires `Test` followed by nothing, or by a character that is not a lower-case letter, and ignores everything else in silence. %s", tok, wantTarget)
	}
	return target{Pkg: pkg, Name: name}, ""
}

// parseTargetColumn parses the whole region after `->`, or returns the refusal that names the token
// which is not a target.
func parseTargetColumn(region string) ([]target, string) {
	list, note, has := splitNote(region)
	if has && strings.TrimSpace(note) == "" {
		return nil, "its ` -- ` commentary field is empty; drop the delimiter or say something after it"
	}
	fields := strings.FieldsFunc(list, isTargetSep)
	if len(fields) == 0 {
		return nil, "it names no target at all before the ` -- ` delimiter, so nothing about it is checkable. " + wantTarget
	}
	var out []target
	for _, f := range fields {
		tg, why := parseTargetToken(f)
		if why != "" {
			return nil, why
		}
		out = append(out, tg)
	}
	return out, ""
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
	// OffLane — the file is not one the toolchain compiles for ANY audited lane, so nothing in it
	// can ever be a claim, however well it is written. Carried so auditCoverage can say WHICH of
	// the two invisibilities this is: written where the parser does not look, or written in a file
	// the parser is not allowed to read.
	OffLane bool
}

// astView is what go/parser says about ONE file's comments: the lines on which a `//` LINE COMMENT
// begins, and every line any comment covers. For a file the toolchain selected it is the AUTHORITY
// on both questions, replacing the hand lexer that used to answer them from raw bytes.
//
// WHY THE PARSER AND NOT THE BYTES. Round 12 demonstrated the consequence of reading claims out of
// a filesystem walk: a real claim moved into cmd/mythical-ctl/testdata/broken.go — a file preceded
// by the line `this is not valid Go` — was CREDITED, and the full parity stage exited 0. Valid Go
// behind `//go:build never` did the same. Both are files no lane compiles, so no claim in either
// can describe anything that runs. The hand lexer could not tell, because it was reading text.
type astView struct {
	lineComment map[int]bool
	anyComment  map[int]bool
}

// parseGoComments parses one Go file and reports its comment geography.
//
// A PARSE FAILURE IS RETURNED, NEVER SWALLOWED. A file the toolchain compiles but this program
// cannot read is a file whose claims nobody is checking — and skipping it looks exactly like a file
// that had no claims, which is the shape of every false green in this program's history.
func parseGoComments(rel string, content []byte) (*astView, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, content, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing %s for its inventory comments: %w", rel, err)
	}
	v := &astView{lineComment: map[int]bool{}, anyComment: map[int]bool{}}
	for _, g := range f.Comments {
		for _, c := range g.List {
			start := fset.Position(c.Slash).Line
			end := fset.Position(c.End()).Line
			for l := start; l <= end; l++ {
				v.anyComment[l] = true
			}
			// A CLAIM IS A `//` LINE COMMENT AND NOTHING ELSE, which is the grammar the protocol
			// already had: invAny anchors on `^[ \t]*//`. A line INSIDE a /* */ block that reads
			// `// PORTED: ...` is therefore not a claim — it is reported as one the parser cannot
			// read, exactly as before.
			if strings.HasPrefix(c.Text, "//") {
				v.lineComment[start] = true
			}
		}
	}
	return v, nil
}

// shifted returns the view with every line number moved by d. Test scaffolding only: a fixture
// written as bare inventory lines needs a `package` clause to be parseable at all, and the
// assertions read the FIXTURE's line numbers, not the scaffolded ones.
func (v *astView) shifted(d int) *astView {
	out := &astView{lineComment: map[int]bool{}, anyComment: map[int]bool{}}
	for l := range v.lineComment {
		out.lineComment[l+d] = true
	}
	for l := range v.anyComment {
		out.anyComment[l+d] = true
	}
	return out
}

// parseInventory reads one Go file's claims. Anything that opens like an inventory line but does
// not parse is returned as malformed rather than skipped — a claim the audit cannot read is a
// claim nobody is checking, which is the same as no claim at all but looks like coverage.
//
// VIEW NIL MEANS THE FILE IS NOT TOOLCHAIN-SELECTED, and then it may carry NO claims at all: every
// claim-shaped line falls through to the stray path and is reported as invisible. Such a file need
// not even be valid Go (testdata routinely is not), which is why the lexer still answers the
// comment question for it — the parser cannot.
func parseInventory(rel string, content []byte, view *astView) ([]claim, []malformed, []stray, error) {
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
		//
		// THE PARSER ANSWERS BOTH QUESTIONS WHERE IT CAN. For a toolchain-selected file the AST says
		// which lines are comments and which of them OPEN a `//` comment, so no byte-level
		// approximation decides whether a claim is a claim. The lexer stays for the files the parser
		// cannot read — the ineligible ones, which may not be valid Go — and there it only ever
		// widens the stray window, never admits a claim.
		var isComment, claimable bool
		if view != nil {
			isComment = view.anyComment[line]
			claimable = view.lineComment[line] && invAny.MatchString(text)
		} else {
			openedInBlock := inBlock
			inBlock, inRaw = lexAfter(inBlock, inRaw, text)
			isComment = openedInBlock || inBlock || invCommentLine.MatchString(text)
		}
		if !isComment {
			region, regionFiles, regionClaim = nil, nil, false
		}
		if claimable {
			if m := invPorted.FindStringSubmatch(text); m != nil {
				targets, why := parseTargetColumn(m[3])
				if why != "" {
					bad = append(bad, malformed{rel, line,
						fmt.Sprintf("its PORTED target column is not a closed list of targets: %s || %s", why, text)})
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
				strays = append(strays, stray{rel, line, p, text, text, claimWords, false, view == nil})
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
			strays = append(strays, stray{rel, sp.line, sp.file, sp.text, joined, regionClaim, true, view == nil})
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

// canonPath is the ONE spelling of a path both halves of the eligibility question can be asked in.
// `go list` prints absolute directories; the inventory walk produces paths relative to -root; and
// on macOS a temporary directory reaches the walk through a symlink and the toolchain through its
// target. Comparing any two of those as written is a silent miss, and a silent miss here means
// every claim in a file becomes invisible — the loudest possible failure for the quietest reason.
func canonPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if r, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		return r
	}
	return abs
}

// ok reports membership in the eligible set. Spelled out rather than read as a zero value, because
// fileOrdinary IS the zero value: `eligible[canon] == fileOrdinary` is true for every file in the
// tree, and reading membership off it would make the whole selection inert.
func ok(eligible map[string]fileKind, canon string) bool {
	_, in := eligible[canon]
	return in
}

// collectInventory reads the whole tree, but only ELIGIBLE files may carry claims.
//
// ELIGIBILITY IS THE TOOLCHAIN'S OWN FILE SELECTION, not a rule this program invents: the union,
// across the audited lanes, of the files `go list` says each package compiles. A file under
// testdata, or excluded by a build constraint, is in no lane's selection — so nothing in it runs,
// nothing in it can describe what runs, and a claim in it is credited to nobody.
//
// THE INELIGIBLE FILES ARE STILL READ, and that is deliberate. A claim moved into one of them is
// not merely uncredited (which shows up as an unclaimed row somewhere else, naming the wrong file);
// it is REPORTED where it sits, so the message names the file somebody actually has to fix.
func collectInventory(root string, eligible map[string]fileKind) ([]claim, []malformed, []stray, int, error) {
	var claims []claim
	var bad []malformed
	var strays []stray
	scanned := 0
	// A SET, NOT A COUNTER, and the difference is a false green. Two walked paths can canonicalize
	// onto ONE eligible key — a symlink beside the file it points at is enough — and a counter then
	// records two hits for one file, which is exactly enough to hide a DIFFERENT selected file the
	// walk never reached (one under a pruned directory, say). The arithmetic balances and the audit
	// exits 0 having never read a file that compiles. A set cannot be inflated: it is a subset of
	// `eligible` by construction, so equal sizes really do mean equal sets.
	found := map[string]bool{}
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
		var view *astView
		site := fileOrdinary
		if canon := canonPath(p); ok(eligible, canon) {
			found[canon] = true
			site = eligible[canon]
			// A MALFORMED ELIGIBLE FILE REFUSES. It is a file the toolchain compiles, so its claims
			// are the ones that count — and a parse error that merely skipped it would look exactly
			// like a file with nothing in it.
			v, verr := parseGoComments(filepath.ToSlash(rel), content)
			if verr != nil {
				return verr
			}
			view = v
		}
		c, b, st, perr := parseInventory(filepath.ToSlash(rel), content, view)
		if perr != nil {
			return perr
		}
		for i := range c {
			c[i].Site = site
		}
		claims = append(claims, c...)
		bad = append(bad, b...)
		strays = append(strays, st...)
		return nil
	})
	if err != nil {
		return nil, nil, nil, scanned, err
	}
	// The scan's own liveness, and it comes FIRST because it is the more basic answer: an empty tree
	// would otherwise be reported as a disagreement between the walk and `go list`, which sends the
	// reader looking for a keying bug that is not there.
	if scanned == 0 {
		return nil, nil, nil, scanned, fmt.Errorf("scanned 0 Go files under %s — the inventory scan is pointed at the wrong tree", root)
	}
	// THE WALK AND THE SELECTION MUST MEET. If a file the toolchain named was never reached by the
	// walk, the two halves are keyed differently or the walk is pointed elsewhere — and the symptom
	// would be a pile of unclaimed rows with no hint of the cause. Say the cause instead.
	if len(found) != len(eligible) {
		// NAME THE FILE THAT IS ACTUALLY MISSING, not an arbitrary selected one. The whole value of
		// this message is that it points at the disagreement instead of leaving a reader to infer it
		// from a pile of unclaimed rows.
		var missing []string
		for f := range eligible {
			if !found[f] {
				missing = append(missing, f)
			}
		}
		sort.Strings(missing)
		return nil, nil, nil, scanned, fmt.Errorf("the inventory walk under %s reached %d of the %d files the toolchain selected — the walk and `go list` disagree about where the source is, so claims would be missing for a reason that has nothing to do with the port (%d never reached; first by path: %s)",
			root, len(found), len(eligible), len(missing), missing[0])
	}
	return claims, bad, strays, scanned, nil
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
//
// COUNTED, NOT FLAGGED, and the count is a witness in its own right. `x` and `x_test` are compiled
// separately and may each declare a test of the same name, so the stream really does print one name
// TWICE for one package — two tests, not a repetition. A boolean cannot hold that, and holding it is
// what lets this half be compared against the source half's DECLARATION COUNT: if the two disagree
// about how many tests carry a name, neither can say which one a claim is about.
func parseGoTestList(content []byte) map[string]map[string]int {
	out := map[string]map[string]int{}
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
				out[f[1]] = map[string]int{}
			}
			for _, n := range cur {
				out[f[1]][n]++
			}
			cur = nil
		}
	}
	return out
}

// notExecutedPrefix marks a --go-exec value that is an ARGUMENT rather than a file: this lane was
// deliberately not run, and the text after the colon says why. It is spelled out at the call site
// rather than inferred, because a lane that quietly opts out of the execution witness is exactly the
// special case this witness was added to forbid.
const notExecutedPrefix = "not-executed:"

// parseGoTestExec reads `go test -json -count=1 ./...` output — THE EXECUTION WITNESS — and returns,
// per package, how many times each test NAME was actually STARTED.
//
// WHY A THIRD WITNESS AT ALL, WHEN TWO ALREADY AGREE. Because both of the others answer
// "does this test EXIST", and neither answers "does it RUN". A test can be declared in a file the
// lane compiles (the source witness), registered by the toolchain and printed by `go test -list`
// (the list witness), and still never execute: `func TestMain(m *testing.M)` is the package's own
// entry point, so it can parse `-test.list` and print whatever it likes, then set `-test.run` to
// something else and call m.Run. MEASURED, with the reviewer's probe: `go test -list '.*'` printed
// only `TestClaimed`, a normal `go test -v` ran only `TestOther`, and both of the other witnesses
// were satisfied. This one is not: the run events name TestOther and nothing else.
//
// AND IT IS NOT UNFORGEABLE — SAY SO PLAINLY, BECAUSE THE OPPOSITE BELIEF IS THE DANGEROUS ONE.
// `go test -json` is `test2json`, a parser of the test binary's STDOUT, and it still honours the
// unmarked framework line format for compatibility. MEASURED on go1.26.5: a package that prints
// `=== RUN   TestClaimed` and `--- PASS: TestClaimed (0.00s)` gets a genuine `"Action":"run"` event
// with `"Test":"TestClaimed"`, indistinguishable from a real one. (Go does prefix its own lines with
// \x16 under `-test.v=test2json`, but the marker is stripped before the JSON is emitted — and a
// package could print that byte too.) So NO stdout-derived evidence can be proof against a package
// that sets out to lie; what this witness does is close the accident and the shortcut. Printing a
// bare identifier during a listing run is something a package can do by mistake; emitting the
// framework's own RUN/PASS lines for a test that did not run is not.
//
// COUNTED, LIKE THE LIST WITNESS, AND FOR THE SAME REASON: `x` and `x_test` may each declare a test
// of one name and both run under one package, so the number of starts is what can be held against
// the number of declarations.
//
// SUBTESTS ARE NOT THEIR PARENT. `t.Run` emits `"Test":"TestFoo/case"`, and counting those toward
// TestFoo would put the run count far above the declaration count for every table-driven test in the
// tree (1662 events against 1369 top-level starts, measured here). A subtest name is also not a
// legal target token, so nothing can claim one; they are dropped.
//
// A START, NOT AN OUTCOME — AND THAT IS THE RIGHT READING, BUT SAY WHICH IT IS. `run` is emitted
// when the test function is INVOKED, so a test that fails still counts (a failing test is still a
// test the claim points at, and whether the suite passes is `check.sh go`'s question) and so does a
// test that runs and then calls t.Skip. This tree has three skipping tests and one of them,
// internal/conf's TestForeignOwnedRefused, IS a PORTED target: it needs root to build a
// foreign-owned fixture. Its inventory line already carries that residual in writing and names a
// second, unprivileged target beside it, which is the honest shape for such a claim — the
// alternative, refusing a start that ends in a skip, would redden that claim on every machine that
// is not root and could never be made green. What this witness rules out is a test that is never
// INVOKED; it does not rule out one that is invoked and declines.
func parseGoTestExec(name string, content []byte) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimRight(sc.Bytes(), "\r")
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var ev struct {
			Action  string
			Package string
			Test    string
		}
		// A LINE THAT IS NOT AN EVENT IS A HARD ERROR, NOT A SKIP. This stream is the only evidence
		// that anything ran; a reader that shrugged at unparseable lines would report an empty or
		// half-empty witness for a stream it had not understood, and every PORTED target would go
		// dangling for a reason that is not about the port.
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("%s line %d is not a `go test -json` event: %w (the execution witness must be the STDOUT of `go test -json -count=1 ./...` and nothing else)", name, line, err)
		}
		if ev.Action != "run" || ev.Test == "" || ev.Package == "" {
			continue
		}
		if strings.Contains(ev.Test, "/") {
			continue
		}
		if out[ev.Package] == nil {
			out[ev.Package] = map[string]int{}
		}
		out[ev.Package][ev.Test]++
	}
	return out, sc.Err()
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
//
// AND WHY THE SOURCE HALF IS KEYED BY testPkg. The two halves used to share one key — the import
// path — which merged a package's internal and external test packages into one name set. See
// testPkg.
type testLane struct {
	name string
	// list — what `go test -list` printed for this lane, per package, WITH MULTIPLICITY. It cannot
	// be keyed any finer: one test binary is built per package under test and its listing prints
	// the internal and external tests together, under one terminator line. What the stream can say
	// is HOW MANY tests carry a name, and that is what is kept.
	list map[string]map[string]int
	// src — what the ACTIVE test files of this lane declare, per COMPILED TEST PACKAGE.
	src declSet
	// exec — what actually STARTED in an unfiltered `go test -json -count=1` run of this lane, per
	// package, with multiplicity. Keyed no finer than the list half for the same reason: one test
	// binary per package under test, and its run events do not say which of the two compiled test
	// packages a name came from.
	exec map[string]map[string]int
	// executed — whether this lane was run at all. A lane that was not run is not a lane whose tests
	// failed to run: it can confirm nothing, and it says so rather than resolving on the strength of
	// the two witnesses that only prove existence.
	executed bool
	// execWhy — the ARGUMENT for not executing this lane, supplied at the call site. A claim that
	// needs this lane is refused with it, so the exception is visible in the refusal rather than
	// buried in a flag.
	execWhy string
}

// testPkg identifies ONE COMPILED TEST PACKAGE: the import path under test, and whether this is the
// EXTERNAL `x_test` package built from XTestGoFiles rather than the package itself.
//
// THIS IS AN IDENTITY THE AUDIT PREVIOUSLY APPROXIMATED, AND THE APPROXIMATION WAS A FALSE GREEN.
// TestGoFiles and XTestGoFiles were concatenated and every declaration stored as a bare
// `import-path/TestName` bit, so `package x`'s TestSame and `package x_test`'s TestSame — two
// separate tests, compiled into two separate packages, both printed by `go test -list` — became one
// target. Delete the external one and keep its claim, and the claim resolved against the internal
// namesake: the audit certifying that deleting the bash tree lost nothing stayed green over a Go
// test that was gone. It is the same shape as every other false green in this program's history — a
// namesake in another package answering for a deleted test — reappearing at the one package boundary
// the key could not express. So the key expresses it.
type testPkg struct {
	Path     string
	External bool
}

// String spells a compiled test package the way a claim must WRITE it to name it: `x_test` is a
// real, distinct package path token, and it is the only way to point at the external half from
// outside it.
func (p testPkg) String() string {
	if p.External {
		return p.Path + "_test"
	}
	return p.Path
}

// testDecl is ONE test declaration — where it is, and the `package` clause its file actually wrote.
//
// A LOCATION, NOT A BIT. A bit answers "does something by this name exist somewhere in this
// package"; a resolution needs "which declaration is this claim about", and a message that cannot
// name the file and line of the thing it is talking about sends its reader looking. The parsed
// clause travels with it because it is the INDEPENDENT witness that a file is in the bucket `go
// list` put it in: an external test file's clause ends in `_test` and an internal one's does not,
// so reading the two file lists in the wrong order stops being silent.
type testDecl struct {
	File    string
	Line    int
	PkgName string
}

// declSet is what one lane's compiled test files declare, per compiled test package: a name maps to
// EVERY declaration of it, so multiplicity survives to be checked rather than being collapsed on the
// way in.
type declSet map[testPkg]map[string][]testDecl

func (d declSet) add(p testPkg, name string, dc testDecl) {
	if d[p] == nil {
		d[p] = map[string][]testDecl{}
	}
	d[p][name] = append(d[p][name], dc)
}

// pkgFiles is what one lane compiles for one package: its ordinary source, and the files that can
// DECLARE tests. The two are kept apart because they answer different questions — every file here
// may carry a CLAIM (it is compiled, so it is real), but only a `_test.go` file can declare a test,
// and a `func TestX` in ordinary source is an exported function the toolchain never registers.
//
// AND THE TWO TEST LISTS ARE NOT ONE LIST. They were concatenated here, which is where the internal
// and external test packages first became indistinguishable; everything downstream inherited it.
type pkgFiles struct {
	Dir   string
	Go    []string // GoFiles — compiled into the package itself
	Test  []string // TestGoFiles — compiled INTO the package under test (`package x`)
	XTest []string // XTestGoFiles — compiled into the EXTERNAL test package (`package x_test`)
}

// AllTest is both test file lists, for the questions that genuinely do not care which package a
// file is compiled into — eligibility to CARRY a claim is the only one.
func (p pkgFiles) AllTest() []string { return append(append([]string{}, p.Test...), p.XTest...) }

// parseGoFileList reads `go list -f '{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles " "}}\t{{join
// .TestGoFiles " "}}\t{{join .XTestGoFiles " "}}'` output and returns, per package import path, the
// absolute paths of the files THAT LANE COMPILES. They are the files go itself selected after
// applying build constraints — which is the whole point: the selection is made by the toolchain for
// the lane, not re-derived here from a walk that ignores tags.
func parseGoFileList(content []byte) (map[string]pkgFiles, error) {
	out := map[string]pkgFiles{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		t := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(t) == "" {
			continue
		}
		f := strings.Split(t, "\t")
		if len(f) != 5 {
			return nil, fmt.Errorf("go-files line is not the 5 tab-separated fields this reader expects: %q", t)
		}
		pkg, dir := f[0], f[1]
		if pkg == "" || dir == "" {
			return nil, fmt.Errorf("go-files line names no package or no directory: %q", t)
		}
		e := pkgFiles{Dir: dir}
		for _, name := range strings.Fields(f[2]) {
			e.Go = append(e.Go, filepath.Join(dir, name))
		}
		// FIELD 4 IS THE IN-PACKAGE TEST FILES AND FIELD 5 IS THE EXTERNAL ONES, kept apart from
		// here down. They used to be appended into one list, which is the whole of Finding 1.
		for _, name := range strings.Fields(f[3]) {
			e.Test = append(e.Test, filepath.Join(dir, name))
		}
		for _, name := range strings.Fields(f[4]) {
			e.XTest = append(e.XTest, filepath.Join(dir, name))
		}
		// A PACKAGE WITH NO FILES CONTRIBUTES NO ENTRY. It declares nothing and compiles nothing, so
		// inventing an empty entry for it would only make the liveness checks below harder to trip.
		if len(e.Go) == 0 && len(e.Test) == 0 && len(e.XTest) == 0 {
			continue
		}
		out[pkg] = e
	}
	return out, sc.Err()
}

// collectLaneSource parses the named files and returns the test functions each package DECLARES.
//
// THROUGH THE GO PARSER, NOT A LINE MATCH. An earlier version matched `^func Test…(` textually,
// which counted a declaration written inside a block comment or a raw string as source evidence —
// the same class of defect the inventory scanner had, in the tool that was fixing it. go/parser
// knows what is code, and a file that does not parse is a hard error rather than a silent zero.
func collectLaneSource(files map[string]pkgFiles) (declSet, error) {
	out := declSet{}
	fset := token.NewFileSet()
	// SORTED, because the messages below name a file and a line and a map iteration would name a
	// different one on each run. A refusal that moves is a refusal nobody trusts.
	paths := make([]string, 0, len(files))
	for pkg := range files {
		paths = append(paths, pkg)
	}
	sort.Strings(paths)
	for _, pkg := range paths {
		pf := files[pkg]
		// ONLY A TEST FILE CAN DECLARE A TEST, and only a package that ACTUALLY DECLARES ONE gets an
		// entry. An entry created up front — for a package with no test files, or with a test file
		// that declares nothing — is an empty witness, and an empty witness is indistinguishable
		// from a real one at every read (`src[p][t]` is empty either way) while making the lane look
		// populated to anything that counts entries. It is created below, on the first declaration.
		//
		// DELIBERATELY REDUNDANT WITH THE `laneDeclared` COUNT IN run(), AND SAY SO. Either one alone
		// closes the hole they were added for, so each is an EQUIVALENT mutation on its own and no
		// test can distinguish them; only reverting BOTH reddens. That is recorded here rather than
		// left for a later reader to discover by deleting one — the pair is two readers of the same
		// fact (this lane can confirm nothing), and the cheaper of the two to get wrong is this one.
		for _, group := range []struct {
			files    []string
			external bool
		}{{pf.Test, false}, {pf.XTest, true}} {
			key := testPkg{Path: pkg, External: group.external}
			for _, p := range group.files {
				f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
				if perr != nil {
					return nil, fmt.Errorf("parsing %s for its test declarations: %w", p, perr)
				}
				// THE FILE'S OWN `package` CLAUSE IS THE SECOND WITNESS TO WHICH PACKAGE IT IS IN,
				// and it is cheap enough that not asking would be a choice. `go list` puts a test
				// file in TestGoFiles or XTestGoFiles by exactly this clause, so the two can be
				// cross-checked: an external test file's clause ends in `_test` and an in-package
				// one's cannot (cmd/go refuses a non-test package name ending that way). Reading the
				// two fields in the wrong order — the single likeliest way to reintroduce Finding 1
				// while every count still balances — inverts both answers at once, and this is what
				// makes that loud instead of silent.
				name := ""
				if f.Name != nil {
					name = f.Name.Name
				}
				if err := checkPackageClause(p, name, group.external); err != nil {
					return nil, err
				}
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					// A METHOD IS NOT A TEST. `func (r *rig) TestX()` is never run by the testing
					// package, so a receiver disqualifies the declaration however the name reads.
					if !ok || fn.Recv != nil || fn.Name == nil {
						continue
					}
					// THE HARNESS ENTRY POINT IS NOT A TEST. `func TestMain(m *testing.M)` is where
					// the test binary STARTS; the toolchain never registers it and `go test -list`
					// never prints it. Counting the declaration was the one name wide enough to walk
					// through the lane pairing: the list witness is `-list` STDOUT, TestMain is the one
					// function that RUNS during a listing run, so a TestMain printing its own name
					// supplied the list half while this loop supplied the other — both witnesses
					// agreeing about a name that registers no test.
					//
					// THE SIGNATURE DECIDES, NOT THE NAME, and that is not a detail: `func TestMain(t
					// *testing.T)` IS a registered, runnable test (measured — `go test -list` prints it
					// with nothing printing it), so excluding the name would refuse a legitimate claim
					// on a legitimate test. This is cmd/go's own rule, applied to the same AST it
					// applies it to: a single `*T`-shaped parameter is a test, anything else named
					// TestMain is the entry point.
					n := fn.Name.Name
					if n == "TestMain" && !isTestTParam(fn) {
						continue
					}
					// The same grammar the testing package applies: `Test` alone, or `Test` followed
					// by a character that is not a lower-case letter.
					if isGoTestName(n) {
						out.add(key, n, testDecl{File: p, Line: fset.Position(fn.Pos()).Line, PkgName: name})
					}
				}
			}
		}
	}
	return out, nil
}

// checkPackageClause holds the file's own `package` clause against the file list `go list` put it
// in. It is a structural cross-check, not a style rule: the whole of Finding 1 was the two lists
// being indistinguishable, and reading them in the wrong order would restore that while every count
// in this program still balanced.
func checkPackageClause(file, clause string, external bool) error {
	if clause == "" {
		return fmt.Errorf("%s declares no package clause — a Go file the toolchain compiles always has one, so this is not the file `go list` named", file)
	}
	isExt := strings.HasSuffix(clause, "_test") && clause != "_test"
	if external && !isExt {
		return fmt.Errorf("%s is in XTestGoFiles — the EXTERNAL test package — but its clause is `package %s`, which does not end in `_test`; the two test file lists are being read in the wrong order, which merges a package's internal and external tests back into one namespace", file, clause)
	}
	if !external && isExt {
		return fmt.Errorf("%s is in TestGoFiles — compiled INTO the package under test — but its clause is `package %s`, which names the external test package; the two test file lists are being read in the wrong order, which merges a package's internal and external tests back into one namespace", file, clause)
	}
	return nil
}

// isTestTParam reports whether fn takes exactly one parameter of the shape `*T` or `*something.T`
// — cmd/go's own test for "this is a testing.T", written the way cmd/go writes it.
//
// IT CANNOT RESOLVE THE IMPORT, AND NEITHER DOES THE TOOLCHAIN: how `testing` was imported is not
// knowable from one file's syntax alone (`import tt "testing"` makes the entry point `*tt.M`), so
// cmd/go compares the SELECTED NAME and so does this. That leaves one honest gap in the same place
// the toolchain leaves it: a package with its own type named `T`, taking `*mine.T`, reads as a
// test. It is the direction that costs nothing here — such a function is a build error under
// `go test` ("wrong signature"), so the lane never lists it and the audit never sees it.
func isTestTParam(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	ptr, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if id, ok := ptr.X.(*ast.Ident); ok {
		return id.Name == "T"
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok {
		return sel.Sel != nil && sel.Sel.Name == "T"
	}
	return false
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
//
// AND IT SAYS WHICH OF THE PACKAGE'S TWO TEST PACKAGES, not only which import path. An unqualified
// claim binds to the compiled test package of the FILE IT IS WRITTEN IN — a claim in an external
// test file is a claim in `x_test`, which is not `x` and may declare a different test of the same
// name. That is the resolution Finding 1 was missing: with the two merged, a claim in `x_test` was
// answered by `x`'s namesake and survived the deletion of the test it was actually about.
func candidatePackages(all map[string]map[string]bool, goFile string, site fileKind, tg target) (map[string]bool, bind) {
	bySeg := map[string][]string{}
	for p := range all {
		bySeg[path.Base(p)] = append(bySeg[path.Base(p)], p)
	}
	out := map[string]bool{}
	// FOR THIS TARGET ONLY, AND FROM ITS OWN TOKEN. A claim naming two tests may qualify one of
	// them and not the other, and the unqualified one must not borrow the qualified one's package.
	// The qualification is part of the token the claim spelled, so no arrangement of words
	// anywhere else in the line can supply, widen or contradict one.
	//
	// A QUALIFICATION CONSTRAINS; IT DOES NOT WIDEN. An earlier version added the qualified package
	// BESIDE the claiming file's own, which left the hole facing the other way:
	// `internal/w.TestShared`, written in internal/x, stayed green after internal/w.TestShared was
	// DELETED, because a namesake in internal/x satisfied it. A claim that says where its target
	// lives is answered by THAT package or by nothing.
	if tg.Pkg != "" {
		addTo(all, bySeg, out, tg.Pkg)
		if len(out) > 0 {
			// THE QUALIFIER NAMES AN IMPORT PATH AND NOT A HALF OF IT, so it constrains the package
			// and leaves the internal/external question to UNIQUENESS: one declaration answers it,
			// two REFUSE. Picking one would be the widening this whole family of findings is made of.
			return out, bindEither
		}
		// `x_test` IS THE EXTERNAL TEST PACKAGE'S REAL PATH, and it is the only way to name that
		// half from outside it. Tried only after the token failed as a path of its own, so a module
		// that really does hold a package whose last segment ends in `_test` keeps it: the exact
		// path always wins.
		if base, ok := strings.CutSuffix(tg.Pkg, "_test"); ok && base != "" {
			addTo(all, bySeg, out, base)
			if len(out) > 0 {
				return out, bindExternal
			}
		}
		return out, bindEither
	}
	// UNQUALIFIED: the claiming file's own package, and nothing else. Resolved by the SAME rule as
	// a qualifier — the directory a claim is written in is a package-path token like any other, and
	// it is matched as a suffix for the same reason (this tool is not told the module path). It was
	// the branch WITHOUT the uniqueness rule for longer than the qualifier one, and it carries
	// nearly every claim in the tree.
	if p, ok := resolvePathToken(all, path.Dir(filepath.ToSlash(goFile))); ok {
		out[p] = true
	}
	return out, site.bind()
}

// fileKind says which of a package's three compiled file sets a file belongs to. It is what makes a
// claim's OWN package knowable: `internal/x/x_test.go` and `internal/x/ext_test.go` sit in one
// directory and resolve to one import path, but one is compiled into `package x` and the other into
// `package x_test`, and a test declared in either is invisible to the other.
type fileKind int

const (
	fileOrdinary     fileKind = iota // GoFiles — compiled into the package itself
	fileInternalTest                 // TestGoFiles — compiled into the package under test
	fileExternalTest                 // XTestGoFiles — compiled into the external `x_test` package
)

// bind says WHICH compiled test package a target may be resolved in.
type bind int

const (
	// bindEither — the claim did not say, so only a UNIQUE declaration answers it. Two same-named
	// declarations refuse rather than one of them winning.
	bindEither bind = iota
	bindInternal
	bindExternal
)

// bind is where a claim written in a file of this kind may look. An ORDINARY source file is not
// compiled into either test package, so a claim in one names no half and falls back to uniqueness —
// the honest answer, and the one that cannot silently pick a winner.
func (k fileKind) bind() bind {
	switch k {
	case fileInternalTest:
		return bindInternal
	case fileExternalTest:
		return bindExternal
	}
	return bindEither
}

// resolution is what ONE lane can say about ONE target in ONE package. Its two problem fields are
// DECISIVE reasons — the question was reached and refused — as opposed to a plain miss, which is
// silence: another lane may still answer, and only if none does are these reported.
type resolution struct {
	OK        bool
	Ambiguous string // two declarations this claim cannot choose between
	WrongPkg  string // declared in this import path, but in its OTHER compiled test package
	Disagree  string // the two witnesses disagree about HOW MANY tests carry the name
	NotRun    string // it exists in this lane, but this lane cannot witness that it RAN
}

// resolve binds ONE target to ONE declaration, or says why it cannot.
//
// EXACTLY ONE DECLARATION, NEVER "AT LEAST ONE". A name present in both `x` and `x_test` is TWO
// tests; answering a claim that does not say which with either of them is how the deleted one keeps
// its claim green. Where the claim's own file settles it — an unqualified claim is about its own
// compiled test package — that is the binding; where nothing settles it, this REFUSES.
func (ln testLane) resolve(pkg string, bd bind, name string) resolution {
	in := ln.src[testPkg{Path: pkg}][name]
	ex := ln.src[testPkg{Path: pkg, External: true}][name]
	var want, other []testDecl
	otherPkg := testPkg{Path: pkg}
	switch bd {
	case bindInternal:
		want, other, otherPkg = in, ex, testPkg{Path: pkg, External: true}
	case bindExternal:
		want, other = ex, in
	default:
		want = append(append([]testDecl{}, in...), ex...)
	}
	if len(want) > 1 {
		return resolution{Ambiguous: fmt.Sprintf(
			"is declared %d times under %s — %s — and this claim names no one of them: a name declared in a package AND in its external test package is TWO tests, compiled separately, and accepting either lets the one this claim is about be deleted while the claim stays green. Name the external one as `%s.%s`, or move the claim into the file whose own package declares the test it is about",
			len(want), pkg, declList(want), testPkg{Path: pkg, External: true}, name)}
	}
	if len(want) == 0 {
		if len(other) > 0 {
			return resolution{WrongPkg: fmt.Sprintf(
				"is not declared in %s — it is declared in %s (%s), which is a DIFFERENT package: `x` and `x_test` are compiled separately and each may declare its own test of a given name, so a claim in one is never about a declaration in the other. Qualify the target as `%s.%s`, or move the claim beside the test",
				bindPkg(pkg, bd), otherPkg, declList(other), otherPkg, name)}
		}
		return resolution{}
	}
	// BOTH WITNESSES, WITHIN ONE LANE. `go test -list` says that lane registers the name (so it
	// compiles and runs there); the lane's ACTIVE test files say that package really declares it.
	// Agreement ACROSS lanes proves nothing: a name printed by one lane's init and declared in a
	// file only another lane compiles satisfies both halves while no lane runs a test by that name.
	listed := ln.list[pkg][name]
	if listed == 0 {
		return resolution{}
	}
	// AND THEY MUST AGREE ON HOW MANY. The listing prints one line per registered test, so a package
	// declaring the name twice — once internally, once externally — prints it twice. A count that
	// does not match the declarations is the two halves describing different worlds: an extra line
	// is something a package PRINTED during the listing run (the list witness is stdout), a missing
	// one is a declaration the toolchain did not register. Either way this lane cannot say which
	// test the claim is about, and saying yes anyway is exactly the guess this audit must not make.
	declared := len(in) + len(ex)
	if listed != declared {
		return resolution{Disagree: fmt.Sprintf(
			"is declared %d time(s) under %s but `go test -list` printed it %d time(s) for that package — the two witnesses disagree about how many tests carry this name, so neither can say which one this claim is about",
			declared, pkg, listed)}
	}
	// THE THIRD WITNESS, AND THE ONLY ONE THAT ANSWERS THE QUESTION THE PROMISE ASKS. Everything
	// above establishes that the test EXISTS: a file this lane compiles declares it, and the
	// toolchain printed it. Neither says it RUNS. `func TestMain(m *testing.M)` is the package's own
	// entry point, so it can print a name during a `-test.list` run and then set `-test.run` to
	// something else for the real one — measured, and both of the checks above stay satisfied.
	if !ln.executed {
		return resolution{NotRun: fmt.Sprintf(
			"is declared and listed under %s, but the %s lane is NOT EXECUTED by this audit (%s) — so nothing here witnesses that it RUNS, and existence is not the claim being made. Either give this lane an execution witness, or move the claim to a test a run of this audit actually executes",
			pkg, ln.name, ln.execWhy)}
	}
	// COUNTED AGAINST THE DECLARATIONS FOR THE REASON THE LISTING IS. A name declared once in the
	// package and once in its external test package is two tests running under one package in the
	// run events; if only one of them started, this lane cannot say which one the claim is about —
	// and the one that did not start is exactly the one a claim would be hiding.
	ran := ln.exec[pkg][name]
	if ran == 0 {
		return resolution{NotRun: fmt.Sprintf(
			"is declared and listed under %s but NEVER RAN: an unfiltered `go test -json -count=1` of the %s lane started no test by that name. A test that exists and does not execute is the hole this inventory exists to prevent, and the two existence witnesses cannot see it",
			pkg, ln.name)}
	}
	if ran != declared {
		return resolution{NotRun: fmt.Sprintf(
			"is declared %d time(s) under %s but only %d of them RAN in the %s lane — the declarations and the run events disagree about how many tests of this name execute, so neither can say which one this claim is about, and the one that never ran is the one a claim would be hiding",
			declared, pkg, ran, ln.name)}
	}
	return resolution{OK: true}
}

// bindPkg spells the package a claim was allowed to look in, for a message.
func bindPkg(pkg string, bd bind) string {
	switch bd {
	case bindInternal:
		return testPkg{Path: pkg}.String()
	case bindExternal:
		return testPkg{Path: pkg, External: true}.String()
	}
	return pkg + " or " + testPkg{Path: pkg, External: true}.String()
}

// declList names WHERE declarations are, because a message about which of two tests a claim means is
// useless without the two files.
func declList(ds []testDecl) string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, fmt.Sprintf("%s:%d", filepath.Base(d.File), d.Line))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// addTo resolves one package token into out. A multi-segment token must match a real path SUFFIX,
// so cmd/probe can never resolve to internal/probe; a bare segment resolves only when it names
// exactly one package in the module, because an ambiguous reference must not widen anything.
func addTo(all map[string]map[string]bool, bySeg map[string][]string, out map[string]bool, tok string) {
	tok = strings.Trim(tok, "/")
	if tok == "" {
		return
	}
	if strings.Contains(tok, "/") {
		if p, ok := resolvePathToken(all, tok); ok {
			out[p] = true
		}
		return
	}
	if ps := bySeg[tok]; len(ps) == 1 {
		out[ps[0]] = true
	}
}

// resolvePathToken resolves ONE package-path token to AT MOST ONE package: an exact match on the
// whole import path wins outright, otherwise a path suffix is accepted only when exactly one
// package has it, and anything else resolves to NOTHING.
//
// A SUFFIX IS NOT AN IDENTITY, AND FOR A WHILE THIS TREATED IT AS ONE. The multi-segment branch
// added EVERY package ending in the token, so with `internal/w` and `nested/internal/w` both in the
// module, `internal/w.TestShared` was answered by both: delete the test the claim is about, keep a
// namesake in the nested package, and the audit certifying that the deleted bash tree lost nothing
// stays green over a Go test that is gone. The bare-segment branch beside it had required
// uniqueness from the start (`len(ps) == 1`) — the rule was already written down, one branch simply
// did not obey it, and the unqualified own-package branch did not either.
//
// So it is spelled ONCE and every branch that turns a path token into a package calls it. That is
// the point of the shape, not tidiness: three copies of a resolution rule is three places for the
// next reader to fix two of.
//
// AMBIGUITY RESOLVES TO NOTHING, NEVER TO A WINNER. An unresolvable claim fails closed and the
// message tells its author to name the package; a claim answered by whichever namesake was seen
// last is a green that means nothing. Widening is the defect this family of findings is made of,
// so it can never also be the fix.
func resolvePathToken(all map[string]map[string]bool, tok string) (string, bool) {
	if _, ok := all[tok]; ok {
		return tok, true
	}
	found, n := "", 0
	for p := range all {
		if strings.HasSuffix(p, "/"+tok) {
			found, n = p, n+1
		}
	}
	if n == 1 {
		return found, true
	}
	return "", false
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
			if s.OffLane {
				// A DIFFERENT INVISIBILITY, AND IT NEEDS ITS OWN SENTENCE. This claim may be
				// perfectly written; the FILE is the problem. No lane compiles it — it is under
				// testdata, or a build constraint excludes it — so nothing in it runs and nothing
				// in it can testify about what runs. Demonstrated: a real claim moved into
				// `<pkg>/testdata/broken.go`, behind a line that is not Go at all, was credited and
				// the whole parity stage exited 0.
				r.fail("%s:%d: this file is in NO audited lane's file selection (under testdata, or excluded by a build constraint), so nothing in it compiles and a claim in it describes nothing that runs — yet it names %s (%s). Move the claim to the test file that actually covers the row: %s",
					s.GoFile, s.GoLine, cand, why, strings.TrimSpace(s.Text))
				break
			}
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
			cands, bd := candidatePackages(goTests, c.GoFile, c.Site, t)
			pkgs := make([]string, 0, len(cands))
			for p := range cands {
				pkgs = append(pkgs, p)
			}
			// SORTED, so a message names the same package on every run. There is at most one
			// candidate today; a resolution rule that depends on map order is a defect waiting for
			// the day there are two.
			sort.Strings(pkgs)
			found := false
			var decisive string
			for _, p := range pkgs {
				for _, ln := range testLanes {
					res := ln.resolve(p, bd, t.Name)
					if res.OK {
						found = true
						break
					}
					// A DECISIVE REASON IS KEPT, A PLAIN MISS IS NOT. Another lane may still answer
					// this target, so nothing is reported until every lane has been asked; but when
					// none does, the reason a lane REACHED and refused says far more than "does not
					// exist" — which is what this used to say about a test sitting in the next
					// package over.
					for _, why := range []string{res.Ambiguous, res.Disagree, res.NotRun, res.WrongPkg} {
						if why != "" && decisive == "" {
							decisive = why
						}
					}
				}
				if found {
					break
				}
			}
			if found {
				continue
			}
			if decisive != "" {
				r.fail("%s:%d: PORTED target %s %s (claim: %s: %q)",
					c.GoFile, c.GoLine, t, decisive, c.Pair.File, c.Pair.Name)
				continue
			}
			var elsewhere []string
			for p, names := range goTests {
				if names[t.Name] {
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
		goExecs   listFlag
		failFirst = flag.Int("max-problems", 0, "print at most this many problems (0 = all)")
	)
	flag.Var(&goLists, "go-list", "file holding `go test -list` output; repeatable (once per build-tag lane)")
	flag.Var(&goFiles, "go-files", "file holding `go list -f '{{.ImportPath}}\\t{{.Dir}}\\t{{join .GoFiles \" \"}}\\t{{join .TestGoFiles \" \"}}\\t{{join .XTestGoFiles \" \"}}'` output for the SAME lane, in the SAME order as --go-list")
	flag.Var(&goExecs, "go-exec", "file holding `go test -json -count=1 ./...` output for the SAME lane, in the SAME order as --go-list — or `not-executed:<why>` to state that this lane is deliberately not run, in which case it can confirm no PORTED target")
	flag.Parse()

	if err := run(*root, *manifest, *writeMan, goLists, goFiles, goExecs, *failFirst); err != nil {
		fmt.Fprintf(os.Stderr, "parity-audit: %v\n", err)
		os.Exit(1)
	}
}

func run(root, manifestRel string, writeMan bool, goLists, goFiles, goExecs []string, maxProblems int) error {
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

	// THE TWO WITNESSES ARRIVE PAIRED, ONE PAIR PER LANE, and the pairing is checked rather than
	// assumed: an unpaired list would silently reintroduce the very independence the pairing
	// removes — a lane whose source half is empty resolves nothing, and one whose list half is
	// empty would be skipped without anybody noticing which lane went missing.
	if len(goFiles) != len(goLists) || len(goExecs) != len(goLists) {
		return fmt.Errorf("--go-list was given %d time(s), --go-files %d and --go-exec %d — they are ONE witness\n"+
			"   TRIPLE per build-tag lane and must be given in the same number and the same order: the source\n"+
			"   half of target resolution is built from the files THAT LANE compiles, and the execution half\n"+
			"   from what THAT LANE actually ran",
			len(goLists), len(goFiles), len(goExecs))
	}
	var testLanes []testLane
	// EVERY FILE THE TOOLCHAIN COMPILES, ACROSS EVERY LANE. This is the set a claim may be written
	// in; nothing outside it is read as a claim, whatever it says. Union rather than intersection
	// because the acceptance lane genuinely compiles a file the default lane does not, and a claim
	// in it is legitimate.
	eligible := map[string]fileKind{}
	names := 0
	executedLanes := 0
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
		for _, pf := range files {
			// THE KIND TRAVELS WITH THE FILE, because a claim's own compiled test package is what an
			// unqualified target resolves against. Ordinary source last would be wrong and internal
			// last would be wrong: a file is in exactly one of the three lists, in every lane, so
			// the order these are written in cannot matter — and checkPackageClause is what proves
			// that independently of `go list`.
			for _, f := range pf.Go {
				eligible[canonPath(f)] = fileOrdinary
			}
			for _, f := range pf.Test {
				eligible[canonPath(f)] = fileInternalTest
			}
			for _, f := range pf.XTest {
				eligible[canonPath(f)] = fileExternalTest
			}
		}
		src, serr := collectLaneSource(files)
		if serr != nil {
			return serr
		}
		// THE EXECUTION HALF OF THIS LANE — a file of `go test -json` events, or a stated argument
		// for not running the lane at all. There is no third possibility and no default: a missing
		// value is refused by the arity check above, so no lane can arrive without having answered
		// the question.
		ln := testLane{name: p, list: parseGoTestList(content), src: src}
		if why, notRun := strings.CutPrefix(goExecs[i], notExecutedPrefix); notRun {
			why = strings.TrimSpace(why)
			// AN OPT-OUT WITH NO ARGUMENT IS THE QUIET SPECIAL CASE THIS WITNESS EXISTS TO FORBID.
			// A lane may legitimately be unrunnable here — the acceptance lane needs a live daemon —
			// but that is a claim about the world, and it has to be written down where the refusal
			// it causes can quote it.
			if why == "" {
				return fmt.Errorf("--go-exec %q declares the lane listed in %s not executed but gives no reason;\n"+
					"   write it as `%s<why this lane cannot be run here>` — a lane that opts out of the\n"+
					"   execution witness can confirm no PORTED target, and the claim that is refused because of\n"+
					"   it quotes this text", goExecs[i], p, notExecutedPrefix)
			}
			ln.execWhy = why
		} else {
			econtent, eerr := os.ReadFile(goExecs[i])
			if eerr != nil {
				return fmt.Errorf("reading go-test execution witness: %w", eerr)
			}
			exec, eperr := parseGoTestExec(goExecs[i], econtent)
			if eperr != nil {
				return eperr
			}
			// THE SAME LIVENESS ARGUMENT THE OTHER TWO HALVES GET, and it is what stops a truncated,
			// empty or failed-to-build witness from silently turning the strongest evidence in this
			// program back into the weakest. An empty file parses cleanly and testifies to nothing.
			laneRan := 0
			for _, ns := range exec {
				laneRan += len(ns)
			}
			if laneRan == 0 {
				return fmt.Errorf("%s records no test as having RUN — `go test -json -count=1` started nothing for\n"+
					"   this lane, so it can witness no target at all. Either the run failed before any test\n"+
					"   executed (a build error, or a filter in the environment), or the witness was not captured.",
					goExecs[i])
			}
			ln.exec, ln.executed = exec, true
			executedLanes++
		}
		// EACH LANE'S OWN LIVENESS, not the union's. A lane that registers nothing, or whose
		// compiled test files declare nothing, resolves no target — and a union check would hide
		// that behind the other lane.
		//
		// COUNTED IN NAMES, NOT IN PACKAGE ENTRIES, and the difference is the whole guard. Both
		// halves manufacture a package entry without a single test in it: `? <pkg> [no test files]`
		// is a terminator line, so parseGoTestList records the package with an empty name set, and a
		// compiled `_test.go` holding nothing but its `package` clause used to do the same on the
		// source side. A lane in exactly that state — no registered test, no declared test — passed
		// both checks, and the comment above said it could not. What a lane must have is a NAME.
		laneListed := 0
		for _, ns := range ln.list {
			laneListed += len(ns)
		}
		if laneListed == 0 {
			return fmt.Errorf("%s lists no test names — `go test -list` registered nothing for this lane, so it can\n"+
				"   confirm no target at all and the other lane would be answering for it", p)
		}
		laneDeclared := 0
		for _, ns := range src {
			laneDeclared += len(ns)
		}
		if laneDeclared == 0 {
			return fmt.Errorf("%s names compiled test files that DECLARE no test — the source half of target\n"+
				"   resolution has nothing to check against for this lane", goFiles[i])
		}
		names += laneListed
		testLanes = append(testLanes, ln)
	}
	// Same liveness argument one level down: an empty set of known tests would make every PORTED
	// target unresolvable, which is loud — but an empty set arriving because nobody passed a list
	// would make it loud for the wrong reason, and the fix would be to add the flag rather than to
	// look at the port. Say so up front.
	if names == 0 {
		return fmt.Errorf("no Go test names were loaded (pass --go-list <file> with `go test -list '.*' ./...` output) — PORTED targets cannot be resolved")
	}
	// ...and the same argument for the execution half. If EVERY lane declares itself not executed
	// the audit still runs, still parses, still resolves nothing — and reports 1,121 dangling
	// targets, which is loud about the wrong thing. Say the real reason once, up front.
	if executedLanes == 0 {
		return fmt.Errorf("no lane was executed: every --go-exec is a `%s` argument, so nothing here witnesses that\n"+
			"   any test RUNS and no PORTED target can be resolved. At least one lane must be run with\n"+
			"   `go test -json -count=1 ./...`, unfiltered", notExecutedPrefix)
	}
	// THE CLAIM-BEARING SET NEEDS NO SEPARATE LIVENESS CHECK, and saying so is worth more than a
	// check that cannot fire: every lane has already been refused unless its compiled TEST files
	// declare something (the `len(src) == 0` check above), and a compiled test file is by
	// construction a member of `eligible`. An empty selection is therefore unreachable from here.
	claims, bad, strays, scanned, err := collectInventory(root, eligible)
	if err != nil {
		return err
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
