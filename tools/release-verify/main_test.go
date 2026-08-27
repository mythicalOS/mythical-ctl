// No bats inventory: this is Wave 8 release tooling, not a port of a bash module. The frozen
// tests/unit/bundle.bats covers the retiring bash bundler's inline-the-modules mechanism, and
// the rewrite plan assigns it to the parity audit as a declared N/A whose successor property is
// the build-twice digest comparison exercised here (TestCompareDetectsADifferingArtifact, and
// the --repro path of tools/build-release.sh).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testVersion = "9.8.7-verifytest"

// Built once for the whole package: six `go build` invocations is the price of grading real
// artifacts instead of fixtures that only look like them, and a fixture binary could not carry
// build info at all.
var (
	builtDir      string // the full matrix, built the way a release builds it
	hostArtifact  string // the host-platform member of that matrix
	unstampedBin  string // host build whose -X names a symbol that does not exist
	noTrimpathBin string // host build without -trimpath
	hostTarget    = Target{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "release-verify-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	builtDir = filepath.Join(dir, "matrix")
	if err := os.MkdirAll(builtDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, t := range targets {
		out := filepath.Join(builtDir, t.Artifact())
		if err := goBuild(out, t, true, VersionSymbolForTest, testVersion); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if t == hostTarget {
			hostArtifact = out
		}
	}
	if err := writeSums(builtDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	unstampedBin = filepath.Join(dir, "unstamped")
	if err := goBuild(unstampedBin, hostTarget, true, "mythicalos.ai/ctl/internal/verzion.Version", testVersion); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	noTrimpathBin = filepath.Join(dir, "notrimpath")
	if err := goBuild(noTrimpathBin, hostTarget, false, VersionSymbolForTest, testVersion); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// VersionSymbolForTest is the same symbol path tools/build-release.sh stamps. It is spelled
// out here rather than imported so that a test cannot agree with the script by construction.
const VersionSymbolForTest = "mythicalos.ai/ctl/internal/version.Version"

func moduleRoot() string { return filepath.Join("..", "..") }

func goBuild(out string, t Target, trimpath bool, symbol, version string) error {
	args := []string{"build"}
	if trimpath {
		args = append(args, "-trimpath")
	}
	args = append(args,
		"-buildvcs=false",
		"-ldflags", "-s -w -X "+symbol+"="+version,
		"-o", out,
		"./cmd/mythical-ctl",
	)
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOFLAGS=",
		"GOOS="+t.GOOS,
		"GOARCH="+t.GOARCH,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build %s: %w: %s", t, err, stderr.String())
	}
	return nil
}

// writeSums produces the checksum file the way the build script does, but with an independent
// implementation, so the tests are not merely re-running the code under test.
func writeSums(dir string) error {
	var b strings.Builder
	for _, t := range targets {
		data, err := os.ReadFile(filepath.Join(dir, t.Artifact()))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), t.Artifact())
	}
	return os.WriteFile(filepath.Join(dir, sumsName), []byte(b.String()), 0o644)
}

// copyMatrix gives a test its own copy of the built matrix to damage.
func copyMatrix(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(builtDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(builtDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func forbidNothingReal() []string { return []string{"/this/path/appears/in/no/binary"} }

func mustFail(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal mentioning %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not mention %q", err.Error(), want)
	}
}

// --- version stamping ------------------------------------------------------------------

func TestCheckVersionRefusesEmpty(t *testing.T) {
	mustFail(t, checkVersion(""), "empty")
}

func TestCheckVersionRefusesLeadingV(t *testing.T) {
	mustFail(t, checkVersion("v1.2.3"), `leading "v"`)
}

func TestCheckVersionRefusesNonSemver(t *testing.T) {
	for _, v := range []string{"1.2", "1.2.3.4", "latest", "1.2.3 ", " 1.2.3", "1.2.3-", "01.2.3-a b"} {
		if err := checkVersion(v); err == nil {
			t.Errorf("checkVersion(%q) accepted a version that is not X.Y.Z[-suffix]", v)
		}
	}
}

func TestCheckVersionAcceptsSemver(t *testing.T) {
	for _, v := range []string{"0.0.0", "1.2.3", "0.1.0-dev", "10.20.30-rc.1"} {
		if err := checkVersion(v); err != nil {
			t.Errorf("checkVersion(%q) = %v, want nil", v, err)
		}
	}
}

func TestCheckStampRefusesAWrongVersion(t *testing.T) {
	mustFail(t, checkStamp(hostArtifact, "0.0.0"), "want")
}

func TestCheckStampAcceptsTheStampedVersion(t *testing.T) {
	if err := checkStamp(hostArtifact, testVersion); err != nil {
		t.Fatalf("checkStamp on the freshly built host artifact: %v", err)
	}
}

// The linker accepts -X against a symbol that does not exist and says nothing, so the artifact
// silently ships the compiled-in default. Nothing but reading the bytes back catches it.
func TestCheckArtifactRefusesAnUnstampedBuild(t *testing.T) {
	_, err := checkArtifact(unstampedBin, hostTarget, testVersion, forbidNothingReal())
	mustFail(t, err, "the -X stamp did not reach it")
}

// --- build-environment independence ----------------------------------------------------

func TestScanForbiddenFindsAPath(t *testing.T) {
	data := []byte("prefix/Users/someone/checkout/internal/x.gosuffix")
	mustFail(t, scanForbidden(data, []string{"/Users/someone/checkout"}), "not path-independent")
	if err := scanForbidden(data, []string{"/opt/elsewhere"}); err != nil {
		t.Fatalf("scanForbidden flagged a path that is not present: %v", err)
	}
}

func TestCheckForbiddenRefusals(t *testing.T) {
	cases := []struct {
		name   string
		forbid []string
		want   string
	}{
		{"empty list", nil, "without reading anything"},
		{"empty entry", []string{"/a", ""}, "empty --forbid entry"},
		{"relative", []string{"relative/path"}, "not an absolute path"},
		{"root", []string{"/"}, "matches every artifact"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, checkForbidden(tc.forbid), tc.want)
		})
	}
	if err := checkForbidden([]string{"/some/build/root"}); err != nil {
		t.Fatalf("checkForbidden rejected a usable path: %v", err)
	}
}

func TestCheckArtifactRefusesAnEmbeddedBuildPath(t *testing.T) {
	dir := t.TempDir()
	leak := "/home/builder/checkout-that-should-not-travel"
	data, err := os.ReadFile(hostArtifact)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, hostTarget.Artifact())
	if err := os.WriteFile(path, append(data, []byte(leak)...), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = checkArtifact(path, hostTarget, testVersion, []string{leak})
	mustFail(t, err, "not path-independent")
}

func TestCheckBuildInfoRefusesANonTrimpathBuild(t *testing.T) {
	mustFail(t, checkBuildInfo(noTrimpathBin, hostTarget), "-trimpath")
}

func TestCheckBuildInfoAcceptsAReleaseBuild(t *testing.T) {
	for _, tg := range targets {
		if err := checkBuildInfo(filepath.Join(builtDir, tg.Artifact()), tg); err != nil {
			t.Errorf("%s: %v", tg, err)
		}
	}
}

// The GOOS/GOARCH suffix in the file name is a claim; the build info is the fact. A file that
// is a copy of another platform's build must not pass under this name.
func TestCheckArtifactRefusesTheWrongPlatform(t *testing.T) {
	var other Target
	for _, tg := range targets {
		if tg != hostTarget {
			other = tg
			break
		}
	}
	_, err := checkArtifact(hostArtifact, other, testVersion, forbidNothingReal())
	mustFail(t, err, "build setting")
}

// --- truncation and permissions ---------------------------------------------------------

func TestCheckArtifactRefusesATruncatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hostTarget.Artifact())
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := checkArtifact(path, hostTarget, testVersion, forbidNothingReal())
	mustFail(t, err, "well-formed digest")
}

func TestCheckArtifactRefusesANonExecutableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hostTarget.Artifact())
	data, err := os.ReadFile(hostArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = checkArtifact(path, hostTarget, testVersion, forbidNothingReal())
	mustFail(t, err, "not executable")
}

// --- the checksum file --------------------------------------------------------------------

func sumsFixture(t *testing.T, body string) (string, []artifact) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, sumsName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	arts := []artifact{
		{name: "mythical-ctl_linux_amd64", size: 2 << 20, digest: strings.Repeat("a", 64)},
		{name: "mythical-ctl_linux_arm64", size: 2 << 20, digest: strings.Repeat("b", 64)},
	}
	return path, arts
}

func TestCheckSumsAcceptsAMatchingFile(t *testing.T) {
	path, arts := sumsFixture(t, strings.Repeat("a", 64)+"  mythical-ctl_linux_amd64\n"+
		strings.Repeat("b", 64)+"  mythical-ctl_linux_arm64\n")
	if err := checkSums(path, arts); err != nil {
		t.Fatalf("checkSums on a matching file: %v", err)
	}
}

func TestCheckSumsRefusals(t *testing.T) {
	good := strings.Repeat("a", 64) + "  mythical-ctl_linux_amd64\n" + strings.Repeat("b", 64) + "  mythical-ctl_linux_arm64\n"
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty file", "", "is empty"},
		{"malformed line", "not a checksum line\n", "is not"},
		{"single space separator", strings.Repeat("a", 64) + " mythical-ctl_linux_amd64\n", "is not"},
		{"path traversal in name", strings.Repeat("a", 64) + "  ../mythical-ctl_linux_amd64\n", "is not"},
		{"duplicate entry", good + strings.Repeat("a", 64) + "  mythical-ctl_linux_amd64\n", "twice"},
		{"missing an artifact", strings.Repeat("a", 64) + "  mythical-ctl_linux_amd64\n", "does not list"},
		{"digest mismatch", strings.Repeat("c", 64) + "  mythical-ctl_linux_amd64\n" + strings.Repeat("b", 64) + "  mythical-ctl_linux_arm64\n", "recomputed"},
		{"lists something extra", good + strings.Repeat("d", 64) + "  mythical-ctl_plan9_386\n", "not one of the artifacts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, arts := sumsFixture(t, tc.body)
			mustFail(t, checkSums(path, arts), tc.want)
		})
	}
}

func TestCheckSumsRefusesAMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, arts := sumsFixture(t, "")
	mustFail(t, checkSums(filepath.Join(dir, sumsName), arts), sumsName)
}

// --- the directory as a whole ---------------------------------------------------------------

func TestVerifyAcceptsAFreshlyBuiltMatrix(t *testing.T) {
	var out bytes.Buffer
	if err := verify(builtDir, testVersion, forbidNothingReal(), hostTarget, false, &out); err != nil {
		t.Fatalf("verify on a freshly built matrix: %v\n%s", err, out.String())
	}
	// Byte counts must be printed beside digests: a digest alone cannot tell a reader that the
	// thing hashed had any content.
	if !strings.Contains(out.String(), "size=") || !strings.Contains(out.String(), "sha256=") {
		t.Fatalf("verify output prints no size/digest pair:\n%s", out.String())
	}
}

func TestVerifyRefusesAnUnexpectedFile(t *testing.T) {
	dir := copyMatrix(t)
	if err := os.WriteFile(filepath.Join(dir, "NOTES.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustFail(t, verify(dir, testVersion, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "unexpected file")
}

func TestVerifyRefusesAMissingArtifact(t *testing.T) {
	dir := copyMatrix(t)
	if err := os.Remove(filepath.Join(dir, targets[0].Artifact())); err != nil {
		t.Fatal(err)
	}
	mustFail(t, verify(dir, testVersion, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "artifact set is incomplete")
}

func TestVerifyRefusesAMissingSumsFile(t *testing.T) {
	dir := copyMatrix(t)
	if err := os.Remove(filepath.Join(dir, sumsName)); err != nil {
		t.Fatal(err)
	}
	mustFail(t, verify(dir, testVersion, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "artifact set is incomplete")
}

func TestVerifyRefusesAVersionTheArtifactsDoNotCarry(t *testing.T) {
	mustFail(t, verify(builtDir, "1.2.3", forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "did not reach it")
}

func TestVerifyRefusesAnEmptyForbidList(t *testing.T) {
	mustFail(t, verify(builtDir, testVersion, nil, hostTarget, false, &bytes.Buffer{}), "without reading anything")
}

func TestVerifyRefusesADirectoryThatIsAFile(t *testing.T) {
	mustFail(t, verify(hostArtifact, testVersion, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "not a directory")
}

// The host round-trip is the only proof that the version symbol still resolves; if the host is
// outside the matrix it cannot run, and that must be an explicit decision rather than a silent
// one.
func TestVerifyRefusesToSkipTheHostRoundTripSilently(t *testing.T) {
	outside := Target{GOOS: "plan9", GOARCH: "386"}
	mustFail(t, verify(builtDir, testVersion, forbidNothingReal(), outside, false, &bytes.Buffer{}), "--allow-no-host-exec")

	var out bytes.Buffer
	if err := verify(builtDir, testVersion, forbidNothingReal(), outside, true, &out); err != nil {
		t.Fatalf("verify with --allow-no-host-exec: %v", err)
	}
	if !strings.Contains(out.String(), "SKIPPED") {
		t.Fatalf("the skip was not announced:\n%s", out.String())
	}
}

// --- reproducibility comparison --------------------------------------------------------------

func TestCompareAcceptsTwoIdenticalBuilds(t *testing.T) {
	other := copyMatrix(t)
	if err := compare(builtDir, other, &bytes.Buffer{}); err != nil {
		t.Fatalf("compare of two identical directories: %v", err)
	}
}

func TestCompareRefusesTheSameDirectory(t *testing.T) {
	mustFail(t, compare(builtDir, builtDir, &bytes.Buffer{}), "proves nothing")
}

func TestCompareDetectsADifferingArtifact(t *testing.T) {
	other := copyMatrix(t)
	data, err := os.ReadFile(noTrimpathBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, hostTarget.Artifact()), data, 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	mustFail(t, compare(builtDir, other, &out), "not byte-reproducible")
	if !strings.Contains(out.String(), "DIFFERS") {
		t.Fatalf("compare did not name the differing target:\n%s", out.String())
	}
}

func TestCompareRefusesAMissingArtifact(t *testing.T) {
	other := copyMatrix(t)
	if err := os.Remove(filepath.Join(other, targets[0].Artifact())); err != nil {
		t.Fatal(err)
	}
	mustFail(t, compare(builtDir, other, &bytes.Buffer{}), targets[0].Artifact())
}

func TestCompareRefusesATruncatedArtifact(t *testing.T) {
	other := copyMatrix(t)
	if err := os.WriteFile(filepath.Join(other, targets[0].Artifact()), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	mustFail(t, compare(builtDir, other, &bytes.Buffer{}), "looks perfectly healthy")
}

// --- the matrix and the CLI -------------------------------------------------------------------

func TestTargetsAreUniqueAndWellFormed(t *testing.T) {
	if len(targets) == 0 {
		t.Fatal("the target matrix is empty: the build loop would build nothing")
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		if tg.GOOS == "" || tg.GOARCH == "" {
			t.Fatalf("target %+v has an empty field", tg)
		}
		if seen[tg.Artifact()] {
			t.Fatalf("two targets share the artifact name %q", tg.Artifact())
		}
		seen[tg.Artifact()] = true
	}
}

func TestTargetsSubcommandPrintsTheMatrix(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"targets"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != len(targets) {
		t.Fatalf("printed %d target lines, matrix has %d", len(lines), len(targets))
	}
	for i, tg := range targets {
		if lines[i] != tg.String() {
			t.Fatalf("line %d is %q, want %q", i, lines[i], tg)
		}
	}
}

func TestRunRejectsUnknownAndMalformedInvocations(t *testing.T) {
	cases := [][]string{
		{},
		{"nonsense"},
		{"targets", "extra"},
		{"compare", "only-one"},
		{"verify"},
		{"verify", "--version", "1.2.3", "--forbid", "/x"},
	}
	for _, args := range cases {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("run(%q) returned nil, want an error", args)
		}
	}
}
