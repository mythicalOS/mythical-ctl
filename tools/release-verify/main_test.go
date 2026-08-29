// NO PORTED/N/A INVENTORY HERE, deliberately. This package is release tooling with no bash
// counterpart to port: the only bats file adjacent to it is tests/unit/bundle.bats, which tests
// the retiring bundler's inline-the-modules mechanism — a mechanism that goes away with the
// bundler rather than being reimplemented. Its underlying property, "the same source produces
// the same artifact", survives as the build-twice digest comparison exercised here
// (TestCompareDetectsADifferingArtifact) and by tools/build-release.sh --repro.
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
	"slices"
	"strings"
	"testing"
)

const testVersion = "9.8.7-verifytest"

// The toolchain these tests build with, read from the go command rather than written down: a
// literal here would go stale at the next toolchain bump and every build-info assertion would
// start failing for a reason that has nothing to do with the code under test.
var testToolchain = goVersionString()

func goVersionString() string {
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		panic("cannot read GOVERSION: " + err.Error())
	}
	return strings.TrimSpace(string(out))
}

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
		"GOFLAGS=", "GOENV=off",
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
	_, err := checkArtifact(unstampedBin, hostTarget, testVersion, testToolchain, forbidNothingReal())
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
	_, err = checkArtifact(path, hostTarget, testVersion, testToolchain, []string{leak})
	mustFail(t, err, "not path-independent")
}

func TestCheckBuildInfoRefusesANonTrimpathBuild(t *testing.T) {
	mustFail(t, checkBuildInfo(noTrimpathBin, hostTarget, testToolchain), "-trimpath")
}

func TestCheckBuildInfoAcceptsAReleaseBuild(t *testing.T) {
	for _, tg := range targets {
		if err := checkBuildInfo(filepath.Join(builtDir, tg.Artifact()), tg, testToolchain); err != nil {
			t.Errorf("%s: %v", tg, err)
		}
	}
}

// The GOOS/GOARCH suffix in the file name is a claim; the build info is the fact. A file that
// is a copy of another platform's build must not pass under this name.
func TestCheckArtifactRefusesTheWrongPlatform(t *testing.T) {
	// One case per FIELD, each asserting the exact diagnosis for that field. Grading against
	// "some other target" is not enough: the microarchitecture pin is GOARCH-derived, so a
	// target that differs in both fields trips the arch-level check and the GOOS and GOARCH pins
	// are never reached -- they could both be deleted and this test would still pass.
	otherOS := map[string]string{"darwin": "linux", "linux": "darwin"}[hostTarget.GOOS]
	otherArch := map[string]string{"amd64": "arm64", "arm64": "amd64"}[hostTarget.GOARCH]
	if otherOS == "" || otherArch == "" {
		t.Fatalf("host %s has no counterpart in the matrix's two axes", hostTarget)
	}
	cases := []struct {
		name   string
		claim  Target
		expect string
	}{
		{"wrong GOOS", Target{GOOS: otherOS, GOARCH: hostTarget.GOARCH},
			fmt.Sprintf("build setting GOOS is %q, want %q", hostTarget.GOOS, otherOS)},
		{"wrong GOARCH", Target{GOOS: hostTarget.GOOS, GOARCH: otherArch},
			fmt.Sprintf("build setting GOARCH is %q, want %q", hostTarget.GOARCH, otherArch)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Contains(targets, tc.claim) {
				t.Fatalf("%s is not in the shipped matrix; this case would grade a platform nobody publishes", tc.claim)
			}
			_, err := checkArtifact(hostArtifact, tc.claim, testVersion, testToolchain, forbidNothingReal())
			mustFail(t, err, tc.expect)
		})
	}
}

// --- truncation and permissions ---------------------------------------------------------

func TestCheckArtifactRefusesATruncatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hostTarget.Artifact())
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := checkArtifact(path, hostTarget, testVersion, testToolchain, forbidNothingReal())
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
	_, err = checkArtifact(path, hostTarget, testVersion, testToolchain, forbidNothingReal())
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

// The refusal must name the MISSING FILE, not fall through to "the file is empty": an absent
// checksum file and an empty one are different accidents, and reading a missing file as empty
// is how a checksum step ends up passing on nothing at all.
func TestCheckSumsRefusesAMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, arts := sumsFixture(t, "")
	err := checkSums(filepath.Join(dir, sumsName), arts)
	mustFail(t, err, sumsName)
	mustFail(t, err, "no such file")
}

// --- the directory as a whole ---------------------------------------------------------------

func TestVerifyAcceptsAFreshlyBuiltMatrix(t *testing.T) {
	var out bytes.Buffer
	if err := verify(builtDir, testVersion, testToolchain, forbidNothingReal(), hostTarget, false, &out); err != nil {
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
	mustFail(t, verify(dir, testVersion, testToolchain, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "unexpected file")
}

func TestVerifyRefusesAMissingArtifact(t *testing.T) {
	dir := copyMatrix(t)
	if err := os.Remove(filepath.Join(dir, targets[0].Artifact())); err != nil {
		t.Fatal(err)
	}
	mustFail(t, verify(dir, testVersion, testToolchain, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "artifact set is incomplete")
}

func TestVerifyRefusesAMissingSumsFile(t *testing.T) {
	dir := copyMatrix(t)
	if err := os.Remove(filepath.Join(dir, sumsName)); err != nil {
		t.Fatal(err)
	}
	mustFail(t, verify(dir, testVersion, testToolchain, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "artifact set is incomplete")
}

func TestVerifyRefusesAVersionTheArtifactsDoNotCarry(t *testing.T) {
	mustFail(t, verify(builtDir, "1.2.3", testToolchain, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "did not reach it")
}

func TestVerifyRefusesAnEmptyForbidList(t *testing.T) {
	mustFail(t, verify(builtDir, testVersion, testToolchain, nil, hostTarget, false, &bytes.Buffer{}), "without reading anything")
}

func TestVerifyRefusesADirectoryThatIsAFile(t *testing.T) {
	mustFail(t, verify(hostArtifact, testVersion, testToolchain, forbidNothingReal(), hostTarget, false, &bytes.Buffer{}), "not a directory")
}

// The host round-trip is the only proof that the version symbol still resolves; if the host is
// outside the matrix it cannot run, and that must be an explicit decision rather than a silent
// one.
func TestVerifyRefusesToSkipTheHostRoundTripSilently(t *testing.T) {
	outside := Target{GOOS: "plan9", GOARCH: "386"}
	mustFail(t, verify(builtDir, testVersion, testToolchain, forbidNothingReal(), outside, false, &bytes.Buffer{}), "--allow-no-host-exec")

	var out bytes.Buffer
	if err := verify(builtDir, testVersion, testToolchain, forbidNothingReal(), outside, true, &out); err != nil {
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

// os.Stat("") errors too, so an untightened test cannot tell the missing-flag refusal from an
// accidental one. The message is the contract here: it is what tells a caller what to fix.
func TestRunVerifyRequiresADirFlag(t *testing.T) {
	err := run([]string{"verify", "--version", "1.2.3", "--forbid", "/x"}, &bytes.Buffer{})
	mustFail(t, err, "--dir is required")
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

// --- build provenance the artifact cannot fake -------------------------------------------

func TestCheckArtifactRefusesANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hostTarget.Artifact())
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := checkArtifact(path, hostTarget, testVersion, testToolchain, forbidNothingReal())
	mustFail(t, err, "not a regular file")
}

// A different main package of THIS module: same module path, different program. The artifact
// name says which platform it is; nothing in the name says which program it is.
func TestCheckBuildInfoRefusesADifferentMainPackage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "other-program")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", out, "./tools/boundary-gate")
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOENV=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building a second main package: %v: %s", err, b)
	}
	mustFail(t, checkBuildInfo(out, hostTarget, testToolchain), "built from")
}

func TestCheckBuildInfoRefusesAForeignModule(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOENV=off")
	init := exec.Command("go", "mod", "init", "example.test/elsewhere")
	init.Dir = src
	init.Env = env
	if b, err := init.CombinedOutput(); err != nil {
		t.Fatalf("go mod init: %v: %s", err, b)
	}
	out := filepath.Join(src, "foreign")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", out, ".")
	build.Dir = src
	build.Env = env
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building a foreign module: %v: %s", err, b)
	}
	mustFail(t, checkBuildInfo(out, hostTarget, testToolchain), "main module is")
}

// CGO_ENABLED=1 needs no C compiler for a package with no cgo in it, but it records itself in
// the build info all the same — which is what makes the setting checkable from the artifact.
func TestCheckBuildInfoRefusesACgoBuild(t *testing.T) {
	out := filepath.Join(t.TempDir(), hostTarget.Artifact())
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X "+VersionSymbolForTest+"="+testVersion,
		"-o", out, "./cmd/mythical-ctl")
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOFLAGS=", "GOENV=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("a CGO_ENABLED=1 build is not available here: %v: %s", err, b)
	}
	// The SPECIFIC diagnosis: dropping the CGO_ENABLED pin would still produce a message
	// naming it, via the unexpected-setting catch-all.
	mustFail(t, checkBuildInfo(out, hostTarget, testToolchain), `build setting CGO_ENABLED is "1", want "0"`)
}

// --- the stamp round-trip, both spellings -------------------------------------------------

// fakeCLI writes an executable that answers the version flags however the test wants. No real
// build can answer one spelling correctly and the other wrongly, so without this the second
// spelling would be an assertion nothing could ever falsify.
func fakeCLI(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckStampChecksBothFlagSpellings(t *testing.T) {
	both := fakeCLI(t, `printf 'mythical-ctl 1.2.3\n'`)
	if err := checkStamp(both, "1.2.3"); err != nil {
		t.Fatalf("checkStamp on a CLI that answers both spellings: %v", err)
	}
	// Correct for --version, wrong for -v.
	onlyLong := fakeCLI(t, `if [ "$1" = --version ]; then printf 'mythical-ctl 1.2.3\n'; else printf 'mythical-ctl 0.0.0\n'; fi`)
	mustFail(t, checkStamp(onlyLong, "1.2.3"), "-v printed")
}

func TestCheckStampRefusesANonZeroExit(t *testing.T) {
	broken := fakeCLI(t, `printf 'boom\n' >&2; exit 3`)
	mustFail(t, checkStamp(broken, "1.2.3"), "boom")
}

// --- the build script's own refusals ------------------------------------------------------

func runBuildScript(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join("tools", "build-release.sh")}, args...)...)
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func TestBuildReleaseScriptRefusesBadInvocations(t *testing.T) {
	// Every path argument is a temp dir. If one of these guards is ever removed, the script
	// must not be able to write build output into the working tree while proving it.
	cases := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"no arguments", nil, nil, "usage:"},
		// The script's OWN wording, not the verifier's. Both refuse an empty version, but the
		// script refuses it before building anything; a test that accepts either message would
		// pass while the script had quietly stopped checking and spent four cross-compiles
		// finding out.
		{"empty version", nil, []string{"", t.TempDir()}, "the version argument is empty"},
		{"too many arguments", nil, []string{"1.2.3", t.TempDir(), "extra"}, "too many arguments"},
		{"drifted toolchain pin", []string{"GOTOOLCHAIN=go1.0.0"}, []string{"1.2.3", t.TempDir()}, "release pin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runBuildScript(t, tc.env, tc.args...)
			if err == nil {
				t.Fatalf("the script accepted %v; output:\n%s", tc.args, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refusal does not mention %q; output:\n%s", tc.want, out)
			}
		})
	}
}

// --- the build environment cannot change the bytes unnoticed --------------------------------

// GOAMD64 changes the instructions the compiler emits, is read from the environment, and is
// recorded. Both --repro builds would inherit it equally and agree, so the comparison cannot
// see it; only the artifact's own record can.
func TestCheckBuildInfoRefusesANonDefaultArchLevel(t *testing.T) {
	target := Target{GOOS: "linux", GOARCH: "amd64"}
	out := filepath.Join(t.TempDir(), target.Artifact())
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X "+VersionSymbolForTest+"="+testVersion, "-o", out, "./cmd/mythical-ctl")
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOENV=off", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v3")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, b)
	}
	// The SPECIFIC diagnosis, not merely a message that happens to contain "GOAMD64": dropping
	// the pin from the expected set would still produce one, via the unexpected-setting catch-all.
	mustFail(t, checkBuildInfo(out, target, testToolchain), `build setting GOAMD64 is "v3", want "v1"`)
}

// The catch-all: any recorded setting outside the pinned list, whether or not anybody thought
// of it in advance. -tags stands in for the whole class.
func TestCheckBuildInfoRefusesAnUnexpectedSetting(t *testing.T) {
	out := filepath.Join(t.TempDir(), hostTarget.Artifact())
	cmd := exec.Command("go", "build", "-tags", "somethingextra", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X "+VersionSymbolForTest+"="+testVersion, "-o", out, "./cmd/mythical-ctl")
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOENV=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, b)
	}
	mustFail(t, checkBuildInfo(out, hostTarget, testToolchain), "unexpected build setting")
}

func TestCheckBuildInfoRefusesAnotherToolchain(t *testing.T) {
	mustFail(t, checkBuildInfo(hostArtifact, hostTarget, "go0.0.0"), "want the pinned go0.0.0")
}

// An empty toolchain would make the compiler-version assertion vacuous rather than absent,
// which is the worse of the two.
func TestCheckBuildInfoRefusesAnEmptyToolchain(t *testing.T) {
	mustFail(t, checkBuildInfo(hostArtifact, hostTarget, ""), "would go unchecked")
}

func TestRunVerifyRequiresAToolchain(t *testing.T) {
	err := run([]string{"verify", "--dir", builtDir, "--version", testVersion, "--forbid", "/x"}, &bytes.Buffer{})
	mustFail(t, err, "--toolchain is required")
}

// Adding a platform must require deciding its microarchitecture level, not inheriting the
// builder's.
func TestExpectedSettingsRefusesAnUndecidedArchitecture(t *testing.T) {
	_, err := expectedSettings(Target{GOOS: "linux", GOARCH: "riscv64"})
	mustFail(t, err, "no pinned microarchitecture level")
	for _, tg := range targets {
		if _, err := expectedSettings(tg); err != nil {
			t.Errorf("the shipped matrix has an undecided platform: %v", err)
		}
	}
}

// --- comparing a build against itself -------------------------------------------------------

func TestCompareRefusesTwoSpellingsOfOneDirectory(t *testing.T) {
	mustFail(t, compare(builtDir, builtDir+string(filepath.Separator)+".", &bytes.Buffer{}), "same directory")
}

func TestCompareRefusesASymlinkToTheSameDirectory(t *testing.T) {
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(builtDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	mustFail(t, compare(builtDir, link, &bytes.Buffer{}), "same directory")
}

// Distinct directories, but one artifact is a hard link to the other: its digest necessarily
// equals itself, so that target would report "identical" having compared nothing.
func TestCompareRefusesAHardLinkedArtifact(t *testing.T) {
	other := copyMatrix(t)
	name := targets[0].Artifact()
	if err := os.Remove(filepath.Join(other, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(builtDir, name), filepath.Join(other, name)); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	mustFail(t, compare(builtDir, other, &bytes.Buffer{}), "same file in both directories")
}
