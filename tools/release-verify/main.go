// Command release-verify decides whether a set of built artifacts may be published.
//
// WHY IT IS A SEPARATE COMMAND FROM THE BUILDER. tools/build-release.sh produces the
// artifacts; this command grades them. A builder that also grades its own output can only
// ever report the intent it was written with, and every release-tooling failure worth
// guarding against is a case where the intent and the bytes disagreed: a -X flag whose symbol
// path no longer resolves (the linker accepts it silently and ships the compiled-in default),
// a target whose build failed while a stale file from the previous run stayed on disk, a
// checksum file that lists something that is not there. So the grader reads the FILES, not the
// commands that made them.
//
// IT ALSO OWNS THE TARGET MATRIX. `release-verify targets` prints the platform list the build
// script loops over, and `verify` requires exactly that set on disk. One list drives both, so
// a platform cannot be advertised in one place and quietly not built in the other -- the
// "claimed but never built" failure has no seam to hide in.
//
// Usage:
//
//	release-verify targets
//	release-verify verify --dir DIR --version V --forbid PATH [--forbid PATH ...]
//	release-verify compare DIR_A DIR_B
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Target is one published platform.
type Target struct {
	GOOS   string
	GOARCH string
}

func (t Target) String() string { return t.GOOS + "/" + t.GOARCH }

// Artifact is the published file name for this target. The GOOS/GOARCH suffix is not
// decoration: `verify` reads it back and requires the binary's own recorded GOOS/GOARCH to
// agree, so a file that is a copy of a different platform's build cannot pass under this name.
func (t Target) Artifact() string { return binaryName + "_" + t.GOOS + "_" + t.GOARCH }

// THE TARGET MATRIX. Adding a platform here adds it to the build loop and to the completeness
// assertion in the same edit. There is no Windows target in this arc (the runtime resolver
// refuses npipe:// endpoints and says so), so none is listed -- an unlisted platform is an
// honest absence, not an unbuilt claim.
var targets = []Target{
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
}

const (
	binaryName  = "mythical-ctl"
	modulePath  = "mythicalos.ai/ctl"
	mainPackage = "mythicalos.ai/ctl/cmd/mythical-ctl"
	sumsName    = "SHA256SUMS"

	// A static Go binary for this program is several megabytes. The floor is not a size
	// assertion, it is a truncation detector: a zero-byte or half-written file still hashes to
	// a perfectly well-formed digest, and a digest of nothing looks exactly like a digest of
	// something. Anything under this is a build that did not finish.
	minArtifactBytes = 1 << 20
)

// The same shape internal/version's default is held to, and the same shape the smoke suite
// parses: X.Y.Z with an optional -suffix. No leading "v" -- the tag carries that, the version
// string does not.
var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// A sums line as sha256sum(1) and `shasum -a 256` both write it: 64 hex digits, two spaces,
// the file name. Anchored, and the name may not contain a separator -- a release checksum file
// that reaches outside its own directory is not something to interpret, it is something to
// refuse.
var sumsLineRE = regexp.MustCompile(`^([0-9a-f]{64})  ([^/\x00]+)$`)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "release-verify: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: release-verify targets | verify --dir D --version V --forbid P... | compare A B")
	}
	switch args[0] {
	case "targets":
		if len(args) != 1 {
			return errors.New("targets takes no arguments")
		}
		for _, t := range targets {
			fmt.Fprintln(out, t)
		}
		return nil
	case "verify":
		return runVerify(args[1:], out)
	case "compare":
		if len(args) != 3 {
			return errors.New("usage: release-verify compare DIR_A DIR_B")
		}
		return compare(args[1], args[2], out)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// forbidList collects repeated --forbid values.
type forbidList []string

func (f *forbidList) String() string     { return strings.Join(*f, ",") }
func (f *forbidList) Set(v string) error { *f = append(*f, v); return nil }

func runVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "directory holding the built artifacts")
	version := fs.String("version", "", "the version the artifacts must report")
	var forbid forbidList
	fs.Var(&forbid, "forbid", "an absolute path that must not appear in any artifact (repeatable)")
	// The host round-trip is the ONLY check that proves the version symbol still resolves, so
	// it is required by default and skipping it takes an explicit flag. A skip that happens
	// silently on a host outside the matrix would retire the strongest guard here without
	// anybody deciding to.
	allowNoExec := fs.Bool("allow-no-host-exec", false, "permit skipping the host round-trip when the host is outside the matrix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *dir == "" {
		return errors.New("--dir is required")
	}
	host := Target{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	return verify(*dir, *version, forbid, host, *allowNoExec, out)
}

// checkVersion refuses an unset or free-form version.
//
// THIS IS THE ONE THE FAMILY HAS ALREADY BEEN BITTEN BY. A build argument that resolves to the
// empty string does not fail; it produces an artifact that reports nothing, and every later
// "which version is this?" answer descends from it. An empty version is refused by name here
// rather than being allowed to travel into an -ldflags string where it becomes invisible.
func checkVersion(v string) error {
	if v == "" {
		return errors.New("version is empty -- refusing to stamp an artifact with nothing")
	}
	if strings.HasPrefix(v, "v") {
		return fmt.Errorf("version %q has a leading \"v\": pass the tag with it stripped", v)
	}
	if !versionRE.MatchString(v) {
		return fmt.Errorf("version %q is not X.Y.Z[-suffix]", v)
	}
	return nil
}

func checkForbidden(forbid []string) error {
	if len(forbid) == 0 {
		return errors.New("no --forbid paths given: the build-environment scan would pass without reading anything")
	}
	for _, p := range forbid {
		if p == "" {
			return errors.New("empty --forbid entry: it matches every artifact, so the scan would refuse everything or mean nothing")
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("--forbid %q is not an absolute path", p)
		}
		if filepath.Clean(p) == string(filepath.Separator) {
			return errors.New(`--forbid "/" matches every artifact; name the build directories instead`)
		}
	}
	return nil
}

type artifact struct {
	target Target
	name   string
	size   int64
	digest string
}

// verify grades a whole artifact directory. The host target is a PARAMETER rather than read
// from runtime here, so the "no artifact could be executed" branch is reachable from a test on
// a machine that is inside the matrix -- an unreachable refusal is a refusal nobody has proven.
func verify(dir, version string, forbid []string, host Target, allowNoExec bool, out io.Writer) error {
	if err := checkVersion(version); err != nil {
		return err
	}
	if err := checkForbidden(forbid); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("artifact directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// The directory must hold the matrix and the checksum file and NOTHING else. A release is
	// published by uploading what is in this directory; an unexplained extra file would be
	// published too, unattested and unhashed.
	want := map[string]bool{sumsName: true}
	for _, t := range targets {
		want[t.Artifact()] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	got := map[string]bool{}
	for _, e := range entries {
		if !want[e.Name()] {
			return fmt.Errorf("unexpected file %q in the artifact directory -- a release publishes this directory as-is", e.Name())
		}
		got[e.Name()] = true
	}
	for name := range want {
		if !got[name] {
			return fmt.Errorf("missing %q: the artifact set is incomplete", name)
		}
	}

	hostSeen := false

	var arts []artifact
	for _, t := range targets {
		path := filepath.Join(dir, t.Artifact())
		a, err := checkArtifact(path, t, version, forbid)
		if err != nil {
			return fmt.Errorf("%s: %w", t.Artifact(), err)
		}
		arts = append(arts, a)
		fmt.Fprintf(out, "  %-28s %-9s size=%d bytes  sha256=%s\n", a.name, t, a.size, a.digest)
		if t == host {
			hostSeen = true
			if err := checkStamp(path, version); err != nil {
				return fmt.Errorf("%s: %w", t.Artifact(), err)
			}
			fmt.Fprintf(out, "  host round-trip (%s): reports %q\n", t, binaryName+" "+version)
		}
	}

	if !hostSeen {
		if !allowNoExec {
			return fmt.Errorf("host %s is outside the target matrix, so no artifact could be executed to prove the version symbol still resolves; pass --allow-no-host-exec to accept that", host)
		}
		fmt.Fprintf(out, "  host round-trip SKIPPED: %s is outside the matrix (--allow-no-host-exec)\n", host)
	}

	if err := checkSums(filepath.Join(dir, sumsName), arts); err != nil {
		return err
	}
	fmt.Fprintf(out, "  %s: %d entries, all digests recomputed and matching\n", sumsName, len(arts))
	return nil
}

// checkArtifact grades one built file against everything that can be read out of it.
func checkArtifact(path string, t Target, version string, forbid []string) (artifact, error) {
	a := artifact{target: t, name: filepath.Base(path)}
	st, err := os.Lstat(path)
	if err != nil {
		return a, err
	}
	if !st.Mode().IsRegular() {
		return a, fmt.Errorf("not a regular file (mode %v)", st.Mode())
	}
	a.size = st.Size()
	if a.size < minArtifactBytes {
		return a, fmt.Errorf("only %d bytes (floor %d) -- a truncated or empty build still produces a well-formed digest", a.size, minArtifactBytes)
	}
	if st.Mode().Perm()&0o111 == 0 {
		return a, fmt.Errorf("not executable (mode %v)", st.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	sum := sha256.Sum256(data)
	a.digest = hex.EncodeToString(sum[:])

	if err := checkBuildInfo(path, t); err != nil {
		return a, err
	}

	// The build environment must not have travelled into the artifact. -trimpath is asserted
	// from the build info above; this reads the bytes, which is the assertion that does not
	// depend on the toolchain telling the truth about itself.
	if err := scanForbidden(data, forbid); err != nil {
		return a, err
	}

	// NECESSARY, NOT SUFFICIENT, and paired on purpose. -X against a symbol path that no
	// longer exists is accepted by the linker without a word (measured), so the only way to
	// notice from outside is that the new string never reached the binary. This catches that
	// for every platform including the ones that cannot be executed here; the host round-trip
	// in verify() is the exact check, and it covers the symbol resolving to the right variable.
	if !bytes.Contains(data, []byte(version)) {
		return a, fmt.Errorf("the version string %q does not appear anywhere in the artifact -- the -X stamp did not reach it", version)
	}
	return a, nil
}

// scanForbidden reports the first build-environment path found inside the artifact bytes.
func scanForbidden(data []byte, forbid []string) error {
	for _, p := range forbid {
		if bytes.Contains(data, []byte(p)) {
			return fmt.Errorf("contains the build-environment path %q -- the artifact is not path-independent", p)
		}
	}
	return nil
}

// checkBuildInfo reads the artifact's own record of how it was built.
//
// This works for every platform, not just the host: the build info is a section of the file,
// and -s -w does not strip it (measured). Two of these settings are the determinism contract
// itself, so they are asserted per ARTIFACT rather than trusted from the build script.
func checkBuildInfo(path string, t Target) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading build info: %w", err)
	}
	// Module before package, deliberately: a binary from a different module also has a
	// different main-package path, so checking the package first would leave the module check
	// with no input that can reach it.
	if bi.Main.Path != modulePath {
		return fmt.Errorf("main module is %q, want %q", bi.Main.Path, modulePath)
	}
	if bi.Path != mainPackage {
		return fmt.Errorf("built from %q, want %q", bi.Path, mainPackage)
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	// -trimpath is recorded ONLY when it was on: a build without it carries no -trimpath
	// setting at all (measured), so "absent" and "false" are the same failure and both are
	// caught by requiring the value "true".
	want := map[string]string{
		"-trimpath":   "true",
		"CGO_ENABLED": "0",
		"GOOS":        t.GOOS,
		"GOARCH":      t.GOARCH,
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, ok := settings[k]
		if !ok {
			return fmt.Errorf("build setting %s is absent, want %q", k, want[k])
		}
		if got != want[k] {
			return fmt.Errorf("build setting %s is %q, want %q", k, got, want[k])
		}
	}
	return nil
}

// checkStamp executes the artifact and requires the exact version line, through both spellings
// of the flag. This is the check that proves the -X symbol path still names the variable the
// CLI actually prints; nothing readable from the file can establish that.
func checkStamp(path, version string) error {
	wantLine := binaryName + " " + version + "\n"
	for _, flagSpelling := range []string{"--version", "-v"} {
		cmd := exec.Command(path, flagSpelling)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("running %s: %w (stderr: %s)", flagSpelling, err, strings.TrimSpace(stderr.String()))
		}
		if stdout.String() != wantLine {
			return fmt.Errorf("%s printed %q, want %q", flagSpelling, stdout.String(), wantLine)
		}
	}
	return nil
}

// checkSums cross-checks the published checksum file against digests computed here.
//
// The file is written by sha256sum(1)/shasum(1) and re-computed by crypto/sha256: two
// independent implementations, which is the only arrangement in which the comparison means
// anything. A checksum file that names a file which is not present, or omits one that is, is
// refused -- `sha256sum -c` on a partial list reports success for the lines it has.
func checkSums(path string, arts []artifact) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", sumsName, err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("%s is empty", sumsName)
	}
	listed := map[string]string{}
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		m := sumsLineRE.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("%s line %d is not \"<64 hex>  <name>\": %q", sumsName, i+1, line)
		}
		if _, dup := listed[m[2]]; dup {
			return fmt.Errorf("%s lists %q twice", sumsName, m[2])
		}
		listed[m[2]] = m[1]
	}
	for _, a := range arts {
		want, ok := listed[a.name]
		if !ok {
			return fmt.Errorf("%s does not list %q -- a consumer verifying this file would never check that artifact", sumsName, a.name)
		}
		if want != a.digest {
			return fmt.Errorf("%s records %s for %q, recomputed %s", sumsName, want, a.name, a.digest)
		}
		delete(listed, a.name)
	}
	for name := range listed {
		return fmt.Errorf("%s lists %q, which is not one of the artifacts", sumsName, name)
	}
	return nil
}

// compare is the reproducibility assertion: two independent builds of the same source, and
// every target must match byte for byte. It requires the full matrix in BOTH directories, so
// two empty directories cannot agree their way to a pass.
func compare(dirA, dirB string, out io.Writer) error {
	if dirA == dirB {
		return errors.New("compare needs two different directories; comparing one against itself proves nothing")
	}
	differ := 0
	for _, t := range targets {
		pa := filepath.Join(dirA, t.Artifact())
		pb := filepath.Join(dirB, t.Artifact())
		da, sa, err := digestFile(pa)
		if err != nil {
			return err
		}
		db, sb, err := digestFile(pb)
		if err != nil {
			return err
		}
		if da == db && sa == sb {
			fmt.Fprintf(out, "  %-28s identical  size=%d bytes  sha256=%s\n", t.Artifact(), sa, da)
			continue
		}
		differ++
		fmt.Fprintf(out, "  %-28s DIFFERS    A: size=%d sha256=%s  B: size=%d sha256=%s\n", t.Artifact(), sa, da, sb, db)
	}
	if differ != 0 {
		return fmt.Errorf("%d of %d targets are not byte-reproducible", differ, len(targets))
	}
	return nil
}

func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	if n < minArtifactBytes {
		return "", n, fmt.Errorf("%s: only %d bytes (floor %d) -- hashing a truncated file yields a digest that looks perfectly healthy", path, n, minArtifactBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
