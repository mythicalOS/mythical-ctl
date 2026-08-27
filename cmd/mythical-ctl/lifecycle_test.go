package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — the CLI-surface half of Task 22's share of tests/acceptance/lifecycle.bats. The other
// forty-five owned tests are claimed in internal/verbs/verbs_test.go; these five are here because
// what they pin is the DISPATCHER: verb resolution, the option parser's missing-value rule, and the
// flag-refusal matrix that refuses a misplaced option instead of ignoring it.
//
// PORTED: tests/acceptance/lifecycle.bats: "CLI: an unknown verb exits 2" -> TestCLIUnknownVerbExitsTwo
// PORTED: tests/acceptance/lifecycle.bats: "CLI: install with no product exits 2 and attempts nothing" -> TestCLIInstallWithNoProductAttemptsNothing
// PORTED: tests/acceptance/lifecycle.bats: "CLI: a value-taking option with no value is a usage error (2), not an operational failure (1)" -> TestCLIValuelessOptionIsAUsageError
// PORTED: tests/acceptance/lifecycle.bats: "CLI: install rejects --purge (an uninstall-only option) and installs nothing" -> TestCLIInstallRejectsPurge
// PORTED: tests/acceptance/lifecycle.bats: "CLI: start rejects --family (an uninstall-only option) even for a valid product" -> TestCLIStartRejectsFamily

const cliHex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func cliDigestRef(name string) string {
	return "ghcr.io/mythicalos/" + name + "@sha256:" + cliHex64
}

// cliRig is the dispatcher's world: a fake daemon reachable through DOCKER_HOST, a family home
// reachable through MYTHICAL_HOME, and one verified fixture product.
type cliRig struct {
	t    *testing.T
	fake *enginetest.Fake
	home string
	env  []string
	out  bytes.Buffer
	errb bytes.Buffer
}

func newCLIRig(t *testing.T) *cliRig {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	f.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, _ []byte) (int, []byte) {
		switch cmd {
		case "selfcheck", "resolve":
			out := "alias=" + args[0] + "\naddress=" + view.DNS[args[0]] + "\n"
			if cmd == "selfcheck" {
				out += "selfcheck=ok\n"
			}
			return 0, []byte(out)
		case "egress":
			return 0, []byte("egress=ok\n")
		}
		return 2, nil
	}
	home := t.TempDir()
	r := &cliRig{
		t:    t,
		fake: f,
		home: home,
		env: []string{
			"MYTHICAL_HOME=" + home,
			"HOME=" + t.TempDir(),
			"DOCKER_HOST=unix://" + f.Socket(),
		},
	}
	if err := layout.Ensure(home); err != nil {
		t.Fatal(err)
	}
	f.PullImage(cliDigestRef("probe"))
	return r
}

// writeProduct lays down a complete, verified document set for one product: policy, manifest, and
// an index whose digests actually match, with the trust anchor recorded for it.
func (r *cliRig) writeProduct(product string) {
	r.t.Helper()
	exp := strconv.FormatInt(time.Now().Unix()+86400, 10)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(r.home, name), []byte(body), 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
	digest := func(name string) string {
		b, err := os.ReadFile(filepath.Join(r.home, name))
		if err != nil {
			r.t.Fatal(err)
		}
		return cliio.SHA256Hex(b)
	}
	write("policy", "mythical-policy 1\nversion=1\nexpires="+exp+"\n"+
		"family_gid="+strconv.Itoa(os.Getgid())+"\n"+
		product+".permitted_role=state\n"+
		product+".permitted_role=secrets\n"+
		product+".bindable_role=state\n"+
		product+".permitted_secret=MYTHICAL_TELEMETRY_KEY\n"+
		product+".permitted_mount=transcripts\n")
	write(product+".manifest", "mythical-manifest 1\nversion=1\nexpires="+exp+"\n"+
		"product="+product+"\nlaunched=true\nimage="+cliDigestRef(product)+"\n"+
		"min_core=0.1.0\nruntime_uid=900\n"+
		"volume=state:/data\nvolume=secrets:/secrets\n"+
		"secret=MYTHICAL_TELEMETRY_KEY\nmount=transcripts\nport=7480\n")
	write("index", "mythical-index 1\nversion=1\nexpires="+exp+"\n"+
		"policy_digest="+digest("policy")+"\n"+
		"probe_image="+cliDigestRef("probe")+"\n"+
		"copy_image="+cliDigestRef("copy")+"\n"+
		"manifest="+product+":"+digest(product+".manifest")+"\n")

	h, err := famlock.Acquire(r.home)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, serr := ledger.Live(h)
	if serr != nil {
		r.t.Fatal(serr)
	}
	if err := trust.AnchorSet(h, st, digest("index")); err != nil {
		r.t.Fatal(err)
	}
	if err := conf.FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "tk"); err != nil {
		r.t.Fatal(err)
	}
}

// docArgs point the dispatcher at the fixture, exactly as the shell suite does.
func (r *cliRig) docArgs() []string {
	return []string{"--index", filepath.Join(r.home, "index"),
		"--policy", filepath.Join(r.home, "policy"),
		"--manifest-dir", r.home}
}

func (r *cliRig) run(args ...string) int {
	r.t.Helper()
	r.out.Reset()
	r.errb.Reset()
	return runEnv(args, r.env, strings.NewReader(""), &r.out, &r.errb)
}

func (r *cliRig) said() string { return r.out.String() + r.errb.String() }

func (r *cliRig) isMember(product string) bool {
	r.t.Helper()
	h, err := famlock.Acquire(r.home)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, serr := ledger.Live(h)
	if serr != nil {
		r.t.Fatal(serr)
	}
	l, rerr := ledger.Read(st)
	if rerr != nil {
		return false
	}
	return l.MemberHas(product) == nil
}

func TestCLIUnknownVerbExitsTwo(t *testing.T) {
	r := newCLIRig(t)
	if rc := r.run("frobnicate"); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if len(r.fake.Requests) != 0 {
		t.Fatalf("an unknown verb reached the daemon: %v", r.fake.Requests)
	}
}

func TestCLIInstallWithNoProductAttemptsNothing(t *testing.T) {
	r := newCLIRig(t)
	r.writeProduct("p1")
	before := r.fake.Snapshot()

	args := append([]string{"install"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if after := r.fake.Snapshot(); after != before {
		t.Fatalf("the runtime changed:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

func TestCLIValuelessOptionIsAUsageError(t *testing.T) {
	// A value-taking option with no value is a USAGE error with nothing attempted — never the
	// operational failure an unchecked shift past the end produces under the shell's errexit.
	r := newCLIRig(t)
	r.writeProduct("p1")
	for _, opt := range []string{"--index", "--policy", "--manifest-dir", "--image"} {
		if rc := r.run("install", "p1", opt); rc != cliio.ExitUsage {
			t.Fatalf("install p1 %s: rc = %d, want 2\n%s", opt, rc, r.said())
		}
		if !strings.Contains(r.said(), "requires a value") {
			t.Fatalf("install p1 %s: no missing-value diagnostic:\n%s", opt, r.said())
		}
	}
}

func TestCLIInstallRejectsPurge(t *testing.T) {
	// --purge belongs to uninstall. Silently ignoring a misplaced option is how `install p1 --purge`
	// returns 0 having quietly done something other than what was written.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1", "--purge"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "--purge applies to uninstall only") {
		t.Fatalf("no refusal diagnostic:\n%s", r.said())
	}
	if r.isMember("p1") {
		t.Fatal("the stray option was accepted and the install ran anyway")
	}
	if len(r.fake.Requests) != 0 {
		t.Fatalf("the refusal reached the daemon: %v", r.fake.Requests)
	}
}

func TestCLIStartRejectsFamily(t *testing.T) {
	// --family belongs to uninstall, and it is refused EVEN when everything else about the
	// invocation is right — a valid, installed product included.
	r := newCLIRig(t)
	r.writeProduct("p1")
	args := append([]string{"install", "p1"}, r.docArgs()...)
	if rc := r.run(args...); rc != cliio.ExitOK {
		t.Fatalf("install rc = %d, want 0\n%s", rc, r.said())
	}
	if !r.isMember("p1") {
		t.Fatal("the fixture install did not complete")
	}
	if rc := r.run("start", "p1", "--family", "--index", filepath.Join(r.home, "index")); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want 2\n%s", rc, r.said())
	}
	if !strings.Contains(r.said(), "--family applies to uninstall only") {
		t.Fatalf("no refusal diagnostic:\n%s", r.said())
	}
}
