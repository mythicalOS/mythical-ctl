package probe_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — tests/unit/probe.bats:
// PORTED: tests/unit/probe.bats: "the probe image comes from the family index, not from a constant" -> TestImageFromIndex -- a *trust.Index is constructible ONLY by the trust acceptors — a constant cannot be one
// PORTED: tests/unit/probe.bats: "an index that does not verify yields no probe image" -> TestImageFromIndex + internal/trust.TestAcceptIndex -- structural: Image takes the acceptors' sealed Index, so a refused index yields no value to pass; the acceptor refusals themselves are the second target
// PORTED: tests/unit/probe.bats: "an index that names neither pinned helper image is refused — the keys are REQUIRED" -> TestIndexRequiresHelperImages
// PORTED: tests/unit/probe.bats: "an index naming a FLOATING tag for the probe image is refused" -> TestIndexRequiresHelperImages
// PORTED: tests/unit/probe.bats: "an UNOBTAINABLE probe image reports unavailable — it never falls back" -> TestAvailable
// PORTED: tests/unit/probe.bats: "a pull refusal keeps the registry's own wording" -> TestAvailable
// PORTED: tests/unit/probe.bats: "an already-present probe image needs no pull" -> TestAvailable
// PORTED: tests/unit/probe.bats: "selfcheck resolves the probe's OWN alias on the target network" -> TestSelfCheck
// PORTED: tests/unit/probe.bats: "selfcheck FAILING is distinguishable from a product not running" -> TestSelfCheck -- the DNS-broken verdict names the probe's own alias, no product
// PORTED: tests/unit/probe.bats: "selfcheck asks about a PER-RUN alias it registered with the network itself" -> TestSelfCheckPerRunAlias
// PORTED: tests/unit/probe.bats: "a selfcheck answered from the container's HOSTS FILE cannot satisfy the check" -> TestSelfCheckHostsFile
// PORTED: tests/unit/probe.bats: "selfcheck refuses an answer that does not STATE selfcheck=ok" -> TestSelfCheckAnswerGates
// PORTED: tests/unit/probe.bats: "selfcheck refuses a zero-exit helper that answers nothing at all" -> TestSelfCheckAnswerGates
// PORTED: tests/unit/probe.bats: "a selfcheck answer about a DIFFERENT alias is refused" -> TestSelfCheckAnswerGates
// PORTED: tests/unit/probe.bats: "an answer that states its result TWICE is refused, not read as the first copy" -> TestSelfCheckAnswerGates
// PORTED: tests/unit/probe.bats: "an out-of-contract helper status is a REPORTED failed check, not an unaccounted-for container" -> TestOutOfContractStatus
// PORTED: tests/unit/probe.bats: "resolve returns the address for an alias" -> TestResolve
// PORTED: tests/unit/probe.bats: "resolve reports 3 when the alias does not resolve, distinctly from a probe failure" -> TestResolve -- ErrNotResolved is the rc-3 analogue
// PORTED: tests/unit/probe.bats: "an answer about a DIFFERENT alias is refused, never returned as this one's address" -> TestResolveAnswerGates
// PORTED: tests/unit/probe.bats: "an answer naming TWO aliases, or TWO addresses, is refused rather than read down to one" -> TestResolveAnswerGates
// PORTED: tests/unit/probe.bats: "an answer carrying no address field at all is a probe failure, not a non-resolving alias" -> TestResolveAnswerGates
// PORTED: tests/unit/probe.bats: "the probe command set is CLOSED — nothing manifest-supplied reaches it" -> internal/engine.TestConstructorRefusals -- engine/client_test.go: HelperCommand outside the closed set is a constructor error; the Prober exposes no free-string command anywhere
// PORTED: tests/unit/probe.bats: "a probe run is recorded under write-ahead intent and cleaned up when it completes" -> TestRunAccounting
// PORTED: tests/unit/probe.bats: "a completed probe removes ITSELF — no container survives and nothing sweeps one up" -> TestRunAccounting
// PORTED: tests/unit/probe.bats: "a run whose container could not be accounted for afterwards KEEPS its intent AND FAILS" -> TestUnaccountedRun
// PORTED: tests/unit/probe.bats: "an unaccountable probe container is not reported as a DNS verdict" -> TestUnaccountedRun
// PORTED: tests/unit/probe.bats: "the probe container is NAMED and LABELLED for this installation, like any other object" -> TestRunAccounting -- the intent records mythical-<ident>-probe-<nonce>; the labels ride engine.Provenance, which the sealed HelperSpec requires
// PORTED: tests/unit/probe.bats: "a leftover probe from an earlier crash is recognised by its label and cleaned up" -> TestCleanup
// PORTED: tests/unit/probe.bats: "cleanup never touches a probe belonging to another installation" -> TestCleanup
// PORTED: tests/unit/probe.bats: "cleanup refuses a container at OUR recorded name that is labelled for another installation" -> TestCleanupRefusals
// PORTED: tests/unit/probe.bats: "a leftover the runtime could not be asked about is PRESERVED, never forgotten" -> TestCleanupRefusals
// PORTED: tests/unit/probe.bats: "cleanup refuses when the installation identity cannot be read" -> TestNewRefusals -- moved to the door: a Prober cannot be constructed without a valid identity, so no removal can ever run unscoped
// PORTED: tests/unit/probe.bats: "egress is reported as a distinct check" -> TestEgress
// PORTED: tests/unit/probe.bats: "egress refuses a zero-exit helper that does not STATE egress=ok" -> TestEgress
// PORTED: tests/unit/probe.bats: "egress refuses an answer that states its result more than once" -> TestEgress

var hex64 = strings.Repeat("ab", 32)

const probeRef = "ghcr.io/x/probe@sha256:" + "abababababababababababababababababababababababababababababababab"

// acctFake is the in-memory write-ahead intent store.
type acctFake struct {
	intents []probe.ProbeIntent
	onOpen  func(name, nonce string)
	listErr error
}

func (a *acctFake) OpenProbe(name, nonce string) error {
	if a.onOpen != nil {
		a.onOpen(name, nonce)
	}
	a.intents = append(a.intents, probe.ProbeIntent{Name: name, Nonce: nonce})
	return nil
}

func (a *acctFake) DropProbe(name string) error {
	for i, r := range a.intents {
		if r.Name == name {
			a.intents = append(a.intents[:i], a.intents[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no intent for %s", name)
}

func (a *acctFake) ProbeIntents() ([]probe.ProbeIntent, error) {
	if a.listErr != nil {
		return nil, a.listErr
	}
	return append([]probe.ProbeIntent(nil), a.intents...), nil
}

type rig struct {
	fake  *enginetest.Fake
	c     *engine.Client
	rt    *runtime.Runtime
	h     famlock.Held
	st    ledger.Store
	acct  *acctFake
	p     *probe.Prober
	ix    *trust.Index
	netID string
	dir   string
	n     int
	diag  *bytes.Buffer // the helpers' stderr pass-through, captured
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	home := t.TempDir()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	st, err := ledger.Live(h)
	if err != nil {
		t.Fatal(err)
	}
	c := f.Client()
	rt, err := runtime.New(h, c)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{fake: f, c: c, rt: rt, h: h, st: st, acct: &acctFake{}, dir: t.TempDir()}
	r.p, err = probe.New(rt, r.acct, "i1", func() (string, error) {
		r.n++
		return fmt.Sprintf("n%d", r.n), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r.diag = &bytes.Buffer{}
	if err := r.p.SetDiagnostics(r.diag); err != nil {
		t.Fatal(err)
	}
	// An anchored, ACCEPTED index — the only way to a *trust.Index.
	ixBytes := indexBytes("probe_image=" + probeRef)
	p := filepath.Join(r.dir, "index")
	if err := os.WriteFile(p, ixBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(h, st, cliio.SHA256Hex(ixBytes)); err != nil {
		t.Fatal(err)
	}
	r.ix, err = trust.AcceptIndex(h, st, p)
	if err != nil {
		t.Fatal(err)
	}
	// The family network the probes run on.
	prov, _ := engine.NewProvenance("i1", "netnonce")
	r.netID, err = rt.NetworkCreate(context.Background(), "family", prov)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func indexBytes(overrides ...string) []byte {
	lines := map[string]string{
		"version": "1", "expires": "99999999999",
		"policy_digest": hex64,
		"probe_image":   "ghcr.io/x/probe@sha256:" + hex64,
		"copy_image":    "ghcr.io/x/copy@sha256:" + hex64,
	}
	for _, o := range overrides {
		k, v, _ := strings.Cut(o, "=")
		if v == "" {
			delete(lines, k)
		} else {
			lines[k] = v
		}
	}
	var b strings.Builder
	b.WriteString("mythical-index 1\n")
	for _, k := range []string{"version", "expires", "policy_digest", "probe_image", "copy_image"} {
		if v, ok := lines[k]; ok {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return []byte(b.String())
}

// conformingHelper answers the way the pinned image contract says: resolve/selfcheck consult
// the RESOLVER surface (view.DNS) — never the hosts file — and state their results.
func conformingHelper(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
	switch cmd {
	case "selfcheck", "resolve":
		// The pinned contract: exit 0 means the probe RAN — an EMPTY address is the
		// documented "did not resolve" answer, not a probe failure. Exit 1 is reserved for a
		// check that ran and FAILED.
		name := args[0]
		addr := view.DNS[name]
		out := "alias=" + name + "\naddress=" + addr + "\n"
		if cmd == "selfcheck" {
			out += "selfcheck=ok\n"
		}
		return 0, []byte(out)
	case "egress":
		return 0, []byte("egress=ok\n")
	}
	return 2, nil
}

func TestImageFromIndex(t *testing.T) {
	r := newRig(t)
	ref, err := r.p.Image(r.ix)
	if err != nil || ref != probeRef {
		t.Fatalf("the probe image is the INDEX's: %q %v", ref, err)
	}
	if _, err := r.p.Image(nil); err == nil {
		t.Fatal("no index, no image")
	}
}

func TestIndexRequiresHelperImages(t *testing.T) {
	r := newRig(t)
	// The keys are REQUIRED: an index naming neither pinned helper image refuses at the
	// acceptor — there is no Index value to read a probe image from.
	for _, mut := range []string{"probe_image=", "copy_image="} {
		bad := indexBytes(mut)
		p := filepath.Join(r.dir, "bad-index-"+mut[:5])
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := trust.AnchorSet(r.h, r.st, cliio.SHA256Hex(bad)); err != nil {
			t.Fatal(err)
		}
		if _, err := trust.AcceptIndex(r.h, r.st, p); err == nil {
			t.Errorf("an index missing %s was accepted", mut)
		}
	}
	// A FLOATING tag is not a digest — the digestref grammar refuses it.
	bad := indexBytes("probe_image=ghcr.io/x/probe:latest")
	p := filepath.Join(r.dir, "floating")
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(r.h, r.st, cliio.SHA256Hex(bad)); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.AcceptIndex(r.h, r.st, p); err == nil {
		t.Fatal("a floating probe tag was accepted")
	}
}

func TestAvailable(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	// UNOBTAINABLE: reported, names the ref, STOPS — never a fallback.
	r.fake.PullOutcome = "notfound"
	err := r.p.Available(ctx, r.ix)
	if err == nil || !strings.Contains(err.Error(), probeRef) || !strings.Contains(err.Error(), "no substitute image") {
		t.Fatalf("unobtainable: %v", err)
	}
	// A pull refusal keeps the REGISTRY's own wording.
	r.fake.PullOutcome = "auth"
	err = r.p.Available(ctx, r.ix)
	if err == nil || !strings.Contains(err.Error(), "denied: requested access") {
		t.Fatalf("registry wording: %v", err)
	}
	// Already present: no pull at all — the poisoned pull outcome proves none was attempted.
	r.fake.PullImage(probeRef)
	r.fake.PullOutcome = "neterr"
	if err := r.p.Available(ctx, r.ix); err != nil {
		t.Fatalf("present image must need no network: %v", err)
	}
}

func TestSelfCheck(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err != nil {
		t.Fatalf("a conforming probe on a working network: %v", err)
	}
	// A resolver that answers nothing: the DNS-broken verdict — about the network's
	// MECHANISM, naming the probe's own alias, not any product.
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 1, []byte("alias=" + args[0] + "\naddress=\n")
	}
	err := r.p.SelfCheck(ctx, r.ix, r.netID)
	if err == nil || !strings.Contains(err.Error(), "OWN per-run alias") || !strings.Contains(err.Error(), "not about any one product") {
		t.Fatalf("DNS verdict: %v", err)
	}
}

// Stderr is diagnostics, never evidence: a helper that prints a complete conforming answer on
// STDERR and nothing on stdout has not passed — the reference read `$(…)`, stdout alone, and a
// reader that merged the streams would let a debug echo satisfy the check.
func TestStderrIsNotEvidence(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		// The knob is read after the entry returns, so the per-run alias can be echoed.
		r.fake.HelperStderr = []byte("alias=" + args[0] + "\naddress=10.88.0.9\nselfcheck=ok\n")
		return 0, nil // exit 0, said NOTHING on stdout
	}
	err := r.p.SelfCheck(ctx, r.ix, r.netID)
	if err == nil {
		t.Fatal("a conforming answer on STDERR alone must not pass the self-check")
	}
	if strings.Contains(err.Error(), "OWN per-run alias") {
		t.Fatalf("an empty stdout is a broken PROBE, not a DNS verdict: %v", err)
	}
}

// Stderr reaches the operator on EVERY run — a passing check's warnings included — exactly as
// the reference's inherited stderr did. It is diagnostics, not evidence (the test above), but
// it is never dropped either.
func TestStderrReachesTheOperatorOnEveryRun(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	r.fake.HelperStderr = []byte("warning: the resolver took two tries\n")
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err != nil {
		t.Fatalf("a conforming probe: %v", err)
	}
	if !strings.Contains(r.diag.String(), "warning: the resolver took two tries") {
		t.Fatalf("a PASSING run's stderr must reach the operator, got %q", r.diag.String())
	}
	r.diag.Reset()
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 1, []byte("alias=" + args[0] + "\naddress=\n")
	}
	r.fake.HelperStderr = []byte("resolver: NXDOMAIN\n")
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err == nil {
		t.Fatal("a failing probe must fail")
	}
	if !strings.Contains(r.diag.String(), "resolver: NXDOMAIN") {
		t.Fatalf("a FAILING run's stderr must reach the operator too, got %q", r.diag.String())
	}
	// ONCE, through the diagnostics writer — not a second time inside the verdict: a verb that
	// reports the error would otherwise print the stderr twice where the reference's inherited
	// stderr appeared exactly once.
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err == nil || strings.Contains(err.Error(), "resolver: NXDOMAIN") {
		t.Fatalf("the verdict must not embed the stderr a second time: %v", err)
	}
	if err := r.p.SetDiagnostics(nil); err == nil {
		t.Fatal("a nil diagnostics writer must be refused — discarding stderr is the failure this seam prevents")
	}
}

func TestSelfCheckPerRunAlias(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	var asked []string
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		asked = append(asked, args[0])
		// The alias the caller asks about is REGISTERED WITH THE NETWORK by the run itself —
		// visible to the resolver, minted after any image could have known it.
		if _, ok := view.DNS[args[0]]; !ok {
			return 1, []byte("alias=" + args[0] + "\naddress=\n")
		}
		return 0, []byte("alias=" + args[0] + "\naddress=" + view.DNS[args[0]] + "\nselfcheck=ok\n")
	}
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err != nil {
		t.Fatal(err)
	}
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[0] == asked[1] || !strings.HasPrefix(asked[0], "probe-selfcheck-") {
		t.Fatalf("a PER-RUN alias, fresh each run: %v", asked)
	}
}

func TestSelfCheckHostsFile(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	// A defective selfcheck that answers out of the HOSTS FILE: the alias is never there —
	// the two surfaces are modelled separately precisely so this implementation fails.
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		addr := view.Hosts[args[0]]
		out := "alias=" + args[0] + "\naddress=" + addr + "\nselfcheck=ok\n"
		if addr == "" {
			return 1, []byte(out)
		}
		return 0, []byte(out)
	}
	if err := r.p.SelfCheck(ctx, r.ix, r.netID); err == nil {
		t.Fatal("a hosts-file selfcheck must not satisfy the check")
	}
}

func TestSelfCheckAnswerGates(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	cases := []struct {
		name string
		out  func(alias, addr string) string
		want string
	}{
		{"no stated result", func(a, addr string) string { return "alias=" + a + "\naddress=" + addr + "\n" },
			"carries no \"selfcheck=\" field"},
		{"stated fail beside exit 0", func(a, addr string) string {
			return "alias=" + a + "\naddress=" + addr + "\nselfcheck=fail\n"
		}, "STATED result governs"},
		{"answers nothing at all", func(a, addr string) string { return "" }, "answered about alias"},
		{"a different alias", func(a, addr string) string {
			return "alias=other-name\naddress=" + addr + "\nselfcheck=ok\n"
		}, "answered about alias"},
		{"result stated twice", func(a, addr string) string {
			return "alias=" + a + "\naddress=" + addr + "\nselfcheck=ok\nselfcheck=fail\n"
		}, "more than once"},
	}
	for _, tc := range cases {
		r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
			return 0, []byte(tc.out(args[0], view.DNS[args[0]]))
		}
		err := r.p.SelfCheck(ctx, r.ix, r.netID)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestOutOfContractStatus(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 7, nil
	}
	err := r.p.SelfCheck(ctx, r.ix, r.netID)
	if err == nil || errors.Is(err, probe.ErrUnaccounted) {
		t.Fatalf("out-of-contract is a FAILED CHECK, never an accounting failure: %v", err)
	}
	if !strings.Contains(err.Error(), "not a status the helper contract defines") {
		t.Fatalf("loudly: %v", err)
	}
	if len(r.acct.intents) != 0 {
		t.Fatal("the container was accounted for; its intent must be retired")
	}
}

func TestResolve(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage("img:v1")
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	// A running sibling under an alias.
	na, _ := engine.NewNetworkAttach(r.netID, "brokkr")
	spec, err := engine.NewContainerSpec("sib1", "img:v1", engine.SpecOpts{Network: na})
	if err != nil {
		t.Fatal(err)
	}
	m, err := engine.NewMutator(r.h, r.c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ContainerCreate(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := m.ContainerStart(ctx, "sib1"); err != nil {
		t.Fatal(err)
	}
	addr, err := r.p.Resolve(ctx, r.ix, r.netID, "brokkr")
	if err != nil || addr == "" {
		t.Fatalf("resolve: %q %v", addr, err)
	}
	// An alias nobody registered: the probe LOOKED and found nothing — ErrNotResolved,
	// distinct from every probe failure.
	_, err = r.p.Resolve(ctx, r.ix, r.netID, "ghost-alias")
	if !errors.Is(err, probe.ErrNotResolved) {
		t.Fatalf("not-resolved: %v", err)
	}
}

func TestResolveAnswerGates(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	cases := []struct {
		name string
		out  string
	}{
		{"a different alias", "alias=other\naddress=10.0.0.5\n"},
		{"two aliases", "alias=want\naddress=10.0.0.5\nalias=want\n"},
		{"two addresses", "alias=want\naddress=10.0.0.5\naddress=10.0.0.6\n"},
		{"no address field at all", "alias=want\n"},
	}
	for _, tc := range cases {
		r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
			return 0, []byte(tc.out)
		}
		_, err := r.p.Resolve(ctx, r.ix, r.netID, "want")
		if err == nil || errors.Is(err, probe.ErrNotResolved) {
			t.Errorf("%s must be a probe failure, never an address and never not-resolved: %v", tc.name, err)
		}
	}
}

func TestRunAccounting(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	var openedName, openedNonce string
	var createsAtOpen int
	r.acct.onOpen = func(name, nonce string) {
		openedName, openedNonce = name, nonce
		for _, req := range r.fake.Requests {
			if strings.HasPrefix(req, "POST ") && strings.HasSuffix(req, "/containers/create") {
				createsAtOpen++
			}
		}
	}
	if err := r.p.Egress(ctx, r.ix, r.netID); err != nil {
		t.Fatal(err)
	}
	// WRITE-AHEAD: the intent existed before any container did.
	if createsAtOpen != 0 {
		t.Fatal("the intent must be recorded BEFORE the container is created")
	}
	// NAMED for this installation, nonce in the name — the shape §6b.2's classifier reads as
	// ours. (The labels ride engine.Provenance, which the sealed HelperSpec requires.)
	if !strings.HasPrefix(openedName, "mythical-i1-probe-") || openedNonce == "" ||
		!strings.HasSuffix(openedName, openedNonce) {
		t.Fatalf("probe name: %q nonce %q", openedName, openedNonce)
	}
	// A completed probe removes ITSELF and retires its intent — nothing survives and nothing
	// has to sweep one up.
	if n := r.fake.ContainerCount(); n != 0 {
		t.Fatalf("%d container(s) survived", n)
	}
	if len(r.acct.intents) != 0 {
		t.Fatalf("intents not retired: %v", r.acct.intents)
	}
}

func TestUnaccountedRun(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	// The daemon dies at the accounting question — the reap's inspect, which addresses the
	// container by NAME (the run's own calls address it by id).
	// The selfcheck consumes n1 for its per-run ALIAS; the container's own nonce is n2.
	r.fake.SetDownFrom("GET /containers/mythical-i1-probe-n2/json")
	err := r.p.SelfCheck(ctx, r.ix, r.netID)
	if !errors.Is(err, probe.ErrUnaccounted) {
		t.Fatalf("an unanswerable accounting question FAILS the run: %v", err)
	}
	// And it is NOT a DNS verdict — the probe may well have resolved its alias before the
	// runtime stopped answering.
	if strings.Contains(err.Error(), "DNS on this network") {
		t.Fatalf("an unaccountable container must never be reported as a DNS finding: %v", err)
	}
	// The intent is KEPT.
	if len(r.acct.intents) != 1 {
		t.Fatalf("the intent must be preserved: %v", r.acct.intents)
	}
}

// standProbe creates a container at our probe-name shape with chosen labels, as a crashed
// run would have left one (raw create: only a defective or interrupted flow leaves these).
func standProbe(t *testing.T, r *rig, name, install, nonce string) {
	t.Helper()
	m, err := engine.NewMutator(r.h, r.c)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := engine.NewProvenance(install, nonce)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := engine.NewNetworkAttach(r.netID, "a1")
	spec, err := engine.NewContainerSpec(name, probeRef, engine.SpecOpts{
		Network: na,
		Labels:  map[string]string{"installation": install, "nonce": nonce},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = prov
	if _, err := m.ContainerCreate(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
}

func TestCleanup(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	// A leftover from an earlier crash: OUR label, OUR recorded nonce — removed and retired.
	standProbe(t, r, "mythical-i1-probe-old1", "i1", "old1")
	if err := r.acct.OpenProbe("mythical-i1-probe-old1", "old1"); err != nil {
		t.Fatal(err)
	}
	// Another installation's probe, NOT in our records: never touched.
	standProbe(t, r, "mythical-other-probe-x1", "other", "x1")
	if err := r.p.Cleanup(ctx); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := r.c.ContainerInspect(ctx, "mythical-i1-probe-old1"); !errors.Is(err, engine.ErrAbsent) {
		t.Fatal("our leftover must be removed")
	}
	if _, err := r.c.ContainerInspect(ctx, "mythical-other-probe-x1"); err != nil {
		t.Fatal("another installation's probe must be untouched")
	}
	if len(r.acct.intents) != 0 {
		t.Fatalf("intents: %v", r.acct.intents)
	}
}

// The verified leftover is removed by its IMMUTABLE ID, never by the reusable name the
// intent recorded: a name reassigned between the inspection and the removal would otherwise
// take an unverified container with it. The DELETE the fake receives must carry the id.
func TestReapRemovesByIdentity(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	standProbe(t, r, "mythical-i1-probe-n7", "i1", "n7")
	info, err := r.c.ContainerInspect(ctx, "mythical-i1-probe-n7")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.acct.OpenProbe("mythical-i1-probe-n7", "n7"); err != nil {
		t.Fatal(err)
	}
	if err := r.p.Cleanup(ctx); err != nil {
		t.Fatalf("a verified leftover is removed: %v", err)
	}
	var deletes []string
	for _, req := range r.fake.Requests {
		if strings.HasPrefix(req, "DELETE /") && strings.Contains(req, "/containers/") {
			deletes = append(deletes, req)
		}
	}
	if len(deletes) != 1 {
		t.Fatalf("exactly one container removal expected, got %v", deletes)
	}
	if !strings.Contains(deletes[0], info.ID) || strings.Contains(deletes[0], "mythical-i1-probe-n7") {
		t.Fatalf("the removal must address the verified id, not the reusable name: %s", deletes[0])
	}
}

func TestCleanupRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	// A container at OUR recorded name, labelled for ANOTHER installation: a name can be
	// reassigned, so the name alone proves nothing — NOT removed, intent PRESERVED.
	standProbe(t, r, "mythical-i1-probe-n9", "other", "n9")
	if err := r.acct.OpenProbe("mythical-i1-probe-n9", "n9"); err != nil {
		t.Fatal(err)
	}
	err := r.p.Cleanup(ctx)
	if err == nil || !strings.Contains(err.Error(), "labelled for installation") {
		t.Fatalf("label mismatch: %v", err)
	}
	if _, ierr := r.c.ContainerInspect(ctx, "mythical-i1-probe-n9"); ierr != nil {
		t.Fatal("the stranger's container must survive")
	}
	if len(r.acct.intents) != 1 {
		t.Fatal("the intent must be preserved")
	}
	// A leftover the runtime cannot be asked about: PRESERVED, never forgotten. (SetDown, not a
	// field write: a handler goroutine from the previous request may still be reading the knob.)
	r.fake.SetDown(true)
	if err := r.p.Cleanup(ctx); err == nil {
		t.Fatal("an unanswerable runtime must refuse cleanup")
	}
	r.fake.SetDown(false)
	// And an intent record that names nothing is preserved and reported.
	r.acct.intents = []probe.ProbeIntent{{Name: "", Nonce: "x"}}
	if err := r.p.Cleanup(ctx); err == nil || !strings.Contains(err.Error(), "carries no name") {
		t.Fatalf("nameless intent: %v", err)
	}
}

func TestNewRefusals(t *testing.T) {
	r := newRig(t)
	// The identity gate moved to the door: a Prober cannot exist without a usable identity,
	// so no removal can ever run unscoped by one.
	if _, err := probe.New(r.rt, r.acct, "", func() (string, error) { return "n", nil }); err == nil {
		t.Fatal("empty identity")
	}
	if _, err := probe.New(r.rt, r.acct, "NOT AN IDENT", func() (string, error) { return "n", nil }); err == nil {
		t.Fatal("malformed identity")
	}
	if _, err := probe.New(nil, r.acct, "i1", nil); err == nil {
		t.Fatal("missing dependencies")
	}
}

func TestEgress(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.PullImage(probeRef)
	r.fake.HelperEntry = conformingHelper
	if err := r.p.Egress(ctx, r.ix, r.netID); err != nil {
		t.Fatalf("egress: %v", err)
	}
	// A zero-exit helper that does not STATE egress=ok is refused — an exit status is not a
	// result.
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 0, nil
	}
	if err := r.p.Egress(ctx, r.ix, r.netID); err == nil {
		t.Fatal("silent zero-exit egress")
	}
	// And a result stated more than once is two answers.
	r.fake.HelperEntry = func(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
		return 0, []byte("egress=ok\negress=fail\n")
	}
	err := r.p.Egress(ctx, r.ix, r.netID)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate result: %v", err)
	}
}
