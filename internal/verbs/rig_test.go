package verbs

// The verb suite's harness. IT CLAIMS NO BATS TEST OF ITS OWN — every claim lives in
// verbs_test.go beside the test that makes it; this file only builds the world those tests run in.
//
// The world is the REAL one wherever it can be: a real ledger on a real temp home under a real
// family lock, the real trust chain over real documents whose digests really match, and the real
// engine client speaking to the hermetic fake daemon over a unix socket. What is faked is the
// daemon and the helper image's entrypoint — the two things a hermetic suite cannot have — and the
// fake reproduces the daemon behaviors the design of record turns on, so a verb that only works
// against a forgiving fake fails here.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func digestRef(name string) string {
	return "ghcr.io/mythicalos/" + name + "@sha256:" + hex64
}

// prodSpec is one fixture product's documents.
type prodSpec struct {
	// key is the index entry and the manifest FILE's base name.
	key string
	// declared is the manifest's own `product=` value. It differs from key only in the test that
	// feeds one product's manifest to another product's install.
	declared   string
	launched   bool
	version    string
	image      string
	extraRoles []string
	precious   []string
}

type prodOpt func(*prodSpec)

func notLaunched() prodOpt           { return func(p *prodSpec) { p.launched = false } }
func docVersion(v string) prodOpt    { return func(p *prodSpec) { p.version = v } }
func declaredAs(name string) prodOpt { return func(p *prodSpec) { p.declared = name } }
func extraRole(role string) prodOpt {
	return func(p *prodSpec) { p.extraRoles = append(p.extraRoles, role) }
}
func preciousRole(r string) prodOpt { return func(p *prodSpec) { p.precious = append(p.precious, r) } }
func imageRef(ref string) prodOpt   { return func(p *prodSpec) { p.image = ref } }

type rig struct {
	t    *testing.T
	fake *enginetest.Fake
	c    *engine.Client
	home string
	env  []string
	out  *bytes.Buffer
	errb *bytes.Buffer
	d    Deps

	// resolveAddr, when set, is the address the fixture helper answers every `resolve` with —
	// the knob that fabricates an alias resolving somewhere other than the container asking.
	resolveAddr string

	products []*prodSpec
	// indexVersion is the family index's document version — the number its anti-rollback floor
	// records. Bumping it is how a test asks whether a newer index was ACCEPTED or merely read.
	indexVersion string
	// policyVersion is the policy index's own document version, for the same reason. It is a
	// FIELD rather than a literal because the policy's floor is the only evidence that an
	// acceptance of the policy actually wrote anything — with a version that never moves, a
	// commit and a no-op are indistinguishable.
	policyVersion string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	home := t.TempDir()
	userHome := t.TempDir()
	r := &rig{
		t:             t,
		fake:          f,
		c:             f.Client(),
		home:          home,
		env:           []string{"MYTHICAL_HOME=" + home, "HOME=" + userHome},
		out:           &bytes.Buffer{},
		errb:          &bytes.Buffer{},
		indexVersion:  "1",
		policyVersion: "1",
	}
	f.HelperEntry = r.helper
	if err := layout.Ensure(home); err != nil {
		t.Fatal(err)
	}
	// The pinned probe image, as a prior pull would have left it.
	f.PullImage(digestRef("probe"))
	r.d = Deps{
		Engine:      r.c,
		Home:        home,
		Stdin:       strings.NewReader(""),
		Stdout:      r.out,
		Stderr:      r.errb,
		Env:         r.env,
		IndexPath:   filepath.Join(home, "index"),
		PolicyPath:  filepath.Join(home, "policy"),
		ManifestDir: home,
	}
	return r
}

// helper is the fixture helper image's entrypoint — the grammar the pinned probe image must answer.
// It consults the RESOLVER surface, never the hosts file, and states its result: exit 0 means the
// probe RAN, and an empty address is the documented "did not resolve" answer rather than a failure.
func (r *rig) helper(cmd string, args []string, view enginetest.HelperNetView, _ []byte) (int, []byte) {
	switch cmd {
	case "selfcheck", "resolve":
		name := args[0]
		addr := view.DNS[name]
		if cmd == "resolve" && r.resolveAddr != "" {
			addr = r.resolveAddr
		}
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

// --- documents -----------------------------------------------------------------------------------

// writeProduct writes (or REWRITES) one fixture product's manifest, adds its entitlements to the
// policy index, and rebuilds the family index over every product written so far — with the digests
// actually matching, and the trust anchor recorded for the index.
func (r *rig) writeProduct(key string, opts ...prodOpt) {
	r.t.Helper()
	spec := &prodSpec{key: key, declared: key, launched: true, version: "1", image: digestRef(key)}
	for _, o := range opts {
		o(spec)
	}
	replaced := false
	for i, p := range r.products {
		if p.key == key {
			r.products[i] = spec
			replaced = true
		}
	}
	if !replaced {
		r.products = append(r.products, spec)
	}
	r.writeDocs()
}

func (r *rig) writeDocs() {
	r.t.Helper()
	exp := strconv.FormatInt(time.Now().Unix()+86400, 10)

	var pol strings.Builder
	pol.WriteString("mythical-policy 1\n")
	pol.WriteString("version=" + r.policyVersion + "\n")
	pol.WriteString("expires=" + exp + "\n")
	// The operating group, so the published ownership spec actually applies on the machine running
	// the suite; a fixed foreign gid would exercise the group-failure path in every test instead of
	// the ordinary one.
	pol.WriteString("family_gid=" + strconv.Itoa(os.Getgid()) + "\n")
	for _, p := range r.products {
		name := p.declared
		pol.WriteString(name + ".permitted_role=state\n")
		pol.WriteString(name + ".permitted_role=secrets\n")
		pol.WriteString(name + ".bindable_role=state\n")
		for _, role := range p.extraRoles {
			pol.WriteString(name + ".permitted_role=" + role + "\n")
			pol.WriteString(name + ".bindable_role=" + role + "\n")
		}
		for _, role := range p.precious {
			pol.WriteString(name + ".precious_role=" + role + "\n")
		}
		pol.WriteString(name + ".permitted_secret=MYTHICAL_TELEMETRY_KEY\n")
		pol.WriteString(name + ".permitted_mount=transcripts\n")
	}
	r.writeFile("policy", pol.String())

	for _, p := range r.products {
		var m strings.Builder
		m.WriteString("mythical-manifest 1\n")
		m.WriteString("version=" + p.version + "\n")
		m.WriteString("expires=" + exp + "\n")
		m.WriteString("product=" + p.declared + "\n")
		m.WriteString("launched=" + strconv.FormatBool(p.launched) + "\n")
		m.WriteString("image=" + p.image + "\n")
		m.WriteString("min_core=0.1.0\n")
		m.WriteString("runtime_uid=900\n")
		m.WriteString("volume=state:/data\n")
		m.WriteString("volume=secrets:/secrets\n")
		for _, role := range p.extraRoles {
			m.WriteString("volume=" + role + ":/" + role + "\n")
		}
		m.WriteString("secret=MYTHICAL_TELEMETRY_KEY\n")
		m.WriteString("mount=transcripts\n")
		m.WriteString("port=7480\n")
		r.writeFile(p.key+".manifest", m.String())
	}

	var idx strings.Builder
	idx.WriteString("mythical-index 1\n")
	idx.WriteString("version=" + r.indexVersion + "\n")
	idx.WriteString("expires=" + exp + "\n")
	idx.WriteString("policy_digest=" + r.digestOf("policy") + "\n")
	idx.WriteString("probe_image=" + digestRef("probe") + "\n")
	idx.WriteString("copy_image=" + digestRef("copy") + "\n")
	for _, p := range r.products {
		idx.WriteString("manifest=" + p.key + ":" + r.digestOf(p.key+".manifest") + "\n")
	}
	r.writeFile("index", idx.String())

	// The anchor and the telemetry key are both writes under the family lock.
	r.withLock(func(h famlock.Held, st ledger.Store) {
		if err := trust.AnchorSet(h, st, r.digestOf("index")); err != nil {
			r.t.Fatal(err)
		}
		if err := conf.FamilyAdd(h, "MYTHICAL_TELEMETRY_KEY", "tk"); err != nil {
			r.t.Fatal(err)
		}
	})
}

// stripPolicyGrant rewrites the policy index with every line containing `frag` removed, and
// re-points the index at the new digest — an entitlement withdrawn by the publisher.
func (r *rig) stripPolicyGrant(frag string) {
	r.t.Helper()
	body, err := os.ReadFile(filepath.Join(r.home, "policy"))
	if err != nil {
		r.t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, frag) {
			continue
		}
		kept = append(kept, line)
	}
	r.writeFile("policy", strings.Join(kept, "\n"))
	idx, err := os.ReadFile(filepath.Join(r.home, "index"))
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(idx), "\n") {
		if strings.HasPrefix(line, "policy_digest=") {
			line = "policy_digest=" + r.digestOf("policy")
		}
		out = append(out, line)
	}
	r.writeFile("index", strings.Join(out, "\n"))
	r.withLock(func(h famlock.Held, st ledger.Store) {
		if err := trust.AnchorSet(h, st, r.digestOf("index")); err != nil {
			r.t.Fatal(err)
		}
	})
}

func (r *rig) writeFile(name, content string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.home, name), []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// ledgerPath is the installer state ledger's own file.
func (r *rig) ledgerPath() string { return filepath.Join(r.home, ".state", "ledger") }

func (r *rig) digestOf(name string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.home, name))
	if err != nil {
		r.t.Fatal(err)
	}
	return cliio.SHA256Hex(b)
}

// --- lock, ledger, observation --------------------------------------------------------------------

func (r *rig) withLock(fn func(famlock.Held, ledger.Store)) {
	r.t.Helper()
	h, err := famlock.Acquire(r.home)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()
	st, err := ledger.Live(h)
	if err != nil {
		r.t.Fatal(err)
	}
	fn(h, st)
}

// mintIdentity establishes the installation identity up front, as an install would have. The
// read-only paths need one to exist so a foreign object can be classified AGAINST it.
func (r *rig) mintIdentity() {
	r.t.Helper()
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l := r.loadLedger(st)
		if _, err := l.IdentEnsure(); err != nil {
			r.t.Fatal(err)
		}
		if err := ledger.Write(h, st, l); err != nil {
			r.t.Fatal(err)
		}
	})
}

func (r *rig) loadLedger(st ledger.Store) *ledger.Ledger {
	r.t.Helper()
	l, err := ledger.Read(st)
	if err != nil {
		if strings.Contains(err.Error(), "no ledger recorded yet") {
			return &ledger.Ledger{}
		}
		r.t.Fatal(err)
	}
	return l
}

// ledgerOnDisk reads the ledger WITHOUT taking the family lock — the only way to look while a
// session under test is still holding it.
func (r *rig) ledgerOnDisk() *ledger.Ledger {
	r.t.Helper()
	return r.loadLedger(ledger.LiveRead(r.home))
}

// ledgerNow reads the ledger the way an outside observer would.
func (r *rig) ledgerNow() *ledger.Ledger {
	r.t.Helper()
	var out *ledger.Ledger
	r.withLock(func(_ famlock.Held, st ledger.Store) { out = r.loadLedger(st) })
	return out
}

// editLedger applies a raw edit under the lock — how a test fabricates the damaged ledgers the
// fail-closed paths must refuse.
func (r *rig) editLedger(fn func(*ledger.Ledger)) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, st ledger.Store) {
		l := r.loadLedger(st)
		fn(l)
		if err := ledger.Write(h, st, l); err != nil {
			r.t.Fatal(err)
		}
	})
}

// appendRows appends raw ledger rows — the Go spelling of piping extra lines through the reference's
// ledger writer, which is how the duplicate-record fixtures are built.
func (r *rig) appendRows(rows ...string) {
	r.t.Helper()
	r.editLedger(func(l *ledger.Ledger) { l.ReplaceLines(append(l.Lines(), rows...)) })
}

func (r *rig) ident() string {
	r.t.Helper()
	id, err := r.ledgerNow().IdentGet()
	if err != nil {
		r.t.Fatalf("no installation identity: %v", err)
	}
	return id
}

func (r *rig) container(product string) string {
	r.t.Helper()
	return "mythical-" + r.ident() + "-" + product
}

func (r *rig) observed(container string) state.Observed {
	r.t.Helper()
	obs, err := state.Observe(context.Background(), state.Engine(r.c), container)
	if err != nil {
		r.t.Fatalf("observing %s: %v", container, err)
	}
	return obs
}

func (r *rig) desired(container string) state.Desired {
	r.t.Helper()
	want, err := state.DesiredGet(r.ledgerNow(), container)
	if err != nil {
		r.t.Fatalf("desired state of %s: %v", container, err)
	}
	return want
}

func (r *rig) outstanding(container string) []state.Check {
	r.t.Helper()
	out, err := state.Outstanding(r.ledgerNow(), container)
	if err != nil {
		r.t.Fatalf("outstanding checks of %s: %v", container, err)
	}
	return out
}

func (r *rig) isMember(product string) bool {
	r.t.Helper()
	return r.ledgerNow().MemberHas(product) == nil
}

// --- verbs, driven -------------------------------------------------------------------------------

func (r *rig) install(product string, opts ...func(*InstallOpts)) int {
	r.t.Helper()
	o := InstallOpts{Product: product}
	for _, f := range opts {
		f(&o)
	}
	return Install(context.Background(), r.d, o)
}

func forced() func(*InstallOpts) { return func(o *InstallOpts) { o.Force = true } }

func withImage(ref string) func(*InstallOpts) {
	return func(o *InstallOpts) { o.Image = ref; o.ImageSet = true }
}

func (r *rig) start(p string) int    { return Start(context.Background(), r.d, p) }
func (r *rig) stop(p string) int     { return Stop(context.Background(), r.d, p) }
func (r *rig) restart(p string) int  { return Restart(context.Background(), r.d, p) }
func (r *rig) recreate(p string) int { return Recreate(context.Background(), r.d, p) }

// said is everything the verb told the operator, on either stream — the analogue of the shell
// harness's merged $output, which is what its assertions read.
func (r *rig) said() string { return r.out.String() + r.errb.String() }

func (r *rig) reset() { r.out.Reset(); r.errb.Reset() }

func (r *rig) mustSay(what string) {
	r.t.Helper()
	if !strings.Contains(r.said(), what) {
		r.t.Fatalf("output does not mention %q:\n%s", what, r.said())
	}
}

func (r *rig) mustNotSay(what string) {
	r.t.Helper()
	if strings.Contains(r.said(), what) {
		r.t.Fatalf("output should not mention %q:\n%s", what, r.said())
	}
}

func (r *rig) mustInstall(product string) {
	r.t.Helper()
	if rc := r.install(product); rc != cliio.ExitOK {
		r.t.Fatalf("installing %s: rc = %d, want 0\n%s", product, rc, r.said())
	}
	r.reset()
}

// requests reports how many times the daemon was asked to do something matching the predicate —
// the Go spelling of grepping the reference harness's call log.
func (r *rig) requests(match func(string) bool) int {
	n := 0
	for _, req := range r.fake.RequestLog() {
		if match(req) {
			n++
		}
	}
	return n
}

func (r *rig) pullCount() int {
	return r.requests(func(req string) bool { return strings.Contains(req, "/images/create") })
}

func (r *rig) volumeExists(name string) bool {
	_, err := r.c.VolumeInspect(context.Background(), name)
	return err == nil
}

func (r *rig) containerExists(name string) bool {
	_, err := r.c.ContainerInspect(context.Background(), name)
	return err == nil
}

func (r *rig) running(name string) bool {
	info, err := r.c.ContainerInspect(context.Background(), name)
	return err == nil && info.Running
}

// fabricateForeignContainer stands a container under our derived name that belongs to ANOTHER
// installation: the name is ours, every label says it is not.
func (r *rig) fabricateForeignContainer(name string) {
	r.t.Helper()
	ctx := context.Background()
	// Ours is removed first: the point of the fixture is that a NAME is reusable, which is exactly
	// why a provenance record alone cannot authorize acting on whatever now stands at it.
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if r.containerExists(name) {
			if err := m.ContainerRemove(ctx, name); err != nil {
				r.t.Fatal(err)
			}
		}
		p, perr := engine.NewProvenance("iotherinst", "notherxxxx")
		if perr != nil {
			r.t.Fatal(perr)
		}
		netID, nerr := m.NetworkCreate(ctx, "foreign-net", p)
		if nerr != nil {
			r.t.Fatal(nerr)
		}
		attach, aerr := engine.NewNetworkAttach(netID, "foreign")
		if aerr != nil {
			r.t.Fatal(aerr)
		}
		r.fake.PullImage(digestRef("foreign"))
		spec, serr := engine.NewContainerSpec(name, digestRef("foreign"), engine.SpecOpts{
			Network: attach,
			Labels: map[string]string{
				"installation": "iotherinst",
				"nonce":        "notherxxxx",
				"product":      "other",
			},
		})
		if serr != nil {
			r.t.Fatal(serr)
		}
		if _, cerr := m.ContainerCreate(ctx, spec); cerr != nil {
			r.t.Fatal(cerr)
		}
		if serr := m.ContainerStart(ctx, name); serr != nil {
			r.t.Fatal(serr)
		}
	})
}

// createStrayVolume stands a volume carrying THIS installation's label that the ledger has no
// record of — the unrecorded same-identity object the gate must stop on.
func (r *rig) createStrayVolume(name string) {
	r.t.Helper()
	ident := r.ident() // BEFORE the lock: ident() takes it too, and it is not re-entrant.
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, "nstrayxxxx")
		if perr != nil {
			r.t.Fatal(perr)
		}
		if err := m.VolumeCreate(context.Background(), name, p); err != nil {
			r.t.Fatal(err)
		}
	})
}

// createNetwork stands an operator-supplied network at a name, out of band, and returns its id.
func (r *rig) createNetwork(name string) string {
	r.t.Helper()
	var id string
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance("ioperatorx", "noperatorx")
		if perr != nil {
			r.t.Fatal(perr)
		}
		id, err = rt.NetworkCreate(context.Background(), name, p)
		if err != nil {
			r.t.Fatal(err)
		}
	})
	return id
}

// removeObjects deletes containers and volumes out of band, by name — the runtime-side half of the
// fixtures that need the ledger to say something about an object the daemon no longer holds.
func (r *rig) removeObjects(names ...string) {
	r.t.Helper()
	ctx := context.Background()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		for _, n := range names {
			if r.containerExists(n) {
				if err := rt.ContainerRemove(ctx, n); err != nil {
					r.t.Fatalf("removing container %s: %v", n, err)
				}
				continue
			}
			if r.volumeExists(n) {
				if err := rt.VolumeRemove(ctx, n); err != nil {
					r.t.Fatalf("removing volume %s: %v", n, err)
				}
			}
		}
	})
}

func (r *rig) floorOf(docid string) string {
	r.t.Helper()
	var out string
	r.withLock(func(_ famlock.Held, st ledger.Store) {
		v, err := trust.FloorGet(st, docid)
		if err != nil {
			out = fmt.Sprintf("<error: %v>", err)
			return
		}
		out = v
	})
	return out
}
