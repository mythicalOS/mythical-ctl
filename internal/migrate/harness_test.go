package migrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
)

// --- a directory chain this process provably owns -------------------------------------------------
//
// EVERY POSITIVE TEST IN THIS PACKAGE NEEDS ONE, and the ambient temp root is not it. The whole
// ancestor chain of a destination must be owner-safe for a migration to be permitted at all, and on
// a typical Linux host `/tmp` is mode 1777 — world-writable — so `t.TempDir()` sits under a
// component this package refuses BY DESIGN. Silently skipping there would turn most of this suite
// into a no-op on exactly the platform CI runs; asserting against the ambient root would make the
// suite's green depend on the host's tmp permissions rather than on the code.
//
// So: use the temp root when its chain really is safe (macOS's per-user $TMPDIR is), and otherwise
// build the base under the operator's own home, whose chain is owner-or-root-owned on every host
// this tool supports. A host where NEITHER is safe is genuinely unfit for the tool, and the failure
// says so rather than quietly passing.
func safeBase(t *testing.T) string {
	t.Helper()
	if d := t.TempDir(); chainSafe(d) {
		return d
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		d, derr := os.MkdirTemp(home, ".mctl-migrate-test-")
		if derr == nil {
			_ = os.Chmod(d, 0o700)
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			if chainSafe(d) {
				return d
			}
		}
	}
	t.Fatalf("no directory chain this process owns is available for the test base: neither the temp\n" +
		"  root nor the operator's home has an owner-safe ancestor chain. migrate-storage would\n" +
		"  refuse to operate anywhere on this host, so there is nothing this suite could assert.")
	return ""
}

func chainSafe(dir string) bool {
	c, err := runtime.Canon(dir)
	if err != nil {
		return false
	}
	return verifyChainOwnerSafe(c, "the test base") == nil
}

// unsafeBase builds a group/other-writable directory, for the refusal tests. Running as root makes
// mode bits unenforceable in the OTHER direction too, but the CHECK here is a mode-bit read, not an
// access attempt, so it still refuses under root: dirOwnerSafe reads the bits rather than trying a
// write. Only the tests that need an unreadable directory skip under root.
func unsafeBase(t *testing.T, mode os.FileMode) string {
	t.Helper()
	base := filepath.Join(safeBase(t), "unsafe")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	return base
}

// --- the seams, faked ------------------------------------------------------------------------------

type fakeDocs struct {
	m    *manifest.Manifest
	p    *policy.Policy
	merr error
	perr error
}

func (f fakeDocs) AcceptManifest(string) (*manifest.Manifest, error) { return f.m, f.merr }
func (f fakeDocs) AcceptPolicy() (*policy.Policy, error)             { return f.p, f.perr }

type fakeObjs struct {
	mounts map[string][]engine.MountRecord
	err    error
}

func (f *fakeObjs) ContainerMounts(_ context.Context, c string) ([]engine.MountRecord, error) {
	if f.err != nil {
		// A PARTIAL ANSWER ALONGSIDE THE ERROR — the shape a real client can produce, and the one
		// a caller that keeps the rows and drops the error would be fooled by.
		return f.mounts[c], f.err
	}
	m, ok := f.mounts[c]
	if !ok {
		return nil, engine.ErrAbsent
	}
	return m, nil
}

type fakeMut struct {
	stopped  []string
	removed  []string
	stopErr  error
	rmErr    error
	onStop   func()
	onRemove func()
	// rmGone models THE REMOVAL RACE, which rmErr cannot: the DELETE answers 404 because something
	// ELSE removed the container between the authority question and this call. Two facts follow,
	// and a knob that carried only one of them would let a test pass for the wrong reason. The
	// object is genuinely gone afterwards — so onRemove fires, exactly as on a successful removal,
	// and a resumed phase sees the world as it really is rather than a container the fake still
	// claims is standing. And THIS CALL REMOVED NOTHING — so the name is NOT appended to `removed`,
	// which is what lets a test tell "the migration removed it" apart from "it was already gone".
	rmGone bool
}

func (f *fakeMut) ContainerStop(_ context.Context, id string) error {
	if f.onStop != nil {
		f.onStop()
	}
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stopped = append(f.stopped, id)
	return nil
}

func (f *fakeMut) ContainerRemove(_ context.Context, id string) error {
	if f.rmGone {
		// Gone from the runtime, and not by this call.
		if f.onRemove != nil {
			f.onRemove()
		}
		return fmt.Errorf("engine: %w: No such container: %s", engine.ErrAbsent, id)
	}
	if f.rmErr != nil {
		return f.rmErr
	}
	f.removed = append(f.removed, id)
	if f.onRemove != nil {
		f.onRemove()
	}
	return nil
}

// fakeProv answers the runtime half of a provenance question: what labels does the live object
// carry? engine.ErrAbsent means the object is GONE — an answer.
type fakeProv struct {
	labels map[string]map[string]string
}

func (f *fakeProv) put(class prov.Class, name, install, nonce string) {
	if f.labels == nil {
		f.labels = map[string]map[string]string{}
	}
	f.labels[string(class)+":"+name] = map[string]string{
		prov.LabelInstall: install,
		prov.LabelNonce:   nonce,
	}
}

func (f *fakeProv) drop(class prov.Class, name string) { delete(f.labels, string(class)+":"+name) }

func (f *fakeProv) Label(_ context.Context, class prov.Class, name, label string) (string, error) {
	m, ok := f.labels[string(class)+":"+name]
	if !ok {
		return "", engine.ErrAbsent
	}
	return m[label], nil
}

func (f *fakeProv) Names(_ context.Context, class prov.Class) ([]string, error) {
	var out []string
	for k := range f.labels {
		if c, n, ok := strings.Cut(k, ":"); ok && c == string(class) {
			out = append(out, n)
		}
	}
	return out, nil
}

type fakeState struct {
	running map[string]bool
	absent  map[string]bool
	err     error
}

func (f *fakeState) State(_ context.Context, c string) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	if f.absent[c] {
		return false, "", engine.ErrAbsent
	}
	if f.running[c] {
		return true, "running", nil
	}
	return false, "exited", nil
}

// fakeCopy stands in for the helper-container copy module.
//
// ITS LinkEscapes IS A FAITHFUL STAND-IN, NOT A SECOND DEFINITION. The real rule and its own
// hostile-input suite belong to the copy module; what THIS package owns — and what the tests below
// assert — is what the MIGRATION does when the rule says "escapes": refuse the commit, move nothing,
// destroy nothing.
type fakeCopy struct {
	availErr  error
	preErr    error
	runErr    error
	verifyErr error
	hostErr   error
	accessErr error
	entries   int
	ranWith   []string
	// sawMapForeign records whether --map-foreign-to-operator reached the copy step.
	sawMapForeign bool
	// refuseUnlessMapForeign models the foreign-uid rule: the copy refuses by DEFAULT, and
	// proceeds only when the operator asked for the mapping explicitly.
	refuseUnlessMapForeign bool
	// afterRun runs once the copy has "populated" staging — the seam the planted-symlink test
	// uses to act inside the window the re-check exists to close.
	afterRun func(staging string)
	// report is what a successful copy tells the operator (the stripped-setuid line, say).
	report string
	log    *bytes.Buffer
}

func (f *fakeCopy) Available(context.Context) error { return f.availErr }

func (f *fakeCopy) Preflight(_ context.Context, staging, _, _ string) error {
	_ = staging
	return f.preErr
}

func (f *fakeCopy) Run(_ context.Context, srcVolume, staging, _, _ string, mf bool) (int, error) {
	f.sawMapForeign = mf
	if f.refuseUnlessMapForeign && !mf {
		return 0, errors.New("copy: the source volume holds entries owned by a foreign uid")
	}
	if f.runErr != nil {
		return 0, f.runErr
	}
	f.ranWith = append(f.ranWith, srcVolume+"->"+staging)
	if f.afterRun != nil {
		f.afterRun(staging)
	}
	if f.report != "" && f.log != nil {
		fmt.Fprintln(f.log, f.report)
	}
	return f.entries, nil
}

func (f *fakeCopy) Verify(context.Context, string, string, int, string, string) error {
	return f.verifyErr
}
func (f *fakeCopy) HostAccessCheck(string) error                      { return f.hostErr }
func (f *fakeCopy) AccessCheck(context.Context, string, string) error { return f.accessErr }

func (f *fakeCopy) LinkEscapes(linkPath, target, root string) bool {
	if filepath.IsAbs(target) {
		return true
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), target))
	return resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator))
}

type fakeBuild struct {
	netID        string
	netErr       error
	prepareErr   error
	rebuildErr   error
	reconcileErr error
	prepared     []string
	rebuilt      []string
	reconciled   []string
	discarded    int
	// objs and prv are updated on a successful rebuild, the way a real bring-up leaves the world:
	// a new container, mounting the bind, with its own provenance recorded.
	objs  *fakeObjs
	prv   *fakeProv
	ident string
	bind  string
	at    string
	// hook runs at the START of a successful rebuild, before the world is updated — the seam the
	// ordering tests use to observe what phase 7 had already done by the time it got here.
	hook func()
}

func (f *fakeBuild) NetTarget(context.Context, *ledger.Ledger) (string, error) {
	return f.netID, f.netErr
}

// Prepare resolves the replacement BEFORE anything irreversible happens; Create builds it after.
func (f *fakeBuild) Prepare(_ context.Context, _ *ledger.Ledger, _, container string, _ string) (Replacement, error) {
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	f.prepared = append(f.prepared, container)
	return &fakeReplacement{b: f, container: container}, nil
}

type fakeReplacement struct {
	b         *fakeBuild
	container string
}

func (r *fakeReplacement) Discard() { r.b.discarded++ }

func (r *fakeReplacement) Create(_ context.Context, l *ledger.Ledger) error {
	f, container := r.b, r.container
	if f.rebuildErr != nil {
		return f.rebuildErr
	}
	if f.hook != nil {
		f.hook()
	}
	f.rebuilt = append(f.rebuilt, container)
	if f.objs != nil {
		f.objs.mounts[container] = []engine.MountRecord{
			{Type: "bind", Source: f.bind, Destination: f.at, RW: true},
		}
	}
	if f.prv != nil {
		f.prv.put(prov.ClassContainer, container, f.ident, "n-new")
	}
	return prov.Record(l, prov.ClassContainer, container, "n-new")
}

func (f *fakeBuild) Reconcile(_ context.Context, _ *ledger.Ledger, container, _ string) error {
	if f.reconcileErr != nil {
		return f.reconcileErr
	}
	f.reconciled = append(f.reconciled, container)
	return nil
}

type fakeMounts struct {
	points []string
	err    error
}

func (f *fakeMounts) MountPoints() ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.points, nil
}

// --- the fixture -----------------------------------------------------------------------------------

const (
	testProduct = "p1"
	testRole    = "state"
	testMount   = "/data"
)

type fx struct {
	t         *testing.T
	base      string
	home      string
	lock      famlock.Held
	store     ledger.Store
	l         *ledger.Ledger
	d         Deps
	ident     string
	container string
	srcvol    string
	dest      string
	confkey   string

	objs *fakeObjs
	mut  *fakeMut
	prv  *fakeProv
	stt  *fakeState
	cp   *fakeCopy
	bld  *fakeBuild
	mt   *fakeMounts
	log  bytes.Buffer
	warn bytes.Buffer

	confirmed bool
	prompts   []string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, confirmed: true}
	f.base = safeBase(t)
	f.home = filepath.Join(f.base, "home")
	if err := os.MkdirAll(filepath.Join(f.home, ".state"), 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := famlock.Acquire(f.home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(lock) })
	f.lock = lock
	st, err := ledger.Live(lock)
	if err != nil {
		t.Fatal(err)
	}
	f.store = st
	f.l = &ledger.Ledger{}
	f.ident, err = f.l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	f.container, _ = manifest.ContainerName(f.ident, testProduct)
	f.srcvol, _ = manifest.VolumeName(f.ident, testProduct, testRole)
	f.confkey, _ = BindKey(testProduct, testRole)
	// A fresh, non-existent leaf inside a real, owner-safe directory.
	f.dest = filepath.Join(f.base, "dest")

	f.objs = &fakeObjs{mounts: map[string][]engine.MountRecord{
		f.container: {{Type: "volume", Name: f.srcvol, Destination: testMount, RW: true}},
	}}
	f.prv = &fakeProv{}
	// A REMOVED CONTAINER IS GONE FROM THE RUNTIME TOO. Without this the fake would keep answering
	// "it is still there" after phase 7 removed it, and a resumed phase 7 would refuse an object
	// this installer had itself removed — a divergence that would make the resume test assert the
	// fake rather than the code.
	f.mut = &fakeMut{onRemove: func() { f.prv.drop(prov.ClassContainer, f.container) }}
	f.prv.put(prov.ClassVolume, f.srcvol, f.ident, "n-vol")
	f.prv.put(prov.ClassContainer, f.container, f.ident, "n-con")
	if err := prov.Record(f.l, prov.ClassVolume, f.srcvol, "n-vol"); err != nil {
		t.Fatal(err)
	}
	if err := prov.Record(f.l, prov.ClassContainer, f.container, "n-con"); err != nil {
		t.Fatal(err)
	}
	f.stt = &fakeState{running: map[string]bool{f.container: true}}
	f.cp = &fakeCopy{entries: 3, log: &f.log}
	f.mt = &fakeMounts{}
	f.bld = &fakeBuild{
		netID: "netid-family", objs: f.objs, prv: f.prv, ident: f.ident,
		bind: f.canonDest(), at: testMount,
	}

	nonces := 0
	f.d = Deps{
		Lock:   lock,
		Docs:   fakeDocs{m: testManifest(t), p: testPolicy(t)},
		Objs:   f.objs,
		Mut:    f.mut,
		Prov:   f.prv,
		State:  f.stt,
		Copy:   f.cp,
		Build:  f.bld,
		Mounts: f.mt,
		Confirm: func(p string) bool {
			f.prompts = append(f.prompts, p)
			return f.confirmed
		},
		Persist: func(l *ledger.Ledger) error { return ledger.Write(lock, st, l) },
		Entries: &EntryCount{},
		Log:     &f.log,
		Warn:    &f.warn,
		NewNonce: func() (string, error) {
			nonces++
			return fmt.Sprintf("nz%d", nonces), nil
		},
	}
	return f
}

func (f *fx) canonDest() string {
	c, err := canonDest(filepath.Join(f.base, "dest"))
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// seed writes a live migration record straight into the ledger, the way a crashed attempt leaves
// one behind.
func (f *fx) seed(r record) {
	f.t.Helper()
	r.Product, r.Role = testProduct, testRole
	if r.SrcVol == "" {
		r.SrcVol = f.srcvol
	}
	if r.ConfKey == "" {
		r.ConfKey = f.confkey
	}
	if r.Mount == "" {
		r.Mount = testMount
	}
	if err := r.put(f.l, f.d); err != nil {
		f.t.Fatal(err)
	}
}

// onDisk reads the ledger as it actually is ON DISK — the only copy a crash leaves behind, and
// therefore the only one the write-ahead contract is about.
func (f *fx) onDisk() *ledger.Ledger {
	f.t.Helper()
	l, err := ledger.Read(ledger.LiveRead(f.home))
	if err != nil {
		f.t.Fatalf("the persisted ledger could not be read: %v", err)
	}
	return l
}

// diskPhase reports the phase the PERSISTED ledger names for this migration, or 0 for none.
func (f *fx) diskPhase() int {
	f.t.Helper()
	p, err := Phase(f.onDisk(), testProduct, testRole)
	if errors.Is(err, ErrNoMigration) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// seedRaw writes a migration record from RAW fields, so a test can build a record this core's own
// writer never would — one missing a field, or carrying it empty. That distinction is exactly what
// the carry-forward rules turn on, and it cannot be expressed through the typed record.
func (f *fx) seedRaw(fields map[string]string) {
	f.t.Helper()
	key := testProduct + ":" + testRole
	rows := []ledger.Field{
		{Key: "key", Value: key},
		{Key: "product", Value: testProduct},
		{Key: "role", Value: testRole},
	}
	for _, k := range []string{"phase", "dest", "srcvol", "staging", "nonce", "confkey", "prior", "attempt", "desired", "mount", "stageid"} {
		if v, ok := fields[k]; ok {
			rows = append(rows, ledger.Field{Key: k, Value: v})
		}
	}
	if err := f.l.Put(Kind, "key", key, rows); err != nil {
		f.t.Fatal(err)
	}
	if err := f.d.Persist(f.l); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) confValue(key string) (string, error) {
	return conf.Get(conf.FamilyPath(f.home), key)
}

func testManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	doc := "mythical-manifest 1\n" +
		"version=1\nexpires=99999999999\nproduct=" + testProduct + "\nlaunched=true\n" +
		"image=ghcr.io/mythicalos/" + testProduct + "@sha256:" + strings.Repeat("ab", 32) + "\n" +
		"min_core=0.1.0\nruntime_uid=900\n" +
		"volume=" + testRole + ":" + testMount + "\nvolume=secrets:/secrets\n"
	m, err := manifest.ParseVerified([]byte(doc), "t")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	doc := "mythical-policy 1\nversion=1\nexpires=99999999999\nfamily_gid=20\n" +
		testProduct + ".permitted_role=" + testRole + "\n" +
		testProduct + ".permitted_role=secrets\n" +
		testProduct + ".bindable_role=" + testRole + "\n"
	p, err := policy.ParseVerified([]byte(doc), "t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mustContain fails unless the refusal says the thing the operator needs to read.
func mustContain(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("wanted a refusal mentioning %q, got success", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal %q does not mention %q", err.Error(), w)
		}
	}
}

func mustNotContain(t *testing.T, err error, unwanted ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, u := range unwanted {
		if strings.Contains(err.Error(), u) {
			t.Fatalf("refusal %q mentions %q, which is the wrong reason", err.Error(), u)
		}
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses mode-bit enforcement, so an unreadable directory cannot be constructed")
	}
}
