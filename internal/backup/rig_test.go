package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/engine/enginetest"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// --- the two seams, faked ---------------------------------------------------------------------

// fakeSafe stands in for internal/migrate's ownership-chain check. It records every path it
// was ASKED about — which is itself load bearing: the whole point of resolving a backup
// directory's symlink leaf is that the check sees the RESOLVED TARGET, never the alias.
type fakeSafe struct {
	unsafe map[string]bool
	asked  []string
	whats  []string
}

func (s *fakeSafe) check(p, what string) error {
	s.asked = append(s.asked, p)
	s.whats = append(s.whats, what)
	if s.unsafe[p] {
		return fmt.Errorf("%s (%s) is group/other-writable — refusing to trust a location another party can write", p, what)
	}
	return nil
}

func (s *fakeSafe) sawPath(p string) bool {
	for _, a := range s.asked {
		if a == p {
			return true
		}
	}
	return false
}

type copyCall struct {
	volume, hostDir, runtimeUID, operatorUID string
}

// fakeCopier stands in for internal/copyfill. Its answers are transcripts, because transcripts
// are what the seam carries: every refusal this package is specified for is a refusal about
// what a helper said.
type fakeCopier struct {
	availableErr error
	// enumerate/count/verify override the defaults for one call each when set.
	enumerate func(vol string) (Transcript, error)
	count     func(vol string) (Transcript, error)
	verify    func(vol string, man []byte) (Transcript, error)
	// fillErr fires on EVERY Fill until cleared — the interrupted-restore knob.
	fillErr error
	runErr  error

	runs   []copyCall
	fills  []copyCall
	filled map[string]bool
	// verified counts how many times a volume was verified, so a test can prove the resume
	// path re-verified rather than trusting a phase marker.
	verified map[string]int
}

func newCopier() *fakeCopier {
	return &fakeCopier{filled: map[string]bool{}, verified: map[string]int{}}
}

// manifestTranscript is one well-formed enumeration: four entries, one of each type the
// contract distinguishes, plus the stated completion.
func manifestTranscript() string {
	return strings.Join([]string{
		"manifest=dir:/src",
		"mode=0755",
		"owner=900:900",
		"mtime=1700000000",
		"manifest=file:/src/a",
		"digest=" + strings.Repeat("a", 64),
		"mode=0644",
		"owner=900:900",
		"mtime=1700000000",
		"manifest=symlink:/src/l",
		"linktarget=4:a",
		"mode=0777",
		"owner=900:900",
		"mtime=1700000000",
		"manifest=hardlink:/src/h",
		"hardlink=/src/a",
		"mode=0644",
		"owner=900:900",
		"mtime=1700000000",
		"done=ok",
	}, "\n")
}

// manifestEntryCount is how many `manifest=` lines manifestTranscript states — the number a
// verification's own `checked=` must equal for the count to bind.
const manifestEntryCount = 4

func (c *fakeCopier) Available(ctx context.Context, ix *trust.Index) error {
	if ix == nil {
		return errors.New("copy: no authenticated family index — refusing")
	}
	return c.availableErr
}

func (c *fakeCopier) Enumerate(ctx context.Context, ix *trust.Index, vol string) (Transcript, error) {
	if c.enumerate != nil {
		return c.enumerate(vol)
	}
	return Transcript{Text: manifestTranscript() + "\n"}, nil
}

func (c *fakeCopier) Count(ctx context.Context, ix *trust.Index, vol string) (Transcript, error) {
	if c.count != nil {
		return c.count(vol)
	}
	n := 0
	if c.filled[vol] {
		n = manifestEntryCount
	}
	return Transcript{Text: "checked=" + strconv.Itoa(n) + "\n"}, nil
}

func (c *fakeCopier) Verify(ctx context.Context, ix *trust.Index, vol string, man []byte) (Transcript, error) {
	c.verified[vol]++
	if c.verify != nil {
		return c.verify(vol, man)
	}
	if !c.filled[vol] {
		return Transcript{Code: 1, Text: "mismatch=/src/a: absent\nchecked=0\ndone=ok\n"}, nil
	}
	return Transcript{Text: "checked=" + strconv.Itoa(manifestEntryCount) + "\ndone=ok\n"}, nil
}

func (c *fakeCopier) Run(ctx context.Context, ix *trust.Index, vol, dst, ruid, ouid string) error {
	c.runs = append(c.runs, copyCall{volume: vol, hostDir: dst, runtimeUID: ruid, operatorUID: ouid})
	return c.runErr
}

func (c *fakeCopier) Fill(ctx context.Context, ix *trust.Index, src, vol, ruid, ouid string) error {
	c.fills = append(c.fills, copyCall{volume: vol, hostDir: src, runtimeUID: ruid, operatorUID: ouid})
	if c.fillErr != nil {
		return c.fillErr
	}
	c.filled[vol] = true
	return nil
}

// --- the rig --------------------------------------------------------------------------------

const hex64 = "abababababababababababababababababababababababababababababababab"

type rig struct {
	t       *testing.T
	home    string
	fake    *enginetest.Fake
	client  *engine.Client
	rt      *runtime.Runtime
	objs    prov.Objects
	lock    famlock.Held
	cop     *fakeCopier
	safe    *fakeSafe
	out     bytes.Buffer
	errb    bytes.Buffer
	confirm bool
	prompts []string
	ident   string
	known   []string
	vols    []volumeRec
	idx     string
	pol     string
	mdir    string
	bk      string
}

// canon resolves a temp directory to the path every canonicalizing check will see. macOS puts
// t.TempDir() under a symlinked /var, so a test that compares raw strings against canonical
// ones passes on Linux and fails on macOS — a portability gap the reference calls a security
// bug in its own right.
func canon(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newRig(t *testing.T) *rig {
	t.Helper()
	home := canon(t, t.TempDir())
	f := enginetest.NewFake()
	t.Cleanup(f.Close)
	client := f.Client()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	rt, err := runtime.New(h, client)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{
		t: t, home: home, fake: f, client: client, rt: rt,
		lock:    h,
		cop:     newCopier(),
		safe:    &fakeSafe{unsafe: map[string]bool{}},
		confirm: true,
		mdir:    home,
		idx:     filepath.Join(home, "index"),
		pol:     filepath.Join(home, "policy"),
		bk:      filepath.Join(canon(t, t.TempDir()), "backup"),
	}
	r.objs = rigObjects{inner: prov.Engine(client), r: r}
	r.install()
	return r
}

func (r *rig) deps() Deps {
	return Deps{
		Lock: r.lock, Home: r.home, RT: r.rt, Objs: r.objs,
		Copier: r.cop, Safe: r.safe.check,
		Confirm: func(prompt string) bool {
			r.prompts = append(r.prompts, prompt)
			return r.confirm
		},
		Out: &r.out, Err: &r.errb,
		Index: r.idx, Policy: r.pol, ManifestDir: r.mdir,
		OperatorUID: "501",
	}
}

func (r *rig) stderr() string { return r.errb.String() }
func (r *rig) stdout() string { return r.out.String() }

func (r *rig) reset() {
	r.out.Reset()
	r.errb.Reset()
}

// install builds the state a completed installation leaves behind: an authenticated document
// chain anchored in the ledger, an installation identity, a provenance record per named
// volume, the volumes themselves labelled to match, and a small tree in the home.
func (r *rig) install() {
	t := r.t
	t.Helper()
	pol := []byte("mythical-policy 1\nversion=1\nexpires=99999999999\nfamily_gid=20\n" +
		"p1.permitted_role=state\np1.permitted_role=secrets\n")
	man := []byte("mythical-manifest 1\nversion=1\nexpires=99999999999\nproduct=p1\nlaunched=true\n" +
		"image=ghcr.io/x/p1@sha256:" + hex64 + "\nmin_core=0.1.0\nruntime_uid=900\n" +
		"volume=state:/var/lib/p1\nvolume=secrets:/run/p1\n")
	ix := []byte("mythical-index 1\nversion=1\nexpires=99999999999\npolicy_digest=" + cliio.SHA256Hex(pol) +
		"\nprobe_image=ghcr.io/x/probe@sha256:" + hex64 +
		"\ncopy_image=ghcr.io/x/copy@sha256:" + hex64 +
		"\nmanifest=p1:" + cliio.SHA256Hex(man) + "\n")
	write(t, r.idx, ix)
	write(t, r.pol, pol)
	write(t, filepath.Join(r.mdir, "p1.manifest"), man)

	st, err := ledger.Live(r.lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AnchorSet(r.lock, st, cliio.SHA256Hex(ix)); err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Read(st)
	if err != nil {
		t.Fatal(err)
	}
	ident, err := l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	r.ident = ident
	if err := l.MemberAdd("p1"); err != nil {
		t.Fatal(err)
	}
	for i, role := range []string{"state", "secrets"} {
		name, err := manifest.VolumeName(ident, "p1", role)
		if err != nil {
			t.Fatal(err)
		}
		nonce := fmt.Sprintf("n%011x", i+1)
		if err := prov.Record(l, prov.ClassVolume, name, nonce,
			ledger.Field{Key: "product", Value: "p1"},
			ledger.Field{Key: "role", Value: role}); err != nil {
			t.Fatal(err)
		}
		r.vols = append(r.vols, volumeRec{name: name, nonce: nonce, product: "p1"})
	}
	if err := ledger.Write(r.lock, st, l); err != nil {
		t.Fatal(err)
	}
	for _, v := range r.vols {
		r.createVolume(v.name, v.nonce, ident)
	}

	// A tree with one of each entry type the capture distinguishes.
	write(t, filepath.Join(r.home, "mythical.conf"), []byte("# family config\n"))
	if err := os.MkdirAll(filepath.Join(r.home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(r.home, "bin", "tool"), []byte("#!/bin/sh\n"))
	if err := os.Symlink("tool", filepath.Join(r.home, "bin", "alias")); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) createVolume(name, nonce, ident string) {
	r.t.Helper()
	p, err := engine.NewProvenance(ident, nonce)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.rt.VolumeCreate(context.Background(), name, p); err != nil {
		r.t.Fatal(err)
	}
	r.known = append(r.known, name)
}

// rigObjects is the READ-ONLY runtime seam for these tests. Label is the REAL engine-backed
// reader — every nonce comparison in this suite goes through the production path.
//
// Names is a STUB, and it has to be: prov.Engine's own Names cannot answer at all. It asks for
// an UNFILTERED listing (nil labels), and engine's list filter refuses a listing with no label
// to select on, so every class errors before a request is even made. That is a defect in a
// neighbouring module, reported rather than fixed here, and pinned by
// TestUnfilteredListingIsCurrentlyUnavailable below; when it is fixed, that tripwire reddens
// and this stub should be deleted in favour of prov.Engine's own.
//
// The stub answers from the daemon's real state — it inspects each name this rig has created
// and reports only the ones the daemon still knows — so a test that removes a volume sees it
// disappear here too.
type rigObjects struct {
	inner prov.Objects
	r     *rig
}

func (o rigObjects) Label(ctx context.Context, class prov.Class, name, label string) (string, error) {
	return o.inner.Label(ctx, class, name, label)
}

func (o rigObjects) Names(ctx context.Context, class prov.Class) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range o.r.known {
		if seen[n] {
			continue
		}
		seen[n] = true
		if _, err := o.inner.Label(ctx, class, n, prov.LabelNonce); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

func (r *rig) removeVolume(name string) {
	r.t.Helper()
	if err := r.rt.VolumeRemove(context.Background(), name); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) nonceOf(name string) (string, error) {
	return r.objs.Label(context.Background(), prov.ClassVolume, name, prov.LabelNonce)
}

// dropLedger is the precondition every restore test starts from: this machine's ledger is
// gone. It is exactly the state restore's own classification exists for.
func (r *rig) dropLedger() {
	r.t.Helper()
	if err := os.Remove(livePath(r.home)); err != nil {
		r.t.Fatal(err)
	}
}

// backupOK writes a backup and fails the test if it does not succeed — the setup step for
// every restore test, never the thing under test there.
func (r *rig) backupOK() string {
	r.t.Helper()
	if err := Run(context.Background(), r.deps(), r.bk); err != nil {
		r.t.Fatalf("setup backup failed: %v\n%s", err, r.stderr())
	}
	r.reset()
	return canon(r.t, r.bk)
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustContain(t *testing.T, hay, needle, what string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Fatalf("%s: %q is not in:\n%s", what, needle, hay)
	}
}

func mustNotContain(t *testing.T, hay, needle, what string) {
	t.Helper()
	if strings.Contains(hay, needle) {
		t.Fatalf("%s: %q is present and must not be:\n%s", what, needle, hay)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
