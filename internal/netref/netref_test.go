package netref

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — tests/unit/netref.bats.
//
// PORTED: tests/unit/netref.bats: "with no MYTHICAL_NET the core creates and OWNS an installation-scoped network" -> TestOwnedNetwork
// PORTED: tests/unit/netref.bats: "an owned network is created only once — a second call adopts the recorded one" -> TestOwnedNetwork
// PORTED: tests/unit/netref.bats: "a recorded owned network that no longer resolves is NOT recreated over" -> TestOwnedNetworkNotRecreated
// PORTED: tests/unit/netref.bats: "an operator-supplied network is resolved to an ID and marked attach-only" -> TestOperatorReference
// PORTED: tests/unit/netref.bats: "an attach-only reference is NEVER authorized for deletion" -> TestOperatorReference
// PORTED: tests/unit/netref.bats: "an AMBIGUOUS resolution stops the operation rather than picking one" -> TestResolveAmbiguity
// PORTED: tests/unit/netref.bats: "a name that now resolves to a DIFFERENT ID stops and reports — never a silent rebind" -> TestVerifyDetectsReplacement
// PORTED: tests/unit/netref.bats: "a MISSING network stops and reports, and still offers the rebind exit" -> TestVerifyDetectsReplacement
// PORTED: tests/unit/netref.bats: "adding MYTHICAL_NET to a running installation is REFUSED, not silently split" -> TestSplitRefusals
// PORTED: tests/unit/netref.bats: "removing MYTHICAL_NET from a running installation is REFUSED, not silently split" -> TestSplitRefusals
// PORTED: tests/unit/netref.bats: "a rebind with NO containers records the new ID directly — there is nothing to migrate" -> TestRebindWithNoContainers
// PORTED: tests/unit/netref.bats: "a rebind with siblings connects EVERY container BEFORE any detach" -> TestPhase2ConnectsEveryoneFirst
// PORTED: tests/unit/netref.bats: "phase 2 attaches the target at a LOWER gateway priority than the source" -> TestPhase2ConnectsEveryoneFirst
// PORTED: tests/unit/netref.bats: "a container carrying our label but ABSENT from provenance stops the migration" -> TestUnrecordedContainerStopsMigration
// PORTED: tests/unit/netref.bats: "phase 3 compares the ADDRESS, so resolving via the old network does not pass" -> TestPhase3ComparesTheAddress
// PORTED: tests/unit/netref.bats: "a STOPPED sibling is DEFERRED, not demanded and not started to verify" -> TestPhase3DefersStoppedSiblings
// PORTED: tests/unit/netref.bats: "phase 3 refuses to defer a STOPPED sibling that never reached the target" -> TestPhase3DefersStoppedSiblings
// PORTED: tests/unit/netref.bats: "phase 3 refuses to migrate a stopped sibling owing an alias check on the source" -> TestPhase3RefusesSourceCheckOwed
// PORTED: tests/unit/netref.bats: "an unobtainable probe STOPS the migration at phase 3 and does NOT detach" -> TestPhase3StopsOnUnavailableProbe
// PORTED: tests/unit/netref.bats: "phase 3 STOPS when the source network cannot be inspected — could-not-ask is not absent" -> TestPhase3StopsWhenSourceUnaskable
// PORTED: tests/unit/netref.bats: "one SILENTLY FAILED detach is caught at phase 5, BEFORE the commit" -> TestPhase5CatchesSilentDetachFailure
// PORTED: tests/unit/netref.bats: "phase 4 detaches only the RECORDED fleet, never a container that appeared mid-migration" -> TestPhase4UsesTheRecordedFleet
// PORTED: tests/unit/netref.bats: "phase 4 re-inspects the target and REFUSES to detach a container no longer on it" -> TestPhase4ReInspects
// PORTED: tests/unit/netref.bats: "a bare phase 4 on a fleet with no recorded migration REFUSES to detach" -> TestBarePhasesRefuse
// PORTED: tests/unit/netref.bats: "a bare phase 6 with no verified migration REFUSES to commit-and-clear" -> TestBarePhasesRefuse
// PORTED: tests/unit/netref.bats: "a FAILED phase 3 does not leave a marker that lets a later phase 4 detach" -> TestBarePhasesRefuse
// PORTED: tests/unit/netref.bats: "phase 6 re-verifies exactly {target} and REFUSES to clear when a container was reattached to the source" -> TestPhase6ReVerifies
// PORTED: tests/unit/netref.bats: "committing clears the intent, so the exact-set check resumes immediately" -> TestPhase6Commits
// PORTED: tests/unit/netref.bats: "the commit refuses a reference that does not match where the containers actually are" -> TestCommitMustMatchReality
// PORTED: tests/unit/netref.bats: "recovery reads the recorded phase and CONTINUES FORWARD — never unwinds" -> TestResumeContinuesForward
// PORTED: tests/unit/netref.bats: "an intent recording only the TARGET cannot complete — the source is required" -> TestResumeRefusesIncompleteIntents
// PORTED: tests/unit/netref.bats: "a migration phase that is not a number REFUSES rather than reporting success" -> TestResumeRefusesIncompleteIntents
// PORTED: tests/unit/netref.bats: "a migration whose source and target are the SAME network is refused outright" -> TestSameSourceAndTargetRefused
// PORTED: tests/unit/netref.bats: "a missing OLD network is recognised as forward-only and named as such" -> TestForwardOnlyMigration
// PORTED: tests/unit/netref.bats: "a forward-only migration (source gone) CONVERGES instead of wedging" -> TestForwardOnlyMigration
// PORTED: tests/unit/netref.bats: "a rebind can migrate the fleet OFF the installer's own network onto an operator's" -> TestRebindOffOwnedNetwork

// --- fakes ---------------------------------------------------------------------------------------

const (
	src    = "netid-source"
	tgt    = "netid-target"
	nOther = "netid-other"
	c1     = "mythical-i0123456789-brokkr"
	c2     = "mythical-i0123456789-saga"
)

type fakeObjs struct {
	// names maps a network NAME to the ids that answer it (more than one = ambiguous).
	names map[string][]string
	// live is the set of network ids that exist.
	live map[string]bool
	// nets maps a container to its attachments.
	nets     map[string][]NetAttach
	byInst   map[string][]string
	netsInst map[string][]string
	idErr    map[string]error
	listErr  error
}

func newObjs() *fakeObjs {
	return &fakeObjs{names: map[string][]string{}, live: map[string]bool{},
		nets: map[string][]NetAttach{}, byInst: map[string][]string{},
		netsInst: map[string][]string{}, idErr: map[string]error{}}
}

func (f *fakeObjs) network(name, id string) {
	f.names[name] = append(f.names[name], id)
	f.live[id] = true
}

func (f *fakeObjs) NetworkID(_ context.Context, ref string) (string, error) {
	if err := f.idErr[ref]; err != nil {
		return "", err
	}
	if ids, ok := f.names[ref]; ok && len(ids) > 0 {
		return ids[0], nil
	}
	if f.live[ref] {
		return ref, nil
	}
	return "", engine.ErrAbsent
}

func (f *fakeObjs) NetworkNames(_ context.Context) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for name, ids := range f.names {
		for range ids {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeObjs) NetworksByInstall(_ context.Context, ident string) ([]string, error) {
	return f.netsInst[ident], nil
}

func (f *fakeObjs) ContainersByInstall(_ context.Context, ident string) ([]string, error) {
	return f.byInst[ident], nil
}

func (f *fakeObjs) ContainerNets(_ context.Context, c string) ([]NetAttach, error) {
	return f.nets[c], nil
}

type conn struct {
	net, container, alias string
	gw                    int
}

type fakeMut struct {
	objs        *fakeObjs
	connects    []conn
	disconnects []conn
	order       []string
	connErr     error
	discSilent  map[string]bool
	// onDisconnect fires before each detach, so a test can observe what DISK held at that moment.
	onDisconnect func()
}

func (m *fakeMut) NetworkCreate(_ context.Context, name string, _ engine.Provenance) (string, error) {
	id := "netid-" + name
	m.objs.network(name, id)
	return id, nil
}

func (m *fakeMut) NetworkConnect(_ context.Context, netID, c, alias string, gw int) error {
	if m.connErr != nil {
		return m.connErr
	}
	m.connects = append(m.connects, conn{netID, c, alias, gw})
	m.order = append(m.order, "connect "+c)
	m.objs.nets[c] = append(m.objs.nets[c], NetAttach{NetworkID: netID, Address: addrFor(c, netID)})
	return nil
}

func (m *fakeMut) NetworkDisconnect(_ context.Context, netID, c string) error {
	if m.onDisconnect != nil {
		m.onDisconnect()
	}
	m.disconnects = append(m.disconnects, conn{net: netID, container: c})
	m.order = append(m.order, "disconnect "+c)
	if m.discSilent[c] {
		return nil // reported success, changed nothing — the failure phase 5 must catch
	}
	var keep []NetAttach
	for _, n := range m.objs.nets[c] {
		if n.NetworkID != netID {
			keep = append(keep, n)
		}
	}
	m.objs.nets[c] = keep
	return nil
}

// aliasOf is the family alias a product's containers actually carry — mythical-<product>, not the
// bare product name. Using the real deriver here rather than a literal is what makes the
// resolve-map keys the ones the code under test reads; a literal silently missed them.
func aliasOf(t *testing.T, c string) string {
	t.Helper()
	product := "brokkr"
	if c == c2 {
		product = "saga"
	}
	a, err := manifest.Alias(product)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func addrFor(c, netID string) string {
	if netID == tgt {
		if c == c1 {
			return "10.1.0.2"
		}
		return "10.1.0.3"
	}
	if c == c1 {
		return "10.0.0.2"
	}
	return "10.0.0.3"
}

type fakeProbe struct {
	selfErr    map[string]error
	egressErr  map[string]error
	resolve    map[string]string
	resolveErr error
	// egressCalls counts Egress per network. Only phase 3 probes egress on the SOURCE, so this is
	// the observable that says WHICH phases a resume actually ran — every phase is idempotent, so
	// the end state alone cannot tell "continued forward" from "started over".
	egressCalls map[string]int
}

func newProbe() *fakeProbe {
	return &fakeProbe{selfErr: map[string]error{}, egressErr: map[string]error{},
		resolve: map[string]string{}, egressCalls: map[string]int{}}
}
func (p *fakeProbe) SelfCheck(_ context.Context, _ *trust.Index, n string) error { return p.selfErr[n] }
func (p *fakeProbe) Egress(_ context.Context, _ *trust.Index, n string) error {
	p.egressCalls[n]++
	return p.egressErr[n]
}
func (p *fakeProbe) Resolve(_ context.Context, _ *trust.Index, n, alias string) (string, error) {
	if p.resolveErr != nil {
		return "", p.resolveErr
	}
	v, ok := p.resolve[n+"/"+alias]
	if !ok {
		return "", errors.New("does not resolve")
	}
	return v, nil
}

type fakeAttach struct{ err map[string]error }

func (f fakeAttach) VerifyAttach(_ context.Context, c, _, _ string) error { return f.err[c] }

type fakeLive struct {
	err map[string]error
	// addr is what the alias resolves to, per container — the check phase 3 really performs.
	objs *fakeObjs
	pr   *fakeProbe
}

func (f fakeLive) VerifyLive(_ context.Context, _ *trust.Index, c, netID, alias string) error {
	if err := f.err[c]; err != nil {
		return err
	}
	expect := ""
	for _, n := range f.objs.nets[c] {
		if n.NetworkID == netID {
			expect = n.Address
		}
	}
	got, ok := f.pr.resolve[netID+"/"+alias]
	if !ok {
		return errors.New("the alias does not resolve")
	}
	if got != expect {
		return errors.New("resolves via something other than this network's endpoint")
	}
	return nil
}

type fakeState struct {
	running map[string]bool
	status  map[string]string
}

func newStateObjs() *fakeState {
	return &fakeState{running: map[string]bool{}, status: map[string]string{}}
}
func (f *fakeState) up(c string)   { f.running[c] = true; f.status[c] = "running" }
func (f *fakeState) down(c string) { f.running[c] = false; f.status[c] = "exited" }
func (f *fakeState) State(_ context.Context, c string) (bool, string, error) {
	st, ok := f.status[c]
	if !ok {
		return false, "", engine.ErrAbsent
	}
	return f.running[c], st, nil
}

var fixedNow = time.Unix(1_700_000_000, 0)

type rig struct {
	l    *ledger.Ledger
	objs *fakeObjs
	mut  *fakeMut
	pr   *fakeProbe
	st   *fakeState
	d    MigDeps
	id   string
	dk   *disk
}

func newRig(t *testing.T) *rig {
	t.Helper()
	l := &ledger.Ledger{}
	id, err := l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	objs := newObjs()
	mut := &fakeMut{objs: objs, discSilent: map[string]bool{}}
	pr := newProbe()
	st := newStateObjs()
	n := 0
	r := &rig{l: l, objs: objs, mut: mut, pr: pr, st: st, id: id}
	r.d = MigDeps{
		Deps: Deps{
			Intent:     nil,
			Configured: "opnet",
			NewNonce:   func() (string, error) { n++; return "n" + string(rune('0'+n)), nil },
			Now:        func() time.Time { return fixedNow },
		},
		Objs:   objs,
		Mut:    mut,
		Probe:  pr,
		Attach: fakeAttach{err: map[string]error{}},
		Live:   fakeLive{err: map[string]error{}, objs: objs, pr: pr},
		State:  st,
	}
	// A WORKING PERSISTENCE SEAM BY DEFAULT. The write-ahead barrier refuses without one, so the
	// cases that assert THAT install their own; r.dk is what the durability cases read back.
	r.dk = &disk{}
	r.d.Persist = r.dk.persistFrom(l)
	return r
}

// disk models the persisted ledger. Persist snapshots the in-memory body; reload builds a fresh
// Ledger from that snapshot — what a LATER PROCESS sees. Every other test in this file reuses one
// in-memory ledger, so none of them can tell a record that was persisted from one that merely
// exists in memory; that is the distinction the durability cases make.
type disk struct {
	lines  []string
	writes int
	err    error
}

func (dk *disk) persistFrom(l *ledger.Ledger) func() error {
	return func() error {
		if dk.err != nil {
			return dk.err
		}
		dk.writes++
		dk.lines = l.Lines()
		return nil
	}
}

func (dk *disk) reload() *ledger.Ledger {
	l := &ledger.Ledger{}
	l.ReplaceLines(dk.lines)
	return l
}

// fleet sets up a two-container installation on `src`, recorded and running.
func (r *rig) fleet(t *testing.T, containers ...string) {
	t.Helper()
	r.objs.live[src] = true
	r.objs.live[tgt] = true
	r.objs.byInst[r.id] = containers
	for _, c := range containers {
		product := "brokkr"
		if c == c2 {
			product = "saga"
		}
		if err := prov.Record(r.l, prov.ClassContainer, c, "n-"+c, ledger.Field{Key: "product", Value: product}); err != nil {
			t.Fatal(err)
		}
		r.objs.nets[c] = []NetAttach{{NetworkID: src, Address: addrFor(c, src)}}
		r.st.up(c)
		if err := state.Commit(r.l, c, state.Running, nil, true); err != nil {
			t.Fatal(err)
		}
		alias, _ := manifest.Alias(product)
		r.pr.resolve[tgt+"/"+alias] = addrFor(c, tgt)
		r.pr.resolve[src+"/"+alias] = addrFor(c, src)
	}
}

// --- owned network + reference --------------------------------------------------------------------

func TestOwnedNetwork(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	d := r.d.Deps
	name, _ := manifest.NetworkName(r.id)
	id, err := OwnedEnsure(ctx, r.l, r.objs, r.mut, d)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("no id")
	}
	// It is OWNED: recorded as provenance, so it is this installation's to remove.
	if _, ferr := prov.Find(r.l, prov.ClassNetwork, name); ferr != nil {
		t.Fatalf("the owned network was not recorded as provenance: %v", ferr)
	}
	r.objs.netsInst[r.id] = []string{name}
	// A SECOND CALL ADOPTS the recorded one — a network is never reissued (D38).
	id2, err := OwnedEnsure(ctx, r.l, r.objs, r.mut, d)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Fatalf("a second call created a new network: %q vs %q", id2, id)
	}
}

func TestOwnedNetworkNotRecreated(t *testing.T) {
	ctx := context.Background()
	// A RECORDED OWNED NETWORK THAT NO LONGER RESOLVES is NOT recreated over: recreating it would
	// strand every attached container on a network the ledger no longer names, with every product
	// reporting healthy.
	r := newRig(t)
	name, _ := manifest.NetworkName(r.id)
	if err := prov.Record(r.l, prov.ClassNetwork, name, "n1", ledger.Field{Key: "id", Value: "netid-gone"}); err != nil {
		t.Fatal(err)
	}
	d := r.d.Deps
	_, err := OwnedEnsure(ctx, r.l, r.objs, r.mut, d)
	if err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("a missing owned network: %v", err)
	}
	if len(r.mut.connects) != 0 || r.objs.live["netid-gone"] {
		t.Fatal("something was created")
	}
	// A record with NO id names nothing the runtime can be asked about.
	r2 := newRig(t)
	name2, _ := manifest.NetworkName(r2.id)
	if err := prov.Record(r2.l, prov.ClassNetwork, name2, "n1"); err != nil {
		t.Fatal(err)
	}
	_, err = OwnedEnsure(ctx, r2.l, r2.objs, r2.mut, r2.d.Deps)
	if err == nil || !strings.Contains(err.Error(), "carries no id") {
		t.Fatalf("a record with no id: %v", err)
	}
}

func TestOperatorReference(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.objs.network("opnet", "netid-op")
	id, err := Target(ctx, r.l, r.objs, r.mut, "opnet", true, r.d.Deps)
	if err != nil {
		t.Fatal(err)
	}
	if id != "netid-op" {
		t.Fatalf("id = %q", id)
	}
	// RESOLVED TO AN ID and marked ATTACH-ONLY — `owned=no`.
	rec, err := r.l.Find(kindNetRef, "key", "family")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ledger.FieldOf(rec, "owned"); v != "no" {
		t.Fatalf("owned = %q, want no", v)
	}
	if v, _ := ledger.FieldOf(rec, "id"); v != "netid-op" {
		t.Fatalf("id = %q", v)
	}
	// AN ATTACH-ONLY REFERENCE IS NEVER AUTHORIZED FOR DELETION: it is a reference, not
	// provenance, so the authority path has no record to say yes with.
	if _, ferr := prov.Find(r.l, prov.ClassNetwork, "opnet"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("an operator network was recorded as provenance")
	}
	objs := newObjs()
	objs.network("opnet", "netid-op")
	err = prov.Authority(ctx, r.l, provObjs{r.objs}, prov.ClassNetwork, "opnet")
	if err == nil {
		t.Fatal("an operator network was authorized for deletion")
	}
}

// provObjs adapts the netref fake to prov's read seam, so the deletion-authority assertion above
// asks the REAL authority function rather than a restatement of it.
type provObjs struct{ f *fakeObjs }

func (p provObjs) Label(_ context.Context, _ prov.Class, name, _ string) (string, error) {
	if p.f.live[name] || len(p.f.names[name]) > 0 {
		return "", nil // exists, carries no labels of ours
	}
	return "", engine.ErrAbsent
}
func (p provObjs) Names(context.Context, prov.Class) ([]string, error) { return nil, nil }

func TestResolveAmbiguity(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	// TWO networks answer one name. Attaching to whichever answered first is how a family joins a
	// network the operator did not mean.
	r.objs.network("opnet", "netid-a")
	r.objs.network("opnet", "netid-b")
	_, err := RefResolve(ctx, r.objs, "opnet")
	if err == nil || !strings.Contains(err.Error(), "AMBIGUOUS") {
		t.Fatalf("ambiguous: %v", err)
	}
	// A listing that could not be made is not "no such network".
	r2 := newRig(t)
	r2.objs.listErr = errors.New("daemon down")
	_, err = RefResolve(ctx, r2.objs, "opnet")
	if err == nil || !strings.Contains(err.Error(), "could not be asked") {
		t.Fatalf("unasked listing: %v", err)
	}
	// An EMPTY name names nothing.
	if _, err := RefResolve(ctx, r.objs, ""); err == nil {
		t.Fatal("an empty name resolved")
	}
}

func TestVerifyDetectsReplacement(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.objs.network("opnet", "netid-op")
	if err := RefCommit(ctx, r.l, r.objs, "netid-op", "opnet"); err != nil {
		t.Fatal(err)
	}
	if err := RefVerify(ctx, r.l, r.objs, "opnet"); err != nil {
		t.Fatalf("a matching reference failed: %v", err)
	}
	// THE OPERATOR REPLACED THE NETWORK: same name, different id. Never a silent rebind — recording
	// the new id alone would leave the fleet on the old network with every product healthy.
	r.objs.names["opnet"] = []string{"netid-new"}
	r.objs.live["netid-new"] = true
	err := RefVerify(ctx, r.l, r.objs, "opnet")
	if err == nil || !strings.Contains(err.Error(), "different network") {
		t.Fatalf("replacement: %v", err)
	}
	if !strings.Contains(err.Error(), "net rebind") {
		t.Fatal("the refusal does not offer the rebind exit")
	}
	// A MISSING network stops and reports, and still offers the exit.
	delete(r.objs.names, "opnet")
	err = RefVerify(ctx, r.l, r.objs, "opnet")
	if err == nil || !strings.Contains(err.Error(), "net rebind") {
		t.Fatalf("missing network: %v", err)
	}
}

func TestSplitRefusals(t *testing.T) {
	ctx := context.Background()
	// ADDING MYTHICAL_NET to an installation that already has its own network with the fleet on
	// it: new containers would go on the operator's network and the existing ones stay behind.
	r := newRig(t)
	name, _ := manifest.NetworkName(r.id)
	if err := prov.Record(r.l, prov.ClassNetwork, name, "n1", ledger.Field{Key: "id", Value: src}); err != nil {
		t.Fatal(err)
	}
	r.objs.network("opnet", "netid-op")
	_, err := Target(ctx, r.l, r.objs, r.mut, "opnet", true, r.d.Deps)
	if err == nil || !strings.Contains(err.Error(), "would split the") {
		t.Fatalf("adding MYTHICAL_NET: %v", err)
	}
	// REMOVING IT from an installation whose fleet is on the operator's network is the same split
	// from the other side.
	r2 := newRig(t)
	r2.objs.network("opnet", "netid-op")
	if err := RefCommit(ctx, r2.l, r2.objs, "netid-op", "opnet"); err != nil {
		t.Fatal(err)
	}
	_, err = Target(ctx, r2.l, r2.objs, r2.mut, "", false, r2.d.Deps)
	if err == nil || !strings.Contains(err.Error(), "would split the") {
		t.Fatalf("removing MYTHICAL_NET: %v", err)
	}
	// AN EMPTY VALUE is not the same statement as no override at all.
	r3 := newRig(t)
	_, err = Target(ctx, r3.l, r3.objs, r3.mut, "", true, r3.d.Deps)
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("empty MYTHICAL_NET: %v", err)
	}
}

func TestCommitMustMatchReality(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.objs.network("opnet", "netid-op")
	// THE COMMIT REFUSES A REFERENCE THAT DOES NOT MATCH WHERE THE CONTAINERS ACTUALLY ARE.
	err := RefCommit(ctx, r.l, r.objs, "netid-somewhere-else", "opnet")
	if err == nil || !strings.Contains(err.Error(), "does not match where the") {
		t.Fatalf("mismatched commit: %v", err)
	}
	if _, ferr := r.l.Find(kindNetRef, "key", "family"); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a refused commit wrote a reference")
	}
	// MYTHICAL_NET UNSET: a reference recorded with no name is one nothing can ever re-verify.
	//
	// The MESSAGE is what is asserted, not merely the refusal. RefResolve would also refuse an
	// empty name ("an empty network name names nothing"), so deleting this guard still fails —
	// with an answer that tells the operator nothing about what to do. The actionable wording is
	// the whole product of the guard; measured, without this assertion the mutation survives.
	err = RefCommit(ctx, r.l, r.objs, "netid-op", "")
	if err == nil {
		t.Fatal("a reference was recorded with no name")
	}
	if !strings.Contains(err.Error(), "Set MYTHICAL_NET") {
		t.Fatalf("refused without telling the operator what to set: %v", err)
	}
}

// --- the phase machine ----------------------------------------------------------------------------

func TestRebindWithNoContainers(t *testing.T) {
	ctx := context.Background()
	// NOTHING TO MIGRATE: the new id is recorded directly, and no phase runs.
	r := newRig(t)
	r.objs.network("opnet", tgt)
	if err := Rebind(ctx, r.l, r.d, tgt); err != nil {
		t.Fatal(err)
	}
	if _, err := MigGet(r.l); !errors.Is(err, ErrNoMigration) {
		t.Fatal("a migration was opened for an empty fleet")
	}
	id, err := RefGet(r.l)
	if err != nil || id != tgt {
		t.Fatalf("reference = %q %v", id, err)
	}
}

func TestPhase2ConnectsEveryoneFirst(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.fleet(t, c1, c2)
	if err := MigRun(ctx, r.l, r.d, src, tgt, 1); err != nil {
		t.Fatal(err)
	}
	if err := MigRun(ctx, r.l, r.d, src, tgt, 2); err != nil {
		t.Fatal(err)
	}
	// EVERY CONTAINER IS CONNECTED, AND NOTHING IS DETACHED.
	if len(r.mut.connects) != 2 {
		t.Fatalf("connects = %+v", r.mut.connects)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("phase 2 detached something")
	}
	// AT A LOWER GATEWAY PRIORITY than the source, so attaching the target does not move the
	// default route out from under a running fleet.
	for _, c := range r.mut.connects {
		if c.gw >= 0 {
			t.Fatalf("connected at gateway priority %d, want negative", c.gw)
		}
	}
	// And the ordering property across a full run: every connect precedes every disconnect.
	r.pr.resolve[tgt+"/"+aliasOf(t, c1)] = addrFor(c1, tgt)
	r.pr.resolve[tgt+"/saga"] = addrFor(c2, tgt)
	for _, p := range []int{3, 4} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatalf("phase %d: %v", p, err)
		}
	}
	lastConnect, firstDisconnect := -1, len(r.mut.order)
	for i, step := range r.mut.order {
		if strings.HasPrefix(step, "connect ") {
			lastConnect = i
		}
		if strings.HasPrefix(step, "disconnect ") && i < firstDisconnect {
			firstDisconnect = i
		}
	}
	if lastConnect > firstDisconnect {
		t.Fatalf("a detach happened before every container was connected: %v", r.mut.order)
	}
}

func TestUnrecordedContainerStopsMigration(t *testing.T) {
	ctx := context.Background()
	// A CONTAINER CARRYING OUR LABEL BUT ABSENT FROM PROVENANCE stops the migration: migrating a
	// fleet we cannot enumerate is migrating one we cannot verify.
	r := newRig(t)
	r.fleet(t, c1)
	r.objs.byInst[r.id] = []string{c1, "mythical-i0123456789-ghost"}
	err := MigRun(ctx, r.l, r.d, src, tgt, 2)
	if err == nil || !strings.Contains(err.Error(), "no record of it") {
		t.Fatalf("unrecorded container: %v", err)
	}
}

func TestPhase3ComparesTheAddress(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.fleet(t, c1)
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	// RESOLVING VIA THE OLD NETWORK DOES NOT PASS. During phase 2 every container is on BOTH
	// networks and aliases are network-scoped, so a name resolving to the SOURCE address proves
	// nothing about the target.
	r.pr.resolve[tgt+"/"+aliasOf(t, c1)] = addrFor(c1, src)
	err := MigRun(ctx, r.l, r.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("old-network resolution passed: %v", err)
	}
	// NOTHING IS DETACHED by a failed phase 3.
	if len(r.mut.disconnects) != 0 {
		t.Fatal("a failed phase 3 detached something")
	}
	// With the TARGET address it passes.
	r.pr.resolve[tgt+"/"+aliasOf(t, c1)] = addrFor(c1, tgt)
	if err := MigRun(ctx, r.l, r.d, src, tgt, 3); err != nil {
		t.Fatalf("phase 3: %v", err)
	}
}

func TestPhase3DefersStoppedSiblings(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.fleet(t, c1)
	r.st.down(c1)
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	// A STOPPED SIBLING IS DEFERRED: not demanded, and NOT STARTED to verify.
	if err := MigRun(ctx, r.l, r.d, src, tgt, 3); err != nil {
		t.Fatalf("phase 3 with a stopped sibling: %v", err)
	}
	// The check is recorded against the TARGET, to be performed at its next explicit start.
	out, err := state.Outstanding(r.l, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Param != tgt {
		t.Fatalf("outstanding = %+v", out)
	}
	// The desired state it was recorded with is PRESERVED, not invented.
	if got, _ := state.DesiredGet(r.l, c1); got != state.Running {
		t.Fatalf("desired = %q", got)
	}

	// PHASE 3 REFUSES TO DEFER A STOPPED SIBLING THAT NEVER REACHED THE TARGET — a connect
	// returned success but the attachment is not there.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.st.down(c1)
	if err := MigRun(ctx, r2.l, r2.d, src, tgt, 1); err != nil {
		t.Fatal(err)
	}
	r2.d.Attach = fakeAttach{err: map[string]error{c1: errors.New("not attached")}}
	err = MigRun(ctx, r2.l, r2.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "NOT confirmed attached") {
		t.Fatalf("unattached stopped sibling: %v", err)
	}
	if len(r2.mut.disconnects) != 0 {
		t.Fatal("something was detached")
	}
}

func TestPhase3RefusesSourceCheckOwed(t *testing.T) {
	ctx := context.Background()
	// A STOPPED SIBLING OWING AN ALIAS CHECK ON THE SOURCE: phase 4 removes that network, after
	// which nothing could ever satisfy the check and the container stays unreconciled forever.
	r := newRig(t)
	r.fleet(t, c1)
	r.st.down(c1)
	if err := state.Commit(r.l, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: src}}, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	err := MigRun(ctx, r.l, r.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "SOURCE network") {
		t.Fatalf("source-check owed: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("something was detached")
	}
}

func TestPhase3StopsOnUnavailableProbe(t *testing.T) {
	ctx := context.Background()
	// AN UNOBTAINABLE PROBE stops the migration and does NOT detach: proceeding unverified because
	// the checker was unavailable is the failure this phase exists to prevent.
	r := newRig(t)
	r.fleet(t, c1)
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	r.pr.selfErr[tgt] = errors.New("probe image missing")
	err := MigRun(ctx, r.l, r.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "checker was unavailable") {
		t.Fatalf("unavailable probe: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("a stopped phase 3 detached something")
	}
	// And a probe that did not RUN during a container's live check is not a verdict either.
	r2 := newRig(t)
	r2.fleet(t, c1)
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r2.l, r2.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	r2.d.Live = fakeLive{err: map[string]error{c1: ErrProbeUnavailable}, objs: r2.objs, pr: r2.pr}
	err = MigRun(ctx, r2.l, r2.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "probe itself did not run") {
		t.Fatalf("probe did not run: %v", err)
	}
	if len(r2.mut.disconnects) != 0 {
		t.Fatal("something was detached")
	}
}

func TestPhase3StopsWhenSourceUnaskable(t *testing.T) {
	ctx := context.Background()
	// COULD-NOT-ASK IS NOT ABSENT: a detach planned against a network we could not ask about is a
	// detach planned in the dark, and treating it as absent would switch to the forward-only rules.
	r := newRig(t)
	r.fleet(t, c1)
	for _, p := range []int{1, 2} {
		if err := MigRun(ctx, r.l, r.d, src, tgt, p); err != nil {
			t.Fatal(err)
		}
	}
	r.objs.idErr[src] = errors.New("daemon down")
	err := MigRun(ctx, r.l, r.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "Could not ask") {
		t.Fatalf("unaskable source: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("something was detached")
	}
}

// runTo drives phases 1..n, failing the test on the first error.
func (r *rig) runTo(t *testing.T, n int) {
	t.Helper()
	for p := 1; p <= n; p++ {
		if err := MigRun(context.Background(), r.l, r.d, src, tgt, p); err != nil {
			t.Fatalf("phase %d: %v", p, err)
		}
	}
}

func TestPhase5CatchesSilentDetachFailure(t *testing.T) {
	ctx := context.Background()
	// ONE SILENTLY FAILED DETACH — the daemon reported success and changed nothing — is caught at
	// phase 5, BEFORE the commit, by re-verifying the exact set.
	r := newRig(t)
	r.fleet(t, c1, c2)
	r.mut.discSilent[c2] = true
	r.runTo(t, 4)
	err := MigRun(ctx, r.l, r.d, src, tgt, 5)
	if err == nil || !strings.Contains(err.Error(), "phase 5 verification failed") {
		t.Fatalf("silent detach failure: %v", err)
	}
	// It NAMES THE NETWORK the container is still attached to. A bare "has 2 attachments" would
	// also be a refusal, and would leave the operator to work out which one is wrong; the
	// attachment-identity arm is what makes the report actionable.
	if !strings.Contains(err.Error(), "still attached to \""+src+"\"") {
		t.Fatalf("the refusal does not name the network still attached: %v", err)
	}
	// STAYS IN PHASE 4 with the intent intact, so the migration resumes rather than committing
	// over an unverified fleet.
	mig, gerr := MigGet(r.l)
	if gerr != nil {
		t.Fatal(gerr)
	}
	if mig.Phase != 4 {
		t.Fatalf("phase = %d, want 4", mig.Phase)
	}
	// And nothing was committed.
	if _, ferr := RefGet(r.l); !errors.Is(ferr, ErrNoReference) {
		t.Fatal("a reference was committed over an unverified fleet")
	}
}

func TestPhase4UsesTheRecordedFleet(t *testing.T) {
	ctx := context.Background()
	// PHASE 4 DETACHES ONLY THE RECORDED FLEET, never a container that appeared mid-migration and
	// was therefore never connected to the target.
	r := newRig(t)
	r.fleet(t, c1)
	r.runTo(t, 3)
	// A newcomer appears, labelled for this installation and attached to the source.
	r.objs.byInst[r.id] = []string{c1, c2}
	r.objs.nets[c2] = []NetAttach{{NetworkID: src, Address: addrFor(c2, src)}}
	if err := MigRun(ctx, r.l, r.d, src, tgt, 4); err != nil {
		t.Fatal(err)
	}
	for _, d := range r.mut.disconnects {
		if d.container == c2 {
			t.Fatal("phase 4 detached a container that appeared mid-migration")
		}
	}
	if len(r.mut.disconnects) != 1 {
		t.Fatalf("disconnects = %+v", r.mut.disconnects)
	}
}

func TestPhase4ReInspects(t *testing.T) {
	ctx := context.Background()
	// PHASE 4 RE-INSPECTS: phase 3's verification is a fact about the past, and detaching a
	// container no longer on the target would leave it on NEITHER network.
	r := newRig(t)
	r.fleet(t, c1)
	r.runTo(t, 3)
	// Between the phases the container loses the target attachment.
	r.objs.nets[c1] = []NetAttach{{NetworkID: src, Address: addrFor(c1, src)}}
	err := MigRun(ctx, r.l, r.d, src, tgt, 4)
	if err == nil || !strings.Contains(err.Error(), "not confirmed attached") {
		t.Fatalf("re-inspect: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("a container not on the target was detached")
	}
}

func TestBarePhasesRefuse(t *testing.T) {
	ctx := context.Background()
	// A BARE PHASE 4 on an ordinary attached fleet with NO recorded migration refuses: it would
	// have to invent the proof that the connect-and-verify phases ran.
	r := newRig(t)
	r.fleet(t, c1)
	err := MigRun(ctx, r.l, r.d, src, tgt, 4)
	if err == nil || !strings.Contains(err.Error(), "NO recorded migration") {
		t.Fatalf("bare phase 4: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("a bare phase 4 detached something")
	}
	// A BARE PHASE 6 with no verified migration refuses to commit-and-clear.
	err = MigRun(ctx, r.l, r.d, src, tgt, 6)
	if err == nil || !strings.Contains(err.Error(), "NO recorded migration") {
		t.Fatalf("bare phase 6: %v", err)
	}
	// A FAILED PHASE 3 DOES NOT LEAVE A MARKER that lets a later phase 4 detach: the record still
	// says phase 2, and phase 4 requires 3.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.runTo(t, 2)
	r2.pr.resolve[tgt+"/"+aliasOf(t, c1)] = "10.9.9.9" // resolves, but to the wrong address
	if err := MigRun(ctx, r2.l, r2.d, src, tgt, 3); err == nil {
		t.Fatal("phase 3 passed with a wrong address")
	}
	err = MigRun(ctx, r2.l, r2.d, src, tgt, 4)
	if err == nil || !strings.Contains(err.Error(), "requires it to have reached") {
		t.Fatalf("phase 4 after a failed phase 3: %v", err)
	}
	if len(r2.mut.disconnects) != 0 {
		t.Fatal("phase 4 detached after a failed phase 3")
	}
	// And phase 6 refuses at phase 4 too — it requires 5.
	r3 := newRig(t)
	r3.fleet(t, c1)
	r3.runTo(t, 4)
	err = MigRun(ctx, r3.l, r3.d, src, tgt, 6)
	if err == nil || !strings.Contains(err.Error(), "requires it to have reached") {
		t.Fatalf("phase 6 at phase 4: %v", err)
	}
	// A phase asked to act on a DIFFERENT pair than the record names refuses.
	err = MigRun(ctx, r3.l, r3.d, src, nOther, 4)
	if err == nil || !strings.Contains(err.Error(), "record does not name") {
		t.Fatalf("mismatched pair: %v", err)
	}
}

func TestPhase6ReVerifies(t *testing.T) {
	ctx := context.Background()
	// PHASE 6 RE-VERIFIES EXACTLY {target} and REFUSES to clear when a container was reattached to
	// the source: committing would strand it mid-migration with nothing to resume from.
	r := newRig(t)
	r.fleet(t, c1)
	r.objs.network("opnet", tgt)
	r.runTo(t, 5)
	r.objs.nets[c1] = append(r.objs.nets[c1], NetAttach{NetworkID: src, Address: addrFor(c1, src)})
	err := MigRun(ctx, r.l, r.d, src, tgt, 6)
	if err == nil || !strings.Contains(err.Error(), "no longer on the target network alone") {
		t.Fatalf("phase 6 re-verify: %v", err)
	}
	// STOPPING WITH THE INTENT INTACT — the migration stays resumable.
	if _, gerr := MigGet(r.l); gerr != nil {
		t.Fatalf("the intent was cleared: %v", gerr)
	}
	if _, ferr := RefGet(r.l); !errors.Is(ferr, ErrNoReference) {
		t.Fatal("a reference was committed over a container on both networks")
	}
}

func TestPhase6Commits(t *testing.T) {
	r := newRig(t)
	r.fleet(t, c1)
	r.objs.network("opnet", tgt)
	r.runTo(t, 6)
	// COMMITTING CLEARS THE INTENT, so the exact-set check resumes immediately — while a migration
	// is recorded, bring-up permits {source,target}; once it is gone, {target} alone.
	if _, err := MigGet(r.l); !errors.Is(err, ErrNoMigration) {
		t.Fatal("phase 6 did not clear the intent")
	}
	id, err := RefGet(r.l)
	if err != nil || id != tgt {
		t.Fatalf("reference = %q %v", id, err)
	}
}

func TestSameSourceAndTargetRefused(t *testing.T) {
	// Phase 4 would detach the only network the family is on, leaving every container attached to
	// nothing.
	r := newRig(t)
	r.fleet(t, c1)
	err := MigRun(context.Background(), r.l, r.d, src, src, 1)
	if err == nil || !strings.Contains(err.Error(), "same network") {
		t.Fatalf("same source and target: %v", err)
	}
	// And an empty one names nothing.
	if err := MigRun(context.Background(), r.l, r.d, "", tgt, 1); err == nil {
		t.Fatal("an empty source was accepted")
	}
}

func TestResumeContinuesForward(t *testing.T) {
	ctx := context.Background()
	// RECOVERY READS THE RECORDED PHASE AND CONTINUES FORWARD — never unwinds. Once containers are
	// on both networks there is nothing to unwind to.
	r := newRig(t)
	r.fleet(t, c1)
	r.objs.network("opnet", tgt)
	r.runTo(t, 2) // crash after phase 2
	if err := MigResume(ctx, r.l, r.d); err != nil {
		t.Fatal(err)
	}
	// It converged: the reference is committed, the intent is gone, and nothing was re-connected
	// to the source.
	if _, err := MigGet(r.l); !errors.Is(err, ErrNoMigration) {
		t.Fatal("the intent survived a completed resume")
	}
	id, err := RefGet(r.l)
	if err != nil || id != tgt {
		t.Fatalf("reference = %q %v", id, err)
	}
	for _, c := range r.mut.connects {
		if c.net == src {
			t.Fatal("resume re-connected the fleet to the source — it unwound")
		}
	}

	// AND IT STARTS AT THE RECORDED PHASE. Every phase is idempotent, so converging proves only
	// that it finished — not that it did not start over. Phase 3 is the only phase that probes
	// egress on the SOURCE, so resuming a migration recorded at phase 5 must never touch it.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.objs.network("opnet", tgt)
	r2.runTo(t, 5)
	before := r2.pr.egressCalls[src]
	if before == 0 {
		t.Fatal("phase 3 never probed source egress, so this instrument measures nothing")
	}
	if err := MigResume(context.Background(), r2.l, r2.d); err != nil {
		t.Fatal(err)
	}
	if got := r2.pr.egressCalls[src]; got != before {
		t.Fatalf("resume re-ran phase 3 (source egress probed %d more times) — it started over rather than continuing", got-before)
	}
}

func TestResumeRefusesIncompleteIntents(t *testing.T) {
	ctx := context.Background()
	// AN INTENT RECORDING ONLY THE TARGET cannot complete: phase 4 cannot know what to detach, and
	// after a crash there is no other way to learn it.
	r := newRig(t)
	r.fleet(t, c1)
	if err := r.l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"}, {Key: "phase", Value: "2"},
		{Key: "target", Value: tgt}, {Key: "containers", Value: c1},
	}); err != nil {
		t.Fatal(err)
	}
	err := MigResume(ctx, r.l, r.d)
	if err == nil || !strings.Contains(err.Error(), "names no source network") {
		t.Fatalf("target-only intent: %v", err)
	}
	if len(r.mut.disconnects) != 0 {
		t.Fatal("something was detached")
	}
	// A PHASE THAT IS NOT A NUMBER refuses rather than reporting success — reading it as 0 would
	// silently restart the migration from the beginning.
	r2 := newRig(t)
	r2.fleet(t, c1)
	if err := r2.l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"}, {Key: "phase", Value: "later"},
		{Key: "source", Value: src}, {Key: "target", Value: tgt}, {Key: "containers", Value: c1},
	}); err != nil {
		t.Fatal(err)
	}
	err = MigResume(ctx, r2.l, r2.d)
	if err == nil || !strings.Contains(err.Error(), "not a number") {
		t.Fatalf("non-numeric phase: %v", err)
	}
	// A missing TARGET is nothing to migrate onto.
	r3 := newRig(t)
	r3.fleet(t, c1)
	if err := r3.l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"}, {Key: "phase", Value: "2"},
		{Key: "source", Value: src}, {Key: "containers", Value: c1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := MigResume(ctx, r3.l, r3.d); err == nil {
		t.Fatal("an intent with no target resumed")
	}
}

func TestForwardOnlyMigration(t *testing.T) {
	ctx := context.Background()
	// A MISSING OLD NETWORK is recognised as FORWARD-ONLY: phases 3 and 5 verify each container
	// against exactly {target} rather than {source,target}, so the migration CONVERGES rather than
	// wedging on a source that is gone.
	r := newRig(t)
	r.fleet(t, c1)
	r.objs.network("opnet", tgt)
	r.runTo(t, 2)
	// The source disappears mid-migration, and the container is already only on the target.
	delete(r.objs.live, src)
	r.objs.nets[c1] = []NetAttach{{NetworkID: tgt, Address: addrFor(c1, tgt)}}
	if err := MigResume(ctx, r.l, r.d); err != nil {
		t.Fatalf("a forward-only migration wedged: %v", err)
	}
	if _, err := MigGet(r.l); !errors.Is(err, ErrNoMigration) {
		t.Fatal("a forward-only migration did not converge")
	}
	id, err := RefGet(r.l)
	if err != nil || id != tgt {
		t.Fatalf("reference = %q %v", id, err)
	}
	// A forward-only phase 3 refuses a container that is NOT on the target alone.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.runTo(t, 2)
	delete(r2.objs.live, src)
	err = MigRun(ctx, r2.l, r2.d, src, tgt, 3)
	if err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatalf("forward-only with a container still on both: %v", err)
	}
}

func TestRebindOffOwnedNetwork(t *testing.T) {
	ctx := context.Background()
	// A REBIND CAN MIGRATE THE FLEET OFF THE INSTALLER'S OWN NETWORK onto an operator's: the
	// source comes from the owned network's provenance record when no reference is recorded.
	r := newRig(t)
	name, _ := manifest.NetworkName(r.id)
	if err := prov.Record(r.l, prov.ClassNetwork, name, "n1", ledger.Field{Key: "id", Value: src}); err != nil {
		t.Fatal(err)
	}
	r.fleet(t, c1)
	r.objs.network("opnet", tgt)
	if err := Rebind(ctx, r.l, r.d, tgt); err != nil {
		t.Fatal(err)
	}
	id, err := RefGet(r.l)
	if err != nil || id != tgt {
		t.Fatalf("reference = %q %v", id, err)
	}
	// The fleet moved: connected to the target, detached from the owned source.
	if len(r.mut.connects) != 1 || r.mut.connects[0].net != tgt {
		t.Fatalf("connects = %+v", r.mut.connects)
	}
	if len(r.mut.disconnects) != 1 || r.mut.disconnects[0].net != src {
		t.Fatalf("disconnects = %+v", r.mut.disconnects)
	}
	// A SECOND migration over a first is refused — the intent is the only record of where the
	// fleet came from.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.runTo(t, 2)
	err = Rebind(ctx, r2.l, r2.d, nOther)
	if err == nil || !strings.Contains(err.Error(), "already recorded") {
		t.Fatalf("second migration: %v", err)
	}
}

func TestRecordedPhaseMustBeOneOfTheSix(t *testing.T) {
	// A NUMERIC CHECK ALONE IS NOT A PHASE CHECK. `phase=7` parses, so the resume loop
	// (`for p := 7; p <= 6`) runs ZERO iterations and returns success — leaving the recorded
	// migration and the fleet exactly as they were while reporting that recovery completed. A
	// migration that reports success without doing anything is the one outcome resume must never
	// produce.
	for _, bad := range []string{"0", "7", "99"} {
		r := newRig(t)
		r.fleet(t, c1)
		if err := r.l.Put(kindNetMig, "key", "family", []ledger.Field{
			{Key: "key", Value: "family"}, {Key: "phase", Value: bad},
			{Key: "source", Value: src}, {Key: "target", Value: tgt}, {Key: "containers", Value: c1},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := MigGet(r.l); err == nil {
			t.Errorf("phase %q was read as a phase", bad)
		}
		err := MigResume(context.Background(), r.l, r.d)
		if err == nil {
			t.Errorf("phase %q resumed successfully without doing anything", bad)
			continue
		}
		if !strings.Contains(err.Error(), "not one of the six phases") {
			t.Errorf("phase %q refused for the wrong reason: %v", bad, err)
		}
		// PRESERVED and reported — never rewritten to something readable.
		if _, gerr := r.l.Find(kindNetMig, "key", "family"); gerr != nil {
			t.Errorf("phase %q: the record was not preserved: %v", bad, gerr)
		}
	}
	// And the six real phases are still accepted — the range check must not over-refuse.
	for p := 1; p <= 6; p++ {
		if _, err := phaseOK(strconv.Itoa(p)); err != nil {
			t.Errorf("phase %d refused: %v", p, err)
		}
	}
}

// --- durability across a crash --------------------------------------------------------------------

func TestOwnedNetworkIntentIsDurableBeforeTheCreate(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	name, _ := manifest.NetworkName(r.id)
	// The daemon accepts the create and the process dies. A NETWORK IS NEVER REISSUED (D38), so an
	// unaccounted one is not something a later run can create its way out of — it has to be found
	// by the record this barrier makes durable.
	if _, err := OwnedEnsure(ctx, r.l, r.objs, r.mut, r.d.Deps); err != nil {
		t.Fatal(err)
	}
	if r.dk.writes == 0 {
		t.Fatal("nothing was ever persisted, so this proves nothing")
	}
	// Read back ONLY what was on disk when the create was issued: the first persist is the barrier.
	firstWrite := &ledger.Ledger{}
	firstWrite.ReplaceLines(r.dk.lines)
	if _, err := intent.Find(firstWrite, prov.ClassNetwork, name); err != nil {
		// The final persist is the confirmation, so an absent intent here is only correct if the
		// PROVENANCE is there instead — either way the network is accounted for.
		if _, perr := prov.Find(firstWrite, prov.ClassNetwork, name); perr != nil {
			t.Fatalf("the network was created with neither a durable intent nor durable provenance: %v / %v", err, perr)
		}
	}

	// A PERSIST THAT FAILS STOPS THE CREATE.
	r2 := newRig(t)
	r2.dk.err = errors.New("disk full")
	if _, err := OwnedEnsure(ctx, r2.l, r2.objs, r2.mut, r2.d.Deps); err == nil {
		t.Fatal("a network was created with an unpersistable intent")
	}
	// A MISSING seam is refused, not skipped.
	r3 := newRig(t)
	r3.d.Persist = nil
	_, err := OwnedEnsure(ctx, r3.l, r3.objs, r3.mut, r3.d.Deps)
	if err == nil || !strings.Contains(err.Error(), "no way to persist") {
		t.Fatalf("a create with no persistence seam: %v", err)
	}
}

func TestPhaseMarkerIsDurableBeforeTheDetach(t *testing.T) {
	ctx := context.Background()
	// THE WEDGE THIS CLOSES: if disk still said phase 3 while some containers were already
	// detached, a resume would re-run phase 3 — whose exact-set check requires {source,target} —
	// and REFUSE exactly the containers phase 4 had already finished. The fleet would be
	// half-migrated with no phase to move forward from.
	r := newRig(t)
	r.fleet(t, c1, c2)
	r.runTo(t, 3)

	// Snapshot what disk holds at the moment the first detach is issued.
	var atFirstDetach []string
	r.mut.onDisconnect = func() {
		if atFirstDetach == nil {
			atFirstDetach = append([]string(nil), r.dk.lines...)
		}
	}
	if err := MigRun(ctx, r.l, r.d, src, tgt, 4); err != nil {
		t.Fatal(err)
	}
	if atFirstDetach == nil {
		t.Fatal("nothing was detached, so this proves nothing")
	}
	disk4 := &ledger.Ledger{}
	disk4.ReplaceLines(atFirstDetach)
	mig, err := MigGet(disk4)
	if err != nil {
		t.Fatalf("no durable migration record at the first detach: %v", err)
	}
	if mig.Phase != 4 {
		t.Fatalf("disk said phase %d when the first detach was issued, want 4 — a crash there would\n"+
			"  resume into phase 3, which refuses an already-detached container", mig.Phase)
	}

	// A PERSIST THAT FAILS STOPS THE PHASE before anything is detached.
	r2 := newRig(t)
	r2.fleet(t, c1)
	r2.runTo(t, 3)
	r2.dk.err = errors.New("disk full")
	if err := MigRun(ctx, r2.l, r2.d, src, tgt, 4); err == nil {
		t.Fatal("phase 4 detached with an unpersistable marker")
	}
	if len(r2.mut.disconnects) != 0 {
		t.Fatal("phase 4 detached despite the marker not being durable")
	}
	// And phase 2 is barriered the same way, before it connects anything.
	r3 := newRig(t)
	r3.fleet(t, c1)
	r3.runTo(t, 1)
	r3.dk.err = errors.New("disk full")
	if err := MigRun(ctx, r3.l, r3.d, src, tgt, 2); err == nil {
		t.Fatal("phase 2 connected with an unpersistable marker")
	}
	if len(r3.mut.connects) != 0 {
		t.Fatal("phase 2 connected despite the marker not being durable")
	}
}
