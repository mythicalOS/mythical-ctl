package bringup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — tests/unit/bringup.bats. The mount/secret/canon half of lib/bringup.sh landed in
// Wave 3 as internal/runtime (Task 15), so those rows are claimed there; this file owns the
// create/verify/recover/reconcile sequence.
//
// PORTED: tests/unit/bringup.bats: "bring-up creates STOPPED, on exactly the target network, with the alias" -> TestRunCreatesStopped
// PORTED: tests/unit/bringup.bats: "attachment verification asserts the network set is EXACTLY the expected ID" -> TestAttachExactSet
// PORTED: tests/unit/bringup.bats: "a container attached to NOTHING fails verification, and says so" -> TestAttachExactSet
// PORTED: tests/unit/bringup.bats: "the same network attached twice is not the same as attached once" -> TestAttachExactSet
// PORTED: tests/unit/bringup.bats: "a missing ALIAS fails verification even when the attachment is right" -> TestAttachAliasRequired
// PORTED: tests/unit/bringup.bats: "verify_attach accepts a NEVER-STARTED container by resolving the network name (empty NetworkID)" -> TestAttachPreStart
// PORTED: tests/unit/bringup.bats: "verify_attach rejects a stray network on a NEVER-STARTED container (exact set holds pre-start)" -> TestAttachPreStart
// PORTED: tests/unit/bringup.bats: "a container on TWO networks WITH a recorded migration intent is permitted, bounded to {old,new}" -> TestAttachDuringMigration
// PORTED: tests/unit/bringup.bats: "a container on a THIRD network is a failure even during a migration" -> TestAttachDuringMigration
// PORTED: tests/unit/bringup.bats: "a container attached only to the migration's SOURCE fails verification against the TARGET" -> TestAttachDuringMigration
// PORTED: tests/unit/bringup.bats: "a container attached only to the migration's TARGET fails verification against the TARGET" -> TestAttachDuringMigration
// PORTED: tests/unit/bringup.bats: "a container attached only to the migration's SOURCE fails verification against the SOURCE" -> TestAttachDuringMigration
// PORTED: tests/unit/bringup.bats: "an AMBIGUOUS migration record refuses verification instead of narrowing the permitted set" -> TestAttachMigrationRecordRefusals
// PORTED: tests/unit/bringup.bats: "a migration record naming only ONE network refuses too — the same narrowing by another route" -> TestAttachMigrationRecordRefusals
// PORTED: tests/unit/bringup.bats: "and a genuinely absent migration record still verifies a correctly attached container" -> TestAttachMigrationRecordRefusals
// PORTED: tests/unit/bringup.bats: "the full bring-up sets the outstanding entry at CONFIRM and clears it only after live verify" -> TestRunSetsAndClearsTheCheck
// PORTED: tests/unit/bringup.bats: "a FRESH install live-verifies the alias — the flag exists and the commonest path sets it" -> TestRunSetsAndClearsTheCheck
// PORTED: tests/unit/bringup.bats: "live verification FAILING leaves the product RUNNING and keeps the entry" -> TestRunLiveFailureLeavesItRunning
// PORTED: tests/unit/bringup.bats: "a probe that could not run leaves the entry outstanding and says the check was not made" -> TestRunLiveFailureLeavesItRunning
// PORTED: tests/unit/bringup.bats: "desired state is a PARAMETER — a replacement preserves stopped" -> TestRunPreserve
// PORTED: tests/unit/bringup.bats: "preserve with NOTHING recorded is a usage error, not a silent running" -> TestRunPreserve
// PORTED: tests/unit/bringup.bats: "a stopped bring-up keeps the outstanding entry rather than clearing or performing it" -> TestRunCreatesStopped
// PORTED: tests/unit/bringup.bats: "the live address is read by RE-INSPECTING after the start" -> TestRunReInspectsAfterStart
// PORTED: tests/unit/bringup.bats: "a bring-up that does not verify confirms NOTHING and removes the container" -> TestRunRemovesWhatDidNotVerify
// PORTED: tests/unit/bringup.bats: "no product state survives a failed bring-up beyond what was recorded ahead of it" -> TestRunRemovesWhatDidNotVerify
// PORTED: tests/unit/bringup.bats: "recovery from a crash after CREATE establishes desired state and the check, then confirms" -> TestRecover
// PORTED: tests/unit/bringup.bats: "recovery restores the desired state the bring-up recorded, not a default" -> TestRecover
// PORTED: tests/unit/bringup.bats: "recovery refuses an intent that does not record what the bring-up was doing" -> TestRecoverRefusesIncompleteIntents
// PORTED: tests/unit/bringup.bats: "recovery refuses when the intent names a different network from the one it is asked about" -> TestRecoverRefusesIncompleteIntents
// PORTED: tests/unit/bringup.bats: "recovery from a crash after CREATE with a WRONG topology removes and reissues" -> TestRecoverWrongTopology
// PORTED: tests/unit/bringup.bats: "recovery refuses a container standing at the name under a DIFFERENT nonce" -> TestRecoverWrongNonce
// PORTED: tests/unit/bringup.bats: "a resume is attempted ONCE per run and recorded — never a restart loop" -> TestReconcileResumesOnce
// PORTED: tests/unit/bringup.bats: "a running container with an outstanding check is verified NOW, and the entry then clears" -> TestReconcileVerifiesNow
// PORTED: tests/unit/bringup.bats: "a stopped container with an outstanding check is deferred, never cleared" -> TestReconcileDefers
// PORTED: tests/unit/bringup.bats: "the live check refuses to clear while the container has gained an EXTRA network" -> TestLiveAsksTheCompleteSet
// PORTED: tests/unit/bringup.bats: "live verification asks the COMPLETE set, not just the address on the target network" -> TestLiveAsksTheCompleteSet
// PORTED: tests/unit/bringup.bats: "the generic intent reconciler REFUSES a container intent instead of finishing it" -> TestGenericReconcilerRefusesContainers
// (bringup.bats' three secret-injection rows are NOT claimed here. Wave 3 moved the behaviour to
// runtime.LaunchProduct's secretsFor, and the claims moved with it — internal/runtime's
// TestSecretsInjection owns them. They were marked N/A here on the argument that the port was
// "elsewhere"; that argument was false. A relocated behaviour is PORTED, not N/A, and saying N/A
// while another file quietly said PORTED left one row described two contradictory ways.)
// (bringup.bats' row about no <product>.conf value reaching a launch argument is claimed in
// internal/verbs by TestNoValueFromAProductConfReachesTheLaunch. It was N/A here on the argument
// that the launch seam takes only a container name and a nonce — but an interface says nothing
// about what an implementation CARRIES, and the real launcher carries the launch config, the
// manifest and the policy into LaunchProduct. The subject of the row exists; "nothing currently
// reads it" is the state a guard preserves, not a guard.)

// --- fakes ---------------------------------------------------------------------------------------

const (
	ident1 = "i0123456789"
	c1     = "mythical-" + ident1 + "-brokkr"
	net1   = "netid-target"
	net2   = "netid-source"
	net3   = "netid-stray"
	al1    = "brokkr"
)

type fakeObjs struct {
	nets     map[string][]Attachment
	labels   map[string]map[string]string
	image    map[string]string
	imageErr map[string]error
	err      map[string]error
	netCall  int
}

func newObjs() *fakeObjs {
	return &fakeObjs{nets: map[string][]Attachment{}, labels: map[string]map[string]string{},
		image: map[string]string{}, imageErr: map[string]error{}, err: map[string]error{}}
}

func (f *fakeObjs) Attachments(_ context.Context, c string) ([]Attachment, error) {
	f.netCall++
	if err := f.err[c]; err != nil {
		return nil, err
	}
	return f.nets[c], nil
}

func (f *fakeObjs) Label(_ context.Context, c, label string) (string, error) {
	if err := f.err[c]; err != nil {
		return "", err
	}
	m, ok := f.labels[c]
	if !ok {
		return "", engine.ErrAbsent
	}
	return m[label], nil
}

// imageErr is its own knob rather than reusing `err`: `err` fails Attachments and Label too, so a
// container using it never reaches the image read at all. The defect under test is an inspection
// that fails while everything BEFORE it succeeded.
func (f *fakeObjs) Image(_ context.Context, c string) (string, error) {
	if err := f.imageErr[c]; err != nil {
		return "", err
	}
	return f.image[c], nil
}

type fakeMut struct {
	started, stopped, removed []string
	startErr, stopErr         error
	// removeErr is the daemon REFUSING a removal — the commonest real cause being a volume or a
	// network still bound to the container. `removed` still records the attempt, so a test can
	// tell "never asked" from "asked and refused".
	removeErr error
	onStart   func()
	// atStartEntry fires as the FIRST thing ContainerStart does, so a test can observe what DISK
	// held at the instant the runtime was asked to act. Inspecting after the call returns cannot
	// tell "written before" from "written after" — which is what made the first durability tests
	// unable to fail.
	atStartEntry func()
}

func (m *fakeMut) ContainerStart(_ context.Context, id string) error {
	if m.atStartEntry != nil {
		m.atStartEntry()
	}
	m.started = append(m.started, id)
	if m.onStart != nil {
		m.onStart()
	}
	return m.startErr
}
func (m *fakeMut) ContainerStop(_ context.Context, id string) error {
	m.stopped = append(m.stopped, id)
	return m.stopErr
}
func (m *fakeMut) ContainerRemove(_ context.Context, id string) error {
	m.removed = append(m.removed, id)
	return m.removeErr
}

type fakeProbe struct {
	selfErr    error
	resolveTo  map[string]string
	resolveErr error
}

func (p *fakeProbe) SelfCheck(context.Context, *trust.Index, string) error { return p.selfErr }
func (p *fakeProbe) Resolve(_ context.Context, _ *trust.Index, netID, alias string) (string, error) {
	if p.resolveErr != nil {
		return "", p.resolveErr
	}
	v, ok := p.resolveTo[netID+"/"+alias]
	if !ok {
		return "", probe.ErrNotResolved
	}
	return v, nil
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

type fakeLauncher struct {
	objs    *fakeObjs
	st      *fakeState
	nets    []Attachment
	calls   int
	err     error
	created string
	// after runs once the container exists, for cases where the world changes between the create
	// and the verification.
	after func()
	// atEntry fires as the FIRST thing Launch does — the instant the daemon would be asked to
	// create. What disk holds THEN is the whole write-ahead question.
	atEntry func()
}

func (l *fakeLauncher) Launch(_ context.Context, container, nonce string) (string, error) {
	if l.atEntry != nil {
		l.atEntry()
	}
	l.calls++
	if l.err != nil {
		return "", l.err
	}
	l.created = container
	l.objs.nets[container] = l.nets
	l.objs.labels[container] = ourLabels(nonce)
	l.objs.image[container] = "sha256:abc"
	// Created STOPPED, always — starting is a separate, later step.
	l.st.down(container)
	if l.after != nil {
		l.after()
	}
	return "cid", nil
}

// ourLabels is the label set of a container THIS installation created.
//
// Every fixture that means "ours" must use it. A bare nonce label is not ownership — a nonce says
// WHICH object and never WHOSE — so a fixture that sets only a nonce is describing a container
// belonging to nobody, whatever it intended to describe. Several of these fixtures did exactly
// that, and it went unnoticed for as long as the code under test judged ownership on the nonce
// alone: the fixture's blind spot and the code's were the same one.
func ourLabels(nonce string) map[string]string {
	return map[string]string{prov.LabelInstall: ident1, prov.LabelNonce: nonce}
}

var fixedNow = time.Unix(1_700_000_000, 0)

func fixture(t *testing.T) (*ledger.Ledger, *fakeObjs, *fakeMut, *fakeProbe, *fakeState, Deps) {
	t.Helper()
	l := &ledger.Ledger{}
	// A FIXED IDENTITY, and the one the constant container names embed. IdentEnsure used to MINT a
	// random one here while c1 stayed "mythical-i0123456789-brokkr", so the ledger's identity and
	// the names derived from it disagreed in every test. Nothing noticed while ownership was judged
	// on the nonce alone; the moment the installation label is read, the fixture describes a fleet
	// belonging to an installation that is not this one.
	if err := l.Put("identity", "id", ident1, []ledger.Field{{Key: "id", Value: ident1}}); err != nil {
		t.Fatal(err)
	}
	if got, err := l.IdentEnsure(); err != nil || got != ident1 {
		t.Fatalf("fixture identity: got %q, %v; want %q", got, err, ident1)
	}
	objs, mut, pr, st := newObjs(), &fakeMut{}, &fakeProbe{resolveTo: map[string]string{}}, newStateObjs()
	n := 0
	d := Deps{
		Objs: objs, Mut: mut, Probe: pr, State: st,
		NewNonce: func() (string, error) { n++; return "n" + string(rune('0'+n)), nil },
		Now:      func() time.Time { return fixedNow },
	}
	// A WORKING PERSISTENCE SEAM BY DEFAULT, so the ordinary cases exercise the ordinary path.
	// The write-ahead barrier refuses without one — deliberately — so the cases that assert THAT
	// install their own (a failing disk, or none at all), and the durability cases install a disk
	// they can read back.
	d.Persist = (&disk{}).persist()
	return l, objs, mut, pr, st, d
}

func attach(netID, addr string, aliases ...string) Attachment {
	return Attachment{NetworkID: netID, Address: addr, Aliases: aliases}
}

func recordMigration(t *testing.T, l *ledger.Ledger, src, tgt string) {
	t.Helper()
	if err := l.Put("netmig", "key", "family", []ledger.Field{
		{Key: "key", Value: "family"}, {Key: "phase", Value: "2"},
		{Key: "source", Value: src}, {Key: "target", Value: tgt},
		{Key: "containers", Value: c1},
	}); err != nil {
		t.Fatal(err)
	}
}

// --- the exact-set attachment check ---------------------------------------------------------------

func TestAttachExactSet(t *testing.T) {
	ctx := context.Background()
	l, objs, _, _, _, d := fixture(t)
	// EXACTLY the expected id.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a correctly attached container failed: %v", err)
	}
	// ATTACHED TO NOTHING, and it says so.
	objs.nets[c1] = nil
	err := VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "NO network at all") {
		t.Fatalf("attached to nothing: %v", err)
	}
	// A STRAY network: "is ours among them" is what lets a default bridge survive.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1), attach(net3, "172.17.0.2")}
	err = VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("stray network: %v", err)
	}
	// THE SAME NETWORK TWICE is not the same as once — one endpoint per network.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1), attach(net1, "10.0.0.3", al1)}
	err = VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "2 times") {
		t.Fatalf("doubled attachment: %v", err)
	}
	// ATTACHED, BUT NOT TO THE EXPECTED ONE.
	objs.nets[c1] = []Attachment{attach(net2, "10.0.0.2", al1)}
	err = VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil {
		t.Fatal("a container on the wrong network verified")
	}
}

func TestAttachAliasRequired(t *testing.T) {
	ctx := context.Background()
	l, objs, _, _, _, d := fixture(t)
	// The attachment is RIGHT and the alias is missing: siblings resolve a product by its alias,
	// so without it family DNS fails silently.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2")}
	err := VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("missing alias: %v", err)
	}
	// A DIFFERENT alias is not this one.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", "saga")}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err == nil {
		t.Fatal("the wrong alias verified")
	}
}

func TestAttachPreStart(t *testing.T) {
	ctx := context.Background()
	l, objs, _, _, _, d := fixture(t)
	// A NEVER-STARTED container reports an empty endpoint id and an empty address; the caller's
	// seam resolves the network NAME to its id, so the check works pre-start — which is exactly
	// when it must, because bring-up verifies before it ever starts anything.
	objs.nets[c1] = []Attachment{attach(net1, "", al1)}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a never-started container failed the attach check: %v", err)
	}
	// AND THE EXACT SET HOLDS PRE-START: a stray network on a never-started container is caught.
	objs.nets[c1] = []Attachment{attach(net1, "", al1), attach(net3, "")}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err == nil {
		t.Fatal("a stray network on a never-started container verified")
	}
}

func TestAttachDuringMigration(t *testing.T) {
	ctx := context.Background()
	// TWO NETWORKS ARE PERMITTED, BOUNDED TO {source, target}: during phase 2 every container is
	// legitimately on both.
	l, objs, _, _, _, d := fixture(t)
	recordMigration(t, l, net2, net1)
	objs.nets[c1] = []Attachment{attach(net2, "10.0.1.2", al1), attach(net1, "10.0.0.2", al1)}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a mid-migration container failed: %v", err)
	}
	// A THIRD network is a failure even during a migration.
	objs.nets[c1] = append(objs.nets[c1], attach(net3, "172.17.0.2"))
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err == nil {
		t.Fatal("a third network verified during a migration")
	}
	// A SUBSET IS NOT THE SET. Attached only to the SOURCE, asked about the target: mid-move.
	objs.nets[c1] = []Attachment{attach(net2, "10.0.1.2", al1)}
	err := VerifyAttach(ctx, l, d, c1, net1, al1)
	// The "not attached to the EXPECTED network" arm answers first here, and either refusal is
	// correct — what must never happen is that a subset passes.
	if err == nil {
		t.Fatal("source-only verified against the target during a migration")
	}
	// Attached only to the TARGET, asked about the target: still mid-move, because the record says
	// it should be on both.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	if err := VerifyAttach(ctx, l, d, c1, net1, al1); err == nil {
		t.Fatal("target-only verified during a migration")
	}
	// Attached only to the SOURCE, asked about the SOURCE: the same rule from the other side.
	objs.nets[c1] = []Attachment{attach(net2, "10.0.1.2", al1)}
	if err := VerifyAttach(ctx, l, d, c1, net2, al1); err == nil {
		t.Fatal("source-only verified against the source during a migration")
	}
}

func TestAttachMigrationRecordRefusals(t *testing.T) {
	ctx := context.Background()
	// AN AMBIGUOUS record refuses rather than narrowing the permitted set — narrowing is how a
	// half-migrated container gets recorded as verified.
	l, objs, _, _, _, d := fixture(t)
	l.ReplaceLines(append(l.Lines(),
		"netmig\tkey=family\tphase=2\tsource="+net2+"\ttarget="+net1+"\tcontainers="+c1,
		"netmig\tkey=family\tphase=2\tsource="+net3+"\ttarget="+net1+"\tcontainers="+c1))
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	err := VerifyAttach(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "cannot read whether") {
		t.Fatalf("an ambiguous migration record narrowed the set: %v", err)
	}
	// A record naming only ONE network refuses too — the same narrowing by another route.
	l2, objs2, _, _, _, d2 := fixture(t)
	if err := l2.Put("netmig", "key", "family", []ledger.Field{
		{Key: "key", Value: "family"}, {Key: "phase", Value: "2"},
		{Key: "target", Value: net1}, {Key: "containers", Value: c1},
	}); err != nil {
		t.Fatal(err)
	}
	objs2.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	err = VerifyAttach(ctx, l2, d2, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "both networks") {
		t.Fatalf("a one-sided migration record narrowed the set: %v", err)
	}
	// AND A GENUINELY ABSENT record still verifies a correctly attached container — the refusals
	// above must not make the ordinary case impossible.
	l3, objs3, _, _, _, d3 := fixture(t)
	objs3.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	if err := VerifyAttach(ctx, l3, d3, c1, net1, al1); err != nil {
		t.Fatalf("no migration recorded: %v", err)
	}
}

// --- live verification ----------------------------------------------------------------------------

func TestLiveAsksTheCompleteSet(t *testing.T) {
	ctx := context.Background()
	l, objs, _, pr, _, d := fixture(t)
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
	if err := VerifyLive(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a correctly attached, resolving container failed: %v", err)
	}
	// AN EXTRA NETWORK gained since the attach check: the live check asks the COMPLETE set, so it
	// refuses to clear even though the address on the target still resolves.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1), attach(net3, "172.17.0.2")}
	err := VerifyLive(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("an extra network was ignored by the live check: %v", err)
	}
	// RESOLVING VIA SOMETHING ELSE is not resolving here: the address must be this container's own
	// endpoint on this network.
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	pr.resolveTo[net1+"/"+al1] = "10.0.0.99"
	err = VerifyLive(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "something other than") {
		t.Fatalf("a foreign address passed: %v", err)
	}
	// A DEFINITE non-resolution is a verdict.
	delete(pr.resolveTo, net1+"/"+al1)
	err = VerifyLive(ctx, l, d, c1, net1, al1)
	if err == nil || errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("a definite non-resolution was reported as unavailable: %v", err)
	}
	// A PROBE THAT DID NOT RUN is NOT a verdict — folding the two would let an unavailable checker
	// retire a verification nothing performed.
	pr.selfErr = errors.New("probe image missing")
	err = VerifyLive(ctx, l, d, c1, net1, al1)
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("an unavailable probe was reported as a failed check: %v", err)
	}
}

// --- the full sequence ----------------------------------------------------------------------------

func TestRunCreatesStopped(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	if err := Run(ctx, l, d, lau, c1, net1, al1, Stopped); err != nil {
		t.Fatal(err)
	}
	// CREATED STOPPED, and never started.
	if len(mut.started) != 0 {
		t.Fatalf("a stopped bring-up started the container: %v", mut.started)
	}
	// On exactly the target network, with the alias — asserted by the sequence having verified.
	if got, err := state.DesiredGet(l, c1); err != nil || got != state.Stopped {
		t.Fatalf("desired = %q %v", got, err)
	}
	// A STOPPED BRING-UP KEEPS THE OUTSTANDING ENTRY rather than clearing or performing it.
	out, err := state.Outstanding(l, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Param != net1 {
		t.Fatalf("outstanding = %+v", out)
	}
	// And the intent is consumed: the container is confirmed.
	if _, err := intent.Find(l, prov.ClassContainer, c1); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the intent survived: %v", err)
	}
	if _, err := prov.Find(l, prov.ClassContainer, c1); err != nil {
		t.Fatalf("no provenance after confirm: %v", err)
	}
}

func TestRunSetsAndClearsTheCheck(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, pr, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	// The address appears at START, which is what makes the re-inspect necessary.
	mut.onStart = func() {
		objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
		st.up(c1)
	}
	pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
	if err := Run(ctx, l, d, lau, c1, net1, al1, Running); err != nil {
		t.Fatal(err)
	}
	// THE COMMONEST PATH SETS THE FLAG and the live verify clears it.
	out, err := state.Outstanding(l, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("the check was not cleared after a passing live verify: %+v", out)
	}
	if got, _ := state.DesiredGet(l, c1); got != state.Running {
		t.Fatalf("desired = %q", got)
	}
	ok, rerr := state.Reconciled(ctx, l, st, c1)
	if rerr != nil || !ok {
		t.Fatalf("not reconciled after a full bring-up: %v %v", ok, rerr)
	}
}

func TestRunReInspectsAfterStart(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, pr, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	// If the live check used the PRE-START inspect it would see an empty address and defer forever.
	// The address exists only after the start.
	mut.onStart = func() {
		objs.nets[c1] = []Attachment{attach(net1, "10.0.0.7", al1)}
		st.up(c1)
	}
	pr.resolveTo[net1+"/"+al1] = "10.0.0.7"
	before := objs.netCall
	if err := Run(ctx, l, d, lau, c1, net1, al1, Running); err != nil {
		t.Fatal(err)
	}
	if objs.netCall <= before+1 {
		t.Fatal("the live check did not re-inspect after the start")
	}
}

func TestRunLiveFailureLeavesItRunning(t *testing.T) {
	ctx := context.Background()
	// LIVE VERIFICATION FAILING leaves the product RUNNING and keeps the entry: a product that
	// works but whose DNS does not is not improved by stopping it.
	l, objs, mut, pr, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	mut.onStart = func() {
		objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
		st.up(c1)
	}
	// Nothing resolves: pr.resolveTo is deliberately left empty, so the probe RUNS and answers a
	// definite "does not resolve" — a verdict, not an unavailability.
	_ = pr
	err := Run(ctx, l, d, lau, c1, net1, al1, Running)
	if err == nil {
		t.Fatal("a failed live verification reported success")
	}
	if len(mut.stopped) != 0 || len(mut.removed) != 0 {
		t.Fatal("a failed live verification stopped or removed a running product")
	}
	out, _ := state.Outstanding(l, c1)
	if len(out) != 1 {
		t.Fatalf("the check was cleared despite failing: %+v", out)
	}

	// A PROBE THAT COULD NOT RUN leaves the entry outstanding and SAYS the check was not made.
	l2, objs2, mut2, pr2, st2, d2 := fixture(t)
	lau2 := &fakeLauncher{objs: objs2, st: st2, nets: []Attachment{attach(net1, "", al1)}}
	mut2.onStart = func() {
		objs2.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
		st2.up(c1)
	}
	pr2.selfErr = errors.New("probe image missing")
	err = Run(ctx, l2, d2, lau2, c1, net1, al1, Running)
	if !errors.Is(err, ErrProbeUnavailable) {
		t.Fatalf("an unavailable probe was reported as a failed check: %v", err)
	}
	if !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("the message does not say the check was not made: %v", err)
	}
	out, _ = state.Outstanding(l2, c1)
	if len(out) != 1 {
		t.Fatalf("the check was cleared by an unavailable probe: %+v", out)
	}
}

func TestRunPreserve(t *testing.T) {
	ctx := context.Background()
	// DESIRED STATE IS A PARAMETER: a replacement preserves stopped rather than starting it.
	l, objs, mut, _, st, d := fixture(t)
	if err := state.Commit(l, c1, state.Stopped, nil, true); err != nil {
		t.Fatal(err)
	}
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	if err := Run(ctx, l, d, lau, c1, net1, al1, Preserve); err != nil {
		t.Fatal(err)
	}
	if len(mut.started) != 0 {
		t.Fatal("preserve started a container recorded as stopped")
	}
	if got, _ := state.DesiredGet(l, c1); got != state.Stopped {
		t.Fatalf("desired = %q", got)
	}
	// PRESERVE WITH NOTHING RECORDED is a usage error, not a silent running.
	l2, objs2, mut2, _, st2, d2 := fixture(t)
	lau2 := &fakeLauncher{objs: objs2, st: st2, nets: []Attachment{attach(net1, "", al1)}}
	err := Run(ctx, l2, d2, lau2, c1, net1, al1, Preserve)
	if err == nil || !strings.Contains(err.Error(), "Refusing to guess") {
		t.Fatalf("preserve with nothing recorded: %v", err)
	}
	if lau2.calls != 0 || len(mut2.started) != 0 {
		t.Fatal("a refused preserve created or started something")
	}
}

func TestRunRemovesWhatDidNotVerify(t *testing.T) {
	ctx := context.Background()
	// A BRING-UP THAT DOES NOT VERIFY CONFIRMS NOTHING AND REMOVES THE CONTAINER: a
	// confirmed-but-detached container is a state this sequence must never produce.
	l, objs, mut, _, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net3, "", al1)}} // wrong network
	err := Run(ctx, l, d, lau, c1, net1, al1, Running)
	if err == nil {
		t.Fatal("a bring-up onto the wrong network reported success")
	}
	if len(mut.removed) != 1 || mut.removed[0] != c1 {
		t.Fatalf("the unverified container was not removed: %v", mut.removed)
	}
	if len(mut.started) != 0 {
		t.Fatal("an unverified container was started")
	}
	// NO PRODUCT STATE SURVIVES beyond what was recorded AHEAD of it: the intent (write-ahead, on
	// purpose) is there; the confirmation, the desired state and the check are not.
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a failed bring-up confirmed provenance")
	}
	if _, serr := state.DesiredGet(l, c1); !errors.Is(serr, ledger.ErrAbsentRecord) {
		t.Fatal("a failed bring-up recorded desired state")
	}
	out, _ := state.Outstanding(l, c1)
	if len(out) != 0 {
		t.Fatalf("a failed bring-up recorded a check: %+v", out)
	}
	if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
		t.Fatalf("the write-ahead intent was consumed by a failed bring-up: %v", ierr)
	}

	// SOMETHING ELSE HOLDING THE NAME is left alone. The nonce is NOT what says it is ours — it
	// says WHICH object and never WHOSE — so this asserts the ownership reason, not merely that
	// something was refused.
	l2, objs2, mut2, _, st2, d2 := fixture(t)
	// The launcher stamps its own nonce onto the container, so the substitution has to happen
	// AFTER it runs — which is exactly when it happens in reality: the create succeeded, and by
	// the time the attach check fails something else holds the name.
	lau2 := &fakeLauncher{objs: objs2, st: st2, nets: []Attachment{attach(net3, "", al1)}}
	lau2.after = func() {
		objs2.labels[c1] = ourLabels("someone-elses")
	}
	err = Run(ctx, l2, d2, lau2, c1, net1, al1, Running)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if len(mut2.removed) != 0 {
		t.Fatalf("removed a container this bring-up did not create: %v", mut2.removed)
	}
	if !strings.Contains(err.Error(), "LEFT ALONE") {
		t.Fatalf("message: %v", err)
	}
	if !strings.Contains(err.Error(), "not the \"n1\" this bring-up created") {
		t.Fatalf("the refusal did not name the ownership evidence that failed: %v", err)
	}
}

// --- recovery -------------------------------------------------------------------------------------

// crashedAfterCreate builds the state a crash between the create and the confirmation leaves: the
// intent is on the ledger, the container exists carrying its nonce, and nothing else was recorded.
func crashedAfterCreate(t *testing.T, l *ledger.Ledger, objs *fakeObjs, st *fakeState, want state.Desired, netID string, nets []Attachment) string {
	t.Helper()
	const nonce = "n1"
	if err := intent.Open(l, prov.ClassContainer, c1, nonce, fixedNow,
		ledger.Field{Key: "desired", Value: string(want)},
		ledger.Field{Key: "check", Value: "alias"},
		ledger.Field{Key: "check_param", Value: netID},
	); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = nets
	objs.labels[c1] = ourLabels(nonce)
	objs.image[c1] = "sha256:abc"
	st.down(c1)
	return nonce
}

func TestRecover(t *testing.T) {
	ctx := context.Background()
	l, objs, _, _, st, d := fixture(t)
	// RECOVERY RESTORES THE DESIRED STATE THE BRING-UP RECORDED, not a default — here `stopped`,
	// which a default of `running` would silently turn into a start.
	crashedAfterCreate(t, l, objs, st, state.Stopped, net1, []Attachment{attach(net1, "", al1)})
	if err := Recover(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
	if got, err := state.DesiredGet(l, c1); err != nil || got != state.Stopped {
		t.Fatalf("desired = %q %v", got, err)
	}
	// AND THE CHECK: an intent that recorded a start without recording what proving it costs is
	// the state an empty outstanding set must never mean.
	out, err := state.Outstanding(l, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Kind != state.CheckAlias || out[0].Param != net1 {
		t.Fatalf("outstanding = %+v", out)
	}
	// THEN CONFIRMS.
	if _, err := prov.Find(l, prov.ClassContainer, c1); err != nil {
		t.Fatalf("recovery did not confirm: %v", err)
	}
	if _, err := intent.Find(l, prov.ClassContainer, c1); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatal("the intent survived recovery")
	}
}

func TestRecoverRefusesIncompleteIntents(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		fields []ledger.Field
		want   string
	}{
		{"no desired state", []ledger.Field{{Key: "check", Value: "alias"}, {Key: "check_param", Value: net1}},
			"does not say which desired state"},
		{"a desired state with no row in the table", []ledger.Field{{Key: "desired", Value: "paused"}, {Key: "check", Value: "alias"}, {Key: "check_param", Value: net1}},
			"neither running nor"},
		{"no check", []ledger.Field{{Key: "desired", Value: "running"}, {Key: "check_param", Value: net1}},
			"does not say what check"},
		{"an unknown check kind", []ledger.Field{{Key: "desired", Value: "running"}, {Key: "check", Value: "reachable"}, {Key: "check_param", Value: net1}},
			"not a kind this core defines"},
		{"no check parameter", []ledger.Field{{Key: "desired", Value: "running"}, {Key: "check", Value: "alias"}},
			"names nothing to verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, objs, mut, _, st, d := fixture(t)
			if err := intent.Open(l, prov.ClassContainer, c1, "n1", fixedNow, tc.fields...); err != nil {
				t.Fatal(err)
			}
			objs.nets[c1] = []Attachment{attach(net1, "", al1)}
			objs.labels[c1] = ourLabels("n1")
			st.down(c1)
			err := Recover(ctx, l, d, c1, net1, al1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal: %v", err)
			}
			// PRESERVED: nothing confirmed, nothing removed, nothing recorded.
			if _, ferr := intent.Find(l, prov.ClassContainer, c1); ferr != nil {
				t.Fatal("the intent was consumed")
			}
			if len(mut.removed) != 0 {
				t.Fatal("the container was removed")
			}
			if _, serr := state.DesiredGet(l, c1); !errors.Is(serr, ledger.ErrAbsentRecord) {
				t.Fatal("desired state was recorded")
			}
		})
	}

	// A DIFFERENT NETWORK is two different bring-ups: nothing is confirmed, removed or recorded.
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net2, []Attachment{attach(net1, "", al1)})
	err := Recover(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "two different bring-ups") {
		t.Fatalf("wrong network: %v", err)
	}
	if len(mut.removed) != 0 {
		t.Fatal("a container was removed over a network mismatch")
	}
	if _, ferr := intent.Find(l, prov.ClassContainer, c1); ferr != nil {
		t.Fatal("the intent was consumed")
	}
}

func TestRecoverWrongTopology(t *testing.T) {
	ctx := context.Background()
	// CREATED BUT WRONG: removed and reissued — a confirmed-but-detached container is a state this
	// sequence must never produce.
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net3, "", al1)})
	err := Recover(ctx, l, d, c1, net1, al1)
	if !errors.Is(err, ErrRebuild) {
		t.Fatalf("a wrong topology did not ask for a rebuild: %v", err)
	}
	if len(mut.removed) != 1 {
		t.Fatalf("the mis-attached container was not removed: %v", mut.removed)
	}
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a mis-attached container was confirmed")
	}

	// AND AN ABSENT container retains the intent for the verb that holds the launch spec.
	l2, _, mut2, _, _, d2 := fixture(t)
	// The intent exists and the container does NOT: nothing is registered with the runtime fake,
	// so the observed state is absent — the crash-before-create window.
	if err := intent.Open(l2, prov.ClassContainer, c1, "n1", fixedNow,
		ledger.Field{Key: "desired", Value: "running"},
		ledger.Field{Key: "check", Value: "alias"},
		ledger.Field{Key: "check_param", Value: net1}); err != nil {
		t.Fatal(err)
	}
	err = Recover(ctx, l2, d2, c1, net1, al1)
	if !errors.Is(err, ErrRetained) {
		t.Fatalf("an absent container did not retain the intent: %v", err)
	}
	if len(mut2.removed) != 0 {
		t.Fatal("something was removed for an absent container")
	}
	if _, ferr := intent.Find(l2, prov.ClassContainer, c1); ferr != nil {
		t.Fatal("the intent was consumed")
	}
}

// A FOREIGN CONTAINER CARRYING OUR NONCE IS NEITHER CONFIRMED NOR REMOVED — the finding this pair
// closes. A nonce says WHICH object, never WHOSE: anyone able to reach this daemon can put our
// nonce on a container of theirs at the name we derive. Judging ownership on the nonce alone let
// this installation adopt and then drive that container when its topology happened to verify, and
// DELETE it when it did not. The installation label is the only thing that answers WHOSE, and it is
// read first.
func TestRunRefusesAForeignContainerCarryingOurNonce(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	// The topology VERIFIES. Only the installation label says this is not ours, which is precisely
	// the case a nonce comparison cannot see.
	lau.after = func() {
		objs.labels[c1] = map[string]string{prov.LabelInstall: "i09999999999", prov.LabelNonce: "n1"}
	}
	err := Run(ctx, l, d, lau, c1, net1, al1, Running)
	if err == nil {
		t.Fatal("a container belonging to another installation was accepted")
	}
	if !strings.Contains(err.Error(), "another installation's container") {
		t.Fatalf("the refusal did not name the reason: %v", err)
	}
	if len(mut.removed) != 0 {
		t.Fatalf("another installation's container was REMOVED: %v", mut.removed)
	}
	if len(mut.started) != 0 {
		t.Fatalf("another installation's container was STARTED: %v", mut.started)
	}
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("another installation's container was confirmed into our provenance")
	}
}

func TestRecoverRefusesAForeignContainerCarryingOurNonce(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
	// Ours by nonce, another installation's by label — and its topology verifies, so nothing else
	// in the sequence would stop it.
	objs.labels[c1] = map[string]string{prov.LabelInstall: "i09999999999", prov.LabelNonce: "n1"}
	err := Recover(ctx, l, d, c1, net1, al1)
	if err == nil {
		t.Fatal("a container belonging to another installation was adopted")
	}
	if !strings.Contains(err.Error(), "another installation's container") {
		t.Fatalf("the refusal did not name the reason: %v", err)
	}
	if len(mut.removed) != 0 {
		t.Fatalf("another installation's container was REMOVED: %v", mut.removed)
	}
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("another installation's container was confirmed into our provenance")
	}
	if _, ferr := intent.Find(l, prov.ClassContainer, c1); ferr != nil {
		t.Fatal("the intent was consumed on evidence that proved nothing")
	}
}

// AN UNLABELLED CONTAINER IS NOT OURS EITHER. No label proves it is ours, and no provenance proves
// it is not someone else's, so it is reported rather than adopted or deleted.
func TestRecoverRefusesAnUnlabelledContainerCarryingOurNonce(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
	objs.labels[c1] = map[string]string{prov.LabelNonce: "n1"}
	err := Recover(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "NO installation label") {
		t.Fatalf("unlabelled container: %v", err)
	}
	if len(mut.removed) != 0 {
		t.Fatalf("an unattributed container was REMOVED: %v", mut.removed)
	}
}

// THE CONFIRMATION TRANSACTION IS ALL-OR-NOTHING. The desired state, the owed check and the
// provenance record are committed and the intent consumed as ONE staged edit, persisted before it
// is published. Editing the caller's ledger and persisting afterwards was the defect: a write that
// failed left the caller holding provenance, desired state and no intent, while disk still carried
// the open intent — the two disagreeing about whether the container was ever built, in the
// direction that makes the container look accounted for when it is not.
func TestRunLeavesTheLedgerUntouchedWhenTheConfirmationCannotBePersisted(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	// Fail the write that carries the confirmation, and ONLY that one — the write-ahead barriers
	// before it must still succeed, or this would be testing a bring-up that never got started.
	dk := &disk{}
	inner := dk.persist()
	// The predicate has to name the OBJECT row, not the key: an intent row is keyed
	// container:<name> too, so matching the key alone fails the very first write-ahead barrier and
	// the test would be asserting against a bring-up that never opened an intent at all.
	d.Persist = func(cl *ledger.Ledger) error {
		for _, ln := range cl.Lines() {
			if strings.HasPrefix(ln, "object\t") && strings.Contains(ln, "key=container:"+c1) {
				return errors.New("disk full")
			}
		}
		return inner(cl)
	}
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	err := Run(ctx, l, d, lau, c1, net1, al1, Running)
	if err == nil {
		t.Fatal("expected the persist failure to refuse the bring-up")
	}
	if !strings.Contains(err.Error(), "could not be persisted") {
		t.Fatalf("message: %v", err)
	}
	// NOTHING of the transaction may have landed in the caller's ledger.
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("provenance was published for a confirmation that was never persisted")
	}
	if _, derr := state.DesiredGet(l, c1); !errors.Is(derr, ledger.ErrAbsentRecord) {
		t.Fatal("desired state was published for a confirmation that was never persisted")
	}
	// And the intent — the thing that says a bring-up is unfinished — must SURVIVE.
	if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
		t.Fatalf("the intent was consumed by a transaction that never reached disk: %v", ierr)
	}
	// The container was started by nothing: the start comes after the transaction.
	if len(mut.started) != 0 {
		t.Fatalf("a container was started on a record that never reached disk: %v", mut.started)
	}
}

// RECOVERY'S TRANSACTION IS ALL-OR-NOTHING TOO, and unlike Run's it is not protected by a persist
// barrier: Recover mutates the in-memory ledger and its CALLER writes that ledger once. So what it
// owes is that a refusal leaves the caller's ledger byte-identical. Committing straight into it
// meant a Confirm that refused left the desired state and the owed check behind — a recovery that
// reported failure having already half-finished the intent it was recovering, after which the next
// run reads a container with desired state, no provenance, and an intent still open.
//
// The refusal is provoked with two tombstones for the one key. Confirm asks that cardinality
// question deliberately BEFORE it rewrites the object record, so it is a refusal that arrives
// after state.Commit has already succeeded — precisely the ordering this asserts.
func TestRecoverLeavesTheLedgerUntouchedWhenTheConfirmationRefuses(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
	objs.labels[c1] = ourLabels("n1")
	for i := 0; i < 2; i++ {
		if err := l.Append("tombstone", []ledger.Field{
			{Key: "key", Value: "container:" + c1},
			{Key: "class", Value: "container"},
			{Key: "name", Value: c1},
			{Key: "nonce", Value: "n1"},
			{Key: "gen", Value: "1"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	before := strings.Join(l.Lines(), "\n")
	err := Recover(ctx, l, d, c1, net1, al1)
	if err == nil {
		t.Fatal("the confirmation was expected to refuse on contradictory tombstones")
	}
	// THE WHOLE LEDGER, byte for byte. Asserting only that desired state is absent would pass a
	// version that committed something else instead.
	if after := strings.Join(l.Lines(), "\n"); after != before {
		t.Fatalf("a refused recovery changed the ledger:\n before: %s\n after:  %s", before, after)
	}
	if len(mut.removed) != 0 {
		t.Fatalf("a refused recovery removed a container: %v", mut.removed)
	}
}

func TestRecoverWrongNonce(t *testing.T) {
	ctx := context.Background()
	// A CONTAINER STANDING AT THE NAME UNDER A DIFFERENT NONCE is NOT adopted and NOT removed.
	l, objs, mut, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
	objs.labels[c1] = ourLabels("someone-elses")
	err := Recover(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "NOT confirmed") || !strings.Contains(err.Error(), "NOT removed") {
		t.Fatalf("wrong nonce: %v", err)
	}
	if !strings.Contains(err.Error(), "carries nonce \"someone-elses\"") {
		t.Fatalf("the refusal did not name the nonce it saw: %v", err)
	}
	if len(mut.removed) != 0 {
		t.Fatalf("another installation's container was removed: %v", mut.removed)
	}
	if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatal("a foreign container was confirmed")
	}
	// A nonce that could not be READ is not a mismatch either — nothing is established.
	l2, objs2, mut2, _, st2, d2 := fixture(t)
	crashedAfterCreate(t, l2, objs2, st2, state.Running, net1, []Attachment{attach(net1, "", al1)})
	delete(objs2.labels, c1)
	err = Recover(ctx, l2, d2, c1, net1, al1)
	if err == nil {
		t.Fatal("an unreadable nonce was treated as a match")
	}
	if len(mut2.removed) != 0 {
		t.Fatal("a container was removed on an unanswered question")
	}
}

// --- reconciliation ---------------------------------------------------------------------------

func TestReconcileResumesOnce(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, pr, st, d := fixture(t)
	if err := state.Commit(l, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	st.down(c1)
	// The container does not stay up: it is started, and it is still down afterwards.
	err := Reconcile(ctx, l, d, c1, net1, al1)
	if err == nil {
		t.Fatal("a container that did not come up reported success")
	}
	if len(mut.started) != 1 {
		t.Fatalf("started %d times", len(mut.started))
	}
	// THE ATTEMPT IS RECORDED, so the next pass reports rather than starting again — restarting on
	// every pass is the loop the record exists to stop.
	err = Reconcile(ctx, l, d, c1, net1, al1)
	if err == nil || !strings.Contains(err.Error(), "ALREADY resumed it") {
		t.Fatalf("second pass: %v", err)
	}
	if len(mut.started) != 1 {
		t.Fatalf("a second start was attempted: %d", len(mut.started))
	}
	// RE-STATING THE INTENT GRANTS A FRESH ATTEMPT.
	if err := state.Commit(l, c1, state.Running, nil, false); err != nil {
		t.Fatal(err)
	}
	mut.onStart = func() { st.up(c1) }
	pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
	if err := Reconcile(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a fresh intent did not grant a fresh attempt: %v", err)
	}
	if len(mut.started) != 2 {
		t.Fatalf("started %d times", len(mut.started))
	}
	// And a passing verification clears the check.
	out, _ := state.Outstanding(l, c1)
	if len(out) != 0 {
		t.Fatalf("the check was not cleared: %+v", out)
	}
}

func TestReconcileVerifiesNow(t *testing.T) {
	ctx := context.Background()
	// A RUNNING container with an outstanding check is verified NOW, not at some future start.
	l, objs, mut, pr, st, d := fixture(t)
	if err := state.Commit(l, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	st.up(c1)
	pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
	if err := Reconcile(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
	if len(mut.started) != 0 {
		t.Fatal("a running container was started to verify it")
	}
	out, _ := state.Outstanding(l, c1)
	if len(out) != 0 {
		t.Fatalf("the entry did not clear: %+v", out)
	}
	// A FAILING re-verification leaves it running and still outstanding, reported once.
	l2, objs2, mut2, _, st2, d2 := fixture(t)
	if err := state.Commit(l2, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs2.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	st2.up(c1)
	if err := Reconcile(ctx, l2, d2, c1, net1, al1); err == nil {
		t.Fatal("a failing verification reported success")
	}
	if len(mut2.stopped) != 0 {
		t.Fatal("a failing verification stopped a running container")
	}
	out, _ = state.Outstanding(l2, c1)
	if len(out) != 1 {
		t.Fatalf("the entry was cleared despite failing: %+v", out)
	}
}

func TestReconcileDefers(t *testing.T) {
	ctx := context.Background()
	// A STOPPED container with an outstanding check is DEFERRED, never cleared: it has no address
	// for its alias to answer with.
	l, objs, mut, _, st, d := fixture(t)
	if err := state.Commit(l, c1, state.Stopped, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = []Attachment{attach(net1, "", al1)}
	st.down(c1)
	if err := Reconcile(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("a deferred check was reported as a failure: %v", err)
	}
	if len(mut.started) != 0 {
		t.Fatal("a stopped container was started to perform a deferred check")
	}
	out, _ := state.Outstanding(l, c1)
	if len(out) != 1 {
		t.Fatalf("a deferred check was cleared: %+v", out)
	}
	// A container a MIGRATION governs is suspended, not restarted.
	l2, objs2, mut2, _, st2, d2 := fixture(t)
	if err := state.Commit(l2, c1, state.Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := intent.Open(l2, prov.ClassContainer, c1, "n9", fixedNow); err != nil {
		t.Fatal(err)
	}
	objs2.nets[c1] = []Attachment{attach(net1, "", al1)}
	st2.down(c1)
	if err := Reconcile(ctx, l2, d2, c1, net1, al1); err != nil {
		t.Fatalf("a suspended container was reported as a failure: %v", err)
	}
	if len(mut2.started) != 0 {
		t.Fatal("the reconciler started a container an intent governs")
	}
}

func TestGenericReconcilerRefusesContainers(t *testing.T) {
	ctx := context.Background()
	// THE GENERIC INTENT RECONCILER REFUSES A CONTAINER INTENT instead of finishing it: it would
	// confirm the object and drop the intent, leaving the container accounted for, with no desired
	// state, never started and never verified. This package's Recover is what finishes one.
	l, objs, _, _, st, d := fixture(t)
	crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
	err := intent.Reconcile(ctx, l, nil, nil, prov.ClassContainer, c1)
	if err == nil || !strings.Contains(err.Error(), "bring-up recovery path") {
		t.Fatalf("the generic reconciler accepted a container intent: %v", err)
	}
	if _, ferr := intent.Find(l, prov.ClassContainer, c1); ferr != nil {
		t.Fatal("the generic reconciler consumed a container intent")
	}
	// And THIS package's recovery does finish it.
	if err := Recover(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatalf("bring-up recovery: %v", err)
	}
}

// --- durability across a crash --------------------------------------------------------------------

// disk models the persisted ledger. Persist snapshots the in-memory body; reload builds a fresh
// Ledger from that snapshot — which is what a later process sees. The earlier tests in this file
// reuse ONE in-memory ledger throughout, so they cannot tell a record that was persisted from one
// that merely exists in memory; that is the distinction these cases exist to make.
type disk struct {
	lines  []string
	writes int
	err    error
}

func (dk *disk) persist() func(*ledger.Ledger) error {
	return func(l *ledger.Ledger) error {
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

func TestIntentIsDurableBeforeTheContainerExists(t *testing.T) {
	ctx := context.Background()
	l, objs, _, _, st, d := fixture(t)
	dk := &disk{}
	d.Persist = dk.persist()

	// THE CRASH: the daemon accepts the create, and the process dies before anything else. What a
	// later run can do about the container depends entirely on what was on DISK AT THAT INSTANT —
	// so the snapshot is taken as the launcher is entered, not after it returns. Reading disk
	// afterwards cannot distinguish "written before the create" from "written after it", which is
	// exactly the ordering under test.
	var atCreate []string
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	lau.atEntry = func() { atCreate = append([]string(nil), dk.lines...) }

	if _, err := Create(ctx, l, d, lau, c1, net1, state.Running); err != nil {
		t.Fatal(err)
	}
	if lau.calls != 1 {
		t.Fatal("the launcher never ran, so this proves nothing about the order")
	}
	reloaded := &ledger.Ledger{}
	reloaded.ReplaceLines(atCreate)
	rec, err := intent.Find(reloaded, prov.ClassContainer, c1)
	if err != nil {
		t.Fatalf("the container was created with no durable intent — nothing could account for it: %v", err)
	}
	// And it carries what recovery needs: the nonce, the desired state, and the owed check.
	for _, w := range []struct{ k, v string }{{"nonce", "n1"}, {"desired", "running"}, {"check", "alias"}, {"check_param", net1}} {
		if got, ok := ledger.FieldOf(rec, w.k); !ok || got != w.v {
			t.Errorf("durable intent %s = %q (present=%v), want %q", w.k, got, ok, w.v)
		}
	}
	// Recovery on a FRESH ledger read back from disk finishes the bring-up.
	if err := Recover(ctx, reloaded, d, c1, net1, al1); err != nil {
		t.Fatalf("recovery from the durable intent failed: %v", err)
	}
}

func TestNoRuntimeMutationWithoutADurableRecord(t *testing.T) {
	ctx := context.Background()
	// A PERSIST THAT FAILS STOPS THE OPERATION. Proceeding would create exactly the unaccounted
	// object the record exists to prevent, and the failure would be invisible until a crash.
	l, objs, mut, _, st, d := fixture(t)
	dk := &disk{err: errors.New("disk full")}
	d.Persist = dk.persist()
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	if _, err := Create(ctx, l, d, lau, c1, net1, state.Running); err == nil {
		t.Fatal("a container was created with an unpersistable intent")
	}
	if lau.calls != 0 {
		t.Fatal("the launcher ran despite the record not being durable")
	}
	// AND THE FAILED WRITE LEFT NOTHING BEHIND IN MEMORY. An intent staged in the caller's ledger
	// behind an error saying nothing was done is a record for an object that was never created —
	// and under D38-style rules a retry would then refuse, wedged behind its own debris.
	if _, ferr := intent.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
		t.Fatalf("a failed persist left an intent in the caller's ledger: %v", ferr)
	}

	// A MISSING Persist is refused, not skipped — skipping would restore the defect invisibly.
	l2, objs2, _, _, st2, d2 := fixture(t)
	d2.Persist = nil
	lau2 := &fakeLauncher{objs: objs2, st: st2, nets: []Attachment{attach(net1, "", al1)}}
	err := Run(ctx, l2, d2, lau2, c1, net1, al1, Running)
	if err == nil || !strings.Contains(err.Error(), "no way to persist") {
		t.Fatalf("a bring-up with no persistence seam: %v", err)
	}
	if lau2.calls != 0 {
		t.Fatal("the launcher ran with no persistence seam")
	}
	_ = mut
}

func TestResumeAttemptIsDurableBeforeTheStart(t *testing.T) {
	ctx := context.Background()
	// A crash between recording the attempt and making it would leave the next run believing it
	// had never tried — the restart loop the record exists to stop, reinstated by the very crash
	// it was meant to survive.
	l, objs, mut, _, st, d := fixture(t)
	dk := &disk{}
	d.Persist = dk.persist()
	if err := state.Commit(l, c1, state.Running, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
	st.down(c1)
	// Snapshot disk AT THE START CALL — the instant the container is asked to run. Reading after
	// the call returns cannot tell whether the marker was written before or after it.
	var atStart []string
	mut.atStartEntry = func() { atStart = append([]string(nil), dk.lines...) }
	if err := Reconcile(ctx, l, d, c1, net1, al1); err == nil {
		t.Fatal("a container that did not come up reported success")
	}
	if len(mut.started) != 1 {
		t.Fatalf("started %d times", len(mut.started))
	}
	// A LATER RUN, reading only what was on disk when the start was issued, must see the attempt.
	reloaded := &ledger.Ledger{}
	reloaded.ReplaceLines(atStart)
	plan, err := state.PlanFor(ctx, reloaded, st, c1)
	if err != nil {
		t.Fatal(err)
	}
	if plan != state.PlanExited {
		t.Fatalf("plan after a crash-following-start = %q, want exited — the attempt was not durable", plan)
	}
}

func TestVerifierUsesThePassedLedger(t *testing.T) {
	ctx := context.Background()
	// THE SEAM MUST READ THE LEDGER IT IS HANDED, not one it captured. bring-up's exact-set check
	// consults the migration record to decide the permitted set, so a verifier answering from a
	// stale ledger would verify against stale migration bounds while the phase advances a fresh
	// one — the mismatch the adapter exists to prevent, reintroduced by the adapter itself.
	//
	// The instrument: a container legitimately on BOTH networks. Against a ledger that RECORDS the
	// migration that is correct; against an empty one it is a stray attachment. So the verdict
	// says which ledger was actually read.
	_, objs, _, _, _, d := fixture(t)
	objs.nets[c1] = []Attachment{attach(net2, "10.0.1.2", al1), attach(net1, "10.0.0.2", al1)}

	withMig := &ledger.Ledger{}
	recordMigration(t, withMig, net2, net1)
	v := Verifier{D: d}
	if err := v.VerifyAttach(ctx, withMig, c1, net1, al1); err != nil {
		t.Fatalf("the verifier refused against the ledger recording the migration: %v", err)
	}
	// And handed a ledger with NO migration, the same container must fail — proving the answer
	// came from the argument.
	if err := v.VerifyAttach(ctx, &ledger.Ledger{}, c1, net1, al1); err == nil {
		t.Fatal("the verifier answered from something other than the ledger it was handed")
	}
}

// TestReconcilerSaysWhyItDidNothing pins the reconciler's two informational verdicts.
//
// BOTH ARE THE RECONCILER DECLINING TO ACT, and that is exactly why they are said out loud: an
// operator watching a pass do nothing cannot tell "deliberately suspended by a migration" or
// "deferred until the container starts" from "the reconciler never looked at it". The reference
// printed both; this port carried the behaviour and left the words in a comment, which makes the
// replacement quieter than the thing it replaces at the two moments quiet is most easily misread.
func TestReconcilerSaysWhyItDidNothing(t *testing.T) {
	ctx := context.Background()

	// Deferred: stopped, with a verification outstanding.
	l, objs, _, _, st, d := fixture(t)
	var said []string
	d.Note = func(s string) { said = append(said, s) }
	if err := state.Commit(l, c1, state.Stopped, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs.nets[c1] = []Attachment{attach(net1, "", al1)}
	st.down(c1)
	if err := Reconcile(ctx, l, d, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
	if j := strings.Join(said, "\n"); !strings.Contains(j, "stopped with a verification outstanding") ||
		!strings.Contains(j, "performed at its next start") {
		t.Fatalf("the deferred verdict was silent or incomplete: %q", said)
	}

	// Suspended: a migration intent governs it.
	l2, objs2, _, _, st2, d2 := fixture(t)
	said = nil
	d2.Note = func(s string) { said = append(said, s) }
	if err := state.Commit(l2, c1, state.Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := intent.Open(l2, prov.ClassContainer, c1, "n9", fixedNow); err != nil {
		t.Fatal(err)
	}
	objs2.nets[c1] = []Attachment{attach(net1, "", al1)}
	st2.down(c1)
	if err := Reconcile(ctx, l2, d2, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
	if j := strings.Join(said, "\n"); !strings.Contains(j, "is suspended") ||
		!strings.Contains(j, "must not restart a container a") {
		t.Fatalf("the suspended verdict was silent or incomplete: %q", said)
	}

	// A verdict with NOTHING TO SAY says nothing. These two lines exist because the reconciler
	// declined to act for a reason; a note on every pass would make them noise and stop being read.
	l3, objs3, _, _, st3, d3 := fixture(t)
	said = nil
	d3.Note = func(s string) { said = append(said, s) }
	objs3.nets[c1] = []Attachment{attach(net1, "10.0.0.9", al1)}
	st3.up(c1)
	if err := state.Commit(l3, c1, state.Running, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, l3, d3, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
	if len(said) != 0 {
		t.Fatalf("a reconcile with nothing outstanding printed a did-nothing note: %q", said)
	}

	// A nil Note is a caller with nowhere to write, not a crash.
	l4, objs4, _, _, st4, d4 := fixture(t)
	if err := state.Commit(l4, c1, state.Stopped, []state.Check{{Kind: state.CheckAlias, Param: net1}}, false); err != nil {
		t.Fatal(err)
	}
	objs4.nets[c1] = []Attachment{attach(net1, "", al1)}
	st4.down(c1)
	if err := Reconcile(ctx, l4, d4, c1, net1, al1); err != nil {
		t.Fatal(err)
	}
}

// --- a removal that was REFUSED, and a confirmation with no image identity ----------------------

// removalAnswers is the THREE facts a removal's answer can establish, which is the correction the
// first version of this fix needed: it treated every non-nil error as "the container is still
// there". The engine splits them at the source — a 404 is an ANSWER from a daemon that is up, a
// transport failure is no answer at all — and conflating them puts back the same wrong-answer
// defect the fix exists to remove, facing the other way: an operator sent to hunt a container that
// does not exist, and (in Recover) a rebuild withheld from a name that is free.
var removalAnswers = []struct {
	name string
	err  error
	// refused — the daemon answered and the removal did not succeed. The report must say the
	// removal FAILED, and must not assert that the container is or is not there.
	refused bool
	// unknown — the report must say nothing was established.
	unknown bool
	// rebuild — Recover may ask for a rebuild (the name is provably free).
	rebuild bool
}{
	{"removed", nil, false, false, true},
	{"already absent (404)", fmt.Errorf("engine: %w: No such container", engine.ErrAbsent), false, false, true},
	{"refused by the daemon", errors.New("container is in use by a running task"), true, false, false},
	{"a server error", errors.New("engine: 500 Internal Server Error"), true, false, false},
	{"the daemon did not answer", fmt.Errorf("engine: %w: dial unix: connection refused", engine.ErrDaemonDown), false, true, false},
}

// TestRunReportsWhatTheRemovalActuallyEstablished: the removal's status is the operator's whole
// picture.
//
// Both removal sites used to read `_ = d.Mut.ContainerRemove(ctx, container)` with the NEXT LINE
// telling the operator the container was removed. A daemon that refused the removal therefore
// produced "removed %q" about an object that is still standing, under this installation's labels,
// at this installation's derived name. An operator told a container was removed has no reason to
// look for it — so the object outlives the run, invisible, and the next bring-up meets it as a
// same-name survivor for reasons nothing in the transcript explains.
func TestRunReportsWhatTheRemovalActuallyEstablished(t *testing.T) {
	ctx := context.Background()
	for _, tc := range removalAnswers {
		t.Run(tc.name, func(t *testing.T) {
			l, objs, mut, _, st, d := fixture(t)
			mut.removeErr = tc.err
			lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net3, "", al1)}} // wrong network
			err := Run(ctx, l, d, lau, c1, net1, al1, Running)
			if err == nil {
				t.Fatal("a bring-up onto the wrong network reported success")
			}
			// IT WAS ASKED — the fix is checking the answer, not skipping the attempt.
			if len(mut.removed) != 1 || mut.removed[0] != c1 {
				t.Fatalf("the removal was not attempted: %v", mut.removed)
			}
			says := func(needle string) bool { return strings.Contains(err.Error(), needle) }
			switch {
			case tc.refused:
				for _, want := range []string{"REMOVING IT DID NOT SUCCEED", "NOT\n  established", "ASK THE CONTAINER RUNTIME"} {
					if !says(want) {
						t.Fatalf("the report does not say %q:\n%v", want, err)
					}
				}
				if says("removed \"") {
					t.Fatalf("a container that was NOT removed was reported as removed:\n%v", err)
				}
				// AND IT DOES NOT ASSERT PRESENCE. A 5xx can follow a partial removal, so
				// "it is STILL THERE" is a fact the answer does not carry.
				if says("STILL THERE") {
					t.Fatalf("a failed removal asserted the container is still there:\n%v", err)
				}
			case tc.unknown:
				if !says("WHETHER IT WAS REMOVED IS UNKNOWN") {
					t.Fatalf("an unanswered removal was not reported as unknown:\n%v", err)
				}
				// AND NOT AS EITHER SETTLED FACT. "still there" and "removed" are both claims
				// nothing measured when the runtime never answered.
				if says("STILL THERE") || says("removed \"") {
					t.Fatalf("an unanswered removal was reported as a settled fact:\n%v", err)
				}
			default:
				if !says("removed \"") {
					t.Fatalf("a container that IS gone was not reported as removed:\n%v", err)
				}
				if says("STILL THERE") || says("UNKNOWN") {
					t.Fatalf("a container that is provably gone was reported as present or unknown:\n%v", err)
				}
			}
			// The verification failure that prompted the removal is reported ALONGSIDE it in every
			// case, never replaced by it: an operator needs both facts to know what to do next.
			if !says("not permitted") {
				t.Fatalf("the report drops the verification failure that prompted the removal:\n%v", err)
			}
			// And nothing was confirmed, while the write-ahead intent is kept.
			if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
				t.Fatal("provenance was confirmed for a container that did not verify")
			}
			if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
				t.Fatalf("the write-ahead intent was consumed: %v", ierr)
			}
			if len(mut.started) != 0 {
				t.Fatalf("an unverified container was started: %v", mut.started)
			}
		})
	}
}

// TestRecoverReportsWhatTheRemovalActuallyEstablished is the same three facts on the recovery path,
// plus the consequence specific to it: the caller acts on ErrRebuild by RE-CREATING the container
// from its launch spec, under the same derived name. So the rebuild may be asked for ONLY when that
// name is provably free — not when the daemon refused the removal (the name is held), and not when
// the daemon never answered (whether it is held was never established).
func TestRecoverReportsWhatTheRemovalActuallyEstablished(t *testing.T) {
	ctx := context.Background()
	for _, tc := range removalAnswers {
		t.Run(tc.name, func(t *testing.T) {
			l, objs, mut, _, st, d := fixture(t)
			mut.removeErr = tc.err
			crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net3, "", al1)})
			err := Recover(ctx, l, d, c1, net1, al1)
			if err == nil {
				t.Fatal("a recovery of a mis-attached container reported success")
			}
			if len(mut.removed) != 1 {
				t.Fatalf("the removal was not attempted: %v", mut.removed)
			}
			if got := errors.Is(err, ErrRebuild); got != tc.rebuild {
				t.Fatalf("ErrRebuild = %v, want %v — a rebuild re-creates under a name this container may\n"+
					"still hold, so it may only be asked for when the name is provably free:\n%v", got, tc.rebuild, err)
			}
			says := func(needle string) bool { return strings.Contains(err.Error(), needle) }
			switch {
			case tc.refused:
				for _, want := range []string{"REMOVING IT DID NOT SUCCEED", "was NOT established", "same-name survivor"} {
					if !says(want) {
						t.Fatalf("the report does not say %q:\n%v", want, err)
					}
				}
				if says("STILL THERE") {
					t.Fatalf("a failed removal asserted the container is still there:\n%v", err)
				}
			case tc.unknown:
				if !says("WHETHER IT WAS REMOVED IS UNKNOWN") || !says("never established") {
					t.Fatalf("an unanswered removal was not reported as unknown:\n%v", err)
				}
				if says("STILL THERE") {
					t.Fatalf("an unanswered removal was reported as a settled fact:\n%v", err)
				}
			default:
				if !says("removed \"") || says("STILL THERE") || says("UNKNOWN") {
					t.Fatalf("a container that is provably gone was not reported as removed:\n%v", err)
				}
			}
			if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
				t.Fatal("provenance was confirmed for a container that did not verify")
			}
			if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
				t.Fatalf("the intent was consumed by a recovery that confirmed nothing: %v", ierr)
			}
		})
	}
}

// imageUnknown is the two ways the image identity can fail to arrive. They are DIFFERENT FACTS —
// a failed question and an empty answer — and each has to refuse on its own.
var imageUnknown = []struct {
	name  string
	arm   func(objs *fakeObjs)
	wants []string
}{
	{"the inspection failed", func(objs *fakeObjs) {
		objs.imageErr[c1] = errors.New("inspect: connection reset")
	}, []string{"could not be read", "connection reset"}},
	{"the runtime reports no image", func(objs *fakeObjs) {
		objs.image[c1] = ""
	}, []string{"NO image"}},
}

// TestRunRefusesToConfirmWithoutAnImageIdentity: `image, _ := d.Objs.Image(...)` discarded the
// error and then wrote `id=<image>` into the provenance record and CONSUMED the intent — in one
// transaction, reported as success. So a failed inspection produced a confirmed container record
// carrying no image identity, and the one thing on disk that would have said this bring-up never
// finished was gone. Nothing afterwards can tell that record from a good one.
//
// The refusal is made BEFORE the staged transaction, which is what makes it free: staged() edits a
// clone and publishes only after the write succeeds, so refusing ahead of it leaves the caller's
// ledger byte-identical and the intent open — exactly the state Recover is written for.
func TestRunRefusesToConfirmWithoutAnImageIdentity(t *testing.T) {
	ctx := context.Background()
	for _, tc := range imageUnknown {
		t.Run(tc.name, func(t *testing.T) {
			l, objs, mut, pr, st, d := fixture(t)
			dk := &disk{}
			d.Persist = dk.persist()
			lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
			pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
			// The launcher sets a good image; the arm removes it AFTER the create, which is when
			// the inspection actually happens.
			lau.after = func() { tc.arm(objs) }

			err := Run(ctx, l, d, lau, c1, net1, al1, Running)
			if err == nil {
				t.Fatal("a bring-up confirmed provenance with no image identity")
			}
			for _, want := range append(tc.wants, "The intent is KEPT") {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not say %q:\n%v", want, err)
				}
			}
			if len(mut.started) != 0 {
				t.Fatalf("an unconfirmed container was started: %v", mut.started)
			}
			// IN MEMORY: nothing confirmed, the intent still open.
			if _, ferr := prov.Find(l, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
				t.Fatal("provenance was confirmed without an image identity")
			}
			if _, serr := state.DesiredGet(l, c1); !errors.Is(serr, ledger.ErrAbsentRecord) {
				t.Fatal("desired state was committed by a refused confirmation")
			}
			if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
				t.Fatalf("the intent was consumed by a refused confirmation: %v", ierr)
			}
			// AND ON DISK: the last thing persisted is still the write-ahead intent — the
			// confirmation transaction never ran, so the record a recovery reads is intact.
			back := dk.reload()
			if _, ierr := intent.Find(back, prov.ClassContainer, c1); ierr != nil {
				t.Fatalf("the persisted intent is gone, so nothing can recover this bring-up: %v", ierr)
			}
			if _, ferr := prov.Find(back, prov.ClassContainer, c1); !errors.Is(ferr, ledger.ErrAbsentRecord) {
				t.Fatal("a confirmation with no image identity reached disk")
			}
		})
	}
}

// TestRecoverRefusesToConfirmWithoutAnImageIdentity is the same refusal on the recovery path. What
// it owes additionally is Recover's own contract: it does not persist, so a refusal must leave the
// caller's ledger BYTE-IDENTICAL to what it was handed.
func TestRecoverRefusesToConfirmWithoutAnImageIdentity(t *testing.T) {
	ctx := context.Background()
	for _, tc := range imageUnknown {
		t.Run(tc.name, func(t *testing.T) {
			l, objs, mut, _, st, d := fixture(t)
			crashedAfterCreate(t, l, objs, st, state.Running, net1, []Attachment{attach(net1, "", al1)})
			tc.arm(objs)
			before := strings.Join(l.Lines(), "\n")

			err := Recover(ctx, l, d, c1, net1, al1)
			if err == nil {
				t.Fatal("a recovery confirmed provenance with no image identity")
			}
			for _, want := range append(tc.wants, "The intent is KEPT") {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not say %q:\n%v", want, err)
				}
			}
			if len(mut.removed) != 0 {
				t.Fatalf("a container was removed by a refusal about its image: %v", mut.removed)
			}
			if got := strings.Join(l.Lines(), "\n"); got != before {
				t.Fatalf("a refused recovery changed the caller's ledger:\n got %q\nwant %q", got, before)
			}
			if _, ierr := intent.Find(l, prov.ClassContainer, c1); ierr != nil {
				t.Fatalf("the intent was consumed by a refused recovery: %v", ierr)
			}
		})
	}
}

// TestRunConfirmsWithTheImageItRead is the counterpart of the two refusals above: the ordinary path
// must still record the image identity, and record the one the runtime actually reported. A fix
// that refused every bring-up, or one that wrote a constant, would satisfy the refusal tests and
// fail here.
func TestRunConfirmsWithTheImageItRead(t *testing.T) {
	ctx := context.Background()
	l, objs, mut, pr, st, d := fixture(t)
	lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
	mut.onStart = func() {
		objs.nets[c1] = []Attachment{attach(net1, "10.0.0.2", al1)}
		st.up(c1)
	}
	pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
	lau.after = func() { objs.image[c1] = "sha256:the-one-the-runtime-reported" }

	if err := Run(ctx, l, d, lau, c1, net1, al1, Running); err != nil {
		t.Fatalf("an ordinary bring-up failed: %v", err)
	}
	rec, ferr := prov.Find(l, prov.ClassContainer, c1)
	if ferr != nil {
		t.Fatalf("an ordinary bring-up confirmed no provenance: %v", ferr)
	}
	id, ok := ledger.FieldOf(rec, "id")
	if !ok || id != "sha256:the-one-the-runtime-reported" {
		t.Fatalf("the provenance record carries id %q (present=%v), not the image the runtime reported", id, ok)
	}
}

// TestTheImageRefusalRemedyMatchesWhatTheFailureEstablished: the fix for the discarded image error
// prescribed a remedy that asserted a fact of its own — "the container was created and STILL
// STANDS at that name: remove it" — whatever the failure had been.
//
// Production Image is a ContainerInspect, so engine.ErrAbsent here is the daemon ANSWERING that no
// such object exists, and engine.ErrDaemonDown is no answer at all. The first version sent an
// operator to hunt and remove a container the runtime had just said does not exist, and asserted
// presence when nothing had been established: the same wrong-answer defect this change exists to
// remove, committed by the fix for it.
func TestTheImageRefusalRemedyMatchesWhatTheFailureEstablished(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		err      error
		wants    []string
		notWants []string
		// retained — Recover must carry ErrRetained, the answer this function already gives for a
		// container that is not there.
		retained bool
	}{
		{"the container is gone (404)", fmt.Errorf("engine: %w: No such container", engine.ErrAbsent),
			[]string{"GONE from that name", "nothing to remove"},
			[]string{"STILL STANDS", "NOT established"}, true},
		{"the runtime did not answer", fmt.Errorf("engine: %w: connection refused", engine.ErrDaemonDown),
			[]string{"NOT established", "Ask it before re-running"},
			[]string{"STILL STANDS", "GONE from that name"}, false},
		{"the runtime answered with some other failure", errors.New("inspect: 500 Internal Server Error"),
			// A 5xx establishes NEITHER presence nor absence. The first version of this fix said
			// "STILL STANDS" here and this test codified it.
			[]string{"NOT established", "inspection\n  failed"},
			[]string{"GONE from that name", "STILL STANDS"}, false},
		{"the inspection answered and reported NO image", nil,
			// The one branch where presence IS established: the inspect succeeded.
			[]string{"STILL STANDS", "the inspection answered"},
			[]string{"GONE from that name", "NOT established"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// --- Run ---
			l, objs, mut, pr, st, d := fixture(t)
			lau := &fakeLauncher{objs: objs, st: st, nets: []Attachment{attach(net1, "", al1)}}
			pr.resolveTo[net1+"/"+al1] = "10.0.0.2"
			lau.after = func() {
				if tc.err == nil {
					objs.image[c1] = "" // the inspect succeeds and reports no image
					return
				}
				objs.imageErr[c1] = tc.err
			}
			err := Run(ctx, l, d, lau, c1, net1, al1, Running)
			if err == nil {
				t.Fatal("a bring-up confirmed provenance with no image identity")
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("Run: the remedy does not say %q:\n%v", w, err)
				}
			}
			for _, w := range tc.notWants {
				if strings.Contains(err.Error(), w) {
					t.Fatalf("Run: the remedy claims %q, which this failure did not establish:\n%v", w, err)
				}
			}
			if len(mut.started) != 0 {
				t.Fatalf("an unconfirmed container was started: %v", mut.started)
			}

			// --- Recover ---
			l2, objs2, _, _, st2, d2 := fixture(t)
			crashedAfterCreate(t, l2, objs2, st2, state.Running, net1, []Attachment{attach(net1, "", al1)})
			if tc.err == nil {
				objs2.image[c1] = ""
			} else {
				objs2.imageErr[c1] = tc.err
			}
			before := strings.Join(l2.Lines(), "\n")
			rerr := Recover(ctx, l2, d2, c1, net1, al1)
			if rerr == nil {
				t.Fatal("a recovery confirmed provenance with no image identity")
			}
			for _, w := range tc.wants {
				if !strings.Contains(rerr.Error(), w) {
					t.Fatalf("Recover: the remedy does not say %q:\n%v", w, rerr)
				}
			}
			// A CONTAINER THAT IS GONE IS THE CASE THIS FUNCTION ALREADY HAS AN ANSWER FOR: the
			// intent is RETAINED for the verb holding the launch spec. Withholding that signal
			// leaves the caller with a bare failure for a state it knows how to finish.
			if got := errors.Is(rerr, ErrRetained); got != tc.retained {
				t.Fatalf("Recover: ErrRetained = %v, want %v:\n%v", got, tc.retained, rerr)
			}
			// And a refusal still leaves the caller's ledger byte-identical.
			if got := strings.Join(l2.Lines(), "\n"); got != before {
				t.Fatalf("Recover: a refusal changed the caller's ledger")
			}
		})
	}
}
