package verbs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/bringup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// Inventory — Task 24's share is tests/unit/repair.bats WHOLE: all 47 tests, each claimed exactly
// once. Task 24 owns nothing in tests/unit/verbs.bats or tests/acceptance/lifecycle.bats, which is a
// decision internal/verbs/owners.go states and TestOwnerMapPartitionsBats asserts.
//
// Three of the 47 are CLI-surface tests and are claimed in cmd/mythical-ctl/repair_cli_test.go
// beside the dispatcher they exercise; the other forty-four are here.
//
// PORTED: tests/unit/repair.bats: "a NEWER ledger schema is refused, naming the required version (already Plan 1; asserted here)" -> TestNewerLedgerSchemaIsRefusedByTheReader
// PORTED: tests/unit/repair.bats: "a schema migration is a no-op at schema 1 and does not rewrite the ledger" -> TestSchemaMigrateIsANoOpAtSchemaOne
// PORTED: tests/unit/repair.bats: "repair candidates are the DISTINCT installation identities present in object labels" -> TestCandidatesAreTheDistinctIdentities
// PORTED: tests/unit/repair.bats: "EXACTLY ONE candidate is still shown and still confirmed — never silently adopted" -> TestExactlyOneCandidateIsStillShownAndConfirmed
// PORTED: tests/unit/repair.bats: "two candidates: both shown, no action until one is chosen, the other's objects untouched" -> TestTwoCandidatesBothShownNothingTouched
// PORTED: tests/unit/repair.bats: "choosing an identity rebuilds provenance for containers, volumes and networks from labels" -> TestChoosingAnIdentityRebuildsProvenance
// PORTED: tests/unit/repair.bats: "repair NEVER rebuilds image provenance and never claims to enumerate images" -> TestRepairNeverRebuildsImageProvenance
// PORTED: tests/unit/repair.bats: "outstanding checks are initialized to {alias} for EVERY recovered container" -> TestOutstandingInitializedToAliasForEveryContainer
// PORTED: tests/unit/repair.bats: "a RUNNING recovered container is verified IN THE SAME REPAIR RUN" -> TestRunningRecoveredContainerIsVerifiedInTheSameRun
// PORTED: tests/unit/repair.bats: "desired state is set from OBSERVATION and reported as inferred, listing each container" -> TestDesiredStateIsInferredFromObservation
// PORTED: tests/unit/repair.bats: "trust floors are RESET, with the rollback window stated and confirmed" -> TestTrustFloorsAreResetWithTheWindowStated
// PORTED: tests/unit/repair.bats: "ZERO candidates offers confirmed REINITIALIZATION rather than deadlocking" -> TestZeroCandidatesOffersReinitialization
// PORTED: tests/unit/repair.bats: "reinitialization is REFUSED when candidates were found — then the answer is to choose one" -> TestReinitializeRefusedWhenCandidatesExist
// PORTED: tests/unit/repair.bats: "repair refuses while a LIVE lock is held" -> TestRepairRefusesWhileTheLockIsHeld
// PORTED: tests/unit/repair.bats: "repair states plainly that it cannot prove nothing is in flight" -> TestRepairStatesItCannotProveNothingIsInFlight
// PORTED: tests/unit/repair.bats: "an object arriving AFTER a repair that RETAINED the identity is unrecorded same-identity" -> TestLateObjectAfterRetainingRepairIsUnrecorded
// PORTED: tests/unit/repair.bats: "an object arriving after a REINITIALIZING repair is foreign-identity, listed, never touched" -> TestLateObjectAfterReinitializingRepairIsUnattributed
// PORTED: tests/unit/repair.bats: "the non-owned reference is reconstructed from mythical.conf, not from the ledger" -> TestNonOwnedReferenceRebuiltFromConfig
// PORTED: tests/unit/repair.bats: "reconstruction that finds a DIFFERENT network than the containers' stops and enters the migration" -> TestDifferentNetworkEntersTheMigration
// PORTED: tests/unit/repair.bats: "containers disagreeing about their network stops and reports — a migration cannot pick a side" -> TestDisagreeingContainersStopTheReconstruction
// PORTED: tests/unit/repair.bats: "abandon-intent refuses before the grace period and succeeds after, with confirmation" -> TestAbandonIntentRespectsTheGracePeriod
// PORTED: tests/unit/repair.bats: "abandon-intent will NOT run without confirmation" -> TestAbandonIntentRefusesWithoutConfirmation
// PORTED: tests/unit/repair.bats: "candidate discovery FAILS CLOSED when an object's installation label cannot be read" -> TestCandidateDiscoveryFailsClosedOnAnUnreadableLabel
// PORTED: tests/unit/repair.bats: "the post-reset rebuild loop FAILS CLOSED when an object's installation label cannot be read" -> TestRebuildLoopFailsClosedOnAnUnreadableLabel
// PORTED: tests/unit/repair.bats: "network reconstruction FAILS CLOSED when a container's installation label cannot be read" -> TestNetworkReconstructionFailsClosedOnAnUnreadableLabel
// PORTED: tests/unit/repair.bats: "'+none' is never recorded from an unread network-attachment state" -> TestNoneIsNeverRecordedFromAnUnreadAttachment
// PORTED: tests/unit/repair.bats: "net rebind FAILS CLOSED on an unreadable/ambiguous migration record instead of starting fresh" -> TestNetRebindFailsClosedOnAnAmbiguousMigrationRecord
// PORTED: tests/unit/repair.bats: "a ledger with a NEWER schema is refused by repair, never renamed aside as if corrupt" -> TestNewerSchemaLedgerIsNeverRenamedAside
// PORTED: tests/unit/repair.bats: "candidate discovery keeps DISTINCT identities distinct even when one is a prefix of another" -> TestCandidatesKeepPrefixIdentitiesDistinct
// PORTED: tests/unit/repair.bats: "a repair-reconstructed network migration never records an empty fleet" -> TestReconstructedMigrationNeverRecordsAnEmptyFleet
// PORTED: tests/unit/repair.bats: "containers that exist but share no attached network are NOT recorded as a clean reference" -> TestUnattachedContainersAreNotACleanReference
// PORTED: tests/unit/repair.bats: "a real candidate is never treated as zero and silently reinitialized" -> TestARealCandidateIsNeverTreatedAsZero
// PORTED: tests/unit/repair.bats: "a reconstructed migration's fleet list names EVERY container, never a truncated prefix" -> TestReconstructedMigrationNamesEveryContainer
// PORTED: tests/unit/repair.bats: "adoption REFUSES an object whose nonce label is present-but-empty, never writes empty-nonce provenance" -> TestAdoptionRefusesAPresentButEmptyNonce
// PORTED: tests/unit/repair.bats: "the PUBLIC verb rejects a surplus operand itself, at the library boundary, nothing attempted" -> TestStateRepairRejectsASurplusOperand
// PORTED: tests/unit/repair.bats: "an ambiguous or unusable trust anchor is dropped, not silently preserved, and the loss is named" -> TestAmbiguousTrustAnchorIsDropped
// PORTED: tests/unit/repair.bats: "net rebind's NEW-rebind branch normalizes a leaked rc 3 to operational failure 1" -> TestNetRebindNormalizesAnAbsentAnswer
// PORTED: tests/unit/repair.bats: "live-verify FAILS CLOSED on a present-but-invalid product label, never clears from a fallback alias" -> TestLiveVerifyFailsClosedOnAnInvalidProductLabel
// PORTED: tests/unit/repair.bats: "the post-repair verify loop FAILS CLOSED on a container record with no readable name" -> TestVerifyLoopFailsClosedOnARecordWithNoName
// PORTED: tests/unit/repair.bats: "net rebind's RESUME branch respects MI_CONFIRM=no, exactly like a fresh rebind does" -> TestNetRebindResumeRespectsRefusal
// PORTED: tests/unit/repair.bats: "a container attached to BOTH old and target networks is detected as mid-migration, not clean" -> TestBothNetworksIsDetectedAsMidMigration
// PORTED: tests/unit/repair.bats: "a newline-bearing installation label is never split into forged candidates, nor adoptable" -> TestNewlineLabelIsNeverSplitIntoCandidates
// PORTED: tests/unit/repair.bats: "a transient/unreadable ledger read does not destroy it — repair fails closed, ledger intact" -> TestTransientLedgerReadFailureDoesNotDestroyIt
// PORTED: tests/unit/repair.bats: "a GENUINELY corrupt ledger (checksum mismatch) still is destroyed, preserved aside, and rebuilt" -> TestGenuinelyCorruptLedgerIsDestroyedAndRebuilt
//
// TestRepairRecordKinds and TestRepairAnchorValidatorMatchesTrust claim no bats test: they pin the
// four record kinds and the digest validator this file had to restate locally against the packages
// that own them, which the bash — one namespace, one set of constants — had no way to get wrong.

// --- the world these tests run in -------------------------------------------------------------

// newRepairRig is newRig plus what repair.bats' own setup() builds: the fixture product's verified
// documents, and MI_CONFIRM=yes so a confirmation gate can be exercised without a tty. Every test
// that is ABOUT a refusal sets MI_CONFIRM=no itself.
func newRepairRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.writeProduct("p1")
	r.setEnv("MI_CONFIRM", "yes")
	return r
}

// setEnv sets one variable in the rig's environment AND in the Deps the verbs read, which are two
// copies of one thing: a test that changed only the first would be confirming through a Deps that
// never saw it.
func (r *rig) setEnv(key, value string) {
	kept := make([]string, 0, len(r.env)+1)
	for _, kv := range r.env {
		if !strings.HasPrefix(kv, key+"=") {
			kept = append(kept, kv)
		}
	}
	kept = append(kept, key+"="+value)
	r.env = kept
	r.d.Env = kept
}

func (r *rig) repair(operands ...string) int {
	r.t.Helper()
	return StateRepair(context.Background(), r.d, operands)
}

// mustRepair drives a repair that is expected to succeed, and says what it printed when it did not.
func (r *rig) mustRepair(operands ...string) {
	r.t.Helper()
	if rc := r.repair(operands...); rc != cliio.ExitOK {
		r.t.Fatalf("repair %v: rc = %d, want 0\n%s", operands, rc, r.said())
	}
}

// labelledVolume stands a volume carrying an arbitrary installation identity and nonce — the shell
// suite's `mi_rt_volume_create <name> <nonce> <identity>`.
func (r *rig) labelledVolume(name, nonce, ident string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, nonce)
		if perr != nil {
			r.t.Fatal(perr)
		}
		if err := rt.VolumeCreate(context.Background(), name, p); err != nil {
			r.t.Fatal(err)
		}
	})
}

// labelledNetwork stands a network carrying an arbitrary installation identity, and returns its id.
func (r *rig) labelledNetwork(name, nonce, ident string) string {
	r.t.Helper()
	var id string
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		p, perr := engine.NewProvenance(ident, nonce)
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

// operatorNetwork stands a network with NO installation label at all — an operator's own network,
// which this installer never created and therefore never labelled.
//
// It speaks to the fake daemon's API DIRECTLY, because the engine client cannot express one:
// NetworkCreate requires provenance, deliberately, so that nothing in the product can create an
// unlabelled object. `docker network create` produces exactly this, and it is what MYTHICAL_NET
// names in every fixture below.
func (r *rig) operatorNetwork(name string) string {
	r.t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", r.fake.Socket())
		},
	}}
	body := strings.NewReader(`{"Name":"` + name + `","Driver":"bridge","Labels":{}}`)
	req, err := http.NewRequest(http.MethodPost, "http://docker/"+engine.APIVersion+"/networks/create", body)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, derr := client.Do(req)
	if derr != nil {
		r.t.Fatal(derr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		r.t.Fatalf("creating operator network %s: status %d", name, resp.StatusCode)
	}
	// The id the daemon minted, read back through the ordinary client so the fixture and the code
	// under test agree about what "the id of that network" means.
	id, ierr := netref.Engine(r.c).NetworkID(context.Background(), name)
	if ierr != nil {
		r.t.Fatal(ierr)
	}
	return id
}

// labelledContainer stands a container on a network with the provenance labels given. A label whose
// value is empty is OMITTED entirely — which is how the present-but-absent nonce fixture is built,
// and the difference from an empty VALUE is exactly what one of these tests is about.
func (r *rig) labelledContainer(name, netID, alias string, labels map[string]string) {
	r.t.Helper()
	ref := digestRef(name + "-img")
	r.fake.PullImage(ref)
	set := map[string]string{}
	for k, v := range labels {
		if v == "" {
			continue
		}
		set[k] = v
	}
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		m, err := engine.NewMutator(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		attach, aerr := engine.NewNetworkAttach(netID, alias)
		if aerr != nil {
			r.t.Fatal(aerr)
		}
		spec, serr := engine.NewContainerSpec(name, ref, engine.SpecOpts{Network: attach, Labels: set})
		if serr != nil {
			r.t.Fatal(serr)
		}
		if _, cerr := m.ContainerCreate(context.Background(), spec); cerr != nil {
			r.t.Fatal(cerr)
		}
	})
}

// productContainer is the common fixture: a container carrying one identity's provenance labels and
// a product label, attached under the canonical family alias that product's siblings resolve.
func (r *rig) productContainer(name, netID, product, ident, nonce string) {
	r.t.Helper()
	alias, err := manifest.Alias(product)
	if err != nil {
		r.t.Fatal(err)
	}
	r.labelledContainer(name, netID, alias, map[string]string{
		"installation": ident, "nonce": nonce, "product": product,
	})
}

func (r *rig) startNamed(name string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := rt.ContainerStart(context.Background(), name); err != nil {
			r.t.Fatal(err)
		}
	})
}

func (r *rig) connect(netID, container, alias string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := rt.NetworkConnect(context.Background(), netID, container, alias, -1); err != nil {
			r.t.Fatal(err)
		}
	})
}

func (r *rig) disconnect(netID, container string) {
	r.t.Helper()
	r.withLock(func(h famlock.Held, _ ledger.Store) {
		rt, err := runtime.New(h, r.c)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := rt.NetworkDisconnect(context.Background(), netID, container); err != nil {
			r.t.Fatal(err)
		}
	})
}

// familyConf writes mythical.conf verbatim — MYTHICAL_NET is what every reconstruction fixture sets.
func (r *rig) familyConf(body string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.home, "mythical.conf"), []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) identOrEmpty() string {
	r.t.Helper()
	id, err := r.ledgerNow().IdentGet()
	if err != nil {
		return ""
	}
	return id
}

func (r *rig) corruptSiblings() []string {
	r.t.Helper()
	matches, err := filepath.Glob(filepath.Join(r.home, ".state", "ledger.corrupt.*"))
	if err != nil {
		r.t.Fatal(err)
	}
	return matches
}

// --- the seams, staged ---------------------------------------------------------------------------

// stageReads replaces the runtime read seam for one test and restores it afterwards.
func stageReads(t *testing.T, wrap func(repairSeams) repairSeams) {
	t.Helper()
	prev := repairReads
	repairReads = func(c *engine.Client) repairSeams { return wrap(prev(c)) }
	t.Cleanup(func() { repairReads = prev })
}

// errUnaskable is what the runtime answers when it could not be asked — never engine.ErrAbsent,
// which is an ANSWER. Every fail-closed test below turns exactly one read into this.
var errUnaskable = errors.New("the container runtime did not answer")

// labelFailer wraps the provenance read seam and makes ONE named label read unanswerable.
type labelFailer struct {
	prov.Objects
	class prov.Class
	name  string
	label string
	// after skips this many matching reads before failing, so a test can let candidate discovery
	// succeed and break the SAME read in a later phase.
	after int
	seen  *int
}

func (f labelFailer) Label(ctx context.Context, class prov.Class, name, label string) (string, error) {
	if class == f.class && name == f.name && label == f.label {
		*f.seen++
		if *f.seen > f.after {
			return "", errUnaskable
		}
	}
	return f.Objects.Label(ctx, class, name, label)
}

// failLabelAfter stages a seam in which one object's ONE label read stops answering after `after`
// successful answers.
func failLabelAfter(t *testing.T, class prov.Class, name, label string, after int) {
	t.Helper()
	seen := 0
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.objs = labelFailer{Objects: rd.objs, class: class, name: name, label: label, after: after, seen: &seen}
		return rd
	})
}

// attachmentFailer wraps the attachment read seam and makes ONE container's attachments
// unanswerable — never engine.ErrAbsent, which would be the ANSWER "the container is gone".
type attachmentFailer struct {
	bringup.Objects
	container string
}

func (f attachmentFailer) Attachments(ctx context.Context, container string) ([]bringup.Attachment, error) {
	if container == f.container {
		return nil, errUnaskable
	}
	return f.Objects.Attachments(ctx, container)
}

func TestRepairRecordKinds(t *testing.T) {
	// THE FOUR RECORD KINDS repair writes that no package exposes a writer for, each round-tripped
	// through the reader that owns it. A copied constant drifts silently the day its owner renames
	// the kind: the write still succeeds, into a row nothing reads.
	l := &ledger.Ledger{}
	if err := l.Put(kindIdentity, "id", "insta", []ledger.Field{{Key: "id", Value: "insta"}}); err != nil {
		t.Fatal(err)
	}
	got, err := l.IdentGet()
	if err != nil || got != "insta" {
		t.Fatalf("identity kind %q does not round-trip through ledger.IdentGet: %q, %v", kindIdentity, got, err)
	}

	if err := (&sessionless{l}).putRef("netid1", "opnet"); err != nil {
		t.Fatal(err)
	}
	ref, rerr := netref.RefGet(l)
	if rerr != nil || ref != "netid1" {
		t.Fatalf("netref kind %q does not round-trip through netref.RefGet: %q, %v", kindNetRef, ref, rerr)
	}

	if err := l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "phase", Value: "1"},
		{Key: "source", Value: "src"},
		{Key: "target", Value: "tgt"},
		{Key: "containers", Value: "c1,c2"},
	}); err != nil {
		t.Fatal(err)
	}
	mig, merr := netref.MigGet(l)
	if merr != nil || mig.Source != "src" || len(mig.Containers) != 2 {
		t.Fatalf("netmig kind %q does not round-trip through netref.MigGet: %+v, %v", kindNetMig, mig, merr)
	}

	if err := prov.Record(l, prov.ClassVolume, "v1", "n1"); err != nil {
		t.Fatal(err)
	}
	recs, aerr := l.All(kindProvObj)
	if aerr != nil || len(recs) != 1 {
		t.Fatalf("object kind %q does not enumerate what prov.Record writes: %d records, %v", kindProvObj, len(recs), aerr)
	}

	// The trust anchor is COUNTED here, never written here — its kind carries a '-' the typed
	// editors refuse, which is why trust keeps its own writer.
	if err := ledger.FieldOK(ledger.Field{Key: trustAnchorKind, Value: "x"}); err {
		t.Fatalf("%q is a legal typed-editor field name after all — the anchor could be written through l.Put, and resetLedger's two-write residual is avoidable", trustAnchorKind)
	}
}

// sessionless lends putNetRef's field shape to the round-trip test without a session.
type sessionless struct{ l *ledger.Ledger }

func (s *sessionless) putRef(id, name string) error {
	return s.l.Put(kindNetRef, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "id", Value: id},
		{Key: "name", Value: name},
		{Key: "owned", Value: "no"},
	})
}

func TestRepairAnchorValidatorMatchesTrust(t *testing.T) {
	// hex64OK is restated in repair.go because internal/trust keeps its own unexported. The two must
	// agree on what a usable anchor digest is, or the reset gate drops one trust would have accepted
	// (or keeps one it would refuse). Pinned through trust's own writer, which validates before it
	// records.
	r := newRig(t)
	cases := []struct {
		digest string
		want   bool
	}{
		{hex64, true},
		{strings.Repeat("b", 64), true},
		{"", false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.ToUpper(hex64), false},
		{strings.Repeat("g", 64), false},
	}
	for _, c := range cases {
		if hex64OK(c.digest) != c.want {
			t.Fatalf("hex64OK(%q) = %v, want %v", c.digest, !c.want, c.want)
		}
		var accepted bool
		r.withLock(func(h famlock.Held, st ledger.Store) {
			accepted = trust.AnchorSet(h, st, c.digest) == nil
		})
		if accepted != c.want {
			t.Fatalf("trust.AnchorSet(%q) accepted = %v, but repair's hex64OK says %v", c.digest, accepted, c.want)
		}
	}
}

// --- the schema gate -------------------------------------------------------------------------

func TestNewerLedgerSchemaIsRefusedByTheReader(t *testing.T) {
	r := newRepairRig(t)
	r.mintIdentity()
	bumpSchema(t, r.ledgerPath(), "99")

	// The reader refuses, so nothing downstream of it can read an identity out of a ledger this
	// build does not understand. (Plan 1's gate; asserted here because repair is the verb an
	// operator reaches for next.)
	if _, err := ledger.Read(ledger.LiveRead(r.home)); err == nil {
		t.Fatal("a schema-99 ledger was read as if this build understood it")
	}
	var got error
	r.withLock(func(_ famlock.Held, st ledger.Store) {
		l, err := ledger.Read(st)
		if err != nil {
			got = err
			return
		}
		_, got = l.IdentGet()
	})
	if got == nil {
		t.Fatal("the installation identity was read out of a schema-99 ledger")
	}
}

func TestSchemaMigrateIsANoOpAtSchemaOne(t *testing.T) {
	r := newRepairRig(t)
	r.mintIdentity()
	before := readFile(t, r.ledgerPath())
	r.withLock(func(h famlock.Held, st ledger.Store) {
		if err := SchemaMigrate(h, st); err != nil {
			t.Fatalf("SchemaMigrate: %v", err)
		}
	})
	if after := readFile(t, r.ledgerPath()); after != before {
		t.Fatalf("the schema migration rewrote the ledger at schema 1:\nbefore: %s\nafter:  %s", before, after)
	}
	// AND IT ASSERTS THE LOCK. A migration that could run unlocked would read-modify-write the
	// ledger beside another process doing the same.
	if err := SchemaMigrate(nil, ledger.LiveRead(r.home)); err == nil {
		t.Fatal("SchemaMigrate ran without the family lock")
	}
}

// --- candidate discovery ---------------------------------------------------------------------

func TestCandidatesAreTheDistinctIdentities(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	r.labelledVolume("v2", "n2", "insta")
	r.labelledVolume("v3", "n3", "instb")

	got, err := Candidates(context.Background(), r.d)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("candidates = %v, want the two DISTINCT identities", got)
	}
	if !hasAll(got, "insta", "instb") {
		t.Fatalf("candidates = %v, want insta and instb", got)
	}
}

func TestCandidatesKeepPrefixIdentitiesDistinct(t *testing.T) {
	// "abc" is a literal string prefix of "abc-x". A dedup that matched on containment — or a
	// space-padded membership test — would collapse the two into one candidate, and the repair would
	// then offer a single identity over objects belonging to two.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "abc-x")
	r.labelledVolume("v2", "n2", "abc")

	got, err := Candidates(context.Background(), r.d)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 2 || !hasAll(got, "abc-x", "abc") {
		t.Fatalf("candidates = %v, want both abc-x and abc", got)
	}
}

func TestNewlineLabelIsNeverSplitIntoCandidates(t *testing.T) {
	// A label VALUE can contain arbitrary bytes, a newline included; the fake daemon's own storage
	// cannot represent that, so the forged label is injected at the read seam, which is the only way
	// to exercise what a real daemon could hand back. The reference appended each value
	// newline-terminated with no validation, so `installation=$'foreign\nvictim'` was reported as
	// TWO candidates and "victim" then passed the membership test for an operator's choice — even
	// though no real object's label is the bare string "victim". Selecting it reset the ledger and
	// adopted an identity that owned nothing.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "real-id")
	r.labelledVolume("v2", "n2", "placeholder")
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.objs = forgedLabel{Objects: rd.objs, class: prov.ClassVolume, name: "v2", value: "foreign\nvictim"}
		return rd
	})

	got, err := Candidates(context.Background(), r.d)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if !hasAll(got, "real-id") {
		t.Fatalf("candidates = %v, want the real identity present", got)
	}
	for _, c := range got {
		if c == "victim" || c == "foreign" || strings.Contains(c, "\n") {
			t.Fatalf("a forged half of the injected label was reported as a candidate: %q", c)
		}
	}
	r.mustSay("not a single")

	// ...and neither half is adoptable.
	if rc := r.repair("victim"); rc == cliio.ExitOK {
		t.Fatalf("repair adopted the forged identity\n%s", r.said())
	}
	r.mustSay("not one of the identities found")
	if id := r.identOrEmpty(); id != "" {
		t.Fatalf("an identity (%q) was recorded by a refused repair", id)
	}
}

func TestCandidateDiscoveryFailsClosedOnAnUnreadableLabel(t *testing.T) {
	// The volume's installation label stops answering. Before the fix that failure became an empty
	// label, v1 was silently omitted, and discovery could report zero or one candidate with an
	// object it never asked about left out entirely.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	failLabelAfter(t, prov.ClassVolume, "v1", prov.LabelInstall, 0)

	got, err := Candidates(context.Background(), r.d)
	if err == nil {
		t.Fatalf("candidate discovery answered %v over an object it could not ask about", got)
	}
	mustContain(t, err.Error(), "could not be asked for its installation label")
	mustContain(t, err.Error(), "cannot prove which identities are present")
}

// --- choosing, and refusing to choose ----------------------------------------------------------

func TestExactlyOneCandidateIsStillShownAndConfirmed(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	r.setEnv("MI_CONFIRM", "no")

	if rc := r.repair(); rc == cliio.ExitOK {
		t.Fatalf("the sole candidate was adopted without being named\n%s", r.said())
	}
	r.mustSay("insta")
	r.mustSay("choose")
}

func TestARealCandidateIsNeverTreatedAsZero(t *testing.T) {
	// The count that decides between "found N, choose one" and "found none, offer to reinitialize"
	// must never collapse a real candidate to zero: with confirmation already granted, that mints a
	// brand-new identity and resets the ledger over the candidate's objects instead of asking.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")

	if rc := r.repair(); rc == cliio.ExitOK {
		t.Fatalf("a repair with a real candidate and no choice succeeded\n%s", r.said())
	}
	r.mustSay("insta")
	r.mustSay("found 1 installation identity")
	r.mustNotSay("reinitializ")
	if id := r.identOrEmpty(); id != "" {
		t.Fatalf("an identity (%q) was minted over a real candidate", id)
	}
}

func TestTwoCandidatesBothShownNothingTouched(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	r.labelledVolume("v3", "n3", "instb")
	r.setEnv("MI_CONFIRM", "no")

	if rc := r.repair(); rc == cliio.ExitOK {
		t.Fatalf("a repair with two candidates and no choice succeeded\n%s", r.said())
	}
	r.mustSay("insta")
	r.mustSay("instb")
	if !r.volumeExists("v3") {
		t.Fatal("the other identity's volume was removed")
	}
}

func TestReinitializeRefusedWhenCandidatesExist(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")

	if rc := r.repair(reinitialize); rc == cliio.ExitOK {
		t.Fatalf("reinitialization ran over an existing candidate\n%s", r.said())
	}
	r.mustSay("choose")
}

func TestStateRepairRejectsASurplusOperand(t *testing.T) {
	// The reference bounded its arity only from below, so a surplus third operand passed straight
	// through and — with confirmation already granted — reset the ledger and adopted an identity
	// from a malformed call. The dispatcher rejects this too; the operator-verb contract (wrong
	// arity → usage, nothing attempted) has to hold for a caller of the library verb directly.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	before := len(r.fake.RequestLog())

	if rc := r.repair("insta", "stray"); rc != cliio.ExitUsage {
		t.Fatalf("rc = %d, want %d (usage)\n%s", rc, cliio.ExitUsage, r.said())
	}
	if id := r.identOrEmpty(); id != "" {
		t.Fatalf("a malformed call adopted identity %q", id)
	}
	// NOTHING ATTEMPTED is half the contract: the refusal has to come before the daemon is asked
	// anything, not after a preflight that already spoke to it.
	if after := r.fake.RequestLog(); len(after) != before {
		t.Fatalf("a malformed call reached the daemon: %v", after[before:])
	}
}

func TestRepairRefusesWhileTheLockIsHeld(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	h, err := famlock.Acquire(r.home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = famlock.Release(h) }()

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("repair ran while another process held the family lock\n%s", r.said())
	}
}

// --- the rebuild -------------------------------------------------------------------------------

func TestChoosingAnIdentityRebuildsProvenance(t *testing.T) {
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.labelledVolume("v1", "n1", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")

	r.mustRepair("insta")

	if id := r.identOrEmpty(); id != "insta" {
		t.Fatalf("identity = %q, want insta", id)
	}
	l := r.ledgerNow()
	for _, c := range []struct {
		class prov.Class
		name  string
	}{{prov.ClassVolume, "v1"}, {prov.ClassNetwork, "netA"}, {prov.ClassContainer, "c1"}} {
		if _, err := prov.Find(l, c.class, c.name); err != nil {
			t.Fatalf("no provenance rebuilt for %s %s: %v", c.class, c.name, err)
		}
	}
}

func TestRepairNeverRebuildsImageProvenance(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")

	r.mustRepair("insta")
	r.mustSay("no image is deleted")
	r.mustSay("cannot say which")

	// Images carry no installation label (D37), so the list lived only in the ledger being
	// repaired; inventing one is what this refuses to do.
	imgs, err := r.ledgerNow().All("image")
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 0 {
		t.Fatalf("repair rebuilt %d image record(s)", len(imgs))
	}
}

func TestOutstandingInitializedToAliasForEveryContainer(t *testing.T) {
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")

	r.mustRepair("insta")

	checks := r.outstanding("c1")
	if len(checks) != 1 || checks[0].Kind != state.CheckAlias {
		t.Fatalf("outstanding = %v, want exactly one alias check", checks)
	}
}

func TestRunningRecoveredContainerIsVerifiedInTheSameRun(t *testing.T) {
	// A running container has an address, so there is nothing to wait for: its owed alias check is
	// performed and retired in the SAME repair run. Only stopped ones carry the entry forward.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.startNamed("c1")

	r.mustRepair("insta")

	if checks := r.outstanding("c1"); len(checks) != 0 {
		t.Fatalf("outstanding = %v, want empty — a running container is verified in the same run\n%s", checks, r.said())
	}
}

func TestDesiredStateIsInferredFromObservation(t *testing.T) {
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.productContainer("c2", net, "p2", "insta", "nc2")
	r.startNamed("c2")

	r.mustRepair("insta")
	r.mustSay("inferred from observation")
	r.mustSay("c1")
	r.mustSay("c2")

	if got := r.desired("c1"); got != state.Stopped {
		t.Fatalf("desired(c1) = %q, want stopped", got)
	}
	if got := r.desired("c2"); got != state.Running {
		t.Fatalf("desired(c2) = %q, want running", got)
	}
}

func TestTrustFloorsAreResetWithTheWindowStated(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")

	r.setEnv("MI_CONFIRM", "no")
	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("repair reset the trust floors without confirmation\n%s", r.said())
	}
	r.mustSay("rollback")

	r.setEnv("MI_CONFIRM", "yes")
	r.reset()
	r.mustRepair("insta")
}

func TestRepairStatesItCannotProveNothingIsInFlight(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")

	r.mustRepair("insta")
	r.mustSay("cannot prove")
}

func TestAdoptionRefusesAPresentButEmptyNonce(t *testing.T) {
	// The inspect ANSWERS, with an empty value — a different fact from "could not be asked" and from
	// "the object is gone". Recording it verbatim writes `nonce=`, which every later authority check
	// refuses, so the object repair just claimed to recover becomes permanently unownable.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.labelledContainer("c1", net, "mythical-p1", map[string]string{"installation": "insta", "product": "p1"})

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("an object with no nonce label was adopted\n%s", r.said())
	}
	r.mustSay("no nonce label at all")
	if _, err := prov.Find(r.ledgerNow(), prov.ClassContainer, "c1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance was written for a nonce-less object: %v", err)
	}
}

func TestRebuildLoopFailsClosedOnAnUnreadableLabel(t *testing.T) {
	// The ledger has ALREADY been reset by the time this read fails, so a silent skip does not leave
	// provenance stale — it leaves it MISSING, permanently, while the run reports a completed
	// repair. Candidate discovery is allowed its one successful answer first; the rebuild loop's
	// read is the one that stops answering.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	failLabelAfter(t, prov.ClassVolume, "v1", prov.LabelInstall, 1)

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("the rebuild reported success over an object it could not ask about\n%s", r.said())
	}
	r.mustSay("could not be asked for its installation label")
	r.mustSay("already been reset")
	if _, err := prov.Find(r.ledgerNow(), prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance for v1 exists after a refused rebuild: %v", err)
	}
	// The message promises the operator a re-run will work, which is only true if the identity the
	// reset established actually reached disk.
	if id := r.identOrEmpty(); id != "insta" {
		t.Fatalf("identity = %q; the refusal's own 'the ledger already carries the new identity' is false", id)
	}
}

func TestVerifyLoopFailsClosedOnARecordWithNoName(t *testing.T) {
	// A container-class record with no `name=` is a shape prov.Record never produces — staged here
	// by a writer that omits it for containers only, standing in for a malformed record this same
	// run just wrote reaching the live-verify loop. Skipping it silently skips that container's
	// observed state and alias verification while the repair still reports success.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.startNamed("c1")

	prev := provRecord
	provRecord = func(l *ledger.Ledger, class prov.Class, name, nonce string, extra ...ledger.Field) error {
		if class != prov.ClassContainer {
			return prev(l, class, name, nonce, extra...)
		}
		k := "container:" + name
		fields := []ledger.Field{
			{Key: "key", Value: k},
			{Key: "class", Value: string(prov.ClassContainer)},
			{Key: "nonce", Value: nonce},
			{Key: "gen", Value: "1"},
		}
		return l.Put(kindProvObj, "key", k, append(fields, extra...))
	}
	t.Cleanup(func() { provRecord = prev })

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("the verify loop stepped over a record it could not read a name from\n%s", r.said())
	}
	r.mustSay("carries no readable name")
}

func TestLiveVerifyFailsClosedOnAnInvalidProductLabel(t *testing.T) {
	// A product label that is not a valid identifier is a DIFFERENT fact from no product label at
	// all (D37's legitimate fallback). Swallowing the derivation failure verifies whatever alias the
	// container happens to carry — so the check gets cleared as "confirmed" from a malformed label,
	// without ever checking the alias siblings actually resolve.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.labelledContainer("c1", net, "mythical-p1", map[string]string{
		"installation": "insta", "nonce": "nc1", "product": "BadProduct",
	})
	r.startNamed("c1")

	r.mustRepair("insta")
	r.mustSay("not a valid identifier")
	if checks := r.outstanding("c1"); len(checks) != 1 {
		t.Fatalf("outstanding = %v, want the alias check still owed", checks)
	}
}

func TestNoneIsNeverRecordedFromAnUnreadAttachment(t *testing.T) {
	// `+none` declares that NO live verification is owed. That is only true when the container
	// genuinely has no attachment, which requires having read them — never a failed read defaulted
	// to empty.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.live = attachmentFailer{Objects: rd.live, container: "c1"}
		return rd
	})

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("repair recorded state for a container whose attachments it could not read\n%s", r.said())
	}
	r.mustSay("'+none' from an unread state")
	if _, err := state.DesiredGet(r.ledgerNow(), "c1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("a desired state was recorded from an unread attachment: %v", err)
	}
}

// --- the network reference, reconstructed ------------------------------------------------------

func TestNonOwnedReferenceRebuiltFromConfig(t *testing.T) {
	r := newRepairRig(t)
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")
	r.labelledVolume("v1", "n1", "insta")

	r.mustRepair("insta")

	l := r.ledgerNow()
	if _, err := netref.RefGet(l); err != nil {
		t.Fatalf("no operator-network reference was rebuilt: %v", err)
	}
	rec, err := l.Find(kindNetRef, "key", "family")
	if err != nil {
		t.Fatal(err)
	}
	if owned, _ := ledger.FieldOf(rec, "owned"); owned != "no" {
		t.Fatalf("the rebuilt reference says owned=%q; repair confers no deletion authority", owned)
	}
}

func TestDifferentNetworkEntersTheMigration(t *testing.T) {
	r := newRepairRig(t)
	src := r.operatorNetwork("oldnet")
	r.productContainer("c1", src, "p1", "insta", "nc1")
	r.startNamed("c1")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	if rc := r.repair("insta"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("differs")

	l := r.ledgerNow()
	mig, err := netref.MigGet(l)
	if err != nil {
		t.Fatalf("no migration intent recorded: %v", err)
	}
	if mig.Source != src {
		t.Fatalf("migration source = %q, want the OBSERVED network %q", mig.Source, src)
	}
	// The reference must name the OBSERVED network, never the target, until the migration completes.
	ref, rerr := netref.RefGet(l)
	if rerr != nil || ref != src {
		t.Fatalf("reference = %q (%v), want the observed network %q", ref, rerr, src)
	}
}

func TestBothNetworksIsDetectedAsMidMigration(t *testing.T) {
	// A container interrupted between migration phases 2 and 4 is attached to BOTH the old network
	// and the configured target. Taking only the FIRST attachment made its "one" network whichever
	// came first: with the target first, the observed network came out equal to the resolved one and
	// a CLEAN reference was recorded with NO migration intent — silently dropping all record of the
	// still-live old attachment, so nothing would ever detach it.
	//
	// THE NAMES ARE CHOSEN SO THE TARGET IS EMITTED FIRST. The attachment reader sorts by network
	// NAME, so "atarget" precedes "zsource" deterministically — the shell suite arranged the same
	// ordering through its fake's join order, which a sorted reader does not have. Named the other
	// way round this test passes with the defect in place, because the first attachment would then
	// be the source and "take the first" would happen to get the right answer.
	r := newRepairRig(t)
	tgt := r.operatorNetwork("atarget")
	src := r.operatorNetwork("zsource")
	r.productContainer("c1", tgt, "p1", "insta", "nc1")
	r.connect(src, "c1", "mythical-p1")
	r.familyConf("MYTHICAL_NET=atarget\n")

	if rc := r.repair("insta"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	l := r.ledgerNow()
	mig, err := netref.MigGet(l)
	if err != nil {
		t.Fatalf("no migration intent recorded for a container on BOTH networks: %v", err)
	}
	if mig.Source != src {
		t.Fatalf("migration source = %q, want the OLD network %q", mig.Source, src)
	}
	ref, rerr := netref.RefGet(l)
	if rerr != nil || ref != src {
		t.Fatalf("reference = %q (%v), want the observed (old) network %q", ref, rerr, src)
	}
}

func TestDisagreeingContainersStopTheReconstruction(t *testing.T) {
	r := newRepairRig(t)
	a := r.operatorNetwork("na")
	b := r.operatorNetwork("nb")
	r.productContainer("c1", a, "p1", "insta", "n1")
	r.productContainer("c2", b, "p2", "insta", "n2")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("a split fleet was reconstructed as if it agreed\n%s", r.said())
	}
	r.mustSay("already split")
}

func TestUnattachedContainersAreNotACleanReference(t *testing.T) {
	// A container with zero attachments reads back successfully but EMPTY, which is a different fact
	// from "no containers carry this identity": the fleet is non-empty while nothing agrees. Reading
	// the two as one recorded the configured network as a clean family reference while the recovered
	// container is not attached to it at all.
	r := newRepairRig(t)
	net := r.operatorNetwork("netA")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.disconnect(net, "c1")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("an unattached fleet was recorded as a clean reference\n%s", r.said())
	}
	r.mustSay("none of them share a single attached")
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded anyway: %v", err)
	}
}

func TestReconstructedMigrationNeverRecordsAnEmptyFleet(t *testing.T) {
	// The reference hardcoded an empty container set into this record, so 'net rebind' read an empty
	// fleet back from the very record that is supposed to describe it and had nothing to move.
	r := newRepairRig(t)
	src := r.operatorNetwork("oldnet")
	r.productContainer("c1", src, "p1", "insta", "nc1")
	r.startNamed("c1")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	if rc := r.repair("insta"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	mig, err := netref.MigGet(r.ledgerNow())
	if err != nil {
		t.Fatal(err)
	}
	if len(mig.Containers) != 1 || mig.Containers[0] != "c1" {
		t.Fatalf("migration fleet = %v, want [c1]", mig.Containers)
	}
}

func TestReconstructedMigrationNamesEveryContainer(t *testing.T) {
	r := newRepairRig(t)
	src := r.operatorNetwork("oldnet")
	r.productContainer("c1", src, "p1", "insta", "nc1")
	r.productContainer("c2", src, "p2", "insta", "nc2")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	if rc := r.repair("insta"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	mig, err := netref.MigGet(r.ledgerNow())
	if err != nil {
		t.Fatal(err)
	}
	if len(mig.Containers) != 2 || !hasAll(mig.Containers, "c1", "c2") {
		t.Fatalf("migration fleet = %v, want both containers — a truncated list looks complete to everything downstream", mig.Containers)
	}
}

func TestNetworkReconstructionFailsClosedOnAnUnreadableLabel(t *testing.T) {
	// The reconstruction's OWN read of the container's installation label — after candidate
	// discovery and the whole rebuild loop have already succeeded against it. Skipping the container
	// silently drops it from the "do the containers agree" comparison, so repair could record a
	// clean reference even though it might still be on the OLD network: a split fleet the ledger
	// would then report as healthy.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")
	// Candidate discovery reads it once; the rebuild loop reads it once more. The third read is the
	// reconstruction's.
	failLabelAfter(t, prov.ClassContainer, "c1", prov.LabelInstall, 2)

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("a reference was reconstructed over a container it could not ask about\n%s", r.said())
	}
	r.mustSay("could not be asked for its installation label")
	r.mustSay("fleet agrees")
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded anyway: %v", err)
	}
}

// --- the reset gate ------------------------------------------------------------------------------

func TestZeroCandidatesOffersReinitialization(t *testing.T) {
	// Host state can exist with no labelled runtime objects at all — a restore that carried the
	// family home but no containers. Refusing here would deadlock the exact case §6b sends to repair.
	r := newRepairRig(t)
	if err := os.WriteFile(filepath.Join(r.home, "brokkr.conf"), []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r.mustRepair()
	r.mustSay("reinitializ")
	r.mustSay("will not be recognised")
	if id := r.identOrEmpty(); id == "" {
		t.Fatalf("no identity was minted by a reinitialization\n%s", r.said())
	}
}

func TestAmbiguousTrustAnchorIsDropped(t *testing.T) {
	// Two anchor rows in an otherwise checksum-valid ledger — the realistic source is a restored or
	// hand-assembled ledger. Preserving both reports the repair a success and the FIRST later trust
	// read then refuses the ambiguous anchor, wedging an installation this repair had just fixed.
	r := newRepairRig(t)
	r.mintIdentity()
	r.appendRows("trust-anchor\tdigest=" + strings.Repeat("b", 64))

	r.mustRepair(reinitialize)
	r.mustSay("GUARANTEE LOST")
	r.mustSay("trust anchors, not one")

	var got error
	r.withLock(func(_ famlock.Held, st ledger.Store) { _, got = trust.AnchorGet(st) })
	if !errors.Is(got, ledger.ErrAbsentRecord) {
		t.Fatalf("the ambiguous anchor survived the repair: %v", got)
	}
}

func TestNewerSchemaLedgerIsNeverRenamedAside(t *testing.T) {
	// A ledger a NEWER build wrote is not corrupt — it is D35's own gate doing its job. Repairing
	// over it would rename a STILL-VALID ledger aside and replace it with an empty one, discarding
	// everything the newer build recorded, through the repair door instead of the read door.
	r := newRepairRig(t)
	r.mintIdentity()
	bumpSchema(t, r.ledgerPath(), "99")
	before := readFile(t, r.ledgerPath())

	if rc := r.repair(reinitialize); rc == cliio.ExitOK {
		t.Fatalf("repair ran over a newer-schema ledger\n%s", r.said())
	}
	r.mustSay("newer than this build")
	if after := readFile(t, r.ledgerPath()); after != before {
		t.Fatalf("the newer-schema ledger was rewritten:\nbefore: %s\nafter:  %s", before, after)
	}
	if sibs := r.corruptSiblings(); len(sibs) != 0 {
		t.Fatalf("a .corrupt.* sibling was created for a merely-newer ledger: %v", sibs)
	}
}

func TestGenuinelyCorruptLedgerIsDestroyedAndRebuilt(t *testing.T) {
	// The other half of the distinction: proving the destroy path is not switched OFF for the case
	// that must still use it. A body changed after the checksum was written is positively confirmed
	// corrupt content.
	r := newRepairRig(t)
	r.mintIdentity()
	appendRaw(t, r.ledgerPath(), "tampered\tx=1\n")

	r.mustRepair(reinitialize)
	r.mustSay("PRESERVED")

	sibs := r.corruptSiblings()
	if len(sibs) != 1 {
		t.Fatalf("%d .corrupt.* siblings, want exactly 1 — the evidence is preserved, not multiplied: %v", len(sibs), sibs)
	}
	if _, err := ledger.Read(ledger.LiveRead(r.home)); err != nil {
		t.Fatalf("the rebuilt ledger does not read clean: %v", err)
	}
	if id := r.identOrEmpty(); id == "" {
		t.Fatal("no fresh identity was minted after destroying a corrupt ledger")
	}
}

func TestTransientLedgerReadFailureDoesNotDestroyIt(t *testing.T) {
	// A read that merely FAILED says nothing about the bytes underneath it. The reference could not
	// tell that apart from real damage — every non-absent failure reached the same destroy branch —
	// and reset a perfectly good ledger, discarding the trust anchor and every rollback floor, over
	// a failure that said nothing about its content.
	r := newRepairRig(t)
	r.mintIdentity()
	before := readFile(t, r.ledgerPath())

	prevRead, prevCorrupt := ledgerRead, ledgerConfirmedCorrupt
	ledgerRead = func(ledger.Store) (*ledger.Ledger, error) { return nil, errUnaskable }
	ledgerConfirmedCorrupt = func(ledger.Store) bool { return false }
	rc := r.repair(reinitialize)
	ledgerRead, ledgerConfirmedCorrupt = prevRead, prevCorrupt

	if rc == cliio.ExitOK {
		t.Fatalf("repair destroyed a ledger over a read that merely failed\n%s", r.said())
	}
	r.mustSay("could not be read")
	r.mustSay("positively confirms")
	if after := readFile(t, r.ledgerPath()); after != before {
		t.Fatalf("the ledger was replaced:\nbefore: %s\nafter:  %s", before, after)
	}
	if sibs := r.corruptSiblings(); len(sibs) != 0 {
		t.Fatalf("a .corrupt.* sibling was created despite no positive confirmation: %v", sibs)
	}
	if _, err := ledger.Read(ledger.LiveRead(r.home)); err != nil {
		t.Fatalf("the untouched ledger no longer reads clean: %v", err)
	}
}

// --- what a repair leaves behind ----------------------------------------------------------------

func TestLateObjectAfterRetainingRepairIsUnrecorded(t *testing.T) {
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	r.mustRepair("insta")
	r.labelledVolume("late", "n9", "insta")

	err := intent.UnaccountedGate(context.Background(), r.ledgerNow(), intent.Engine(r.c))
	if err == nil {
		t.Fatal("an object carrying THIS identity with no record did not stop a mutating verb")
	}
	mustContain(t, err.Error(), "unrecorded")
}

func TestLateObjectAfterReinitializingRepairIsUnattributed(t *testing.T) {
	// The foreign object must arrive AFTER the reinitializing repair: created first it would be a
	// genuine candidate, and reinitialization over an existing candidate is refused.
	r := newRepairRig(t)
	r.mustRepair(reinitialize)
	r.labelledVolume("old", "n1", "instold")

	l := r.ledgerNow()
	if err := intent.UnaccountedGate(context.Background(), l, intent.Engine(r.c)); err != nil {
		t.Fatalf("a FOREIGN object stopped a mutating verb: %v", err)
	}
	found := false
	for _, f := range intent.UnaccountedScan(context.Background(), l, intent.Engine(r.c)) {
		if f.Kind == intent.FindingUnattributed && f.Name == "old" {
			found = true
		}
	}
	if !found {
		t.Fatal("the foreign object was not reported as unattributed")
	}
	if !r.volumeExists("old") {
		t.Fatal("the foreign object was removed")
	}
}

// --- state abandon-intent -------------------------------------------------------------------------

func TestAbandonIntentRespectsTheGracePeriod(t *testing.T) {
	r := newRepairRig(t)
	r.openNetworkIntent("net1")
	// THE REFUSAL COMES BEFORE THE PROMPT. Asking "abandon this intent?" and announcing "abandoning
	// the intent for network net1" for something that cannot be abandoned yet teaches the operator
	// to answer yes to a question the tool was never going to honour — and it is what an
	// unconditional confirm-then-try structure looks like from the outside even when the deeper
	// writer happens to refuse too.
	asked := 0
	r.d.Confirm = func(string) bool { asked++; return true }

	if rc := AbandonIntent(context.Background(), r.d, "network", "net1"); rc == cliio.ExitOK {
		t.Fatalf("an intent was abandoned inside its grace period\n%s", r.said())
	}
	if asked != 0 {
		t.Fatalf("the operator was asked to confirm an abandonment the grace period already refused\n%s", r.said())
	}
	r.mustNotSay("abandoning the intent for")
	if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); err != nil {
		t.Fatalf("the intent was dropped by a refused abandonment: %v", err)
	}

	r.reset()
	r.setEnv("MI_INTENT_GRACE", "0")
	if rc := AbandonIntent(context.Background(), r.d, "network", "net1"); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0 once the grace period has passed\n%s", rc, r.said())
	}
	if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("the intent survived a confirmed abandonment: %v", err)
	}
}

func TestAbandonIntentRefusesWithoutConfirmation(t *testing.T) {
	r := newRepairRig(t)
	r.openNetworkIntent("net1")
	r.setEnv("MI_INTENT_GRACE", "0")
	r.setEnv("MI_CONFIRM", "no")

	if rc := AbandonIntent(context.Background(), r.d, "network", "net1"); rc == cliio.ExitOK {
		t.Fatalf("an intent was abandoned without confirmation\n%s", r.said())
	}
	r.mustSay("not confirmed")
	if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); err != nil {
		t.Fatalf("the intent was dropped anyway: %v", err)
	}
}

// openNetworkIntent records a write-ahead intent for a network that never appeared.
func (r *rig) openNetworkIntent(name string) {
	r.t.Helper()
	r.editLedger(func(l *ledger.Ledger) {
		if _, err := l.IdentEnsure(); err != nil {
			r.t.Fatal(err)
		}
		nonce, err := intent.NonceNew()
		if err != nil {
			r.t.Fatal(err)
		}
		if err := intent.Open(l, prov.ClassNetwork, name, nonce, time.Now()); err != nil {
			r.t.Fatal(err)
		}
	})
}

// --- net rebind ------------------------------------------------------------------------------------

func TestNetRebindFailsClosedOnAnAmbiguousMigrationRecord(t *testing.T) {
	// A SECOND raw netmig row makes the key ambiguous — a refusal, never the ANSWER "no migration".
	// Reading the two as one falls through to starting a brand-new rebind, writing phase 1 over an
	// in-flight migration record nobody could read and discarding the only account of where the
	// fleet came from.
	r := newRepairRig(t)
	r.mintIdentity()
	r.editLedger(func(l *ledger.Ledger) {
		if err := l.Put(kindNetMig, "key", "family", []ledger.Field{
			{Key: "key", Value: "family"},
			{Key: "phase", Value: "2"},
			{Key: "source", Value: "srcid"},
			{Key: "target", Value: "tgtid"},
			{Key: "containers", Value: ""},
		}); err != nil {
			t.Fatal(err)
		}
	})
	r.appendRows("netmig\tkey=family\tphase=2\tsource=srcid\ttarget=other\tcontainers=")
	r.familyConf("MYTHICAL_NET=whatever\n")

	if rc := NetRebind(context.Background(), r.d); rc == cliio.ExitOK {
		t.Fatalf("a fresh rebind started over an unreadable migration record\n%s", r.said())
	}
	r.mustSay("could not be read from the")
	r.mustSay("ledger")
}

func TestNetRebindResumeRespectsRefusal(t *testing.T) {
	// Resuming is not a read: depending on the recorded phase it connects containers to the target,
	// DETACHES them from the source, and commits the new reference — the same destructive steps a
	// fresh rebind performs, picked up partway through. The reference called resume unconditionally,
	// so an explicit refusal was silently overridden the moment a migration was already recorded.
	r := newRepairRig(t)
	r.mintIdentity()
	r.editLedger(func(l *ledger.Ledger) {
		if err := l.Put(kindNetMig, "key", "family", []ledger.Field{
			{Key: "key", Value: "family"},
			{Key: "phase", Value: "2"},
			{Key: "source", Value: "srcid"},
			{Key: "target", Value: "tgtid"},
			{Key: "containers", Value: "c1"},
		}); err != nil {
			t.Fatal(err)
		}
	})
	before, ferr := r.ledgerNow().Find(kindNetMig, "key", "family")
	if ferr != nil {
		t.Fatal(ferr)
	}
	r.setEnv("MI_CONFIRM", "no")

	if rc := NetRebind(context.Background(), r.d); rc == cliio.ExitOK {
		t.Fatalf("a recorded migration was resumed despite a refused confirmation\n%s", r.said())
	}
	r.mustSay("not confirmed")
	r.mustNotSay("resuming the recorded network migration")

	after, aerr := r.ledgerNow().Find(kindNetMig, "key", "family")
	if aerr != nil {
		t.Fatalf("the migration record did not survive the refusal: %v", aerr)
	}
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("the migration record changed under a refusal:\nbefore: %v\nafter:  %v", before, after)
	}
}

func TestNetRebindNormalizesAnAbsentAnswer(t *testing.T) {
	// Both migration entry points end by re-reading a record they were just told exists, and a race
	// in that window makes that read answer ABSENT. Leaking that answer out of the verb as exit 3
	// tells automation "not launched" — that nothing happened — while the fleet may already be
	// partway migrated. The race is not constructible from outside one synchronous call, so the
	// normalization is pinned directly.
	r := newRepairRig(t)
	r.mintIdentity() // the probe arm this verb assembles is scoped by the installation identity
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")

	prev := netRebindFn
	netRebindFn = func(context.Context, *ledger.Ledger, netref.MigDeps, string) (string, error) {
		return "", netref.ErrNoMigration
	}
	defer func() { netRebindFn = prev }()

	rc := NetRebind(context.Background(), r.d)
	if rc != cliio.ExitFail {
		t.Fatalf("rc = %d, want %d — an absent answer during a rebind is operational failure, never 'not launched' (%d)",
			rc, cliio.ExitFail, cliio.ExitNotLaunched)
	}
}

// --- small helpers ---------------------------------------------------------------------------

// forgedLabel answers ONE object's installation label with a value the fake daemon's own storage
// cannot hold.
type forgedLabel struct {
	prov.Objects
	class prov.Class
	name  string
	value string
}

func (f forgedLabel) Label(ctx context.Context, class prov.Class, name, label string) (string, error) {
	if class == f.class && name == f.name && label == prov.LabelInstall {
		return f.value, nil
	}
	return f.Objects.Label(ctx, class, name, label)
}

func hasAll(got []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("message does not mention %q:\n%s", want, got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// bumpSchema rewrites the ledger's schema number in place, leaving the checksum stale — which is
// exactly the state an operator reaching for repair is usually in, and the reason the schema peek
// cannot go through the integrity-first reader.
func bumpSchema(t *testing.T, path, to string) {
	t.Helper()
	body := readFile(t, path)
	out := strings.Replace(body, "schema=1", "schema="+to, 1)
	if out == body {
		t.Fatalf("no schema line to bump in %s", path)
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- guards the frozen bats suite does not exercise ---------------------------------------------
//
// THESE CLAIM NO BATS TEST. Every one of them pins a refusal lib/repair.sh states and its own suite
// leaves uncovered: each was found by reverting the guard in isolation and watching the whole suite
// stay green. They are the same class as the tests above — "could not ask" must never become an
// answer — and their mutations are killed here rather than noted as fine.

// listFailer wraps the provenance read seam and makes ONE class's LISTING unanswerable, after a
// given number of successful answers.
type listFailer struct {
	prov.Objects
	class prov.Class
	after int
	seen  *int
}

func (f listFailer) Names(ctx context.Context, class prov.Class) ([]string, error) {
	if class == f.class {
		*f.seen++
		if *f.seen > f.after {
			return nil, errUnaskable
		}
	}
	return f.Objects.Names(ctx, class)
}

func failListAfter(t *testing.T, class prov.Class, after int) {
	t.Helper()
	seen := 0
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.objs = listFailer{Objects: rd.objs, class: class, after: after, seen: &seen}
		return rd
	})
}

// stateFailer wraps the observed-state seam and makes ONE container unanswerable after a given
// number of successful answers.
type stateFailer struct {
	state.Objects
	container string
	after     int
	seen      *int
}

func (f stateFailer) State(ctx context.Context, container string) (bool, string, error) {
	if container == f.container {
		*f.seen++
		if *f.seen > f.after {
			return false, "", errUnaskable
		}
	}
	return f.Objects.State(ctx, container)
}

func TestCandidateDiscoveryFailsClosedOnAnUnreadableListing(t *testing.T) {
	// A listing that could not be taken is not an empty daemon. Reading the two as one reports
	// FEWER candidates than exist — and a repair that sees one candidate where there were two adopts
	// an identity over another installation's objects, or offers to reinitialize over them.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	failListAfter(t, prov.ClassVolume, 0)

	got, err := Candidates(context.Background(), r.d)
	if err == nil {
		t.Fatalf("candidate discovery answered %v over a listing it could not take", got)
	}
	mustContain(t, err.Error(), "Refusing to report a partial list")
}

func TestZeroCandidatesRefusesAnIdentityNothingCarries(t *testing.T) {
	// Naming an identity no object carries is not a request to mint it. Falling through to the
	// reinitialize branch would answer a specific question ("adopt insta") with a different action.
	r := newRepairRig(t)

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("repair adopted an identity nothing carries\n%s", r.said())
	}
	r.mustSay("no runtime object carries identity")
	r.mustNotSay("reinitializ")
	if id := r.identOrEmpty(); id != "" {
		t.Fatalf("identity %q was minted by a refused repair", id)
	}
}

func TestReinitializationRequiresConfirmation(t *testing.T) {
	// Reinitialization resets every trust floor and mints an identity nothing existing carries. It
	// is offered, never taken.
	r := newRepairRig(t)
	r.setEnv("MI_CONFIRM", "no")

	if rc := r.repair(); rc == cliio.ExitOK {
		t.Fatalf("this installation was reinitialized without confirmation\n%s", r.said())
	}
	r.mustSay("not confirmed")
	if id := r.identOrEmpty(); id != "" {
		t.Fatalf("identity %q was minted without confirmation", id)
	}
}

func TestRebuildFailsClosedOnAnUnreadableListing(t *testing.T) {
	// The ledger is already reset here, so a listing read as empty does not leave provenance stale —
	// it leaves a whole CLASS of objects missing from the rebuild, permanently, while the run reports
	// success.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	// Candidate discovery takes the volume listing once; the rebuild loop's is the second.
	failListAfter(t, prov.ClassVolume, 1)

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("the rebuild reported success over a listing it could not take\n%s", r.said())
	}
	r.mustSay("cannot be fully rebuilt")
	if _, err := prov.Find(r.ledgerNow(), prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance for v1 exists after a refused rebuild: %v", err)
	}
}

func TestRebuildFailsClosedOnAnUnreadableNonce(t *testing.T) {
	// A nonce that could not be READ is not an absent nonce and is certainly not a different one.
	// Recording provenance with the wrong nonce — or none — is exactly the misidentification a nonce
	// exists to prevent (§6a).
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	failLabelAfter(t, prov.ClassVolume, "v1", prov.LabelNonce, 0)

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("an object was adopted with a nonce nobody could read\n%s", r.said())
	}
	r.mustSay("its nonce could not be read")
	if _, err := prov.Find(r.ledgerNow(), prov.ClassVolume, "v1"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance was written for an unreadable nonce: %v", err)
	}
}

func TestRebuildFailsClosedOnAnUnreadableNetworkID(t *testing.T) {
	// A network is recorded BY its id (§6a). There is nothing to record without one, and recording
	// an empty one names a network that does not exist — a record every later authority check would
	// resolve to nothing.
	r := newRepairRig(t)
	r.labelledNetwork("netA", "nA", "insta")
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.nets = netIDFailer{Objects: rd.nets, ref: "netA"}
		return rd
	})

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("a network was recorded with an id nobody could read\n%s", r.said())
	}
	r.mustSay("its id could not be read")
	if _, err := prov.Find(r.ledgerNow(), prov.ClassNetwork, "netA"); !errors.Is(err, ledger.ErrAbsentRecord) {
		t.Fatalf("provenance was written for a network with no id: %v", err)
	}
}

// netIDFailer makes ONE network reference unresolvable — never engine.ErrAbsent, which is the
// ANSWER "no such network".
type netIDFailer struct {
	netref.Objects
	ref string
}

func (f netIDFailer) NetworkID(ctx context.Context, ref string) (string, error) {
	if ref == f.ref {
		return "", errUnaskable
	}
	return f.Objects.NetworkID(ctx, ref)
}

func TestVerifyLoopNeverClearsFromAnUnreadObservation(t *testing.T) {
	// A container that could not be asked whether it is running is not a container that is not
	// running. Its outstanding check is left exactly as recorded — never cleared on an unread state
	// — and the rebuild as a whole still completes.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.startNamed("c1")
	// The rebuild's own observation is the first; the verify loop's is the second.
	seen := 0
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.state = stateFailer{Objects: rd.state, container: "c1", after: 1, seen: &seen}
		return rd
	})

	r.mustRepair("insta")
	r.mustSay("could not be asked whether it is running")
	if checks := r.outstanding("c1"); len(checks) != 1 {
		t.Fatalf("outstanding = %v, want the alias check still owed — it was cleared on an unread state", checks)
	}
}

func TestNetreconstructionFailsClosedOnUnreadableAttachments(t *testing.T) {
	// A container that may still be on a DIFFERENT network cannot be ruled out on an unanswered
	// question. Recording a clean reference over it is how the ledger ends up naming a network the
	// fleet is split from, with every product reporting healthy.
	r := newRepairRig(t)
	net := r.operatorNetwork("opnet")
	_ = net
	r.familyConf("MYTHICAL_NET=opnet\n")
	r.productContainer("c1", r.labelledNetwork("netA", "nA", "insta"), "p1", "insta", "nc1")
	// The rebuild's desired-state block reads the attachments first; the reconstruction's is second.
	seen := 0
	stageReads(t, func(rd repairSeams) repairSeams {
		rd.live = attachmentFailerAfter{Objects: rd.live, container: "c1", after: 1, seen: &seen}
		return rd
	})

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("a reference was recorded over a container whose attachments could not be read\n%s", r.said())
	}
	// The RECONSTRUCTION's own message, not the desired-state block's — they read the same
	// attachments and both refuse, so asserting on wording they share would pass either way and
	// prove nothing about which read was pinned.
	r.mustSay("cannot be ruled out on an")
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded anyway: %v", err)
	}
}

type attachmentFailerAfter struct {
	bringup.Objects
	container string
	after     int
	seen      *int
}

func (f attachmentFailerAfter) Attachments(ctx context.Context, container string) ([]bringup.Attachment, error) {
	if container == f.container {
		*f.seen++
		if *f.seen > f.after {
			return nil, errUnaskable
		}
	}
	return f.Objects.Attachments(ctx, container)
}

func TestEnteringTheMigrationRequiresConfirmation(t *testing.T) {
	// Entering the phased migration writes a reference the ledger did not have and an intent that
	// authorizes a later 'net rebind' to move the whole fleet. The reset gate above it is confirmed;
	// this one is a SECOND decision and is asked separately.
	r := newRepairRig(t)
	src := r.operatorNetwork("oldnet")
	r.productContainer("c1", src, "p1", "insta", "nc1")
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")
	// Yes to the trust-floor reset, no to the migration: the two gates are distinct questions, and a
	// blanket MI_CONFIRM=no could not tell them apart.
	r.d.Confirm = func(prompt string) bool { return !strings.Contains(prompt, "phased network migration") }

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("the migration was entered without confirmation\n%s", r.said())
	}
	r.mustSay("not confirmed. Nothing recorded")
	l := r.ledgerNow()
	if _, err := netref.MigGet(l); !errors.Is(err, netref.ErrNoMigration) {
		t.Fatalf("a migration intent was recorded without confirmation: %v", err)
	}
	if _, err := netref.RefGet(l); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded without confirmation: %v", err)
	}
}

func TestNetRebindFreshRequiresConfirmation(t *testing.T) {
	// A silent rebind is how a container gets joined to a network you did not intend.
	r := newRepairRig(t)
	r.mintIdentity()
	r.operatorNetwork("opnet")
	r.familyConf("MYTHICAL_NET=opnet\n")
	r.setEnv("MI_CONFIRM", "no")

	if rc := NetRebind(context.Background(), r.d); rc == cliio.ExitOK {
		t.Fatalf("a fresh rebind ran without confirmation\n%s", r.said())
	}
	r.mustSay("not confirmed")
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded by a refused rebind: %v", err)
	}
}

func TestNetRebindRefusesWithNoConfiguredNetwork(t *testing.T) {
	// MYTHICAL_NET unset means there is no operator-supplied network to rebind ONTO — an answer.
	// mythical.conf that could not be READ is not that answer, and taking a fleet-moving action on
	// either would be acting on a question nobody asked.
	r := newRepairRig(t)
	r.mintIdentity()

	if rc := NetRebind(context.Background(), r.d); rc == cliio.ExitOK {
		t.Fatalf("a rebind ran with no configured network\n%s", r.said())
	}
	r.mustSay("MYTHICAL_NET is not set")
}

func TestAbandonIntentRefusesAMalformedInvocation(t *testing.T) {
	// A blank class or name names nothing, and a grace period that is not a count of seconds fails
	// OPEN in the reference's own comparison — every intent becomes immediately abandonable. Both
	// refuse before the daemon is asked anything.
	r := newRepairRig(t)
	r.openNetworkIntent("net1")
	before := len(r.fake.RequestLog())

	for _, c := range [][2]string{{"", "net1"}, {"network", ""}} {
		if rc := AbandonIntent(context.Background(), r.d, c[0], c[1]); rc != cliio.ExitUsage {
			t.Fatalf("AbandonIntent(%q, %q) rc = %d, want %d (usage)", c[0], c[1], rc, cliio.ExitUsage)
		}
	}
	r.setEnv("MI_INTENT_GRACE", "not-a-number")
	if rc := AbandonIntent(context.Background(), r.d, "network", "net1"); rc == cliio.ExitOK {
		t.Fatalf("an intent was abandoned under an unreadable grace period\n%s", r.said())
	}
	r.mustSay("not a number of seconds")
	if _, err := intent.Find(r.ledgerNow(), prov.ClassNetwork, "net1"); err != nil {
		t.Fatalf("the intent was dropped by a malformed invocation: %v", err)
	}
	if after := r.fake.RequestLog(); len(after) != before {
		t.Fatalf("a malformed invocation reached the daemon: %v", after[before:])
	}
}

func TestUnreadableLedgerPermissionsAreNeverReadAsCorruption(t *testing.T) {
	// A permissions problem is an operational fact about THIS PROCESS, not evidence about the
	// ledger's content — the bytes underneath may be perfectly valid. Nothing is touched and nothing
	// is moved, which is the only honest answer to a question we structurally cannot ask.
	if os.Geteuid() == 0 {
		t.Skip("running as root: every file is readable, so the refusal is unreachable")
	}
	r := newRepairRig(t)
	r.mintIdentity()
	before := readFile(t, r.ledgerPath())
	if err := os.Chmod(r.ledgerPath(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r.ledgerPath(), 0o600) })

	rc := r.repair(reinitialize)
	if rc == cliio.ExitOK {
		t.Fatalf("repair ran over a ledger it could not read at all\n%s", r.said())
	}
	r.mustSay("not readable by this process")
	if sibs := r.corruptSiblings(); len(sibs) != 0 {
		t.Fatalf("a .corrupt.* sibling was created for a permissions problem: %v", sibs)
	}
	if err := os.Chmod(r.ledgerPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	if after := readFile(t, r.ledgerPath()); after != before {
		t.Fatalf("the ledger was rewritten:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestFailedLiveVerificationLeavesTheCheckOutstanding(t *testing.T) {
	// The alias RESOLVES — to something other than this container's own endpoint on this network.
	// The container is left running and the check stays owed: clearing it would tell every sibling
	// product this one is reachable when the name points somewhere else.
	r := newRepairRig(t)
	net := r.labelledNetwork("netA", "nA", "insta")
	r.productContainer("c1", net, "p1", "insta", "nc1")
	r.startNamed("c1")
	r.resolveAddr = "10.9.9.9"

	r.mustRepair("insta")
	r.mustSay("did not verify")
	if checks := r.outstanding("c1"); len(checks) != 1 {
		t.Fatalf("outstanding = %v, want the alias check still owed after a failed verification", checks)
	}
}

func TestUnusableTrustAnchorIsDropped(t *testing.T) {
	// ONE anchor row whose digest is not a usable one. The whole-ledger checksum proves the bytes
	// were not altered after they were written — not that this record is one the installer's own
	// writer ever produced. Preserving it wedges the next command that reads it.
	r := newRig(t)
	r.setEnv("MI_CONFIRM", "yes")
	r.mintIdentity()
	r.appendRows("trust-anchor\tdigest=not-a-digest")

	if rc := r.repair(reinitialize); rc != cliio.ExitOK {
		t.Fatalf("rc = %d, want 0\n%s", rc, r.said())
	}
	r.mustSay("not a usable digest")
	r.mustSay("GUARANTEE LOST")
	var got error
	r.withLock(func(_ famlock.Held, st ledger.Store) { _, got = trust.AnchorGet(st) })
	if !errors.Is(got, ledger.ErrAbsentRecord) {
		t.Fatalf("the unusable anchor survived the repair: %v", got)
	}
}

func TestReconstructionRefusesAnUnreadableConfig(t *testing.T) {
	// mythical.conf that could not be READ is not MYTHICAL_NET being unset. Taking the
	// installer's-own-network branch on it would silently decide which network this family joins
	// from a file nobody could read.
	r := newRepairRig(t)
	r.labelledVolume("v1", "n1", "insta")
	r.familyConf("MYTHICAL_NET=has\ta\tcontrol\tbyte\n")

	if rc := r.repair("insta"); rc == cliio.ExitOK {
		t.Fatalf("the reference was reconstructed from a config that could not be read\n%s", r.said())
	}
	r.mustSay("mythical.conf could not be read")
	if _, err := netref.RefGet(r.ledgerNow()); !errors.Is(err, netref.ErrNoReference) {
		t.Fatalf("a reference was recorded anyway: %v", err)
	}
}

func TestNetRebindRefusesAnUnreadableConfig(t *testing.T) {
	r := newRepairRig(t)
	r.mintIdentity()
	r.familyConf("MYTHICAL_NET=has\ta\tcontrol\tbyte\n")

	if rc := NetRebind(context.Background(), r.d); rc == cliio.ExitOK {
		t.Fatalf("a rebind started from a config that could not be read\n%s", r.said())
	}
	r.mustSay("cannot be")
	r.mustNotSay("MYTHICAL_NET is not set")
}
