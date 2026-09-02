package netref

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// THE MIGRATION MACHINE (§ net rebind).
//
// Moving a running family from one network to another is not a rebind of a pointer; it is a fleet
// operation with a crash window at every step. The phases exist so that a crash anywhere leaves a
// state a later run can READ and CONTINUE FORWARD from — never unwind, because there is nothing to
// unwind to once containers are on both networks.
//
//	1  record the intent and the fleet it opened against
//	2  CONNECT every container to the target, at a LOWER gateway priority than the source
//	3  VERIFY every container on the target (and that egress still works through the source)
//	4  DETACH each from the source — only ones confirmed on the target
//	5  RE-VERIFY the whole fleet on the target ALONE, before anything is committed
//	6  COMMIT the reference and clear the intent
//
// The ordering is the safety property: connect-all before detach-any, and verify-all before
// commit. Phases 4 and 6 additionally REFUSE to run unless the record shows the earlier phases
// actually ran — a bare phase against an ordinary attached fleet is how the family gets split.

// The six phases, named once. MigResume loops from the recorded phase to phaseLast, so a recorded
// phase outside this range would make that loop a no-op that reports success.
const (
	phaseFirst = 1
	phaseLast  = 6
)

// Prober is the live-verification seam: the alias must RESOLVE, on the target network, to the
// container's own endpoint address there. *probe.Prober satisfies it.
type Prober interface {
	SelfCheck(ctx context.Context, ix *trust.Index, netID string) error
	Resolve(ctx context.Context, ix *trust.Index, netID, alias string) (string, error)
	Egress(ctx context.Context, ix *trust.Index, netID string) error
}

// AttachVerifier is bring-up's pre-start attachment check, injected rather than imported: bringup
// consumes this package's migration records (its own attach check permits {source,target} during a
// migration), so an import in this direction would be a cycle. The seam is the one function this
// package needs of it.
//
// IT TAKES THE LEDGER. bring-up's check reads the migration record to decide the permitted set, so
// it must read the SAME ledger this phase is advancing — a verifier holding its own would answer
// from stale migration bounds while the phase writes to a fresh one, which is precisely the
// mismatch the adapter claims to prevent. Passing it through leaves no way to hold the wrong one.
type AttachVerifier interface {
	VerifyAttach(ctx context.Context, l *ledger.Ledger, container, netID, alias string) error
}

// LiveVerifier is bring-up's live check, injected for the same reason. ErrProbeUnavailable
// distinguishes "the probe did not run" from "the check failed" — the former stops the migration
// without detaching, because nothing was established either way.
type LiveVerifier interface {
	VerifyLive(ctx context.Context, l *ledger.Ledger, ix *trust.Index, container, netID, alias string) error
}

// ErrProbeUnavailable is what a LiveVerifier returns when the probe itself could not run.
var ErrProbeUnavailable = errors.New("netref: the probe did not run")

// MigDeps is everything a phase needs beyond the ledger and the runtime.
type MigDeps struct {
	Deps
	Objs     Objects
	Mut      Mutator
	Probe    Prober
	Attach   AttachVerifier
	Live     LiveVerifier
	State    state.Objects
	Index    *trust.Index
	Verified bool // set by the caller when the index is the authenticated one
}

// Migration is the recorded intent: where the fleet came from, where it is going, how far it got,
// and WHICH containers it opened against.
type Migration struct {
	Phase      int
	Source     string
	Target     string
	Containers []string
}

// phaseOK: a phase parsed out of the ledger is not a number until it has been checked, and it is
// not a PHASE until it has been checked against the six that exist.
//
// The numeric half: reading a non-numeric phase as 0 would silently restart a migration from the
// beginning — re-connecting a fleet that may already be detached. The RANGE half is the one a
// numeric check alone misses: a record carrying `phase=7` parses, so MigResume's `for p := 7; p <=
// 6` runs ZERO iterations and returns success, leaving the recorded migration and the fleet
// exactly as they were while reporting that recovery completed. A migration that reports success
// without doing anything is the one outcome resume must never produce.
func phaseOK(s string) (int, error) {
	bad := func() (int, error) {
		return 0, fmt.Errorf("netref: the recorded migration phase %q is not a number, so there is no point to resume\n"+
			"  from. It is PRESERVED and reported. Run 'mythical-ctl state repair'.", s)
	}
	if s == "" || len(s) > 18 {
		return bad()
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return bad()
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return bad()
	}
	if n < phaseFirst || n > phaseLast {
		return 0, fmt.Errorf("netref: the recorded migration phase %q is not one of the six phases. It is PRESERVED\n"+
			"  and reported. Run 'mythical-ctl state repair'.", s)
	}
	return n, nil
}

// MigGet reads the recorded migration. ErrNoMigration means none — an answer.
func MigGet(l *ledger.Ledger) (*Migration, error) {
	rec, err := l.Find(kindNetMig, "key", "family")
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return nil, ErrNoMigration
	}
	if err != nil {
		return nil, err
	}
	p, ok := ledger.FieldOf(rec, "phase")
	if !ok {
		return nil, errors.New("netref: the recorded migration intent names no phase, so nothing can say how far it got.\n" +
			"  It is PRESERVED and reported. Run 'mythical-ctl state repair'.")
	}
	phase, perr := phaseOK(p)
	if perr != nil {
		return nil, perr
	}
	src, _ := ledger.FieldOf(rec, "source")
	tgt, _ := ledger.FieldOf(rec, "target")
	list, ok := ledger.FieldOf(rec, "containers")
	if !ok {
		return nil, errors.New("netref: the recorded migration names no container set, so the fleet it opened against\n" +
			"  is unknown. It is PRESERVED and reported. Run 'mythical-ctl state repair'.")
	}
	var cs []string
	for _, c := range strings.Split(list, ",") {
		if c != "" {
			cs = append(cs, c)
		}
	}
	return &Migration{Phase: phase, Source: src, Target: tgt, Containers: cs}, nil
}

func migRecord(l *ledger.Ledger, phase int, src, tgt string, cs []string) error {
	return l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "phase", Value: strconv.Itoa(phase)},
		{Key: "source", Value: src},
		{Key: "target", Value: tgt},
		{Key: "containers", Value: strings.Join(cs, ",")},
	})
}

// fleetFor is WHICH containers this phase acts on. Once a migration is recorded, it is the
// RECORDED set — never a fresh enumeration, which could sweep in a container that appeared after
// the migration opened and was never connected to the target.
func fleetFor(ctx context.Context, l *ledger.Ledger, objs Objects) ([]string, error) {
	mig, err := MigGet(l)
	switch {
	case err == nil:
		return mig.Containers, nil
	case errors.Is(err, ErrNoMigration):
		ident, ierr := l.IdentGet()
		if ierr != nil {
			return nil, ierr
		}
		return objs.ContainersByInstall(ctx, ident)
	default:
		return nil, fmt.Errorf("netref: whether a migration is already recorded could not be read from the ledger, so the\n"+
			"  fleet this phase must act on cannot be established. Re-enumerating the live set could\n"+
			"  sweep in a container this migration never connected. Nothing is done: %w", err)
	}
}

// aliasFor derives a container's family alias.
//
// THE RECORD IS THE PERMISSION, THE NAME IS THE DERIVATION — and the two are separate questions.
//
// A container carrying this installation's label that the ledger has no record of stops the
// migration: migrating a fleet we cannot enumerate is migrating one we cannot verify. That is what
// the provenance lookup is for, and the record must also DESCRIBE this container — a record keyed
// for it while describing something else is conflicting evidence, and consuming it here would
// derive an alias for the OTHER object, which phase 2 would then attach and phase 3 would "verify"
// against itself. prov.Find asks that question now, for every consumer of a keyed record rather
// than for the ones that remembered; this function does not restate it, only reports it as itself.
// (The reference reads the record's `product` field without asking at all; the same latent blind
// spot as its root-overlap one, closed there rather than carried.)
//
// The alias itself is derived from the NAME, not from a `product` field — because nothing writes
// that field for a container. Both this port and the reference record a container's provenance as
// key/class/name/nonce/gen/id (the confirmation passes only `id=`), so a `product` lookup refuses
// EVERY container the bring-up path creates: in the reference, network migration of a real fleet
// could never derive a single alias. The name is authoritative and always present — it is
// `mythical-<identity>-<product>`, the same decomposition internal/state uses for its
// storage-migration question.
func aliasFor(l *ledger.Ledger, container string) (string, error) {
	_, err := prov.Find(l, prov.ClassContainer, container)
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return "", fmt.Errorf("netref: %q carries this installation's label but the ledger has no record of it.\n"+
			"  Stopping the migration rather than migrating a fleet we cannot enumerate.", container)
	}
	// A RECORD THAT DESCRIBES SOMETHING ELSE IS REPORTED AS ITSELF. prov.Find refuses it, and the
	// refusal names the fact; wrapping it in "could not be read from the ledger" below would tell
	// the operator the ledger was unreadable when it was read and is contradictory — two different
	// situations with two different remedies. The refusal is the selector's, not a second copy of
	// the question.
	if errors.Is(err, prov.ErrMismatch) {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("netref: whether %q is recorded could not be read from the ledger, so the fleet cannot be\n"+
			"  enumerated. Stopping: %w", container, err)
	}
	ident, ierr := l.IdentGet()
	if ierr != nil {
		return "", ierr
	}
	product, ok := strings.CutPrefix(container, manifest.NamePrefix+"-"+ident+"-")
	if !ok || product == "" {
		return "", fmt.Errorf("netref: %q is not shaped like one of this installation's containers, so the product\n"+
			"  its alias is derived from cannot be read out of it. Stopping rather than guessing.", container)
	}
	return manifest.Alias(product)
}

// liveOK is the resolution check: the alias must resolve, on the TARGET network, to this
// container's endpoint address THERE.
//
// The address comparison is the whole point. During phase 2 every container is on BOTH networks
// and aliases are network-scoped, so a name resolving via the OLD network proves nothing about the
// new one — it would resolve to the container's address on the source.
func liveOK(ctx context.Context, d MigDeps, container, netID, alias, expect string) error {
	if expect == "" {
		return fmt.Errorf("netref: %q is running but has no endpoint address on the target network, so its alias\n"+
			"  has nothing to answer with.", container)
	}
	if err := d.Probe.SelfCheck(ctx, d.Index, netID); err != nil {
		return err
	}
	resolved, err := d.Probe.Resolve(ctx, d.Index, netID, alias)
	if err != nil {
		return err
	}
	if resolved != expect {
		return fmt.Errorf("netref: %q resolves to %q, but %q is at %q on the target network.\n"+
			"  The name resolves — via something other than this network's endpoint for this container.",
			alias, resolved, container, expect)
	}
	return nil
}

// targetOnlyOK is the EXACT-SET check used by phases 5 and 6 (and by 3 when the source is gone):
// this container's network set must be exactly {target}, and if it is running its alias must
// resolve there.
func targetOnlyOK(ctx context.Context, d MigDeps, container, tgt, alias string) error {
	nets, err := d.Objs.ContainerNets(ctx, container)
	if err != nil {
		return err
	}
	expect := ""
	for _, n := range nets {
		if n.NetworkID != tgt {
			return fmt.Errorf("netref: %q is still attached to %q — its network set must be exactly {%s}.",
				container, n.NetworkID, tgt)
		}
		expect = n.Address
	}
	if len(nets) != 1 {
		return fmt.Errorf("netref: %q has %d network attachments and must have exactly one — the target.",
			container, len(nets))
	}
	obs, err := state.Observe(ctx, d.State, container)
	if err != nil {
		return err
	}
	if obs == state.ObsRunning {
		return liveOK(ctx, d, container, tgt, alias, expect)
	}
	return nil
}

// onTarget reports whether the container is attached to the target at all — phase 4's precondition
// before it detaches anything from the source.
func onTarget(ctx context.Context, d MigDeps, container, tgt string) (bool, error) {
	nets, err := d.Objs.ContainerNets(ctx, container)
	if err != nil {
		return false, err
	}
	for _, n := range nets {
		if n.NetworkID == tgt {
			return true, nil
		}
	}
	return false, nil
}

// admits gates phases 4 and 6: they DETACH or COMMIT, so they may only run when the record shows
// the connect-and-verify phases actually ran, on THIS source/target pair.
func admits(l *ledger.Ledger, run int, src, tgt string, lo, hi int) error {
	mig, err := MigGet(l)
	if errors.Is(err, ErrNoMigration) {
		return fmt.Errorf("netref: phase %d detaches or commits, and there is NO recorded migration to show the\n"+
			"  connect-and-verify phases ran. Refusing to act on proof it would have to invent — a bare\n"+
			"  phase against an ordinary attached fleet is how the family is split. Nothing is done.", run)
	}
	if err != nil {
		return fmt.Errorf("netref: whether a migration is recorded could not be read, so phase %d cannot establish\n"+
			"  that the earlier phases ran. Nothing is done: %w", run, err)
	}
	if mig.Source != src || mig.Target != tgt {
		return fmt.Errorf("netref: phase %d was asked to act on source=%s target=%s, but the recorded migration\n"+
			"  documents source=%s target=%s. Refusing to detach or commit against a pair the\n"+
			"  record does not name.", run, src, tgt, mig.Source, mig.Target)
	}
	if mig.Phase < lo || mig.Phase > hi {
		return fmt.Errorf("netref: phase %d cannot run — the recorded migration is at phase %d, and phase %d\n"+
			"  requires it to have reached phase %d. The connect-and-verify phases have not completed,\n"+
			"  and detaching or committing now is the split this ordering exists to prevent. Nothing is\n"+
			"  done.", run, mig.Phase, run, lo)
	}
	return nil
}

// sourcePresence tells a genuinely-absent source apart from one that could not be asked about.
// COULD-NOT-ASK IS NOT ABSENT: a detach planned against a network we could not ask about is a
// detach planned in the dark.
func sourcePresence(ctx context.Context, objs Objects, src string) (bool, error) {
	_, err := objs.NetworkID(ctx, src)
	if errors.Is(err, engine.ErrAbsent) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("netref: the source network (%s) could not be inspected, so whether this is a\n"+
			"  forward-only migration or a source that is genuinely gone cannot be told apart.\n"+
			"  'Could not ask' is not 'absent' — stopping without detaching. Run 'mythical-ctl\n"+
			"  state repair': %w", src, err)
	}
	return true, nil
}

// MigRun executes ONE phase.
func MigRun(ctx context.Context, l *ledger.Ledger, d MigDeps, src, tgt string, phase int) error {
	if src == "" || tgt == "" {
		return errors.New("netref: a migration needs both a source and a target network id. Nothing is done.")
	}
	if src == tgt {
		return fmt.Errorf("netref: the migration source and target are the same network (%s). Phase 4 would detach\n"+
			"  the only network the family is on, leaving every container attached to nothing.\n"+
			"  Nothing is done.", src)
	}
	cs, err := fleetFor(ctx, l, d.Objs)
	if err != nil {
		return err
	}
	switch phase {
	case 1:
		return migRecord(l, 1, src, tgt, cs)

	case 2:
		// CONNECT EVERY CONTAINER BEFORE ANY LEAVES THE OLD NETWORK. The target goes on at a
		// LOWER gateway priority (-1) than the source, so attaching it does not move the default
		// route out from under a running fleet mid-migration.
		// THE PHASE MARKER IS DURABLE BEFORE THE PHASE ACTS, and recording it is ONE step with the
		// write. A crash with disk saying nothing at all would leave containers attached to the
		// target with no record that a migration is under way — and bring-up's exact-set check
		// would then refuse every one of them.
		if err := staged(d.Deps, l, "connect the fleet to the target network", func(c *ledger.Ledger) error {
			return migRecord(c, 2, src, tgt, cs)
		}); err != nil {
			return err
		}
		for _, c := range cs {
			alias, aerr := aliasFor(l, c)
			if aerr != nil {
				return aerr
			}
			nets, nerr := d.Objs.ContainerNets(ctx, c)
			if nerr != nil {
				return nerr
			}
			already := false
			for _, n := range nets {
				if n.NetworkID == tgt {
					already = true
				}
			}
			if already {
				continue
			}
			if cerr := d.Mut.NetworkConnect(ctx, tgt, c, alias, -1); cerr != nil {
				return fmt.Errorf("netref: could not connect %q to the target network. Stopping in phase 2 — every\n"+
					"  container must be on the new network before any leaves the old one: %w", c, cerr)
			}
		}
		return nil

	case 3:
		return migPhase3(ctx, l, d, src, tgt, cs)

	case 4:
		if err := admits(l, 4, src, tgt, 3, 4); err != nil {
			return err
		}
		// THE MARKER IS DURABLE BEFORE THE FIRST DETACH — this is the destructive phase, and the
		// one where a stale marker wedges the migration. If disk still said phase 3 while some
		// containers were already detached, a resume would re-run phase 3, whose exact-set check
		// requires {source,target}, and REFUSE exactly the containers this phase had already
		// finished. The fleet would be half-migrated with no phase to move forward from.
		if err := staged(d.Deps, l, "detach the fleet from the source network", func(c *ledger.Ledger) error {
			return migRecord(c, 4, src, tgt, cs)
		}); err != nil {
			return err
		}
		for _, c := range cs {
			// RE-INSPECT before detaching: phase 3's verification is a fact about the past, and
			// detaching a container no longer on the target leaves it on NEITHER network.
			ok, oerr := onTarget(ctx, d, c, tgt)
			if oerr != nil {
				return oerr
			}
			if !ok {
				return fmt.Errorf("netref: phase 4: %q is not confirmed attached to the target network, so detaching\n"+
					"  it from the source would leave it on neither. Stopping without detaching — the\n"+
					"  intent stays at phase 4 and the migration resumes. Reconnect %q to the target, or\n"+
					"  run 'mythical-ctl state repair', then re-run.", c, c)
			}
			// A detach that fails is not fatal here — phase 5 catches a SILENTLY failed one by
			// re-verifying the exact set, which is the check that must not be skipped.
			_ = d.Mut.NetworkDisconnect(ctx, src, c)
		}
		return nil

	case 5:
		for _, c := range cs {
			alias, aerr := aliasFor(l, c)
			if aerr != nil {
				return aerr
			}
			if verr := targetOnlyOK(ctx, d, c, tgt, alias); verr != nil {
				return fmt.Errorf("netref: phase 5 verification failed for %q. STAYING IN PHASE 4 with the intent\n"+
					"  intact, so the migration resumes rather than committing over an unverified fleet —\n"+
					"  committing now would leave a container on {source,target} with no intent recorded,\n"+
					"  which nothing can resume: %w", c, verr)
			}
		}
		if eerr := d.Probe.Egress(ctx, d.Index, tgt); eerr != nil {
			return fmt.Errorf("netref: phase 5: egress on the target network does not work. Staying in phase 4: %w", eerr)
		}
		return migRecord(l, 5, src, tgt, cs)

	case 6:
		if err := admits(l, 6, src, tgt, 5, 5); err != nil {
			return err
		}
		for _, c := range cs {
			alias, aerr := aliasFor(l, c)
			if aerr != nil {
				return aerr
			}
			if verr := targetOnlyOK(ctx, d, c, tgt, alias); verr != nil {
				return fmt.Errorf("netref: phase 6: %q is no longer on the target network alone, so committing the\n"+
					"  reference and clearing the intent now would strand it mid-migration with nothing to\n"+
					"  resume from — the split phase 5 exists to prevent. STOPPING with the intent intact;\n"+
					"  the migration stays resumable. Run 'mythical-ctl state repair' if this persists: %w", c, verr)
			}
		}
		if cerr := RefCommit(ctx, l, d.Objs, tgt, d.Configured); cerr != nil {
			return fmt.Errorf("netref: phase 6 recorded nothing, so the migration intent is KEPT and this stays\n"+
				"  resumable. The containers are already on %s; clearing the intent without recording\n"+
				"  where they are would leave the fleet on a network the ledger does not name.\n"+
				"  Decide which network you want and re-run 'mythical-ctl net rebind': %w", tgt, cerr)
		}
		return l.Del(kindNetMig, "key", "family")
	}
	return fmt.Errorf("netref: %d is not a migration phase", phase)
}

// migPhase3 is the verification phase, and the one that decides whether phase 4 may ever detach.
//
// EVERY EDIT IT MAKES LANDS ON A CLONE, PUBLISHED ONLY WHEN THE WHOLE FLEET HAS PASSED. This
// phase writes as it walks: a stopped container's deferred alias check is committed at the moment
// that container is confirmed attached. Committing those into the caller's ledger as it went made
// a fleet whose SECOND container failed verification return an error with the marker still at
// phase 2 while the FIRST container's desired state and owed check had ALREADY changed — a
// half-verified fleet recorded as if the phase had run for part of it, which no later phase can
// resume from. A refusal must leave the caller's ledger exactly as it found it, and that includes
// the phase-3 marker itself: the marker and the commits it stands for move together or not at all.
//
// THE CLONE IS ALSO WHAT THE VERIFIERS ARE ASKED AGAINST. Both seams take the ledger precisely so
// they read the one this phase is advancing (see AttachVerifier); handing them `l` while the edits
// went to a copy would answer from a ledger missing what this phase has already established, which
// is the same wrong-ledger mismatch the seam exists to make impossible.
func migPhase3(ctx context.Context, l *ledger.Ledger, d MigDeps, src, tgt string, cs []string) error {
	cp := l.Clone()
	if err := migPhase3On(ctx, cp, d, src, tgt, cs); err != nil {
		return err
	}
	return l.Adopt(cp)
}

// migPhase3On is phase 3 against ONE ledger — the staged clone. It is a separate function rather
// than an inline block so that every ledger reference in the body IS the staged one: where both
// were in scope, a single missed substitution would restore the defect silently and nothing about
// the code would look wrong.
func migPhase3On(ctx context.Context, l *ledger.Ledger, d MigDeps, src, tgt string, cs []string) error {
	srcPresent, err := sourcePresence(ctx, d.Objs, src)
	if err != nil {
		return err
	}
	if err := d.Probe.SelfCheck(ctx, d.Index, tgt); err != nil {
		return fmt.Errorf("netref: stopping at phase 3. Nothing is detached — proceeding unverified because the\n"+
			"  checker was unavailable is the failure this phase exists to prevent: %w", err)
	}
	for _, c := range cs {
		alias, aerr := aliasFor(l, c)
		if aerr != nil {
			return aerr
		}
		obs, oerr := state.Observe(ctx, d.State, c)
		if oerr != nil {
			return oerr
		}
		out, serr := state.Outstanding(l, c)
		if serr != nil {
			return fmt.Errorf("netref: could not read the outstanding checks for %q, so whether this migration\n"+
				"  would strand one cannot be established. Stopping without detaching: %w", c, serr)
		}
		// AN ALIAS CHECK OWED ON THE SOURCE would be unsatisfiable after phase 4 removes that
		// network — the container would stay unreconciled forever.
		for _, ch := range out {
			if ch.Kind == state.CheckAlias && ch.Param == src {
				return fmt.Errorf("netref: %q owes an alias check on the SOURCE network, which phase 4 removes — after\n"+
					"  which nothing could ever satisfy it and the container would stay unreconciled\n"+
					"  forever. Refusing to migrate it into that state. Start %q to discharge the check,\n"+
					"  or run 'mythical-ctl state repair', then re-run the migration.", c, c)
			}
		}
		if obs != state.ObsRunning {
			// A STOPPED container has no address to answer with, so its check is DEFERRED — but
			// only once it is confirmed attached to the target.
			if srcPresent {
				if verr := d.Attach.VerifyAttach(ctx, l, c, tgt, alias); verr != nil {
					return fmt.Errorf("netref: phase 3: %q is stopped and is NOT confirmed attached to the target\n"+
						"  network — a connect returned success but the attachment is not there. Stopping\n"+
						"  without detaching: %w", c, verr)
				}
			} else {
				if verr := targetOnlyOK(ctx, d, c, tgt, alias); verr != nil {
					return fmt.Errorf("netref: phase 3: %q is stopped and is not on the target network alone (the source\n"+
						"  is gone, so this is a forward-only migration). Stopping without detaching: %w", c, verr)
				}
			}
			want, werr := state.DesiredGet(l, c)
			if werr != nil {
				return fmt.Errorf("netref: %q is stopped and this installation has no readable record of what state\n"+
					"  it is meant to be in, so the deferred check cannot be recorded without inventing\n"+
					"  an intent for it. Stopping without detaching. Run 'mythical-ctl state repair': %w", c, werr)
			}
			if cerr := state.Commit(l, c, want, []state.Check{{Kind: state.CheckAlias, Param: tgt}}, false); cerr != nil {
				return cerr
			}
			continue
		}
		if srcPresent {
			verr := d.Live.VerifyLive(ctx, l, d.Index, c, tgt, alias)
			if errors.Is(verr, ErrProbeUnavailable) {
				return fmt.Errorf("netref: phase 3 could not verify %q — the probe itself did not run, so nothing was\n"+
					"  established either way. Stopping without detaching: %w", c, verr)
			}
			if verr != nil {
				return fmt.Errorf("netref: phase 3 verification failed for %q on the target network.\n"+
					"  Resolution is compared against the sibling's endpoint address on the TARGET\n"+
					"  NETWORK — during phase 2 every container is on BOTH networks and aliases\n"+
					"  are network-scoped, so a name resolving via the OLD network proves nothing about\n"+
					"  the new one. Stopping without detaching: %w", c, verr)
			}
		} else {
			if verr := targetOnlyOK(ctx, d, c, tgt, alias); verr != nil {
				return fmt.Errorf("netref: phase 3 verification failed for %q on the target network (forward-only —\n"+
					"  the source is gone, so the container must be on the target alone). Stopping without\n"+
					"  detaching: %w", c, verr)
			}
		}
	}
	if srcPresent {
		// EGRESS THROUGH THE SOURCE must still work: if it does not, attaching the target moved
		// the route despite the lower gateway priority.
		if eerr := d.Probe.Egress(ctx, d.Index, src); eerr != nil {
			return fmt.Errorf("netref: egress through the SOURCE network is no longer working in phase 3, which means\n"+
				"  attaching the target moved the route despite the lower gateway priority. Stopping: %w", eerr)
		}
	}
	return migRecord(l, 3, src, tgt, cs)
}

// ForwardOnlyAdvisory is what a resume must tell the operator when the SOURCE network is gone.
//
// Returned as data for the same reason as intent.AbandonAdvisory: it is a success-path statement,
// and it is load-bearing — it says plainly that there is nothing to roll back to, rather than
// hiding behind a rollback promise that could not be kept.
const ForwardOnlyAdvisory = "netref: the previous network no longer exists, so this migration is forward-only:\n" +
	"  there is nothing to detach and nothing to return to. Phases 3 and 5 verify each container\n" +
	"  against exactly {target} rather than {source,target}, so the migration completes FORWARD\n" +
	"  rather than wedging on a source that is gone."

// MigResume reads the recorded phase and CONTINUES FORWARD — never unwinds. Once containers are on
// both networks there is nothing to unwind to. It returns the advisory the caller must surface
// (empty unless the migration turned out to be forward-only).
func MigResume(ctx context.Context, l *ledger.Ledger, d MigDeps) (string, error) {
	mig, err := MigGet(l)
	if err != nil {
		return "", err
	}
	if mig.Source == "" {
		return "", errors.New("netref: the recorded migration intent names no source network.\n" +
			"  Phase 4 cannot know what to detach, and after a crash there is no other way to learn it:\n" +
			"  the containers may by then be on two networks with nothing to say which was the old one.\n" +
			"  An intent naming only the target cannot complete its own migration. Manual recovery:\n" +
			"  inspect each container's attachments and detach the one that is not the target.")
	}
	if mig.Target == "" {
		return "", errors.New("netref: the recorded migration intent names no target network, so there is nothing to\n" +
			"  migrate onto. It is PRESERVED and reported. Run 'mythical-ctl state repair'.")
	}
	// A source that is GONE makes this FORWARD-ONLY, which is stated rather than hidden behind a
	// rollback promise that could not be kept. A source that could not be ASKED about stops.
	present, perr := sourcePresence(ctx, d.Objs, mig.Source)
	if perr != nil {
		return "", fmt.Errorf("netref: whether the previous network (%s) still exists could not be established, so\n"+
			"  nothing is resumed. A detach planned against a network we could not ask about is a\n"+
			"  detach planned in the dark: %w", mig.Source, perr)
	}
	advisory := ""
	if !present {
		advisory = ForwardOnlyAdvisory
	}
	for p := mig.Phase; p <= phaseLast; p++ {
		if err := MigRun(ctx, l, d, mig.Source, mig.Target, p); err != nil {
			return "", err
		}
	}
	return advisory, nil
}

// Rebind starts a migration onto `target` and runs it to completion.
func Rebind(ctx context.Context, l *ledger.Ledger, d MigDeps, target string) (string, error) {
	if target == "" {
		return "", errors.New("netref: a rebind needs a resolved target network id, not an empty one.")
	}
	// A SECOND MIGRATION OVER A FIRST would write over the only record of where the fleet came
	// from.
	_, merr := MigGet(l)
	switch {
	case errors.Is(merr, ErrNoMigration):
	case merr == nil:
		return "", errors.New("netref: a network migration is already recorded. Refusing to start a second one over\n" +
			"  it — its intent is the only record of where the fleet came from. Resume it with\n" +
			"  'mythical-ctl net rebind'.")
	default:
		return "", fmt.Errorf("netref: whether a migration is already under way could not be read from the ledger.\n"+
			"  Starting one now would write over an intent nobody could read. Nothing is started: %w", merr)
	}
	ident, ierr := l.IdentGet()
	if ierr != nil {
		return "", ierr
	}
	cs, cerr := d.Objs.ContainersByInstall(ctx, ident)
	if cerr != nil {
		return "", cerr
	}
	if len(cs) == 0 {
		// NOTHING TO MIGRATE: record the new reference directly, and there is no advisory — no
		// fleet moved, so nothing about rollback needs saying.
		return "", RefCommit(ctx, l, d.Objs, target, d.Configured)
	}
	src, serr := RefGet(l)
	switch {
	case serr == nil:
	case errors.Is(serr, ErrNoReference):
		oname, nerr := manifest.NetworkName(ident)
		if nerr != nil {
			return "", nerr
		}
		rec, perr := prov.Find(l, prov.ClassNetwork, oname)
		switch {
		case perr == nil:
			src, serr = adoptOwned(ctx, d.Objs, rec, oname)
			if serr != nil {
				return "", serr
			}
		case errors.Is(perr, prov.ErrMismatch):
			// The record answers for this name and describes another object: reported as itself
			// rather than as a ledger that could not be read (see aliasFor).
			return "", perr
		case errors.Is(perr, ledger.ErrAbsentRecord):
			return "", errors.New("netref: there is no reference to migrate FROM and no installer-owned network is\n" +
				"  recorded, yet containers exist — where the fleet is cannot be established, so\n" +
				"  phase 4 would not know what to detach. Run 'mythical-ctl state repair'.")
		default:
			return "", fmt.Errorf("netref: whether this installation has its own network could not be read, so the\n"+
				"  migration source is unknown. Nothing is started: %w", perr)
		}
	default:
		return "", fmt.Errorf("netref: the recorded network reference could not be read, so phase 4 would not know what\n"+
			"  to detach. Nothing is started: %w", serr)
	}
	if err := MigRun(ctx, l, d, src, target, 1); err != nil {
		return "", err
	}
	return MigResume(ctx, l, d)
}
