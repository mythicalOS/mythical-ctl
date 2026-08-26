// Package bringup is the create → verify-attach → start → verify-live sequence, and the recovery
// paths that finish or unwind it after a crash.
//
// THE RULE THE WHOLE SEQUENCE ENFORCES: verification failures REFUSE FORWARD PROGRESS and record
// an outstanding check — never "probably fine". A container is confirmed only once its topology
// has been proved, and its live check is retired only once the alias has actually resolved to its
// own endpoint address.
//
// The order is load-bearing at every step:
//   - the intent is opened BEFORE the container is created, carrying the desired state and the
//     check this bring-up owes, so a crash between them leaves a record that says what was being
//     built;
//   - the attachment is verified BEFORE anything is confirmed, and a container that does not
//     verify is REMOVED (a confirmed-but-detached container is a state this sequence must never
//     produce) — but only if it still carries the nonce we created it with;
//   - the desired state and the outstanding check are committed BEFORE the confirmation, so a
//     crash cannot leave a container accounted for with no desired state;
//   - the check is cleared only AFTER the live verification passes.
package bringup

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
	"time"
)

var (
	// ErrProbeUnavailable — the probe itself did not run, so NOTHING was established either way.
	// Distinct from a failed check: a caller may not treat it as a verdict. It is netref's error,
	// re-exported, because the two packages hand it to each other across the verifier seam.
	ErrProbeUnavailable = netref.ErrProbeUnavailable
	// ErrRebuild — the container is gone and must be re-created from the launch spec, which this
	// package does not hold. The verb that owns the spec acts on it.
	ErrRebuild = errors.New("bringup: the container must be rebuilt from its launch spec")
	// ErrRetained — the intent is kept for the verb that opened it.
	ErrRetained = errors.New("bringup: the intent is retained")
)

// Attachment is one resolved network attachment, with the aliases the endpoint registered.
type Attachment struct {
	NetworkID string
	Address   string
	Aliases   []string
}

// Objects is the read side.
type Objects interface {
	// Attachments lists a container's attachments with network ids RESOLVED — a never-started
	// container reports an EMPTY endpoint id, so only the network NAME identifies it until first
	// start, and resolution has to happen before any comparison.
	Attachments(ctx context.Context, container string) ([]Attachment, error)
	// Label reads one provenance label off the container.
	Label(ctx context.Context, container, label string) (string, error)
	// Image reports the image the container was created from.
	Image(ctx context.Context, container string) (string, error)
}

// Mutator is the write side; *runtime.Runtime satisfies it.
type Mutator interface {
	ContainerStart(ctx context.Context, id string) error
	ContainerStop(ctx context.Context, id string) error
	ContainerRemove(ctx context.Context, id string) error
}

// Prober is the live-resolution seam. *probe.Prober satisfies it.
type Prober interface {
	SelfCheck(ctx context.Context, ix *trust.Index, netID string) error
	Resolve(ctx context.Context, ix *trust.Index, netID, alias string) (string, error)
}

// Launcher creates the container. It is an interface rather than a direct call because
// internal/runtime's LaunchProduct is the SOLE creation site (check.sh's boundary rule), and this
// package must reach it without becoming a second one.
type Launcher interface {
	Launch(ctx context.Context, container, nonce string) (string, error)
}

// Deps is everything a bring-up needs beyond the ledger.
type Deps struct {
	Objs     Objects
	Mut      Mutator
	Probe    Prober
	State    state.Objects
	Index    *trust.Index
	NewNonce func() (string, error)
	// Now is the clock the intent's creation time comes from.
	Now func() time.Time
}

// Desired is the desired state a bring-up records, plus `preserve`.
type Desired string

const (
	Running  Desired = "running"
	Stopped  Desired = "stopped"
	Preserve Desired = "preserve"
)

// permittedNets is the EXACT SET a container's attachments must equal.
//
// Normally that is {target}. During a RECORDED MIGRATION it is {source, target} — during phase 2
// every container is legitimately on both. A migration record that names only one of them REFUSES
// rather than narrowing the set: narrowing is how a half-migrated container gets recorded as
// verified. So does a record that cannot be read — assuming there is no migration narrows the set
// by another route.
func permittedNets(l *ledger.Ledger, want string) ([]string, error) {
	mig, err := netref.MigGet(l)
	switch {
	case errors.Is(err, netref.ErrNoMigration):
		return []string{want}, nil
	case err != nil:
		return nil, fmt.Errorf("bringup: cannot read whether a network migration is in progress.\n"+
			"  Refusing rather than assuming there is none — assuming would narrow the permitted\n"+
			"  set and accept a container standing half-way through one: %w", err)
	}
	if mig.Source == "" || mig.Target == "" {
		return nil, errors.New("bringup: a network migration is recorded but does not name both networks.\n" +
			"  Refusing to verify against a narrower set than the record implies — that is\n" +
			"  how a half-migrated container gets recorded as verified. Run 'mythical-ctl state repair'.")
	}
	return []string{mig.Source, mig.Target}, nil
}

// attachOK is the EXACT-SET check. "Is ours among them" is what lets a stray default bridge
// survive, so every attachment must be permitted, the expected one must be present, and each
// permitted network must appear EXACTLY ONCE — the same network attached twice is not the same as
// attached once.
func attachOK(l *ledger.Ledger, container, want, alias string, nets []Attachment) error {
	if len(nets) == 0 {
		return fmt.Errorf("bringup: %q is attached to NO network at all.\n"+
			"  Its network set must be exactly {%s}.", container, want)
	}
	permitted, err := permittedNets(l, want)
	if err != nil {
		return err
	}
	isPermitted := func(id string) bool {
		for _, p := range permitted {
			if p == id {
				return true
			}
		}
		return false
	}
	for _, n := range nets {
		if !isPermitted(n.NetworkID) {
			return fmt.Errorf("bringup: %q is attached to network %q, which is not permitted.\n"+
				"  Its network set must be exactly {%v} — 'is ours among them' is what lets a\n"+
				"  stray default bridge survive.", container, n.NetworkID, permitted)
		}
	}
	found := false
	for _, n := range nets {
		if n.NetworkID == want {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("bringup: %q is not attached to the expected network %q.", container, want)
	}
	for _, p := range permitted {
		count := 0
		for _, n := range nets {
			if n.NetworkID == p {
				count++
			}
		}
		switch {
		case count == 1:
		case count == 0:
			return fmt.Errorf("bringup: %q is NOT attached to network %q.\n"+
				"  Its network set must be exactly {%v}.\n"+
				"  A subset is not the set: during a recorded migration a container standing on only one\n"+
				"  of the two is mid-move, not reconciled, and this is the check whose success retires\n"+
				"  the outstanding verification.", container, p, permitted)
		default:
			return fmt.Errorf("bringup: %q is attached to network %q %d times.\n"+
				"  Its network set must be exactly {%v} — one endpoint per network.", container, p, count, permitted)
		}
	}
	// THE ALIAS, on the expected network. Siblings resolve a product by its alias; without it,
	// family DNS fails silently.
	for _, n := range nets {
		if n.NetworkID != want {
			continue
		}
		for _, a := range n.Aliases {
			if a == alias {
				return nil
			}
		}
		return fmt.Errorf("bringup: %q does not carry the alias %q on network %q (has: %v)\n"+
			"  Siblings resolve a product by its alias; without it, family DNS fails silently.",
			container, alias, want, n.Aliases)
	}
	return fmt.Errorf("bringup: %q has no alias recorded on network %q", container, want)
}

// VerifyAttach proves a container's topology. It works PRE-START, which is why the attachments
// arrive with their network ids already resolved from the endpoint's network NAME.
func VerifyAttach(ctx context.Context, l *ledger.Ledger, d Deps, container, netID, alias string) error {
	nets, err := d.Objs.Attachments(ctx, container)
	if err != nil {
		return err
	}
	return attachOK(l, container, netID, alias, nets)
}

// VerifyLive proves the alias RESOLVES, on this network, to this container's own endpoint address.
//
// It asks the COMPLETE attachment set first, not just the address on the target: a container that
// has gained an EXTRA network since the attach check is not verified, and clearing its outstanding
// check would retire a verification nothing performed.
func VerifyLive(ctx context.Context, l *ledger.Ledger, d Deps, container, netID, alias string) error {
	nets, err := d.Objs.Attachments(ctx, container)
	if err != nil {
		return err
	}
	if aerr := attachOK(l, container, netID, alias, nets); aerr != nil {
		return aerr
	}
	expect := ""
	for _, n := range nets {
		if n.NetworkID == netID {
			expect = n.Address
		}
	}
	if expect == "" {
		return fmt.Errorf("bringup: %q has no endpoint address on %q — it is not running, so its alias has\n"+
			"  no endpoint to answer with. Deferring the check to its next explicit start.", container, netID)
	}
	if serr := d.Probe.SelfCheck(ctx, d.Index, netID); serr != nil {
		return fmt.Errorf("%w: %v", ErrProbeUnavailable, serr)
	}
	resolved, rerr := d.Probe.Resolve(ctx, d.Index, netID, alias)
	if rerr != nil {
		// A PROBE THAT DID NOT RUN IS NOT A VERDICT; only a definite "did not resolve" is, and
		// probe.ErrNotResolved is what says so. Folding the two would let an unavailable checker
		// retire a verification nothing performed — the failure the whole probe arm exists to
		// prevent — and folding them the other way would keep a genuinely broken alias outstanding
		// forever under the heading "could not check".
		if errors.Is(rerr, probe.ErrNotResolved) {
			return fmt.Errorf("bringup: the alias %q does not resolve on network %q.", alias, netID)
		}
		return fmt.Errorf("%w: %v", ErrProbeUnavailable, rerr)
	}
	if resolved != expect {
		return fmt.Errorf("bringup: %q resolves to %q on network %q, but %q is at %q.\n"+
			"  The name resolves — via something other than this network's endpoint for this container.",
			alias, resolved, netID, container, expect)
	}
	return nil
}

// Create opens the intent and creates the container STOPPED. It returns the nonce the intent and
// the container both carry.
//
// The intent records the desired state AND the check this bring-up owes, together, before the
// container exists — an intent that records a start without recording what proving it costs is
// exactly the state an empty outstanding set must never be allowed to mean.
func Create(ctx context.Context, l *ledger.Ledger, d Deps, launch Launcher, container, netID string, want state.Desired) (string, error) {
	if want != state.Running && want != state.Stopped {
		return "", fmt.Errorf("bringup: %q is not a desired state a container can be created with", string(want))
	}
	nonce, err := d.NewNonce()
	if err != nil {
		return "", err
	}
	if err := intent.Open(l, prov.ClassContainer, container, nonce, d.Now(),
		ledger.Field{Key: "desired", Value: string(want)},
		ledger.Field{Key: "check", Value: string(state.CheckAlias)},
		ledger.Field{Key: "check_param", Value: netID},
	); err != nil {
		return "", err
	}
	// THE INTENT IS ON THE LEDGER IN MEMORY BEFORE THE CONTAINER EXISTS. The caller persists it,
	// and does so BEFORE calling Run — the write-ahead property is the caller's to keep, and the
	// intent is worthless if the container is created first.
	if _, err := launch.Launch(ctx, container, nonce); err != nil {
		return "", err
	}
	return nonce, nil
}

// Run is the full sequence.
func Run(ctx context.Context, l *ledger.Ledger, d Deps, launch Launcher, container, netID, alias string, desired Desired) error {
	var want state.Desired
	switch desired {
	case Running:
		want = state.Running
	case Stopped:
		want = state.Stopped
	case Preserve:
		// PRESERVE WITH NOTHING RECORDED IS A USAGE ERROR, not a silent running: guessing
		// 'running' would start something nobody asked for, and 'stopped' would take a working
		// install down.
		w, err := state.DesiredGet(l, container)
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return fmt.Errorf("bringup: asked to preserve the desired state of %q, but there is no desired state\n"+
				"  recorded for it. Refusing to guess: 'running' would start something nobody asked\n"+
				"  for, and 'stopped' would take a working install down.", container)
		}
		if err != nil {
			return err
		}
		want = w
	default:
		return fmt.Errorf("bringup: %q is not running, stopped or preserve", string(desired))
	}

	nonce, err := Create(ctx, l, d, launch, container, netID, want)
	if err != nil {
		return err
	}
	if verr := VerifyAttach(ctx, l, d, container, netID, alias); verr != nil {
		// REMOVED — but only if it still carries the nonce we created it with. Something else
		// standing at that name is left alone.
		actual, lerr := d.Objs.Label(ctx, container, prov.LabelNonce)
		if lerr == nil && actual == nonce {
			_ = d.Mut.ContainerRemove(ctx, container)
			return fmt.Errorf("bringup: removed %q because it did not verify. Nothing was confirmed: %w", container, verr)
		}
		return fmt.Errorf("bringup: %q did not verify AND no longer carries the nonce we created it with —\n"+
			"  something else holds that name. It is left alone. Nothing was confirmed: %w", container, verr)
	}
	// THE COMMIT COMES BEFORE THE CONFIRMATION: a crash between them must not leave a container
	// accounted for with no desired state.
	if cerr := state.Commit(l, container, want, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false); cerr != nil {
		return cerr
	}
	image, _ := d.Objs.Image(ctx, container)
	if cerr := intent.Confirm(l, prov.ClassContainer, container, nonce, ledger.Field{Key: "id", Value: image}); cerr != nil {
		return cerr
	}
	if want == state.Stopped {
		// A STOPPED BRING-UP KEEPS THE OUTSTANDING ENTRY rather than clearing or performing it:
		// a stopped container has no address for its alias to answer with.
		return nil
	}
	if serr := d.Mut.ContainerStart(ctx, container); serr != nil {
		return fmt.Errorf("bringup: %q was created and confirmed, but did not start: %w", container, serr)
	}
	// THE LIVE ADDRESS IS READ BY RE-INSPECTING AFTER THE START — a container's endpoint address
	// is assigned at start, so the pre-start inspect has nothing to compare against.
	verr := VerifyLive(ctx, l, d, container, netID, alias)
	if verr == nil {
		return state.OutstandingClear(l, container, state.CheckAlias, netID)
	}
	if errors.Is(verr, ErrProbeUnavailable) {
		return fmt.Errorf("bringup: %q is running, but the probe could not run, so its alias was not verified: %w", container, verr)
	}
	return fmt.Errorf("bringup: %q is running, but its alias did not verify. It is left running and the check\n"+
		"  remains outstanding; it will be retried on the next operation: %w", container, verr)
}

// Recover finishes a bring-up that crashed after the container was created.
//
// It reads what the INTENT recorded — the desired state and the check — rather than defaulting
// either: confirming an intent that does not say what was being built would consume the only
// record of it and leave the container accounted for, never started and never verified.
func Recover(ctx context.Context, l *ledger.Ledger, d Deps, container, netID, alias string) error {
	rec, err := intent.Find(l, prov.ClassContainer, container)
	if err != nil {
		return err
	}
	nonce, ok := ledger.FieldOf(rec, "nonce")
	if !ok || nonce == "" {
		return fmt.Errorf("bringup: the intent for %q carries no nonce, so nothing can say which container it\n"+
			"  describes. It is PRESERVED and reported. Run 'mythical-ctl state repair'.", container)
	}
	wantStr, ok := ledger.FieldOf(rec, "desired")
	if !ok {
		return fmt.Errorf("bringup: the intent for %q does not say which desired state this bring-up was recording.\n"+
			"  Confirming it would consume the only record of what was being built and leave the\n"+
			"  container accounted for, never started and never verified. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", container)
	}
	want := state.Desired(wantStr)
	if want != state.Running && want != state.Stopped {
		return fmt.Errorf("bringup: the intent for %q records desired state %q, which is neither running nor\n"+
			"  stopped — and that value is on DISK, in the intent, not in this call. The container and the\n"+
			"  intent are both PRESERVED. Run 'mythical-ctl state repair'.", container, wantStr)
	}
	check, ok := ledger.FieldOf(rec, "check")
	if !ok {
		return fmt.Errorf("bringup: the intent for %q does not say what check this bring-up owed. An intent that\n"+
			"  records a start without recording what proving it costs is the state D50 refuses to let\n"+
			"  an empty outstanding set mean. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", container)
	}
	if check != string(state.CheckAlias) {
		return fmt.Errorf("bringup: the intent for %q records a %q check, which is not a kind this core defines.\n"+
			"  It is PRESERVED and reported. Run 'mythical-ctl state repair'.", container, check)
	}
	param, _ := ledger.FieldOf(rec, "check_param")
	if param == "" {
		return fmt.Errorf("bringup: the intent for %q records a %q check that names nothing to verify.\n"+
			"  An 'alias' check carries the network the alias must resolve on, and one carrying nothing\n"+
			"  can never be matched and so can never be cleared. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", container, check)
	}
	if param != netID {
		return fmt.Errorf("bringup: the intent for %q was opened for network %q, and this recovery was asked\n"+
			"  about %q. Those are two different bring-ups. Nothing is confirmed, nothing is\n"+
			"  removed, and nothing is recorded.", container, param, netID)
	}
	obs, oerr := state.Observe(ctx, d.State, container)
	if oerr != nil {
		return oerr
	}
	if obs == state.ObsAbsent {
		return fmt.Errorf("bringup: the intent for %q names a container that does not exist; retaining the intent\n"+
			"  so the verb that opened it can re-create it from the launch spec: %w", container, ErrRetained)
	}
	actual, lerr := d.Objs.Label(ctx, container, prov.LabelNonce)
	if lerr != nil {
		return fmt.Errorf("bringup: the nonce of %q could not be read, so whether it is the container this intent\n"+
			"  describes was never established. Nothing is confirmed and nothing is removed: %w", container, lerr)
	}
	if actual != nonce {
		return fmt.Errorf("bringup: %q exists but carries nonce %q, not the recorded %q.\n"+
			"  It is NOT adopted and NOT removed. Resolve it with the container runtime, then re-run.",
			container, actual, nonce)
	}
	if verr := VerifyAttach(ctx, l, d, container, netID, alias); verr != nil {
		_ = d.Mut.ContainerRemove(ctx, container)
		return fmt.Errorf("bringup: removed %q — it was created but its topology does not verify, and a\n"+
			"  confirmed-but-detached container is a state this sequence must never produce: %w",
			container, errors.Join(ErrRebuild, verr))
	}
	if cerr := state.Commit(l, container, want, []state.Check{{Kind: state.CheckAlias, Param: param}}, false); cerr != nil {
		return cerr
	}
	image, _ := d.Objs.Image(ctx, container)
	return intent.Confirm(l, prov.ClassContainer, container, nonce, ledger.Field{Key: "id", Value: image})
}

// Reconcile acts on the plan the state module computes, and NOTHING else — every branch is one of
// its verdicts, so the reconciler and the planner cannot disagree about what a situation means.
func Reconcile(ctx context.Context, l *ledger.Ledger, d Deps, container, netID, alias string) error {
	plan, err := state.PlanFor(ctx, l, d.State, container)
	if err != nil {
		return err
	}
	switch plan {
	case state.PlanNone:
		return nil
	case state.PlanSuspended:
		// The reconciler must not restart a container a migration deliberately stopped.
		return nil
	case state.PlanDefer:
		// A stopped container has no address, so there is nothing to resolve; the check is
		// performed at its next start.
		return nil
	case state.PlanExited:
		return fmt.Errorf("bringup: %q should be running and is not, and this installer has ALREADY resumed it\n"+
			"  once under the intent currently recorded. It does not stay up. Reported rather than\n"+
			"  started again — restarting on every pass is the loop the attempt record exists to\n"+
			"  stop. Re-stating the intent grants a fresh attempt.", container)
	case state.PlanRebuild:
		return ErrRebuild
	case state.PlanStop:
		if serr := d.Mut.ContainerStop(ctx, container); serr != nil {
			return fmt.Errorf("bringup: %q should be stopped but stopping it failed. Reported once, not retried: %w", container, serr)
		}
		return nil
	case state.PlanVerify:
		if verr := VerifyLive(ctx, l, d, container, netID, alias); verr != nil {
			return fmt.Errorf("bringup: the outstanding verification for %q failed again. Left running, still\n"+
				"  outstanding, reported once: %w", container, verr)
		}
		return state.OutstandingClear(l, container, state.CheckAlias, netID)
	case state.PlanStartVerify:
		// THE ATTEMPT IS RECORDED BEFORE IT IS MADE. A crash between starting and recording would
		// leave the next run believing it had never tried, which is the restart loop.
		if rerr := state.ResumeRecord(l, container); rerr != nil {
			return rerr
		}
		if serr := d.Mut.ContainerStart(ctx, container); serr != nil {
			return fmt.Errorf("bringup: %q should be running but did not start. Attempted ONCE this run and\n"+
				"  reported as a failure — never retried in a loop, because a container that exits\n"+
				"  immediately on a broken image would become an invisible restart cycle: %w", container, serr)
		}
		if verr := VerifyLive(ctx, l, d, container, netID, alias); verr != nil {
			return fmt.Errorf("bringup: %q started but its alias did not verify. Left running, still outstanding: %w", container, verr)
		}
		return state.OutstandingClear(l, container, state.CheckAlias, netID)
	}
	return fmt.Errorf("bringup: internal error — unknown plan %q", string(plan))
}
