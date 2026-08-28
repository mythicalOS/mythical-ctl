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
//     produce) — but ONLY if it can be proven ours, which the nonce alone does not prove: the
//     installation label is read first, because a nonce says WHICH object and never WHOSE;
//   - the desired state and the outstanding check are committed BEFORE the confirmation, so a
//     crash cannot leave a container accounted for with no desired state;
//   - the check is cleared only AFTER the live verification passes.
package bringup

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/engine"
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
	// Persist commits THE LEDGER IT IS GIVEN to disk. It is REQUIRED, and it is the whole of the
	// write-ahead guarantee.
	//
	// IT TAKES THE LEDGER RATHER THAN CLOSING OVER ONE. A closure captured at construction stays
	// bound to the ledger that existed then, so a caller that reloads (recovery does exactly that)
	// and reuses its Deps gets a Persist that writes the OLD copy, reports success, and lets the
	// runtime mutation proceed with the new copy's record never written — the failure this seam
	// exists to prevent, wearing its own success.
	//
	// These functions mutate a *ledger.Ledger the caller owns; nothing here reaches disk. So
	// "the intent is opened BEFORE the container is created" is only true if the ledger is
	// PERSISTED between those two steps — and a caller of Run cannot do that itself, because Run
	// creates the container internally. Without this seam the record exists only in memory when
	// the daemon accepts the create, and a process death there leaves an unaccounted container
	// with nothing to recover from: precisely the state the write-ahead record exists to prevent.
	//
	// It lives in Deps rather than being a ledger.Write call here because writing requires the
	// family-lock token, which the caller holds — the same reason this package never holds a
	// Mutator of its own.
	Persist func(*ledger.Ledger) error
	// Note is where the reconciler's two informational verdicts go — the two situations in which it
	// deliberately does NOTHING and the operator would otherwise see silence. Optional: a nil Note
	// is a caller with nowhere to write, and the reconciler's behaviour does not depend on it.
	Note func(string)
}

func (d Deps) note(format string, a ...any) {
	if d.Note != nil {
		d.Note(fmt.Sprintf(format, a...))
	}
}

// barrier persists the ledger before a runtime mutation, and REFUSES when it cannot.
//
// A nil Persist is refused rather than skipped: silently proceeding would restore exactly the
// defect this seam closes, and it would do so invisibly — the operation would succeed, and only a
// crash would reveal that nothing was ever written ahead.
// errCannotAsk marks an ownership question that was never ANSWERED, as opposed to one answered
// "no". Neither permits acting on the object, but a caller reporting to an operator must not tell
// them a container is foreign when the truth is that the runtime did not reply.
var errCannotAsk = errors.New("bringup: ownership could not be established")

// provenOurs answers "is the thing standing at this name the container this bring-up created, and
// is it OURS?" — and refuses to answer from the nonce alone.
//
// A NONCE SAYS WHICH OBJECT, NEVER WHOSE. Anyone who can put a container on this daemon can put our
// nonce label on it, so a nonce match by itself is not evidence of ownership. Acting on one lets
// this installation confirm and then drive a foreign container, or REMOVE it, purely because it
// carries a label it was handed. intent.ours() draws this line correctly a few files away; this
// asks the same question in the same order.
//
// THE INSTALLATION LABEL IS READ FIRST, because WHOSE has to be settled before WHICH means
// anything: a nonce comparison against another installation's container is a question about the
// wrong object. Every non-nil return means DO NOT ACT — do not confirm, do not start, do not
// remove.
func provenOurs(ctx context.Context, d Deps, l *ledger.Ledger, container, nonce string) error {
	ident, err := l.IdentGet()
	if err != nil {
		return fmt.Errorf("bringup: this installation's own identity could not be read, so nothing can be shown to\n"+
			"  belong to it. %q is neither confirmed nor removed: %w",
			container, errors.Join(errCannotAsk, err))
	}
	label, err := d.Objs.Label(ctx, container, prov.LabelInstall)
	if err != nil {
		return fmt.Errorf("bringup: the installation label of %q could not be read, so whether it belongs to this\n"+
			"  installation was never established. It is neither confirmed nor removed: %w",
			container, errors.Join(errCannotAsk, err))
	}
	// The SHARED label rule: a label meaning ABSENT must read as absent here too, or a container
	// labelled `installation=<no value>` reads as a foreign installation's rather than as unlabelled.
	// Both refuse, but they refuse for different reasons and an operator needs the right one.
	label = prov.NormalizeLabel(label)
	if label == "" {
		return fmt.Errorf("bringup: %q carries NO installation label, so nothing about the object itself says this\n"+
			"  installation created it. It is neither confirmed nor removed: no label proves it is ours,\n"+
			"  and no provenance proves it is not someone else's.", container)
	}
	if label != ident {
		return fmt.Errorf("bringup: %q is labelled for installation %q; this installation is %q.\n"+
			"  A nonce says WHICH object, never WHOSE — anyone who can put a container on this daemon\n"+
			"  can put that label on it — so this is another installation's container. It is NOT\n"+
			"  confirmed, NOT started and NOT removed.", container, label, ident)
	}
	actual, err := d.Objs.Label(ctx, container, prov.LabelNonce)
	if err != nil {
		return fmt.Errorf("bringup: the nonce of %q could not be read, so whether it is the container this bring-up\n"+
			"  created was never established. It is neither confirmed nor removed: %w",
			container, errors.Join(errCannotAsk, err))
	}
	shown := prov.NormalizeLabel(actual)
	if shown != nonce {
		if shown == "" {
			shown = "<none>"
		}
		return fmt.Errorf("bringup: %q carries nonce %q, not the %q this bring-up created. A create against an\n"+
			"  existing name SUCCEEDS and returns whatever already holds it without applying our labels,\n"+
			"  so the name standing here is not evidence that this is the object. It is NOT confirmed\n"+
			"  and NOT removed.", container, shown, nonce)
	}
	return nil
}

// removalOutcome is what a removal's answer ESTABLISHES about the container — three facts, not two.
//
// CHECKING THE ERROR IS ONLY HALF THE FIX, AND THE FIRST VERSION OF THIS FIX ONLY DID THAT HALF.
// Treating every non-nil answer as "it is still there" replaces one wrong answer with another:
// the engine returns ErrAbsent for a 404 — a daemon that IS answering, saying the object is gone —
// and ErrDaemonDown for a transport failure, where nothing about the container was established at
// all. Reporting the first as "STILL THERE" sends an operator to hunt an object that does not
// exist, and (in Recover) withholds the rebuild of a name that is free. Reporting the second as
// "STILL THERE" states a fact nothing measured.
type removalOutcome int

const (
	// removalGone — it is NOT at that name: removed by this call, or already absent. The name is
	// free and a rebuild may proceed.
	removalGone removalOutcome = iota
	// removalRefused — the daemon ANSWERED and the removal did NOT succeed (still in use, denied,
	// a server error). What is established is that the DELETE did not report success; whether the
	// container is still standing is NOT — a 5xx can follow a partial removal. So callers may say
	// the removal failed and may not say the object is there.
	removalRefused
	// removalUnknown — the daemon could not be asked at all. Nothing is established either way.
	removalUnknown
)

func classifyRemoval(err error) removalOutcome {
	switch {
	case err == nil:
		return removalGone
	case errors.Is(err, engine.ErrAbsent):
		return removalGone
	case errors.Is(err, engine.ErrDaemonDown):
		return removalUnknown
	}
	return removalRefused
}

// imageRemedy says what to do next, based ONLY on what the image-read failure established about
// the container itself.
//
// A "just re-run" remedy is false while the container stands: a re-run opens a FRESH intent under a
// new nonce (a keyed put supersedes) and then fails to create over the occupied name, after which
// the surviving container matches no record and the unaccounted gate stops the next run. But that
// reasoning only applies when something IS standing there, which is exactly what has to be
// established rather than assumed.
func imageRemedy(ierr error) string {
	switch {
	case errors.Is(ierr, engine.ErrAbsent):
		// AN ANSWER: the daemon says there is no such object. Nothing to remove, and the
		// write-ahead intent is the record a recovery or a re-run reads.
		return "\n  The container is GONE from that name — the runtime answered that no such object exists.\n" +
			"  There is nothing to remove; the write-ahead intent is what a recovery reads."
	case errors.Is(ierr, engine.ErrDaemonDown):
		return "\n  Whether the container is still standing at that name was NOT established — the container\n" +
			"  runtime did not answer. Ask it before re-running."
	}
	return "\n  The container was created and STILL STANDS at that name: remove it with the container\n" +
		"  runtime before re-running, or run 'mythical-ctl state repair'."
}

// imageRefusal is the one refusal both confirmation sites make about the image identity.
//
// AN EMPTY ANSWER AND A FAILED QUESTION ARE DIFFERENT FACTS and it says which. Neither may be
// written into a provenance record: the record is what a later run reads to know what this
// container was built from, and `id=` with nothing after it is not a smaller answer, it is a
// record that will be believed and cannot be checked.
func imageRefusal(container string, ierr error, kept string) error {
	// THE REMEDY IS CLASSIFIED FROM WHAT THE FAILURE ESTABLISHED, and the first version of it was
	// not — it asserted the container "STILL STANDS" whatever went wrong. Production Image is a
	// ContainerInspect, so an ErrAbsent here says the daemon ANSWERED that no such object exists,
	// and an ErrDaemonDown says nothing at all. Telling an operator to go and remove a container
	// that does not exist is the same wrong-answer defect this whole change is about, committed by
	// the fix for it.
	remedy := imageRemedy(ierr)
	if ierr != nil {
		return fmt.Errorf("bringup: the image %q was created from could not be read, so its provenance record would\n"+
			"  carry no image identity — and a confirmed record nothing can check is worse than an\n"+
			"  unfinished one. %s.%s\n"+
			"  The image could not be read because: %w", container, kept, remedy, errors.Join(errCannotAsk, ierr))
	}
	return fmt.Errorf("bringup: the runtime reports NO image for %q. A provenance record confirmed with an empty\n"+
		"  image identity says this container was built from nothing, which is not a fact anything\n"+
		"  measured. %s.%s", container, kept, remedy)
}

func barrier(d Deps, l *ledger.Ledger, what string) error {
	if d.Persist == nil {
		return fmt.Errorf("bringup: refusing to %s with no way to persist the record written ahead of it —\n"+
			"  the record would exist only in memory, and a crash would leave an object nothing can\n"+
			"  account for", what)
	}
	if err := d.Persist(l); err != nil {
		return fmt.Errorf("bringup: the record written ahead of %s could not be persisted, so nothing is done: %w", what, err)
	}
	return nil
}

// staged runs edit on a COPY of l, persists the copy, and only then publishes it into l.
//
// This is what makes a failed barrier leave nothing behind. The edit and the barrier are one
// step: if the write fails, the caller's ledger is byte-identical to before, so a retry sees the
// world it actually left. Editing in place first was a real defect — a failed resume barrier left
// the `resumed` marker in memory, and a retry then read PlanExited and refused to start a
// container that had never been started.
func staged(d Deps, l *ledger.Ledger, what string, edit func(*ledger.Ledger) error) error {
	if d.Persist == nil {
		return fmt.Errorf("bringup: refusing to %s with no way to persist the record written ahead of it —\n"+
			"  the record would exist only in memory, and a crash would leave an object nothing can\n"+
			"  account for", what)
	}
	cp := l.Clone()
	if err := edit(cp); err != nil {
		return err
	}
	if err := d.Persist(cp); err != nil {
		return fmt.Errorf("bringup: the record written ahead of %s could not be persisted, so nothing is done: %w", what, err)
	}
	return l.Adopt(cp)
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
	// THE INTENT IS DURABLE BEFORE THE CONTAINER EXISTS — and the open and the write are ONE step,
	// so a failed write leaves no intent for an object that was never created.
	if err := staged(d, l, "create a container", func(c *ledger.Ledger) error {
		return intent.Open(c, prov.ClassContainer, container, nonce, d.Now(),
			ledger.Field{Key: "desired", Value: string(want)},
			ledger.Field{Key: "check", Value: string(state.CheckAlias)},
			ledger.Field{Key: "check_param", Value: netID},
		)
	}); err != nil {
		return "", err
	}
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
		// REMOVED — but ONLY if it can be PROVEN ours. The nonce match this used to rely on is not
		// that proof: a nonce says WHICH object, never WHOSE, so removing on one alone deletes
		// another installation's container whenever it carries our label at our derived name.
		if oerr := provenOurs(ctx, d, l, container, nonce); oerr != nil {
			return fmt.Errorf("bringup: %q did not verify, and it could not be proven to be the container this\n"+
				"  bring-up created and owns — so it is LEFT ALONE and nothing was confirmed.\n"+
				"  %v\n"+
				"  It failed to verify because: %w", container, oerr, verr)
		}
		// THE REMOVAL'S OWN STATUS IS CHECKED, NEVER DISCARDED. This used to be
		// `_ = d.Mut.ContainerRemove(...)` with the very next line telling the operator the
		// container was removed — so a daemon that REFUSED the removal produced a message saying
		// the object is gone while it was still standing, running or not, under this
		// installation's labels. An operator told a container was removed does not go looking for
		// it, and that is the whole cost: the report is the only thing they act on.
		rerr := d.Mut.ContainerRemove(ctx, container)
		switch classifyRemoval(rerr) {
		case removalRefused:
			return fmt.Errorf("bringup: %q did not verify, and REMOVING IT DID NOT SUCCEED — the container runtime\n"+
				"  answered with a failure, so whether the container is still standing at that name was NOT\n"+
				"  established. Nothing was confirmed and nothing was started.\n"+
				"  ASK THE CONTAINER RUNTIME AND REMOVE IT YOURSELF BEFORE RE-RUNNING: while something\n"+
				"  stands at that name a re-run cannot create the container, and the write-ahead record\n"+
				"  that ties this one to this bring-up is replaced by the attempt.\n"+
				"  The removal failed because: %v\n"+
				"  It failed to verify because: %w", container, rerr, verr)
		case removalUnknown:
			return fmt.Errorf("bringup: %q did not verify, and WHETHER IT WAS REMOVED IS UNKNOWN — the container\n"+
				"  runtime did not answer, so nothing was established either way. Nothing was confirmed and\n"+
				"  nothing was started.\n"+
				"  Check with the container runtime whether it is still there before re-running.\n"+
				"  The removal could not be asked for because: %v\n"+
				"  It failed to verify because: %w", container, rerr, verr)
		}
		return fmt.Errorf("bringup: removed %q because it did not verify. Nothing was confirmed: %w", container, verr)
	}
	// OWNERSHIP IS RE-ESTABLISHED BEFORE CONFIRMATION rather than assumed from the create. A create
	// against an existing name SUCCEEDS and returns whatever already holds it without applying our
	// labels, so what just verified is not necessarily what we made — and confirming it would put a
	// foreign container under this installation's control.
	if oerr := provenOurs(ctx, d, l, container, nonce); oerr != nil {
		return fmt.Errorf("bringup: %q verified, but it could not be proven to be the container this bring-up\n"+
			"  created and owns. Nothing is confirmed, nothing is started and nothing is removed.\n"+
			"  %w", container, oerr)
	}
	// A STOPPED BRING-UP KEEPS THE OUTSTANDING ENTRY rather than clearing or performing it: a
	// stopped container has no address for its alias to answer with.
	what := "start a container"
	if want == state.Stopped {
		what = "finish a stopped bring-up"
	}
	// THE COMMIT AND THE CONFIRMATION ARE ONE TRANSACTION, staged and persisted together.
	// Editing the caller's ledger and persisting afterwards was the defect: a barrier failure left
	// the caller holding desired state, provenance and no intent while disk still carried the open
	// intent — and a Confirm that refused left the commit behind. The commit still comes before the
	// confirmation WITHIN the transaction, because a crash between them must not leave a container
	// accounted for with no desired state.
	//
	// THE IMAGE IS READ BEFORE THE TRANSACTION, AND A FAILED READ REFUSES. This used to be
	// `image, _ := ...`, so an inspection that failed confirmed the provenance record with an
	// EMPTY image identity and CONSUMED the intent — the record that would have said this
	// bring-up never finished. The result was a success return over a container accounted for
	// with no image, and nothing left on disk to notice it. Refusing HERE, before staged(),
	// leaves the caller's ledger byte-identical and the intent open, which is exactly the state a
	// recovery is written for.
	image, ierr := d.Objs.Image(ctx, container)
	if ierr != nil || image == "" {
		return imageRefusal(container, ierr, "The intent is KEPT and nothing is started")
	}
	if err := staged(d, l, what, func(c *ledger.Ledger) error {
		if cerr := state.Commit(c, container, want, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false); cerr != nil {
			return cerr
		}
		return intent.Confirm(c, prov.ClassContainer, container, nonce, ledger.Field{Key: "id", Value: image})
	}); err != nil {
		return err
	}
	if want == state.Stopped {
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
	// OWNERSHIP BEFORE ANYTHING ELSE, and the installation label BEFORE the nonce. This used to
	// compare the nonce alone, which is not ownership: a foreign container carrying our recorded
	// nonce at our derived name was adopted when its topology happened to verify, and REMOVED when
	// it did not. Both outcomes act on another installation's container on the strength of a label
	// anyone able to reach this daemon can apply.
	if oerr := provenOurs(ctx, d, l, container, nonce); oerr != nil {
		return fmt.Errorf("bringup: the intent for %q could not be finished, because the container standing at that\n"+
			"  name could not be proven to be the one the intent describes and to belong to this\n"+
			"  installation. The intent is KEPT, nothing is confirmed and nothing is removed.\n"+
			"  %w", container, oerr)
	}
	if verr := VerifyAttach(ctx, l, d, container, netID, alias); verr != nil {
		// A FAILED REMOVAL IS NOT A REBUILD, and that is the second half of checking it. The
		// caller acts on ErrRebuild by RE-CREATING the container from its launch spec — under the
		// same derived name. If the removal was refused, that name is still held by the container
		// standing here, so the rebuild would meet itself as a same-name survivor. So the error
		// says the container REMAINS and deliberately does not carry ErrRebuild.
		rerr := d.Mut.ContainerRemove(ctx, container)
		switch classifyRemoval(rerr) {
		case removalRefused:
			// NO REBUILD. The caller acts on ErrRebuild by RE-CREATING from the launch spec, under
			// the same derived name — and a removal that did not succeed leaves no evidence that
			// the name is free, so the rebuild could meet a same-name survivor.
			return fmt.Errorf("bringup: the intent for %q describes a container whose topology does not verify, and\n"+
				"  REMOVING IT DID NOT SUCCEED — the container runtime answered with a failure, so whether\n"+
				"  that name is free was NOT established. Nothing is confirmed, the intent is KEPT, and no\n"+
				"  rebuild is asked for: re-creating under a name something may still hold would meet it\n"+
				"  as a same-name survivor.\n"+
				"  The removal failed because: %v\n"+
				"  The topology does not verify because: %w", container, rerr, verr)
		case removalUnknown:
			// NO REBUILD EITHER, and for the opposite reason: not "the name is held" but "whether
			// it is held was never established". A rebuild authorized on an unanswered question is
			// the fail-open this whole sequence refuses.
			return fmt.Errorf("bringup: the intent for %q describes a container whose topology does not verify, and\n"+
				"  WHETHER IT WAS REMOVED IS UNKNOWN — the container runtime did not answer. Nothing is\n"+
				"  confirmed, the intent is KEPT, and no rebuild is asked for: whether that name is free\n"+
				"  was never established.\n"+
				"  The removal could not be asked for because: %v\n"+
				"  The topology does not verify because: %w", container, rerr, verr)
		}
		return fmt.Errorf("bringup: removed %q — it was created but its topology does not verify, and a\n"+
			"  confirmed-but-detached container is a state this sequence must never produce: %w",
			container, errors.Join(ErrRebuild, verr))
	}
	// ONE TRANSACTION on a clone, published only once BOTH edits succeed. Committing into the
	// caller's ledger first meant a Confirm that refused left the desired state and the owed check
	// behind — a recovery that reported failure while having already half-finished the intent it
	// was recovering. Recover does not persist: its caller writes the ledger once, so what this
	// owes is that a refusal leaves that ledger byte-identical.
	//
	// SAME REFUSAL, SAME REASON, one step before the clone — so the caller's ledger is
	// byte-identical, which is the whole of what Recover owes on a refusal.
	image, ierr := d.Objs.Image(ctx, container)
	if ierr != nil || image == "" {
		refusal := imageRefusal(container, ierr, "The intent is KEPT and nothing is confirmed")
		// THE SAME ANSWER THIS FUNCTION ALREADY GIVES FOR AN ABSENT CONTAINER. The ObsAbsent
		// branch above returns ErrRetained — the intent is kept so the verb that opened it can
		// re-create from the launch spec — and a container that vanished between that observation
		// and this read is the same fact arriving later. Not ErrRebuild: this package does not
		// hold the launch spec, and the verb that does acts on ErrRetained.
		if errors.Is(ierr, engine.ErrAbsent) {
			return errors.Join(ErrRetained, refusal)
		}
		return refusal
	}
	cp := l.Clone()
	if cerr := state.Commit(cp, container, want, []state.Check{{Kind: state.CheckAlias, Param: param}}, false); cerr != nil {
		return cerr
	}
	if cerr := intent.Confirm(cp, prov.ClassContainer, container, nonce, ledger.Field{Key: "id", Value: image}); cerr != nil {
		return cerr
	}
	return l.Adopt(cp)
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
		// SAID OUT LOUD, not merely done. These two verdicts are the reconciler declining to act,
		// and an operator watching a reconcile pass do nothing has no way to tell "deliberately
		// suspended" from "the reconciler did not look". The reference printed both; carrying only
		// the behaviour and leaving the words in a comment makes the port quieter than the thing it
		// replaces, at the two moments quiet is most easily misread. (The sibling verdict — a
		// stopped container with no endpoint address — is already carried as an error string.)
		d.note("note: reconciliation of %q is suspended — a migration intent is recorded for it and\n"+
			"  carries the desired state to restore. The reconciler must not restart a container a\n"+
			"  migration deliberately stopped.", container)
		return nil
	case state.PlanDefer:
		d.note("note: %q is stopped with a verification outstanding. A stopped container has no\n"+
			"  address, so there is nothing to resolve; the check is performed at its next start.", container)
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
		// THE ATTEMPT IS DURABLE BEFORE THE START, and recording it is ONE step with the write. A
		// crash between recording and starting would leave the next run believing it had never
		// tried — the restart loop the record exists to stop, reinstated by the very crash it was
		// meant to survive. And a FAILED write must not leave the marker in memory either, or a
		// retry reads PlanExited and refuses to start a container that was never started.
		if err := staged(d, l, "resume a container", func(c *ledger.Ledger) error {
			return state.ResumeRecord(c, container)
		}); err != nil {
			return err
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
