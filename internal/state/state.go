// Package state is the reconciler's memory: what each container is SUPPOSED to be doing, what
// live checks it still owes, and what should be done about the difference.
//
// The distinction the whole module turns on: DESIRED STATE IS RECORDED, OBSERVED STATE IS ASKED.
// A container's desired state lives in the ledger and survives a recreate; whether it is actually
// running is never read from the ledger, because a record of the past is not evidence about the
// present.
//
// Like internal/prov and internal/intent these functions mutate an IN-MEMORY *ledger.Ledger, and
// the caller's single ledger.Write persists them — which is what makes "desired state and the
// outstanding set commit in ONE ledger write" structural: a crash between them cannot happen,
// because there is only one.
package state

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

const (
	kindDesired     = "desired"
	kindOutstanding = "outstanding"
	kindStorageMig  = "storagemig"
	kindResumed     = "resumed"
)

// Desired is what a container is supposed to be doing. There is deliberately no default: a
// container with no record has no desired state, which is not the same as "running".
type Desired string

const (
	Running Desired = "running"
	Stopped Desired = "stopped"
)

// CheckKind is a live verification a transition owes. D52 made this set TYPED — a boolean flag
// records no kind and no parameter, so it could never say WHAT was owed or be cleared by naming it.
// `alias` is the only kind this core defines; its parameter is the network the alias must resolve
// on, and a container legitimately owes one per network.
type CheckKind string

const CheckAlias CheckKind = "alias"

// Check is one owed verification.
type Check struct {
	Kind  CheckKind
	Param string
}

// Observed is what the runtime says right now.
type Observed string

const (
	ObsRunning Observed = "running"
	ObsStopped Observed = "stopped"
	ObsAbsent  Observed = "absent"
)

// Plan is the reconciler's verdict for one container.
type Plan string

const (
	// PlanNone — nothing to do (including "nothing is recorded, so there is nothing to converge to").
	PlanNone Plan = "none"
	// PlanSuspended — something else governs this container: an unconfirmed intent, or a storage
	// migration. Acting here would act on a half-built container, or on one a migration stopped
	// on purpose.
	PlanSuspended Plan = "suspended"
	// PlanRebuild — desired running, and the container is GONE. Never a bare start: there is
	// nothing to start.
	PlanRebuild Plan = "rebuild"
	// PlanStartVerify — desired running, container stopped, and this attempt has not been made.
	PlanStartVerify Plan = "start verify"
	// PlanExited — desired running, container stopped, and it was ALREADY resumed once. Reported
	// rather than started again: starting a container that does not stay up, on every pass, for
	// ever, is the loop the attempt record exists to stop.
	PlanExited Plan = "exited"
	// PlanVerify — running, and it still owes a check. Verify NOW, not at some future start.
	PlanVerify Plan = "verify"
	// PlanStop — desired stopped and still running. Reconciliation runs BOTH ways.
	PlanStop Plan = "stop"
	// PlanDefer — desired stopped, stopped, and a check is still owed. A stopped container has no
	// address to verify, so the check waits rather than being retired unperformed.
	PlanDefer Plan = "defer"
)

// Objects is the read side: the runtime's answer about ONE container. Narrow because that is all
// the observed half needs, and it must never be able to reach the ledger.
type Objects interface {
	// State reports the container's running flag and the daemon's own status word.
	// engine.ErrAbsent means the container is genuinely gone (an answer); any other error means
	// the question could not be asked.
	State(ctx context.Context, container string) (running bool, status string, err error)
}

type engineObjects struct{ c *engine.Client }

// Engine wraps a client as the observed-state seam.
func Engine(c *engine.Client) Objects { return engineObjects{c: c} }

func (e engineObjects) State(ctx context.Context, container string) (bool, string, error) {
	info, err := e.c.ContainerInspect(ctx, container)
	if err != nil {
		return false, "", err
	}
	return info.Running, info.Status, nil
}

// knownStatus is the daemon's own vocabulary. The reference read a boolean template and refused an
// answer that was "neither true nor false"; a typed bool has no third value, so what ports is the
// same refusal one field along — a STATUS WORD this core has no meaning for. The boolean then
// decides, exactly as the reference's did, so every state it handled is handled identically.
var knownStatus = map[string]bool{
	"created": true, "running": true, "paused": true, "restarting": true,
	"removing": true, "exited": true, "dead": true,
}

func desiredOK(d Desired) error {
	switch d {
	case Running, Stopped:
		return nil
	}
	return fmt.Errorf("state: desired state must be running or stopped, not %q", string(d))
}

func kindCheckOK(k CheckKind) error {
	if k == CheckAlias {
		return nil
	}
	return fmt.Errorf("state: %q is not a check kind this core defines (the only kind is %q)", string(k), string(CheckAlias))
}

// verifyOf decides the `verify=` field a commit records, and it is the one place the three inputs
// meet: what state is wanted, whether the caller DECLARED that nothing is owed, and whether the
// outstanding set actually holds anything after the commit's own additions.
//
// The `running` case is the load-bearing one. Every transition that leaves a container running
// ends in a live check — "it started" is not evidence that its alias resolves — and an empty
// outstanding set is exactly what a crash between recording the intent and recording the check
// leaves behind. The two cannot be told apart afterwards, so silence is REFUSED: a caller either
// names the checks this start owes, or says explicitly that it owes none.
func verifyOf(want Desired, declaredNone, owed bool) (string, error) {
	if owed {
		if declaredNone {
			return "", errors.New("state: refusing to record that nothing needs verifying while this container still owes\n" +
				"  an outstanding check. A commit PRESERVES the set; it verifies nothing. Clear the check\n" +
				"  with OutstandingClear, naming what was verified. Nothing was written.")
		}
		return "owed", nil
	}
	if declaredNone {
		return "none", nil
	}
	if want == Running {
		return "", errors.New("state: refusing to record 'running' for a container that owes no live verification and\n" +
			"  does not say so. Every transition that leaves a container running ends in one — 'it\n" +
			"  started' is not evidence that its alias resolves — and an empty outstanding set is\n" +
			"  exactly what a crash between recording the intent and recording the check leaves\n" +
			"  behind, so the two cannot be told apart afterwards. Pass the checks this start owes,\n" +
			"  or declare that it owes none. Nothing was written.")
	}
	return "none", nil
}

// DesiredGet reads the recorded desired state. ledger.ErrAbsentRecord means NOTHING is recorded —
// an answer, and specifically NOT "running".
//
// Both fields are validated on READ, and the refusals say so: the value is on DISK, and the
// ledger's checksum proves the bytes were not altered after they were written, not that this
// installation wrote them.
func DesiredGet(l *ledger.Ledger, container string) (Desired, error) {
	rec, err := l.Find(kindDesired, "container", container)
	if err != nil {
		return "", err
	}
	v, ok := ledger.FieldOf(rec, "state")
	if !ok {
		return "", fmt.Errorf("state: the record of desired state for %q does not say which state is wanted. It says\n"+
			"  this container was given an intent without saying what it was, so it can be neither\n"+
			"  reconciled nor left alone. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", container)
	}
	if err := desiredOK(Desired(v)); err != nil {
		return "", fmt.Errorf("%w\n  — and that value is on DISK, in the ledger, not in this call. The ledger is checksummed,\n"+
			"  which proves the bytes were not altered after they were written, not that this\n"+
			"  installation wrote them. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", err)
	}
	vfy, ok := ledger.FieldOf(rec, "verify")
	if !ok {
		return "", fmt.Errorf("state: the record of desired state for %q does not say whether a live verification is\n"+
			"  owed. An empty outstanding set beside a silent row is indistinguishable from a crash\n"+
			"  between recording the intent and recording the check it owed, so this container can be\n"+
			"  neither reconciled nor left alone. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", container)
	}
	if vfy != "owed" && vfy != "none" {
		return "", fmt.Errorf("state: a desired-state record says verify=%q — it must be 'owed' or 'none'\n"+
			"  — and that value is on DISK, in the ledger, not in this call. It is PRESERVED and\n"+
			"  reported. Run 'mythical-ctl state repair'.", vfy)
	}
	return Desired(v), nil
}

// Outstanding lists the live checks a container still owes.
//
// EVERY field is required and none may be empty. An entry that does not say what KIND of check is
// owed can never be performed and never cleared, and leaving it OUT of the set would make the
// container look fully reconciled — so an unreadable entry refuses the WHOLE set rather than
// shortening it.
func Outstanding(l *ledger.Ledger, container string) ([]Check, error) {
	if !ledger.FieldOK(ledger.Field{Key: "container", Value: container}) {
		return nil, fmt.Errorf("state: %q is not a container name this format can hold", container)
	}
	rows, err := l.Select(kindOutstanding, []ledger.Field{{Key: "container", Value: container}})
	if err != nil {
		return nil, err
	}
	var out []Check
	for _, rec := range rows {
		k, ok := ledger.FieldOf(rec, "kind")
		if !ok {
			return nil, fmt.Errorf("state: an outstanding check recorded for %q does not say what KIND of check is owed,\n"+
				"  so it can never be performed and never cleared. Leaving it out of the set would make\n"+
				"  this container look fully reconciled. It is PRESERVED and reported.\n"+
				"  Run 'mythical-ctl state repair'.", container)
		}
		if k == "" {
			return nil, fmt.Errorf("state: an outstanding check recorded for %q carries an EMPTY kind — it says a check is\n"+
				"  owed without saying which, which no clear can ever match. It is PRESERVED and reported.\n"+
				"  Run 'mythical-ctl state repair'.", container)
		}
		p, ok := ledger.FieldOf(rec, "param")
		if !ok {
			return nil, fmt.Errorf("state: an outstanding %q check recorded for %q does not say WHAT it must verify.\n"+
				"  An 'alias' entry carries the network the alias must resolve on; one carrying nothing\n"+
				"  schedules a check of nothing, and no clear can ever name it. It is PRESERVED and\n"+
				"  reported. Run 'mythical-ctl state repair'.", k, container)
		}
		if p == "" {
			return nil, fmt.Errorf("state: an outstanding %q check recorded for %q carries an EMPTY parameter — it\n"+
				"  names nothing to verify and no clear can match it, so it would keep this container\n"+
				"  unreconciled forever. It is PRESERVED and reported.\n"+
				"  Run 'mythical-ctl state repair'.", k, container)
		}
		out = append(out, Check{Kind: CheckKind(k), Param: p})
	}
	return out, nil
}

// Commit records desired state and ADDS to the outstanding set — it never replaces it. A commit
// PRESERVES the set because it verifies nothing: only a clear, naming what was verified, retires a
// check.
//
// declaredNone is the caller saying explicitly that this intent owes NO live verification. It
// cannot be given beside a check that IS owed — that is a contradiction, not a shorthand.
//
// The container's RESUME-ATTEMPT record is dropped: a fresh statement of intent grants a fresh
// attempt, or a container that failed to stay up once could never be started again.
func Commit(l *ledger.Ledger, container string, want Desired, checks []Check, declaredNone bool) error {
	if err := desiredOK(want); err != nil {
		return err
	}
	if declaredNone && len(checks) > 0 {
		return errors.New("state: declaring that this intent owes NO live verification cannot be given beside a\n" +
			"  check that IS owed. Nothing was written.")
	}
	// EVERY argument judged BEFORE anything is written, or a refusal halfway through leaves the
	// ledger holding some of a commit.
	for _, ch := range checks {
		if err := kindCheckOK(ch.Kind); err != nil {
			return err
		}
		if ch.Param == "" {
			return fmt.Errorf("state: the outstanding %q check carries no parameter. D52 made this set TYPED\n"+
				"  because a flag records no kind and no parameters: an 'alias' entry carries the network\n"+
				"  the alias must resolve on, and one carrying nothing can never be matched and so can\n"+
				"  never be cleared. Nothing was written.", string(ch.Kind))
		}
		for _, f := range []ledger.Field{
			{Key: "container", Value: container},
			{Key: "kind", Value: string(ch.Kind)},
			{Key: "param", Value: ch.Param},
		} {
			if !ledger.FieldOK(f) {
				return fmt.Errorf("state: refusing to record the outstanding %q check for %q — %s=%s is not a\n"+
					"  ledger field. Nothing was written.", string(ch.Kind), container, f.Key, f.Value)
			}
		}
	}
	if !ledger.FieldOK(ledger.Field{Key: "container", Value: container}) {
		return fmt.Errorf("state: refusing to record desired state for %q — it is not a name this format can\n"+
			"  hold, and a container name that would forge a record is never serialized. Nothing was written.", container)
	}
	// The existing set is READ before anything is added, so a repeat of the same check records
	// once: recording it twice would need two clears to retire what one verification proved.
	existing, err := Outstanding(l, container)
	if err != nil {
		return err
	}
	have := map[Check]bool{}
	for _, ch := range existing {
		have[ch] = true
	}
	var toAdd []Check
	for _, ch := range checks {
		if have[ch] {
			continue
		}
		have[ch] = true
		toAdd = append(toAdd, ch)
	}
	owed := len(existing)+len(toAdd) > 0
	vfy, err := verifyOf(want, declaredNone, owed)
	if err != nil {
		return err
	}
	// EVERY CARDINALITY QUESTION THIS COMMIT WILL ASK, ASKED BEFORE THE FIRST MUTATION.
	//
	// The two writes below can each refuse on their own — a contradiction among desired rows, or a
	// `resumed` record this module cannot read — and discovering that AFTER the outstanding
	// additions have landed leaves exactly the half-commit this function exists to make
	// impossible: a check recorded with no desired row stating what it is owed for. Measured: two
	// contradicting desired rows produced precisely that, an appended outstanding row beside the
	// evidence the commit then refused to touch.
	if _, derr := l.Find(kindDesired, "container", container); derr != nil && !errors.Is(derr, ledger.ErrAbsentRecord) {
		return derr
	}
	if _, rerr := l.Select(kindResumed, []ledger.Field{{Key: "container", Value: container}}); rerr != nil {
		return rerr
	}
	// Nothing above has mutated the ledger; from here on it is the write.
	for _, ch := range toAdd {
		if err := l.Append(kindOutstanding, []ledger.Field{
			{Key: "container", Value: container},
			{Key: "kind", Value: string(ch.Kind)},
			{Key: "param", Value: ch.Param},
		}); err != nil {
			return err
		}
	}
	if _, err := l.DelAll(kindResumed, []ledger.Field{{Key: "container", Value: container}}); err != nil {
		return err
	}
	return l.Put(kindDesired, "container", container, []ledger.Field{
		{Key: "container", Value: container},
		{Key: "state", Value: string(want)},
		{Key: "verify", Value: vfy},
	})
}

// OutstandingClear retires ONE check, naming both what kind it was and WHICH one — this set holds
// several entries of one kind with different parameters, so a clear that names only the kind
// retires checks nobody performed.
//
// It also drops the resume-attempt record: the verification that proves the container came up is
// what retires the attempt.
func OutstandingClear(l *ledger.Ledger, container string, kind CheckKind, param string) error {
	if err := kindCheckOK(kind); err != nil {
		return err
	}
	if param == "" {
		return fmt.Errorf("state: refusing to clear the outstanding %q check for %q without saying WHICH\n"+
			"  one was verified. This set holds several entries of one kind with different parameters\n"+
			"  — an 'alias' check per network — so a clear that names only the kind retires checks\n"+
			"  nobody performed. Nothing was written.", string(kind), container)
	}
	match := []ledger.Field{
		{Key: "container", Value: container},
		{Key: "kind", Value: string(kind)},
		{Key: "param", Value: param},
	}
	for _, f := range match {
		if !ledger.FieldOK(f) {
			return fmt.Errorf("state: refusing to clear the outstanding %q check for %q — %s=%s is not a\n"+
				"  ledger field, so it could never have matched one. Nothing was written.", string(kind), container, f.Key, f.Value)
		}
	}
	// EVERY QUESTION THIS CLEAR WILL ASK, ASKED BEFORE THE FIRST EDIT. Both deletions can refuse
	// on their own — DelAll refuses when a record of the kind it is asked about cannot be read —
	// and discovering that AFTER the outstanding check is already gone leaves the caller holding a
	// ledger from which a verification has been silently retired, behind an error that says
	// nothing was written. (Same class as the Commit ordering defect: a refusal must leave the
	// ledger byte-identical, because the caller's single Write is what makes it durable.)
	if _, err := l.Select(kindOutstanding, match); err != nil {
		return err
	}
	resumed := []ledger.Field{{Key: "container", Value: container}}
	if _, err := l.Select(kindResumed, resumed); err != nil {
		return err
	}
	// Nothing above has mutated the ledger; from here on it is the write.
	if _, err := l.DelAll(kindOutstanding, match); err != nil {
		return err
	}
	_, err := l.DelAll(kindResumed, resumed)
	return err
}

// Forget drops everything recorded about one container — the desired row, the WHOLE outstanding
// set (not just the one row a selector resolves to), and the resume-attempt record. For a family
// uninstall, and only for the container it names.
func Forget(l *ledger.Ledger, container string) error {
	if !ledger.FieldOK(ledger.Field{Key: "container", Value: container}) {
		return fmt.Errorf("state: %q is not a container name this format can hold", container)
	}
	match := []ledger.Field{{Key: "container", Value: container}}
	// THE SAME PREFLIGHT, for the same reason. The desired-row deletion refuses on ambiguity, and
	// it runs LAST — so without this, two contradicting desired rows would be discovered only
	// after the whole outstanding set and the resume record had already been dropped. Forget is
	// the one operation whose failure mode is losing exactly what it was asked to preserve
	// evidence of.
	if _, err := l.Select(kindOutstanding, match); err != nil {
		return err
	}
	if _, err := l.Select(kindResumed, match); err != nil {
		return err
	}
	if _, err := l.Find(kindDesired, "container", container); err != nil && !errors.Is(err, ledger.ErrAbsentRecord) {
		return err
	}
	// Nothing above has mutated the ledger; from here on it is the write.
	if _, err := l.DelAll(kindOutstanding, match); err != nil {
		return err
	}
	if _, err := l.DelAll(kindResumed, match); err != nil {
		return err
	}
	return l.Del(kindDesired, "container", container)
}

// ResumeRecord notes that this container has been resumed once. Recording the same attempt twice
// records it once — it is a marker, not a counter.
func ResumeRecord(l *ledger.Ledger, container string) error {
	if !ledger.FieldOK(ledger.Field{Key: "container", Value: container}) {
		return fmt.Errorf("state: %q is not a container name this format can hold", container)
	}
	return l.Put(kindResumed, "container", container, []ledger.Field{{Key: "container", Value: container}})
}

// Observe asks the RUNTIME. Never the ledger: a record of the past is not evidence about the
// present, and that distinction is the reason this function exists at all.
func Observe(ctx context.Context, objs Objects, container string) (Observed, error) {
	if objs == nil {
		return "", errors.New("state: no runtime to ask — observed state is never read from the ledger")
	}
	running, status, err := objs.State(ctx, container)
	if errors.Is(err, engine.ErrAbsent) {
		return ObsAbsent, nil // genuinely gone, and the daemon answered to say so
	}
	if err != nil {
		return "", fmt.Errorf("state: the container runtime could not be asked whether %q is running: %w", container, err)
	}
	if !knownStatus[status] {
		return "", fmt.Errorf("state: the runtime answered %q when asked what state %q is in, which is not a\n"+
			"  status this core has a meaning for. Reading it as 'stopped' would plan a start against a\n"+
			"  container whose state was never established.", status, container)
	}
	if running {
		return ObsRunning, nil
	}
	return ObsStopped, nil
}

// Reconciled: the container is in its desired state AND owes no outstanding check. An outstanding
// check makes a container NOT reconciled even when observed equals desired — "it started" is not
// evidence that its alias resolves.
func Reconciled(ctx context.Context, l *ledger.Ledger, objs Objects, container string) (bool, error) {
	want, err := DesiredGet(l, container)
	if err != nil {
		return false, err
	}
	obs, err := Observe(ctx, objs, container)
	if err != nil {
		return false, err
	}
	out, err := Outstanding(l, container)
	if err != nil {
		return false, err
	}
	if len(out) > 0 {
		return false, nil
	}
	return string(want) == string(obs), nil
}

// resumedFor reports whether this container already has a resume-attempt record.
func resumedFor(l *ledger.Ledger, container string) (bool, error) {
	if !ledger.FieldOK(ledger.Field{Key: "container", Value: container}) {
		return false, fmt.Errorf("state: %q is not a container name this format can hold", container)
	}
	rows, err := l.Select(kindResumed, []ledger.Field{{Key: "container", Value: container}})
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// storageMigFor reports whether a recorded storage migration governs this container.
//
// The migration is recorded per PRODUCT, and the container name carries the product after the
// installation prefix — so a name not shaped like one of this installation's own containers is
// simply not governed, rather than an error.
func storageMigFor(l *ledger.Ledger, container string) (bool, error) {
	if _, err := prov.Find(l, prov.ClassContainer, container); err != nil {
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return false, nil
		}
		return false, err
	}
	ident, err := l.IdentGet()
	if err != nil {
		// No identity minted yet: nothing this installer created can match. Any OTHER failure is a
		// question that could not be asked.
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return false, nil
		}
		return false, err
	}
	pfx := "mythical-" + ident + "-"
	product, ok := strings.CutPrefix(container, pfx)
	if !ok || product == "" {
		return false, nil
	}
	rows, err := l.Select(kindStorageMig, []ledger.Field{{Key: "product", Value: product}})
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// PlanFor is the reconciler's table (§6b's recovery table), and its refusals matter as much as its
// verdicts: a container whose situation cannot be established gets NO plan, rather than an empty
// one that reads as "nothing to do".
func PlanFor(ctx context.Context, l *ledger.Ledger, objs Objects, container string) (Plan, error) {
	// AN UNCONFIRMED INTENT SUSPENDS: a half-built container is not reconcilable, and "the
	// question failed" is not "there is no intent". Asked through the intent package's own
	// lookup rather than by naming its record kind here — two spellings of what an intent record
	// is would be two chances for one of them to stop matching.
	_, ierr := intent.Find(l, prov.ClassContainer, container)
	switch {
	case ierr == nil:
		return PlanSuspended, nil
	case errors.Is(ierr, ledger.ErrAbsentRecord):
	default:
		return "", fmt.Errorf("state: cannot tell whether an unconfirmed intent governs %q, so this container gets no\n"+
			"  plan. A half-built container is not reconcilable, and 'the question failed' is not\n"+
			"  'there is no intent': %w", container, ierr)
	}
	// A STORAGE MIGRATION SUSPENDS: acting here would act on a container a migration may have
	// stopped on purpose.
	mig, merr := storageMigFor(l, container)
	if merr != nil {
		return "", fmt.Errorf("state: cannot tell whether a storage migration governs %q, so this container gets no\n"+
			"  plan. Acting here would be acting on a container a migration may have stopped on purpose: %w", container, merr)
	}
	if mig {
		return PlanSuspended, nil
	}
	want, derr := DesiredGet(l, container)
	if errors.Is(derr, ledger.ErrAbsentRecord) {
		return PlanNone, nil // nothing recorded: nothing to converge to
	}
	if derr != nil {
		return "", derr
	}
	obs, oerr := Observe(ctx, objs, container)
	if oerr != nil {
		return "", oerr
	}
	out, err := Outstanding(l, container)
	if err != nil {
		return "", err
	}
	switch {
	case want == Running && obs == ObsAbsent:
		return PlanRebuild, nil
	case want == Running && obs == ObsStopped:
		// ONE resume, then reported. Starting a container that does not stay up, on every pass,
		// for ever, is the loop the attempt record exists to stop — and reading an unreadable
		// attempt record as "not tried yet" would restart exactly that loop.
		tried, rerr := resumedFor(l, container)
		if rerr != nil {
			return "", fmt.Errorf("state: cannot tell whether %q was already resumed, so this container gets no plan.\n"+
				"  Reading that as 'not yet' would start it again — and starting a container that does not\n"+
				"  stay up, on every pass, for ever, is the loop the attempt record exists to stop: %w", container, rerr)
		}
		if tried {
			return PlanExited, nil
		}
		return PlanStartVerify, nil
	case want == Running && obs == ObsRunning:
		if len(out) > 0 {
			return PlanVerify, nil
		}
		return PlanNone, nil
	case want == Stopped && obs == ObsRunning:
		return PlanStop, nil
	case want == Stopped && obs == ObsStopped:
		if len(out) > 0 {
			return PlanDefer, nil
		}
		return PlanNone, nil
	case want == Stopped && obs == ObsAbsent:
		return PlanNone, nil
	}
	return "", fmt.Errorf("state: %q is desired %q and observed %q, which is not a row of the\n"+
		"  reconciler's table. Refusing rather than printing an empty plan.", container, string(want), string(obs))
}
