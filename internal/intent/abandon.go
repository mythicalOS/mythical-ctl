package intent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

// secondsOK is the reference's digits-before-arithmetic rule, applied to a timestamp read out of
// the ledger. Go has no arithmetic evaluator to reach, so what survives is the refusal: a
// creation time that is not a number is not silently treated as 0, because a zero makes an intent
// older than any grace period the moment it is read.
func secondsOK(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, true
}

// Abandonable reports whether the intent for class/name may be aged out (D39's bounded retention).
// nil means yes; every other answer is a refusal carrying its reason.
//
// `now` and `grace` are the caller's. The reference read the clock and the grace period itself and
// refused when either was unreadable, because an unreadable input does not fail the comparison —
// IT FAILS IT OPEN, and every intent then reads as older than the grace period. Typed values
// remove both failure modes; what survives is the refusal of a NEGATIVE grace, which fails open in
// exactly the same direction.
func Abandonable(ctx context.Context, l *ledger.Ledger, objs Objects, class prov.Class, name string, now time.Time, grace time.Duration) error {
	if !prov.ClassOK(class) {
		return fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	rec, err := Find(l, class, name)
	if err != nil {
		return err
	}
	if objs == nil {
		return errors.New("intent: no runtime to ask — zero matches would prove nothing")
	}
	// ZERO MATCHES PROVES NOTHING FROM A DAEMON THAT IS NOT ANSWERING, and everything below turns
	// on a zero. Asked before the search rather than inferred from its result.
	if perr := objs.Ping(ctx); perr != nil {
		return fmt.Errorf("intent: the container runtime is not answering, so zero matches proves nothing: %w", perr)
	}
	nonce, err := nonceOf(rec, name)
	if err != nil {
		return err
	}
	matches, err := objs.FindByNonce(ctx, class, nonce)
	if err != nil {
		return fmt.Errorf("intent: the container runtime could not be asked which %ss carry nonce %q: %w",
			string(class), nonce, err)
	}
	if len(matches) != 0 {
		ident, ierr := l.IdentGet()
		if ierr != nil {
			return fmt.Errorf("intent: this installation's own identity cannot be read, so nothing carrying this\n"+
				"  nonce can be shown to be ours or not ours. Refusing to age the intent out.\n"+
				"  Run 'mythical-ctl state repair': %w", ierr)
		}
		mine := false
		for _, m := range matches {
			own, why, oerr := ours(ctx, objs, class, name, m, ident, nonce)
			if oerr != nil {
				return fmt.Errorf("%w\n  Refusing to age an intent out on a question that was never answered.", oerr)
			}
			switch own {
			case ownOurs:
				mine = true
			case ownNotOurs, ownGone:
				// Someone else's, or already gone: neither keeps this intent alive.
			case ownOtherName:
				return fmt.Errorf("%s\n  Refusing to age this intent out while an object of ours carries its nonce.", why)
			case ownNonceMismatch:
				return fmt.Errorf("%s\n  Refusing to age this intent out while an object of ours stands at its name.", why)
			}
		}
		if mine {
			return errors.New("intent: the object for this intent has appeared — reconcile it instead of abandoning it.")
		}
	}

	createdStr, _ := ledger.FieldOf(rec, "created")
	created, ok := secondsOK(createdStr)
	if !ok {
		return fmt.Errorf("intent: the intent for %s %q carries a creation time that is not a number\n"+
			"  (%q) — refusing to age it out. The ledger is checksummed, which proves it was\n"+
			"  not altered, not that this installation wrote it. Run 'mythical-ctl state repair'.",
			string(class), name, createdStr)
	}
	if grace < 0 {
		return fmt.Errorf("intent: the grace period is %s, which is not a length of time to wait.\n"+
			"  A negative threshold does not fail the comparison, it fails it OPEN — every intent\n"+
			"  would read as older than the grace period. Refusing until it is not negative.", grace)
	}
	nowSecs := now.Unix()
	if created > nowSecs {
		return errors.New("intent: this intent is dated in the future — refusing to age it out.")
	}
	age := time.Duration(nowSecs-created) * time.Second
	if age < grace {
		return fmt.Errorf("intent: this intent is %s old; the grace period is %s.\n"+
			"  Wait, then try again. The delay makes a late arrival from the daemon less likely — it is\n"+
			"  not a check that the daemon has finished, which cannot be observed.", age, grace)
	}
	return nil
}

// AbandonAdvisory is what a successful abandonment obliges the caller to tell the operator.
//
// IT IS RETURNED AS DATA rather than written somewhere, because it is a SUCCESS-path statement and
// a Go error has no channel for one. The reference prints it from the same function that succeeds;
// here the verb layer owns operator output, so the sentence travels to it as a value — a caller
// that drops it is visibly dropping something, which a warning written into the void would not be.
const AbandonAdvisory = "intent: abandoning the recorded intent. The object may still appear later.\n" +
	"  This does NOT guarantee convergence: the installer cannot distinguish 'never created'\n" +
	"  from 'not yet visible', so the object may still appear later. If it does, it is caught as\n" +
	"  an unrecorded same-identity object and the next operation will stop and report it."

// Abandon drops an intent that Abandonable has cleared, and returns the advisory the caller must
// surface (see AbandonAdvisory). On refusal the advisory is empty — there is nothing to say about
// an abandonment that did not happen.
func Abandon(ctx context.Context, l *ledger.Ledger, objs Objects, class prov.Class, name string, now time.Time, grace time.Duration) (string, error) {
	if err := Abandonable(ctx, l, objs, class, name, now, grace); err != nil {
		return "", err
	}
	if err := Drop(l, class, name); err != nil {
		return "", err
	}
	return AbandonAdvisory, nil
}
