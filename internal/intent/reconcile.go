package intent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

// ownership is the answer to "whose is it, and is it the one?" — WHICH the nonce answers and
// WHOSE it never does. Spelled as a closed set because the reference returned five distinct exit
// codes here and every caller switched on them; folding any two together is what turned "another
// installation's object" into "adopt it".
type ownership int

const (
	ownOurs          ownership = iota // ours, at the right name, carrying the right nonce
	ownNotOurs                        // unlabelled, or labelled for another installation
	ownGone                           // it was listed and is already gone
	ownOtherName                      // carries this nonce, but stands at a DIFFERENT name
	ownNonceMismatch                  // stands at the name, carrying a different nonce
)

// ours judges ONE candidate. The error is reserved for "the question could not be answered" —
// never for a "no", which is an ownership value and carries its own reason.
func ours(ctx context.Context, objs Objects, class prov.Class, name, cand, ident, nonce string) (ownership, string, error) {
	label, err := objs.Label(ctx, class, cand, prov.LabelInstall)
	if errors.Is(err, engine.ErrAbsent) {
		return ownGone, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("intent: the container runtime could not be asked for the installation label of %s %q.\n"+
			"  Nothing is adopted, aged out or accounted for on the strength of a question that was\n"+
			"  never answered: %w", string(class), cand, err)
	}
	if label == "" {
		return ownNotOurs, fmt.Sprintf("intent: %s %q carries this intent's nonce but NO installation label, so nothing\n"+
			"  about the object itself says this installation created it. It is neither adopted nor\n"+
			"  removed: no label proves it is ours, and no provenance proves it is not someone else's.",
			string(class), cand), nil
	}
	if label != ident {
		return ownNotOurs, fmt.Sprintf("intent: %s %q carries this intent's nonce but is labelled for installation\n"+
			"  %q; this installation is %q. A nonce says WHICH object, never WHOSE —\n"+
			"  anyone who can put an object on this daemon can put that label on it — so this is\n"+
			"  another installation's object. It is NOT adopted, NOT removed and NOT counted as ours.",
			string(class), cand, label, ident), nil
	}
	if cand != name {
		return ownOtherName, fmt.Sprintf("intent: %s %q carries this intent's nonce, but the intent is for %q.\n"+
			"  Provenance, deletion authority and the unaccounted gate all look an object up by NAME,\n"+
			"  so recording this one under %q would record it for a name nothing holds. It is\n"+
			"  reported rather than adopted, and it is not removed.", string(class), cand, name, name), nil
	}
	actual, err := objs.Label(ctx, class, cand, prov.LabelNonce)
	if errors.Is(err, engine.ErrAbsent) {
		return ownGone, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("intent: the container runtime could not be asked for the nonce label of %s %q: %w",
			string(class), cand, err)
	}
	if actual != nonce {
		shown := actual
		if shown == "" {
			shown = "<none>"
		}
		return ownNonceMismatch, fmt.Sprintf("intent: %s %q carries nonce %q, which does not match the\n"+
			"  %q this intent recorded. A create against an existing name SUCCEEDS and returns\n"+
			"  whatever already holds it without applying our labels, so the name standing here is\n"+
			"  not evidence that this is the object. It is NOT adopted — nothing proves it is ours —\n"+
			"  and NOT removed.", string(class), cand, shown, nonce), nil
	}
	return ownOurs, "", nil
}

// reportingFields carries the intent's descriptive fields into the confirmation, so a later report
// can name what was being built.
func reportingFields(fields []ledger.Field) []ledger.Field {
	var out []ledger.Field
	for _, k := range []string{"product", "role", "precious"} {
		if v, ok := ledger.FieldOf(fields, k); ok {
			out = append(out, ledger.Field{Key: k, Value: v})
		}
	}
	return out
}

// Reconcile finishes an open intent: adopt the object if it can be PROVED ours, reissue it if the
// class allows, and retain the intent otherwise.
//
// errors.Is(err, ErrRetained) means the intent was kept for a later run — its own outcome, not a
// failure. Any other error is a refusal.
func Reconcile(ctx context.Context, l *ledger.Ledger, objs Objects, rt Reissuer, class prov.Class, name string) error {
	if !prov.ClassOK(class) {
		return fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	// A CONTAINER INTENT IS NOT RECONCILED HERE. It is opened write-ahead and records the desired
	// state and the check its bring-up owes; finishing it means committing both BEFORE confirming,
	// and then verifying the container live. This function does none of that — it would confirm
	// the object and drop the intent, leaving the container accounted for, with no desired state,
	// never started and never verified.
	if class == prov.ClassContainer {
		return fmt.Errorf("intent: a container intent is not reconciled here. It is opened write-ahead and records\n"+
			"  the desired state and the check its bring-up owes; finishing it means committing both\n"+
			"  BEFORE confirming, and then verifying the container live. This function does none of\n"+
			"  that — it would confirm the object and drop the intent, leaving %q accounted for,\n"+
			"  with no desired state, never started and never verified.\n"+
			"  Finish it through the bring-up recovery path, or run 'mythical-ctl state repair'.", name)
	}
	rec, err := Find(l, class, name)
	if err != nil {
		return err
	}
	nonce, err := nonceOf(rec, name)
	if err != nil {
		return err
	}
	ident, err := l.IdentGet()
	if err != nil {
		return err
	}
	// NO ANSWER AND AN EMPTY ANSWER ARE NOT THE SAME FACT: every decision below — reissuing,
	// adopting, abandoning — would otherwise be made from a question that was never answered.
	matches, err := objs.FindByNonce(ctx, class, nonce)
	if err != nil {
		return fmt.Errorf("intent: the container runtime could not be asked which %ss carry nonce %q.\n"+
			"  The intent for %s %q is RETAINED and will be reconciled on a later run: %w",
			string(class), nonce, string(class), name, errors.Join(ErrRetained, err))
	}

	if len(matches) > 1 {
		// EVERY candidate is named. The reference's report stopped correctly and named NONE of
		// them, because the list was published through a shell global assigned inside a subshell.
		return fmt.Errorf("intent: more than one %s carries nonce %q — stopping.\n"+
			"  This can only come from a duplicate create and cannot be safely disambiguated.\n"+
			"  Candidates:\n    %s\n"+
			"  Remove the one you do not want with the container runtime directly, then re-run.",
			string(class), nonce, strings.Join(matches, "\n    "))
	}

	if len(matches) == 1 {
		found := matches[0]
		own, why, oerr := ours(ctx, objs, class, name, found, ident, nonce)
		if oerr != nil {
			return errors.Join(ErrRetained, oerr)
		}
		switch own {
		case ownOurs:
		case ownGone:
			return fmt.Errorf("intent: the %s carrying nonce %q is already gone. Nothing is adopted; the\n"+
				"  intent is RETAINED and will be reconciled on a later run: %w", string(class), nonce, ErrRetained)
		default:
			return fmt.Errorf("%s\n  The intent for %s %q is RETAINED and will be reconciled on a later run: %w",
				why, string(class), name, ErrRetained)
		}
		var extra []ledger.Field
		if class == prov.ClassNetwork {
			// A NETWORK IS RECORDED BY ITS ID (§6a rejects names as reassignable), so with no id
			// there is nothing to record.
			id, ierr := objs.NetworkID(ctx, found)
			if errors.Is(ierr, engine.ErrAbsent) {
				return fmt.Errorf("intent: network %q was listed and is already gone. Nothing is adopted; the\n"+
					"  intent is RETAINED and will be reconciled on a later run: %w", found, ErrRetained)
			}
			if ierr != nil {
				return fmt.Errorf("intent: the network carrying nonce %q could not be inspected, so this run\n"+
					"  cannot record what it is. The intent is RETAINED and nothing was written: %w",
					nonce, errors.Join(ErrRetained, ierr))
			}
			if id == "" {
				return fmt.Errorf("intent: the runtime named no id for network %q. A network is recorded by its\n"+
					"  id (§6a rejects names as reassignable), so there is nothing to record. The intent\n"+
					"  is RETAINED: %w", found, ErrRetained)
			}
			extra = append(extra, ledger.Field{Key: "id", Value: id})
		}
		return Confirm(l, class, name, nonce, append(extra, reportingFields(rec)...)...)
	}

	// NOTHING CARRIES THE NONCE.
	switch class {
	case prov.ClassNetwork:
		// D38: a network is NEVER reissued — two networks answering one name is the failure this
		// refusal exists to prevent.
		return fmt.Errorf("intent: no network carries nonce %q yet, and a network is never reissued (D38).\n"+
			"  The intent is retained and will be reconciled on a later run.\n"+
			"  If it never appears, 'mythical-ctl state abandon-intent network %s' offers a\n"+
			"  confirmed abandonment after a grace period: %w", nonce, name, ErrRetained)
	case prov.ClassProbe:
		return fmt.Errorf("intent: no probe carries nonce %q; rebuilding it needs the launch spec, so the\n"+
			"  intent is retained and the verb that opened it will re-create it: %w", nonce, ErrRetained)
	case prov.ClassVolume:
	default:
		return fmt.Errorf("intent: reissuing a %s is not implemented — the intent is retained: %w", string(class), ErrRetained)
	}

	if rt == nil {
		return fmt.Errorf("intent: no runtime to reissue volume %q with — the intent is RETAINED: %w", name, ErrRetained)
	}
	p, perr := engine.NewProvenance(ident, nonce)
	if perr != nil {
		return perr
	}
	if err := rt.VolumeCreate(ctx, name, p); err != nil {
		return fmt.Errorf("intent: reissuing volume %q failed — retaining the intent for the next run: %w",
			name, errors.Join(ErrRetained, err))
	}
	// THE REISSUE IS NOT THE PROOF. A create against an existing name SUCCEEDS and returns
	// whatever already holds it, without applying our labels — so what the reissue returned is
	// asked the same ownership question as anything else found by nonce.
	own, why, oerr := ours(ctx, objs, prov.ClassVolume, name, name, ident, nonce)
	if oerr != nil {
		return errors.Join(ErrRetained, oerr)
	}
	switch own {
	case ownOurs:
	case ownGone:
		return fmt.Errorf("intent: the volume the reissue returned is already gone. The intent is RETAINED: %w", ErrRetained)
	default:
		return fmt.Errorf("%s\n  The intent for volume %q is RETAINED, and nothing was recorded for it: %w",
			why, name, ErrRetained)
	}
	return Confirm(l, prov.ClassVolume, name, nonce, reportingFields(rec)...)
}
