package prov

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
)

// Authority is THE function every removal path must call, and the only one that may say yes.
//
// It answers ONE question in two halves, and it takes evidence for both: DID THIS INSTALLER CREATE
// THIS OBJECT (the object's installation label equals this installation's identity) AND IS THE
// THING THERE NOW STILL IT (the object's nonce label equals the recorded one). A record alone is a
// claim about the past; both labels are the object's own answer about the present.
//
// nil authorized · ErrGone the object is already gone (nothing to do) · any other error NOT
// authorized, and it carries the reason.
//
// Every "no" preserves. There is no argument that flips it, and no caller may fall back to
// deleting by name when this refuses — that is exactly the misidentification the nonce catches.
func Authority(ctx context.Context, l *ledger.Ledger, objs Objects, class Class, name string) error {
	if class == "image" {
		return errors.New("prov: images are never removed automatically (D37) — the ledger proves acquisition, not\n" +
			"  ownership, and the same digest may back another installation or a local build.")
	}
	if err := classCheck(class); err != nil {
		return err
	}
	if objs == nil {
		return errors.New("prov: no runtime to ask — authorizing nothing")
	}

	fields, err := Find(l, class, name)
	if errors.Is(err, ledger.ErrAbsentRecord) {
		// NO ACTIVE RECORD IS NOT ONE FACT, IT IS TWO, and the reference answered both the same
		// way. A resume that reaches its removal phase after its OWN prior attempt already removed
		// the object and tombstoned its record has nothing left to authorize and nothing to fear
		// either — the object is GONE, by this installer's own hand. That is "already gone", not
		// "cannot prove ownership". So ask the runtime directly before concluding:
		//   GONE (the object does not exist)     → ErrGone: nothing to authorize, nothing to preserve.
		//   PRESENT                              → an unattributed object is preserved and reported,
		//                                          never assumed ours on no evidence.
		//   COULD NOT BE ASKED                   → fail closed, exactly like the sibling checks
		//                                          below: authorizing "already gone" on a question
		//                                          that could not even be asked would be the same
		//                                          refusal-into-answer fold this module exists to
		//                                          prevent.
		_, lerr := objs.Label(ctx, class, name, LabelInstall)
		if errors.Is(lerr, engine.ErrAbsent) {
			return ErrGone
		}
		if lerr != nil {
			return fmt.Errorf("prov: %q has no provenance record, and whether it still exists could not be\n"+
				"  established either — the container runtime did not answer. Refusing rather than\n"+
				"  authorizing anything on a question that could not be asked: %w", name, lerr)
		}
		return fmt.Errorf("prov: %q has no provenance record — preserving it and reporting.\n"+
			"  The installer cannot prove it created this, so it will not remove it.", name)
	}
	if err != nil {
		return err
	}

	// THE RECORD MUST BE ABOUT WHAT WAS ASKED ABOUT — the third door, and the one that stays shut
	// when the other two are walked around. A record whose key says one object while its class and
	// name describe another answers the lookup for the first and then hands this function the
	// SECOND object's nonce, compared against the FIRST object's label — and if they happen to
	// match, deletion of an object this installer never created is authorized.
	//
	// Checked here rather than in Find: this is the only function that turns a record into
	// permission to delete, and a check in Find as well would be a check in neither — the earlier
	// would shadow the later.
	if derr := Describes(fields, class, name); derr != nil {
		return derr
	}

	recorded, _ := ledger.FieldOf(fields, "nonce")
	if recorded == "" {
		return fmt.Errorf("prov: the record for %q carries no nonce — preserving it and reporting.", name)
	}

	// WHOSE IS IT — the half the nonce does not answer.
	//
	// Authority once rested on the nonce alone. A nonce says the record and the object agree about
	// WHICH object this is; it says nothing about WHOSE. So with this installation `iA`, a record
	// for `volume:v` carrying `nonce=N`, and a live volume `v` labelled `installation=iB, nonce=N`,
	// deleting ANOTHER INSTALLATION'S OBJECT was authorized — the exact collision the installation
	// identity exists to prevent (§4b.4). The realistic source is a restored or foreign ledger,
	// where whoever supplied the record supplied the nonce with it, so the nonce proves nothing on
	// its own; the evidence that does is the object's own installation label.
	//
	// Asked BEFORE the nonce so the refusal names the real fact: telling an operator that a foreign
	// object's nonce mismatched would be true and useless, and if the nonces happened to match
	// there would be nothing to tell them at all.
	label, err := objs.Label(ctx, class, name, LabelInstall)
	if errors.Is(err, engine.ErrAbsent) {
		return ErrGone // already gone: nothing to authorize, nothing to fear
	}
	if err != nil {
		return fmt.Errorf("prov: the container runtime could not be asked who owns %q — authorizing nothing: %w", name, err)
	}
	label = normalizeLabel(label)
	if label == "" {
		return fmt.Errorf("prov: %q carries no installation label — nothing about the object itself says this\n"+
			"  installer created it. An unlabelled object standing at a name this installer would\n"+
			"  create is neither adopted nor removed: no label proves it is ours, and no provenance\n"+
			"  proves it is not someone else's. PRESERVED and reported.", name)
	}
	self, serr := l.IdentGet()
	if serr != nil {
		return fmt.Errorf("prov: this installation's own identity cannot be read, so nothing can be shown to belong\n"+
			"  to it — no removal is authorized. Every runtime name and every ownership claim is\n"+
			"  scoped by that identity. Run 'mythical-ctl state repair': %w", serr)
	}
	if label != self {
		return fmt.Errorf("prov: %q is labelled for installation %q; this installation is %q.\n"+
			"  It belongs to another installation on the same daemon. A ledger record and a matching\n"+
			"  nonce do not make it ours — a restored or foreign ledger supplies both — so it is\n"+
			"  PRESERVED and reported, never removed and never adopted.", name, label, self)
	}

	actual, err := objs.Label(ctx, class, name, LabelNonce)
	if errors.Is(err, engine.ErrAbsent) {
		return ErrGone
	}
	if err != nil {
		return fmt.Errorf("prov: the container runtime could not be asked which object %q is — authorizing nothing: %w", name, err)
	}
	if normalizeLabel(actual) != recorded {
		return fmt.Errorf("prov: %q carries nonce %q but the ledger recorded %q — it does not match.\n"+
			"  A name can be reassigned to an object this installer never created, so this is\n"+
			"  PRESERVED and reported rather than removed.", name, normalizeLabel(actual), recorded)
	}
	return nil
}
