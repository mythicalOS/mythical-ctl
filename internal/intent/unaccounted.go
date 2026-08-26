package intent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
)

// FindingKind is what the scan concluded about one object. The four reported kinds are the four a
// verb must act on; everything the scan can account for produces no finding at all.
type FindingKind string

const (
	// FindingUnattributed — labelled for ANOTHER installation on this daemon. Left untouched, and
	// it does not stop anything: another user's objects are not this installation's business.
	FindingUnattributed FindingKind = "unattributed"
	// FindingUnrecorded — labelled for THIS installation, and the ledger has no record of it.
	// Ours, and the ledger is wrong about it. Never silently adopted, never automatically deleted.
	FindingUnrecorded FindingKind = "unrecorded"
	// FindingColliding — holds a name this installer would create, but carries no label at all.
	FindingColliding FindingKind = "colliding"
	// FindingUnasked — the question could not be asked. An empty answer and no answer are not the
	// same fact, and this is the one the gate must never fold into "nothing there".
	FindingUnasked FindingKind = "unasked"
)

// Finding is one row of the report. Name is "-" when what could not be asked for is a whole
// listing rather than an object.
type Finding struct {
	Kind  FindingKind
	Class prov.Class
	Name  string
}

// accounts answers whether a ledger record accounts for what is ACTUALLY standing there: it must
// describe this object, and its recorded nonce must be present and equal the live one. An empty
// recorded nonce accounts for nothing — it is the value that matches everything by looking like
// nothing.
func accounts(rec []ledger.Field, class prov.Class, name, live string) bool {
	if prov.Describes(rec, class, name) != nil {
		return false
	}
	recorded, _ := ledger.FieldOf(rec, "nonce")
	return recorded != "" && live != "" && recorded == live
}

// classify decides what one object is, in the order the evidence becomes available.
func classify(ctx context.Context, l *ledger.Ledger, objs Objects, class prov.Class, name, ident string) FindingKind {
	lident, err := objs.Label(ctx, class, name, prov.LabelInstall)
	if errors.Is(err, engine.ErrAbsent) {
		return "" // gone between the listing and the question: nothing to report
	}
	if err != nil {
		return FindingUnasked
	}
	if lident == "" {
		// UNLABELLED. Only a name this installer would create matters: anything else on the daemon
		// is simply not ours to have an opinion about.
		if name == manifest.NamePrefix+"-"+ident || strings.HasPrefix(name, manifest.NamePrefix+"-"+ident+"-") {
			return FindingColliding
		}
		return ""
	}
	if lident != ident {
		return FindingUnattributed
	}
	lnonce, err := objs.Label(ctx, class, name, prov.LabelNonce)
	if errors.Is(err, engine.ErrAbsent) {
		return ""
	}
	if err != nil {
		return FindingUnasked
	}
	// A provenance record accounts for it, or an OPEN INTENT does — an object mid-creation is
	// accounted for by the record that says it was about to be created.
	rec, ferr := prov.Find(l, class, name)
	switch {
	case ferr == nil:
		if accounts(rec, class, name, lnonce) {
			return ""
		}
	case errors.Is(ferr, ledger.ErrAbsentRecord):
	default:
		return FindingUnasked
	}
	irec, ierr := Find(l, class, name)
	switch {
	case ierr == nil:
		if accounts(irec, class, name, lnonce) {
			return ""
		}
	case errors.Is(ierr, ledger.ErrAbsentRecord):
	default:
		return FindingUnasked
	}
	// THE LEDGER ANSWERS FOR THE NAME, and the object standing at it carries a nonce that is not
	// the one recorded. A name can be reassigned: an object can be removed and another created at
	// the same name, and it inherits nothing from the record of the one that is gone.
	return FindingUnrecorded
}

// UnaccountedScan is §6b.2's sweep: every object the runtime holds, judged against the ledger.
// It REPORTS — it never deletes, and it never adopts.
func UnaccountedScan(ctx context.Context, l *ledger.Ledger, objs Objects) []Finding {
	var out []Finding
	if objs == nil {
		return []Finding{{Kind: FindingUnasked, Class: "container runtime", Name: "-"}}
	}
	ident, err := l.IdentGet()
	if err != nil {
		// NO IDENTITY AT ALL is first use — nothing of ours can exist, so there is nothing to
		// account for. Any OTHER failure to read it is a question that could not be asked, and
		// every ownership answer below is scoped by that identity.
		if errors.Is(err, ledger.ErrAbsentRecord) {
			return nil
		}
		return []Finding{{Kind: FindingUnasked, Class: "installation identity", Name: "-"}}
	}
	for _, class := range []prov.Class{prov.ClassContainer, prov.ClassVolume, prov.ClassNetwork} {
		names, lerr := objs.Names(ctx, class)
		if lerr != nil {
			out = append(out, Finding{Kind: FindingUnasked, Class: class, Name: "-"})
			continue
		}
		for _, name := range names {
			if name == "" {
				continue
			}
			if k := classify(ctx, l, objs, class, name, ident); k != "" {
				out = append(out, Finding{Kind: k, Class: class, Name: name})
			}
		}
	}
	return out
}

// UnaccountedGate is what a verb asks BEFORE it changes anything. nil means proceed; an error
// wrapping ErrUnaccounted carries the whole report, every row of it.
//
// An unattributed object does NOT stop anything — it belongs to another installation and is left
// untouched. The other three do.
func UnaccountedGate(ctx context.Context, l *ledger.Ledger, objs Objects) error {
	var notes, stops []string
	for _, f := range UnaccountedScan(ctx, l, objs) {
		switch f.Kind {
		case FindingUnattributed:
			notes = append(notes, fmt.Sprintf("note: %s %q carries an installation label that is not this\n"+
				"  installation's. It may belong to another user on this daemon. It is left untouched.",
				string(f.Class), f.Name))
		case FindingUnrecorded:
			stops = append(stops, fmt.Sprintf("stop: %s %q is an unrecorded same-identity object: it is labelled for THIS\n"+
				"  installation, but the ledger has no record of it.\n"+
				"  This is ours and the ledger is wrong about it — most often an abandoned intent's\n"+
				"  object that surfaced, a create confirmed after 'state repair' snapshotted, or a crash\n"+
				"  that lost the intent. It is never silently adopted and never automatically deleted.\n"+
				"  Run 'mythical-ctl state repair', or remove it with the container runtime directly.",
				string(f.Class), f.Name))
		case FindingColliding:
			stops = append(stops, fmt.Sprintf("stop: %s %q holds a name this installer would create, but is not labelled.\n"+
				"  It is neither adopted nor removed: no label proves it is ours, and no provenance\n"+
				"  proves it is not someone else's. Rename or remove it, then re-run.",
				string(f.Class), f.Name))
		case FindingUnasked:
			what := fmt.Sprintf("%s %q could not be asked about", string(f.Class), f.Name)
			if f.Name == "-" {
				what = fmt.Sprintf("the %s could not be asked for", string(f.Class))
			}
			stops = append(stops, fmt.Sprintf("stop: %s, so nothing here can be shown to be\n"+
				"  accounted for.\n"+
				"  An empty answer and no answer are not the same fact, and this gate is what a\n"+
				"  verb asks before it changes anything. Start the container runtime — or, if the\n"+
				"  installer state is what could not be read, run 'mythical-ctl state repair' — then\n"+
				"  re-run.", what))
		}
	}
	if len(stops) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", strings.Join(append(notes, stops...), "\n"), ErrUnaccounted)
}
