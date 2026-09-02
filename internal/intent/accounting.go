package intent

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
)

// ProbeAccounting is the DURABLE implementation of probe.Accounting — the seam internal/probe
// defines and stands an in-test fake behind. A probe container is an ordinary intent of class `probe`: opened
// write-ahead before the container exists, retired only once the runtime has said the object is
// gone. Nothing about it is special except that the prober, not a verb, owns its lifecycle.
//
// It is the one place in this package that reaches the DISK, because the interface it satisfies
// takes no ledger: each method is a read-modify-write under the family lock, whose token it holds.
// Everything else here mutates an in-memory ledger the caller persists.
type ProbeAccounting struct {
	h   famlock.Held
	st  ledger.Store
	now func() time.Time
}

// NewProbeAccounting binds the accounting to a held family lock. It asserts the token up front so
// a caller cannot build one from a lock it does not hold and discover that only at the first probe.
func NewProbeAccounting(h famlock.Held, now func() time.Time) (*ProbeAccounting, error) {
	if err := famlock.Assert(h, "record probe intents"); err != nil {
		return nil, err
	}
	st, err := ledger.Live(h)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &ProbeAccounting{h: h, st: st, now: now}, nil
}

// load reads the ledger, treating ABSENT as the legitimate empty start — the same distinction the
// ledger itself draws, and never conflated with a read that failed.
func (a *ProbeAccounting) load() (*ledger.Ledger, error) {
	l, err := ledger.Read(a.st)
	if errors.Is(err, ledger.ErrMissingLedger) {
		return &ledger.Ledger{}, nil
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

// OpenProbe records intent for a probe container BEFORE it is created.
func (a *ProbeAccounting) OpenProbe(name, nonce string) error {
	l, err := a.load()
	if err != nil {
		return err
	}
	if err := Open(l, prov.ClassProbe, name, nonce, a.now()); err != nil {
		return err
	}
	return ledger.Write(a.h, a.st, l)
}

// DropProbe retires the record. Called ONLY once the runtime has said the object is gone, or it
// has been removed — dropping it any earlier is how a probe container outlives the only record
// that would authorize removing it.
func (a *ProbeAccounting) DropProbe(name string) error {
	l, err := a.load()
	if err != nil {
		return err
	}
	if err := Drop(l, prov.ClassProbe, name); err != nil {
		return err
	}
	return ledger.Write(a.h, a.st, l)
}

// ProbeIntents lists every recorded probe intent. A ledger that does not exist yet is an EMPTY
// list — first use, nothing of ours can exist — and that is the only absence folded this way: a
// ledger that exists and cannot be read is an error, never an empty sweep.
//
// A record whose nonce this module refuses to read is REPORTED, not skipped: the prober's reap
// would otherwise walk past exactly the record that needs a human.
//
// THIS IS A SELECTION POINT, AND THE ONE THAT MUTATES THE RUNTIME FROM WHAT IT RETURNS. The rows
// come out of a listing rather than a keyed lookup, so Find's agreement check never sees them —
// and what the caller does with each row is REMOVE THE CONTAINER IT NAMES and then drop the record
// by key. Both questions Find would have asked have to be asked here instead, and they have to be
// asked over the WHOLE list before any of it is handed back, because the caller acts on row 1
// before it has looked at row 2:
//
//   - AGREEMENT. A row's `key=` is what Drop and Open address it by; its `name=` is what gets
//     removed. Nothing makes them agree. A row keyed `probe:a` naming `b` had `b` removed and
//     then `probe:a` dropped — the wrong container gone, and its own record left standing to say
//     it is still there. (Asked in BOTH directions: a row whose class is `probe` while its key is
//     not, and a row in the `probe:` key namespace whose class is not, are the same defect seen
//     from either end, and skipping the second would hide a probe container from every reap.)
//   - CARDINALITY. Two rows keyed `probe:p1` are two claims about one object. The listing returned
//     both, the caller reaped the container on the first — and only THEN did the keyed Drop refuse
//     ErrAmbiguous. The runtime had already been mutated on evidence that contradicted itself, and
//     the refusal that was supposed to prevent it arrived one step too late. It is the ledger's own
//     rule (Find and Del refuse a key two rows answer for), applied where a listing bypasses it.
func (a *ProbeAccounting) ProbeIntents() ([]probe.ProbeIntent, error) {
	l, err := a.load()
	if err != nil {
		return nil, err
	}
	rows, err := All(l)
	if err != nil {
		return nil, err
	}
	var out []probe.ProbeIntent
	seen := map[string]bool{}
	for _, rec := range rows {
		class, _ := ledger.FieldOf(rec, "class")
		k, _ := ledger.FieldOf(rec, "key")
		isProbe := class == string(prov.ClassProbe)
		keyedProbe := strings.HasPrefix(k, string(prov.ClassProbe)+":")
		if !isProbe && !keyedProbe {
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok || name == "" {
			return nil, errors.New("intent: a probe intent carries no name — it describes nothing that can be found or removed; preserved and reported. Run 'mythical-ctl state repair'")
		}
		// The key this module would MINT for what the row says it is about, against the key the row
		// actually carries. Same function, so there is no second spelling of the key format to drift.
		if want := key(prov.ClassProbe, name); !isProbe || k != want {
			return nil, fmt.Errorf("intent: a probe intent is filed under %q while describing %s %q — it would be\n"+
				"  addressed as one object and acted on as another: the container named here would be\n"+
				"  removed and the record under that key dropped, leaving each of them accounted for by\n"+
				"  the other. Nothing is reaped and nothing is dropped; it is PRESERVED and reported.\n"+
				"  Run 'mythical-ctl state repair'.", k, class, name)
		}
		if seen[k] {
			return nil, fmt.Errorf("intent: more than one probe intent answers for %q — two claims about one object.\n"+
				"  Reaping on one of them and discovering the contradiction afterwards would have\n"+
				"  removed a container on evidence that contradicts itself. Nothing is reaped;\n"+
				"  everything is PRESERVED and reported. Run 'mythical-ctl state repair': %w", k, ledger.ErrAmbiguous)
		}
		seen[k] = true
		nonce, nerr := nonceOf(rec, name)
		if nerr != nil {
			return nil, nerr
		}
		out = append(out, probe.ProbeIntent{Name: name, Nonce: nonce})
	}
	return out, nil
}
