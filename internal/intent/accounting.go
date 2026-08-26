package intent

import (
	"errors"
	"time"

	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
)

// ProbeAccounting is the DURABLE implementation of probe.Accounting — the seam Wave 3 defined and
// stood an in-test fake behind. A probe container is an ordinary intent of class `probe`: opened
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
	for _, rec := range rows {
		class, _ := ledger.FieldOf(rec, "class")
		if class != string(prov.ClassProbe) {
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok || name == "" {
			return nil, errors.New("intent: a probe intent carries no name — it describes nothing that can be found or removed; preserved and reported. Run 'mythical-ctl state repair'")
		}
		nonce, nerr := nonceOf(rec, name)
		if nerr != nil {
			return nil, nerr
		}
		out = append(out, probe.ProbeIntent{Name: name, Nonce: nonce})
	}
	return out, nil
}
