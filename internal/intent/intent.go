// Package intent is §6b's write-ahead record: the installer writes down what it is ABOUT to
// create before it creates it, so a crash between "the daemon accepted the request" and "the
// record exists" leaves evidence rather than an orphan.
//
// The rule that shapes it: AN INTENT IS OPENED BEFORE ITS OBJECT IS CREATED AND CONFIRMED ONLY
// AFTER THE OBJECT IS VERIFIED PRESENT. Everything else follows — reconciliation adopts only what
// it can prove is ours, abandonment is bounded by a grace period and never guarantees
// convergence, and the unaccounted gate REPORTS: it never deletes.
//
// Like internal/prov, these functions mutate an IN-MEMORY *ledger.Ledger and the caller's single
// ledger.Write persists them — which is what makes "provenance in, intent out, ONE ledger write"
// structural here rather than a discipline. Two writes would leave a window in which the object is
// both intended and recorded, and a crash there gives the next run two accounts of one object.
package intent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
)

const kindIntent = "intent"

// DefaultGrace is D39's grace period. NOT "quiescence": §6b.1 concedes the installer cannot
// observe whether the daemon has finished a request it accepted, so there is no quiescent state to
// detect. This is a heuristic delay that makes a late arrival less likely, and nothing more. Five
// minutes — long enough that a daemon completing an accepted create has finished, short enough
// that an operator hitting the wedge is not told to come back tomorrow.
const DefaultGrace = 5 * time.Minute

var (
	// ErrRetained — the intent could not be finished on this run and is KEPT for a later one.
	// Its own outcome, distinct from a refusal: nothing is wrong, nothing was written, and the
	// caller proceeds rather than stopping.
	ErrRetained = errors.New("intent: retained — it will be reconciled on a later run")
	// ErrUnaccounted — the gate found objects the ledger cannot account for. Reported, never acted
	// on: nothing here deletes.
	ErrUnaccounted = errors.New("intent: objects the ledger does not account for")
)

// NonceNew mints a fresh nonce: a safe label value that must not repeat across calls.
//
// The reference derived it from pid, clock and $RANDOM through a digest, and its comment had to
// explain at length why a monotonic counter beside it did NOT contribute (every caller reads a
// PRINTED value, so command substitution ran the function in a subshell and discarded the
// counter's increment — measured, it read 1 on every call). None of that machinery survives the
// port: crypto/rand is the source, and 8 bytes of it is the whole argument. The FORMAT is kept
// byte-compatible with the reference's — `n` + 16 lowercase hex — because it is a label value that
// existing installations already carry.
func NonceNew() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("intent: cannot mint a nonce: %w", err)
	}
	return "n" + hex.EncodeToString(b), nil
}

// key is class:name — ONE LIVE INTENT PER OBJECT, and the same class+name key provenance uses, for
// the same reason (a container and a volume can derive the same name).
func key(class prov.Class, name string) string { return string(class) + ":" + name }

// Objects is the read side intent needs, over prov's: the ping that makes "zero matches" mean
// something, the nonce-filtered find that recovery searches with, and a network's id.
type Objects interface {
	prov.Objects
	// Ping reports whether the runtime is answering at all.
	Ping(ctx context.Context) error
	// FindByNonce lists the names of objects of the class carrying the nonce label. An error
	// means the runtime could not be ASKED — never "there are none".
	FindByNonce(ctx context.Context, class prov.Class, nonce string) ([]string, error)
	// NetworkID returns a network's immutable id. engine.ErrAbsent means it is gone.
	NetworkID(ctx context.Context, name string) (string, error)
}

// Reissuer is the ONE mutation intent performs: re-creating a volume whose intent is open but
// whose object never appeared. *runtime.Runtime satisfies it, which is how the family lock stays
// on the path — intent never holds a Mutator of its own.
type Reissuer interface {
	VolumeCreate(ctx context.Context, name string, p engine.Provenance) error
}

type engineObjects struct {
	prov.Objects
	c *engine.Client
}

// Engine wraps a client as intent's read seam.
func Engine(c *engine.Client) Objects {
	return engineObjects{Objects: prov.Engine(c), c: c}
}

func (e engineObjects) Ping(ctx context.Context) error { return e.c.Ping(ctx) }

func (e engineObjects) FindByNonce(ctx context.Context, class prov.Class, nonce string) ([]string, error) {
	filter := map[string]string{"nonce": nonce}
	switch class {
	case prov.ClassVolume:
		rows, err := e.c.VolumeList(ctx, filter)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out, nil
	case prov.ClassNetwork:
		rows, err := e.c.NetworkList(ctx, filter)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out, nil
	case prov.ClassContainer, prov.ClassProbe:
		// A probe IS a container to the runtime — the one class whose runtime kind is not its own
		// name, folded HERE rather than at every query.
		rows, err := e.c.ContainerList(ctx, filter)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Names...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("intent: %q is not a class the runtime can be searched by", string(class))
}

func (e engineObjects) NetworkID(ctx context.Context, name string) (string, error) {
	info, err := e.c.NetworkInspect(ctx, name)
	if err != nil {
		return "", err
	}
	return info.ID, nil
}

// nonceOf reads THE NONCE OUT OF AN INTENT RECORD — and PRESENCE is not the question, a VALUE is.
//
// A field spelled `nonce=` with nothing after it is a legal field, so "the record answered" is not
// "there is a nonce". An empty nonce is the single value that makes every label query match
// nothing while looking exactly like a clean zero — after which reconciliation reissues and
// abandonment clears, both on the strength of a question that asked about nothing.
func nonceOf(fields []ledger.Field, name string) (string, error) {
	v, ok := ledger.FieldOf(fields, "nonce")
	if !ok {
		return "", fmt.Errorf("intent: the intent for %q carries no nonce — it names nothing the runtime can be\n"+
			"  asked about, so it can be neither reconciled nor aged out. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", name)
	}
	if v == "" {
		return "", fmt.Errorf("intent: the intent for %q carries an EMPTY nonce — it says an object was about to be\n"+
			"  created without saying which one. A label query for it matches nothing, which is\n"+
			"  indistinguishable from 'it was never created'. It is PRESERVED and reported.\n"+
			"  Run 'mythical-ctl state repair'.", name)
	}
	return v, nil
}

// Open records an intent. Extra fields ride along (product, role, id) so the confirmation and any
// report can name what was being built.
//
// `now` is the caller's clock. The reference read it itself and REFUSED when it could not, because
// its fallback (`created=0`) was fail-open in the one direction that matters: a zero makes an
// intent older than any grace period the moment it is written, so a network intent created seconds
// ago becomes abandonable immediately. Here the clock cannot fail to be read, so what survives is
// the refusal of a value that would fail open — a zero or negative timestamp.
func Open(l *ledger.Ledger, class prov.Class, name, nonce string, now time.Time, extra ...ledger.Field) error {
	if !prov.ClassOK(class) {
		return fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	// REFUSED ON THE WAY IN AS WELL AS ON THE WAY OUT. nonceOf refuses an empty nonce when a
	// record is READ, because a restored ledger can carry one; this refuses a caller that would
	// WRITE one, because an intent that names no object can never be reconciled and would sit in
	// the ledger forever. The two are the same rule at the two ends the record travels between.
	if nonce == "" {
		return errors.New("intent: refusing to record an intent with an empty nonce — the nonce is the only thing\n" +
			"  that lets recovery find the object this intent describes.")
	}
	secs := now.Unix()
	if secs <= 0 {
		return fmt.Errorf("intent: refusing to record an intent dated %d — a zero or negative creation time\n"+
			"  makes it abandonable the moment it is written, and a delayed create could then surface\n"+
			"  after abandonment. That is the bounded-retention rule this timestamp exists to enforce.", secs)
	}
	k := key(class, name)
	fields := []ledger.Field{
		{Key: "key", Value: k},
		{Key: "class", Value: string(class)},
		{Key: "name", Value: name},
		{Key: "nonce", Value: nonce},
		{Key: "created", Value: strconv.FormatInt(secs, 10)},
	}
	fields = append(fields, extra...)
	return l.Put(kindIntent, "key", k, fields)
}

// Find returns the intent record for class/name. ledger.ErrAbsentRecord is the ANSWER "none".
func Find(l *ledger.Ledger, class prov.Class, name string) ([]ledger.Field, error) {
	if !prov.ClassOK(class) {
		return nil, fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	return l.Find(kindIntent, "key", key(class, name))
}

// All lists every recorded intent. COMPLETENESS IS THE CONTRACT: one record it cannot read is a
// refusal, never a shorter list.
func All(l *ledger.Ledger) ([][]ledger.Field, error) { return l.All(kindIntent) }

// Drop retires an intent record.
func Drop(l *ledger.Ledger, class prov.Class, name string) error {
	if !prov.ClassOK(class) {
		return fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	return l.Del(kindIntent, "key", key(class, name))
}

// Confirm is PROVENANCE IN, INTENT OUT — the second half of the write-ahead pair.
//
// It touches THREE record sets (the intent it consumes, the object record it writes, the tombstone
// it supersedes), and each gets the cardinality question asked of it by the one function that asks
// it. A hand-rolled "drop every row whose key matches" filter would replace two contradicting
// intent rows, or two tombstones, with one confirmation — destroying the only evidence that the
// ledger needed repairing.
func Confirm(l *ledger.Ledger, class prov.Class, name, nonce string, extra ...ledger.Field) error {
	if !prov.ClassOK(class) {
		return fmt.Errorf("intent: %q is not a provenance class", string(class))
	}
	// THERE MUST BE SOMETHING THIS IS THE SECOND HALF OF. Provenance is written for an object this
	// installer recorded that it was about to create, never on its own.
	fields, err := l.Find(kindIntent, "key", key(class, name))
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return fmt.Errorf("intent: there is no recorded intent for %s %q, so there is nothing this\n"+
			"  confirmation is the second half of. Provenance is written for an object this installer\n"+
			"  recorded that it was about to create, never on its own. Nothing was written.",
			string(class), name)
	}
	if err != nil {
		return err
	}
	if derr := prov.Describes(fields, class, name); derr != nil {
		return derr
	}
	inonce, nerr := nonceOf(fields, name)
	if nerr != nil {
		return nerr
	}
	if inonce != nonce {
		return fmt.Errorf("intent: the intent for %s %q names nonce %q, and this confirmation\n"+
			"  carries %q. Those are two different objects, and recording one while dropping\n"+
			"  the record of the other would leave whatever is actually standing there accounted for\n"+
			"  by nothing at all. Both are PRESERVED and nothing was written.",
			string(class), name, inonce, nonce)
	}
	// THREE RECORD SETS, THREE CARDINALITY QUESTIONS, ALL ASKED BEFORE ANYTHING IS WRITTEN. The
	// intent above; the object record, which prov.Record's generation read asks for; and the
	// TOMBSTONE, which is not covered by either — a confirmation drops it (the object is standing
	// again, so the record of its removal is no longer the surviving account of it), and a
	// contradiction among tombstones must refuse BEFORE the object record has been rewritten
	// rather than after.
	if _, terr := prov.TombstoneFind(l, class, name); terr != nil && !errors.Is(terr, ledger.ErrAbsentRecord) {
		return terr
	}
	// prov.Record computes the generation from what it can READ, so a confirmation cannot invent
	// one, and its keyed put supersedes rather than appending beside.
	if err := prov.Record(l, class, name, nonce, extra...); err != nil {
		return err
	}
	if err := prov.TombstoneDrop(l, class, name); err != nil {
		return err
	}
	return l.Del(kindIntent, "key", key(class, name))
}
