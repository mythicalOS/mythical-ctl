// Package prov is §6a — provenance: the record of what THIS installer created, and the only
// authority for deleting it.
//
// Why it lives in the ledger and nowhere else: every other location is disqualified. A generated
// artifact under the family home cannot carry it, because §4.1a forbids reading those back as
// authority. The manifest cannot: it describes the product, not this machine's history. The
// runtime objects cannot: an image digest is identical whether the installer pulled it or the
// operator built it.
//
// THE INVARIANT THAT SHAPES EVERY FUNCTION HERE: ANY MISMATCH PRESERVES. A checksum failure, an
// unparseable ledger, an identity that does not match what is actually there, or an object present
// with no record — all resolve to leave it alone and report. No ambiguity is ever resolved in
// favour of deletion.
//
// AUTHORIZATION NOTE (the Go shape, as in internal/ledger): the reference asserted the family lock
// inside mi_prov_tombstone because it wrote the file itself. These functions mutate an IN-MEMORY
// *ledger.Ledger — inert until persisted — and ledger.Write is the single authorization point.
// Tombstone's "both edits in ONE ledger write" requirement is therefore structural here rather
// than a discipline: the caller's single Write persists both, and a crash before it persists
// neither, which is precisely the window the reference's one-write rule existed to close.
package prov

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
)

// The three record kinds this module owns. A kind is a CLOSED vocabulary; ledger holds it to the
// same grammar a field name obeys, because it is written to the same line by the same serializer.
const (
	kindObject = "object"
	kindTomb   = "tombstone"
	kindImage  = "image"
)

// Class is a provenance class — the closed set of object kinds this installer creates and may
// therefore be authority over. `probe` is a container by every runtime question and its own class
// by every provenance question, which is exactly why it is spelled separately here.
type Class string

const (
	ClassContainer Class = "container"
	ClassVolume    Class = "volume"
	ClassNetwork   Class = "network"
	ClassProbe     Class = "probe"
)

var (
	// ErrGone — the object is ALREADY GONE: nothing to authorize and nothing to fear. The rc-3
	// analogue, and never conflated with a refusal (which is what "cannot prove ownership" is).
	ErrGone = errors.New("prov: the object is already gone")
	// ErrNotFirstUse — a ledger exists, so this machine is not a first install. An ANSWER, not a
	// refusal: the caller proceeds normally.
	ErrNotFirstUse = errors.New("prov: an installer state ledger exists — not a first install")
	// ErrMismatch — a record answered a lookup by its `key=` and then described something else.
	// A REFUSAL, and it is spelled as a sentinel because ONE caller has to tell it apart from a
	// read that failed: the unaccounted classifier, whose whole job is to distinguish an ANSWER
	// ("nothing here accounts for that object") from a question that could not be asked. Everyone
	// else propagates it, and every one of them refuses on it.
	ErrMismatch = errors.New("prov: the record does not describe the object it was found under")
)

// ClassOK closes the vocabulary. Exported because the verbs name a class from operator input.
func ClassOK(c Class) bool {
	switch c {
	case ClassContainer, ClassVolume, ClassNetwork, ClassProbe:
		return true
	}
	return false
}

func classCheck(c Class) error {
	if !ClassOK(c) {
		return fmt.Errorf("prov: %q is not a provenance class", string(c))
	}
	return nil
}

// key is CLASS + NAME, and it must be a SINGLE FIELD because the ledger editor matches one field.
//
// Keying on the name alone is not merely imprecise, it is a REACHABLE collision: a product
// literally named `p1-state` derives the container name `mythical-<id>-p1-state`, which is
// byte-identical to the volume name for product `p1` role `state`. Recording either would then
// DELETE the other's record — and an object whose provenance vanished is unauthorized for deletion
// forever, and trips §6b.2's unrecorded-same-identity gate on every later operation.
func key(class Class, name string) string { return string(class) + ":" + name }

// Objects is the READ-ONLY runtime seam this module needs: an object's label, and an unfiltered
// listing. Narrow on purpose — provenance asks the runtime what is there, and never changes it.
// The nil Objects is not accepted anywhere; every entry point that needs one refuses it, because
// "could not ask" must never arrive spelled as a nil dereference.
type Objects interface {
	// Label returns the value of the given provenance label on the named object.
	// engine.ErrAbsent means the OBJECT is gone (an answer); any other error means the question
	// could not be asked (never an answer).
	Label(ctx context.Context, class Class, name, label string) (string, error)
	// Names lists every object of the class, unfiltered. An error means the runtime could not be
	// ASKED — never "there is nothing there", which is the one conclusion a caller must never
	// reach by default.
	Names(ctx context.Context, class Class) ([]string, error)
}

// The two labels authority reads. Both are the OBJECT's own answer about the present, against
// which a record — a claim about the past — is checked.
const (
	LabelInstall = "installation"
	LabelNonce   = "nonce"
)

// engineObjects adapts the read side of the engine client. It is the only production Objects.
type engineObjects struct{ c *engine.Client }

// Engine wraps a client as the runtime seam.
func Engine(c *engine.Client) Objects { return engineObjects{c: c} }

func (e engineObjects) Label(ctx context.Context, class Class, name, label string) (string, error) {
	if err := classCheck(class); err != nil {
		return "", err
	}
	full := engine.LabelNS + label
	switch class {
	case ClassVolume:
		info, err := e.c.VolumeInspect(ctx, name)
		if err != nil {
			return "", err
		}
		return info.Labels[full], nil
	case ClassNetwork:
		info, err := e.c.NetworkInspect(ctx, name)
		if err != nil {
			return "", err
		}
		return info.Labels[full], nil
	default:
		// container AND probe: a probe is a container to every runtime question. The reference
		// folded the class the same way (`ikind`), and it is the reason the fold lives here
		// rather than at each call site.
		info, err := e.c.ContainerInspect(ctx, name)
		if err != nil {
			return "", err
		}
		return info.Labels[full], nil
	}
}

func (e engineObjects) Names(ctx context.Context, class Class) ([]string, error) {
	if err := classCheck(class); err != nil {
		return nil, err
	}
	// An UNFILTERED listing: nil labels, not an empty map — only first-use needs this, and it has
	// no identity to filter by (the ledger that held it is absent). Everything else works from
	// labels, because §6a rejects names as reassignable.
	switch class {
	case ClassVolume:
		rows, err := e.c.VolumeList(ctx, nil)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out, nil
	case ClassNetwork:
		rows, err := e.c.NetworkList(ctx, nil)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out, nil
	case ClassContainer:
		rows, err := e.c.ContainerList(ctx, nil)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Names...)
		}
		return out, nil
	}
	// probe is not a LISTABLE kind: it is a provenance class over containers, and listing it
	// would double-count the container listing. A default arm, because the reference's missing
	// one was a fail-open from a typo — an unknown kind fell through to "answered, nothing there".
	return nil, fmt.Errorf("prov: %q is not a listable object kind", string(class))
}

// Describes answers: DOES THIS RECORD DESCRIBE THE OBJECT IT WAS FOUND UNDER?
//
// A record is retrieved by its `key=` field, but `key`, `class` and `name` are three INDEPENDENT
// fields and nothing makes them agree. A record keyed `volume:v1` while carrying `class=container`
// and `name=other` answers the lookup for `volume v1` and then speaks about something else.
//
// ONE PREDICATE, APPLIED WHERE THE ROW IS SELECTED — not at each place a row is later consumed.
//
// It used to be called at the three places that consumed a record most visibly (deletion
// authority, the tombstone that outlives the object, and a confirmation's intent), and the rows
// selected by every OTHER caller went unchecked: a generation was read off a mismatched record and
// the record then overwritten by Record, an intent belonging to another object was reissued and
// abandoned, and a tombstone describing something else was replaced. Checking at consumption means
// remembering, once per consumer, forever; checking at SELECTION means a row that answers a lookup
// for X and speaks about Y never leaves the lookup at all.
//
// So it has THREE call sites, and they are the three selectors: prov.Find, prov.TombstoneFind and
// intent.Find — which is why it is EXPORTED rather than duplicated. A second copy of a guard is a
// guard that can be deleted with nothing observable changing; a guard past which no row travels is
// the only kind worth having.
func Describes(fields []ledger.Field, class Class, name string) error {
	rclass, _ := ledger.FieldOf(fields, "class")
	rname, _ := ledger.FieldOf(fields, "name")
	if rclass == string(class) && rname == name {
		return nil
	}
	shown := func(s string, what string) string {
		if s == "" {
			return "<no " + what + ">"
		}
		return s
	}
	return mismatch{fmt.Errorf("prov: the record found for %s %q does not describe it — it describes %s %q.\n"+
		"  A record that is about something else is not authority over this and is not the record OF\n"+
		"  this either, so it is PRESERVED and reported rather than acted on.\n"+
		"  Run 'mythical-ctl state repair'.",
		string(class), name, shown(rclass, "class"), shown(rname, "name"))}
}

// mismatch answers errors.Is for ErrMismatch WITHOUT appending the sentinel's text to the
// operator's message. The sentence above is complete; wrapping the sentinel with %w would print
// the same fact twice, and the operator-facing text of these refusals is load-bearing.
type mismatch struct{ error }

func (mismatch) Is(target error) bool { return target == ErrMismatch }

// genOK: A VALUE PARSED OUT OF A FILE IS NOT A NUMBER UNTIL IT HAS BEEN CHECKED.
//
// The reference's warning was about `$(( ))` being an EVALUATOR — a `gen=` carrying
// `a[$(command)]` executed that command the next time anything recorded provenance. Go has no
// arithmetic evaluator to reach, so the injection half of that hazard does not port. What DOES
// port is the rest of the rule, and it is not decoration: a generation that is not a number is
// REFUSED rather than reset to 0, because a silent reset is how a tampered record erases the
// history that would show it had been tampered with. The 18-digit bound ports as well — it keeps
// the counter inside what one signed 64-bit add can carry, so Record's +1 cannot wrap.
func genOK(s string) bool {
	if s == "" || len(s) > 18 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Find returns the object record for class/name. errors.Is(err, ledger.ErrAbsentRecord) is the
// ANSWER "no record", never a refusal.
//
// THE ROW IT RETURNS DESCRIBES WHAT WAS ASKED FOR. `key`, `class` and `name` are three
// INDEPENDENT fields and nothing in the format makes them agree, so a row keyed `volume:v1` can
// answer this lookup while speaking about a container called something else. Every caller then
// consumes it as the record FOR v1 — its generation is read and incremented, its nonce is compared
// against v1's label, its `id=` becomes the network the fleet attaches to — and the row itself is
// overwritten by the next keyed put. Refusing here is what makes "any mismatch preserves" true for
// all of them at once instead of once per caller who remembered.
func Find(l *ledger.Ledger, class Class, name string) ([]ledger.Field, error) {
	if err := classCheck(class); err != nil {
		return nil, err
	}
	fields, err := l.Find(kindObject, "key", key(class, name))
	if err != nil {
		return nil, err
	}
	if derr := Describes(fields, class, name); derr != nil {
		return nil, derr
	}
	return fields, nil
}

// Gen is the generation of the record currently held for class/name, or 0 when there is none.
func Gen(l *ledger.Ledger, class Class, name string) (uint64, error) {
	fields, err := Find(l, class, name)
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	g, _ := ledger.FieldOf(fields, "gen")
	if !genOK(g) {
		return 0, fmt.Errorf("prov: the record for %q carries a generation that is not a number (%q) — refusing.\n"+
			"  The ledger is checksummed, which proves it was not altered, not that this installation\n"+
			"  wrote it. Preserving it and reporting; run 'mythical-ctl state repair'.", name, g)
	}
	// genOK has proved digits-only and ≤18 of them, so this cannot fail and cannot overflow.
	n, perr := strconv.ParseUint(g, 10, 64)
	if perr != nil {
		return 0, perr
	}
	return n, nil
}

// Record records (or supersedes) provenance for one object. Extra fields are passed through — an
// `id=` for a container or network, a `product=`/`role=` for reporting.
//
// GENERATION-AWARE BY REWRITING: the keyed put drops the existing record for this class+name
// before appending, so reinstalling SUPERSEDES rather than appending beside. An append-only log of
// three installs otherwise leaves three claims about one object, the oldest as authoritative as
// the newest. The `gen=` counter is diagnostic; the KEY is class+name.
//
// WHAT IT SUPERSEDES IS A RECORD OF THIS OBJECT, and that is the generation read's doing rather
// than the put's: Gen goes through Find, so a row keyed here while describing something else
// refuses BEFORE the put that would have overwritten it. Superseding is for a newer claim about
// the same object; a claim about a DIFFERENT one is conflicting evidence, and this module never
// resolves that by writing over it.
func Record(l *ledger.Ledger, class Class, name, nonce string, extra ...ledger.Field) error {
	if err := classCheck(class); err != nil {
		return err
	}
	gen, err := Gen(l, class, name)
	if err != nil {
		return err
	}
	k := key(class, name)
	fields := []ledger.Field{
		{Key: "key", Value: k},
		{Key: "class", Value: string(class)},
		{Key: "name", Value: name},
		{Key: "nonce", Value: nonce},
		{Key: "gen", Value: strconv.FormatUint(gen+1, 10)},
	}
	fields = append(fields, extra...)
	return l.Put(kindObject, "key", k, fields)
}

// ImageRecord records an image acquisition (D37).
//
// Docker fixes image labels at BUILD time, so a digest-pinned image pulled from a registry cannot
// carry an installation-specific label and the nonce scheme simply does not apply. And the ledger
// proves ACQUISITION, not OWNERSHIP: even an intact ledger records only that THIS installer pulled
// that digest — never whether another installation on the same daemon, or the operator's own work,
// also depends on it. Which is why Authority refuses the image class outright.
func ImageRecord(l *ledger.Ledger, ref, product string) error {
	return l.Put(kindImage, "ref", ref, []ledger.Field{
		{Key: "ref", Value: ref},
		{Key: "product", Value: product},
	})
}

// Tombstone writes the tombstone and drops the object record.
//
// §6b: provenance survives what it describes. An ordinary uninstall RETAINS named volumes, so
// removing a product's records outright would leave a later `--purge` with no authority over
// volumes that still exist — and the fail-safe rule would then preserve them forever. So uninstall
// tombstones what it removed and keeps the rest.
//
// Both edits land in the caller's single ledger.Write (see the package note): there is no window
// in which the object is neither recorded nor tombstoned.
func Tombstone(l *ledger.Ledger, class Class, name string) error {
	if err := classCheck(class); err != nil {
		return err
	}
	k := key(class, name)

	// THE REFERENCE NEEDED ITS OWN COPY OF THE FIELD RULE HERE; THIS DOES NOT, AND THE DIFFERENCE
	// IS STRUCTURAL RATHER THAN AN OMISSION.
	//
	// The bash tombstone was the module's THIRD WRITER: it serialized its own record with printf,
	// bypassing mi_led_put, so a newline in <name> forged a whole record unless the rule was
	// restated right here. This one assembles a field LIST and hands it to the same typed editor
	// every other write goes through — and that editor refuses a malformed selector at its own
	// gate, on EVERY entry point, before anything is read or dropped. Measured: with a forged
	// name, the first call this function makes (the object-record Find, above) already refuses,
	// so no lookup, no Del and no Put is reached and nothing is written.
	//
	// A restated check here would therefore be a guard NO INPUT REACHES — and the rule this module
	// states in its own comments is that such a guard is not defence in depth, it is a guard whose
	// removal no test would notice. (`name` cannot be malformed while the key is well-formed: the
	// key IS "<class>:<name>", so a TAB or newline in one is a TAB or newline in the other.
	// `class` is closed by classCheck; `nonce` and `gen` come back out of a TAB-split line, so
	// neither can carry a separator however the ledger was written.) ONE ENFORCEMENT POINT.

	// ONE READ, AND BOTH CARDINALITY QUESTIONS ASKED BEFORE ANYTHING IS READ AS EVIDENCE OR
	// DROPPED. This rewrites TWO record sets — the object record it consumes and the earlier
	// tombstone it supersedes — so "how many are there?" is answered for BOTH, up front. The
	// second is not covered by the first: when the object record is present the tombstone lookup
	// is never reached, and the rewrite would still replace every tombstone row for this key.
	//
	// A failed lookup PROPAGATES rather than falling through to "there is no record": falling
	// through was already wrong for an unreadable ledger, and became a way to lose evidence the
	// moment a lookup could also fail for AMBIGUITY — two object records read as none, then
	// dropped by a tombstone written with an empty identity.
	//
	// BOTH LOOKUPS GO THROUGH THIS PACKAGE'S OWN SELECTORS, which is what makes the agreement
	// question cover the tombstone as well as the object record. Reading the tombstone with a raw
	// keyed find checked only the row this function ended up CONSUMING: with a good object record
	// present, a tombstone describing something else was never looked at and was replaced by the
	// put below — the other object's only surviving account, destroyed by an unrelated removal.
	orec, err := Find(l, class, name)
	if err != nil && !errors.Is(err, ledger.ErrAbsentRecord) {
		return err
	}
	otomb, terr := TombstoneFind(l, class, name)
	if terr != nil && !errors.Is(terr, ledger.ErrAbsentRecord) {
		return terr
	}

	// WHERE THE IDENTITY COMES FROM, AND WHAT A REPEAT MUST NOT LOSE. The object record is
	// authoritative while it exists. Once it is gone, THE TOMBSTONE IS the surviving record of
	// what was there — so a second removal of the same object copies it forward. Reading only the
	// object record left the retry with nothing to read: it re-initialised the identity to empty,
	// dropped the tombstone it had written a moment earlier and replaced it with an empty one —
	// inverting the one rule this operation exists to serve.
	rec := orec
	if rec == nil {
		rec = otomb
	}

	nonce, gen := "", "0"
	if rec != nil {
		// THE RECORD DESCRIBES WHAT IS BEING TOMBSTONED — established by the selectors above, on
		// BOTH sources, before either was read as evidence or dropped. A record whose class and
		// name describe something else would otherwise be consumed here anyway, its identity
		// copied into a tombstone for the object that was ASKED about and the record itself
		// dropped: conflicting evidence REPLACED, the one thing this module may never do.
		//
		// A MISSING `nonce=` loses the same way. PRESENCE is the question, not emptiness: a
		// tombstone written for an object with no record carries `nonce=` with an empty value on
		// purpose, and a repeat removal must read that back and copy it forward unchanged.
		n, ok := ledger.FieldOf(rec, "nonce")
		if !ok {
			return fmt.Errorf("prov: the record for %q carries no nonce — a tombstone records the identity of\n"+
				"  what was removed, and this record does not carry one. Preserving it and reporting;\n"+
				"  an empty tombstone would erase the fact that a record was there at all.\n"+
				"  Run 'mythical-ctl state repair'.", name)
		}
		nonce = n
		g, _ := ledger.FieldOf(rec, "gen")
		// THE SAME RULE AS THE READER'S — this module's second reader of `gen` and its only
		// writer of a gen it did not compute. Copying a generation it has just refused to READ
		// into the record that OUTLIVES the object would preserve it for the next reader instead
		// of reporting it.
		if !genOK(g) {
			return fmt.Errorf("prov: the record for %q carries a generation that is not a number (%q) —\n"+
				"  refusing to carry it into a tombstone. Run 'mythical-ctl state repair'.", name, g)
		}
		gen = g
	}

	// Exactly the two rows the selectors resolved to, and no other. The object row goes because it
	// is what is being tombstoned — CLASS AND NAME, not name alone: a container and a volume can
	// derive the same name (see key), and tombstoning one must not erase the other's provenance.
	// The earlier tombstone row goes because a second removal SUPERSEDES it rather than appending
	// beside it, or a reinstall/uninstall cycle accumulates one tombstone per generation.
	if err := l.Del(kindObject, "key", k); err != nil {
		return err
	}
	return l.Put(kindTomb, "key", k, []ledger.Field{
		{Key: "key", Value: k},
		{Key: "class", Value: string(class)},
		{Key: "name", Value: name},
		{Key: "nonce", Value: nonce},
		{Key: "gen", Value: gen},
	})
}

// TombstoneDrop retires the tombstone for class/name. A CONFIRMATION drops it: the object is
// standing again, so the record of its removal is no longer the surviving account of it, and
// leaving it beside a live object record would give the next reader two answers. Ambiguity refuses
// here as everywhere — two contradicting tombstones are evidence, not tidying material.
//
// PRECONDITION, AND WHY IT IS NOT RESTATED AS A GUARD: the row must already have been proved to
// describe class/name. Its one caller, intent.Confirm, proves it through TombstoneFind BEFORE it
// writes anything — which is where the question has to be asked anyway, because a refusal after
// prov.Record has run is a refusal that arrives too late to prevent a half-written confirmation.
// Asking it again here would be a guard standing behind another one on the only path that reaches
// it: nothing could reach it with a mismatched row, so no mutation could kill it and no test could
// see it. A second caller must ask the same question before it writes, for the same ordering
// reason, not by leaning on a check here.
func TombstoneDrop(l *ledger.Ledger, class Class, name string) error {
	if err := classCheck(class); err != nil {
		return err
	}
	return l.Del(kindTomb, "key", key(class, name))
}

// TombstoneFind returns the tombstone for class/name — the surviving record of what was removed.
//
// It asks the same agreement question as Find, for the same reason and about the other record set.
// Once the object record is gone the tombstone IS the account of what was there, so a tombstone
// keyed for this object while describing another is the only record of that other object — and it
// was being read as this one's identity, superseded by the next removal, and dropped by the next
// confirmation.
func TombstoneFind(l *ledger.Ledger, class Class, name string) ([]ledger.Field, error) {
	if err := classCheck(class); err != nil {
		return nil, err
	}
	fields, err := l.Find(kindTomb, "key", key(class, name))
	if err != nil {
		return nil, err
	}
	if derr := Describes(fields, class, name); derr != nil {
		return nil, derr
	}
	return fields, nil
}

// NormalizeLabel folds the runtime's spellings of ABSENT into one.
//
// EXPORTED because it is the reference's SHARED reader rule: its `_mi_intent_label` normalizes,
// and every caller — deletion authority, reconciliation's ownership question, and the unaccounted
// classifier — reads labels through it. A copy per package is a rule that drifts, and a package
// that skips it reads a label MEANING absent as a real value: an object at one of our own derived
// names labelled `installation=<no value>` would classify as another installation's rather than as
// the unlabelled collision that blocks creation.
//
// The reference read labels through a Go TEMPLATE, whose `index` on a label map with no such key
// prints `<no value>` rather than the empty string — so absence arrived spelled two ways depending
// on whether the object had any labels at all, and both had to be folded. The typed client has no
// template: an absent key is an absent map key, one spelling. The literal is still folded here
// because a REAL label whose value is that string says nothing about ownership either, and it
// cannot collide with a genuine identity (a minted one is `i` + 10 hex digits).
func NormalizeLabel(s string) string {
	if strings.TrimSpace(s) == "<no value>" {
		return ""
	}
	return s
}
