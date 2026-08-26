package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AUTHORIZATION NOTE: the bash asserted the lock inside each editor (mi_led_put and friends)
// because its editors wrote the file directly. The Go editors mutate an IN-MEMORY Ledger —
// inert until persisted — and Write is the single authorization point: it asserts the token,
// requires a writable store, and requires the store's token to BE the presented one. Nothing
// reaches disk through any other door.

// The generalized ledger editor — the bash kept it in the provenance module because the trust
// module's simpler editor predated it; Go keeps it beside the data it edits. Its invariants,
// verbatim from the reference:
//
//   - ONE RECORD, ONE MEANING: a record read off disk is either well-formed (every token a
//     key=value field with a lowercase name, no forged separator, no field NAME twice) or it
//     matches nothing and is PRESERVED and reported. Ill-formed rows are never dropped by an
//     ordinary edit — they are the evidence a ledger needs repairing.
//   - ONE LOOKUP, ONE ANSWER: zero is an answer, one is an answer, MANY is a question the
//     ledger cannot settle — readers refuse rather than pick, writers refuse rather than
//     collapse the contradiction (two byte-identical rows included).
//   - A KEYED REPLACEMENT CARRIES ITS KEY, exactly once — or it is a record-drop path.

var (
	// ErrAbsentRecord — the rc-3 analogue: no record answers, which is an ANSWER (first use,
	// not-a-member), never conflated with a refusal.
	ErrAbsentRecord = errors.New("no such record")
	// ErrAmbiguous — more than one record answers; everything preserved, repair named.
	ErrAmbiguous = errors.New("more than one record answers — preserved; run 'mythical-ctl state repair'")
)

// Lines returns a COPY of the raw record rows. Read-only raw access exists because the trust
// module keeps its own record shape (its document ids contain ':' — e.g. manifest:brokkr —
// which the provenance field-name grammar deliberately refuses), exactly as the bash kept two
// editors. Everything general still goes through the typed editors below.
func (l *Ledger) Lines() []string {
	out := make([]string, len(l.lines))
	copy(out, l.lines)
	return out
}

// ReplaceLines swaps the entire body — the trust module's one-write multi-record replace
// (floor and anchor must move together or not at all). RESTRICTED: check.sh's boundary gate
// pins its references to internal/trust; nothing else may bypass the typed editors.
func (l *Ledger) ReplaceLines(lines []string) {
	l.lines = append([]string(nil), lines...)
}

// FieldOK: key=value, lowercase [a-z_]+ name, no TAB, no newline in either half, ≤1024 bytes.
// A TAB forges a field boundary and a newline forges a whole record — the same
// serialize-safely-on-write rule the config writer applies; there is no escaping in this
// format, so refusal is the only correct move.
func FieldOK(f Field) bool {
	if f.Key == "" || len(f.Key)+1+len(f.Value) > 1024 {
		return false
	}
	for i := 0; i < len(f.Key); i++ {
		b := f.Key[i]
		if (b < 'a' || b > 'z') && b != '_' {
			return false
		}
	}
	return !strings.ContainsAny(f.Key, "\t\n") && !strings.ContainsAny(f.Value, "\t\n")
}

// kindOK: the same grammar on the kind — it is written to the same line by the same
// serializer, and a TAB or newline in it forges precisely what one in a field forges.
func kindOK(kind string) bool {
	if kind == "" || len(kind) > 64 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		b := kind[i]
		if (b < 'a' || b > 'z') && b != '_' {
			return false
		}
	}
	return true
}

// fieldsOK judges a whole list: every field by the field rule, and ONE NAME, ONE FIELD — a
// duplicate name lets a record answer for one object while describing another, and every
// reader takes the first hit.
func fieldsOK(fields []Field) error {
	seen := map[string]bool{}
	for _, f := range fields {
		if !FieldOK(f) {
			return fmt.Errorf("ledger: %q=%q is not a ledger field — key=value, lowercase name, no tab and no newline; a record carrying one is never written, and on disk it matches nothing and is left exactly where it is", f.Key, f.Value)
		}
		if seen[f.Key] {
			return fmt.Errorf("ledger: a record carries %q twice — one name, one field; ambiguous, so refused on write and inert on read", f.Key)
		}
		seen[f.Key] = true
	}
	return nil
}

// parseRecord splits one row's field portion and judges it — the ONLY way to obtain a
// record's fields, so no reader can iterate a record it has not judged. The split consumes
// one TAB at a time: an empty field is one token like any other (never collapsed), and
// nothing is ever glob-expanded — the two measured defects of the IFS idiom this replaces.
func parseRecord(row string) ([]Field, error) {
	if row == "" {
		return nil, errors.New("ledger: a record carries no fields at all — it describes nothing, so it matches nothing and grants nothing; run 'mythical-ctl state repair'")
	}
	toks := strings.Split(row, "\t")
	fields := make([]Field, 0, len(toks))
	for _, tok := range toks {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			// A bare token is not a field AT ALL — refused before it can masquerade as an
			// empty-valued field of its own name (the writer's *=* precondition, both
			// directions, one implementation).
			return nil, fmt.Errorf("ledger: %q is not a ledger field (no '='): record refused, preserved as it is", tok)
		}
		fields = append(fields, Field{Key: k, Value: v})
	}
	if err := fieldsOK(fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// rowOf answers "is this line a record of kind" — including the BARE form (`identity` with no
// TAB and no fields), which is a record of that kind with an EMPTY field list: skipping it
// made an existing identity look absent and minted a second one beside it.
func rowOf(line, kind string) (rest string, ok bool) {
	if line == kind {
		return "", true
	}
	if r, found := strings.CutPrefix(line, kind+"\t"); found {
		return r, true
	}
	return "", false
}

func serialize(kind string, fields []Field) string {
	var b strings.Builder
	b.WriteString(kind)
	for _, f := range fields {
		b.WriteString("\t" + f.Key + "=" + f.Value)
	}
	return b.String()
}

// selectOne is the cardinality question, asked in one place: the row (verbatim) of the single
// record of kind whose field kf equals kv. ErrAbsentRecord for zero; ErrAmbiguous for many
// (byte-identical duplicates included). Ill-formed records match nothing.
func (l *Ledger) selectOne(kind, kf, kv string) (string, error) {
	hit := ""
	count := 0
	for _, line := range l.lines {
		if line == "" {
			continue
		}
		row, ok := rowOf(line, kind)
		if !ok {
			continue
		}
		fields, err := parseRecord(row)
		if err != nil {
			continue // matches nothing; preserved
		}
		for _, f := range fields {
			if f.Key == kf && f.Value == kv {
				count++
				if count == 1 {
					hit = row
				}
				break
			}
		}
	}
	switch {
	case count == 0:
		return "", fmt.Errorf("ledger: no %s record with %s=%s: %w", kind, kf, kv, ErrAbsentRecord)
	case count > 1:
		return "", fmt.Errorf("ledger: %d %q records answer for %s=%s — reading one would act on a claim another contradicts, and replacing them would destroy the contradiction: %w", count, kind, kf, kv, ErrAmbiguous)
	}
	return hit, nil
}

// without returns the lines minus ONE row equal to kind+TAB+drop ("" drops nothing). Blank
// rows are preserved — a row this module cannot read is evidence, not tidying material.
func (l *Ledger) without(kind, drop string) []string {
	want := ""
	if drop != "" {
		want = serializePrefix(kind, drop)
	}
	out := make([]string, 0, len(l.lines))
	dropped := false
	for _, line := range l.lines {
		if !dropped && want != "" && line == want {
			dropped = true
			continue
		}
		out = append(out, line)
	}
	return out
}

func serializePrefix(kind, row string) string {
	if row == "" {
		return kind
	}
	return kind + "\t" + row
}

func argsOK(kind, kf, kv string) error {
	if !kindOK(kind) {
		return fmt.Errorf("ledger: refusing record kind %q — a kind is lowercase letters and underscore", kind)
	}
	if !FieldOK(Field{Key: kf, Value: kv}) {
		return fmt.Errorf("ledger: refusing key selector %s=%s — a selector is one key=value field", kf, kv)
	}
	return nil
}

// Put replaces (or inserts) ONE record of kind whose kf equals kv, preserving every other
// record verbatim. The replacement must carry the selector exactly once.
func (l *Ledger) Put(kind, kf, kv string, fields []Field) error {
	if err := argsOK(kind, kf, kv); err != nil {
		return err
	}
	if err := fieldsOK(fields); err != nil {
		return err
	}
	n := 0
	for _, f := range fields {
		if f.Key == kf && f.Value == kv {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("ledger: the replacement for %s=%s does not carry it exactly once (%d times) — a field list without its key drops one record and writes another; nothing was written", kf, kv, n)
	}
	old := ""
	if row, err := l.selectOne(kind, kf, kv); err == nil {
		old = row
	} else if !errors.Is(err, ErrAbsentRecord) {
		return err
	}
	l.lines = append(l.without(kind, old), serialize(kind, fields))
	return nil
}

// Del removes the ONE record of kind whose kf equals kv. Deleting what is absent succeeds —
// a deletion that finds nothing has achieved its purpose; ambiguity refuses.
func (l *Ledger) Del(kind, kf, kv string) error {
	if err := argsOK(kind, kf, kv); err != nil {
		return err
	}
	old := ""
	if row, err := l.selectOne(kind, kf, kv); err == nil {
		old = row
	} else if !errors.Is(err, ErrAbsentRecord) {
		return err
	} else {
		return nil
	}
	l.lines = l.without(kind, old)
	return nil
}

// Find returns the fields of the one record of kind whose kf equals kv.
func (l *Ledger) Find(kind, kf, kv string) ([]Field, error) {
	if err := argsOK(kind, kf, kv); err != nil {
		return nil, err
	}
	row, err := l.selectOne(kind, kf, kv)
	if err != nil {
		return nil, err
	}
	return parseRecord(row)
}

// All lists every record of kind. COMPLETENESS IS THE CONTRACT: one record it cannot read
// refuses the WHOLE listing — a listing that silently omits what it could not read would let
// a caller act on a subset believing it had the set. (The selector-based readers differ
// deliberately: a selector asks about ONE object, and an unreadable record simply does not
// match it.)
func (l *Ledger) All(kind string) ([][]Field, error) {
	if !kindOK(kind) {
		return nil, fmt.Errorf("ledger: refusing record kind %q", kind)
	}
	var out [][]Field
	for _, line := range l.lines {
		if line == "" {
			continue
		}
		row, ok := rowOf(line, kind)
		if !ok {
			continue
		}
		fields, err := parseRecord(row)
		if err != nil {
			return nil, fmt.Errorf("ledger: refusing to list %q records — one of them cannot be read, and a listing that leaves out what it could not read is not a listing of all of them; it is preserved as it is: %w", kind, err)
		}
		out = append(out, fields)
	}
	return out, nil
}

// FieldOf reads one field's value out of a record's field list.
func FieldOf(fields []Field, key string) (string, bool) {
	for _, f := range fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return "", false
}

// --- installation identity (D32/§4b.4) ----------------------------------------------------------
// Container and volume names are daemon-GLOBAL while ~/.mythical/ is per-user, so every
// runtime name is scoped by an identity minted once per installation: `i` + 10 hex — NO
// HYPHEN and FIXED LENGTH, both load-bearing: `-` is inside the ident charset, so an identity
// carrying one could make two (product, role) pairs derive the SAME flat-joined name.

const (
	identKind  = "identity"
	memberKind = "product"
)

func mintIdent() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ledger: cannot mint an installation identity: %w", err)
	}
	return "i" + hex.EncodeToString(b), nil
}

// IdentGet returns the recorded installation identity. ErrAbsentRecord means first use;
// anything else refuses — a corrupt ledger must never look like a fresh machine, an identity
// record with an EMPTY id is presence-without-an-answer (minting over it would orphan every
// object the previous identity named), and two identity records cannot say which one this
// installation is.
func (l *Ledger) IdentGet() (string, error) {
	recs, err := l.All(identKind)
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return "", fmt.Errorf("ledger: no installation identity recorded: %w", ErrAbsentRecord)
	}
	if len(recs) > 1 {
		return "", fmt.Errorf("ledger: %d installation identities recorded — every runtime name is scoped by the identity, so guessing would adopt or delete another installation's objects: %w", len(recs), ErrAmbiguous)
	}
	v, ok := FieldOf(recs[0], "id")
	if !ok || v == "" {
		return "", errors.New("ledger: the recorded installation identity carries no value — preserved and reported; run 'mythical-ctl state repair'")
	}
	return v, nil
}

// IdentEnsure mints the identity if none is recorded and returns it either way. Mutates the
// in-memory ledger; the caller persists via Write — identity initialization is part of
// creating the ledger, so there is no state where trust exists but identity is unknowable.
func (l *Ledger) IdentEnsure() (string, error) {
	v, err := l.IdentGet()
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrAbsentRecord) {
		return "", err
	}
	v, err = mintIdent()
	if err != nil {
		return "", err
	}
	if err := l.Put(identKind, "id", v, []Field{{"id", v}}); err != nil {
		return "", err
	}
	return v, nil
}

// The initialized-product set (§6b): a product NOT in the set is first-use (TOFU); IN the set
// with no floor is FAIL-CLOSED. Membership is a set, not a flag — a family-scoped flag made
// every SECOND product fail closed.

func (l *Ledger) MemberAdd(product string) error {
	return l.Put(memberKind, "name", product, []Field{{"name", product}})
}

// MemberHas: nil = a member; ErrAbsentRecord = NOT a member; any other error = CANNOT SAY.
// The three are not two — treating any non-nil as "not a member" takes the first-use TOFU
// branch on a ledger this module refused to read, re-accepting a recorded floor from nothing.
func (l *Ledger) MemberHas(product string) error {
	_, err := l.Find(memberKind, "name", product)
	return err
}

// MemberDel: only a FAMILY uninstall calls this — an ordinary uninstall keeps membership and
// the trust floor, or uninstall-then-install becomes a one-command rollback bypass.
func (l *Ledger) MemberDel(product string) error {
	return l.Del(memberKind, "name", product)
}

// --- the SET editors (Task 20) -------------------------------------------------------------------
// The typed editors above answer "the ONE record whose <field> is <value>". A container's
// outstanding checks are not that shape: they are a SET keyed by three fields together
// (container + kind + param), and D52 made them typed precisely so several entries of one kind can
// coexist with different parameters. Matching them on one field would retire checks nobody
// performed; synthesizing a composite `key=` would change the on-disk record, which an existing
// installation's ledger already carries in the three-field form.
//
// So the same rules are offered over a MULTI-FIELD match. Every rule is the one above it: a match
// field is judged by the FIELD rule (it has to equal a serialized field byte for byte), an
// ill-formed record matches nothing and is preserved, and a listing that cannot read a record of
// the kind it was asked about REFUSES rather than returning a shorter list.

func matchOK(kind string, match []Field) error {
	if !kindOK(kind) {
		return fmt.Errorf("ledger: refusing record kind %q — a kind is lowercase letters and underscore", kind)
	}
	if len(match) == 0 {
		return errors.New("ledger: a set selector with no fields matches every record of its kind — refusing rather than acting on all of them")
	}
	seen := map[string]bool{}
	for _, f := range match {
		if !FieldOK(f) {
			return fmt.Errorf("ledger: refusing set selector %s=%s — a selector field is one key=value field", f.Key, f.Value)
		}
		if seen[f.Key] {
			return fmt.Errorf("ledger: a set selector names %q twice — one name, one field", f.Key)
		}
		seen[f.Key] = true
	}
	return nil
}

// recordMatches: does this record carry EVERY match field? A record whose field list this module
// cannot read never reaches here — the callers refuse first.
func recordMatches(fields []Field, match []Field) bool {
	for _, want := range match {
		v, ok := FieldOf(fields, want.Key)
		if !ok || v != want.Value {
			return false
		}
	}
	return true
}

// Select lists every record of kind matching all of match. COMPLETENESS IS THE CONTRACT: one
// record of that kind it cannot read is a refusal, because a short list of outstanding checks
// reads as a container that owes fewer than it does.
func (l *Ledger) Select(kind string, match []Field) ([][]Field, error) {
	if err := matchOK(kind, match); err != nil {
		return nil, err
	}
	var out [][]Field
	for _, line := range l.lines {
		if line == "" {
			continue
		}
		row, ok := rowOf(line, kind)
		if !ok {
			continue
		}
		fields, err := parseRecord(row)
		if err != nil {
			return nil, fmt.Errorf("ledger: a %q record cannot be read, so this listing would be shorter than the truth: %w", kind, err)
		}
		if recordMatches(fields, match) {
			out = append(out, fields)
		}
	}
	return out, nil
}

// DelAll removes EVERY record of kind matching all of match and reports how many went. Zero is a
// success — a deletion that finds nothing has achieved its purpose.
//
// It refuses BEFORE removing anything if any record of that kind cannot be read: deleting around
// evidence would leave a ledger that looks tidy and is still wrong. Blank rows and records of
// every other kind are preserved exactly where they are.
func (l *Ledger) DelAll(kind string, match []Field) (int, error) {
	if err := matchOK(kind, match); err != nil {
		return 0, err
	}
	for _, line := range l.lines {
		if line == "" {
			continue
		}
		row, ok := rowOf(line, kind)
		if !ok {
			continue
		}
		if _, err := parseRecord(row); err != nil {
			return 0, fmt.Errorf("ledger: a %q record cannot be read, so this deletion would act around evidence it cannot account for: %w", kind, err)
		}
	}
	out := make([]string, 0, len(l.lines))
	dropped := 0
	for _, line := range l.lines {
		if line != "" {
			if row, ok := rowOf(line, kind); ok {
				if fields, err := parseRecord(row); err == nil && recordMatches(fields, match) {
					dropped++
					continue
				}
			}
		}
		out = append(out, line)
	}
	l.lines = out
	return dropped, nil
}

// Append adds ONE record of kind with no selector at all — a SET member, added only after a
// Select proved it absent. There is deliberately no keyed replacement here: replacing by one field
// is what would collapse a container's several same-kind checks into the last one written.
func (l *Ledger) Append(kind string, fields []Field) error {
	if !kindOK(kind) {
		return fmt.Errorf("ledger: refusing record kind %q — a kind is lowercase letters and underscore", kind)
	}
	if len(fields) == 0 {
		return errors.New("ledger: a record with no fields describes nothing — refusing to write one")
	}
	if err := fieldsOK(fields); err != nil {
		return err
	}
	l.lines = append(l.lines, serialize(kind, fields))
	return nil
}
