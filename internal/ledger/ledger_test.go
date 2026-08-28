package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// Inventory — tests/unit/ledger.bats:
// PORTED: tests/unit/ledger.bats: "missing ledger returns 3 and prints nothing" -> TestMissingLedgerDistinct
// PORTED: tests/unit/ledger.bats: "write then read round-trips records" -> TestWriteReadRoundTrip
// PORTED: tests/unit/ledger.bats: "write is refused without the lock held (no token, no lock file)" -> TestWriteAuthorization
// PORTED: tests/unit/ledger.bats: "write is refused when the token does not match the lock file" -> TestWriteAuthorization (store-token identity + released-token refusal — the sealed-capability port)
// PORTED: tests/unit/ledger.bats: "a ledger truncated by its final newline fails closed" -> TestCorruptionFailsClosed
// PORTED: tests/unit/ledger.bats: "a torn ledger fails closed" -> TestCorruptionFailsClosed
// PORTED: tests/unit/ledger.bats: "a newer schema is refused, not parsed" -> TestSchemaGate
// PORTED: tests/unit/ledger.bats: "a non-numeric schema is refused (fail closed, not parsed)" -> TestSchemaGate
// PORTED: tests/unit/ledger.bats: "a HUGE numeric schema (past integer range) is still refused" -> TestSchemaGate
// PORTED: tests/unit/ledger.bats: "the writer refuses to clobber an existing corrupt ledger" -> TestWriterNeverDestroysEvidence
// N/A: tests/unit/ledger.bats: "input records without a trailing newline still produce a readable ledger" -- the Go writer serializes its own lines; there is no stdin framing whose missing newline could fuse a record onto the checksum
// PORTED: tests/unit/ledger.bats: "mi_ledger_get selects by kind and key" -> TestEditorFindAndField
// PORTED: tests/unit/ledger.bats: "mi_ledger_get fails closed on a corrupt ledger (no ambient pipefail)" -> TestCorruptionFailsClosed (Read errors; no editor can run without a Ledger value)
// N/A: tests/unit/ledger.bats: "mi_ledger_read leaves no read-snapshot temp behind" -- the Go read is one os.ReadFile into memory; no snapshot file exists to leak
// N/A: tests/unit/ledger.bats: "ledger write fails closed when the hasher itself fails (no checksum-empty ledger)" -- the hasher is in-process crypto/sha256, not an external tool that can fail or be shimmed
// N/A: tests/unit/ledger.bats: "ledger read fails closed when the hasher itself fails" -- same: no external hasher exists
// PORTED: tests/unit/ledger.bats: "a failed ledger write refuses instead of replacing a valid ledger" -> TestWriterNeverDestroysEvidence
// PORTED: tests/unit/ledger.bats: "a ledger path that is a DIRECTORY is refused by both the reader and the writer" -> TestNonRegularLedgerRefused
// PORTED: tests/unit/ledger.bats: "a ledger path that is a DANGLING SYMLINK is refused, not treated as absent" -> TestNonRegularLedgerRefused
// N/A: tests/unit/ledger.bats: "the ledger path override refuses anything outside the two paths this code owns" -- no override exists in Go: the sealed Store's three constructors own both paths and nothing else is expressible
// N/A: tests/unit/ledger.bats: "the ledger path override accepts the real ledger path with no further conditions" -- same: no override
// N/A: tests/unit/ledger.bats: "the staging path is refused UNLESS the internal marker is also set (codex gate round 1, fix 1)" -- the marker protocol guarded an env seam that does not exist; staging is a distinct sealed constructor whose caller set check.sh's boundary gate pins
// N/A: tests/unit/ledger.bats: "the staging path is accepted once BOTH the override and the internal marker are set" -- the other half of the same override protocol, and it does not exist in Go either: staging is reached through the sealed OpenStaging constructor, not by setting two environment variables, and check.sh's boundary rule pins its only legal caller
// PORTED: tests/unit/ledger.bats: "the staging reader/writer round-trip, without touching the real ledger" -> TestStagingRoundTripLeavesLiveAlone
// PORTED: tests/unit/ledger.bats: "Plan 1's ledger.bats still passes unchanged: an ordinary write/read never sees the override" -> TestStagingRoundTripLeavesLiveAlone (Live and staging paths asserted distinct; an ordinary store never resolves to staging)
//
// Inventory — tests/unit/prov.bats (Task 8 owns the editor/identity/membership rows; the
// provenance-semantics remainder is Task 18's):
// PORTED: tests/unit/prov.bats: "the ledger editor replaces a record keyed by an explicit field" -> TestEditorPutReplacesKeyed
// PORTED: tests/unit/prov.bats: "the editor preserves every other record" -> TestEditorPutReplacesKeyed
// PORTED: tests/unit/prov.bats: "a field value containing a TAB or newline is REFUSED — it would forge a field or a record" -> TestFieldGrammar
// PORTED: tests/unit/prov.bats: "a field that is not KEY=VALUE is refused" -> TestFieldGrammar
// PORTED: tests/unit/prov.bats: "the editor refuses without the family lock" -> TestWriteAuthorization (Go editors mutate in-memory state; Write is the single authorization door — nothing reaches disk unasserted)
// PORTED: tests/unit/prov.bats: "identity is minted once and is stable" -> TestIdentity
// PORTED: tests/unit/prov.bats: "a minted identity is a valid name component" -> TestIdentity
// PORTED: tests/unit/prov.bats: "the minted identity contains no hyphen, so the flat name join stays unambiguous" -> TestIdentity
// PORTED: tests/unit/prov.bats: "mi_ident_get reports 3 before any identity exists, never an empty string" -> TestIdentity
// PORTED: tests/unit/prov.bats: "a corrupt ledger fails CLOSED for identity — it never looks like first use" -> TestCorruptionFailsClosed
// PORTED: tests/unit/prov.bats: "membership is a SET, so a second product's absent floor is first-use not rollback" -> TestMembershipSet
// PORTED: tests/unit/prov.bats: "a family uninstall drops one membership and keeps the rest, and needs the lock to do it" -> TestMembershipSet

func liveFor(t *testing.T) (famlock.Held, Store, string) {
	t.Helper()
	home := t.TempDir()
	h, err := famlock.Acquire(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = famlock.Release(h) })
	st, err := Live(h)
	if err != nil {
		t.Fatal(err)
	}
	return h, st, home
}

func TestMissingLedgerDistinct(t *testing.T) {
	_, st, _ := liveFor(t)
	_, err := Read(st)
	if !errors.Is(err, ErrMissingLedger) {
		t.Fatalf("want ErrMissingLedger, got %v", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatal("missing conflated with corrupt")
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	h, st, home := liveFor(t)
	l := &Ledger{}
	if err := l.Put("object", "key", "volume:v1", []Field{
		{"key", "volume:v1"}, {"class", "volume"}, {"name", "v1"}, {"nonce", "n1"}, {"gen", "1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Write(h, st, l); err != nil {
		t.Fatal(err)
	}
	got, err := Read(LiveRead(home))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := got.Find("object", "key", "volume:v1")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := FieldOf(fields, "nonce"); v != "n1" {
		t.Fatalf("nonce %q", v)
	}
}

// The golden fixture was written by the BASH writer (lib/ledger.sh, verbatim run). The Go
// reader must accept it, and a Go rewrite of the same records must be byte-identical.
func TestBashGoldenFixtureRoundTrips(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "bash-written.ledger"))
	if err != nil {
		t.Fatal(err)
	}
	h, st, _ := liveFor(t)
	s, _ := unseal(st)
	if err := os.WriteFile(s.path, golden, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Read(st)
	if err != nil {
		t.Fatalf("the bash-written ledger does not read: %v", err)
	}
	if v, err := l.IdentGet(); err != nil || v != "i0123456789" {
		t.Fatalf("identity from bash ledger: %q, %v", v, err)
	}
	if err := Write(h, st, l); err != nil {
		t.Fatal(err)
	}
	rewritten, _ := os.ReadFile(s.path)
	if string(rewritten) != string(golden) {
		t.Fatalf("Go rewrite is not byte-identical to the bash file:\n%q\nvs\n%q", rewritten, golden)
	}
}

func TestWriteAuthorization(t *testing.T) {
	h, st, _ := liveFor(t)
	if err := Write(nil, st, &Ledger{}); err == nil {
		t.Fatal("nil token wrote the ledger")
	}
	// A DIFFERENT holder's token does not authorize this store: the store was opened under h,
	// and presenting another token — even a live one for another home — refuses.
	home2 := t.TempDir()
	h2, err := famlock.Acquire(home2)
	if err != nil {
		t.Fatal(err)
	}
	defer famlock.Release(h2)
	if err := Write(h2, st, &Ledger{}); err == nil {
		t.Fatal("another home's token wrote this store")
	}
	// A released token fails the assert even on its own store.
	if err := Write(h, st, &Ledger{}); err != nil {
		t.Fatalf("the rightful token refused: %v", err)
	}
	_ = famlock.Release(h)
	if err := Write(h, st, &Ledger{}); err == nil {
		t.Fatal("a released token wrote the ledger")
	}
	// And the read-only store refuses by type, whatever the token.
	if err := Write(h2, LiveRead(home2), &Ledger{}); !errors.Is(err, ErrReadOnlyStore) {
		t.Fatalf("read-only store: %v", err)
	}
}

func TestCorruptionFailsClosed(t *testing.T) {
	cases := map[string]string{
		"truncated final newline": "#mythical-ctl-ledger schema=1\nidentity\tid=i0123456789\n#sha256=deadbeef",
		"checksum mismatch":       "#mythical-ctl-ledger schema=1\nidentity\tid=i0123456789\n#sha256=" + strings.Repeat("0", 64) + "\n",
		"missing checksum line":   "#mythical-ctl-ledger schema=1\nidentity\tid=i0123456789\n",
		"malformed header":        "#not-a-ledger\n#sha256=x\n",
		"non-numeric schema":      "#mythical-ctl-ledger schema=two\n#sha256=x\n",
	}
	for name, content := range cases {
		_, st, _ := liveFor(t)
		s, _ := unseal(st)
		if err := os.WriteFile(s.path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Read(st)
		if err == nil {
			t.Fatalf("%s: accepted", name)
			continue
		}
		// Non-numeric schema and malformed header hide behind the checksum for the fixtures
		// above (their checksums are wrong too) — that IS corruption either way. The point
		// pinned here: every one is an error, none is ErrMissingLedger, and identity can
		// never be asked (there is no Ledger value to ask) — a corrupt ledger NEVER looks
		// like first use.
		if errors.Is(err, ErrMissingLedger) {
			t.Fatalf("%s: corruption reported as first use", name)
		}
	}
	// A checksum-VALID body with a bad schema, to reach the schema gate itself:
	_, st, _ := liveFor(t)
	s, _ := unseal(st)
	writeChecksummed(t, s.path, "#mythical-ctl-ledger schema=abc\n")
	if _, err := Read(st); err == nil || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-numeric schema past a valid checksum: %v", err)
	}
}

// writeChecksummed builds header+body with a CORRECT trailing checksum, so tests can reach
// the gates that sit behind integrity.
func writeChecksummed(t *testing.T, path, headerAndBody string) {
	t.Helper()
	sum := cliio.SHA256Hex([]byte(headerAndBody))
	if err := os.WriteFile(path, []byte(headerAndBody+"#sha256="+sum+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaGate(t *testing.T) {
	_, st, _ := liveFor(t)
	s, _ := unseal(st)
	// Newer, checksum-valid: refused as NEWER — never as corrupt (repair must not destroy it).
	writeChecksummed(t, s.path, "#mythical-ctl-ledger schema=2\n")
	_, err := Read(st)
	if !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("want ErrNewerSchema, got %v", err)
	}
	if errors.Is(err, ErrCorrupt) || ConfirmedCorrupt(st) {
		t.Fatal("a newer-schema ledger reported destroy-eligible")
	}
	// A HUGE numeric schema refuses the same way, no integer parse anywhere.
	writeChecksummed(t, s.path, "#mythical-ctl-ledger schema="+strings.Repeat("9", 40)+"\n")
	if _, err := Read(st); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("huge schema: %v", err)
	}
	// And ConfirmedCorrupt answers true ONLY for real corruption.
	if err := os.WriteFile(s.path, []byte("#mythical-ctl-ledger schema=1\nx\n#sha256=bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ConfirmedCorrupt(st) {
		t.Fatal("real corruption not confirmed")
	}
}

func TestWriterNeverDestroysEvidence(t *testing.T) {
	h, st, _ := liveFor(t)
	s, _ := unseal(st)
	corrupt := "#mythical-ctl-ledger schema=1\nidentity\tid=x\n#sha256=" + strings.Repeat("0", 64) + "\n"
	if err := os.WriteFile(s.path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(h, st, &Ledger{}); err == nil {
		t.Fatal("the writer clobbered a corrupt ledger")
	}
	if b, _ := os.ReadFile(s.path); string(b) != corrupt {
		t.Fatal("the corrupt ledger was modified")
	}
	// A failed WRITE refuses instead of replacing a valid ledger: make the directory
	// unwritable so the temp file cannot be created.
	h2, st2, home2 := liveFor(t)
	l := &Ledger{}
	_ = l.MemberAdd("brokkr")
	if err := Write(h2, st2, l); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(filepath.Join(home2, ".state", "ledger"))
	if err := os.Chmod(filepath.Join(home2, ".state"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(home2, ".state"), 0o755) })
	if os.Getuid() == 0 {
		t.Skip("root writes through 0500")
	}
	if err := Write(h2, st2, &Ledger{}); err == nil {
		t.Fatal("a write that could not land its temp reported success")
	}
	if b, _ := os.ReadFile(filepath.Join(home2, ".state", "ledger")); string(b) != string(valid) {
		t.Fatal("the valid ledger was replaced by a failed write")
	}
}

func TestNonRegularLedgerRefused(t *testing.T) {
	h, st, home := liveFor(t)
	// A DIRECTORY at the path.
	if err := os.Mkdir(filepath.Join(home, ".state", "ledger"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(st); err == nil || errors.Is(err, ErrMissingLedger) {
		t.Fatalf("directory read as absent/ok: %v", err)
	}
	if err := Write(h, st, &Ledger{}); err == nil {
		t.Fatal("writer accepted a directory")
	}
	// A DANGLING SYMLINK is refused, not treated as absent.
	h2, st2, home2 := liveFor(t)
	if err := os.Symlink(filepath.Join(home2, "gone"), filepath.Join(home2, ".state", "ledger")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(st2); err == nil || errors.Is(err, ErrMissingLedger) {
		t.Fatalf("dangling symlink read as absent: %v", err)
	}
	if err := Write(h2, st2, &Ledger{}); err == nil {
		t.Fatal("writer accepted a dangling symlink")
	}
}

func TestStagingRoundTripLeavesLiveAlone(t *testing.T) {
	h, st, home := liveFor(t)
	live := &Ledger{}
	_ = live.MemberAdd("brokkr")
	if err := Write(h, st, live); err != nil {
		t.Fatal(err)
	}
	liveBytes, _ := os.ReadFile(filepath.Join(home, ".state", "ledger"))

	stg, err := OpenStaging(h)
	if err != nil {
		t.Fatal(err)
	}
	sl := &Ledger{}
	_ = sl.MemberAdd("saga")
	if err := Write(h, stg, sl); err != nil {
		t.Fatal(err)
	}
	got, err := Read(stg)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.MemberHas("saga"); err != nil {
		t.Fatalf("staging round-trip: %v", err)
	}
	// The real ledger is untouched, and the two stores resolve to distinct paths — an
	// ordinary store can never see the staging file.
	if b, _ := os.ReadFile(filepath.Join(home, ".state", "ledger")); string(b) != string(liveBytes) {
		t.Fatal("staging write touched the live ledger")
	}
	ss, _ := unseal(stg)
	ls, _ := unseal(st)
	if ss.path == ls.path {
		t.Fatal("staging resolves to the live path")
	}
}

func TestEditorPutReplacesKeyed(t *testing.T) {
	l := &Ledger{}
	_ = l.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}, {"gen", "1"}})
	_ = l.Put("object", "key", "volume:v2", []Field{{"key", "volume:v2"}, {"gen", "1"}})
	if err := l.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}, {"gen", "2"}}); err != nil {
		t.Fatal(err)
	}
	f1, err := l.Find("object", "key", "volume:v1")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := FieldOf(f1, "gen"); v != "2" {
		t.Fatalf("replacement did not supersede: gen=%q", v)
	}
	// Every other record preserved.
	f2, err := l.Find("object", "key", "volume:v2")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := FieldOf(f2, "gen"); v != "1" {
		t.Fatal("an unrelated record was disturbed")
	}
	// A replacement that does not carry its selector is a record-drop path: refused.
	if err := l.Put("object", "key", "volume:v1", []Field{{"key", "volume:OTHER"}, {"gen", "3"}}); err == nil {
		t.Fatal("selector-less replacement accepted")
	}
}

func TestFieldGrammar(t *testing.T) {
	l := &Ledger{}
	bad := [][]Field{
		{{"key", "v"}, {"note", "a\tb"}},           // TAB forges a field
		{{"key", "v"}, {"note", "a\nb"}},           // newline forges a record
		{{"key", "v"}, {"NOTUPPER", "x"}},          // name grammar
		{{"key", "v"}, {"", "x"}},                  // empty name
		{{"key", "v"}, {"dup", "1"}, {"dup", "2"}}, // one name, one field
	}
	for i, fields := range bad {
		if err := l.Put("object", "key", "v", fields); err == nil {
			t.Errorf("bad field list %d accepted", i)
		}
	}
	// And a kind is held to the same grammar — a forged kind is a forged record.
	if err := l.Put("identity\tid=forged\nobject", "key", "v", []Field{{"key", "v"}}); err == nil {
		t.Fatal("forged kind accepted")
	}
}

func TestAmbiguityPreserves(t *testing.T) {
	// Two records answering one key: reads refuse, edits refuse, and BOTH rows stay.
	l := &Ledger{lines: []string{
		"object\tkey=volume:v1\tnonce=a",
		"object\tkey=volume:v1\tnonce=b",
	}}
	if _, err := l.Find("object", "key", "volume:v1"); !errors.Is(err, ErrAmbiguous) {
		t.Fatal("ambiguous read did not refuse")
	}
	if err := l.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}}); !errors.Is(err, ErrAmbiguous) {
		t.Fatal("ambiguous put did not refuse")
	}
	if err := l.Del("object", "key", "volume:v1"); !errors.Is(err, ErrAmbiguous) {
		t.Fatal("ambiguous del did not refuse")
	}
	if len(l.lines) != 2 {
		t.Fatal("evidence was destroyed")
	}
	// An ill-formed row matches nothing, is preserved by edits, and refuses a LISTING (the
	// completeness contract) while a keyed lookup still answers for well-formed records.
	l2 := &Ledger{lines: []string{
		"object\tkey=volume:v1\tnonce=a",
		"object\tnot-a-field",
		"", // a blank row is preserved too
	}}
	if _, err := l2.Find("object", "key", "volume:v1"); err != nil {
		t.Fatalf("keyed lookup blocked by an unrelated ill-formed row: %v", err)
	}
	if _, err := l2.All("object"); err == nil {
		t.Fatal("a listing silently omitted what it could not read")
	}
	if err := l2.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}, {"gen", "2"}}); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range l2.lines {
		if line == "object\tnot-a-field" || line == "" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("an edit tidied away evidence: %v", l2.lines)
	}
}

func TestEditorFindAndField(t *testing.T) {
	l := &Ledger{}
	_ = l.Put("object", "key", "volume:v1", []Field{{"key", "volume:v1"}, {"class", "volume"}})
	fields, err := l.Find("object", "key", "volume:v1")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := FieldOf(fields, "class"); !ok || v != "volume" {
		t.Fatalf("FieldOf: %q %v", v, ok)
	}
	if _, err := l.Find("object", "key", "volume:none"); !errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("absent: %v", err)
	}
}

func TestIdentity(t *testing.T) {
	l := &Ledger{}
	if _, err := l.IdentGet(); !errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("pre-mint IdentGet: %v (must be ErrAbsentRecord, never an empty string success)", err)
	}
	v1, err := l.IdentEnsure()
	if err != nil {
		t.Fatal(err)
	}
	// Valid name component: 'i' + 10 hex, NO hyphen, fixed length 11 — the flat name join's
	// unambiguity depends on both.
	if !regexp.MustCompile(`^i[0-9a-f]{10}$`).MatchString(v1) {
		t.Fatalf("minted identity %q", v1)
	}
	v2, err := l.IdentEnsure()
	if err != nil || v2 != v1 {
		t.Fatalf("identity not stable: %q vs %q (%v)", v1, v2, err)
	}
	// An identity record with an EMPTY id is presence-without-an-answer: refused, preserved.
	l2 := &Ledger{lines: []string{"identity\tid="}}
	if _, err := l2.IdentGet(); err == nil || errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("empty id read as first use: %v", err)
	}
	// A BARE `identity` row (no fields) is a record of the kind — not invisible: the listing
	// refuses it, so IdentGet refuses rather than minting a second identity beside it.
	l3 := &Ledger{lines: []string{"identity"}}
	if _, err := l3.IdentGet(); err == nil || errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("bare identity row read as first use: %v", err)
	}
	if _, err := l3.IdentEnsure(); err == nil {
		t.Fatal("IdentEnsure minted beside an unreadable identity row")
	}
	// Two identities: cannot say which — refuse.
	l4 := &Ledger{lines: []string{"identity\tid=iaaaaaaaaaa", "identity\tid=ibbbbbbbbbb"}}
	if _, err := l4.IdentGet(); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two identities: %v", err)
	}
}

func TestMembershipSet(t *testing.T) {
	l := &Ledger{}
	if err := l.MemberHas("brokkr"); !errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("empty set: %v", err)
	}
	_ = l.MemberAdd("brokkr")
	_ = l.MemberAdd("saga")
	if err := l.MemberHas("brokkr"); err != nil {
		t.Fatal(err)
	}
	// A SET: saga's membership says nothing about skuld — skuld stays first-use.
	if err := l.MemberHas("skuld"); !errors.Is(err, ErrAbsentRecord) {
		t.Fatalf("membership leaked across products: %v", err)
	}
	// Family uninstall drops one and keeps the rest.
	if err := l.MemberDel("brokkr"); err != nil {
		t.Fatal(err)
	}
	if err := l.MemberHas("brokkr"); !errors.Is(err, ErrAbsentRecord) {
		t.Fatal("deleted member still present")
	}
	if err := l.MemberHas("saga"); err != nil {
		t.Fatal("an unrelated membership was dropped")
	}
	// Idempotent delete: finding nothing has achieved its purpose.
	if err := l.MemberDel("brokkr"); err != nil {
		t.Fatal(err)
	}
}

// TestReadRegularFileResolvesTheNameOnce: an Lstat followed by a ReadFile is two lookups of one
// name, and both failures that live in the gap between them were measured on this tree.
//
// A FIFO makes an ordinary read BLOCK FOREVER — an installer that never returns, on paths every
// command takes — and a symlink is FOLLOWED, so the bytes judged are the target's while the name
// still refers to the link, and a caller that then moves "the file it judged" moves the link.
// O_NOFOLLOW|O_NONBLOCK plus an fstat of the handle already held answers both.
func TestReadRegularFileResolvesTheNameOnce(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "plain")
	if err := os.WriteFile(good, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadRegularFile(good); err != nil || string(got) != "hello\n" {
		t.Fatalf("a regular file: %q, %v", got, err)
	}

	// A SYMLINK IS REFUSED, NOT FOLLOWED — even one pointing at a perfectly good file.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(link); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a symlink to a regular file was followed: %v", err)
	}

	// A FIFO IS REFUSED AND DOES NOT BLOCK. The deadline is the assertion: without O_NONBLOCK this
	// call never returns and the test would HANG rather than fail, which is why it runs off-thread.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("this filesystem does not support a FIFO (%v) — the blocking branch is not reachable here", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadRegularFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("a FIFO: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadRegularFile did not return for a FIFO — it opened without O_NONBLOCK and is " +
			"waiting for a writer that will never come")
	}

	// A DIRECTORY, and an absent path, are their own answers.
	if _, err := ReadRegularFile(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a directory: %v", err)
	}
	if _, err := ReadRegularFile(filepath.Join(dir, "nope")); !os.IsNotExist(err) {
		t.Fatalf("an absent path should answer NotExist: %v", err)
	}
}
