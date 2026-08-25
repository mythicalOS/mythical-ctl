// Package ledger is the single atomic state ledger (D28): one checksummed file, replaced by
// atomic rename under the family lock (D36/§4b.3a), fail-closed on any corruption (D28),
// schema-versioned (D35).
//
// Wire format, byte-identical to the bash (a golden fixture written by the bash writer is
// round-tripped in the tests):
//
//	#mythical-ctl-ledger schema=1
//	<kind>\t<key=value>\t<key=value>...
//	...
//	#sha256=<hex>
package ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
)

// Schema is the newest ledger schema this build understands (D35).
const Schema = "1"

var (
	// ErrMissingLedger — no ledger yet: a legitimate first write, distinct from every failure.
	ErrMissingLedger = errors.New("no ledger recorded yet")
	// ErrCorrupt — the content is POSITIVELY confirmed corrupt: a checksum computed over a
	// complete, faithfully-read copy of the bytes disagrees with what they claim, or those
	// proven bytes fail to parse as a ledger. ONLY repair's destroy-and-rebuild gate may act on
	// this distinction (via ConfirmedCorrupt); every ordinary caller treats it as any other
	// refusal. A transient read failure is NEVER this error — destroying a ledger because
	// reading it once failed for a reason that said nothing about its bytes was the bash bug
	// the distinction exists to prevent.
	ErrCorrupt = errors.New("ledger is corrupt (fail closed)")
	// ErrNewerSchema — checksum-valid, cleanly parsed, and written by a NEWER mythical-ctl.
	// Refused, but never mistaken for corruption: reporting it corrupt would route a
	// still-valid ledger into repair's reset and delete what a newer build recorded.
	ErrNewerSchema = errors.New("ledger schema is newer than this mythical-ctl understands")
	// ErrReadOnlyStore — a mutation presented the read-only live store.
	ErrReadOnlyStore = errors.New("this ledger store is read-only")
)

// Store is the SEALED state backend: exactly three constructors, no other implementation.
// Live(h) is what every mutating path constructs; LiveRead(home) is the lock-free read-only
// view (status and the TUI dashboard read without contending with mutations, exactly as the
// bash's status takes no lock); OpenStaging(h) is the restore staging area, constructed ONLY
// by internal/backup — check.sh's boundary gate enforces that caller set. The bash reached
// staging through an env-override pair scrubbed at the entrypoint; the Go live path derives
// its location from the lock token and consults nothing else, so there is no redirection seam
// at all, and staging is simply a DIFFERENT store no lifecycle path ever constructs.
type Store interface {
	sealedLedgerStore() *store
}

type store struct {
	path     string
	writable bool
	tok      famlock.Held // nil for LiveRead
}

func (s *store) sealedLedgerStore() *store { return s }

// Live is the authoritative store under the token's home.
func Live(h famlock.Held) (Store, error) {
	home, err := famlock.HomeOf(h)
	if err != nil {
		return nil, err
	}
	return &store{path: filepath.Join(home, ".state", "ledger"), writable: true, tok: h}, nil
}

// LiveRead is the read-only live store, keyed by home — no lock, no write capability (writers
// refuse it by type, checked at the top of every mutation).
func LiveRead(home string) Store {
	return &store{path: filepath.Join(home, ".state", "ledger"), writable: false}
}

// OpenStaging is the restore staging area — same format, same integrity discipline, a distinct
// well-known name beside the real ledger, and explicitly NOT authoritative: no operation
// launches, deletes or reconciles from it. The path derives from the token (never a caller
// path — an arbitrary directory was the round-3 redirect seam), and only internal/backup may
// construct one.
func OpenStaging(h famlock.Held) (Store, error) {
	home, err := famlock.HomeOf(h)
	if err != nil {
		return nil, err
	}
	return &store{path: filepath.Join(home, ".state", "ledger.staging"), writable: true, tok: h}, nil
}

func unseal(s Store) (*store, error) {
	// Exact dynamic type — an embedding wrapper is refused, and a nil-inner wrapper cannot
	// panic a promoted method call because no method is called (same rule as famlock).
	t, ok := s.(*store)
	if !ok || t == nil {
		return nil, errors.New("ledger: not a store this package minted — refusing")
	}
	return t, nil
}

// Ledger is the body: raw record rows, preserved VERBATIM — including rows this module cannot
// read (ill-formed and blank rows match nothing and grant nothing, but they are evidence a
// ledger needs repair, and evidence is never tidied away by an ordinary edit).
type Ledger struct {
	lines []string
}

// Field is one key=value token of a record — ordered, because byte-identical output requires
// the field sequence and a map would destroy it.
type Field struct{ Key, Value string }

// Read validates and returns the ledger at st. errors.Is: ErrMissingLedger (first write),
// ErrCorrupt (positively confirmed — see the variable), ErrNewerSchema, or a plain error for
// anything that says nothing about the bytes (unreadable, not a regular file).
func Read(st Store) (*Ledger, error) {
	s, err := unseal(st)
	if err != nil {
		return nil, err
	}
	return readPath(s.path)
}

func readPath(path string) (*Ledger, error) {
	// ABSENT is the legitimate first write. PRESENT-BUT-NOT-REGULAR is not absent: conflating
	// them made the bash's writer move its temp INTO a directory or through a dangling symlink
	// — each write "succeeded", each read said absent, and a fresh identity was minted per
	// invocation.
	fi, lerr := os.Lstat(path)
	if lerr != nil {
		if os.IsNotExist(lerr) {
			return nil, fmt.Errorf("ledger: %s: %w", path, ErrMissingLedger)
		}
		return nil, fmt.Errorf("ledger: cannot examine %s — refusing (fail closed): %w", path, lerr)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("ledger: %s exists but is not a regular file — refusing (fail closed); run 'state repair'", path)
	}
	// ONE read yields the bytes every check below judges — a reread per check is the TOCTOU
	// the bash closed with its snapshot.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ledger: cannot read — refusing (fail closed): %w", err)
	}
	// From here every refusal is POSITIVE evidence about these bytes: ErrCorrupt.
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("ledger is not newline-terminated (truncated?): %w", ErrCorrupt)
	}
	body := string(data)
	lastNL := strings.LastIndexByte(body[:len(body)-1], '\n')
	checkline := body[lastNL+1 : len(body)-1]
	expected, ok := strings.CutPrefix(checkline, "#sha256=")
	if !ok {
		return nil, fmt.Errorf("ledger checksum line missing or malformed: %w", ErrCorrupt)
	}
	hashed := data[:lastNL+1]
	if cliio.SHA256Hex(hashed) != expected {
		return nil, fmt.Errorf("ledger checksum mismatch: %w", ErrCorrupt)
	}
	// Schema gate AFTER integrity, so a torn header reads as corruption first.
	lines := strings.Split(strings.TrimSuffix(string(hashed), "\n"), "\n")
	header := lines[0]
	schema, ok := strings.CutPrefix(header, "#mythical-ctl-ledger schema=")
	if !ok {
		return nil, fmt.Errorf("ledger header malformed: %w", ErrCorrupt)
	}
	if schema == "" || strings.IndexFunc(schema, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return nil, fmt.Errorf("ledger schema %q is not a number: %w", schema, ErrCorrupt)
	}
	if decGT(schema, Schema) {
		return nil, fmt.Errorf("ledger schema %s vs %s: %w", schema, Schema, ErrNewerSchema)
	}
	return &Ledger{lines: lines[1:]}, nil
}

// decGT compares two all-digit decimal strings, a > b, without integer conversion — an
// arbitrarily long schema must refuse as NEWER, never overflow into a parse.
func decGT(a, b string) bool {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

// ConfirmedCorrupt answers repair's destroy-and-rebuild gate and NOTHING else: true only when
// the content is positively confirmed corrupt. A valid ledger, an absent one, and one
// unreadable for an unproven reason all answer false — do not destroy.
func ConfirmedCorrupt(st Store) bool {
	_, err := Read(st)
	return errors.Is(err, ErrCorrupt)
}

// Write replaces the ledger atomically. It asserts the family lock, requires a WRITABLE store
// whose token IS the presented token (a store built under home A can never be written with
// home B's lock), and never destroys evidence: an existing ledger must validate — or be
// legitimately absent, or a still-valid NEWER one must be refused untouched — before it is
// replaced.
func Write(h famlock.Held, st Store, l *Ledger) error {
	if err := famlock.Assert(h, "write the ledger"); err != nil {
		return err
	}
	s, err := unseal(st)
	if err != nil {
		return err
	}
	if !s.writable {
		return fmt.Errorf("ledger: refusing to write %s: %w", s.path, ErrReadOnlyStore)
	}
	if s.tok != h {
		return fmt.Errorf("ledger: the presented lock token is not the one this store was opened under — refusing")
	}
	if _, err := readPath(s.path); err != nil && !errors.Is(err, ErrMissingLedger) {
		return fmt.Errorf("existing ledger does not validate — refusing to overwrite it; run 'state repair': %w", err)
	}

	var b strings.Builder
	b.WriteString("#mythical-ctl-ledger schema=" + Schema + "\n")
	for _, line := range l.lines {
		b.WriteString(line + "\n")
	}
	sum := cliio.SHA256Hex([]byte(b.String()))
	b.WriteString("#sha256=" + sum + "\n")

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".ledger.*")
	if err != nil {
		return fmt.Errorf("ledger: cannot create a temp file in %s — refusing (fail closed): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("ledger: cannot write the records — refusing (fail closed): %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("ledger: cannot replace %s — refusing (fail closed): %w", s.path, err)
	}
	return nil
}
