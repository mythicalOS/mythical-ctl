// Package backup writes a backup and performs the staging-ledger restore (§6c/D59).
//
// COPYING THE DIRECTORY IS NOT A BACKUP (§3a). The named volumes and the product's runtime
// secrets are not in the installer home at all, and removing that directory leaves every
// container running. A backup is: the tree, the installer state LEDGER, and per volume a
// contents archive plus its per-entry MANIFEST and its recorded NONCE. Refusing to write one
// without the ledger is the point — a tree-only "backup" is a data-loss trap dressed as a
// feature: it restores a machine that has silently discarded every rollback floor and no
// longer recognizes its own containers.
//
// VOLUME BACKUPS CARRY IDENTITY METADATA, NOT JUST BYTES (D59). Restoring volume *contents*
// into freshly created volumes produces volumes whose nonce labels are absent — so the
// restored ledger, faithfully carried by the same backup, would reject the very volumes the
// restore just created: every identity check fails, every operation preserves-and-stops, and
// the "restored" installation is wedged by its own consistency rules working correctly on
// inconsistent inputs. Carrying the nonce (and re-labelling on create) is what keeps that from
// happening.
//
// THE STAGING LEDGER IS NON-AUTHORITATIVE (§6c/D59, internal/ledger). A restore writes the
// incoming ledger plus its own intent to `.state/ledger.staging` — same format, same checksum
// discipline, a distinct well-known path beside the real ledger — BEFORE anything is created.
// D28 permits exactly one authoritative ledger; nothing here launches, deletes or reconciles
// from the staging one, and every ordinary command that finds it (with no active ledger)
// refuses and names it as an in-progress restore, never as first use (see prov.FirstUse —
// that classification already existed before this package; this module is what actually
// produces and clears the marker it recognises).
//
// THIS IS THE ONLY PACKAGE THAT MAY CONSTRUCT THE STAGING STORE. check.sh's boundary gate
// pins ledger.OpenStaging to this import path: a lifecycle path that could open staging would
// treat a not-yet-verified restore as live state. Nothing here re-exports it, hands a caller a
// staging Store, or hands one the path of one — INCLUDING the seams. A restore genuinely does
// have to authenticate documents against the STAGED ledger (the anchor the backup carries is
// the one it must measure against), but that acceptance happens HERE and only the resulting
// authenticated *trust.Index crosses the seam: an index is an answer, not a capability, and it
// carries no way to read or write any ledger. Handing the seam the Store and the lock instead
// would have left the gate green while the boundary it names was open — a caller could have
// written to staging without ever naming OpenStaging.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// restoreKind is the ledger record kind the restore intent lives under — its own kind, so no
// ordinary reader of `object` records can ever meet it, and clearing it is a record-drop of
// exactly one row.
const restoreKind = "restore"

// kindObject is the provenance record kind this module walks. It is spelled here rather than
// imported because internal/prov keeps it unexported; the volume loops read the same rows
// prov.Record writes, and a drift between the two is caught by TestVolumeRecordsAreProvRecords.
const kindObject = "object"

// Transcript is ONE pinned-helper run's answer: the helper's stdout verbatim, and the exit
// status beside it. The two are kept apart deliberately — an exit status is not a result
// (a helper that regressed to exiting 0 while printing nothing must not read as a pass), and
// a non-zero status with a well-formed transcript still carries observations worth naming.
type Transcript struct {
	// Text is the helper's stdout, verbatim. Never its stderr: a helper that could not be
	// LAUNCHED and a check that ran and failed are different facts, and the runtime's own
	// words on stderr are what tell them apart (§7.3). Only the answer is parsed.
	Text string
	// Code is the helper's own exit status. 0 is success.
	Code int
}

// Copier is the narrow seam onto the PINNED COPY CONTAINER (the reference's lib/copy.sh; the
// Go home of the implementation is internal/copyfill). The host cannot read a named volume at
// all (D54), so every question about a volume's contents — enumerate it, count it, verify it,
// fill it, drain it — is asked through this one door.
//
// It is an interface here, and NOT a dependency on that package, for two reasons that both
// matter: this module's refusals are specified against the TRANSCRIPT (the grammar, the stated
// observations, the count that binds verification to the manifest), so the transcript is what
// crosses the seam; and the copy module is developed independently, so a compile-time
// dependency in this direction would couple two ports that have no reason to move together.
// The production implementation is wired by an adapter at the CLI.
//
// EVERY METHOD TAKES AN ALREADY-AUTHENTICATED *trust.Index AND NOTHING ELSE FROM THE STATE
// LAYER. That is deliberate and it is the whole shape of the seam. A restore's copy calls DO
// have to be measured against the STAGED ledger rather than the (absent) active one — the
// pinned copy image is named by the family index, the index is authenticated against the
// recorded trust anchor, and the anchor lives IN A LEDGER, so a restore with no active ledger
// would otherwise fail "no anchor has been recorded" on precisely the machine it is rebuilding.
// That acceptance therefore happens INSIDE this module, against the store the operation runs
// under, and only its RESULT crosses the seam. An index is an answer; a Store and a lock are
// capabilities, and handing those out would have opened the staging boundary while its gate
// stayed green.
//
// An error means the helper COULD NOT BE RUN — never an answer. A helper that ran and failed
// reports itself in Transcript.Code.
type Copier interface {
	// Available makes the pinned copy image usable, or refuses (reported).
	Available(ctx context.Context, ix *trust.Index) error
	// Enumerate runs the per-entry manifest enumeration over a volume.
	Enumerate(ctx context.Context, ix *trust.Index, volume string) (Transcript, error)
	// Count runs the entry-count enumeration over a volume.
	Count(ctx context.Context, ix *trust.Index, volume string) (Transcript, error)
	// Verify checks a volume's contents against a per-entry manifest, which is handed to the
	// helper on its STDIN rather than mounted as a third host path.
	Verify(ctx context.Context, ix *trust.Index, volume string, manifest []byte) (Transcript, error)
	// Run copies a VOLUME's contents out to a host directory (the backup direction).
	Run(ctx context.Context, ix *trust.Index, volume, dstHostDir, runtimeUID, operatorUID string) error
	// Fill copies a host directory's contents INTO a volume (the restore direction — host
	// data read-only, the volume writable; the reverse of Run).
	Fill(ctx context.Context, ix *trust.Index, srcHostDir, volume, runtimeUID, operatorUID string) error
}

// SafeChain is the OWNERSHIP-SAFETY CHECK for an operator-named location: it refuses unless
// every component of the (already canonical) path is owned by root or the operator and is not
// group- or other-writable.
//
// BOTH the backup's OUTPUT directory and the restore's INPUT directory are named by the
// operator on the command line, and both sit on the untrusted side of the same TOCTOU class
// migrate-storage already closed for its own destination: an attacker-writable parent could
// otherwise be swapped for a symlink between this process naming the path and it ever being
// written to or read from. There is no fd-relative filesystem operation here that would let a
// re-verification be atomic, so the fix is REQUIRING a safe location, never trying to out-race
// a hostile parent with more re-checks.
//
// THIS IS ALSO THE ONLY AUTHENTICATION A BACKUP GETS. There is no secret to sign the tree
// with, and the ledger's plain sha256 is exactly as recomputable by whoever can write the tree
// as it is by this code — an attacker who can write a volume's data can write a mutually
// consistent manifest beside it, and the ledger's own checksum right along with it. So the
// checksums authenticate INTERNAL CONSISTENCY (the bytes were not damaged after being
// written), never PROVENANCE (that this installer's own backup wrote them). What stands in for
// a signature is LOCATION: if no other party can write anywhere in the backup root, no other
// party can forge the manifest or the data underneath it either, mutually consistent or not.
//
// IT IS A SEAM, NOT A SECOND IMPLEMENTATION. The check itself is migrate-storage's own
// hardened primitive (internal/migrate); a second, hand-written copy of a security check is
// exactly the drift this codebase's "one implementation" rule exists to prevent. A nil
// SafeChain refuses every operation in this package rather than defaulting to permissive.
type SafeChain func(canonicalPath, what string) error

// Chain is the authenticated-document context one operation runs under: the lock that
// authorizes a trust-floor advance, the STORE that advance lands in, and the family index it
// is measured against. A backup runs its chain against the LIVE ledger; every step of a
// restore runs against the STAGED one, which is where any floor advance belongs until
// activation carries it forward.
//
// IT NEVER CROSSES A SEAM. Only this module holds one; what it hands the copy module is the
// authenticated index a Chain produces (see acceptIndex), never the Chain itself.
type Chain struct {
	Lock  famlock.Held
	Store ledger.Store
	Index string
}

// Deps is everything the two verbs need from the rest of the tree. Every seam is REQUIRED:
// a nil one refuses, because "could not ask" must never arrive spelled as a nil dereference.
type Deps struct {
	// Lock is the held family lock. Every path here mutates — the ledger, the staging ledger,
	// or the fleet — and the trust-floor advances the copy image's own authentication performs
	// are ledger writes like any other.
	Lock famlock.Held
	// Home is the installer home the lock was taken on.
	Home string
	// RT is the runtime facade: volume creation and removal.
	RT *runtime.Runtime
	// Objs is the READ-ONLY runtime seam: an object's label, and an unfiltered listing.
	Objs prov.Objects
	// Copier is the pinned copy container.
	Copier Copier
	// Safe is the ownership-safety check for operator-named locations.
	Safe SafeChain
	// Confirm gates every destructive path.
	Confirm cliio.ConfirmFunc
	// Out carries progress; Err carries every refusal, in full prose. A refusal is REPORTED
	// on Err and ALSO returned as an error: the prose is the operator's, the error is the
	// caller's control signal, and the caller does not print it again.
	Out, Err io.Writer
	// Index, Policy and ManifestDir locate the authenticated documents each volume's own
	// product manifest is resolved through — runtime_uid decides who owns copied files, so it
	// has to come from a document this installation vouches for, never a bare parse.
	Index, Policy, ManifestDir string
	// OperatorUID is the invoking user's uid, as the copy container's ownership contract
	// names it.
	OperatorUID string
}

func (d Deps) warn(format string, a ...any) { cliio.Warnf(d.Err, format, a...) }

func (d Deps) log(format string, a ...any) { fmt.Fprintf(d.Out, format+"\n", a...) }

// check refuses an incomplete Deps before anything is touched. Every field below is load
// bearing on a destructive path; a zero one is a programming error, and discovering it halfway
// through a restore is the one time it must not be discovered.
func (d Deps) check() error {
	switch {
	case d.Lock == nil:
		return errors.New("backup: no family lock — refusing")
	case d.Home == "":
		return errors.New("backup: no installer home — refusing")
	case d.RT == nil:
		return errors.New("backup: no container runtime — refusing")
	case d.Objs == nil:
		return errors.New("backup: no runtime to ask about objects — refusing")
	case d.Copier == nil:
		return errors.New("backup: no copy module — the host cannot read a named volume, so there is nothing to refuse into; refusing")
	case d.Safe == nil:
		return errors.New("backup: no location-safety check — an operator-named directory is the only authentication a backup gets; refusing")
	case d.Confirm == nil:
		return errors.New("backup: no confirmation seam — refusing")
	case d.Out == nil || d.Err == nil:
		return errors.New("backup: no output streams — refusing")
	case d.OperatorUID == "":
		return errors.New("backup: no operator uid — refusing")
	}
	return nil
}

// --- the two well-known ledger paths ------------------------------------------------------
//
// DERIVED HERE, NOT HANDED OUT. internal/ledger seals its stores: nothing outside it can ask a
// Store where it points, which is what makes OpenStaging's boundary gate meaningful. This
// module needs the two paths as FILES — a restore renames the staging ledger into the live one
// and preserves a corrupt one aside, and neither is a record edit — so it derives them from
// the same home the stores are derived from. TestPathsAgreeWithLedgerStores pins the two
// definitions together by writing through the real stores and stat-ing these paths, so a
// change to either side reddens rather than silently drifting.

func livePath(home string) string { return filepath.Join(home, ".state", "ledger") }

func stagingPath(home string) string { return filepath.Join(home, ".state", "ledger.staging") }

// regularFile answers the reference's `[ -f <p> ]`: present, and a regular file after
// following symlinks. A directory at the name answers false, exactly as the test does.
func regularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// --- shared: a safe location for the operator-named directory -------------------------------
//
// THE WHOLE CANONICAL PATH IS RESOLVED, LEAF INCLUDED, WHEN IT ALREADY EXISTS. Canonicalizing
// only the PARENT and keeping the raw leaf name verbatim means an EXISTING backup-directory
// symlink is never followed, and everything below trusts the alias rather than what it
// actually names. runtime.Canon on an existing path resolves it fully, following a symlink
// leaf exactly as it already follows one mid-chain; on a leaf that does not exist yet it falls
// back to canonical-parent-plus-name, so one call is correct for both a backup being read and
// one about to be created.
//
// WHICH ANCESTOR CHAIN GETS THE OWNERSHIP CHECK then depends on whether anything is there yet:
// a leaf that already exists is checked WHOLE, itself included — an existing backup root that
// is group/other-writable is exactly as forgeable as an unsafe parent. A leaf that does not
// exist cannot be stat'd at all, so only its (already-canonical) parent is checked; the leaf
// itself is safe by construction the instant THIS process creates it under a parent nothing
// else can write into.
func (d Deps) safeDir(raw, what string) (string, error) {
	canon, err := runtime.Canon(raw)
	if err != nil {
		d.warn("backup: %q does not resolve. Refusing to use it for %s.", raw, what)
		return "", fmt.Errorf("backup: %s does not resolve: %w", what, err)
	}
	target, subject := canon, what
	if _, lerr := os.Lstat(canon); lerr != nil {
		target, subject = filepath.Dir(canon), "the parent of "+what
	}
	if serr := d.Safe(target, subject); serr != nil {
		d.warn("backup: %v", serr)
		d.warn("backup: refusing to use an unsafe location for %s.", what)
		return "", fmt.Errorf("backup: unsafe location for %s: %w", what, serr)
	}
	return canon, nil
}

// canonUnder canonicalizes a path AT THE POINT OF USE, refusing unless it resolves to
// something still inside root (which must already be canonical — safeDir's own output).
//
// This is what closes the gap between an early existence/type check on a path and the moment
// it is actually read or bound into the copy container: checking a path once and then using
// the RAW form later leaves a window in which an entry could be replaced between the two.
// Canonicalizing immediately before use collapses that window to this call itself, the same
// discipline safeDir already applies to the root, and the containment check catches a symlink
// that escapes the root outright rather than trusting wherever it leads.
func (d Deps) canonUnder(p, root, what string) (string, error) {
	canon, err := runtime.Canon(p)
	if err != nil {
		d.warn("restore: %s does not resolve. Refusing to use it.", what)
		return "", fmt.Errorf("restore: %s does not resolve: %w", what, err)
	}
	if canon != root && !strings.HasPrefix(canon, withSep(root)) {
		d.warn("restore: %s resolves to %q, which is OUTSIDE the verified backup root (%q).", what, canon, root)
		d.warn("  Refusing — a symlink escaping the root cannot be trusted.")
		return "", fmt.Errorf("restore: %s escapes the backup root", what)
	}
	return canon, nil
}

// withSep is the prefix that means "strictly inside p" — except for the root, whose
// descendants all begin with exactly "/".
func withSep(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}

// acceptIndex authenticates the family index against the trust anchor recorded in THIS
// operation's store, and hands back the result. It is where a restore's "measure this against
// the ledger the backup carried, not the machine's own" actually happens, and it is the only
// thing the copy seam ever receives from the state layer.
//
// It is called at each point the reference calls its own copy-availability check, rather than
// once per verb: the reference re-authenticates per helper invocation, and any floor advance
// that follows lands in the same store either way.
func (d Deps) acceptIndex(ch Chain) (*trust.Index, error) {
	ix, err := trust.AcceptIndex(ch.Lock, ch.Store, ch.Index)
	if err != nil {
		d.warn("backup: the family index cannot be authenticated — the pinned copy image it names")
		d.warn("  cannot be trusted, so nothing is read or written through it: %v", err)
		return nil, fmt.Errorf("backup: the family index cannot be authenticated: %w", err)
	}
	return ix, nil
}

// runtimeUID resolves EACH VOLUME'S REAL, DECLARED runtime_uid through the FULL authenticated
// chain — index, policy and trust — never a fixed stand-in and never a bare parse. A product
// declaring runtime_uid=900 owns its files as uid 900: treating every volume as if it belonged
// to uid 0 makes a backup refuse files genuinely owned by the product (foreign to the assumed
// pair) and makes a restore grant ownership to uid 0, leaving the product unable to read the
// data it was just given back. That is D59 restated at the ownership layer, not a
// simplification.
//
// A volume whose product cannot be authenticated, or whose manifest declares no runtime_uid,
// REFUSES rather than guessing 0.
func (d Deps) runtimeUID(ch Chain, product, vol string) (string, error) {
	manfile := filepath.Join(d.ManifestDir, product+".manifest")
	m, err := trust.AcceptManifest(ch.Lock, ch.Store, ch.Index, d.Policy, manfile, product)
	if err != nil {
		d.warn("backup: could not authenticate the manifest for product %q (volume %q) —", product, vol)
		d.warn("  refusing to guess its runtime uid: %v", err)
		return "", fmt.Errorf("backup: cannot authenticate the manifest for %q — refusing to guess its runtime uid: %w", product, err)
	}
	// A SECOND DOOR THE SCHEMA CURRENTLY MAKES UNREACHABLE: `runtime_uid` is a required
	// manifest key, so a manifest without one does not parse and the acceptance above refuses
	// first (TestManifestWithNoRuntimeUIDIsRefusedByTheChain measures exactly that). It is kept
	// because "unstated silently meaning uid 0" is the one answer that is never safe here —
	// ownership of every copied file rides on it — and a later schema change must not be able
	// to open that path quietly.
	ruid := m.RuntimeUID()
	if ruid == "" {
		d.warn("backup: the manifest for product %q (volume %q) declares no runtime_uid —", product, vol)
		d.warn("  refusing to guess it.")
		return "", fmt.Errorf("backup: the manifest for %q declares no runtime uid", product)
	}
	return ruid, nil
}

// volumeRecords walks one ledger's object records and returns the (name, nonce, product)
// triples for its volumes, FAILING CLOSED on a semantically incomplete one.
//
// A record can pass the checksum and the field grammar — every token a valid key=value — and
// still be semantically incomplete: `object` with `class=volume` but no `name=` or no
// `nonce=`. Skipping past that treats it exactly like "this record is not a volume" and moves
// on, so a backup could OMIT a ledger-declared volume with no trace that anything was skipped
// — a silent partial backup, and on the restore side a volume the restore would never create.
// The record itself is named in the refusal when there is no volume name to name it by.
//
// verb spells the refusals ("backup" or "restore"): one walk, two callers, and the operator is
// told which operation stopped.
func (d Deps) volumeRecords(l *ledger.Ledger, verb string) ([]volumeRec, error) {
	records, err := l.All(kindObject)
	if err != nil {
		if verb == "backup" {
			d.warn("backup: the installer state ledger's object records could not be listed in full — refusing")
			d.warn("  a backup that would silently omit some of them: %v", err)
		} else {
			d.warn("restore: the staging ledger's object records could not be listed in full — refusing to")
			d.warn("  proceed on a partial view of which volumes this restore is responsible for: %v", err)
		}
		return nil, fmt.Errorf("%s: the object records could not be listed in full: %w", verb, err)
	}
	var out []volumeRec
	// ONE VOLUME, ONE ROW. The selector below settles cardinality by KEY, which leaves one
	// shape open: a second row keyed for something else while NAMING a volume that does have
	// its own row. Both walk to the same volume, so the loop would visit it twice — restore
	// filling it, then meeting it again as "already filled" — on the authority of a row that
	// is not its record at all. Two rows reaching one name is a contradiction the ledger
	// cannot settle, so it refuses here rather than picking.
	seen := map[string]bool{}
	for _, fields := range records {
		if class, _ := ledger.FieldOf(fields, "class"); class != "volume" {
			continue
		}
		name, ok := ledger.FieldOf(fields, "name")
		if !ok || name == "" {
			d.warn("%s: a 'volume' object record carries no name — refusing rather than silently omitting a", verb)
			d.warn("  ledger-declared volume. Record: %s", renderRecord(fields))
			return nil, fmt.Errorf("%s: a volume object record carries no name", verb)
		}
		// THE ROW IS RE-SELECTED THROUGH THE ONE PROVENANCE SELECTOR, and the fields used from
		// here down are the ones IT returns. A walk of raw rows answers two questions this
		// module must not answer for itself.
		//
		// DOES THE ROW DESCRIBE WHAT IT IS KEYED AS? `key`, `class` and `name` are three
		// INDEPENDENT fields and nothing in the format makes them agree, so a row keyed
		// `volume:X` while naming Y would have this restore create and fill Y on X's
		// authority — and the restored installation could then never authorize Y, because the
		// selector it authorizes through would refuse the very same row.
		//
		// AND IS IT THE ONLY ROW THAT ANSWERS? Two rows for one volume are a contradiction the
		// ledger cannot settle. Acting on the first one fills the volume, meets the second,
		// finds it non-empty and verifying, calls it "already done", and ACTIVATES a ledger in
		// which that volume can never be authorized again — a machine wedged by its own
		// consistency rules working correctly on inconsistent input, which is exactly what
		// this module exists to prevent. The selector refuses ambiguity; this walk must not
		// route around it.
		selected, serr := prov.Find(l, prov.ClassVolume, name)
		if serr != nil {
			d.warn("%s: the ledger's record for volume %q cannot be read as the authority for it —", verb, name)
			d.warn("  refusing rather than acting on a row that answers for one object while describing")
			d.warn("  another, or on one of several rows that contradict each other: %v", serr)
			d.warn("  Record: %s", renderRecord(fields))
			return nil, fmt.Errorf("%s: the record for volume %q is not its authority: %w", verb, name, serr)
		}
		fields = selected
		nonce, ok := ledger.FieldOf(fields, "nonce")
		if !ok || nonce == "" {
			d.warn("%s: the record for volume %q carries no nonce — refusing rather than silently omitting it.", verb, name)
			return nil, fmt.Errorf("%s: the record for volume %q carries no nonce", verb, name)
		}
		product, ok := ledger.FieldOf(fields, "product")
		if !ok || product == "" {
			d.warn("%s: the record for volume %q carries no product — refusing rather than guessing which", verb, name)
			d.warn("  manifest declares its runtime uid.")
			return nil, fmt.Errorf("%s: the record for volume %q carries no product", verb, name)
		}
		if seen[name] {
			d.warn("%s: more than one 'volume' object record reaches volume %q — refusing rather than", verb, name)
			d.warn("  acting on one of several rows that contradict each other about the same object.")
			d.warn("  Record: %s", renderRecord(fields))
			return nil, fmt.Errorf("%s: more than one record reaches volume %q", verb, name)
		}
		seen[name] = true
		out = append(out, volumeRec{name: name, nonce: nonce, product: product})
	}
	return out, nil
}

type volumeRec struct{ name, nonce, product string }

func renderRecord(fields []ledger.Field) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f.Key+"="+f.Value)
	}
	if len(parts) == 0 {
		return "<empty>"
	}
	return strings.Join(parts, " ")
}

// --- the backup manifest --------------------------------------------------------------------
//
// THE BACKUP MANIFEST AUTHENTICATES THE CONTRACT, NOT JUST THE BYTES. Per-file digests alone
// let a restore verify "success" while silently losing everything the copy contract promises:
// a symlink re-created as a file has no bytes to mismatch, flattened hardlinks digest
// identically, and dropped modes or ownership are invisible to a content hash alone.
//
// So the manifest records, per entry: TYPE, and per type — content digest (regular files), the
// verbatim link target (symlinks), hardlink grouping, mode, ownership and mtime. It is
// produced by the SAME pinned copy container that reads the volume for the backup's contents
// archive (the host cannot read a named volume at all — D54).

// ManifestWrite enumerates one volume through the copy container and installs the transcript
// as that volume's per-entry manifest. Nothing is written unless the helper both conformed to
// the grammar and STATED its own completion: an exit status is not a result.
func ManifestWrite(ctx context.Context, d Deps, ch Chain, vol, out string) error {
	if err := d.check(); err != nil {
		return err
	}
	ix, err := d.acceptIndex(ch)
	if err != nil {
		return err
	}
	if err := d.Copier.Available(ctx, ix); err != nil {
		return err
	}
	t, err := d.Copier.Enumerate(ctx, ix, vol)
	if err != nil || t.Code != 0 {
		d.warn("backup: could not enumerate volume %q for its manifest — the backup is NOT written.", vol)
		if err != nil {
			d.warn("  %v", err)
		}
		return fmt.Errorf("backup: could not enumerate volume %q for its manifest", vol)
	}
	text := body(t.Text)
	if gerr := d.grammarOK(text, "manifest", "digest", "linktarget", "mode", "owner", "mtime", "hardlink", "done"); gerr != nil {
		d.warn("backup: the manifest transcript for volume %q is not well-formed — the backup is NOT", vol)
		d.warn("  written.")
		return fmt.Errorf("backup: the manifest transcript for volume %q is not well-formed: %w", vol, gerr)
	}
	doneval, derr := d.stated(text, "done", "backup manifest", "completion")
	if derr != nil {
		return derr
	}
	if doneval != "ok" {
		d.warn("backup: the manifest helper for volume %q did not report completion (done=%s).", vol, orEmpty(doneval))
		d.warn("  The backup is NOT written.")
		return fmt.Errorf("backup: the manifest helper for volume %q did not report completion", vol)
	}
	if werr := writeFileAtomic(out, []byte(text+"\n")); werr != nil {
		d.warn("backup: cannot write the manifest for volume %q: %v", vol, werr)
		return fmt.Errorf("backup: cannot write the manifest for volume %q: %w", vol, werr)
	}
	return nil
}

func orEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

// writeFileAtomic installs bytes through a temp file in the SAME directory and one rename — a
// half-written manifest beside a complete data directory is a backup that verifies against a
// contract it does not carry.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// --- backup -----------------------------------------------------------------------------------

// Run writes a backup of this installation to rawDir: the ledger, the tree, and every named
// volume's contents WITH its identity metadata.
func Run(ctx context.Context, d Deps, rawDir string) error {
	if err := d.check(); err != nil {
		return err
	}
	dir, err := d.safeDir(rawDir, "the backup output directory")
	if err != nil {
		return err
	}

	// THE OUTPUT MAY NOT CONTAIN THE INSTALLATION IT IS CAPTURING. Inside the home is fine —
	// the walk skips that subtree — but an output directory that IS the home, or an ancestor of
	// it, cannot produce a coherent tree: every file the capture writes lands inside the thing
	// being captured, and the exclusion has no subtree left to skip. Refused with nothing
	// created, rather than writing a backup whose tree is a partial copy of its own output.
	homeCanon, herr := runtime.Canon(d.Home)
	if herr != nil {
		d.warn("backup: the installer home (%s) does not resolve: %v", d.Home, herr)
		return fmt.Errorf("backup: the installer home does not resolve: %w", herr)
	}
	if dir == homeCanon || strings.HasPrefix(homeCanon, withSep(dir)) {
		d.warn("backup: %q is the installer home, or contains it.", dir)
		d.warn("  A backup written there would capture its own output as part of the tree. Name a")
		d.warn("  directory outside the installation, or one inside it.")
		return fmt.Errorf("backup: the output directory contains the installation being captured")
	}

	lf := livePath(d.Home)
	if !regularFile(lf) {
		d.warn("backup: there is no installer state ledger to back up.")
		d.warn("  Refusing to write a backup without it: restoring the tree alone would give you a machine")
		d.warn("  that has silently discarded every rollback floor and no longer recognizes its own")
		d.warn("  containers.")
		return errors.New("backup: there is no installer state ledger to back up")
	}
	live, err := ledger.Live(d.Lock)
	if err != nil {
		return err
	}
	l, err := ledger.Read(live)
	if err != nil {
		d.warn("backup: the ledger does not validate. Refusing to capture state we cannot read: %v", err)
		return fmt.Errorf("backup: the ledger does not validate: %w", err)
	}

	// THE LEDGER'S VOLUME RECORDS ARE JUDGED BEFORE ANYTHING IS WRITTEN. The walk is a pure
	// read, and it is the one thing that can prove this backup would be COMPLETE — a record
	// that passes the checksum and the field grammar and is still semantically incomplete
	// (class=volume with no name= or no nonce=) means some ledger-declared volume cannot be
	// captured. Discovering that after the output directory and the captured ledger already
	// exist leaves a half-written backup that looks like a backup, which is exactly the
	// data-loss trap this module exists to prevent, so the refusal happens first and nothing
	// is created at all.
	vols, err := d.volumeRecords(l, "backup")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(dir, "volumes"), 0o700); err != nil {
		d.warn("backup: cannot create %q: %v", dir, err)
		return fmt.Errorf("backup: cannot create %q: %w", dir, err)
	}
	if err := copyFilePreserving(lf, filepath.Join(dir, "ledger")); err != nil {
		d.warn("backup: cannot capture the ledger: %v", err)
		return fmt.Errorf("backup: cannot capture the ledger: %w", err)
	}

	if err := d.captureTree(dir); err != nil {
		return err
	}

	ch := Chain{Lock: d.Lock, Store: live, Index: d.Index}
	for _, v := range vols {
		ruid, err := d.runtimeUID(ch, v.product, v.name)
		if err != nil {
			return err
		}
		base := filepath.Join(dir, "volumes", v.name)
		if err := os.WriteFile(base+".nonce", []byte(v.nonce+"\n"), 0o600); err != nil {
			d.warn("backup: cannot record the nonce for volume %q: %v", v.name, err)
			return fmt.Errorf("backup: cannot record the nonce for volume %q: %w", v.name, err)
		}
		if err := ManifestWrite(ctx, d, ch, v.name, base+".manifest"); err != nil {
			return err
		}
		if err := os.MkdirAll(base+".data", 0o700); err != nil {
			d.warn("backup: cannot create the contents directory for volume %q: %v", v.name, err)
			return fmt.Errorf("backup: cannot create the contents directory for volume %q: %w", v.name, err)
		}
		ix, ierr := d.acceptIndex(ch)
		if ierr != nil {
			return ierr
		}
		if err := d.Copier.Available(ctx, ix); err != nil {
			return err
		}
		if err := d.Copier.Run(ctx, ix, v.name, base+".data", ruid, d.OperatorUID); err != nil {
			return err
		}
		d.log("backup: captured volume %s (contents, per-entry manifest, and its nonce).", v.name)
	}

	d.log("backup: written to %s.", dir)
	d.log("  It contains the ledger, the tree, and every named volume's contents WITH its identity")
	d.log("  metadata. Restoring contents alone would create volumes with no nonce labels, which the")
	d.log("  restored ledger would then reject — the installation would be wedged by its own consistency")
	d.log("  rules working correctly on inconsistent inputs.")
	return nil
}

// captureTree copies the installer home into <dir>/tree, EXCLUDING the ephemeral lock and both
// ledgers.
//
// RESTORING A STALE LOCK WEDGES THE FIRST OPERATION AFTER A RESTORE, and the lock is not
// ledger content: it is ephemeral, lives beside the ledger, and is never backed up. The ledger
// and any staging ledger are excluded here too — the ledger is captured through its own
// authoritative path, and a staging one is never legitimate to carry forward at all — so a
// second, generic copy under `tree/.state/` would just be a confusing duplicate for a future
// restore to reason about.
//
// A WALK THAT COULD NOT FINISH IS NOT AN EMPTY ONE. A directory this process cannot read makes
// the walk report a partial view, which looks exactly like "walked the whole tree and found
// nothing else" — so any walk error refuses the backup rather than writing a partial tree.
//
// THE WHOLE LIST IS TAKEN BEFORE THE FIRST BYTE IS WRITTEN, and the reason is not tidiness.
// Nothing stops an operator naming an output directory INSIDE the installer home, and the
// output directory already exists by the time this runs (the ledger was captured into it). A
// live walk would then descend into the tree it is itself creating and copy it into itself,
// again, without bound — a disk-filling loop reachable from an ordinary invocation. Listing
// first bounds it exactly as the reference's own `find > file` then read-the-file does; the
// skip below then removes the self-reference entirely, so a backup never contains a partial
// copy of itself.
func (d Deps) captureTree(dir string) error {
	home := d.Home
	treeRoot := filepath.Join(dir, "tree")

	// THE WALK STARTS AT THE CANONICAL HOME, and this is not tidiness either. A tree walk does
	// not follow a symlink handed to it as its ROOT: on an installation whose home is itself a
	// link — an operator who relocated their storage, the ordinary reason to make one — the
	// walk would visit that single entry, descend into nothing, and this function would report
	// a complete tree having captured NOTHING, silently. (The reference has no such hole: its
	// `find` runs inside a `cd` into the home, and `cd` follows the link.) Resolving first also
	// makes the output-directory comparison below meaningful, since that path is canonical
	// already — comparing a canonical path against alias-prefixed walk paths never matches, and
	// the subtree it is meant to skip would be captured into itself.
	root, cerr := runtime.Canon(home)
	if cerr != nil {
		d.warn("backup: the installer home (%s) does not resolve — refusing rather than capturing", home)
		d.warn("  a tree from a location this process cannot name: %v", cerr)
		return fmt.Errorf("backup: the installer home does not resolve: %w", cerr)
	}

	type entry struct {
		path string
		rel  string
		info os.FileInfo
	}
	var entries []entry
	var walkErr error
	if werr := filepath.WalkDir(root, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			walkErr = err
			return err
		}
		if p == root {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			walkErr = rerr
			return rerr
		}
		// THE BACKUP BEING WRITTEN IS NOT PART OF THE INSTALLATION. Skipping the whole
		// subtree, not merely its root, is what keeps an output directory named inside the
		// home from appearing in its own tree copy half-written.
		if p == dir {
			return filepath.SkipDir
		}
		if excludedFromTree(rel) {
			// PRUNED, NOT MERELY SKIPPED. Returning nil on a DIRECTORY visits it and then
			// descends anyway, and the children carry names the exclusion list does not
			// match — so `.state/lock/…` or `.state/ledger/…` would be copied one level
			// down while the operator was told the lock and the ledger were left out. Any of
			// these three names can genuinely BE a directory: a failed restore is documented
			// as leaving the ledger path as one. The reference prunes; so does this.
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := de.Info()
		if ierr != nil {
			d.warn("backup: cannot examine %q: %v", rel, ierr)
			walkErr = ierr
			return ierr
		}
		entries = append(entries, entry{path: p, rel: rel, info: info})
		return nil
	}); werr != nil {
		if walkErr != nil {
			d.warn("backup: could not fully walk the installer home (%s) — refusing a partial tree.", home)
			return fmt.Errorf("backup: could not fully walk the installer home: %w", walkErr)
		}
		return fmt.Errorf("backup: capturing the tree failed: %w", werr)
	}

	for _, e := range entries {
		p, rel, info := e.path, e.rel, e.info
		dst := filepath.Join(treeRoot, rel)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			tgt, lerr := os.Readlink(p)
			if lerr != nil {
				d.warn("backup: cannot read symlink target for %q", rel)
				return lerr
			}
			if merr := os.MkdirAll(filepath.Dir(dst), 0o700); merr != nil {
				return merr
			}
			if serr := os.Symlink(tgt, dst); serr != nil {
				d.warn("backup: cannot recreate symlink %q", rel)
				return serr
			}
		case info.IsDir():
			if merr := os.MkdirAll(dst, 0o700); merr != nil {
				return merr
			}
		case info.Mode().IsRegular():
			if merr := os.MkdirAll(filepath.Dir(dst), 0o700); merr != nil {
				return merr
			}
			if cerr := copyFilePreserving(p, dst); cerr != nil {
				d.warn("backup: cannot copy %q", rel)
				return cerr
			}
		default:
			d.warn("backup: %q is not a regular file, directory or symlink — skipped (not product data).", rel)
		}
	}
	return nil
}

// excludedFromTree names the four paths that are never carried into a backup's tree copy, in
// the reference's own terms: the lock and any lock sidecar, the ledger, and a staging ledger.
func excludedFromTree(rel string) bool {
	switch rel {
	case filepath.Join(".state", "lock"),
		filepath.Join(".state", "ledger"),
		filepath.Join(".state", "ledger.staging"):
		return true
	}
	return strings.HasPrefix(rel, filepath.Join(".state", "lock")+".")
}

// preservedMode is what a copy carries across: the permission bits AND the three that are not
// permissions — setuid, setgid and sticky. The permission bits alone are what `Perm()` returns,
// and a file restored without its setgid bit is not the file that was backed up; on a directory
// that bit is what makes a whole subtree's group ownership work.
func preservedMode(m os.FileMode) os.FileMode {
	return m & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// copyFilePreserving copies one regular file and carries its metadata across, as `cp -p` does:
// the whole mode, and the access and modification times.
//
// OWNERSHIP IS NOT ATTEMPTED, and that is the same thing `cp -p` does here rather than a gap:
// changing a file's owner requires privilege this process does not have, so the copy lands
// owned by whoever ran it. The volumes are the half where ownership is load bearing, and there
// it IS carried — recorded per entry in the backup's own manifest and re-applied by the copier
// under the product's declared runtime uid.
func copyFilePreserving(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	mode := preservedMode(fi.Mode())
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// AFTER the close: writing through the descriptor is what sets the mtime in the first
	// place, so stamping it before would be undone by the copy itself. The mode is re-applied
	// here too, because the open honours the process umask and the bits above it does not.
	//
	// THE ZERO atime IS A SENTINEL, NOT A TIMESTAMP: os.Chtimes documents "A zero time.Time
	// value will leave the corresponding file time unchanged", so this stamps the modification
	// time and lets the access time be whatever creating the copy made it. Spelled out because
	// it reads like a request for the zero instant, and a reviewer did read it that way;
	// TestChtimesZeroLeavesTheOtherTimeAlone measures the sentinel so a change in that
	// behaviour reddens here rather than silently ageing every captured file.
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	return os.Chtimes(dst, time.Time{}, fi.ModTime())
}
