package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
)

// State is the restore-verb's own classification of this machine. §6b's first-use rule gains a
// THIRD column (prov.FirstUse already implements the read side of it): no active ledger BUT a
// staging one present is neither first use nor inconsistent — it is an in-progress restore.
type State string

const (
	// StateNone — no active ledger and no staging one: a fresh restore may begin.
	StateNone State = "none"
	// StateWithIntent — a staging ledger that still records a live restore intent: an
	// interrupted restore, to be resumed.
	StateWithIntent State = "staging-with-intent"
	// StateNoIntent — a checksum-valid staging ledger with NO intent: phase 5 completed, so
	// the only thing left is activation.
	StateNoIntent State = "staging-no-intent"
	// StateCorrupt — a staging ledger POSITIVELY CONFIRMED corrupt (ledger.ErrCorrupt): its
	// checksum, computed over a complete copy of its own bytes, disagrees with what they claim,
	// or those proven bytes do not parse. It authorizes nothing. It is deliberately NOT the
	// classification for "the ledger could not be read" or "a newer build wrote it" — both
	// branches that act on this state MOVE THE FILE ASIDE, and a file may only be moved out of
	// the way on evidence about the file, never on the failure of the question.
	StateCorrupt State = "staging-corrupt"
	// StateActive — this machine has a live installation. Restore is a RECOVERY operation and
	// refuses.
	StateActive State = "active"
)

// CurrentState classifies the machine for the restore verb.
//
// A FOLDED READ IS DELIBERATE HERE AND NOWHERE ELSE. Whether the staged ledger still carries a
// live intent is asked with an ordinary lookup: absent, ambiguous and unreadable all answer
// "no intent", because this function only DISPATCHES. The one place that fold would be unsafe
// — activation, which acts on "the intent is genuinely gone" — asks the question again and
// distinguishes the three (see Activate).
//
// THE TWO PRESENCE QUESTIONS ARE NOT FOLDED, and that is the opposite rule for the opposite
// reason. StateNone is not a dispatch detail — it AUTHORIZES every destructive branch of the
// verb (create volumes, fill them, install a ledger at the active name), so it must mean
// "nothing is there", not "the thing that is there is not a regular file" and not "I could not
// look". See ledgerPresence.
//
// NOR IS THE VALIDITY QUESTION FOLDED, for the same reason one step further in. StateCorrupt is
// the other authorizing answer: both verbs act on it by MOVING THE STAGING LEDGER ASIDE. So it
// means "these bytes are confirmed wrong" and nothing else — a schema this build is too old to
// read, and a read that failed outright, are refusals, and they return an error rather than a
// state so that neither verb reaches a branch that touches the file.
func CurrentState(d Deps) (State, error) {
	if err := d.check(); err != nil {
		return "", err
	}
	live, err := d.ledgerPresence(livePath(d.Home), "the active installer state ledger")
	if err != nil {
		return "", err
	}
	if live {
		return StateActive, nil
	}
	stagingThere, err := d.ledgerPresence(stagingPath(d.Home), "the staging ledger")
	if err != nil {
		return "", err
	}
	if !stagingThere {
		return StateNone, nil
	}
	st, err := ledger.OpenStaging(d.Lock)
	if err != nil {
		return "", err
	}
	l, err := ledger.Read(st)
	switch {
	case err == nil:
	case errors.Is(err, ledger.ErrCorrupt):
		// THE ONLY ANSWER THAT MAY BE CALLED CORRUPTION. ErrCorrupt is positive evidence about
		// the BYTES: a checksum computed over a complete, faithfully-read copy of them disagrees
		// with what they claim, or those proven bytes do not parse. Both callers of this
		// classification act on StateCorrupt by MOVING THE FILE ASIDE, so every other read
		// failure reaching this arm would be a file destroyed on the strength of a question that
		// was never answered.
		return StateCorrupt, nil
	case errors.Is(err, ledger.ErrNewerSchema):
		// CHECKSUM-VALID AND CLEANLY PARSED — written by a NEWER mythical-ctl. Nothing about it
		// is corrupt; this build simply does not understand its schema. Classifying it as
		// corruption moved a still-valid record a newer build wrote out of the way, which is
		// the one thing an unreadable-but-intact file must never have happen to it.
		d.warn("restore: the staging ledger was written by a NEWER mythical-ctl than this one:")
		d.warn("    %s: %v", stagingPath(d.Home), err)
		d.warn("  It is checksum-VALID and it parsed cleanly — this build does not understand its")
		d.warn("  schema, which is not the same fact as its contents being wrong. It is LEFT EXACTLY")
		d.warn("  WHERE IT IS: nothing is moved aside, nothing is removed, and no volume is touched.")
		d.warn("  Upgrade mythical-ctl to a build that understands it and run this again.")
		return "", fmt.Errorf("restore: the staging ledger was written by a newer mythical-ctl: %w", err)
	default:
		// THE QUESTION COULD NOT BE ASKED. An unreadable file, a file that vanished between the
		// presence test and this read — none of it establishes anything about the bytes, so none
		// of it may be reported as "the checksum failed" and none of it may authorize moving the
		// file out of the way.
		d.warn("restore: the staging ledger could not be read, so whether it is valid was never")
		d.warn("  established:")
		d.warn("    %s: %v", stagingPath(d.Home), err)
		d.warn("  A read that FAILED is not a checksum that DISAGREED, and only the second is evidence")
		d.warn("  about the bytes. Nothing is moved aside and nothing is removed.")
		return "", fmt.Errorf("restore: the staging ledger could not be read: %w", err)
	}
	if _, ferr := l.Find(restoreKind, "key", "restore"); ferr != nil {
		return StateNoIntent, nil
	}
	return StateWithIntent, nil
}

// The six phases (§6c):
//
//	1  write the staging ledger, restore intent inside it (host-side, before anything is created)
//	2  per volume: create WITH the recorded nonce label — then RE-INSPECT: the nonce must be
//	   present and the volume EMPTY. `volume create` against an existing name returns the
//	   existing volume WITHOUT applying the label (D56), so a same-name survivor fails one of
//	   the two checks and the restore REFUSES, naming it — never fills a volume it cannot prove
//	   it just created
//	3  fill, via the pinned copy container — the REVERSE of an ordinary copy's direction (host
//	   backup data, read-only, into the volume being filled)
//	4  verify contents against the PER-ENTRY manifest the backup carries, not bytes alone
//	5  only when EVERY volume verifies: atomically rewrite the staging ledger to its final,
//	   intent-free form — this is the ready-to-activate state
//	6  ACTIVATE — atomically rename the staging ledger into the ledger path. Until this step
//	   the machine has no ACTIVE ledger claiming these volumes, so nothing launches them
//
// PHASE 5 EXISTS BECAUSE THE INTENT LIVES INSIDE THE FILE BEING ACTIVATED. Renaming the
// staging ledger unchanged would activate a ledger that still says a restore is in progress —
// every subsequent command meeting a live intent on a completed restore. So the intent is
// removed by an atomic rewrite FIRST, and the two staging states are recovery's dispatch:
// staging WITH an intent ⇒ resume the phases; staging WITHOUT one (and checksum-valid) ⇒ phase
// 5 completed, activate.
//
// LABEL-FIRST ALONE creates the opposite hazard from contents-only: a crash DURING filling
// leaves a volume that passes every identity check while holding PARTIAL contents, and a
// restored ledger would let ordinary reconciliation launch the product on half its data.
// Identity must not authenticate contents that are not there yet — which is why activation is
// last.

// Restore performs (or resumes) a restore from rawDir.
func Restore(ctx context.Context, d Deps, rawDir string) error {
	if err := d.check(); err != nil {
		return err
	}
	sf := stagingPath(d.Home)
	st, err := CurrentState(d)
	if err != nil {
		return err
	}

	switch st {
	case StateActive:
		// RESTORE REQUIRES THAT NO ACTIVE LEDGER EXISTS — it is a RECOVERY operation, not a
		// replacement. On a machine with a live installation, restore would create its volumes
		// beside the running ones and phase 5 would atomically replace the live ledger —
		// ORPHANING EVERY RUNNING CONTAINER of the current installation in one rename, with
		// its provenance gone.
		d.warn("restore: an active installer state ledger is present:")
		d.warn("    %s", livePath(d.Home))
		d.warn("  Refusing. Activating a restored ledger would orphan every running container of the")
		d.warn("  installation that is here now — their provenance would be gone in one rename.")
		d.warn("  Replacing a live installation with a backup is a deliberately destructive operation that")
		d.warn("  must be designed as one. Uninstall first, or wait for an explicit 'restore --replace'")
		d.warn("  with its own safeguards. It is NOT a side effect a recovery verb may have.")
		return errors.New("restore: an active installer state ledger is present")
	case StateCorrupt:
		// A CORRUPT STAGING LEDGER CANNOT AUTHORIZE CLEANUP — its contents are exactly what
		// the checksum says not to trust.
		aside, residue, merr := preserveCorrupt(sf)
		if merr != nil {
			d.warn("restore: cannot preserve the corrupt staging ledger: %v", merr)
			return fmt.Errorf("restore: cannot preserve the corrupt staging ledger: %w", merr)
		}
		d.warn("restore: the staging ledger does not validate. It has been PRESERVED at %s.", aside)
		d.reportResidue(residue, sf)
		d.warn("  It authorizes nothing: the record of which partial volumes a previous attempt created is")
		d.warn("  exactly what the checksum says not to trust.")
		d.warn("  Any partial volumes from that attempt are PRESERVED and are BLOCKING a fresh restore.")
		d.warn("  Removing them is your explicit call — the installer cannot prove they are its own.")
		d.reportBlocking(ctx)
		return errors.New("restore: the staging ledger does not validate")
	}

	// EVERY REMAINING BRANCH DOES SOMETHING DESTRUCTIVE — creates and fills volumes, or
	// activates the incoming ledger in place of the (absent) active one — so it is gated HERE,
	// ONCE, covering all three (a fresh start, a resume, and the activate-only
	// staging-no-intent case) before any of them runs, exactly as the other destructive verbs
	// gate themselves. The two refusals above are pure refusals — nothing is touched — so they
	// return before this gate, never through it.
	prompt := "restore: resume the in-progress restore and activate it once every volume verifies?"
	if st == StateNone {
		prompt = fmt.Sprintf("restore: restore from %q — creates and fills named volumes under their recorded identity, then activates the incoming ledger?", rawDir)
	}
	if !d.Confirm(prompt) {
		d.warn("restore: not confirmed.")
		return errors.New("restore: not confirmed")
	}

	staging, err := ledger.OpenStaging(d.Lock)
	if err != nil {
		return err
	}

	switch st {
	case StateNoIntent:
		d.log("restore: a completed restore is ready to activate. Activating.")
		return Activate(d)
	case StateWithIntent:
		d.log("restore: resuming the in-progress restore.")
	case StateNone:
		dir, derr := d.safeDir(rawDir, "the backup directory")
		if derr != nil {
			return derr
		}
		if fi, serr := os.Stat(dir); serr != nil || !fi.IsDir() {
			d.warn("restore: %q is not a backup directory", dir)
			return fmt.Errorf("restore: %q is not a backup directory", dir)
		}
		// Canonicalized AT THE POINT OF USE, immediately before the read that trusts it — not
		// checked once here and read via the raw path later, which is exactly the window a
		// root nobody else can write still leaves between a type check and the copy after it.
		ledgercanon, cerr := d.canonUnder(filepath.Join(dir, "ledger"), dir, "the backup's ledger")
		if cerr != nil {
			return cerr
		}
		if !regularFile(ledgercanon) {
			d.warn("restore: %q carries no ledger (or it is not a plain file). A backup without one", dir)
			d.warn("  cannot support a verified restore — it would rebuild a machine with no rollback")
			d.warn("  floors and no provenance.")
			return fmt.Errorf("restore: %q carries no ledger", dir)
		}
		// Phase 1: the staging ledger IS the incoming ledger, WITH the intent already inside
		// it — parsed in memory, edited in memory, and installed in ONE atomic write.
		//
		// THE INTENT MUST NEVER BE A SECOND WRITE. Copying the incoming ledger onto the
		// well-known staging name and adding the intent afterwards leaves a window in which
		// that name holds a checksum-VALID, intent-FREE ledger — which is byte-for-byte the
		// state a COMPLETED phase 5 leaves, and which recovery therefore reads as "ready to
		// activate". A crash in that window, or merely a failure of the second write, would
		// hand the next invocation a ledger it activates WITHOUT HAVING CREATED, FILLED OR
		// VERIFIED A SINGLE VOLUME. The failure is not even hypothetical: a backup directory
		// whose canonical path is long enough that `source=<path>` exceeds the record format's
		// field bound makes the edit fail deterministically, every time, on an ordinary
		// operator path. Building the whole thing first and writing once closes it: the file
		// either does not exist or carries the intent.
		incoming, rerr := os.ReadFile(ledgercanon)
		if rerr != nil {
			d.warn("restore: cannot read the backup's ledger: %v", rerr)
			return fmt.Errorf("restore: cannot read the backup's ledger: %w", rerr)
		}
		l, verr := ledger.ReadBytes(incoming)
		if verr != nil {
			d.warn("restore: the incoming ledger does not validate — refusing to stage it: %v", verr)
			return fmt.Errorf("restore: the incoming ledger does not validate: %w", verr)
		}
		if perr := l.Put(restoreKind, "key", "restore", []ledger.Field{
			{Key: "key", Value: "restore"},
			{Key: "phase", Value: "2"},
			{Key: "source", Value: dir},
			{Key: "volumes", Value: ""},
		}); perr != nil {
			d.warn("restore: cannot record the restore intent — nothing has been staged: %v", perr)
			return fmt.Errorf("restore: cannot record the restore intent: %w", perr)
		}
		if werr := ledger.Write(d.Lock, staging, l); werr != nil {
			d.warn("restore: cannot stage the incoming ledger: %v", werr)
			return fmt.Errorf("restore: cannot stage the incoming ledger: %w", werr)
		}
	}

	// From here on, EVERY path (a fresh start and a resume) reads its source directory back OUT
	// OF THE STAGING LEDGER'S OWN INTENT RECORD, never re-trusts the raw operand a second time
	// — a resume is not handed a directory at all (the verb's dispatch does not even require
	// one), and using the CLI argument here rather than the recorded value would let a resume
	// silently read a DIFFERENT directory than the one phase 1 committed to.
	staged, err := ledger.Read(staging)
	if err != nil {
		d.warn("restore: the staging ledger does not validate: %v", err)
		return fmt.Errorf("restore: the staging ledger does not validate: %w", err)
	}
	irec, err := staged.Find(restoreKind, "key", "restore")
	if err != nil {
		d.warn("restore: the staging ledger carries no restore intent to resume.")
		return errors.New("restore: the staging ledger carries no restore intent to resume")
	}
	dir, ok := ledger.FieldOf(irec, "source")
	if !ok || dir == "" {
		d.warn("restore: the staging ledger's restore intent names no source directory.")
		return errors.New("restore: the staging ledger's restore intent names no source directory")
	}

	// RE-AUTHENTICATE THE BACKUP ROOT AT THE POINT OF USE, on EVERY entry INCLUDING RESUME.
	// Phase 1 checked this location, but a crash-and-resume can span an attacker making the
	// backup root group-writable and swapping its in-root data and manifest in between; the
	// fresh-restore path's own safety comes from this same check, so a resume must re-run it
	// now rather than trust the phase-1 result over the location's state at this instant. The
	// re-verified CANONICAL path is what every read and mount below uses.
	dir, err = d.safeDir(dir, "the backup directory being restored")
	if err != nil {
		return err
	}

	// The staging ledger's OWN installation identity — the original installation's, carried
	// faithfully by the backup — is what every volume this restore creates must be labelled
	// with. Read from the STAGED ledger, never from the machine's own (which answers for
	// whatever ACTIVE ledger it has — none, by construction, while a restore is in progress).
	ident, err := staged.IdentGet()
	if err != nil {
		d.warn("restore: the staging ledger's own installation identity cannot be read — refusing to")
		d.warn("  create volumes under an identity this process cannot establish: %v", err)
		return fmt.Errorf("restore: the staging ledger's installation identity cannot be read: %w", err)
	}

	ch := Chain{Lock: d.Lock, Store: staging, Index: d.Index}
	vols, err := d.volumeRecords(staged, "restore")
	if err != nil {
		return err
	}
	for _, v := range vols {
		if err := d.restoreVolume(ctx, ch, dir, ident, v); err != nil {
			return err
		}
	}

	// Phase 5: the intent-free rewrite, atomically. The staging ledger is RE-READ first — the
	// per-volume loop authenticates documents against it, and a trust-floor advance is a
	// ledger write like any other, so writing back the copy read before the loop would silently
	// discard whatever the loop recorded.
	final, err := ledger.Read(staging)
	if err != nil {
		d.warn("restore: the staging ledger does not validate: %v", err)
		return fmt.Errorf("restore: the staging ledger does not validate: %w", err)
	}
	if derr := final.Del(restoreKind, "key", "restore"); derr != nil {
		return derr
	}
	if werr := ledger.Write(d.Lock, staging, final); werr != nil {
		return werr
	}
	d.log("restore: every volume verified. The staging ledger is now intent-free and ready to activate.")

	// Phase 6.
	return Activate(d)
}

// restoreVolume runs phases 2 to 4 for one volume.
func (d Deps) restoreVolume(ctx context.Context, ch Chain, dir, ident string, v volumeRec) error {
	// Same authenticated-manifest resolution as the backup's own loop, and under the SAME
	// staging-ledger store as every other trust-chain read during a restore.
	ruid, err := d.runtimeUID(ch, v.product, v.name)
	if err != nil {
		return err
	}
	src := filepath.Join(dir, "volumes", v.name)
	// CANONICALIZED AT THE POINT OF USE, immediately before the fill/verify calls that trust
	// them — never checked once here and read via the raw path later.
	datacanon, err := d.canonUnder(src+".data", dir, fmt.Sprintf("the backup's contents for volume %q", v.name))
	if err != nil {
		return err
	}
	if fi, serr := os.Stat(datacanon); serr != nil || !fi.IsDir() {
		d.warn("restore: the backup has no contents directory for volume %q (or it is not a plain", v.name)
		d.warn("  directory).")
		return fmt.Errorf("restore: the backup has no contents directory for volume %q", v.name)
	}
	mancanon, err := d.canonUnder(src+".manifest", dir, fmt.Sprintf("the backup's manifest for volume %q", v.name))
	if err != nil {
		return err
	}
	if !regularFile(mancanon) {
		d.warn("restore: the backup has no per-entry manifest for volume %q.", v.name)
		d.warn("  A backup without one cannot support verified restore — this backup was not written by")
		d.warn("  a version that captures one.")
		return fmt.Errorf("restore: the backup has no per-entry manifest for volume %q", v.name)
	}

	// Phase 2, then RE-INSPECT.
	p, perr := engine.NewProvenance(ident, v.nonce)
	if perr != nil {
		d.warn("restore: cannot label volume %q under the recorded identity: %v", v.name, perr)
		return perr
	}
	if cerr := d.RT.VolumeCreate(ctx, v.name, p); cerr != nil {
		d.warn("restore: cannot create volume %q: %v", v.name, cerr)
		return fmt.Errorf("restore: cannot create volume %q: %w", v.name, cerr)
	}
	actual, lerr := d.Objs.Label(ctx, prov.ClassVolume, v.name, prov.LabelNonce)
	if lerr != nil && !errors.Is(lerr, engine.ErrAbsent) {
		// A DAEMON THAT COULD NOT BE ASKED IS NOT A VOLUME THAT IS ABSENT. Absence is an
		// answer this loop may act on (it lands in the mismatch branch below, naming
		// "<none>"); "could not ask" is not, and folding it in would fill or refuse on a
		// question nothing answered.
		d.warn("restore: could not verify volume %q — the container runtime did not answer. The", v.name)
		d.warn("  intent is retained so a re-run converges once the runtime is reachable.")
		return fmt.Errorf("restore: could not verify volume %q: %w", v.name, lerr)
	}
	if actual != v.nonce {
		d.warn("restore: a volume named %q already exists and does not carry the recorded nonce.", v.name)
		d.warn("    recorded: %s", v.nonce)
		d.warn("    found:    %s", orNone(actual))
		d.warn("  Refusing. 'volume create' against an existing name succeeds and does NOT apply the")
		d.warn("  new label, so this is a SURVIVOR, not the volume we just created — and the restore")
		d.warn("  never fills a volume it cannot prove it created.")
		return fmt.Errorf("restore: volume %q is a survivor, not the volume this restore created", v.name)
	}

	empty, eerr := d.volumeEmpty(ctx, ch, v.name)
	if eerr != nil {
		return eerr
	}
	if empty {
		// Phase 3: fill, via the pinned copy container — HOST BACKUP DATA (read-only) into the
		// VOLUME (writable). The reverse of the backup direction.
		ix, ierr := d.acceptIndex(ch)
		if ierr != nil {
			return ierr
		}
		if aerr := d.Copier.Available(ctx, ix); aerr != nil {
			return d.reported(aerr)
		}
		if ferr := d.Copier.Fill(ctx, ix, datacanon, v.name, ruid, d.OperatorUID); ferr != nil {
			return d.reported(ferr)
		}
		// Phase 4: against THE MANIFEST'S contract, not bytes alone.
		if verr := d.verify(ctx, ch, v.name, mancanon); verr != nil {
			return verr
		}
		d.log("restore: volume %s filled and verified against the backup's per-entry manifest.", v.name)
		return nil
	}
	// NOT EMPTY is not automatically a survivor to refuse: RESUME IS STATE-VERIFYING, NOT
	// PHASE-TRUSTING. Re-running these phases from the top on every resume — the simplest
	// correct thing to do, since phases 2-4 have no other durable per-volume marker — means a
	// crash while filling volume B, with volume A already filled and verified in this SAME
	// attempt, must find A non-empty and NOT treat that as a foreign survivor. The
	// distinguishing fact is whether it verifies against OUR manifest: if it does, this volume
	// is already done and the loop moves on; if it does not, it genuinely holds partial
	// contents from an interrupted fill (or is a real survivor), and there is no safe way to
	// tell those apart except refusing and pointing at abandonment.
	verr := d.verify(ctx, ch, v.name, mancanon)
	if verr == nil {
		d.log("restore: volume %s already filled and verified (resumed).", v.name)
		return nil
	}
	// A VERIFICATION THAT COULD NOT BE PERFORMED IS NOT A FINDING ABOUT THE DATA. Both outcomes
	// refuse and neither fills over anything, but only one of them may say what is in the volume —
	// and only one may recommend `restore --abandon`, which REMOVES volumes.
	if errors.Is(verr, errUnmeasured) {
		d.warn("restore: volume %q carries our nonce and is NOT EMPTY, and whether its contents match", v.name)
		d.warn("  the backup's manifest could not be established at all — the refusal above says why.")
		d.warn("  Refusing rather than filling over whatever is there blindly. This is NOT a finding")
		d.warn("  that the volume holds partial contents: nothing measured it. Resolve the reason above")
		d.warn("  and re-run; only if it then turns out to be a partial fill does abandoning the")
		d.warn("  restore ('restore --abandon') apply.")
		return fmt.Errorf("restore: volume %q is not empty and could not be verified against the backup's manifest: %w", v.name, errUnmeasured)
	}
	d.warn("restore: volume %q carries our nonce but is NOT EMPTY and does not verify against", v.name)
	d.warn("  the backup's manifest — it holds partial contents from an interrupted attempt.")
	d.warn("  Resuming would fill over them blindly. Abandon the restore ('restore --abandon') so")
	d.warn("  the partial volumes are removed under their recorded identity, then start again.")
	return fmt.Errorf("restore: volume %q holds partial contents from an interrupted attempt", v.name)
}

func orNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

// Activate is ONE atomic rename. Until this instant the machine has no active ledger claiming
// these volumes, so nothing can start the product on them.
func Activate(d Deps) error {
	if err := d.check(); err != nil {
		return err
	}
	staging, err := ledger.OpenStaging(d.Lock)
	if err != nil {
		return err
	}
	l, err := ledger.Read(staging)
	if err != nil {
		d.warn("restore: the staging ledger does not validate — refusing to activate it: %v", err)
		return fmt.Errorf("restore: the staging ledger does not validate: %w", err)
	}
	// FOUND = a live restore intent is still recorded (restore not finished) → refuse.
	// ABSENT = the intent is genuinely GONE (the restore cleared it) → the only case that may
	// activate. ANY OTHER ERROR = the intent read FAILED (ambiguous, unreadable) — FAIL
	// CLOSED, never fold a reader failure into "absent" and atomically activate a ledger that
	// may still record an unfinished restore.
	_, ferr := l.Find(restoreKind, "key", "restore")
	switch {
	case ferr == nil:
		d.warn("restore: the staging ledger still carries a live restore intent — refusing to activate.")
		d.warn("  Activating it would leave every later command meeting an in-progress restore that has")
		d.warn("  finished.")
		return errors.New("restore: the staging ledger still carries a live restore intent")
	case !errors.Is(ferr, ledger.ErrAbsentRecord):
		d.warn("restore: whether the staging ledger still carries a live restore intent could not be")
		d.warn("  established — the intent read failed. Refusing to activate rather than risk activating a")
		d.warn("  ledger that still records an unfinished restore: %v", ferr)
		return fmt.Errorf("restore: the restore-intent read failed: %w", ferr)
	}
	// THE PRESENCE TEST AND THE MOVE ARE ONE OPERATION, not a check followed by a rename. A
	// `[ -f ]` that answers "absent" about a dangling symlink, and a rename that REPLACES
	// whatever it lands on, together make phase 6 destroy a node the verb concluded was not
	// there — and a regular ledger that appears in the window between the two is destroyed the
	// same way, by a rename that was authorized by a fact that stopped being true. activateRename
	// is one atomic no-replace step: the kernel decides, once, and installs the ledger only onto
	// a name nothing occupies. See activate.go.
	lf := livePath(d.Home)
	rerr := activateRename(stagingPath(d.Home), lf)
	switch {
	case rerr == nil:
	case errors.Is(rerr, errActivatedWithResidue):
		// NEITHER SUCCESS NOR FAILURE, AND IT MUST NOT BE REPORTED AS EITHER. The ledger is at
		// the active name and the installation IS live; only the staging copy is left over.
		// Calling this "activation failed" would send an operator to re-run a restore that has
		// already happened.
		d.log("restore: activated. The installation is live again.")
		d.warn("%v", rerr)
		d.warn("  The installation IS restored and live — this is not a failed activation, and re-running")
		d.warn("  the restore is not what it needs. What is left is a copy of the now-active ledger at")
		d.warn("    %s", stagingPath(d.Home))
		d.warn("  REMOVE IT before any future restore. Nothing acts on it while an active ledger is")
		d.warn("  present, but it sits at the well-known staging name and it is checksum-valid and")
		d.warn("  intent-free — which is byte-for-byte the state a COMPLETED restore leaves. So on the")
		d.warn("  next machine state where there is no active ledger at all, which is the ONLY condition")
		d.warn("  a restore runs under, this stale copy is read as ready to activate and activated,")
		d.warn("  reinstating the state of this moment instead of the backup that was asked for.")
		return nil
	case errors.Is(rerr, fs.ErrExist):
		d.warn("restore: an active ledger appeared — refusing to overwrite it:")
		d.warn("    %s — %s", lf, whatIsAt(lf))
		d.warn("  Activation is an atomic no-replace move: it installs the restored ledger only onto a")
		d.warn("  name nothing occupies. Anything standing there — a live ledger, a dangling symlink, a")
		d.warn("  device node — is something this verb cannot prove is not a live installation's")
		d.warn("  provenance, so it is preserved and the staging ledger is kept.")
		return fmt.Errorf("restore: an active ledger appeared: %w", rerr)
	default:
		d.warn("restore: activation failed: %v", rerr)
		return fmt.Errorf("restore: activation failed: %w", rerr)
	}
	d.log("restore: activated. The installation is live again.")
	return nil
}

// ledgerPresence answers "is there a ledger at this well-known path", and REFUSES rather than
// answering when it cannot tell.
//
// fs.ErrNotExist IS THE ONLY ABSENCE. The reference's `[ -f "$p" ]` — os.Stat plus IsRegular —
// is false for four distinct facts: nothing is there, a DANGLING symlink is there, a FIFO or a
// directory is there, and the path could not be examined at all. Only the first is an absence,
// and the caller acts on absence by creating volumes, filling them, and moving a ledger onto
// that exact name. Reading the other three as an absence is therefore how this verb concludes a
// machine is empty and then writes over what is standing at the name it just declared free.
//
// Lstat, not Stat, is what makes a dangling symlink visible at all: Stat follows the link and
// answers ENOENT — byte-identical to "nothing is there" — for a link that plainly IS there.
//
// A SYMLINK TO A REAL LEDGER IS ALSO A REFUSAL, not an answer of "active". This installer never
// creates one, so its presence means something else put it there, and "follow it and treat what
// it points at as our ledger" is a decision this function has no basis to make. Refusing is the
// same posture internal/ledger's own reader already takes at the same paths.
func (d Deps) ledgerPresence(path, what string) (bool, error) {
	fi, err := os.Lstat(path)
	switch {
	case err == nil && fi.Mode().IsRegular():
		return true, nil
	case err == nil:
		d.warn("restore: %s is present but is not a regular file:", what)
		d.warn("    %s — %s", path, whatIsAt(path))
		d.warn("  Something is there, so this is not 'no ledger'. It is a state this verb cannot")
		d.warn("  classify, and every branch that follows from 'no ledger' creates volumes and ends by")
		d.warn("  installing a ledger at that exact name. Refusing rather than treating it as absent.")
		d.warn("  Run 'mythical-ctl state repair'.")
		return false, fmt.Errorf("restore: %s is present but is not a regular file: %s", what, path)
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		d.warn("restore: %s could not be examined, so absence cannot be established:", what)
		d.warn("    %s: %v", path, err)
		d.warn("  Refusing rather than reading a failed question as 'there is nothing here'.")
		return false, fmt.Errorf("restore: %s could not be examined (%s): %w", what, path, err)
	}
}

// whatIsAt names what is standing at a path, for a refusal that has already been decided. It is
// DIAGNOSIS ONLY — nothing branches on it — so its own failure is reported rather than being a
// second refusal.
func whatIsAt(p string) string {
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Sprintf("it could not be examined: %v", err)
	}
	m := fi.Mode()
	switch {
	case m.IsRegular():
		return "a regular file"
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		target, rerr := os.Readlink(p)
		if rerr != nil {
			return "a symlink"
		}
		if _, serr := os.Stat(p); errors.Is(serr, fs.ErrNotExist) {
			return fmt.Sprintf("a DANGLING symlink to %q", target)
		}
		return fmt.Sprintf("a symlink to %q", target)
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0:
		return "a device node"
	}
	return "of type " + m.Type().String()
}

// Abandon removes the volumes THIS restore created and then the staging ledger.
//
// ABANDONMENT CLEANS UP BEFORE DESTROYING ITS OWN AUTHORITY. The staging ledger is the only
// record proving which partial volumes the restore created — deleting it first leaves
// nonce-labelled, non-empty volumes that a restarted restore then meets as same-name survivors
// and REFUSES, with no authoritative record left to remove them: a wedge built from two
// correct rules.
func Abandon(ctx context.Context, d Deps) error {
	if err := d.check(); err != nil {
		return err
	}
	sf := stagingPath(d.Home)
	st, err := CurrentState(d)
	if err != nil {
		return err
	}
	switch st {
	case StateNone:
		d.warn("restore: there is no in-progress restore to abandon.")
		return errors.New("restore: there is no in-progress restore to abandon")
	case StateActive:
		d.warn("restore: this machine has an active ledger; there is no restore in progress.")
		return errors.New("restore: this machine has an active ledger; there is no restore in progress")
	case StateCorrupt:
		// THE SAME PRESERVE-ASIDE the restore path's own corrupt branch performs — one
		// behaviour for one fact, whichever verb the operator reached it through. Leaving the
		// corrupt file in place here while the other path moved it aside would mean the SAME
		// corrupt ledger is preserved as forensic evidence on one path and left sitting at the
		// well-known name on the other, for no reason tied to what actually happened.
		aside, residue, merr := preserveCorrupt(sf)
		if merr != nil {
			d.warn("restore: cannot preserve the corrupt staging ledger: %v", merr)
			return fmt.Errorf("restore: cannot preserve the corrupt staging ledger: %w", merr)
		}
		d.warn("restore: the staging ledger does not validate. It has been PRESERVED at %s.", aside)
		d.reportResidue(residue, sf)
		d.warn("  It authorizes no cleanup: the record of which partial volumes a previous attempt")
		d.warn("  created is exactly what the checksum says not to trust.")
		d.reportBlocking(ctx)
		return errors.New("restore: the staging ledger does not validate")
	}

	d.warn("restore: abandoning the in-progress restore.")
	d.warn("  Volumes this restore created — matching the EXACT name and nonce it recorded — are removed")
	d.warn("  first. Anything that does not match is preserved and reported.")
	if !d.Confirm("restore: abandon it?") {
		d.warn("restore: not confirmed.")
		return errors.New("restore: not confirmed")
	}

	staging, err := ledger.OpenStaging(d.Lock)
	if err != nil {
		return err
	}
	l, err := ledger.Read(staging)
	if err != nil {
		d.warn("restore: the staging ledger does not validate: %v", err)
		return fmt.Errorf("restore: the staging ledger does not validate: %w", err)
	}
	vols, err := d.volumeRecords(l, "restore")
	if err != nil {
		return err
	}
	failed := false
	for _, v := range vols {
		// ABSENT and "the daemon could not be asked" are NOT the same fact: absence means
		// nothing to remove; an unreachable daemon means this loop cannot tell whether the
		// volume is ours at all, and treating it as "gone" would silently skip a real one.
		actual, lerr := d.Objs.Label(ctx, prov.ClassVolume, v.name, prov.LabelNonce)
		if lerr != nil && !errors.Is(lerr, engine.ErrAbsent) {
			d.warn("  could not determine whether %q still carries our nonce — the container runtime", v.name)
			d.warn("  did not answer. Refusing to guess; the staging ledger is kept so a re-run can finish.")
			failed = true
			continue
		}
		if errors.Is(lerr, engine.ErrAbsent) {
			actual = ""
		}
		switch {
		case actual == v.nonce:
			// THE REMOVAL'S OWN STATUS IS CHECKED, NEVER MASKED. A volume this daemon refuses
			// to remove (still mounted by a container, most often) must not be reported as
			// removed — reporting success here is worse than a bare failure: an operator
			// reading "removed" has no reason to look again, while the volume and its record,
			// about to be destroyed below, are both still live.
			if rerr := d.RT.VolumeRemove(ctx, v.name); rerr != nil {
				d.warn("  COULD NOT remove partial volume %s (it may still be in use) — the staging ledger", v.name)
				d.warn("  is kept: deleting it while this volume is still labelled with our nonce would leave")
				d.warn("  it as an unrecorded survivor no future restore could prove is its own.")
				failed = true
				continue
			}
			d.log("  removed partial volume %s.", v.name)
		case actual != "":
			d.warn("  PRESERVED %s — it carries nonce %q, not the recorded %q.", v.name, actual, v.nonce)
		}
	}
	if failed {
		return errors.New("restore: abandonment did not complete — the staging ledger is kept")
	}
	if rerr := os.Remove(sf); rerr != nil {
		d.warn("restore: could not remove the staging ledger: %v", rerr)
		return fmt.Errorf("restore: could not remove the staging ledger: %w", rerr)
	}
	d.warn("restore: abandoned. The machine has no active and no staging ledger.")
	return nil
}

// preserveCorrupt moves the staging ledger aside under a name NOTHING ELSE OCCUPIES and returns
// where it went. It is EVIDENCE: a checksum that failed is a fact worth keeping, and nothing else
// in this package is allowed to delete it.
//
// A PID IS NOT A UNIQUE NAME, AND os.Rename REPLACES. Together those two made the preservation
// step destroy the very thing it exists to keep: PIDs are reused, and a single process reaching
// this twice (the restore verb and then `restore --abandon`, or two staging ledgers in one run)
// computes the SAME destination both times — so the second corruption silently overwrote the
// first, and the bytes that were preserved as forensic evidence were gone with no record that
// they had ever been there. "Evidence of a corruption destroyed by the next corruption" is the
// module's own answer-versus-refusal rule broken by its own cleanup step.
//
// So the move is the same ATOMIC NO-REPLACE primitive activation uses (see activate.go): the
// kernel decides, once, whether the destination is free, and installs the file only if it is.
// A destination that IS occupied comes back as fs.ErrExist — an ANSWER — and the next candidate
// name is tried. Nothing races between choosing a name and taking it, so two processes reaching
// here at the same instant cannot both win the same one.
//
// THE RESIDUE IS RETURNED, NOT SWALLOWED, and it is not a failure. On a filesystem whose
// no-replace rename is refused, activateRename falls back to link+unlink; if the link succeeds
// and the unlink does not, the evidence IS at `aside` and a copy also remains at the staging
// name. Reporting that as "cannot preserve" would tell an operator the bytes were lost when they
// were kept, and reporting it as plain success would leave a second copy at the well-known name
// unmentioned. Both callers say the two things separately.
func preserveCorrupt(sf string) (aside string, residue error, err error) {
	// THE VERDICT AND THE MOVE MUST BE ABOUT THE SAME BYTES. CurrentState judged the file some
	// instructions ago; this renames whatever occupies the path NOW. Between the two, a manual
	// restore, a scheduled job or another tool can put a VALID — or newer-schema — ledger there,
	// and it would then be moved aside and reported corrupt, which is precisely the destruction of
	// an intact record this whole classification exists to prevent, arriving by a different route.
	// The no-replace primitive below protects the DESTINATION; nothing about it protects the
	// identity of the source.
	//
	// So the bytes are re-read and re-judged HERE, immediately before the move, and only a file
	// that is corrupt AT THIS MOMENT is preserved. A file that now validates is left exactly where
	// it is and the caller is told it changed.
	//
	// THE RESIDUAL WINDOW IS REAL AND IS STATED RATHER THAN CLAIMED CLOSED: no filesystem offers
	// rename-if-contents-match, so a swap between this read and the rename below cannot be
	// excluded. What it buys is that the report is only ever made about bytes this function
	// actually read, and a swap that happens before the read is DETECTED instead of mis-reported.
	if data, rerr := os.ReadFile(sf); rerr != nil {
		return "", nil, fmt.Errorf("restore: the staging ledger could not be re-read before moving it aside, so\n"+
			"  whether the file about to be moved is the one that failed its checksum could not be\n"+
			"  established. Nothing is moved: %w", rerr)
	} else if _, verr := ledger.ReadBytes(data); !errors.Is(verr, ledger.ErrCorrupt) {
		return "", nil, fmt.Errorf("restore: the staging ledger no longer fails its checksum — it CHANGED between being\n" +
			"  classified and being moved aside. Nothing is moved and nothing is removed: this file is\n" +
			"  not the one that was judged, and moving it would destroy a record nobody found fault\n" +
			"  with. Run the command again to classify what is there now.")
	}
	// A BOUND, so a directory that somehow answers EEXIST forever cannot spin. 128 is far past
	// any real collision count: it takes 128 distinct preserved corruptions beside one staging
	// ledger, none of them ever cleaned up.
	const candidates = 128
	base := sf + ".corrupt." + strconv.Itoa(os.Getpid())
	for i := 0; i < candidates; i++ {
		to := base
		if i > 0 {
			to += "-" + strconv.Itoa(i)
		}
		merr := activateRename(sf, to)
		switch {
		case merr == nil:
			return to, nil, nil
		case errors.Is(merr, errActivatedWithResidue):
			// The move HAPPENED — `to` holds the corrupt bytes. Only the source could not be
			// unlinked, which is a leftover, not a lost file.
			return to, merr, nil
		case errors.Is(merr, fs.ErrExist):
			// AN ANSWER: that name is taken. Never retried through a replacing move — the whole
			// point is that an occupied name is left alone.
			continue
		default:
			return "", nil, merr
		}
	}
	return "", nil, fmt.Errorf("restore: %d preserved copies of a corrupt staging ledger already exist beside %s;\n"+
		"  refusing to overwrite any of them. Move or remove them and run this again", candidates, sf)
}

// reportResidue says the second half of a preservation that half-succeeded: the evidence IS at
// the aside name, and a copy is ALSO still at the staging name. It is deliberately not an error —
// the bytes were kept — but it must be SAID, because the leftover sits at the well-known staging
// name where the next run will meet it and preserve it all over again.
func (d Deps) reportResidue(residue error, sf string) {
	if residue == nil {
		return
	}
	d.warn("  A COPY ALSO REMAINS at %s — the move was made by linking and the original could not be", sf)
	d.warn("  unlinked: %v", residue)
	d.warn("  The evidence is safe at the preserved name; remove the leftover yourself.")
}

// reportBlocking names the volumes that may belong to an attempt whose record just failed its
// checksum. It cannot prove any of them is ours — the record that would have said so is the
// file that failed — so it NAMES them and stops.
func (d Deps) reportBlocking(ctx context.Context) {
	d.warn("restore: partial volumes that may belong to the abandoned attempt:")
	names, err := d.Objs.Names(ctx, prov.ClassVolume)
	if err != nil {
		d.warn("  (the container runtime could not be asked which volumes exist)")
	} else {
		for _, n := range names {
			if strings.HasPrefix(n, manifest.NamePrefix+"-") {
				d.warn("    volume %s", n)
			}
		}
	}
	d.warn("  The installer cannot prove these are its own — the record that would have said so is the")
	d.warn("  file whose checksum just failed. They BLOCK a fresh restore, and removing them is your")
	d.warn("  explicit call: remove them with the container runtime's own volume-removal command.")
}

// errUnmeasured marks a verification that COULD NOT BE PERFORMED, as distinct from one that ran
// and DISAGREED.
//
// THE DIFFERENCE DECIDES WHAT AN OPERATOR IS TOLD ABOUT THEIR DATA, and it is the
// answer-versus-refusal rule at its sharpest. A verifier that reported a `mismatch=` measured this
// volume and found it wrong. A copy image that could not be obtained, a manifest that could not be
// read, a helper that never launched, a transcript outside the grammar, a completion nobody
// claimed, a count that binds to nothing — none of those establish ANYTHING about the volume's
// contents. Reporting them as "it holds partial contents from an interrupted attempt" states a
// fact nothing measured, and it steers the operator to `restore --abandon`, which REMOVES volumes.
// Recommending a destructive recovery on an unestablished premise is the one outcome this module
// exists to prevent.
//
// Both still REFUSE, and neither fills over anything: refusing is correct either way. Only the
// words differ, and the words are the whole of what the operator acts on.
var errUnmeasured = errors.New("restore: the volume's contents could not be measured against the backup's manifest")

// volumeEmpty observes emptiness THROUGH the daemon — the host cannot read a named volume
// (D54). A count that cannot be obtained, or that is not a number, REFUSES rather than
// assuming: "assume empty" fills over survivors and "assume non-empty" wedges a fresh restore.
func (d Deps) volumeEmpty(ctx context.Context, ch Chain, vol string) (bool, error) {
	ix, ierr := d.acceptIndex(ch)
	if ierr != nil {
		return false, ierr
	}
	if err := d.Copier.Available(ctx, ix); err != nil {
		return false, d.reported(err)
	}
	t, err := d.Copier.Count(ctx, ix, vol)
	if err != nil || t.Code != 0 {
		d.warn("restore: cannot determine whether volume %q is empty — refusing rather than assuming.", vol)
		if err != nil {
			d.warn("  %v", err)
		}
		return false, fmt.Errorf("restore: cannot determine whether volume %q is empty", vol)
	}
	v, serr := d.stated(t.Text, "checked", "restore emptiness check", "the entry count")
	if serr != nil {
		return false, serr
	}
	if v == "0" {
		return true, nil
	}
	if !digitsOnly(v) {
		d.warn("restore: the emptiness check's count for %q is not a number (%q).", vol, v)
		return false, fmt.Errorf("restore: the emptiness check's count for %q is not a number", vol)
	}
	return false, nil
}

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// verify is phase 4: verification against the manifest's PER-ENTRY CONTRACT, never bytes
// alone. The manifest is handed to the helper on STDIN rather than mounted as a third host
// path.
//
// EVERY FAILING OBSERVATION IS COLLECTED BEFORE THE VERDICT. An early return on the first
// mismatch would name one entry and hide the rest, and an operator deciding whether to abandon
// a restore needs the whole picture.
func (d Deps) verify(ctx context.Context, ch Chain, vol, man string) error {
	ix, ierr := d.acceptIndex(ch)
	if ierr != nil {
		return fmt.Errorf("%w: %w", errUnmeasured, ierr)
	}
	if err := d.Copier.Available(ctx, ix); err != nil {
		return fmt.Errorf("%w: %w", errUnmeasured, d.reported(err))
	}
	fi, lerr := os.Lstat(man)
	if lerr != nil || !fi.Mode().IsRegular() {
		d.warn("restore: the manifest for volume %q is missing or not a plain file — refusing to", vol)
		d.warn("  verify without it.")
		return fmt.Errorf("restore: the manifest for volume %q is missing or not a plain file: %w", vol, errUnmeasured)
	}
	manifestBytes, rerr := os.ReadFile(man)
	if rerr != nil {
		d.warn("restore: could not read the manifest for volume %q: %v", vol, rerr)
		return fmt.Errorf("restore: could not read the manifest for volume %q (%v): %w", vol, rerr, errUnmeasured)
	}

	t, herr := d.Copier.Verify(ctx, ix, vol, manifestBytes)
	if herr != nil {
		// The helper could not be RUN. That is not an answer, so it is folded into the same
		// "did not complete" verdict below rather than being read as a pass.
		t = Transcript{Code: 1}
	}
	text := body(t.Text)
	if gerr := d.grammarOK(text, "mismatch", "checked", "done"); gerr != nil {
		return fmt.Errorf("%w: %w", errUnmeasured, gerr)
	}

	// `bad` is "this verification did not pass"; `mismatched` is the narrower "the verifier
	// MEASURED this volume against this manifest and they disagree". Every other refusal below
	// leaves the second false, because none of them establishes anything about the contents — see
	// errUnmeasured.
	bad, mismatched := false, false
	for _, v := range fields(text, "mismatch") {
		if v == "" {
			continue
		}
		d.warn("restore: VERIFICATION MISMATCH in %s: %s", vol, v)
		d.warn("  The manifest authenticates type, link targets, hardlink topology, mode, ownership and")
		d.warn("  mtime — not bytes alone. A symlink re-created as a file has no bytes to mismatch, and")
		d.warn("  flattened hardlinks digest identically.")
		bad, mismatched = true, true
	}
	if hasKey(text, "mismatch") && !bad {
		d.warn("restore: the verifier reported a mismatch that names nothing — treated as a mismatch.")
		bad, mismatched = true, true
	}
	if t.Code != 0 && !bad {
		d.warn("restore: verification of volume %q did not complete.", vol)
		bad = true
	}

	doneval, derr := d.stated(text, "done", "restore verification", "completion")
	if derr != nil {
		bad = true
	}
	if !bad && doneval != "ok" {
		d.warn("restore: the verifier for %q reported 'done=%s' rather than completion.", vol, orEmpty(doneval))
		bad = true
	}

	// THE COUNT BINDS VERIFICATION TO THE MANIFEST ITSELF: a verifier that "checked" fewer (or
	// more) entries than the manifest actually names cannot be trusted as a verification of
	// THAT manifest. An empty manifest is legal, so zero is a real count; a manifest that could
	// not be counted at all is not, and refuses rather than binding to a number this process
	// never established.
	mcount := 0
	for _, line := range strings.Split(string(manifestBytes), "\n") {
		if strings.HasPrefix(line, "manifest=") {
			mcount++
		}
	}
	// The three arms below OVERLAP DELIBERATELY, and the overlap is measured: an absent
	// `checked=` is refused by the count comparison on its own, so removing this arm alone
	// changes nothing observable (a mutation of it survives; removing the whole binding
	// reddens the named test). It is kept because the three say different things — this one
	// says the observation was never made, the numeric arm says it is not a count, and the
	// comparison says it is the wrong count — and an operator meeting a verification failure
	// on a restore needs to be told which.
	checkedval, cerr := d.stated(text, "checked", "restore verification", "the checked count")
	if cerr != nil {
		bad = true
	}
	if !bad {
		switch {
		case checkedval == strconv.Itoa(mcount):
		case !digitsOnly(checkedval):
			d.warn("restore: the verifier's checked count for %q is not a number (%q).", vol, checkedval)
			bad = true
		default:
			d.warn("restore: the verifier for %q checked %s entries, but the manifest names", vol, checkedval)
			d.warn("  %d. A count that does not match the manifest cannot bind verification to it —", mcount)
			d.warn("  refusing rather than trusting a partial or padded check.")
			bad = true
		}
	}

	if bad {
		if !mismatched {
			return fmt.Errorf("restore: volume %q could not be verified against the backup's per-entry manifest: %w", vol, errUnmeasured)
		}
		return fmt.Errorf("restore: volume %q did not verify against the backup's per-entry manifest", vol)
	}
	return nil
}
