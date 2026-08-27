package backup

import (
	"context"
	"errors"
	"fmt"
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
	// StateCorrupt — a staging ledger that does not validate. It authorizes nothing.
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
func CurrentState(d Deps) (State, error) {
	if err := d.check(); err != nil {
		return "", err
	}
	if regularFile(livePath(d.Home)) {
		return StateActive, nil
	}
	if !regularFile(stagingPath(d.Home)) {
		return StateNone, nil
	}
	st, err := ledger.OpenStaging(d.Lock)
	if err != nil {
		return "", err
	}
	l, err := ledger.Read(st)
	if err != nil {
		return StateCorrupt, nil
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
		aside, merr := preserveCorrupt(sf)
		if merr != nil {
			d.warn("restore: cannot preserve the corrupt staging ledger: %v", merr)
			return fmt.Errorf("restore: cannot preserve the corrupt staging ledger: %w", merr)
		}
		d.warn("restore: the staging ledger does not validate. It has been PRESERVED at %s.", aside)
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
	if verr := d.verify(ctx, ch, v.name, mancanon); verr == nil {
		d.log("restore: volume %s already filled and verified (resumed).", v.name)
		return nil
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
	lf := livePath(d.Home)
	if regularFile(lf) {
		d.warn("restore: an active ledger appeared — refusing to overwrite it")
		return errors.New("restore: an active ledger appeared")
	}
	if rerr := os.Rename(stagingPath(d.Home), lf); rerr != nil {
		d.warn("restore: activation failed: %v", rerr)
		return fmt.Errorf("restore: activation failed: %w", rerr)
	}
	d.log("restore: activated. The installation is live again.")
	return nil
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
		aside, merr := preserveCorrupt(sf)
		if merr != nil {
			d.warn("restore: cannot preserve the corrupt staging ledger: %v", merr)
			return fmt.Errorf("restore: cannot preserve the corrupt staging ledger: %w", merr)
		}
		d.warn("restore: the staging ledger does not validate. It has been PRESERVED at %s.", aside)
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

// preserveCorrupt moves the staging ledger aside under a name unique to this process and
// returns where it went. It is EVIDENCE: a checksum that failed is a fact worth keeping, and
// nothing else in this package is allowed to delete it.
func preserveCorrupt(sf string) (string, error) {
	aside := sf + ".corrupt." + strconv.Itoa(os.Getpid())
	if err := os.Rename(sf, aside); err != nil {
		return "", err
	}
	return aside, nil
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
		return ierr
	}
	if err := d.Copier.Available(ctx, ix); err != nil {
		return d.reported(err)
	}
	fi, lerr := os.Lstat(man)
	if lerr != nil || !fi.Mode().IsRegular() {
		d.warn("restore: the manifest for volume %q is missing or not a plain file — refusing to", vol)
		d.warn("  verify without it.")
		return fmt.Errorf("restore: the manifest for volume %q is missing or not a plain file", vol)
	}
	manifestBytes, rerr := os.ReadFile(man)
	if rerr != nil {
		d.warn("restore: could not read the manifest for volume %q: %v", vol, rerr)
		return fmt.Errorf("restore: could not read the manifest for volume %q: %w", vol, rerr)
	}

	t, herr := d.Copier.Verify(ctx, ix, vol, manifestBytes)
	if herr != nil {
		// The helper could not be RUN. That is not an answer, so it is folded into the same
		// "did not complete" verdict below rather than being read as a pass.
		t = Transcript{Code: 1}
	}
	text := body(t.Text)
	if gerr := d.grammarOK(text, "mismatch", "checked", "done"); gerr != nil {
		return gerr
	}

	bad := false
	for _, v := range fields(text, "mismatch") {
		if v == "" {
			continue
		}
		d.warn("restore: VERIFICATION MISMATCH in %s: %s", vol, v)
		d.warn("  The manifest authenticates type, link targets, hardlink topology, mode, ownership and")
		d.warn("  mtime — not bytes alone. A symlink re-created as a file has no bytes to mismatch, and")
		d.warn("  flattened hardlinks digest identically.")
		bad = true
	}
	if hasKey(text, "mismatch") && !bad {
		d.warn("restore: the verifier reported a mismatch that names nothing — treated as a mismatch.")
		bad = true
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
		return fmt.Errorf("restore: volume %q did not verify against the backup's per-entry manifest", vol)
	}
	return nil
}
