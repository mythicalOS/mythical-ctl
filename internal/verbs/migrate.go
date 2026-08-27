package verbs

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/bringup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/copyfill"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/migrate"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// migrate-storage's runtime wiring.
//
// THE PHASE MACHINE IS internal/migrate AND NOTHING HERE REPEATS IT. That package deliberately
// takes its copy helper and its container rebuild as SEAMS, because a package that imported the
// copy module would become a second definition of the escape rule and one that imported the
// bring-up would become a second launch site. What was missing was the layer that holds every
// seam at once — the lock, the store, the ledger, the authenticated documents, the runtime facade
// and the bring-up sequence — and that layer is this one. It is why the verb lives here rather
// than in the dispatcher: assembling it from `cmd` would mean rebuilding openSession's whole
// preamble beside it, and two preambles is one that drifts.
//
// EVERY SEAM BELOW NAMES THE LEDGER IT ACTS ON. The phase machine holds one ledger for the whole
// verb and hands it back through each seam call; a seam that reached for the session's own field
// instead would be acting on a different object the moment those two ever diverged — and the
// phase machine's write-ahead discipline is exactly what makes them diverge (it persists a CLONE
// and adopts it back). See netTargetOn, launchOn and reconcileOn for the same rule one level down.

// MigrateStorage moves one product role's storage from its named volume to a host directory.
//
// THE ARITY AND THE OPTION MATRIX ARE THE DISPATCHER'S, not this function's — a malformed
// invocation must be refused before a lock is taken or a daemon is spoken to, and the dispatcher
// is the only layer that can see what the operator actually typed. What is checked HERE is what
// remains true of any caller: a product and a role must both be named.
func MigrateStorage(ctx context.Context, d Deps, product, role string, o migrate.Options) int {
	if product == "" || role == "" {
		d.warn("verbs: migrate-storage needs a product and a role")
		return cliio.ExitUsage
	}
	if rc := daemonReady(ctx, d); rc != cliio.ExitOK {
		return rc
	}
	s, err := openSession(d)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	defer s.close()
	return s.migrateStorage(ctx, product, role, o)
}

func (s *session) migrateStorage(ctx context.Context, product, role string, o migrate.Options) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// THE FAMILY INDEX, AUTHENTICATED, IS WHAT NAMES THE COPY IMAGE. It is CHECKED rather than
	// ACCEPTED here: accepting is the door that records a trust anchor on first use, and a machine
	// with no anchor has nothing to migrate — there is no installation. A check against the
	// recorded anchor is the right question for a verb that only ever runs on an existing one, and
	// the manifest and policy acceptances (which DO advance floors) happen through the documents
	// seam, at every phase, exactly as the reference re-accepts them.
	ix, ierr := trust.CheckIndex(s.st, d.IndexPath)
	if ierr != nil {
		d.warnErr(ierr)
		return cliio.ExitFail
	}
	ident, iderr := s.l.IdentGet()
	if iderr != nil {
		d.warn("verbs: no installation identity — has anything been installed?")
		d.warnErr(iderr)
		return cliio.ExitFail
	}
	cop, cerr := s.copySeam(ix, ident)
	if cerr != nil {
		d.warnErr(cerr)
		return cliio.ExitFail
	}
	md := migrate.Deps{
		Lock:   s.h,
		Docs:   sessionDocs{s: s},
		Objs:   migrateObjects{c: d.Engine},
		Mut:    s.rt,
		Prov:   prov.Engine(d.Engine),
		State:  state.Engine(d.Engine),
		Copy:   cop,
		Build:  &rebuilder{s: s, product: product},
		Mounts: migrate.SystemMounts{},
		// THE CONFIRMATION IS THE SESSION'S OWN SEAM, so a front-end that answers through an
		// overlay and the plain terminal path cannot disagree about what "yes" means.
		Confirm:  d.ask,
		Persist:  s.persistFn(),
		Entries:  &migrate.EntryCount{},
		Log:      d.out(),
		Warn:     d.errw(),
		NewNonce: intent.NonceNew,
	}
	if err := migrate.MigrateStorage(ctx, s.l, md, product, role, o); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	return cliio.ExitOK
}

// copySeam builds the copy helper for this migration and adapts it to the phase machine's seam.
func (s *session) copySeam(ix *trust.Index, ident string) (migrate.Copier, error) {
	c, err := copyfill.New(s.rt, ident, intent.NonceNew)
	if err != nil {
		return nil, err
	}
	if err := c.SetOutput(s.d.out()); err != nil {
		return nil, err
	}
	if err := c.SetDiagnostics(s.d.errw()); err != nil {
		return nil, err
	}
	return migrateCopier{c: c, ix: ix}, nil
}

// --- the copy seam ------------------------------------------------------------------------------

// migrateCopier satisfies migrate.Copier over internal/copyfill.
//
// IT CARRIES THE AUTHENTICATED INDEX, and that is the whole reason the seam's own methods do not
// take one. The copy image is read from the family index and nowhere else — an index that merely
// PARSED cannot reach the copier, because *trust.Index is constructible only by the acceptors —
// so the question "which image is about to be handed every byte of this product's data with a
// writable mount" is answered once, at the point the index was authenticated, rather than at each
// of the six call sites.
//
// THE ESCAPE RULE IS FORWARDED, NEVER RESTATED. LinkEscapes is the copy module's own, already
// validated definition of "this symlink target leaves the tree"; the migration reaches it through
// this seam precisely so that package never grows a second one, and two spellings of that rule is
// how one of them stops matching.
type migrateCopier struct {
	c  *copyfill.Copier
	ix *trust.Index
}

func (m migrateCopier) LinkEscapes(linkPath, target, root string) bool {
	return copyfill.LinkEscapes(linkPath, target, root)
}

func (m migrateCopier) Available(ctx context.Context) error {
	return m.c.Available(ctx, m.ix)
}

func (m migrateCopier) Preflight(ctx context.Context, staging, runtimeUID, operatorUID string) error {
	return m.c.Preflight(ctx, m.ix, staging, runtimeUID, operatorUID)
}

func (m migrateCopier) Run(ctx context.Context, srcVolume, staging, runtimeUID, operatorUID string, mapForeign bool) (int, error) {
	return m.c.Run(ctx, m.ix, srcVolume, staging, runtimeUID, operatorUID,
		copyfill.Options{MapForeignToOperator: mapForeign})
}

func (m migrateCopier) Verify(ctx context.Context, srcVolume, staging string, entries int, runtimeUID, operatorUID string) error {
	return m.c.Verify(ctx, m.ix, srcVolume, staging, entries, runtimeUID, operatorUID)
}

func (m migrateCopier) HostAccessCheck(staging string) error {
	return copyfill.HostAccessCheck(staging)
}

func (m migrateCopier) AccessCheck(ctx context.Context, staging, runtimeUID string) error {
	return m.c.AccessCheck(ctx, m.ix, staging, runtimeUID)
}

// --- the document seam --------------------------------------------------------------------------

// sessionDocs satisfies migrate.Documents.
//
// ACCEPTING A DOCUMENT ADVANCES THE ANTI-ROLLBACK TRUST FLOOR, and that advance is a write to the
// ledger FILE performed by the acceptor itself, which takes the lock token rather than a ledger.
// So the session's in-memory copy is stale the instant either call returns, and it is re-read IN
// PLACE — the phase machine is mid-sequence with that very ledger in hand, so a re-read that
// published a replacement would leave it editing an object nothing will persist.
//
// A FAILED RE-READ POISONS THE SESSION rather than being swallowed: from that point the copy is no
// longer known to contain everything on disk, and persisting it could erase the floor that was
// just recorded. adoptDisk sets that state; every later write refuses.
type sessionDocs struct{ s *session }

func (sd sessionDocs) AcceptManifest(product string) (*manifest.Manifest, error) {
	m, err := trust.AcceptManifest(sd.s.h, sd.s.st, sd.s.d.IndexPath, sd.s.d.PolicyPath,
		sd.s.manifestPath(product), product)
	if aerr := sd.s.adoptDisk(); aerr != nil {
		return nil, errors.Join(err, aerr)
	}
	return m, err
}

func (sd sessionDocs) AcceptPolicy() (*policy.Policy, error) {
	p, err := trust.AcceptPolicy(sd.s.h, sd.s.st, sd.s.d.IndexPath, sd.s.d.PolicyPath)
	if aerr := sd.s.adoptDisk(); aerr != nil {
		return nil, errors.Join(err, aerr)
	}
	return p, err
}

// --- the runtime read seam ----------------------------------------------------------------------

// migrateObjects answers what a container ACTUALLY mounts. engine.ErrAbsent passes through
// untouched: "the container is gone" and "the question could not be asked" are different facts and
// the phase that consults this acts on the difference.
type migrateObjects struct{ c *engine.Client }

func (m migrateObjects) ContainerMounts(ctx context.Context, container string) ([]engine.MountRecord, error) {
	info, err := m.c.ContainerInspect(ctx, container)
	if err != nil {
		return nil, err
	}
	return info.Mounts, nil
}

// --- the rebuild seam ---------------------------------------------------------------------------

// rebuilder satisfies migrate.Rebuilder over the ordinary product bring-up.
//
// IT IS SPLIT IN TWO BECAUSE THE ORDER IS A SAFETY PROPERTY, and this is the half that has to
// honour it. Docker mounts are fixed at creation, so "switch the mount" is not an operation and
// the container must be rebuilt — but the rebuild's irreversible step is removing the old
// container, and everything that can fail while working out WHAT to build has to happen before
// it. Prepare therefore does the whole of that work (resolve the network, settle which image,
// make it present, create the mount points, assemble the launch and DRY-RUN it through the same
// assembler the create uses) and hands back something whose remaining step cannot meaningfully
// fail for a reason that was knowable earlier. A single Rebuild call could not express that: it
// would necessarily resolve after the removal, and a launch spec that could not be built would
// leave the product with no container at all.
type rebuilder struct {
	s       *session
	product string
}

func (r *rebuilder) NetTarget(ctx context.Context, l *ledger.Ledger) (string, error) {
	return r.s.netTargetOn(ctx, l)
}

func (r *rebuilder) Reconcile(ctx context.Context, l *ledger.Ledger, container, netID string) error {
	alias, err := manifest.Alias(r.product)
	if err != nil {
		return err
	}
	return r.s.reconcileOn(ctx, l, container, netID, alias)
}

// Prepare resolves and renders EVERYTHING the replacement needs, and creates nothing.
func (r *rebuilder) Prepare(ctx context.Context, l *ledger.Ledger, product, container, netID string) (migrate.Replacement, error) {
	// THE PRODUCT IS RE-STATED BY THE CALLER AND CHECKED AGAINST THE ONE THIS SEAM WAS BUILT FOR.
	// The seam's other method takes no product at all (it derives the alias from this field), so a
	// caller preparing one product through a rebuilder bound to another would reconcile the wrong
	// container under the right name. A mismatch preserves: nothing is prepared.
	if product != r.product {
		return nil, fmt.Errorf("verbs: asked to prepare a replacement for %q through the rebuild seam of %q.\n"+
			"  Refusing rather than building one product's container and settling another's.", product, r.product)
	}
	s := r.s
	pc, cerr := s.productCtx(product, s.manifestPath(product))
	if cerr != nil {
		return nil, cerr
	}
	if pc.Container != container {
		return nil, fmt.Errorf("verbs: the migration names container %q, but %q's recorded identity derives\n"+
			"  %q. Refusing rather than replacing a container this installation does not own.",
			container, product, pc.Container)
	}
	// THE RECORDED DESIRED STATE MUST BE READABLE, AND THAT IS ESTABLISHED HERE.
	//
	// The create PRESERVES it rather than expressing one — a migration must not decide for the
	// operator what their product should be doing — but "preserve" REFUSES when there is nothing
	// recorded to preserve, and refuses again when the record cannot be read. Left to the create,
	// that refusal fires past phase 7's removal and tombstone, over a fact that was fully knowable
	// while the old container was still standing: the product ends up with no container because of
	// a ledger row, which is the exact shape this seam is split in two to eliminate. (The phase
	// machine's own phase 1 tolerates an absent row and defaults its RECORD to running, so this is
	// reachable rather than theoretical.)
	//
	// IT DOES NOT DECIDE ANYTHING. The value is not read out, carried, or substituted — asking
	// here and preserving there is the same question asked earlier, not a second answer, and the
	// row cannot move in between: one lock, one process, and phase 7 writes only the tombstone.
	// Passing the migration record's own remembered state instead would make the migration express
	// an intent, which is precisely what the seam's shape forbids.
	if _, derr := state.DesiredGet(l, container); derr != nil {
		return nil, fmt.Errorf("verbs: the recorded desired state for %q could not be read, so a replacement cannot\n"+
			"  preserve it — and this migration must not decide for you what %q should be doing.\n"+
			"  Nothing was removed; the old container is still there and the migration stays at\n"+
			"  phase 7. Run 'mythical-ctl state repair': %w", container, product, derr)
	}
	image, ierr := r.image(l, pc)
	if ierr != nil {
		return nil, ierr
	}
	// The image must be present BEFORE the old container is removed — a manifest that advanced to
	// an unpulled image, or an unreachable registry, must fail here with the working container
	// intact rather than after it has been torn down and cannot be rebuilt.
	if err := s.ensureImage(ctx, image, product); err != nil {
		return nil, err
	}
	// A migration that follows a manual deletion of transcripts/ or logs/ must re-create them
	// rather than refuse at the create, when the old container is already gone.
	if err := ensureMountPoints(s.d.Home); err != nil {
		return nil, err
	}
	// ASSEMBLED ONCE AND CARRIED, never re-derived either side of the teardown: the dry run and the
	// real create must be judging the same launch, and re-reading mythical.conf for the second one
	// would let them disagree about which host port to publish.
	cfg, cfgErr := s.launchConfig(pc, image, netID)
	if cfgErr != nil {
		return nil, cfgErr
	}
	if err := s.checkLaunchable(pc, cfg); err != nil {
		return nil, err
	}
	// THE BRING-UP DEPENDENCIES ARE BUILT HERE TOO, and this is not tidiness. Assembling them is
	// fallible in its own right — the probe accounting opens the ledger store, the probe arm
	// validates the installation identity and its diagnostics writer — and every one of those
	// failures has nothing whatever to do with the container being replaced. Left to the create,
	// they would fire AFTER the old container is gone and leave the product with none, for a
	// reason that was fully knowable while it was still standing. (Codex gate round 3.)
	bd, berr := s.bringupDeps(pc.Index, cfg.Identity)
	if berr != nil {
		return nil, berr
	}
	// AND SO IS THE REPLACEMENT'S OWN NONCE. Minting one is fallible — it reads the system's
	// entropy source — and leaving it to the create makes it the LAST fallible step, on the far
	// side of the removal, which is precisely the shape the rest of this function exists to
	// eliminate. The bring-up mints exactly one per run (the write-ahead intent's, recorded ahead
	// of the container that carries it), so pre-minting hands it the same value at the same
	// moment, decided earlier. (Codex gate round 4.)
	nonce, nerr := intent.NonceNew()
	if nerr != nil {
		return nil, fmt.Errorf("verbs: the replacement container's nonce could not be minted, so nothing was\n"+
			"  removed — the old container is still there and the migration stays at phase 7: %w", nerr)
	}
	bd.NewNonce = func() (string, error) { return nonce, nil }
	return &replacement{s: s, pc: pc, cfg: cfg, bd: bd, nonce: nonce}, nil
}

// image settles WHICH image the replacement runs.
//
// A RECORDED IMAGE OVERRIDE IS PRESERVED, and this is a deliberate divergence from the frozen
// reference, which reads the manifest's image unconditionally. install may have been given
// `--image X`, which it recorded and which `status` reports as the running image; reverting to the
// manifest's image here would move the product's storage AND silently change what it runs — and if
// the manifest's image was never pulled, it would fail this preparation for a product that was
// working, on a machine where nothing was wrong. recreate, the sibling verb that rebuilds a
// container for its own reasons, already preserves the override for exactly these two reasons.
func (r *rebuilder) image(l *ledger.Ledger, pc *productContext) (string, error) {
	ov, err := l.Find(kindForced, "key", pc.Product+":image-override")
	switch {
	case err == nil:
		ref, ok := ledger.FieldOf(ov, "ref")
		if !ok || ref == "" {
			return "", fmt.Errorf("verbs: the recorded image override for %q names no reference", pc.Product)
		}
		r.s.d.warn("verbs: image override preserved — %q runs %q (recorded at install), not the", pc.Product, ref)
		r.s.d.warn("  manifest's image. migrate-storage does not change the image install selected.")
		return ref, nil
	case errors.Is(err, ledger.ErrAbsentRecord):
		return pc.Image, nil
	default:
		return "", fmt.Errorf("verbs: could not read the image-override record for %q from the ledger, so which\n"+
			"  image the replacement should run cannot be established. Nothing is removed: %w", pc.Product, err)
	}
}

// replacement is one prepared container, ready to be created once the old one is actually gone.
type replacement struct {
	s   *session
	pc  *productContext
	cfg runtime.LaunchConfig
	// bd is the bring-up sequence's dependencies, ASSEMBLED IN Prepare — see the note there.
	bd bringup.Deps
	// nonce is the replacement's own, MINTED IN Prepare for the same reason, and the value bd's
	// mint hands back.
	nonce     string
	discarded bool
}

// Create builds it, PRESERVING the recorded desired state. `preserve` is not a parameter because
// the migration must not express intent: the replacement reads the desired state already recorded,
// so a migration of a stopped product leaves it stopped.
func (rp *replacement) Create(ctx context.Context, l *ledger.Ledger) error {
	// A DISCARDED REPLACEMENT IS SPENT. Discard is the phase's release path and runs on every way
	// out; creating from one afterwards would be building from something whose preparation has
	// already been given up on, and on the day this holds a real resource it would be building from
	// one that has been freed.
	if rp.discarded {
		return errors.New("verbs: this replacement has been discarded and cannot be created. Nothing is built.")
	}
	return rp.s.launchWith(ctx, l, rp.bd, rp.pc, rp.cfg, bringup.Preserve)
}

// Discard releases what Prepare rendered.
//
// WHAT IT HOLDS TODAY IS NOTHING ON DISK, and that is a property of this tree rather than an
// oversight. The reference had to render the product's bootstrap secrets into a host env file
// before the create and remove it on every branch out of the phase; here the secrets are assembled
// INSIDE the runtime facade, in memory, at the create itself — no secret value leaves that package
// and no file is written — so a prepared replacement is a plan and two authenticated documents.
// The method is not therefore a no-op: it MARKS the replacement spent, so that the contract the
// phase machine relies on ("released on every path out, built or abandoned") has an observable
// effect and a test that can fail. When something here does acquire a resource, this is where it
// is released, and the ordering is already correct.
func (rp *replacement) Discard() { rp.discarded = true }
