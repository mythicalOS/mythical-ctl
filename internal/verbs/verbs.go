package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"mythicalos.ai/ctl/internal/bringup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/preflight"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// kindForced is the ledger record kind the two install-time annotations share: the image override
// and the force-install marker. Both are written AFTER bring-up succeeds and cleared otherwise.
const kindForced = "forced"

// InstallOpts is install's own option set — the reference's `[--image REF] [--force-install]`.
//
// ImageSet IS SEPARATE FROM Image on purpose: the reference's library-level option loop
// distinguishes three states — no --image, --image with a reference, and --image with NOTHING after
// it — and the third is the verb's OWN usage error, not something to fold into the caller's control
// flow. A lone `Image string` can only express two of the three, and the state it loses is exactly
// the one that must be refused.
type InstallOpts struct {
	Product string
	// Image is the --image override. It applies to install ONLY, and to exactly one product.
	Image string
	// ImageSet reports that --image was given at all. Set with an empty Image is the value-less
	// form: a usage error, at once.
	ImageSet bool
	// Force is --force-install: install a product whose manifest says it has not launched.
	Force bool
}

// --- install (desired state: running) ---------------------------------------------------------

// Install converges one product: identity, membership, network, volumes, container, running,
// verified. It returns the exit code.
//
// INSTALL ALWAYS DECLARES `running`. install EXPRESSES intent, it never inherits a prior
// generation's — preserving is recreate's job alone. So a previously-installed container is
// REPLACED, but the desired state it is rebuilt into stays `running`, never the `stopped` a prior
// stop may have left behind.
func Install(ctx context.Context, d Deps, opts InstallOpts) int {
	if opts.Product == "" {
		d.warn("verbs: install needs a product")
		return cliio.ExitUsage
	}
	// THE LIBRARY REFUSES ITS OWN VALUE-LESS OPTION, and it does so before anything else: a caller
	// reaching this package directly has no entrypoint parser in front of it, and a missing value
	// is this verb's usage error (2), never an operational failure.
	if opts.ImageSet && opts.Image == "" {
		d.warn("verbs: install option '--image' requires a value")
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
	return s.install(ctx, opts)
}

func (s *session) install(ctx context.Context, opts InstallOpts) int {
	d := s.d
	product := opts.Product

	if err := layout.Ensure(d.Home); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// "No ledger" is only first use when nothing else is there either; an inconsistent home
	// (a half-restored ledger path, objects with no ledger) refuses.
	if err := prov.FirstUse(ctx, d.Home, prov.Engine(d.Engine)); err != nil && !errors.Is(err, prov.ErrNotFirstUse) {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.probeCleanup(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// THE UNACCOUNTED-OBJECT GATE RUNS BEFORE ANY AUTHENTICATED-STATE WRITE. productCtx below
	// advances the manifest's anti-rollback trust floor — an enumerated exempt side effect — so
	// running the gate AFTER it let a refused install (a stray same-identity object) still advance
	// the floor, permanently blocking a rollback for an install that was never allowed.
	if err := intent.UnaccountedGate(ctx, s.l, s.objs); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	pc, cerr := s.productCtx(product, s.manifestPath(product))
	notLaunched := errors.Is(cerr, trust.ErrNotLaunched)
	if cerr != nil && !notLaunched {
		d.warnErr(cerr)
		return cliio.ExitFail
	}
	if notLaunched {
		if !opts.Force {
			// The enumerated exempt side effects, and NOTHING else: the trust floor for the
			// manifest that was read has ALREADY been recorded, before the launch-state branch, so
			// a withdrawn `launched` manifest cannot be replayed later against a machine that never
			// established one. No identity, no membership, no pull, no object.
			d.say("not-launched", "%s has not launched yet.", product)
			d.say("not-launched", "  Its manifest declares it unpublished, so no pull was attempted and nothing was created.")
			d.say("not-launched", "  Nothing is wrong — this product is not available yet.")
			return cliio.ExitNotLaunched
		}
		d.warn("verbs: FORCED install of %q, whose manifest says it has not launched.", product)
		d.warn("  You are asserting the image is published. It is reported by 'status' once the install")
		d.warn("  succeeds — the force-install record, like the image-override record, is written AFTER")
		d.warn("  bring-up, so a forced install that fails leaves no false annotation behind.")
		// A forced install IS a real install — it pulls and creates a container — so it legitimately
		// establishes the installation identity here. This is the ONE not-launched path that may
		// mint one, and only on the operator's explicit override.
		if err := s.mintIdentity(pc); err != nil {
			d.warnErr(err)
			return cliio.ExitFail
		}
	}

	image := pc.Image
	if opts.ImageSet {
		// An override may name ANY reference, including a local build. Loud, and reported by status.
		// The override LEDGER record is written AFTER bring-up succeeds, not here — a record written
		// before the install completes would survive a failed --image install and be applied by a
		// later recreate.
		d.warn("verbs: IMAGE OVERRIDE — %q will run %q instead of the manifest's image.", product, opts.Image)
		d.warn("  The manifest's digest pin does not apply to an overridden reference. It is reported by")
		d.warn("  'status' once the install succeeds.")
		image = opts.Image
	}

	netID, nerr := s.netTarget(ctx)
	if nerr != nil {
		d.warnErr(nerr)
		return cliio.ExitFail
	}

	// The pull, through the SAME gate recreate uses (so the two cannot drift): present/absent is
	// disambiguated with a ping, a genuinely-absent image is pulled, an unanswerable daemon stops
	// rather than pulls, and the image is recorded. This is BEFORE the container replacement below,
	// so a missing image never tears down a working container.
	if err := s.ensureImage(ctx, image, product); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	// <product>.conf, created if absent, additive thereafter, with the policy index's canonical
	// family gid.
	if err := s.ensureProductConf(pc); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// The core-fixed user-data mount points, before the mount check validates them.
	if err := ensureMountPoints(d.Home); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.ensureVolumes(ctx, pc); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	// The replacement branch, gated on provenance exactly as recreate's is.
	if err := s.replaceContainer(ctx, pc.Container, "install"); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	if err := s.launch(ctx, pc, image, netID, bringup.Running); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	// The two install-time annotations reflect the install that SUCCEEDED, reconciled HERE — after
	// bring-up, never before it. A failed --image install must leave no override for a later
	// recreate to run or status to report; a plain install with no --image reverts to the manifest
	// image, so it must CLEAR any override a prior install recorded. Deleting what is absent is a
	// no-op, so the clearing branch is unconditional.
	if err := s.annotate(product, "image-override", opts.ImageSet, ledger.Field{Key: "ref", Value: opts.Image}); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.annotate(product, "force-install", opts.Force); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.l.MemberAdd(product); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	d.say("install", "%s: installed and running.", product)
	return cliio.ExitOK
}

// --- start (desired state: running) -----------------------------------------------------------

// Start brings a product up and verifies it: intent → set the entry → start → verify live → clear.
func Start(ctx context.Context, d Deps, product string) int {
	return simpleVerb(ctx, d, product, (*session).start)
}

func (s *session) start(ctx context.Context, product string) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	c, err := s.containerFor(product)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.installedContainer(product, c); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.authorityOK(ctx, c); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	netID, nerr := s.netTarget(ctx)
	if nerr != nil {
		d.warnErr(nerr)
		return cliio.ExitFail
	}
	alias, aerr := manifest.Alias(product)
	if aerr != nil {
		d.warnErr(aerr)
		return cliio.ExitFail
	}
	// ONE atomic write: desired=running AND the outstanding alias check it owes. Splitting them
	// leaves a window where a crash produces a container recovery starts and then considers fully
	// reconciled.
	if err := state.Commit(s.l, c, state.Running, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	return s.reconcile(ctx, product, c, netID, alias)
}

// --- stop (desired state: stopped) --------------------------------------------------------------

// Stop records the intent FIRST and then acts — the ordering is the whole point. A `stopped` intent
// owes no live verification, so it declares none structurally.
func Stop(ctx context.Context, d Deps, product string) int {
	return simpleVerb(ctx, d, product, (*session).stop)
}

func (s *session) stop(ctx context.Context, product string) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	c, err := s.containerFor(product)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.installedContainer(product, c); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.authorityOK(ctx, c); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := state.Commit(s.l, c, state.Stopped, nil, false); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// THE STOP MUST ACTUALLY HAPPEN. Folding a daemon/permission/runtime failure into success
	// leaves the product RUNNING while the CLI reports completion. An already-stopped container
	// makes the stop an idempotent no-op that still succeeds, and a container that is not present
	// is nothing to stop either — both are genuinely stopped. Only a stop that was ATTEMPTED and
	// could not complete is a failure.
	if serr := s.rt.ContainerStop(ctx, c); serr == nil {
		d.say("stop", "%s: stopped.", product)
		return cliio.ExitOK
	}
	obs, oerr := state.Observe(ctx, state.Engine(d.Engine), c)
	if oerr == nil && obs == state.ObsAbsent {
		d.say("stop", "%s: already stopped (its container is not present).", product)
		return cliio.ExitOK
	}
	d.warn("verbs: %q could not be stopped — its container is still present and the runtime did", product)
	d.warn("  not complete the stop, so it may still be running. Reported as a failure.")
	return cliio.ExitFail
}

// --- restart (desired state: PRESERVED; refused on a stopped product) ---------------------------

// Restart is refused on a product the operator stopped: restart preserves what you asked for.
func Restart(ctx context.Context, d Deps, product string) int {
	return simpleVerb(ctx, d, product, (*session).restart)
}

func (s *session) restart(ctx context.Context, product string) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	c, err := s.containerFor(product)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	want, werr := state.DesiredGet(s.l, c)
	if werr != nil {
		if errors.Is(werr, ledger.ErrAbsentRecord) {
			d.warn("verbs: %q is not installed", product)
			return cliio.ExitFail
		}
		d.warnErr(werr)
		return cliio.ExitFail
	}
	if err := s.authorityOK(ctx, c); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if want == state.Stopped {
		d.warn("verbs: %q is stopped, so there is nothing to restart.", product)
		d.warn("  Refusing rather than starting it: 'restart' preserves what you asked for, and you asked")
		d.warn("  for it to be stopped. Use 'start' if you want it running.")
		return cliio.ExitFail
	}
	netID, nerr := s.netTarget(ctx)
	if nerr != nil {
		d.warnErr(nerr)
		return cliio.ExitFail
	}
	alias, aerr := manifest.Alias(product)
	if aerr != nil {
		d.warnErr(aerr)
		return cliio.ExitFail
	}
	if err := state.Commit(s.l, c, state.Running, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	// The stop is a MEANS here (restart brings the container down in order to bring it back up),
	// but it must actually HAPPEN — the same rule stop enforces on its own. A swallowed stop leaves
	// the container RUNNING; the reconciler then sees a live container whose alias still resolves,
	// clears the outstanding check and succeeds — a restart that never restarted. Only "there is
	// nothing there to stop" is not a failure: the reconciler's start-verify plan then creates and
	// starts it.
	if serr := s.rt.ContainerStop(ctx, c); serr != nil {
		obs, oerr := state.Observe(ctx, state.Engine(d.Engine), c)
		if oerr != nil || obs != state.ObsAbsent {
			d.warn("verbs: %q could not be restarted — its container could not be stopped and is", product)
			d.warn("  still present, so it may still be running. Reported as a failure.")
			return cliio.ExitFail
		}
	}
	return s.reconcile(ctx, product, c, netID, alias)
}

// --- recreate (desired state: PRESERVED) --------------------------------------------------------

// Recreate replaces the container without touching membership, config or volumes. A recreate of a
// stopped product leaves it stopped; it live-verifies like a fresh install.
func Recreate(ctx context.Context, d Deps, product string) int {
	return simpleVerb(ctx, d, product, (*session).recreate)
}

func (s *session) recreate(ctx context.Context, product string) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	c, err := s.containerFor(product)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if _, derr := state.DesiredGet(s.l, c); derr != nil {
		if errors.Is(derr, ledger.ErrAbsentRecord) {
			d.warn("verbs: %q is not installed", product)
			return cliio.ExitFail
		}
		d.warnErr(derr)
		return cliio.ExitFail
	}

	pc, cerr := s.productCtx(product, s.manifestPath(product))
	// NORMALIZE TO THE VERB CONTRACT (only 0/1/2/3 may leave a verb), and HONOR a recorded
	// force-install. A not-launched manifest normally refuses a recreate (unlike install it has no
	// FRESH not-launched path, and the batch aggregate treats 3 as benign, which this is not — so
	// it maps to 1). BUT if the operator force-installed this product they asserted the image is
	// published, and recreate honors that exactly as it honors a recorded --image override.
	if errors.Is(cerr, trust.ErrNotLaunched) {
		if _, ferr := s.l.Find(kindForced, "key", product+":force-install"); ferr == nil {
			d.warn("verbs: %q was force-installed against a not-launched manifest; recreate honors that", product)
			d.warn("  override and rebuilds the container the operator explicitly stood up.")
			cerr = nil
		}
	}
	if cerr != nil {
		d.warnErr(cerr)
		d.warn("verbs: cannot build the context to recreate %q — its manifest or", product)
		d.warn("  policy could not be authenticated, or has been withdrawn. Nothing was changed.")
		return cliio.ExitFail
	}

	image := pc.Image
	// PRESERVE a recorded image override. install may have been given `--image X`, which it
	// recorded and which status reports as the running image. recreate takes no --image of its own
	// and must NOT silently revert to the manifest's image — doing so runs an image status does not
	// name (and, if the manifest's image was never pulled, tears the container down and cannot
	// rebuild it).
	ov, ovErr := s.l.Find(kindForced, "key", product+":image-override")
	switch {
	case ovErr == nil:
		ref, ok := ledger.FieldOf(ov, "ref")
		if !ok || ref == "" {
			d.warn("verbs: the recorded image override for %q names no reference", product)
			return cliio.ExitFail
		}
		image = ref
		d.warn("verbs: image override preserved — %q runs %q (recorded at install), not the", product, image)
		d.warn("  manifest's image. recreate does not change the image install selected.")
	case errors.Is(ovErr, ledger.ErrAbsentRecord):
	default:
		d.warn("verbs: could not read the image-override record for %q from the ledger.", product)
		d.warnErr(ovErr)
		return cliio.ExitFail
	}

	// Ensure the selected image is available BEFORE removing the running container — install's
	// gate, which recreate previously skipped. A manifest that advanced to an unpulled image (or an
	// unreachable registry) must fail the recreate here with the working container INTACT, not
	// after it has been torn down and cannot be rebuilt.
	if err := s.ensureImage(ctx, image, product); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	netID, nerr := s.netTarget(ctx)
	if nerr != nil {
		d.warnErr(nerr)
		return cliio.ExitFail
	}
	// A recreate after a manual deletion of transcripts/ or logs/ must re-create them rather than
	// refuse.
	if err := ensureMountPoints(d.Home); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.replaceContainer(ctx, c, "recreate"); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.launch(ctx, pc, image, netID, bringup.Preserve); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	return cliio.ExitOK
}

// --- shared machinery ---------------------------------------------------------------------------

// simpleVerb is the arity check, the daemon preflight, the lock, and the release, for the four
// verbs whose only operand is a product.
func simpleVerb(ctx context.Context, d Deps, product string, run func(*session, context.Context, string) int) int {
	if product == "" {
		d.warn("verbs: this verb needs a product")
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
	return run(s, ctx, product)
}

// daemonReady runs the container-runtime preflight, which every mutating verb does BEFORE it takes
// the family lock — a daemon that is not usable is not a reason to make everyone else wait.
func daemonReady(ctx context.Context, d Deps) int {
	if d.Engine == nil {
		d.warn("verbs: no container runtime connection — nothing can be created, started or verified")
		return cliio.ExitFail
	}
	if err := preflight.Daemon(ctx, d.Engine); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	return cliio.ExitOK
}

func (s *session) manifestPath(product string) string {
	return filepath.Join(s.d.ManifestDir, product+".manifest")
}

// mintIdentity establishes the installation identity and fills in the container name the context
// could not carry — on a FORCED not-launched install on a brand-new machine the context was
// assembled before the identity existed.
func (s *session) mintIdentity(pc *productContext) error {
	ident, err := s.l.IdentEnsure()
	if err != nil {
		return err
	}
	if err := s.persist(); err != nil {
		return err
	}
	if pc.Container == "" {
		c, cerr := manifest.ContainerName(ident, pc.Product)
		if cerr != nil {
			return cerr
		}
		pc.Container = c
	}
	return nil
}

// containerFor derives this product's container name from the recorded installation identity.
func (s *session) containerFor(product string) (string, error) {
	ident, err := s.l.IdentGet()
	if err != nil {
		return "", fmt.Errorf("verbs: no installation identity — has anything been installed? %w", err)
	}
	return manifest.ContainerName(ident, product)
}

// installedContainer distinguishes "not installed" from "the ledger cannot say".
//
// AN AMBIGUOUS OR UNREADABLE RECORD IS NOT THE SAME AS ABSENT, and reporting it as "not installed"
// sends the operator to install rather than to repair.
func (s *session) installedContainer(product, container string) error {
	_, err := prov.Find(s.l, prov.ClassContainer, container)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ledger.ErrAbsentRecord):
		return fmt.Errorf("verbs: %q is not installed", product)
	default:
		return fmt.Errorf("verbs: the container record for %q is ambiguous or unreadable — this is not the same\n"+
			"  as not installed. Run 'mythical-ctl state repair': %w", product, err)
	}
}

// authorityOK proves the container standing under our name is OURS before start/stop/restart acts
// on it.
//
// A PROVENANCE RECORD EXISTING IS NOT ENOUGH: after our container was deleted out of band, another
// installation could stand a container under the same name, and starting, stopping or committing
// state for it would act on someone else's object. "Already gone" is fine — nothing foreign is
// there, and the verb rebuilds or no-ops.
func (s *session) authorityOK(ctx context.Context, container string) error {
	err := prov.Authority(ctx, s.l, prov.Engine(s.d.Engine), prov.ClassContainer, container)
	if err == nil || errors.Is(err, prov.ErrGone) {
		return nil
	}
	return fmt.Errorf("verbs: a container stands under this product's name that is not this installation's — refusing\n"+
		"  to start, stop or restart another installation's object. Run 'mythical-ctl state repair'.\n"+
		"  %w", err)
}

// reconcile runs the state plan and NORMALIZES its outcome to the verb contract.
//
// The reconciler reports "needs a rebuild" for a plan only install/recreate can carry out; relaying
// that verdict as-is would leak an exit code the contract does not define. It — and anything else
// non-zero — maps to operational failure, naming the recovery.
func (s *session) reconcile(ctx context.Context, product, container, netID, alias string) int {
	// THE IDENTITY AND THE VERIFIED INDEX ARE BOTH REQUIRED, and both are read here rather than
	// defaulted. The probe arm scopes every removal by the identity and takes its pinned image from
	// the index, so an empty identity or an unread index does not degrade the reconciliation — it
	// makes it impossible, and passing either as a zero value turns every start and restart into a
	// refusal that names the probe instead of the real problem. (Measured: an empty identity here
	// made start and restart fail before the reconciler ran at all, while the tests that expected a
	// failure still passed — for the wrong reason.)
	ident, ierr := s.l.IdentGet()
	if ierr != nil {
		s.d.warnErr(ierr)
		return cliio.ExitFail
	}
	ix, xerr := trust.CheckIndex(s.st, s.d.IndexPath)
	if xerr != nil {
		s.d.warn("verbs: the family index could not be authenticated, so %q cannot be verified after it", product)
		s.d.warn("  starts — and an unverified start is the one this installer does not report as done.")
		s.d.warnErr(xerr)
		return cliio.ExitFail
	}
	bd, err := s.bringupDeps(ix, ident)
	if err != nil {
		s.d.warnErr(err)
		return cliio.ExitFail
	}
	rerr := bringup.Reconcile(ctx, s.l, bd, container, netID, alias)
	if perr := s.persist(); perr != nil {
		s.d.warnErr(perr)
		return cliio.ExitFail
	}
	if rerr == nil {
		return cliio.ExitOK
	}
	if errors.Is(rerr, bringup.ErrRebuild) {
		s.d.warn("verbs: %q needs a rebuild that start/restart cannot perform — run", product)
		s.d.warn("  'mythical-ctl recreate %s'.", product)
		return cliio.ExitFail
	}
	s.d.warnErr(rerr)
	return cliio.ExitFail
}

// ensureImage makes the selected image present, and records it.
//
// PULL ONLY ON CONFIRMED ABSENCE. An image inspect answers present/not-present but cannot tell
// "absent" from "the daemon could not answer", and sending the second to a pull is the
// refusal-into-answer fold this codebase refuses everywhere — so a not-present answer is
// disambiguated with a ping (a question that does not depend on the image): a daemon that answers
// means the image is genuinely absent and we pull; a daemon that does NOT answer stops rather than
// pulling.
//
// Install AND recreate both call this BEFORE they stop or remove any existing container, so an
// image that cannot be made available fails the verb with the working installation PRESERVED.
func (s *session) ensureImage(ctx context.Context, image, product string) error {
	present := true
	if _, err := s.d.Engine.ImageInspect(ctx, image); err != nil {
		present = false
	}
	if !present {
		if err := s.d.Engine.Ping(ctx); err != nil {
			return fmt.Errorf("verbs: could not determine whether the image for %q is already present — the\n"+
				"  container runtime did not answer. Refusing rather than pulling on a question that\n"+
				"  could not be asked: %w", product, err)
		}
		if err := s.rt.ImagePull(ctx, image); err != nil {
			return fmt.Errorf("verbs: the image for %q could not be pulled:\n"+
				"    %s\n"+
				"  The runtime said:\n"+
				"    %v\n"+
				"  The manifest declares this product LAUNCHED, so this is a release or registry problem,\n"+
				"  not a pre-launch state. It is reported as a failure deliberately.", product, image, err)
		}
	}
	if err := prov.ImageRecord(s.l, image, product); err != nil {
		return err
	}
	return s.persist()
}

// ensureProductConf creates <product>.conf if absent and never modifies it thereafter.
//
// A group that could not be set is a REPORTED CONDITION, not an install failure: the file exists and
// is correct, only the shared-group ownership did not take — the ordinary outcome for an
// unprivileged installer whose operator is not in the family group. The product runs; its settings
// screen is read-only until the group is fixed.
func (s *session) ensureProductConf(pc *productContext) error {
	gid, ok := pc.Policy.FamilyGID()
	if !ok || gid == "" {
		return errors.New("verbs: the policy index declares no family group id, so <product>.conf cannot be given the ownership the published spec requires")
	}
	err := conf.ProductEnsure(s.h, pc.Product, gid)
	if err == nil {
		return nil
	}
	var oe *conf.OwnershipError
	if errors.As(err, &oe) {
		s.d.warn("verbs: %s", oe.Error())
		s.d.warn("  The install continues.")
		return nil
	}
	return err
}

// ensureVolumes creates a named volume for every declared role that has no operator bind, under a
// write-ahead intent.
func (s *session) ensureVolumes(ctx context.Context, pc *productContext) error {
	ident, err := s.l.IdentGet()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, v := range pc.Manifest.Volumes() {
		if seen[v.Role] {
			continue
		}
		seen[v.Role] = true
		vol, verr := manifest.VolumeName(ident, pc.Product, v.Role)
		if verr != nil {
			return verr
		}
		// The data class, resolved from the AUTHENTICATED policy index and recorded ON the volume,
		// not re-derived at destruction time: a product being uninstalled may be one whose manifest
		// has been withdrawn, and a purge that fails closed on a missing policy index cannot
		// uninstall anything, while one that falls back to "not precious" answers the question in
		// the direction that costs data.
		precious := "0"
		if pc.Policy.Precious(pc.Product, v.Role) {
			precious = "1"
		}
		if err := s.ensureVolume(ctx, ident, pc.Product, v.Role, vol, precious); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) ensureVolume(ctx context.Context, ident, product, role, vol, precious string) error {
	// ABSENT IS THE ONLY STATUS THAT AUTHORIZES CREATING ONE. A record that already answers means
	// it exists (skip); a ledger that cannot say whether the volume is already recorded must not be
	// answered by creating a second one under the same name.
	_, pfErr := prov.Find(s.l, prov.ClassVolume, vol)
	switch {
	case pfErr == nil:
		return nil
	case errors.Is(pfErr, ledger.ErrAbsentRecord):
	default:
		return fmt.Errorf("verbs: the provenance record for volume %q could not be read; refusing to create a\n"+
			"  second volume under the same name on an unreadable ledger: %w", vol, pfErr)
	}

	extra := []ledger.Field{
		{Key: "product", Value: product},
		{Key: "role", Value: role},
		{Key: "precious", Value: precious},
	}

	_, ifErr := intent.Find(s.l, prov.ClassVolume, vol)
	switch {
	case ifErr == nil:
		// An intent is already open for it: the reconciler decides whether the object appeared,
		// must be re-issued, or cannot be settled.
		if err := intent.Reconcile(ctx, s.l, s.objs, s.rt, prov.ClassVolume, vol); err != nil {
			return err
		}
		return s.persist()
	case errors.Is(ifErr, ledger.ErrAbsentRecord):
	default:
		return fmt.Errorf("verbs: the intent record for volume %q could not be read; refusing to open a second: %w", vol, ifErr)
	}

	nonce, nerr := intent.NonceNew()
	if nerr != nil {
		return nerr
	}
	// THE INTENT IS DURABLE BEFORE THE VOLUME EXISTS.
	if err := intent.Open(s.l, prov.ClassVolume, vol, nonce, timeNow(), extra...); err != nil {
		return err
	}
	if err := s.persist(); err != nil {
		return err
	}
	p, perr := engine.NewProvenance(ident, nonce)
	if perr != nil {
		return perr
	}
	if err := s.rt.VolumeCreate(ctx, vol, p); err != nil {
		return err
	}
	// RE-INSPECT: a volume create against an existing name SUCCEEDS without applying the labels, so
	// a create is never evidence of creation — the nonce label is. The STATUS is captured, not just
	// the value: a daemon that could not answer is not the same fact as a volume carrying a
	// different nonce.
	got, lerr := prov.Engine(s.d.Engine).Label(ctx, prov.ClassVolume, vol, prov.LabelNonce)
	if lerr != nil && !errors.Is(lerr, engine.ErrAbsent) {
		return fmt.Errorf("verbs: could not verify volume %q — the container runtime did not answer. The\n"+
			"  intent is retained so a re-run converges once the runtime is reachable: %w", vol, lerr)
	}
	if got != nonce {
		return fmt.Errorf("verbs: volume %q already existed and does not carry our nonce. Not adopted, not\n"+
			"  removed. The intent is retained.", vol)
	}
	if err := intent.Confirm(s.l, prov.ClassVolume, vol, nonce, extra...); err != nil {
		return err
	}
	return s.persist()
}

// replaceContainer removes the container standing under this name, if any, so bring-up can create
// its replacement.
//
// PROVING IT IS OURS APPLIES TO A REPLACEMENT EXACTLY AS IT APPLIES TO AN UNINSTALL. "We are about
// to replace it" is not an exemption. And the removal must SUCCEED before bring-up creates the
// replacement under the same name: a discarded removal failure left the old container
// stopped-but-present and bring-up then failed on the name collision — taking a working
// installation DOWN for a replacement that could not happen.
func (s *session) replaceContainer(ctx context.Context, container, verb string) error {
	_, pfErr := prov.Find(s.l, prov.ClassContainer, container)
	switch {
	case errors.Is(pfErr, ledger.ErrAbsentRecord):
		// No prior container recorded: straight to a fresh create.
		return nil
	case pfErr != nil:
		return fmt.Errorf("verbs: the provenance record for container %q is ambiguous or unreadable, so this\n"+
			"  %s cannot tell whether a container already stands under that name. Refusing to create\n"+
			"  over it rather than adopt an unreadable ledger. Run 'mythical-ctl state repair': %w",
			container, verb, pfErr)
	}
	aerr := prov.Authority(ctx, s.l, prov.Engine(s.d.Engine), prov.ClassContainer, container)
	switch {
	case errors.Is(aerr, prov.ErrGone):
		return nil // already gone: nothing to remove, nothing to fear
	case aerr != nil:
		return fmt.Errorf("verbs: refusing to replace %q. It is preserved, and this\n"+
			"  %s stops rather than creating a second container under the same name.\n"+
			"  %w", container, verb, aerr)
	}
	_ = s.rt.ContainerStop(ctx, container)
	if rmErr := s.rt.ContainerRemove(ctx, container); rmErr != nil {
		// Restore the container we just stopped (best effort) and fail rather than proceed.
		_ = s.rt.ContainerStart(ctx, container)
		return fmt.Errorf("verbs: could not remove the existing container %q to replace it. It is\n"+
			"  left in place (a restart was attempted) rather than taking your installation down.\n"+
			"  Resolve the removal failure — check the container runtime and permissions — then re-run: %w",
			container, rmErr)
	}
	return nil
}

// launch runs the full bring-up sequence for this product.
func (s *session) launch(ctx context.Context, pc *productContext, image, netID string, desired bringup.Desired) error {
	ident, err := s.l.IdentGet()
	if err != nil {
		return err
	}
	ports, perr := hostPorts(s.d.Home, pc.Product, pc.Manifest)
	if perr != nil {
		return perr
	}
	bd, berr := s.bringupDeps(pc.Index, ident)
	if berr != nil {
		return berr
	}
	launcher := &productLauncher{
		rt:        s.rt,
		m:         pc.Manifest,
		p:         pc.Policy,
		ident:     ident,
		netID:     netID,
		image:     image,
		hostPorts: ports,
	}
	rerr := bringup.Run(ctx, s.l, bd, launcher, pc.Container, netID, pc.Alias, desired)
	if err := s.persist(); err != nil {
		return err
	}
	return rerr
}

// annotate writes or clears one install-time annotation record.
func (s *session) annotate(product, kind string, on bool, extra ...ledger.Field) error {
	key := product + ":" + kind
	if !on {
		return s.l.Del(kindForced, "key", key)
	}
	fields := []ledger.Field{
		{Key: "key", Value: key},
		{Key: "product", Value: product},
		{Key: "kind", Value: kind},
	}
	fields = append(fields, extra...)
	return s.l.Put(kindForced, "key", key, fields)
}

// productLauncher is the bring-up sequence's Launcher for a product container: it holds everything
// the launch varies and reaches the SOLE creation site through the runtime facade. Nothing here
// assembles a container spec — that is the facade's, and it is a boundary the build enforces.
type productLauncher struct {
	rt        *runtime.Runtime
	m         *manifest.Manifest
	p         *policy.Policy
	ident     string
	netID     string
	image     string
	hostPorts map[uint16]uint16
}

func (pl *productLauncher) Launch(ctx context.Context, container, nonce string) (string, error) {
	return pl.rt.LaunchProduct(ctx, pl.m, pl.p, runtime.LaunchConfig{
		Identity:  pl.ident,
		Nonce:     nonce,
		NetworkID: pl.netID,
		Image:     pl.image,
		HostPorts: pl.hostPorts,
	})
}

// ensureMountPoints creates the core-fixed user-data mount points: ~/.mythical/transcripts and
// ~/.mythical/logs.
//
// The layout helper deliberately leaves these "to appear when a product binds them" — they are the
// user-data ownership class, not installer state — and binding them is exactly what a launch does.
// So they are created HERE, before the core-fixed set is validated and before the runtime refuses a
// bind whose source is missing. Created if absent, never touched otherwise; mkdir makes real
// directories, which is what the no-symlink / exact-canonical checks require.
func ensureMountPoints(home string) error {
	for _, d := range []string{"transcripts", "logs"} {
		p := filepath.Join(home, d)
		if fi, err := os.Lstat(p); err == nil {
			if fi.IsDir() {
				continue
			}
			return fmt.Errorf("verbs: %s exists and is not a directory, so it cannot be the %q mount point", p, d)
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("verbs: cannot create the %q mount point under the family home: %w", d, err)
		}
	}
	return nil
}
