package verbs

// uninstall — the two scopes, and they deliberately do NOT share an implementation.
//
// A PRODUCT uninstall removes the container and RETAINS everything else: named volumes, membership,
// and the anti-rollback trust floor. If it cleared the floor, `uninstall` then `install` would be a
// supported one-command rollback bypass — drop the floor, replay a withdrawn manifest, recover the
// vulnerable image. The floor outlives the install that established it, and a reinstall inherits it.
//
// A FAMILY uninstall resets everything: afterwards the machine is genuinely indistinguishable from
// a fresh one. That is acceptable precisely because it is an explicit operator action rather than a
// remote input, and it is the ONLY path that removes identity, membership, trust floors and the
// family-index anchor.
//
// USER DATA IS NEVER TOUCHED BY EITHER. transcripts/, logs/ and any host bind are the user-data
// ownership class. Named volumes go only with --purge, under the same authority check.
//
// THE TWO SCOPES ARE TWO FUNCTIONS, not one carrying a `Family bool`. `uninstall <product>
// --family` is a contradiction — it names a product and then asks for an operation that has none —
// and honouring the flag while dropping the product runs something materially MORE destructive than
// what was written. A struct that can hold both states needs a guard to refuse the combination;
// two functions cannot express it at all, which is the same reasoning InstallOpts applies in the
// other direction (there the third state is real and must be representable, so it is).

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
)

// --- product uninstall ----------------------------------------------------------------------------

// Uninstall removes one product's container. Named volumes, membership and the trust floor are
// RETAINED unless purge is set; with purge they are listed, confirmed, and then removed.
func Uninstall(ctx context.Context, d Deps, product string, purge bool) int {
	if product == "" {
		d.warn("verbs: uninstall needs <product> [--purge]")
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
	return s.uninstall(ctx, product, purge)
}

func (s *session) uninstall(ctx context.Context, product string, purge bool) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	// THE LISTINGS ARE READ ONCE, UP FRONT, AND FAIL CLOSED — before any removal. An unreadable
	// ledger must refuse the uninstall rather than remove the container and then silently skip the
	// volumes it could not enumerate.
	objs, oerr := recordsOf(s.l, kindObject)
	if oerr != nil {
		d.warnErr(oerr)
		return cliio.ExitFail
	}
	imgs, ierr := recordsOf(s.l, kindImage)
	if ierr != nil {
		d.warnErr(ierr)
		return cliio.ExitFail
	}

	if purge {
		if !s.confirmProductPurge(product, objs) {
			d.warn("verbs: not confirmed.")
			return cliio.ExitFail
		}
	}

	rc := cliio.ExitOK
	c, cerr := s.containerFor(product)
	if cerr != nil {
		d.warnErr(cerr)
		return cliio.ExitFail
	}
	ok, stop := s.removeProductContainer(ctx, product, c)
	if !ok {
		rc = cliio.ExitFail
	}
	if stop != nil {
		return s.stopAfterPartialRemoval(stop)
	}
	if ok, stop = s.productVolumes(ctx, product, objs, purge); !ok {
		rc = cliio.ExitFail
	}
	if stop != nil {
		return s.stopAfterPartialRemoval(stop)
	}
	if purge {
		s.offerImages(product, imgs)
	}
	if perr := s.persist(); perr != nil {
		d.warnErr(perr)
		return cliio.ExitFail
	}
	if rc != cliio.ExitOK {
		return rc
	}
	// RETAINED, DELIBERATELY: membership and the trust floor. Nothing here drops either.
	d.say("uninstall", "%s: uninstalled. Its rollback floor and initialization record are retained, so a", product)
	d.say("uninstall", "  reinstall cannot replay a withdrawn manifest.")
	return cliio.ExitOK
}

// stopAfterPartialRemoval reports a ledger-edit failure, makes DURABLE whatever this verb has
// already recorded, and stops.
//
// EVERY OTHER FAILURE IN A REMOVAL LOOP IS ABOUT ONE OBJECT and leaves the rest of the operation
// meaningful — the reference reports those and continues. A ledger that will not record what was
// just removed is not that: from there, every further removal is a removal nothing will record,
// which is why the reference spells these `|| return 1` in the middle of the loop.
//
// The persist restores the other half of that `return 1`. The reference's ledger editors wrote the
// file themselves, so its earlier tombstones were already durable when it returned; these edit
// memory, so an object removed from the runtime whose tombstone exists only in memory would be
// forgotten outright. The failing edit itself mutates nothing — both editors ask every cardinality
// question before they write anything — so what is persisted here is exactly the work that
// succeeded.
func (s *session) stopAfterPartialRemoval(cause error) int {
	s.d.warnErr(cause)
	if perr := s.persist(); perr != nil {
		s.d.warnErr(perr)
	}
	return cliio.ExitFail
}

// confirmProductPurge NAMES what is about to be destroyed and then asks.
//
// SCOPED TO --purge DELIBERATELY. A plain product uninstall KEEPS every volume — and says so, per
// volume, in the loop that follows — so prompting there would train operators to type y at a
// question that never means anything, and a confirmation that is usually harmless is a confirmation
// nobody reads by the time it is not.
//
// IT ASKS BEFORE THE CONTAINER IS REMOVED, which is why the listing is read up front: a prompt that
// arrives after the container is already gone is not a decision point, it is a notification. And it
// names each volume WITH ITS DATA CLASS, because "are you sure?" against an unnamed set is a
// question the operator has no way to answer.
func (s *session) confirmProductPurge(product string, objs [][]ledger.Field) bool {
	d := s.d
	var precious, regen []string
	unattributed := 0
	any := false
	for _, rec := range objs {
		if recClass(rec) != "volume" {
			continue
		}
		p, hasProduct := ledger.FieldOf(rec, "product")
		if p != product {
			// A volume whose record names NO product at all is out of scope here and is COUNTED,
			// not silently skipped: this verb selects by product, so it has no way to know the
			// volume is this product's, and acting on it would be acting on a guess. Saying nothing
			// would let "purge complete" mean "and some volumes were left that I could not
			// attribute". status lists them with the same classification this warning uses.
			if !hasProduct {
				unattributed++
			}
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok {
			name = "(a volume whose record carries no readable name)"
		}
		role, _ := ledger.FieldOf(rec, "role")
		if role == "" {
			role = "?"
		}
		any = true
		if volPrecious(rec) {
			precious = append(precious, fmt.Sprintf("      %s (role %s) — %s", name, role, volClass(rec)))
			continue
		}
		regen = append(regen, fmt.Sprintf("      %s (role %s) — regenerable", name, role))
	}

	d.warn("verbs: PURGE of %q. Its container is removed, and so are its named volumes.", product)
	if !any {
		d.warn("  No volume records are in scope, so this removes the container only.")
	}
	if len(precious) > 0 {
		d.warn("  THESE HOLD DATA THAT CANNOT BE REGENERATED. Removing them is not recoverable by")
		d.warn("  reinstalling, and this tool keeps no copy:")
		for _, line := range precious {
			d.warn("%s", line)
		}
	}
	if len(regen) > 0 {
		d.warn("  These are declared regenerable — a reinstall rebuilds their contents:")
		for _, line := range regen {
			d.warn("%s", line)
		}
	}
	if unattributed > 0 {
		d.warn("  NOTE: %d volume record(s) name no product, so this verb cannot attribute them and", unattributed)
		d.warn("  will NOT remove them. They are left in place. 'mythical-ctl status' lists them.")
	}
	d.warn("  transcripts/, logs/ and any host binds are never touched by any verb.")
	d.warn("  Without --purge, every volume above is KEPT.")
	return d.ask(fmt.Sprintf("verbs: purge %q and remove the volumes listed above?", product))
}

// removeProductContainer removes this product's container, under the provenance authority every
// removal path in this tree obeys.
//
// It reports (step succeeded, stop the verb). A refusal or a failed removal is reported and the
// uninstall continues with the rest; only a ledger edit that could not be made stops it.
func (s *session) removeProductContainer(ctx context.Context, product, c string) (bool, error) {
	d := s.d
	aerr := prov.Authority(ctx, s.l, prov.Engine(d.Engine), prov.ClassContainer, c)
	switch {
	case aerr == nil:
		_ = s.rt.ContainerStop(ctx, c)
		// TOMBSTONE ONLY ON A REMOVAL THAT ACTUALLY SUCCEEDED. Recording a removal that did not
		// happen strips the container's authority record while it is still running — after which
		// nothing can ever remove it.
		if rerr := s.rt.ContainerRemove(ctx, c); rerr != nil {
			d.warnErr(rerr)
			d.warn("verbs: could not remove the container for %q. Its record is KEPT so it stays", product)
			d.warn("  removable later; nothing is tombstoned for a removal that did not happen.")
			return false, nil
		}
	case errors.Is(aerr, prov.ErrGone):
		// Already gone: nothing to remove and nothing to preserve, so the record is retired.
	default:
		d.warnErr(aerr)
		d.warn("verbs: the container for %q is preserved (see above). Continuing with the rest.", product)
		return false, nil
	}
	if err := prov.Tombstone(s.l, prov.ClassContainer, c); err != nil {
		return false, err
	}
	if err := state.Forget(s.l, c); err != nil {
		return false, err
	}
	return true, nil
}

// productVolumes keeps or purges this product's named volumes, saying which per volume.
//
// THE PER-VOLUME STATEMENT IS THE POINT of a plain uninstall, not a summary line: an operator who
// is told "your data is kept" learns nothing they can check, while a line per volume names exactly
// what survived and how to remove it if they meant to.
func (s *session) productVolumes(ctx context.Context, product string, objs [][]ledger.Field, purge bool) (bool, error) {
	d := s.d
	okAll := true
	for _, rec := range objs {
		if recClass(rec) != "volume" {
			continue
		}
		if p, _ := ledger.FieldOf(rec, "product"); p != product {
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok {
			d.warn("verbs: a volume record for %q carries no", product)
			d.warn("  readable name; --purge cannot act on it and it is left in place. Run 'state repair'.")
			okAll = false
			continue
		}
		role, _ := ledger.FieldOf(rec, "role")
		if role == "" {
			role = "?"
		}
		class := volClass(rec)
		if !purge {
			d.say("uninstall", "  keeping volume %s (role %s, %s) — your data. 'uninstall --purge' removes it.", name, role, class)
			continue
		}
		ok, stop := s.purgeVolume(ctx, name, role, class)
		if !ok {
			okAll = false
		}
		if stop != nil {
			return okAll, stop
		}
	}
	return okAll, nil
}

func (s *session) purgeVolume(ctx context.Context, name, role, class string) (bool, error) {
	d := s.d
	aerr := prov.Authority(ctx, s.l, prov.Engine(d.Engine), prov.ClassVolume, name)
	switch {
	case aerr == nil:
		if rerr := s.rt.VolumeRemove(ctx, name); rerr != nil {
			d.warnErr(rerr)
			d.warn("  could NOT remove volume %s — its record is kept, so it stays removable later.", name)
			return false, nil
		}
		if err := prov.Tombstone(s.l, prov.ClassVolume, name); err != nil {
			return false, err
		}
		d.say("uninstall", "  removed volume %s (role %s, %s).", name, role, class)
		return true, nil
	case errors.Is(aerr, prov.ErrGone):
		// ALREADY GONE is not a refusal: nothing to remove and nothing to preserve, so the record
		// is tombstoned. Only a real refusal — no record, or a nonce that does not match —
		// preserves.
		if err := prov.Tombstone(s.l, prov.ClassVolume, name); err != nil {
			return false, err
		}
		d.say("uninstall", "  volume %s was already gone; its record is tombstoned.", name)
		return true, nil
	default:
		d.warnErr(aerr)
		d.say("uninstall", "  PRESERVED volume %s — see the reason above.", name)
		return false, nil
	}
}

// offerImages names the images this installer pulled for the product and REMOVES NONE OF THEM.
//
// NO VERB REMOVES AN IMAGE — not uninstall, not --purge. The ledger records that this installer
// PULLED a digest, which is not the same as owning it: another installation on the same daemon, or
// the operator's own local work, may depend on the same bytes. `--purge` may only OFFER the
// reclamation, naming the references and stating the shared-use risk plainly.
func (s *session) offerImages(product string, imgs [][]ledger.Field) {
	d := s.d
	var refs []string
	for _, rec := range imgs {
		if p, _ := ledger.FieldOf(rec, "product"); p != product {
			continue
		}
		if ref, ok := ledger.FieldOf(rec, "ref"); ok {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return
	}
	d.say("uninstall", "  Images acquired for %s are NOT removed:", product)
	for _, ref := range refs {
		d.say("uninstall", "    %s", ref)
	}
	d.say("uninstall", "  They may be in use by another installation on this daemon, or by your own local work —")
	d.say("uninstall", "  the ledger records that this installer PULLED them, which is not the same as owning them.")
	d.say("uninstall", "  To reclaim the space yourself: docker image rm <digest>   (or: docker image prune)")
}

// --- family uninstall -----------------------------------------------------------------------------

// UninstallFamily removes EVERY product's container and resets the ledger entirely: identity,
// membership, every anti-rollback trust floor, and the family-index anchor.
//
// It takes NO product. The scope IS the family.
func UninstallFamily(ctx context.Context, d Deps, purge bool) int {
	if rc := daemonReady(ctx, d); rc != cliio.ExitOK {
		return rc
	}
	s, err := openSession(d)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	defer s.close()
	return s.uninstallFamily(ctx, purge)
}

func (s *session) uninstallFamily(ctx context.Context, purge bool) int {
	d := s.d
	if err := s.prepare(ctx); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	ident, ierr := s.l.IdentGet()
	if ierr != nil {
		d.warnErr(ierr)
		d.warn("verbs: there is no installation to uninstall.")
		return cliio.ExitFail
	}
	d.warn("verbs: FAMILY UNINSTALL of installation %q.", ident)
	d.warn("  Every product's container is removed, and the ledger is reset ENTIRELY: the installation")
	d.warn("  identity, the initialized-product set, every anti-rollback trust floor, and the")
	d.warn("  family-index anchor. Afterwards this machine is indistinguishable from a fresh one.")

	// READ BEFORE THE PROMPT, not after it. Reading after meant an unreadable ledger asked the
	// operator to confirm a family uninstall and only then refused to perform it — a question asked
	// about work that could not be done either way. It also meant the warning could not name what
	// --purge was about to destroy, so the one prompt guarding every volume on the machine said
	// "THAT IS YOUR DATA" without saying which data. Nothing here mutates, so there is no ordering
	// cost. It is ALSO the guard on the reset below: an unreadable object listing must not read as
	// an empty one, which would remove nothing, leave `preserved` clear, and let the reset wipe the
	// ledger over containers and volumes it never touched.
	objs, oerr := recordsOf(s.l, kindObject)
	if oerr != nil {
		d.warnErr(oerr)
		return cliio.ExitFail
	}
	imgs, ierr2 := recordsOf(s.l, kindImage)
	if ierr2 != nil {
		d.warnErr(ierr2)
		return cliio.ExitFail
	}

	s.familyPurgeWarning(objs, purge)
	d.warn("  transcripts/, logs/ and any host binds are never touched by any verb.")
	if !d.ask("verbs: uninstall the whole family?") {
		d.warn("verbs: not confirmed.")
		return cliio.ExitFail
	}

	// Containers first, then volumes, then the network — a network cannot be removed while a
	// container is attached to it. `preserved` is what holds the ledger reset back: wiping the
	// ledger while an object it describes is still there would strip that object's provenance,
	// making it permanently unauthorized for deletion AND an unrecorded same-identity object that
	// stops every later operation.
	preserved, stop := s.familyContainers(ctx, objs)
	if stop != nil {
		return s.stopAfterPartialRemoval(stop)
	}
	if s.familyVolumes(ctx, objs, purge) {
		preserved = true
	}
	if s.familyNetworks(ctx, objs) {
		preserved = true
	}
	if s.familyOperatorRef() {
		preserved = true
	}
	s.familyImages(imgs)

	if perr := s.persist(); perr != nil {
		d.warnErr(perr)
		return cliio.ExitFail
	}
	if preserved {
		d.warn("family: some objects could not be removed (see above), so the ledger is NOT reset — it is")
		d.warn("  the only record of what they are. Resolve them, then re-run.")
		return cliio.ExitFail
	}

	// THE RESET. It is unconditional with respect to --purge: identity, membership, every trust
	// floor and the family-index anchor go regardless — --purge gates only the VOLUMES' fate. A
	// volume deliberately KEPT without --purge is not a preservation; it is orphaned on purpose.
	if werr := s.persistFn()(&ledger.Ledger{}); werr != nil {
		d.warnErr(werr)
		return cliio.ExitFail
	}
	if !purge {
		d.say("uninstall", "family: uninstalled. Identity, membership, every rollback floor and the network are gone;")
		d.say("uninstall", "  this machine is a fresh installation again. Your named volumes were KEPT (your data) and")
		d.say("uninstall", "  are now orphaned but preserved — a later installation sees them as another's and never")
		d.say("uninstall", "  touches them. ~/.mythical/ still holds your transcripts, logs and config files; remove the")
		d.say("uninstall", "  directory by hand to clear those too.")
		return cliio.ExitOK
	}
	d.say("uninstall", "family: uninstalled. ~/.mythical/ still holds your transcripts, logs and config files;")
	d.say("uninstall", "  remove the directory by hand if you want them gone too.")
	return cliio.ExitOK
}

// familyPurgeWarning states the volumes' fate before the one prompt that governs it — the same
// enumeration the product-scoped purge shows, over every product at once. Unregenerable first, and
// separately, because that is the half a reinstall does not bring back.
func (s *session) familyPurgeWarning(objs [][]ledger.Field, purge bool) {
	d := s.d
	if !purge {
		d.warn("  Named volumes are KEPT (your data). 'uninstall --family --purge' removes them.")
		return
	}
	d.warn("  --purge: this installation's named volumes are removed too. THAT IS YOUR DATA.")
	var precious, regen []string
	for _, rec := range objs {
		if recClass(rec) != "volume" {
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok {
			name = "(a volume whose record carries no readable name)"
		}
		role, _ := ledger.FieldOf(rec, "role")
		if role == "" {
			role = "?"
		}
		if volPrecious(rec) {
			precious = append(precious, fmt.Sprintf("      %s (role %s) — %s", name, role, volClass(rec)))
			continue
		}
		regen = append(regen, fmt.Sprintf("      %s (role %s) — regenerable", name, role))
	}
	if len(precious) > 0 {
		d.warn("  THESE HOLD DATA THAT CANNOT BE REGENERATED. Removing them is not recoverable by")
		d.warn("  reinstalling, and this tool keeps no copy:")
		for _, line := range precious {
			d.warn("%s", line)
		}
	}
	if len(regen) > 0 {
		d.warn("  These are declared regenerable — a reinstall rebuilds their contents:")
		for _, line := range regen {
			d.warn("%s", line)
		}
	}
}

// familyContainers removes every recorded container. It returns (anything PRESERVED, stop the
// verb) — see stopAfterPartialRemoval for why a ledger edit that could not be made is the one
// failure here that is not survivable.
func (s *session) familyContainers(ctx context.Context, objs [][]ledger.Field) (bool, error) {
	d := s.d
	preserved := false
	for _, rec := range objs {
		if recClass(rec) != "container" {
			continue
		}
		name, nerr := recName(rec)
		if nerr != nil {
			d.warnErr(nerr)
			preserved = true
			continue
		}
		aerr := prov.Authority(ctx, s.l, prov.Engine(d.Engine), prov.ClassContainer, name)
		switch {
		case aerr == nil:
			_ = s.rt.ContainerStop(ctx, name)
			if rerr := s.rt.ContainerRemove(ctx, name); rerr != nil {
				d.warnErr(rerr)
				d.warn("  could NOT remove container %s — it is left alone and its record is kept.", name)
				preserved = true
				continue
			}
			d.say("uninstall", "  removed container %s.", name)
		case errors.Is(aerr, prov.ErrGone):
			// Already gone: nothing to preserve.
		default:
			d.warnErr(aerr)
			d.say("uninstall", "  PRESERVED container %s — see the reason above. Its record is kept.", name)
			preserved = true
			continue
		}
		// A REMOVAL THAT FAILED IS NEVER FOLLOWED BY FORGETTING ITS STATE — that would leave the
		// container running with nothing recording it. Only the two branches above reach here.
		if ferr := state.Forget(s.l, name); ferr != nil {
			return preserved, ferr
		}
	}
	return preserved, nil
}

// familyVolumes keeps or purges every recorded volume. It returns whether anything was PRESERVED.
func (s *session) familyVolumes(ctx context.Context, objs [][]ledger.Field, purge bool) bool {
	d := s.d
	preserved := false
	for _, rec := range objs {
		if recClass(rec) != "volume" {
			continue
		}
		name, nerr := recName(rec)
		if nerr != nil {
			d.warnErr(nerr)
			preserved = true
			continue
		}
		if !purge {
			// LEFT IN PLACE without --purge (your data). The family reset still happens — only the
			// VOLUMES' fate is gated on --purge — so afterwards they carry an identity that no
			// longer exists and read as another installation's on any later operation: orphaned but
			// PRESERVED, which is what "any mismatch preserves" produces for them. They are NAMED
			// here while the ledger still records them, because the reset drops those records and
			// this installer will then have no authority to remove them again.
			d.say("uninstall", "  keeping volume %s (%s) — your data. After the reset it is", name, volClass(rec))
			d.say("uninstall", "    orphaned; remove it by hand with 'docker volume rm %s', or re-run with --purge", name)
			d.say("uninstall", "    instead of keeping it.")
			continue
		}
		aerr := prov.Authority(ctx, s.l, prov.Engine(d.Engine), prov.ClassVolume, name)
		switch {
		case aerr == nil:
			if rerr := s.rt.VolumeRemove(ctx, name); rerr != nil {
				d.warnErr(rerr)
				d.warn("  could NOT remove volume %s — its record is kept.", name)
				preserved = true
				continue
			}
			d.say("uninstall", "  removed volume %s (%s).", name, volClass(rec))
		case errors.Is(aerr, prov.ErrGone):
			// Already gone: nothing to remove, nothing to preserve.
		default:
			d.warnErr(aerr)
			d.say("uninstall", "  PRESERVED volume %s — see the reason above. Its record is kept.", name)
			preserved = true
		}
	}
	return preserved
}

// familyNetworks removes the network this installer CREATED, and only that one.
//
// A non-owned reference is attach-only and carries no deletion authority — it is the operator's
// network and is left alone. The provenance predicate cannot see a network REFERENCE record, so no
// path here can read one as something to remove.
func (s *session) familyNetworks(ctx context.Context, objs [][]ledger.Field) bool {
	d := s.d
	preserved := false
	for _, rec := range objs {
		if recClass(rec) != "network" {
			continue
		}
		name, nerr := recName(rec)
		if nerr != nil {
			d.warnErr(nerr)
			preserved = true
			continue
		}
		aerr := prov.Authority(ctx, s.l, prov.Engine(d.Engine), prov.ClassNetwork, name)
		switch {
		case aerr == nil:
			if rerr := s.rt.NetworkRemove(ctx, name); rerr != nil {
				d.warnErr(rerr)
				d.warn("  could NOT remove network %s — its record is kept.", name)
				preserved = true
				continue
			}
			d.say("uninstall", "  removed network %s.", name)
		case errors.Is(aerr, prov.ErrGone):
			// Already gone.
		default:
			d.warnErr(aerr)
			d.say("uninstall", "  PRESERVED network %s — see the reason above. Its record is kept.", name)
			preserved = true
		}
	}
	return preserved
}

// familyOperatorRef reports on the operator-supplied network, which is never removed. It returns
// whether the reset must be held back.
//
// AN UNREADABLE REFERENCE IS NOT "NONE CONFIGURED". Flattening the two would let the reset wipe the
// ledger that records the attachment while unable to read it. Fail closed: block the reset until
// repair.
func (s *session) familyOperatorRef() bool {
	d := s.d
	_, err := netref.RefGet(s.l)
	switch {
	case err == nil:
		d.say("uninstall", "  the operator-supplied network is LEFT ALONE — it was never this installer's to remove.")
		return false
	case errors.Is(err, netref.ErrNoReference):
		return false
	default:
		d.warnErr(err)
		d.warn("family: an operator-network reference is recorded but could not be read; the ledger is NOT")
		d.warn("  reset over it. Run 'mythical-ctl state repair', then re-run.")
		return true
	}
}

// familyImages names every image this installer pulled and removes none of them. Family uninstall
// is not an exemption from that rule: the ledger proves acquisition, not ownership, and another
// installation on this daemon may depend on the same digest.
func (s *session) familyImages(imgs [][]ledger.Field) {
	d := s.d
	var refs []string
	for _, rec := range imgs {
		if ref, ok := ledger.FieldOf(rec, "ref"); ok {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return
	}
	d.say("uninstall", "  Images are NOT removed, by this verb or any other:")
	for _, ref := range refs {
		d.say("uninstall", "    %s", ref)
	}
	d.say("uninstall", "  Reclaim the space yourself with: docker image prune")
}
