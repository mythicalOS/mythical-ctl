package verbs

// status — READ-ONLY, and it exits 0 even with bad news.
//
// An operator running it in a loop must not have their fleet mutated by the act of looking, and a
// monitoring wrapper needs it to SUCCEED in order to read its output. So it takes no family lock,
// starts nothing, and is never gated by its own findings: every refusal it meets is REPORTED as a
// refusal and the report continues.
//
// THE DISTINCTION THIS WHOLE FILE TURNS ON: an ANSWER ("absent", "gone", "not configured") is never
// the same fact as a REFUSAL ("the question could not be asked"). Reporting the second as the first
// tells an operator whose objects are orphaned that their machine is clean, which is the one wrong
// answer that costs them the recovery. Every read below therefore has three arms, not two.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/state"
)

// The two ledger record kinds the provenance module writes and the verb layer LISTS.
//
// They are named here rather than imported because provenance exposes selectors, not a listing —
// exactly as the reference's verbs call `mi_led_all object` / `mi_led_all image` themselves. The
// coupling is real, and it is covered rather than commented away: a rename on the provenance side
// would make these listings return nothing, and the tests that install a product and then read its
// volumes back out of status and out of --purge would go red on the spot.
const (
	kindObject = "object"
	kindImage  = "image"
)

// --- shared record readers -----------------------------------------------------------------------
//
// status REPORTS through these and `--purge` ACTS through them, so the two can never disagree about
// what a volume holds. One reader, two consumers — the reference's own reason for factoring them.

// volClass is the data class of one volume record, as a phrase for a report.
//
// ABSENCE IS NOT "REGENERABLE". A record with no `precious` field was written by a version of this
// installer that had no vocabulary for the distinction, or by an adoption path that lost it —
// either way this installation does not know, and "unknown" must read as unrecoverable. The
// opposite default is the one that costs data, and it costs it silently: the operator sees a volume
// listed as regenerable, purges, and finds out afterwards. Only an EXPLICIT `precious=0` is a claim
// that the contents can be rebuilt.
func volClass(rec []ledger.Field) string {
	switch v, _ := ledger.FieldOf(rec, "precious"); v {
	case "0":
		return "regenerable"
	case "1":
		return "UNREGENERABLE"
	default:
		return "UNREGENERABLE (unclassified)"
	}
}

// volPrecious is true iff this volume must be treated as holding unrecoverable data — including
// when it says nothing.
func volPrecious(rec []ledger.Field) bool {
	v, _ := ledger.FieldOf(rec, "precious")
	return v != "0"
}

// recordsOf fully reads one kind of ledger record for a MUTATING verb, FAILING CLOSED if the
// listing is not complete.
//
// A verb that loops over a listing it could not fully read skips every object it should have acted
// on: family uninstall would reset the ledger over containers it never removed; `uninstall --purge`
// would leave volumes behind and still exit 0. The ledger's own lister already refuses an
// incomplete listing; this names what that means for the operation about to run.
func recordsOf(l *ledger.Ledger, kind string) ([][]ledger.Field, error) {
	recs, err := l.All(kind)
	if err != nil {
		return nil, fmt.Errorf("verbs: the ledger's %q records could not be fully read, so this operation cannot see\n"+
			"  every object it must act on. Refusing rather than acting on a partial view of the ledger.\n"+
			"  Run 'mythical-ctl state repair': %w", kind, err)
	}
	return recs, nil
}

// recClass / recName read the two fields every object record is selected by.
func recClass(rec []ledger.Field) string {
	v, _ := ledger.FieldOf(rec, "class")
	return v
}

// recName is the name of a class-matched object record, or an error if it has none.
//
// A record that passes the listing's field-format check can still be missing a SEMANTIC field like
// `name=` — and skipping such a record silently meant, in a mutating family verb, that the object
// was neither removed nor counted as preserved, so the ledger reset wiped its provenance while it
// still stood. Callers FAIL CLOSED on the error, never skip.
func recName(rec []ledger.Field) (string, error) {
	n, ok := ledger.FieldOf(rec, "name")
	if !ok {
		return "", errors.New("verbs: an object record carries no readable name — it cannot be acted on. The ledger is not\n" +
			"  reset over it. Run 'mythical-ctl state repair'.")
	}
	return n, nil
}

// --- the report ----------------------------------------------------------------------------------

// statusSeams are the three READ-ONLY runtime views the report needs. Each is nil when there is no
// container runtime connection at all — which is a state status must survive and REPORT, not one it
// may panic on or quietly render as an empty fleet.
type statusSeams struct {
	objs  prov.Objects
	ints  intent.Objects
	state state.Objects
}

// Status reports the installation: identity, network, any migration in flight, every product with
// its desired/observed state and what it still owes, every named VOLUME with its role, data class
// and ownership, pending intents, and the objects that account for nothing.
//
// IT TAKES NO INDEX. The reference's signature carries one and its body never reads it; carrying a
// parameter here that nothing consumes would invite a later reader to authenticate a document
// inside a verb documented to start nothing and mutate nothing.
//
// It always returns 0. There is no finding that gates it.
func Status(ctx context.Context, d Deps, products []string) int {
	var s statusSeams
	if d.Engine == nil {
		// NOT A REFUSAL AND NOT A PANIC. The ledger half of the report is still readable and still
		// worth printing; what cannot be observed is named as unobservable rather than invented.
		d.say("status", "runtime:      UNAVAILABLE — there is no container runtime connection, so nothing below can")
		d.say("status", "  be observed. Live answers are reported as unknown rather than invented.")
	} else {
		s = statusSeams{objs: prov.Engine(d.Engine), ints: intent.Engine(d.Engine), state: state.Engine(d.Engine)}
	}

	// THE LEDGER IS READ WITHOUT THE FAMILY LOCK. status mutates nothing, and a report that waited
	// on a wedged verb's lock could not diagnose the wedge it was run to diagnose.
	l, lerr := ledger.Read(ledger.LiveRead(d.Home))
	switch {
	case errors.Is(lerr, ledger.ErrMissingLedger):
		l = &ledger.Ledger{}
	case lerr != nil:
		d.warnErr(lerr)
		d.say("status", "installation: UNREADABLE — the installer state ledger is present and could not be read (see")
		d.say("status", "  the warning above). This is NOT 'nothing installed'; objects this installation named may")
		d.say("status", "  be orphaned. Run 'mythical-ctl state repair'.")
		return cliio.ExitOK
	}

	ident, ok := statusIdentity(d, l)
	if !ok {
		return cliio.ExitOK
	}
	statusNetwork(d, l, ident)
	statusMigration(d, l)
	statusObjects(ctx, d, s, l, ident, products)
	statusIntents(d, l)
	statusUnaccounted(ctx, d, s, l)
	return cliio.ExitOK
}

// statusIdentity reports the installation identity, distinguishing ABSENT from UNREADABLE. The
// bool reports whether the rest of the report can be produced at all: everything below is scoped by
// the identity, so there is nothing further to say without one.
func statusIdentity(d Deps, l *ledger.Ledger) (string, bool) {
	ident, err := l.IdentGet()
	switch {
	case err == nil:
		d.say("status", "installation: %s", ident)
		return ident, true
	case errors.Is(err, ledger.ErrAbsentRecord):
		d.say("status", "No installation state found. Nothing has been installed yet.")
		return "", false
	default:
		// AN IDENTITY THAT IS RECORDED BUT UNREADABLE (corrupt, ambiguous, or empty) IS NOT
		// "NOTHING INSTALLED". Reporting the second for the first tells an operator whose objects
		// are actually orphaned that they are clean; they are sent to repair instead.
		d.warnErr(err)
		d.say("status", "installation: UNREADABLE — an identity is recorded but could not be read (see the warning")
		d.say("status", "  above). This is NOT 'nothing installed'; objects this installation named may be orphaned.")
		d.say("status", "  Run 'mythical-ctl state repair'.")
		return "", false
	}
}

// statusNetwork reports THE network this family is on: the operator's, or the installer's own.
func statusNetwork(d Deps, l *ledger.Ledger, ident string) {
	ref, err := netref.RefGet(l)
	switch {
	case err == nil:
		d.say("status", "network:      %s (operator-supplied, attach-only — this installer will never remove it)", ref)
		return
	case errors.Is(err, netref.ErrNoReference):
		// No operator network is configured: fall through to the installer-owned one below.
	default:
		// AN OPERATOR NETWORK **IS** CONFIGURED AND ITS RECORD CANNOT BE READ. Hiding that behind
		// the installer-owned "not created yet" would tell the operator to create a network they
		// already pointed this installation at.
		d.warnErr(err)
		d.say("status", "network:      UNREADABLE — an operator network reference is recorded but could not be read")
		d.say("status", "  (see the warning above); this is not an absent network. Run 'mythical-ctl state repair'.")
		return
	}

	nname, nerr := manifest.NetworkName(ident)
	if nerr != nil {
		d.warnErr(nerr)
		d.say("status", "network:      UNREADABLE — the installer-owned network name cannot be derived from this")
		d.say("status", "  installation's identity. Run 'mythical-ctl state repair'.")
		return
	}
	rec, ferr := prov.Find(l, prov.ClassNetwork, nname)
	switch {
	case ferr == nil:
		// A RECORD THAT EXISTS AND NAMES NO NETWORK IS NOT A NETWORK. Printing an empty id reads as
		// a created network whose id happens not to render.
		if id, ok := ledger.FieldOf(rec, "id"); ok && id != "" {
			d.say("status", "network:      %s (%s, created by this installer)", id, nname)
			return
		}
		d.say("status", "network:      UNREADABLE — the record for %q exists but carries no id. Run", nname)
		d.say("status", "  'mythical-ctl state repair'.")
	case errors.Is(ferr, ledger.ErrAbsentRecord):
		d.say("status", "network:      not created yet")
	default:
		// Same distinction one level in: no record is "not created yet", but a record that cannot
		// be read must not be flattened into it — that tells an operator with a corrupt network
		// record that no network exists, and invites a second one.
		d.warnErr(ferr)
		d.say("status", "network:      UNREADABLE — the record for %q could not be read (see the warning", nname)
		d.say("status", "  above); this is not an absent network. Run 'mythical-ctl state repair'.")
	}
}

// statusMigration reports a network migration in flight. No migration is the normal case and prints
// nothing; a migration that is RECORDED but cannot be trusted must not be swallowed the same way —
// that would let status describe a normal network while the fleet is spread across two.
func statusMigration(d Deps, l *ledger.Ledger) {
	mig, err := netref.MigGet(l)
	switch {
	case errors.Is(err, netref.ErrNoMigration):
		return
	case err == nil && mig.Source != "" && mig.Target != "":
		d.say("status", "NETWORK MIGRATION IN PROGRESS — phase %d", mig.Phase)
		d.say("status", "  source %s → target %s", mig.Source, mig.Target)
		d.say("status", "  Containers are on both networks; family DNS resolves on either. Resume with 'net rebind'.")
	case errors.Is(err, ledger.ErrAmbiguous):
		d.warnErr(err)
		d.say("status", "NETWORK MIGRATION record UNREADABLE — a migration is recorded but its record could not be")
		d.say("status", "  read. Status of the network cannot be trusted. Run 'mythical-ctl state repair'.")
	default:
		// ONE record answered, and it does not describe a migration: a missing or out-of-range
		// phase, no container set, or a blank source or target. Printing a blank phase/source/
		// target reads as a usable migration, which is the one thing this must not produce.
		d.warnErr(err)
		d.say("status", "NETWORK MIGRATION record UNREADABLE — a migration is recorded but is missing fields, so its")
		d.say("status", "  state cannot be trusted. Run 'mythical-ctl state repair'.")
	}
}

// statusObjects reports the products and their named volumes, off ONE reading of the object
// listing.
//
// AN UNREADABLE LISTING IS REPORTED, NEVER RENDERED AS AN EMPTY FLEET. A monitor reading "no
// products" off a corrupt ledger is worse than one reading "UNREADABLE": the first is a conclusion,
// the second is a question. status is not gated by the finding — it says so and carries on.
func statusObjects(ctx context.Context, d Deps, s statusSeams, l *ledger.Ledger, ident string, products []string) {
	forced, ferr := l.All(kindForced)
	if ferr != nil {
		d.warnErr(ferr)
		d.say("status", "note:         the override / force-install annotations could not be read — repair advised.")
		forced = nil
	}
	objs, oerr := l.All(kindObject)
	if oerr != nil {
		d.warnErr(oerr)
		d.say("status", "products:     UNREADABLE — the installed-object records could not be fully read, so this")
		d.say("status", "  listing would omit products. Run 'mythical-ctl state repair'.")
		return
	}
	statusContainers(ctx, d, s, l, objs, forced, ident, products)
	statusVolumes(ctx, d, s, l, objs, products)
}

func statusContainers(ctx context.Context, d Deps, s statusSeams, l *ledger.Ledger,
	objs, forced [][]ledger.Field, ident string, products []string) {
	for _, rec := range objs {
		if recClass(rec) != "container" {
			continue
		}
		// A CONTAINER RECORD WITH NO READABLE NAME IS CORRUPT, NOT ABSENT. Skipping past it would
		// let status show no product while its provenance stands and needs repair.
		c, ok := ledger.FieldOf(rec, "name")
		if !ok {
			d.say("status", "product:      UNREADABLE — an installed-container record carries no name. Run 'mythical-ctl")
			d.say("status", "  state repair'.")
			continue
		}
		// The container's provenance record does not carry the product: bring-up opens its
		// write-ahead intent before the product name is in scope, so the confirmation writes no
		// `product` field. Derive it from the installation-scoped container name, which is the same
		// value the product filter and the annotation lookup below key on.
		product, _ := ledger.FieldOf(rec, "product")
		if product == "" {
			product = strings.TrimPrefix(c, manifest.NamePrefix+"-"+ident+"-")
		}
		if !selected(products, product) {
			continue
		}
		d.say("status", "%s: desired=%s observed=%s outstanding=%s next=%s",
			product, desiredOf(l, c), observedOf(ctx, s, c), outstandingOf(l, c), planOf(ctx, s, l, c))
		statusAnnotations(d, forced, product)
	}
}

// statusAnnotations reports the two install-time annotations for one product.
func statusAnnotations(d Deps, forced [][]ledger.Field, product string) {
	for _, fr := range forced {
		if p, _ := ledger.FieldOf(fr, "product"); p != product {
			continue
		}
		switch kind, _ := ledger.FieldOf(fr, "kind"); kind {
		case "image-override":
			ref, _ := ledger.FieldOf(fr, "ref")
			d.say("status", "  image override in effect — running %s instead of the manifest's pinned image", ref)
		case "force-install":
			d.say("status", "  installed with --force-install (the manifest said not launched)")
		}
	}
}

// statusVolumes reports every named volume: presence, role, whether its contents can be rebuilt,
// and provenance — deliberately NOT SIZE.
//
// THE HOST CANNOT READ A NAMED VOLUME'S CONTENTS and the runtime reports no size for one, so any
// number printed here would have to be invented or obtained by starting a container — and status
// starts nothing. An invented number in a report an operator reads before deciding whether to purge
// is worse than no number: it is a number they would act on.
//
// The provenance predicate is the SANCTIONED one, reused rather than re-derived. It is silent when
// a volume checks out, so its diagnostics appear only when something genuinely is wrong — which is
// precisely what this report exists to surface.
func statusVolumes(ctx context.Context, d Deps, s statusSeams, l *ledger.Ledger, objs [][]ledger.Field, products []string) {
	for _, rec := range objs {
		if recClass(rec) != "volume" {
			continue
		}
		name, ok := ledger.FieldOf(rec, "name")
		if !ok {
			d.say("status", "volume:       UNREADABLE — a volume record carries no name. Run 'mythical-ctl state repair'.")
			continue
		}
		product, _ := ledger.FieldOf(rec, "product")
		// The same product filter the container loop applies, so `status <product>` stays scoped. A
		// volume record with no readable product is shown UNFILTERED rather than hidden: it is
		// exactly the record an operator needs to see, and silently dropping it from a filtered
		// view is how an unattributable volume becomes invisible.
		if product != "" && !selected(products, product) {
			continue
		}
		role, _ := ledger.FieldOf(rec, "role")
		if role == "" {
			role = "?"
		}
		shown := product
		if shown == "" {
			shown = "?"
		}
		head := fmt.Sprintf("volume %s: role=%s data=%s product=%s", name, role, volClass(rec), shown)
		aerr := prov.Authority(ctx, l, s.objs, prov.ClassVolume, name)
		switch {
		case aerr == nil:
			d.say("status", "%s — present, created by this installation", head)
		case errors.Is(aerr, prov.ErrGone):
			d.say("status", "%s — recorded but GONE from the runtime", head)
		default:
			d.warnErr(aerr)
			d.say("status", "%s — provenance NOT established (see above); 'uninstall --purge' will preserve it", head)
		}
	}
}

// statusIntents reports the intents that are open — so a wedge is visible rather than mysterious.
func statusIntents(d Deps, l *ledger.Ledger) {
	all, err := intent.All(l)
	if err != nil {
		d.warnErr(err)
		d.say("status", "PENDING:      UNREADABLE — the intent records could not be read. Run 'mythical-ctl state repair'.")
		return
	}
	for _, rec := range all {
		class, _ := ledger.FieldOf(rec, "class")
		name, _ := ledger.FieldOf(rec, "name")
		d.say("status", "PENDING: %s %s — created and not yet confirmed", class, name)
	}
}

// statusUnaccounted reports the objects the ledger does not account for. REPORTED, NEVER ACTIONED:
// this is the one place an operator sees them, and status proposes removing none of them.
func statusUnaccounted(ctx context.Context, d Deps, s statusSeams, l *ledger.Ledger) {
	for _, f := range intent.UnaccountedScan(ctx, l, s.ints) {
		switch f.Kind {
		case intent.FindingUnattributed:
			d.say("status", "unattributed %s: %s", string(f.Class), f.Name)
			d.say("status", "  Carries a mythicalOS installation label that is not this installation's. It may belong")
			d.say("status", "  to another user on this daemon. Diagnostic only.")
		case intent.FindingUnrecorded:
			d.say("status", "unrecorded %s: %s", string(f.Class), f.Name)
			d.say("status", "  Labelled for THIS installation but absent from the ledger. Mutating operations will")
			d.say("status", "  stop until this is resolved — run 'state repair'.")
		case intent.FindingColliding:
			d.say("status", "name collision, %s: %s (unlabelled, holds a name this installer would create)", string(f.Class), f.Name)
		case intent.FindingUnasked:
			// THE REFERENCE'S CASE STATEMENT HAD NO ARM FOR THIS AND DROPPED IT ON THE FLOOR. A
			// question that could not be asked is the finding an operator most needs from a
			// diagnostic — silence here reads as "the scan found nothing", which is the one
			// conclusion a failed scan must never produce.
			what := fmt.Sprintf("%s %q could not be asked about", string(f.Class), f.Name)
			if f.Name == "-" {
				what = fmt.Sprintf("the %s could not be asked for", string(f.Class))
			}
			d.say("status", "UNACCOUNTED SCAN INCOMPLETE — %s, so nothing here can be shown to be accounted for.", what)
			d.say("status", "  An empty answer and no answer are not the same fact. Start the container runtime and re-run.")
		}
	}
}

// --- the per-container reads ----------------------------------------------------------------------
//
// Each returns a PHRASE, and each keeps its three arms apart: a recorded answer, a legitimate
// absence, and a read that could not be performed. The reference folded the third into the second
// for the outstanding set (`|| true` under pipefail), which reported a container that owes checks
// nobody can enumerate as one that owes none — the reassuring direction. Here it says so.

func desiredOf(l *ledger.Ledger, container string) string {
	want, err := state.DesiredGet(l, container)
	switch {
	case err == nil:
		return string(want)
	case errors.Is(err, ledger.ErrAbsentRecord):
		return "(none)"
	default:
		return "(unreadable)"
	}
}

func observedOf(ctx context.Context, s statusSeams, container string) string {
	if s.state == nil {
		return "(unknown)"
	}
	obs, err := state.Observe(ctx, s.state, container)
	if err != nil {
		return "(unknown)"
	}
	return string(obs)
}

func outstandingOf(l *ledger.Ledger, container string) string {
	out, err := state.Outstanding(l, container)
	if err != nil {
		return "UNREADABLE"
	}
	if len(out) == 0 {
		return "none"
	}
	kinds := make([]string, 0, len(out))
	for _, c := range out {
		kinds = append(kinds, string(c.Kind))
	}
	// The reference piped the kinds through `tr '\n' ','`, which left a trailing comma; the same
	// information, joined.
	return strings.Join(kinds, ",")
}

func planOf(ctx context.Context, s statusSeams, l *ledger.Ledger, container string) string {
	if s.state == nil {
		return "?"
	}
	p, err := state.PlanFor(ctx, l, s.state, container)
	if err != nil {
		return "?"
	}
	return string(p)
}

// selected applies the product filter. An empty filter selects everything.
func selected(products []string, product string) bool {
	if len(products) == 0 {
		return true
	}
	for _, p := range products {
		if p == product {
			return true
		}
	}
	return false
}
