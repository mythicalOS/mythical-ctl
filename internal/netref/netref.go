// Package netref decides WHICH network the family joins, records that decision, and moves the
// fleet when it changes.
//
// Two kinds of network exist and they are not interchangeable. An INSTALLER-OWNED network is
// created by this installation, recorded as provenance, and removable by it. An OPERATOR-SUPPLIED
// network (MYTHICAL_NET) is referenced by id and is ATTACH-ONLY: it is never authorized for
// deletion, because the installer did not create it and cannot know what else depends on it.
//
// A NETWORK IS REFERENCED BY ITS ID, never by its name (§6a rejects names as reassignable). Every
// refusal in this package follows from that: a name that now resolves to a different id is a
// REPLACED network, not a renamed one, and recording the new id alone would leave the fleet on the
// old network with every product reporting healthy.
package netref

import (
	"context"
	"errors"
	"fmt"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"time"
)

const (
	kindNetRef = "netref"
	kindNetMig = "netmig"
)

// NetAttach is one resolved network attachment of a container: the network's ID and this
// container's endpoint address on it.
type NetAttach struct {
	NetworkID string
	Address   string
}

// Objects is the read side.
type Objects interface {
	// NetworkID resolves a reference (id or name) to the network's id. engine.ErrAbsent means no
	// such network; any other error means the question could not be asked.
	NetworkID(ctx context.Context, ref string) (string, error)
	// NetworkNames lists every network name, unfiltered — the only way to see that TWO networks
	// answer one name, which a resolve-by-name can never reveal on its own.
	NetworkNames(ctx context.Context) ([]string, error)
	// NetworksByInstall / ContainersByInstall list this installation's own objects by label.
	NetworksByInstall(ctx context.Context, ident string) ([]string, error)
	ContainersByInstall(ctx context.Context, ident string) ([]string, error)
	// ContainerNets lists a container's attachments with the network IDs RESOLVED — a
	// never-started container's endpoint carries an empty NetworkID and only the name identifies
	// it, so resolution has to happen before any comparison.
	ContainerNets(ctx context.Context, container string) ([]NetAttach, error)
}

// Mutator is the write side. *runtime.Runtime satisfies it, which is how the family lock stays on
// the path — this package never holds a Mutator of its own.
type Mutator interface {
	NetworkCreate(ctx context.Context, name string, p engine.Provenance) (string, error)
	NetworkConnect(ctx context.Context, networkID, containerID, alias string, gwPriority int) error
	NetworkDisconnect(ctx context.Context, networkID, containerID string) error
}

// Deps carries what this package cannot derive: a clock, a nonce source, and the intent layer's
// runtime seam. They are PARAMETERS rather than package state because the migration machine's
// refusals turn on them — a test has to be able to hand it a stopped clock and a runtime that
// answers a particular way, and production hands it the real ones.
type Deps struct {
	// Intent is the read seam intent.Reconcile needs. *intent's engine wrapper satisfies it.
	Intent intent.Objects
	// Configured is MYTHICAL_NET as mythical.conf holds it (empty when unset) — READ BY THE
	// CALLER, because this package never touches the config file: the config reader is the one
	// authority on what that file says, and a second reader here would be a second answer.
	Configured string
	// NewNonce mints a fresh object nonce.
	NewNonce func() (string, error)
	// Now reads the clock — the creation time an intent carries.
	Now func() time.Time
	// Persist commits THE LEDGER IT IS GIVEN to disk. REQUIRED, and it is the whole of the
	// write-ahead guarantee.
	//
	// IT TAKES THE LEDGER rather than closing over one: a closure captured at construction stays
	// bound to the ledger that existed then, so a caller that reloads and reuses its Deps gets a
	// Persist that writes the OLD copy, reports success, and lets the runtime mutation proceed
	// with the new copy's marker never written.
	//
	// Nothing in this package reaches disk: it mutates a *ledger.Ledger the caller owns. So an
	// intent "opened before the network is created", and a migration phase "recorded before the
	// phase acts", are only true if the ledger is PERSISTED in between — and the caller cannot do
	// that itself, because these functions perform the runtime mutation internally. Without this
	// seam a crash after the daemon accepts a create leaves an unaccounted network, and a crash
	// part-way through a detach phase leaves a fleet whose recorded phase is behind reality, which
	// resume cannot move forward from.
	//
	// It lives here rather than being a ledger.Write call because writing requires the family-lock
	// token, which the caller holds.
	Persist func(*ledger.Ledger) error
}

// staged runs edit on a COPY of l, persists the copy, and only then publishes it into l — so a
// failed write leaves the caller's ledger byte-identical and a retry sees the world it left. A nil
// Persist is refused rather than skipped: silently proceeding would restore the defect this seam
// closes, invisibly.
func staged(d Deps, l *ledger.Ledger, what string, edit func(*ledger.Ledger) error) error {
	if d.Persist == nil {
		return fmt.Errorf("netref: refusing to %s with no way to persist the record written ahead of it —\n"+
			"  the record would exist only in memory, and a crash would leave the fleet in a state\n"+
			"  nothing can resume from", what)
	}
	cp := l.Clone()
	if err := edit(cp); err != nil {
		return err
	}
	if err := d.Persist(cp); err != nil {
		return fmt.Errorf("netref: the record written ahead of %s could not be persisted, so nothing is done: %w", what, err)
	}
	return l.Adopt(cp)
}

var (
	// ErrNoReference — no operator-network reference is recorded. An ANSWER (the installer's own
	// network is the target), never a refusal.
	ErrNoReference = errors.New("netref: no operator network reference is recorded")
	// ErrNoMigration — no migration is recorded. Also an answer.
	ErrNoMigration = errors.New("netref: no network migration is recorded")
)

type engineObjects struct {
	c *engine.Client
}

// Engine wraps a client as the read seam.
func Engine(c *engine.Client) Objects { return engineObjects{c: c} }

func (e engineObjects) NetworkID(ctx context.Context, ref string) (string, error) {
	info, err := e.c.NetworkInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	return info.ID, nil
}

func (e engineObjects) NetworkNames(ctx context.Context) ([]string, error) {
	rows, err := e.c.NetworkList(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out, nil
}

func (e engineObjects) NetworksByInstall(ctx context.Context, ident string) ([]string, error) {
	rows, err := e.c.NetworkList(ctx, map[string]string{"installation": ident})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out, nil
}

func (e engineObjects) ContainersByInstall(ctx context.Context, ident string) ([]string, error) {
	rows, err := e.c.ContainerList(ctx, map[string]string{"installation": ident})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Names...)
	}
	return out, nil
}

func (e engineObjects) ContainerNets(ctx context.Context, container string) ([]NetAttach, error) {
	info, err := e.c.ContainerInspect(ctx, container)
	if err != nil {
		return nil, err
	}
	pairs, err := runtime.ResolveNetPairs(ctx, e.c, info)
	if err != nil {
		return nil, err
	}
	out := make([]NetAttach, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, NetAttach{NetworkID: p.ID, Address: p.Addr})
	}
	return out, nil
}

// --- the installer-owned network -----------------------------------------------------------------

// adoptOwned reads the recorded owned network and proves it is STILL THERE, by its id.
//
// Recreating it silently would strand every attached container on a network the ledger no longer
// names, with every product reporting healthy — so every answer other than "the recorded id is
// answered by itself" refuses.
//
// `rec` COMES FROM prov.Find, WHICH HAS ALREADY PROVED IT DESCRIBES `name`. That question used to
// be asked here, because a record keyed for this name while describing something else supplies
// THAT object's id — and this function's answer is the network the whole family is then attached
// to, so the fleet would join a network the ledger never named. It is asked at the lookup now, for
// every consumer of a keyed record rather than the two that remembered; both call sites below
// report the refusal as itself. (The reference reads `id` without asking at all; the same latent
// blind spot as its sibling in the migration alias path.)
func adoptOwned(ctx context.Context, objs Objects, rec []ledger.Field, name string) (string, error) {
	id, ok := ledger.FieldOf(rec, "id")
	if !ok {
		return "", errors.New("netref: the recorded family network carries no id. A network is recorded BY its id (§6a\n" +
			"  rejects names as reassignable), so this record names nothing the runtime can be asked\n" +
			"  about — and creating one now would stand a second network beside whatever it describes.\n" +
			"  It is PRESERVED and reported. Run 'mythical-ctl state repair'.")
	}
	if id == "" {
		return "", errors.New("netref: the recorded family network carries an EMPTY id — it says a network was created\n" +
			"  without saying which. It is PRESERVED and reported, never created over.\n" +
			"  Run 'mythical-ctl state repair'.")
	}
	actual, err := objs.NetworkID(ctx, id)
	switch {
	case err == nil && actual == id:
		return id, nil
	case errors.Is(err, engine.ErrAbsent):
		return "", fmt.Errorf("netref: the recorded family network (%s) no longer exists.\n%s", id, repairOrStrand)
	case err != nil:
		return "", fmt.Errorf("netref: the recorded family network (%s) could not be inspected, so whether it is still\n"+
			"  there was never established.\n%s: %w", id, repairOrStrand, err)
	}
	return "", fmt.Errorf("netref: the recorded family network id (%s) is answered by %q.\n%s", id, actual, repairOrStrand)
}

const repairOrStrand = "  Run 'mythical-ctl state repair' — recreating it silently would strand every attached\n" +
	"  container on a network the ledger no longer names, with every product reporting healthy."

// OwnedEnsure returns this installation's own family network id, creating it exactly once.
//
// A NETWORK IS NEVER REISSUED (D38), so every step that cannot establish what is already there
// refuses rather than creating: a second create is precisely the duplicate that rule prevents.
func OwnedEnsure(ctx context.Context, l *ledger.Ledger, objs Objects, m Mutator, d Deps) (string, error) {
	ident, err := l.IdentGet()
	if err != nil {
		return "", err
	}
	name, err := manifest.NetworkName(ident)
	if err != nil {
		return "", err
	}
	rec, ferr := prov.Find(l, prov.ClassNetwork, name)
	switch {
	case ferr == nil:
		return adoptOwned(ctx, objs, rec, name)
	case errors.Is(ferr, ledger.ErrAbsentRecord):
	case errors.Is(ferr, prov.ErrMismatch):
		// A record that answers for this name and describes another object is reported as itself.
		// It is not "could not be read": the ledger read fine and holds a contradiction, and a
		// network is never reissued, so nothing is created either way.
		return "", ferr
	default:
		return "", fmt.Errorf("netref: whether this installation already has a family network could not be read from\n"+
			"  the ledger. Creating one now would stand a second network beside whatever is\n"+
			"  recorded. Nothing is created. Run 'mythical-ctl state repair': %w", ferr)
	}
	// A create may already be UNDER WAY. Reconcile it rather than starting a second one.
	_, ierr := intent.Find(l, prov.ClassNetwork, name)
	switch {
	case errors.Is(ierr, ledger.ErrAbsentRecord):
	case ierr == nil:
		if rerr := intent.Reconcile(ctx, l, d.Intent, nil, prov.ClassNetwork, name); rerr != nil {
			return "", rerr
		}
		rec, ferr = prov.Find(l, prov.ClassNetwork, name)
		if errors.Is(ferr, prov.ErrMismatch) {
			return "", ferr
		}
		if ferr != nil {
			return "", fmt.Errorf("netref: the network intent reconciled, but no provenance record can be read for it.\n"+
				"  Nothing is created over it. Run 'mythical-ctl state repair': %w", ferr)
		}
		return adoptOwned(ctx, objs, rec, name)
	default:
		return "", fmt.Errorf("netref: whether a network create was already under way could not be read from the\n"+
			"  ledger. A network is never reissued (D38), and starting a second create here is\n"+
			"  exactly the duplicate that rule exists to prevent. Nothing is created: %w", ierr)
	}

	nonce, err := d.NewNonce()
	if err != nil {
		return "", err
	}
	p, err := engine.NewProvenance(ident, nonce)
	if err != nil {
		return "", err
	}
	// THE INTENT IS DURABLE BEFORE THE NETWORK EXISTS, and the open and the write are ONE step. A
	// network is never reissued (D38), so an unaccounted one created by a crashed run is not
	// something a later run can create its way out of — it has to be found by this record. And a
	// FAILED write must leave no intent behind either, or the retry finds one and refuses under
	// D38 rather than creating the network that was never created.
	if err := staged(d, l, "create the family network", func(c *ledger.Ledger) error {
		return intent.Open(c, prov.ClassNetwork, name, nonce, d.Now())
	}); err != nil {
		return "", err
	}
	id, cerr := m.NetworkCreate(ctx, name, p)
	if cerr != nil {
		return "", fmt.Errorf("netref: creating the family network failed. The intent is retained and reconciled later: %w", cerr)
	}
	if id == "" {
		return "", errors.New("netref: the runtime named no id for the network it created. A network is recorded BY its\n" +
			"  id, so there is nothing to confirm; the intent is RETAINED and reconciled later.")
	}
	// A DUPLICATE CREATE CANNOT BE RULED OUT WITHOUT ASKING, and an unasked question is not a
	// clean answer: the intent stays open rather than confirming one of two networks.
	mine, lerr := objs.NetworksByInstall(ctx, ident)
	if lerr != nil {
		return "", fmt.Errorf("netref: the runtime could not be asked which networks carry this installation's identity,\n"+
			"  so a duplicate create cannot be ruled out. The intent is RETAINED and nothing is\n"+
			"  confirmed: %w", lerr)
	}
	if len(mine) > 1 {
		return "", fmt.Errorf("netref: more than one network carries this installation's identity. Stopping.\n"+
			"  This can only come from a duplicate create and cannot be safely disambiguated.\n    %v", mine)
	}
	if err := intent.Confirm(l, prov.ClassNetwork, name, nonce, ledger.Field{Key: "id", Value: id}); err != nil {
		return "", err
	}
	return id, nil
}

// --- the operator-supplied reference -------------------------------------------------------------

// RefGet returns the recorded operator-network id. ErrNoReference means none is recorded.
func RefGet(l *ledger.Ledger) (string, error) {
	rec, err := l.Find(kindNetRef, "key", "family")
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return "", ErrNoReference
	}
	if err != nil {
		return "", err
	}
	id, ok := ledger.FieldOf(rec, "id")
	if !ok {
		return "", errors.New("netref: the recorded network reference carries no id — it says this installation was\n" +
			"  pointed at an operator's network without saying which one. It is PRESERVED and\n" +
			"  reported. Run 'mythical-ctl state repair'.")
	}
	if id == "" {
		return "", errors.New("netref: the recorded network reference carries an EMPTY id, which names no network the\n" +
			"  runtime can be asked about. It is PRESERVED and reported.\n" +
			"  Run 'mythical-ctl state repair'.")
	}
	return id, nil
}

// RefResolve turns a network NAME into exactly one id, or refuses.
//
// The ambiguity check is why this lists names rather than inspecting the name directly: an inspect
// answers with whichever network the daemon reached first, and attaching to that is how a family
// joins a network the operator did not mean.
func RefResolve(ctx context.Context, objs Objects, name string) (string, error) {
	if name == "" {
		return "", errors.New("netref: an empty network name names nothing, so nothing is resolved.")
	}
	all, err := objs.NetworkNames(ctx)
	if err != nil {
		return "", fmt.Errorf("netref: the container runtime could not be asked which networks exist, so %q can be\n"+
			"  neither resolved nor shown to be absent. Nothing is resolved: %w", name, err)
	}
	count := 0
	for _, n := range all {
		if n == name {
			count++
		}
	}
	if count == 0 {
		return "", fmt.Errorf("netref: no network named %q exists.", name)
	}
	if count > 1 {
		return "", fmt.Errorf("netref: more than one network is named %q. The reference is AMBIGUOUS, and the\n"+
			"  operation stops rather than picking one — attaching to whichever answered first is how\n"+
			"  a family joins a network the operator did not mean.", name)
	}
	id, err := objs.NetworkID(ctx, name)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("netref: the runtime named no id for network %q. A network is referenced BY its id\n"+
			"  (§6a rejects names as reassignable), so there is nothing to record.", name)
	}
	return id, nil
}

// RefCommit records the operator-network reference, and refuses one that does not match where the
// containers actually are.
//
// `configured` is MYTHICAL_NET as mythical.conf holds it (empty when unset) — read by the caller,
// because this package never touches the config file.
func RefCommit(ctx context.Context, l *ledger.Ledger, objs Objects, target, configured string) error {
	if target == "" {
		return errors.New("netref: refusing to record a network reference with no id.")
	}
	if configured == "" {
		return errors.New("netref: MYTHICAL_NET is not set, so there is no operator network to record a reference to.\n" +
			"  A reference recorded with no name is one nothing can ever re-verify. Nothing was\n" +
			"  written. Set MYTHICAL_NET, or use the installer's own network.")
	}
	now, err := RefResolve(ctx, objs, configured)
	if err != nil {
		return fmt.Errorf("netref: MYTHICAL_NET names %q, which does not resolve to exactly one network, so no\n"+
			"  reference is recorded. Fix the configuration and re-run: %w", configured, err)
	}
	if now != target {
		return fmt.Errorf("netref: MYTHICAL_NET names %q, which resolves to %s — but the network being\n"+
			"  recorded is %s. Refusing to record a reference that does not match where the\n"+
			"  containers actually are. Decide which network you want and re-run.", configured, now, target)
	}
	return l.Put(kindNetRef, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "id", Value: target},
		{Key: "name", Value: configured},
		{Key: "owned", Value: "no"},
	})
}

// RefVerify checks the recorded reference against the configuration and the runtime. A name that
// now resolves to a DIFFERENT id means the operator replaced the network underneath this
// installation — reported, never silently rebound.
func RefVerify(ctx context.Context, l *ledger.Ledger, objs Objects, configured string) error {
	recorded, err := RefGet(l)
	if err != nil {
		return err
	}
	if configured == "" {
		return errors.New("netref: a non-owned network reference is recorded, but MYTHICAL_NET is no longer set.\n" +
			"  Stopping. To adopt the installer's own network instead, remove the reference with a\n" +
			"  confirmed rebind: 'mythical-ctl net rebind'.")
	}
	now, rerr := RefResolve(ctx, objs, configured)
	if rerr != nil {
		return fmt.Errorf("netref: MYTHICAL_NET names %q, which does not resolve to exactly one network.\n"+
			"  Stopping. 'mythical-ctl net rebind' offers an explicitly confirmed rebind once the\n"+
			"  network exists again: %w", configured, rerr)
	}
	if now != recorded {
		return fmt.Errorf("netref: %q now resolves to a different network.\n"+
			"    recorded: %s\n    now:      %s\n"+
			"  The operator has replaced the network underneath this installation. Stopping.\n"+
			"  'mythical-ctl net rebind' performs a confirmed rebind — which re-attaches EVERY existing\n"+
			"  container to the new id and verifies each, because recording the new id alone would\n"+
			"  leave the fleet on the old network with every product reporting healthy.", configured, recorded, now)
	}
	return nil
}

// Target decides which network this family joins, and is the ONE function the launch path calls.
//
// The two SPLIT refusals are the heart of it: adding MYTHICAL_NET to an installation that already
// has its own network with the fleet on it, and removing it from one whose fleet is on the
// operator's, would each put new containers on one network and leave the existing ones on another.
// Both demand a confirmed rebind, which MOVES the fleet.
func Target(ctx context.Context, l *ledger.Ledger, objs Objects, m Mutator, configured string, configuredSet bool, d Deps) (string, error) {
	// An EMPTY override is not the same statement as no override at all.
	if configuredSet && configured == "" {
		return "", errors.New("netref: MYTHICAL_NET is set to an empty value. It names no network, and an empty override\n" +
			"  is not the same statement as no override at all. Remove the key to use the installer's\n" +
			"  own network, or name one.")
	}
	if !configuredSet {
		// No override: the owned network — unless a reference says the fleet is elsewhere.
		_, rerr := RefGet(l)
		switch {
		case errors.Is(rerr, ErrNoReference):
		case rerr == nil:
			return "", errors.New("netref: MYTHICAL_NET is not set, but a reference to an operator network is recorded and\n" +
				"  the fleet is on it. Adopting the installer's own network now would split the family.\n" +
				"  Remove the reference with a confirmed rebind: 'mythical-ctl net rebind'.")
		default:
			return "", rerr
		}
		return OwnedEnsure(ctx, l, objs, m, d)
	}
	return refEnsure(ctx, l, objs, configured)
}

// refEnsure adopts (or re-verifies) the operator's network.
func refEnsure(ctx context.Context, l *ledger.Ledger, objs Objects, configured string) (string, error) {
	id, err := RefGet(l)
	switch {
	case err == nil:
		if verr := RefVerify(ctx, l, objs, configured); verr != nil {
			return "", verr
		}
		return id, nil
	case errors.Is(err, ErrNoReference):
	default:
		return "", err // there IS a reference and it could not be read
	}
	ident, ierr := l.IdentGet()
	if ierr != nil {
		return "", ierr
	}
	oname, nerr := manifest.NetworkName(ident)
	if nerr != nil {
		return "", nerr
	}
	_, oerr := prov.Find(l, prov.ClassNetwork, oname)
	switch {
	case errors.Is(oerr, ledger.ErrAbsentRecord): // a genuine first-time adoption
	case oerr == nil:
		return "", errors.New("netref: MYTHICAL_NET names an operator network, but this installation already has its\n" +
			"  own family network with the fleet on it. Recording a reference now would split the\n" +
			"  family — new containers on the operator's network, the existing ones left behind.\n" +
			"  Move the fleet with a confirmed rebind: 'mythical-ctl net rebind'.")
	default:
		return "", fmt.Errorf("netref: whether this installation already has its own family network could not be read,\n"+
			"  so recording a reference to the operator's network might split the fleet. Nothing is\n"+
			"  recorded. Run 'mythical-ctl state repair': %w", oerr)
	}
	id, err = RefResolve(ctx, objs, configured)
	if err != nil {
		return "", err
	}
	if err := RefCommit(ctx, l, objs, id, configured); err != nil {
		return "", err
	}
	return id, nil
}
