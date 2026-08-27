package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
)

// Kind is the ledger record kind a live storage migration is recorded under.
//
// internal/state's reconciler SUSPENDS a container while a record of this kind names its product,
// so the two spellings must agree or that suspension silently stops matching the records it guards.
// TestSuspendsReconciliation asserts the agreement against state.PlanFor rather than against a
// second copy of the string.
const Kind = "storagemig"

// PhaseFirst and PhaseLast bound the nine durable phases. A recorded phase outside them is refused
// rather than looped over: `for p := 10; p <= 9` runs ZERO iterations and reports success, and a
// migration that reports success without doing anything is the one outcome resume must never
// produce.
const (
	PhaseFirst = 1
	PhaseLast  = 9
)

// Documents is the authenticated-document seam. ACCEPTING a document advances the anti-rollback
// trust floor, which is a ledger write and belongs to whoever holds the store — so this package
// asks for the result rather than performing the acceptance itself.
type Documents interface {
	AcceptManifest(product string) (*manifest.Manifest, error)
	AcceptPolicy() (*policy.Policy, error)
}

// Objects is the read side of the runtime.
type Objects interface {
	// ContainerMounts reports what the container actually mounts. engine.ErrAbsent means the
	// container is genuinely gone; any other error means the question could not be asked.
	ContainerMounts(ctx context.Context, container string) ([]engine.MountRecord, error)
}

// Mutator is the write side this package needs. *runtime.Runtime satisfies it.
type Mutator interface {
	ContainerStop(ctx context.Context, id string) error
	ContainerRemove(ctx context.Context, id string) error
}

// Copier is the helper-container copy seam (the volume fill/copy/verify module). It is an
// interface, not an import, for two reasons: this package must not become a second definition of
// the escape rule or the access checks, and the copy module's own hostile-input tests own those
// behaviours. What migrate owns is what happens to the MIGRATION when a copy step refuses.
type Copier interface {
	Escaper
	// Available reports whether the copy helper image is present and authenticated.
	Available(ctx context.Context) error
	// Preflight prepares the staging directory as a writable bind source for the helper.
	Preflight(ctx context.Context, staging, runtimeUID, operatorUID string) error
	// Run copies the volume into staging and returns the SOURCE-ENTRY COUNT it derived.
	Run(ctx context.Context, srcVolume, staging, runtimeUID, operatorUID string, mapForeign bool) (int, error)
	// Verify re-reads the copy against the source, bound to the entry count Run derived.
	Verify(ctx context.Context, srcVolume, staging string, entries int, runtimeUID, operatorUID string) error
	// HostAccessCheck walks the staged tree on the host.
	HostAccessCheck(staging string) error
	// AccessCheck proves the runtime uid can write the staged tree, from inside the helper.
	AccessCheck(ctx context.Context, staging, runtimeUID string) error
}

// Rebuilder replaces the product's container so it mounts the new bind. Docker mounts are FIXED AT
// CREATION — there is no update call that exposes a mount, volume or bind option — so "switch the
// mount" is not an operation and the container must be rebuilt from its launch spec. The spec lives
// with the verb that owns product bring-up, so this is a seam.
//
// IT IS SPLIT IN TWO BECAUSE THE ORDER IS A SAFETY PROPERTY. Everything that can fail while working
// out WHAT to build — resolving the network, the image, the mount and publish set, rendering the
// secrets — happens in Prepare, BEFORE the old container is removed. A single Rebuild call would
// necessarily do that work after the irreversible removal, so a launch spec that could not be built
// would leave the product with no container at all, where the reference leaves the old one standing
// and the migration resumable.
type Rebuilder interface {
	// NetTarget resolves the network the family attaches to.
	NetTarget(ctx context.Context, l *ledger.Ledger) (string, error)
	// Prepare resolves and renders EVERYTHING the replacement needs. It runs before anything
	// irreversible, so it must acquire nothing the caller cannot abandon — whatever it does
	// acquire is released by Discard.
	Prepare(ctx context.Context, l *ledger.Ledger, product, container, netID string) (Replacement, error)
	// Reconcile drives the container toward its recorded desired state.
	Reconcile(ctx context.Context, l *ledger.Ledger, container, netID string) error
}

// Replacement is one prepared container, ready to be created once the old one is actually gone.
type Replacement interface {
	// Create builds it. `preserve` is not a parameter because the migration MUST NOT EXPRESS
	// INTENT: the replacement reads the desired state already recorded.
	Create(ctx context.Context, l *ledger.Ledger) error
	// Discard releases what Prepare rendered — a secrets env file, say. Called on EVERY path out
	// of the phase, whether the replacement was built or abandoned.
	Discard()
}

// EntryCount carries the source-entry count from the copy (phase 3) to the verification (phase 4),
// WITHIN ONE PROCESS. It is a pointer in Deps rather than a return value threaded through the phase
// loop because that is exactly the reference's own lifetime: a value the copy step sets and the
// verification step reads, which does NOT survive to another process. Unset means the copy did not
// run here, and phase 4 refuses rather than verify against a count no step derived.
type EntryCount struct {
	n   int
	set bool
}

// Set records the count the copy derived.
func (e *EntryCount) Set(n int) {
	if e == nil {
		return
	}
	e.n, e.set = n, true
}

// Get reports the recorded count, and whether one was ever recorded.
func (e *EntryCount) Get() (int, bool) {
	if e == nil {
		return 0, false
	}
	return e.n, e.set
}

// Deps is everything a phase needs beyond the ledger.
type Deps struct {
	// Lock is the family lock. Every mutation this package performs asserts it.
	Lock famlock.Held
	// Docs is the authenticated-document seam.
	Docs Documents
	// Objs and Mut are the runtime's read and write sides.
	Objs Objects
	Mut  Mutator
	// Prov answers ownership questions about runtime objects.
	Prov prov.Objects
	// State observes a container's actual state.
	State state.Objects
	// Copy is the copy helper.
	Copy Copier
	// Build replaces the container and settles it.
	Build Rebuilder
	// Mounts is the system mount table.
	Mounts MountTable
	// Confirm is the destructive-action confirmation. A RESUME IS NEVER AUTOMATIC either.
	Confirm func(prompt string) bool
	// Persist commits THE LEDGER IT IS GIVEN to disk. It is REQUIRED, and it is the whole of the
	// write-ahead guarantee: a phase is recorded BEFORE it is entered, which is what makes a crash
	// resumable at the phase that was in progress rather than at the last one that finished. It
	// takes the ledger rather than closing over one, so a caller that reloads cannot end up
	// persisting the copy that existed when Deps was built.
	Persist func(*ledger.Ledger) error
	// Entries carries the copy's source-entry count from phase 3 to phase 4.
	Entries *EntryCount
	// MapForeign is --map-foreign-to-operator.
	MapForeign bool
	// Log is where the success-path narrative goes (never the refusals, which are errors).
	Log io.Writer
	// NewNonce mints a fresh staging nonce.
	NewNonce func() (string, error)
}

func (d Deps) home() (string, error) { return famlock.HomeOf(d.Lock) }

func (d Deps) logf(format string, a ...any) {
	if d.Log == nil {
		return
	}
	fmt.Fprintf(d.Log, format+"\n", a...)
}

// staged runs edit on a COPY of the ledger, PERSISTS the copy, and only then publishes it into the
// caller's ledger — so a failed write leaves the caller's ledger exactly as it found it.
//
// THE ORDER IS THE WHOLE POINT (round 1, finding 2). Editing the caller's ledger first and
// persisting afterwards leaves, on a failed or absent write, an in-memory phase that was never
// durable: a caller reusing that ledger reads a phase disk does not have, and phase 9's own
// deletion would leave the intent gone in memory while disk still carries it — a same-process
// resume would then answer "nothing to resume" about a migration that is still recorded. The
// reference cannot produce that state at all, because its ledger editor writes the FILE.
//
// A nil Persist is REFUSED, never skipped: silently proceeding would restore the defect this seam
// closes, and it would do so invisibly — the operation would succeed and only a crash would reveal
// that nothing was ever written ahead.
func (d Deps) staged(l *ledger.Ledger, what string, edit func(*ledger.Ledger) error) error {
	if d.Persist == nil {
		return fmt.Errorf("migrate: no way to write the intent down before acting on it (%s). A phase recorded only\n"+
			"  in memory is a phase no crash can resume from, which is the whole of the durable-phase\n"+
			"  contract. Nothing is done.", what)
	}
	cp := l.Clone()
	if err := edit(cp); err != nil {
		return err
	}
	if err := d.Persist(cp); err != nil {
		return fmt.Errorf("migrate: the record written ahead of %s could not be persisted, so nothing is done: %w", what, err)
	}
	return l.Adopt(cp)
}

func recordKey(product, role string) string { return product + ":" + role }

// BindKey is the mythical.conf key a role's bind is recorded under.
func BindKey(product, role string) (string, error) {
	up := strings.ToUpper(strings.ReplaceAll(product, "-", "_"))
	rup := strings.ToUpper(strings.ReplaceAll(role, "-", "_"))
	key := "MYTHICAL_" + up + "_" + rup + "_BIND"
	if _, ok := conf.BindKeyType(key); !ok {
		return "", fmt.Errorf("migrate: %q/%q does not derive a bind key mythical.conf accepts — refusing rather\n"+
			"  than reading or writing the wrong key.", product, role)
	}
	return key, nil
}

// record is the recorded intent, as a struct rather than as a bag of field lookups: every phase
// carries the same set forward, and a field silently dropped on the way through is how a resume
// loses the destination it was meant to finish.
type record struct {
	Phase   int
	Product string
	Role    string
	Dest    string
	SrcVol  string
	Staging string
	Nonce   string
	ConfKey string
	Prior   string
	Attempt string
	Desired string
	Mount   string
	StageID string
	// attemptPresent and desiredPresent record whether the FIELD WAS THERE, not whether it had a
	// value. Only these two carry a non-empty default, and defaulting on emptiness rather than on
	// absence is a silent upgrade of a corrupt record: `desired=` (present, empty) must reach
	// phase 9's "neither running nor stopped" refusal, not be restored as `running`, and
	// `attempt=` must not be presented to the compare-and-set as a fresh write.
	attemptPresent bool
	desiredPresent bool
}

func (r record) fields() []ledger.Field {
	k := recordKey(r.Product, r.Role)
	return []ledger.Field{
		{Key: "key", Value: k},
		{Key: "product", Value: r.Product},
		{Key: "role", Value: r.Role},
		{Key: "phase", Value: strconv.Itoa(r.Phase)},
		{Key: "dest", Value: r.Dest},
		{Key: "srcvol", Value: r.SrcVol},
		{Key: "staging", Value: r.Staging},
		{Key: "nonce", Value: r.Nonce},
		{Key: "confkey", Value: r.ConfKey},
		{Key: "prior", Value: r.Prior},
		{Key: "attempt", Value: r.Attempt},
		{Key: "desired", Value: r.Desired},
		{Key: "mount", Value: r.Mount},
		{Key: "stageid", Value: r.StageID},
	}
}

// put writes the record and PERSISTS IT as ONE step, through the staging seam. A phase marker held
// only in memory while the phase's own action runs is a marker no crash can resume from — and a
// marker published into the caller's ledger before the write succeeded is worse, because it reads
// as durable.
func (r record) put(l *ledger.Ledger, d Deps) error {
	return d.staged(l, fmt.Sprintf("entering phase %d of %s/%s", r.Phase, r.Product, r.Role),
		func(c *ledger.Ledger) error {
			return c.Put(Kind, "key", recordKey(r.Product, r.Role), r.fields())
		})
}

// ErrNoMigration means no migration is recorded for this product/role — an ANSWER, not a refusal.
var ErrNoMigration = errors.New("migrate: no storage migration is recorded")

// find reads the recorded intent. The phase is validated here rather than by each caller: a record
// naming a phase this core does not define must never reach a loop that would silently skip it.
func find(l *ledger.Ledger, product, role string) (record, error) {
	fields, err := l.Find(Kind, "key", recordKey(product, role))
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return record{}, ErrNoMigration
	}
	if err != nil {
		return record{}, fmt.Errorf("migrate: the recorded state for %s/%s could not be established. Refusing to act\n"+
			"  over a ledger this core cannot read. Run 'mythical-ctl state repair': %w", product, role, err)
	}
	get := func(k string) string { v, _ := ledger.FieldOf(fields, k); return v }
	_, attemptPresent := ledger.FieldOf(fields, "attempt")
	_, desiredPresent := ledger.FieldOf(fields, "desired")
	ps := get("phase")
	if ps == "" {
		return record{}, fmt.Errorf("migrate: the recorded migration for %s/%s does not name a phase. Run\n"+
			"  'mythical-ctl state repair'.", product, role)
	}
	phase, perr := strconv.Atoi(ps)
	if perr != nil || phase < PhaseFirst || phase > PhaseLast {
		return record{}, fmt.Errorf("migrate: the recorded migration for %s/%s names phase %q, which is not\n"+
			"  one this core defines. Run 'mythical-ctl state repair'.", product, role, ps)
	}
	return record{
		Phase: phase, Product: product, Role: role,
		Dest: get("dest"), SrcVol: get("srcvol"), Staging: get("staging"), Nonce: get("nonce"),
		ConfKey: get("confkey"), Prior: get("prior"), Attempt: get("attempt"),
		Desired: get("desired"), Mount: get("mount"), StageID: get("stageid"),
		attemptPresent: attemptPresent, desiredPresent: desiredPresent,
	}, nil
}

// Phase reports the recorded phase for a migration. ErrNoMigration means there is none.
func Phase(l *ledger.Ledger, product, role string) (int, error) {
	r, err := find(l, product, role)
	if err != nil {
		return 0, err
	}
	return r.Phase, nil
}

// StageID reports the recorded phase-5 identity (device+inode). An EMPTY string with a nil error is
// legitimate: no migration has reached phase 3 yet, so there is nothing to have recorded.
func StageID(l *ledger.Ledger, product, role string) (string, error) {
	r, err := find(l, product, role)
	if err != nil {
		return "", err
	}
	return r.StageID, nil
}

// Precheck answers ONE question: may this migration proceed at all?
//
// THE ORDER IS: is the destination's whole ancestor chain safe to operate in? — then, is there a
// LIVE INTENT matching this exact operation? — then the rest. Refusing on an unsafe parent FIRST,
// before any role/policy/volume question, is what makes the guarantee "no party with write access
// anywhere on the destination's path is ever let in" hold regardless of which product/role
// combination is requested. And the live-intent lookup comes before the remaining rules because a
// rule that refused on a present bind "before anything else" would refuse to RESUME, stranding the
// migration permanently at the phase that had just succeeded (phase 6 writes the bind while the
// intent is still live).
//
// THE LIVE-INTENT EARLY RETURN DOES NOT BYPASS THE PARENT-TRUST GATE. A migration interrupted while
// its destination's parent was safe, whose parent became group- or world-writable since, must not
// resume through that early return with the gate skipped: there is no legitimate reason to copy or
// rename into an unsafe location, fresh migration or resume alike.
//
// rc: nil ⇒ proceed — either a fresh migration, or a live intent for this exact (product, role,
// destination) the caller is free to resume. WHICH of those it is is NOT signalled here: the caller
// determines it independently by asking Phase, the same ledger record this function just consulted.
func Precheck(ctx context.Context, l *ledger.Ledger, d Deps, product, role, dest string) error {
	ident, err := l.IdentGet()
	if err != nil {
		return err
	}
	m, err := d.Docs.AcceptManifest(product)
	if err != nil {
		return err
	}
	p, err := d.Docs.AcceptPolicy()
	if err != nil {
		return err
	}

	// CANONICALIZED HERE TOO, NOT ONLY BY THE VERB — Precheck is a boundary in its own right
	// (called directly, and reachable other than through the verb), so it re-derives its own
	// canonical value rather than assume a caller already has one. Canonicalizing an
	// ALREADY-canonical path is a no-op, so this costs nothing on the verb's own path.
	dest, err = canonDest(dest)
	if err != nil {
		return err
	}
	if err := CheckParentTrust(dest); err != nil {
		return err
	}

	// A live intent for (product, role) is resumed ONLY IF the requested destination matches the
	// recorded one — resuming on (product, role) alone would silently hijack a migration to a
	// DIFFERENT path, reporting success for a destination the operator did not name.
	switch rec, ferr := find(l, product, role); {
	case ferr == nil:
		if rec.Dest != "" && rec.Dest == dest {
			// Skipping every check below is deliberate: the destination may legitimately be
			// non-empty by now (a completed rename from an earlier phase), and re-running "is it
			// empty" here would refuse a migration that is correctly in progress. The parent-trust
			// gate above is NOT one of the checks being skipped — it already ran, unconditionally.
			return nil
		}
		shown := rec.Dest
		if shown == "" {
			shown = "<unreadable>"
		}
		return fmt.Errorf("migrate: a migration of %s/%s is already in flight, to a different destination:\n"+
			"    in flight: %s\n"+
			"    requested: %s\n"+
			"  Stopping. Finish or abandon the in-flight migration explicitly, then re-run.",
			product, role, shown, dest)
	case errors.Is(ferr, ErrNoMigration):
	default:
		return ferr
	}

	// The role must EXIST in the manifest — which also gives the operator the list.
	roles := make([]string, 0, len(m.Volumes()))
	found := false
	for _, v := range m.Volumes() {
		roles = append(roles, v.Role)
		if v.Role == role {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("migrate: %q has no volume role %q. Its roles are: %s", product, role, strings.Join(roles, " "))
	}

	// BUT RECOGNISING A ROLE IS NOT AUTHORIZING IT (D53). Rejecting only UNKNOWN roles makes every
	// known one migratable — including a product's secrets role, which D5 keeps in the product's
	// own store precisely because it is a 0600 named volume. Migrating it to a host bind would move
	// every credential in it onto an operator-chosen path with whatever permissions and backup
	// exposure that path has: a supported, one-line way to defeat the secrets boundary that nothing
	// in "the role exists" would have stopped.
	if !p.Bindable(product, role) {
		return fmt.Errorf("migrate: the role %q is permitted for %q — the product mounts it — but it is\n"+
			"  not bindable. Bindability is a policy entitlement, declared in the family policy index,\n"+
			"  never by the product: a product must not be able to authorize widening its own storage\n"+
			"  boundary. A secrets role is deliberately kept off this list, because binding it would\n"+
			"  move every credential in it onto a host path with whatever exposure that path has.", role, product)
	}

	// AND THE ROLE MUST CURRENTLY BE VOLUME-BACKED (D55). The source is always the DERIVED NAMED
	// VOLUME, so after a role has been migrated to a bind, running this again would copy that STALE
	// volume — whose contents stopped changing at the first migration — over the live bind and then
	// rewrite mythical.conf to point at it. The operator would lose everything written since.
	home, err := d.home()
	if err != nil {
		return err
	}
	key, err := BindKey(product, role)
	if err != nil {
		return err
	}
	cur, cerr := conf.Get(conf.FamilyPath(home), key)
	switch {
	case cerr == nil:
		return fmt.Errorf("migrate: %s/%s is already bind-backed, at:\n"+
			"    %s\n"+
			"  Refusing. The source of a migration is always the derived named volume, and that volume\n"+
			"  is now stale — its contents stopped changing when you first migrated. Copying it over\n"+
			"  the live bind would lose everything written since.\n"+
			"  Bind-to-bind migration is a different operation and is not implemented: its source is a\n"+
			"  host path, it needs no copy container, and its failure modes differ.", product, role, cur)
	case errors.Is(cerr, conf.ErrAbsent), errors.Is(cerr, conf.ErrMissing):
	default:
		return fmt.Errorf("migrate: mythical.conf could not be read, so whether %s/%s is already bind-backed\n"+
			"  cannot be established. Refusing rather than guessing: %w", product, role, cerr)
	}

	// POSITIVE INSPECTION: the current container must be OBSERVED mounting the recorded source
	// volume, identified by name (D56). An absent config key is weak evidence, since a bind could
	// have been configured without the config reflecting it.
	srcvol, err := manifest.VolumeName(ident, product, role)
	if err != nil {
		return err
	}
	container, err := manifest.ContainerName(ident, product)
	if err != nil {
		return err
	}
	mounts, _ := d.Objs.ContainerMounts(ctx, container)
	if !mountsVolume(mounts, srcvol) {
		return fmt.Errorf("migrate: the container for %q does not mount the volume this migration would read.\n"+
			"    expected volume: %s\n"+
			"    container mounts: %s\n"+
			"  Refusing on positive inspection rather than assuming from an absent config key.",
			product, srcvol, describeMounts(mounts))
	}
	if err := prov.Authority(ctx, l, d.Prov, prov.ClassVolume, srcvol); err != nil {
		return fmt.Errorf("migrate: the source volume %q does not match this installation's record: %w", srcvol, err)
	}

	// A NON-EMPTY DESTINATION IS A REFUSAL BY DEFAULT, not combined with the copy — combining an
	// untrusted tree with the copy is how the two become one. Our OWN staging does not count,
	// because staging is a SIBLING of the destination and never appears inside it; that is what
	// keeps a crashed migration from permanently blocking its own retry.
	if st, serr := os.Lstat(dest); serr == nil {
		canon, cerr := runtime.Canon(dest)
		if cerr != nil {
			return cerr
		}
		if !st.IsDir() {
			return fmt.Errorf("migrate: %q exists and is not a directory", dest)
		}
		// PRESENCE, NOT READABILITY: a directory listing sees a DANGLING symlink, which a plain
		// existence test does not. A destination holding only one is not empty.
		ents, rerr := os.ReadDir(canon)
		if rerr != nil {
			return fmt.Errorf("migrate: the destination %q could not be listed, so whether it is empty cannot be\n"+
				"  established. Refusing rather than guessing: %w", canon, rerr)
		}
		if len(ents) > 0 {
			return fmt.Errorf("migrate: the destination %q is not empty (found %s).\n"+
				"  Refusing rather than combining it with the copy: both trees here are untrusted, and\n"+
				"  combining an unproven tree into the copy is exactly how the two become one.",
				canon, ents[0].Name())
		}
	}

	// EXCEPT WHEN THE DESTINATION IS ITSELF A MOUNT POINT — then its sibling may be on the PARENT
	// filesystem, making the rename cross-device (EXDEV), and replacing a mount point fails
	// regardless (EBUSY). "Could not be established" is its OWN case, never folded into "not a
	// mount point".
	isMP, mperr := IsMountPoint(d.Mounts, dest)
	if mperr != nil {
		return fmt.Errorf("migrate: whether %q is a mount point could not be established. Refusing\n"+
			"  rather than proceed on the strength of an unreadable mount table: %w", dest, mperr)
	}
	if isMP {
		return mountPointRefusal(dest)
	}

	// The destination must not be inside the family home, and must not overlap another bind.
	return runtime.CheckOverlap(home, product, dest)
}

func mountPointRefusal(dest string) error {
	return fmt.Errorf("migrate: %q is itself a mount point, so the atomic commit cannot work: a sibling of it\n"+
		"  may be on the parent filesystem (EXDEV), and replacing a mount point fails anyway (EBUSY).\n"+
		"  The remedy is to migrate into a subdirectory of the mount instead — that restores a\n"+
		"  same-filesystem sibling and works normally. Refusing beats silently falling back to a\n"+
		"  non-atomic copy, which would give up the one property this phase exists to provide.", dest)
}

func mountsVolume(mounts []engine.MountRecord, name string) bool {
	for _, m := range mounts {
		if m.Type == "volume" && m.Name == name {
			return true
		}
	}
	return false
}

func describeMounts(mounts []engine.MountRecord) string {
	if len(mounts) == 0 {
		return "<none>"
	}
	parts := make([]string, 0, len(mounts))
	for _, m := range mounts {
		src := m.Name
		if src == "" {
			src = m.Source
		}
		parts = append(parts, m.Type+"|"+src+"|"+m.Destination)
	}
	return strings.Join(parts, " ")
}

// Run executes ONE phase.
//
// PHASES ARE RECORDED BEFORE THEY ARE ENTERED, which is what makes a crash resumable at the phase
// that was in progress rather than at the last one that finished.
//
// THIS IS THE ONE MUTATION CHOKEPOINT. Every phase and every entry point — the verb, a direct call,
// a resume — funnels through here, and every mutation in the package (the staging mkdir, the copy,
// the rename, the bind) happens inside it. Canonicalizing only at the verb/precheck boundary left
// two gaps: a caller invoking this DIRECTLY with a raw symlinked-alias destination bypassed both,
// reaching phase 3's staging mkdir on the raw path; and a pre-canonicalization in-flight ledger
// record still carries a RAW staging path, which a resume would mkdir/rename through unchanged.
// Canonicalizing HERE, once, before any phase logic runs, closes both.
func Run(ctx context.Context, l *ledger.Ledger, d Deps, product, role, dest string, phase int) error {
	if phase < PhaseFirst || phase > PhaseLast {
		return fmt.Errorf("migrate: %d is not a migration phase", phase)
	}
	dest, err := canonDest(dest)
	if err != nil {
		return err
	}
	if err := CheckParentTrust(dest); err != nil {
		return err
	}
	if err := famlock.Assert(d.Lock, "run a storage-migration phase"); err != nil {
		return err
	}

	ident, err := l.IdentGet()
	if err != nil {
		return err
	}
	m, err := d.Docs.AcceptManifest(product)
	if err != nil {
		return err
	}
	if _, err := d.Docs.AcceptPolicy(); err != nil {
		return err
	}
	srcvol, err := manifest.VolumeName(ident, product, role)
	if err != nil {
		return err
	}
	container, err := manifest.ContainerName(ident, product)
	if err != nil {
		return err
	}
	key, err := BindKey(product, role)
	if err != nil {
		return err
	}
	ruid := m.RuntimeUID()
	ouid := strconv.Itoa(os.Geteuid())
	mount, merr := runtime.RoleTarget(m, role)
	if merr != nil {
		return merr
	}

	// THE RECORDED STATE, READ ONCE, AS IT WAS WHEN THIS CALL BEGAN. "No record at all" (phase 1's
	// own entry) is the only status that defaults to "nothing carried forward"; an unreadable or
	// ambiguous ledger must not be silently treated as an empty one, since every later phase's
	// carry-forward reads would then write blanks over a migration this core simply failed to read.
	prev, ferr := find(l, product, role)
	switch {
	case ferr == nil:
	case errors.Is(ferr, ErrNoMigration):
		prev = record{}
	default:
		return ferr
	}

	// EVERY PHASE'S CARRIED SET, IN ONE PLACE. next starts as the record this phase will write; each
	// phase overrides only what it changes. Building it once is what keeps a field from being
	// dropped on the way through one phase and not another.
	//
	// PHASE 7 CARRIES A DIFFERENT DEFAULT FOR `attempt`, and it is not an inconsistency: every
	// phase before it defaults to "none" because a write of the bind has not been attempted yet,
	// while phase 7 is only ever REACHED through a completed phase 6, so a record that does not
	// carry the field at all (a repaired or hand-written one) describes a migration whose write
	// was already begun. Defaulting it to "none" there would make a later fall-back to phase 5
	// re-present an already-written bind to the compare-and-set as a FRESH write, which refuses
	// against the value phase 6 itself put in mythical.conf — a migration wedged by its own
	// recovery path.
	attemptDefault := "none"
	if phase == 7 {
		attemptDefault = "started"
	}
	next := record{
		Product: product, Role: role, Dest: dest, SrcVol: srcvol, ConfKey: key, Mount: mount,
		Nonce: prev.Nonce, Prior: prev.Prior, StageID: prev.StageID,
		Attempt:        carried(prev.Attempt, prev.attemptPresent, attemptDefault),
		Desired:        carried(prev.Desired, prev.desiredPresent, string(state.Running)),
		attemptPresent: true, desiredPresent: true,
	}
	// ALWAYS DERIVED FROM THE CANONICAL DEST, NEVER THE LEDGER'S CARRIED RAW VALUE. A record written
	// by a caller that never canonicalized can carry a raw staging path through a symlinked alias;
	// creating or renaming through it again would be the exact check-canonical/use-raw gap this
	// closes. Staging is a SIBLING of the destination, and the parent's PHYSICAL location on disk is
	// the same real directory whether it was reached through the raw alias or the canonical path —
	// so deriving it fresh from the now-canonical destination and the CARRIED nonce lands at the
	// identical physical directory a prior run created (the recorded device+inode still matches),
	// while every path used below is canonical and immune to alias repointing.
	next.Staging = StagingPath(dest, next.Nonce)

	switch phase {
	case 1:
		return runPhase1(l, d, next, container, key)
	case 2:
		return runPhase2(ctx, l, d, next, container)
	case 3:
		return runPhase3(ctx, l, d, next, ruid, ouid)
	case 4:
		return runPhase4(ctx, d, prev, next, ruid, ouid)
	case 5:
		return runPhase5(l, d, next)
	case 6:
		return runPhase6(l, d, prev, next)
	case 7:
		return runPhase7(ctx, l, d, next, container)
	case 8:
		return runPhase8(ctx, l, d, next, container)
	case 9:
		return runPhase9(ctx, l, d, next, container)
	}
	return fmt.Errorf("migrate: %d is not a migration phase", phase)
}

// carried applies a default ONLY when the field was absent. A field that is there and empty is
// carried forward verbatim, so the phase that consumes it sees the record as it actually is.
func carried(v string, present bool, dflt string) string {
	if present {
		return v
	}
	return dflt
}

// runPhase1 opens the intent. EACH ATTEMPT ALLOCATES A FRESH NONCE AND A FRESH STAGING PATH. The
// identity cannot be captured before the directory exists, so there is always a window — a crash
// between the mkdir and the ledger write — that leaves a directory nothing can prove is ours. Rather
// than removing on suspicion, an unprovable leftover is preserved, reported once, and STEPPED
// AROUND: the retry proceeds beside it.
func runPhase1(l *ledger.Ledger, d Deps, r record, container, key string) error {
	if d.NewNonce == nil {
		return errors.New("migrate: no way to mint a staging nonce — refusing to open an intent that cannot name\n" +
			"  its own staging directory.")
	}
	nonce, err := d.NewNonce()
	if err != nil {
		return err
	}
	home, err := d.home()
	if err != nil {
		return err
	}
	prior, cerr := conf.Get(conf.FamilyPath(home), key)
	switch {
	case cerr == nil:
	case errors.Is(cerr, conf.ErrAbsent), errors.Is(cerr, conf.ErrMissing):
		prior = ""
	default:
		return fmt.Errorf("migrate: mythical.conf could not be read, so the prior value of %s cannot be\n"+
			"  established. Refusing to record an intent over configuration this core cannot read: %w", key, cerr)
	}
	desired, derr := state.DesiredGet(l, container)
	switch {
	case derr == nil:
	case errors.Is(derr, ledger.ErrAbsentRecord):
		desired = state.Running
	default:
		return fmt.Errorf("migrate: the recorded desired state for %q could not be read. Refusing to record an\n"+
			"  intent over a state this core cannot establish. Run 'mythical-ctl state repair': %w", container, derr)
	}
	r.Phase, r.Nonce, r.Staging = 1, nonce, StagingPath(r.Dest, nonce)
	r.Prior, r.Attempt, r.Desired, r.StageID = prior, "none", string(desired), ""
	return r.put(l, d)
}

// runPhase2 stops the writer. DESIRED STATE IS PRESERVED — this stops the container as a MEANS, not
// as an intent, and a verb that stops a container as a means to an end must not overwrite what the
// operator wants.
//
// A STOP THAT FAILS MUST STOP THE MIGRATION. Copying a live tree the product is still writing to is
// racing a process that gets to move the goalposts, and phase 4 would then verify a copy of a moment
// that never existed as a whole. A FAILURE TO ANSWER IS NOT EVIDENCE THAT IT STOPPED: folding an
// unanswerable observation into "not running" would let a copy proceed against a volume that may
// still be live, on exactly the flaky-daemon moment this check exists to catch.
func runPhase2(ctx context.Context, l *ledger.Ledger, d Deps, r record, container string) error {
	r.Phase = 2
	if err := r.put(l, d); err != nil {
		return err
	}
	if err := d.Mut.ContainerStop(ctx, container); err != nil {
		obs, oerr := state.Observe(ctx, d.State, container)
		if oerr != nil || obs == state.ObsRunning {
			return fmt.Errorf("migrate: %q could not be stopped, and whether it is still running could not be\n"+
				"  established either way. Refusing to copy a volume that may still be written to.\n"+
				"  The intent stays at phase 2 and can be resumed: %w", container, errors.Join(err, oerr))
		}
	}
	return nil
}

// runPhase3 stages and copies.
//
// `Mkdir`, NOT `MkdirAll`: MkdirAll succeeds on an EXISTING directory, so after the documented crash
// window (between the mkdir and the stageid write) a retry would adopt whatever sits at the staging
// name, record ITS identity, and copy into it — the opposite of the rule that an unprovable leftover
// is preserved, reported once, and stepped around with a fresh nonce.
func runPhase3(ctx context.Context, l *ledger.Ledger, d Deps, r record, ruid, ouid string) error {
	if err := d.Copy.Available(ctx); err != nil {
		return err
	}
	isMP, mperr := IsMountPoint(d.Mounts, r.Dest)
	if mperr != nil {
		return fmt.Errorf("migrate: whether %q is a mount point could not be established.\n"+
			"  Refusing rather than proceed on the strength of an unreadable mount table: %w", r.Dest, mperr)
	}
	if isMP {
		return fmt.Errorf("migrate: %q became a mount point", r.Dest)
	}
	if err := os.Mkdir(r.Staging, 0o755); err != nil {
		if _, lerr := os.Lstat(r.Staging); lerr == nil {
			// THE PATH IS CAPTURED BEFORE IT IS CLEARED. The record steps back to phase 1 with the
			// nonce and staging path emptied, so the next attempt mints fresh ones and proceeds
			// BESIDE the leftover — but the refusal must still NAME the directory being preserved,
			// or the operator has nothing to inspect or reclaim.
			leftover := r.Staging
			r.Phase, r.Staging, r.Nonce, r.StageID = 1, "", "", ""
			if perr := r.put(l, d); perr != nil {
				return perr
			}
			return fmt.Errorf("migrate: %q already exists, so this attempt cannot prove the directory is its\n"+
				"  own. It is preserved and reported; re-run to proceed beside it with a fresh nonce\n"+
				"  and a fresh staging path. Reclaiming the space is your decision.", leftover)
		}
		return fmt.Errorf("migrate: cannot create the staging directory %s: %w", r.Staging, err)
	}
	sid, err := Identity(r.Staging)
	if err != nil {
		return fmt.Errorf("migrate: cannot read the staging identity: %w", err)
	}
	r.Phase, r.StageID = 3, sid
	if err := r.put(l, d); err != nil {
		return err
	}
	// RE-VERIFIED IMMEDIATELY BEFORE EACH POINT the staging directory is handed to the copy helper
	// as a writable bind source — never trusted on the strength of the identity captured above
	// alone. The ledger write between that capture and here, and the whole preflight round-trip
	// before the second check, are real wall-clock time in which an attacker who controls the
	// destination's parent could replace it with a symlink; the helper would then follow the raw
	// path and write volume contents outside the intended root.
	if err := verifyIdentity(r.Staging, sid, "the staging directory"); err != nil {
		return err
	}
	if err := d.Copy.Preflight(ctx, r.Staging, ruid, ouid); err != nil {
		return err
	}
	if err := verifyIdentity(r.Staging, sid, "the staging directory"); err != nil {
		return err
	}
	n, err := d.Copy.Run(ctx, r.SrcVol, r.Staging, ruid, ouid, d.MapForeign)
	if err != nil {
		return err
	}
	d.Entries.Set(n)
	return nil
}

// runPhase4 verifies the copy. IT IS NOT SEPARATELY RECORDED: a crash during verification is handled
// EXACTLY as one during phase 3 — the ledger still names phase 3, so a resumed process re-enters
// phase 3, and the non-adopting mkdir refuses to take over the unconfirmed copy.
func runPhase4(ctx context.Context, d Deps, prev, r record, ruid, ouid string) error {
	// os.Stat, NOT Lstat: the question here is "is there a directory at this name", which the
	// reference asks with `[ -d ]` — and that FOLLOWS a symlink. Reading a symlink-to-directory as
	// "there is nothing to verify" would skip the whole verification and advance the phase, where
	// the reference instead proceeds and lets the Lstat-based identity check report the
	// substitution. The identity question below is still asked by Lstat, which is what makes a swap
	// to a symlink observable at all.
	st, serr := os.Stat(r.Staging)
	if serr != nil || !st.IsDir() {
		// A resume that reaches this with no staging directory has nothing to verify. That can only
		// happen from a corrective ledger edit, never from a real crash — phase 3 always creates it
		// before this phase can be reached — so it is reported and treated as a no-op that advances.
		d.logf("migrate: no staging directory at %s to verify — nothing was copied in this", r.Staging)
		d.logf("  process to compare against. A genuine crash here re-enters phase 3, which redoes the")
		d.logf("  copy from scratch; this call has nothing to do.")
		return nil
	}
	// A RECORDED IDENTITY TO VERIFY AGAINST MUST EXIST HERE. Phase 3 records `stageid` in the SAME
	// ledger write that creates the staging directory (never one without the other), so reaching
	// phase 4 with the directory on disk but no recorded identity is a corrective ledger edit, not a
	// live migration — exactly the ambiguity phase 5 refuses under.
	if prev.StageID == "" {
		return fmt.Errorf("migrate: phase 4 has no recorded staging identity, so this process cannot prove the\n"+
			"  directory at %q is its own. Refusing to verify or access it.", r.Staging)
	}
	n, ok := d.Entries.Get()
	if !ok {
		return errors.New("migrate: no source-entry count is available to bind verification to the source\n" +
			"  (the copy step did not run in this process). Refusing to verify against a count\n" +
			"  no step derived.")
	}
	// THE SAME TOCTOU PHASE 3 CLOSES, CLOSED HERE TOO — the staging directory is handed to THREE
	// separate external touches below, each its own process round-trip, each a window in which an
	// attacker who controls the destination's parent could replace it with a symlink to somewhere
	// else entirely.
	if err := verifyIdentity(r.Staging, prev.StageID, "the staging directory"); err != nil {
		return err
	}
	if err := d.Copy.Verify(ctx, r.SrcVol, r.Staging, n, ruid, ouid); err != nil {
		return err
	}
	if err := verifyIdentity(r.Staging, prev.StageID, "the staging directory"); err != nil {
		return err
	}
	if err := d.Copy.HostAccessCheck(r.Staging); err != nil {
		return err
	}
	if ruid != ouid {
		if err := verifyIdentity(r.Staging, prev.StageID, "the staging directory"); err != nil {
			return err
		}
		if err := d.Copy.AccessCheck(ctx, r.Staging, ruid); err != nil {
			return err
		}
	}
	return nil
}

// runPhase5 is the atomic commit. Recorded BEFORE renaming, so a crash after the rename but before
// the phase advance is resolvable from the identity rather than from the (now non-empty)
// destination.
func runPhase5(l *ledger.Ledger, d Deps, r record) error {
	stageid := r.StageID
	r.Phase = 5
	if err := r.put(l, d); err != nil {
		return err
	}
	if stageid == "" {
		// NO IDENTITY, NO COMMIT — unless there is provably nothing to protect. A real crash always
		// leaves this identity recorded (phase 3 records it before the copy even starts), so
		// reaching phase 5 with none recorded, from a process that itself never ran phase 3 or 4, is
		// a corrective ledger edit. If something exists at either candidate path it cannot be
		// attributed to this attempt and is left alone; if NOTHING exists anywhere, there is nothing
		// that could be a hostile substitution and nothing legitimate to lose.
		_, sErr := os.Lstat(r.Staging)
		_, dErr := os.Lstat(r.Dest)
		if sErr == nil || dErr == nil {
			return fmt.Errorf("migrate: phase 5 has no recorded staging identity, so this process cannot prove the\n"+
				"  directory at %q is its own. Refusing to commit it onto %q.\n"+
				"  Nothing is removed. Re-run to proceed beside it with a fresh nonce.", r.Staging, r.Dest)
		}
		if err := os.MkdirAll(r.Dest, 0o755); err != nil {
			return fmt.Errorf("migrate: cannot create %q: %w", r.Dest, err)
		}
		return nil
	}
	where, err := ResolvePhase5(r.Dest, r.Staging, stageid)
	if err != nil {
		return err
	}
	if where != AtStaging {
		return nil
	}
	// AN EMPTY DESTINATION IS RENAMED ONTO; A MISSING ONE TOO — but the rmdir's OWN result decides
	// which of those this is, never an assumption. Precheck accepted the destination empty or
	// absent, which an attacker who controls its parent can undo afterward by creating a NON-EMPTY
	// directory (or a symlink to one) there before this phase runs. Discarding the rmdir's failure
	// and moving on regardless lets the rename silently REINTERPRET the operation: a rename onto an
	// EXISTING non-empty directory is not a replacement, so the whole copy would land one level
	// down beside whatever the attacker put there — non-atomic, and wrong in a way nothing
	// afterward would notice.
	if _, err := os.Lstat(r.Dest); err == nil {
		// rmdir(2), NOT a general remove. A general remove unlinks a NON-directory too, so a symlink
		// planted at the destination after the precheck would be silently deleted and the staged
		// tree committed in its place — the migration would then quietly redefine where the
		// operator's destination points. rmdir refuses anything that is not an EMPTY directory,
		// which is exactly the two cases this commit is allowed to replace.
		_ = syscall.Rmdir(r.Dest)
		if _, err := os.Lstat(r.Dest); err == nil {
			return fmt.Errorf("migrate: %q is no longer the empty or absent directory this migration\n"+
				"  verified — something exists there now that could not be removed (it is not\n"+
				"  empty, or is not a directory at all). Refusing to move the copy onto it: doing\n"+
				"  so would nest it INSIDE whatever is there instead of atomically\n"+
				"  replacing it. Nothing was moved; the copy is intact at %s.", r.Dest, r.Staging)
		}
	}
	// THE LAST THING BEFORE THE COMMIT: a content-level re-check, not another identity check.
	// Placed as close to the rename as this can be put, to make the residual window as small as
	// achievable.
	if err := VerifyNoEscapingSymlinks(d.Copy, r.Staging); err != nil {
		return err
	}
	if err := renameDir(r.Staging, r.Dest); err != nil {
		return fmt.Errorf("migrate: the atomic commit (rename) failed. The copy is intact at %s; nothing\n"+
			"  was destroyed. If the destination is on a different filesystem or is a mount\n"+
			"  point, migrate into a subdirectory instead: %w", r.Staging, err)
	}
	// AND AFTER THE RENAME, THE RESULT IS VERIFIED TOO — not assumed from the rename's own success.
	// A rename this process just performed should leave the destination carrying exactly the
	// identity that just moved there; if it does not, something about the destination is not what
	// this process believes it just put in place, and continuing to phase 6 (which writes this very
	// path into mythical.conf) would commit to it anyway.
	return verifyIdentity(r.Dest, stageid, "the destination")
}

// runPhase6 writes the bind.
//
// THE BIND IS WRITTEN BEFORE THE CONTAINER IS REPLACED, not after. A container is built FROM
// mythical.conf — so with the write ordered last, the replacement would have recreated the product
// ON THE NAMED VOLUME IT WAS MIGRATING AWAY FROM, and only then recorded the bind. Configuration
// precedes the object built from it.
//
// THE `attempt` PASSED TO THE COMPARE-AND-SET IS READ FROM THE STALE RECORD — the record as it was
// BEFORE this call — deliberately: on a fresh entry it still reads "none" (nothing here has touched
// it), and on a RESUMED entry (a crash after this phase's own write below, before the
// compare-and-set completed) it reads "started" from that crashed attempt's own write. That is
// exactly the distinction the compare-and-set needs to tell a crash from a hand edit.
func runPhase6(l *ledger.Ledger, d Deps, prev, r record) error {
	// THE WRITE-AHEAD RECORD LANDS FIRST, EVEN FOR A STATE THIS PHASE IS ABOUT TO REFUSE. The
	// carried attempt state is judged AFTER the record is durable, exactly as the reference orders
	// it: the record is rewritten with attempt=started, and only then is the STALE value presented
	// to the compare-and-set. Judging first and returning early would leave an unrecognised value
	// in the ledger for ever — every retry would reach the same refusal, where the reference's next
	// attempt reads back "started" and takes the resumable recovery path.
	carriedAttempt := r.Attempt
	r.Phase, r.Attempt = 6, "started"
	if err := r.put(l, d); err != nil {
		return err
	}
	// THE RECORDED STATE IS MAPPED, NOT COERCED. A value that is neither of the two this core
	// defines is a corrupt or hand-edited record, and folding it into "none" would present a
	// migration that may already have written mythical.conf to the compare-and-set as a FRESH
	// write — the one situation the attempt field exists to tell apart.
	var attempt conf.Attempt
	switch carriedAttempt {
	case "none":
		attempt = conf.AttemptNone
	case "started":
		attempt = conf.AttemptStarted
	default:
		return fmt.Errorf("migrate: the recorded write-attempt state %q for %s/%s is neither 'none' nor\n"+
			"  'started'. Refusing to present it to the one door authorized to change a value in\n"+
			"  mythical.conf — a crash and a hand edit are told apart by this field alone.\n"+
			"  The intent is now recorded as a write IN PROGRESS, so a re-run takes the recovery\n"+
			"  path rather than this refusal. Run 'mythical-ctl state repair' if it persists.",
			carriedAttempt, r.Product, r.Role)
	}
	return conf.FamilyCAS(d.Lock, r.ConfKey, r.Dest, prev.Prior, attempt, d.Confirm)
}

// runPhase7 REPLACES THE CONTAINER, because "switch the mount" is not an operation: mounts are fixed
// at creation. The new container is built by the ordinary bring-up, the old one is removed and
// tombstoned, and both are provenance-recorded like any other object.
//
// TOMBSTONE ONLY WHAT WAS ACTUALLY REMOVED. A transient removal failure followed by a tombstone
// strips the old container's authority record while it is still there: recovery then reads it as
// absent, skips the removal, and cannot create the replacement under the same name — phase 7
// stranded, with nothing left that can remove the blocker.
func runPhase7(ctx context.Context, l *ledger.Ledger, d Deps, r record, container string) error {
	stageid := r.StageID
	r.Phase = 7
	if err := r.put(l, d); err != nil {
		return err
	}
	// RE-VERIFIED BEFORE THE REPLACEMENT CONTAINER MOUNTS IT, and before the (irreversible) removal
	// below — the destination is about to become a live bind source for the ACTUAL product
	// container. When none was ever recorded (phase 5's "nothing was there to protect" fallback,
	// which establishes no identity because it attributed nothing) there is nothing to check
	// against, and this is the same absence of evidence phase 5 itself already accepted.
	if stageid != "" {
		if err := verifyIdentity(r.Dest, stageid, "the destination"); err != nil {
			return err
		}
	}
	netID, err := d.Build.NetTarget(ctx, l)
	if err != nil {
		return err
	}
	// EVERY FALLIBLE STEP OF WORKING OUT WHAT TO BUILD RUNS FIRST, while the old container is still
	// there. The removal below cannot be undone, so a launch spec that could not be resolved — a
	// missing image, a secret that will not render, a mount set that does not validate — must fail
	// HERE, with the old container standing and the migration resumable, rather than after the
	// product has been left with no container at all.
	rep, perr := d.Build.Prepare(ctx, l, r.Product, container, netID)
	if perr != nil {
		return fmt.Errorf("migrate: the replacement container for %q could not be prepared, so nothing was\n"+
			"  removed — the old container is still there and the migration stays at phase 7: %w", container, perr)
	}
	// Released on EVERY path out, built or abandoned: whatever Prepare rendered is this phase's to
	// clean up, exactly as the reference removes its rendered secrets file on every branch.
	defer rep.Discard()
	switch aerr := prov.Authority(ctx, l, d.Prov, prov.ClassContainer, container); {
	case aerr == nil:
		if rerr := d.Mut.ContainerRemove(ctx, container); rerr != nil {
			return fmt.Errorf("migrate: could not remove the old container %q. Its record is kept so it stays\n"+
				"  removable; the migration stays at phase 7 and can be resumed: %w", container, rerr)
		}
	case errors.Is(aerr, prov.ErrGone):
	default:
		return fmt.Errorf("migrate: refusing to replace %q at phase 7. The migration stays at\n"+
			"  phase 7 with its intent intact and can be resumed once the container is resolved: %w", container, aerr)
	}
	if err := d.staged(l, "tombstone the replaced container", func(c *ledger.Ledger) error {
		return prov.Tombstone(c, prov.ClassContainer, container)
	}); err != nil {
		return fmt.Errorf("migrate: could not tombstone the removed container %q. The migration stays at phase\n"+
			"  7 and can be resumed; run 'mythical-ctl state repair' if a later step reports the\n"+
			"  object as already accounted for: %w", container, err)
	}
	return rep.Create(ctx, l)
}

// runPhase8 verifies the mount BY INSPECTION.
//
// PHASE 8 CANNOT ASK THE CONTAINER ANYTHING. Bring-up leaves a replacement STOPPED when the desired
// state is `stopped`, and starting a product whose desired state is stopped is forbidden — so
// "verify the container sees the migrated data" was unreachable for exactly the products most likely
// to be migrated.
//
// Split by what is provable without running: THE DATA was verified host-side at phase 4; THE MOUNT
// CONFIGURATION is verified by inspection here; and the CONTAINER-SIDE VIEW is not verified at all —
// the check that would have carried it was removed as unimplementable, because it needs tooling no
// product image is required to ship. Not deferred, not outstanding, not claimed.
func runPhase8(ctx context.Context, l *ledger.Ledger, d Deps, r record, container string) error {
	_ = l
	canon, err := runtime.Canon(r.Dest)
	if err != nil {
		return err
	}
	mounts, err := d.Objs.ContainerMounts(ctx, container)
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m.Source == canon && m.Destination == r.Mount {
			d.logf("migrate: verified by inspection that %s mounts %s at %s.", container, canon, r.Mount)
			d.logf("  The data was verified host-side at phase 4. The container-side read is not verified at all")
			d.logf("  and is not claimed — it would need tooling no product image is required to ship.")
			return nil
		}
	}
	return fmt.Errorf("migrate: the replacement container does not mount %q at %q.\n"+
		"    inspected mounts: %s", canon, r.Mount, describeMounts(mounts))
}

// runPhase9 clears the intent and settles the container.
//
// RESTORE THE DESIRED STATE FIRST, EXPLICITLY, THEN CLEAR THE INTENT — not because phase 7's
// bring-up leaves it wrong (it does not), but because the family lock is released the instant this
// process crashes, and a crash between phase 7 and phase 9 leaves the migration SUSPENDED while
// still letting an operator's plain stop/start write straight over the desired-state row with no
// reconciliation to catch it. Restoring from the copy captured at phase 1 — rather than trusting
// whatever the row currently says — is what makes that window safe. And the intent is cleared only
// after the last thing it authorizes has succeeded: an intent cleared first, followed by a failed
// restore, would leave nothing recording that the container should still reach its prior state.
//
// THE SOURCE VOLUME IS RETAINED. Removing it is never automatic: it is the operator's data, and the
// copy is what was just verified, not a substitute for their decision.
func runPhase9(ctx context.Context, l *ledger.Ledger, d Deps, r record, container string) error {
	netID, err := d.Build.NetTarget(ctx, l)
	if err != nil {
		return err
	}
	switch state.Desired(r.Desired) {
	case state.Running:
		if err := d.staged(l, "restore the recorded desired state", func(c *ledger.Ledger) error {
			return state.Commit(c, container, state.Running, []state.Check{{Kind: state.CheckAlias, Param: netID}}, false)
		}); err != nil {
			return err
		}
	case state.Stopped:
		if err := d.staged(l, "restore the recorded desired state", func(c *ledger.Ledger) error {
			return state.Commit(c, container, state.Stopped, nil, true)
		}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("migrate: the recorded desired state %q for %q is neither running nor\n"+
			"  stopped — refusing to restore it blindly. Run 'mythical-ctl state repair'.", r.Desired, container)
	}
	if err := d.staged(l, "clear the completed intent", func(c *ledger.Ledger) error {
		return c.Del(Kind, "key", recordKey(r.Product, r.Role))
	}); err != nil {
		return err
	}
	// Report a failed reconciliation rather than swallowing it: the data has moved and the config
	// names it, so the migration itself succeeded — but a replacement that is not in its recorded
	// desired state is not a finished job.
	if err := d.Build.Reconcile(ctx, l, container, netID); err != nil {
		d.logf("migrate: the data has moved and %s names it, but %q did not reach its recorded", r.ConfKey, container)
		d.logf("  desired state (%s). The migration is complete; the container is not settled.", r.Desired)
		d.logf("  'mythical-ctl status %s' shows what is outstanding.", r.Product)
	}
	d.logf("migrate: %s/%s now uses the host directory %s.", r.Product, r.Role, r.Dest)
	d.logf("  The source volume %q is retained. It holds the data as it was before the copy,", r.SrcVol)
	d.logf("  and removing it is your decision.")
	return nil
}

// Resume resumes every live storage migration from its recorded phase.
//
// A RESUME IS NEVER AUTOMATIC, exactly like the fresh path. Every phase from here to 9 can stop the
// container, copy data, write mythical.conf or replace the container — the SAME destructive steps a
// fresh migration confirms before touching anything — and arriving through the resume door (a
// reconciliation sweep, not an operator's own invocation) must not skip asking. A scripted
// confirmation still resumes unattended on purpose; what must not happen is a destructive resume
// with NO confirmation input at all.
//
// THE LISTING IS CAPTURED AND CHECKED FIRST, and nothing from it is trusted for the actual resume
// decision beyond WHICH migrations exist: each one is re-read fresh before anything is decided. A
// listing that could not be fully read is a REFUSAL — reading it as an empty list would report
// success having resumed nothing at all.
func Resume(ctx context.Context, l *ledger.Ledger, d Deps) error {
	rows, err := l.All(Kind)
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("migrate: the recorded storage migrations could not be fully read, so this cannot see every\n"+
			"  migration it must resume. Refusing rather than resuming a partial view of the ledger.\n"+
			"  Run 'mythical-ctl state repair': %w", err)
	}
	for _, row := range rows {
		product, ok := ledger.FieldOf(row, "product")
		if !ok || product == "" {
			return errors.New("migrate: a recorded storage migration does not name a product. Refusing to guess which\n" +
				"  one it is. Run 'mythical-ctl state repair'.")
		}
		role, ok := ledger.FieldOf(row, "role")
		if !ok || role == "" {
			return fmt.Errorf("migrate: the recorded migration for %q does not name a role. Run 'mythical-ctl\n"+
				"  state repair'.", product)
		}
		if err := ResumeOne(ctx, l, d, product, role); err != nil {
			return err
		}
	}
	return nil
}

// ResumeOne resumes the ONE migration recorded for product/role. A record that is GONE by the time
// this re-reads it is not an error: another properly serialized process already finished or
// abandoned it, and there is nothing left to do.
func ResumeOne(ctx context.Context, l *ledger.Ledger, d Deps, product, role string) error {
	rec, err := find(l, product, role)
	if errors.Is(err, ErrNoMigration) {
		return nil
	}
	if err != nil {
		return err
	}
	if rec.Dest == "" {
		return fmt.Errorf("migrate: the recorded migration for %s/%s does not name a destination. Run\n"+
			"  'mythical-ctl state repair'.", product, role)
	}
	// CANONICALIZED HERE TOO — a fresh migration records the canonical destination from the start,
	// so this is ordinarily a no-op; it matters for a record a repair tool ever wrote by hand, where
	// a raw operand could still be sitting in the ledger.
	dest, err := canonDest(rec.Dest)
	if err != nil {
		return err
	}
	// THE SAME GATE THE VERB GOES THROUGH VIA Precheck. This is an INDEPENDENT entry point (a
	// reconciliation sweep, not necessarily reached through the verb at all), so it must establish
	// parent trust itself rather than assume some other caller already did.
	if err := CheckParentTrust(dest); err != nil {
		return err
	}
	p := ResumePhase(rec.Phase, dest, rec.StageID)
	if p == rec.Phase {
		d.logf("migrate: resuming %s/%s at phase %d.", product, role, rec.Phase)
	} else {
		d.logf("migrate: %s/%s recorded phase %d, but the destination does not verifiably", product, role, rec.Phase)
		d.logf("  carry phase 5's result. Re-deriving from observable state: resuming at phase %d instead.", p)
	}
	if !d.confirm(fmt.Sprintf("migrate: %s/%s is recorded at phase %d and will be resumed — depending on the\n"+
		"  phase this stops the container, copies data, writes mythical.conf, or replaces the\n"+
		"  container. Never automatic.\nmigrate: resume %s/%s from phase %d?", product, role, p, product, role, p)) {
		return fmt.Errorf("migrate: not confirmed. %s/%s stays recorded at phase %d; nothing was done.",
			product, role, rec.Phase)
	}
	for ; p <= PhaseLast; p++ {
		if err := Run(ctx, l, d, product, role, dest, p); err != nil {
			return err
		}
	}
	return nil
}

// confirm refuses when there is no confirmation seam at all. A missing prompt is NOT consent.
func (d Deps) confirm(prompt string) bool {
	if d.Confirm == nil {
		return false
	}
	return d.Confirm(prompt)
}

// Options is the parsed `migrate-storage` option set. Every option this verb does not own is
// refused by the dispatcher, not silently ignored.
type Options struct {
	// ToBind is the destination, an ABSOLUTE path.
	ToBind string
	// MapForeign is --map-foreign-to-operator.
	MapForeign bool
}

// MigrateStorage is the verb: precheck, confirm, then run the phase loop to completion.
func MigrateStorage(ctx context.Context, l *ledger.Ledger, d Deps, product, role string, o Options) error {
	if o.ToBind == "" {
		return errors.New("migrate: migrate-storage needs --to-bind <path>")
	}
	if !filepath.IsAbs(o.ToBind) {
		// ITS OWN REFUSAL, not the canonicalizer's. Every path comparison downstream is on absolute
		// paths, and a relative operand would be resolved against whatever directory the process
		// happens to be in — a location the operator did not name. Saying so HERE, at the boundary
		// the operand enters through, is what makes the message about the OPTION.
		return errors.New("migrate: --to-bind needs an absolute path, not a path relative to the current directory")
	}
	// CANONICALIZE ONCE, HERE, AT THE BOUNDARY. This single reassignment makes every downstream use
	// — the precheck, and the phase loop below including phase 1, which RECORDS it into the ledger
	// so a resume reads it back already canonical — refer to the exact path whose whole ancestor
	// chain the parent-trust gate is about to verify. Nothing downstream ever sees the raw operand.
	dest, err := canonDest(o.ToBind)
	if err != nil {
		return err
	}
	d.MapForeign = o.MapForeign
	if err := Precheck(ctx, l, d, product, role, dest); err != nil {
		return err
	}

	// RESUME-VS-FRESH IS NOT PRECHECK'S TO SIGNAL. It already consulted the one ledger record this
	// decision rests on; asking again is an ordinary second read of that same record, not a second
	// decision — and it keeps the precheck's contract to one question.
	p := PhaseFirst
	switch rec, ferr := find(l, product, role); {
	case errors.Is(ferr, ErrNoMigration):
		if !d.confirm(fmt.Sprintf("migrate: migrating %s/%s to the host directory %q. This stops the\n"+
			"  container, copies the data, writes mythical.conf, and replaces the container to mount\n"+
			"  the new location. Never automatic.\nmigrate: migrate %s/%s storage to %q?",
			product, role, dest, product, role, dest)) {
			return errors.New("migrate: not confirmed.")
		}
	case ferr == nil:
		// THE RECORDED PHASE IS A WRITE-AHEAD INTENT, VERIFIED BEFORE IT IS TRUSTED. A phase of 6 or
		// later is resumed there directly only when the destination verifiably carries phase 5's
		// result; otherwise this re-derives the true starting phase, so the operator is told — and
		// this proceeds from — the phase that will actually run.
		p = ResumePhase(rec.Phase, dest, rec.StageID)
		// CONFIRMATION COVERS RESUME TOO, NOT ONLY A FRESH START.
		if !d.confirm(fmt.Sprintf("migrate: a migration of %s/%s to %q is already recorded and will be resumed\n"+
			"  from phase %d. This is never automatic.\nmigrate: resume the recorded migration?",
			product, role, dest, p)) {
			return errors.New("migrate: not confirmed.")
		}
		d.logf("migrate: resuming the in-flight migration of %s/%s at phase %d.", product, role, p)
	default:
		return fmt.Errorf("migrate: could not tell whether a migration of %s/%s is already recorded.\n"+
			"  Refusing rather than guessing. Run 'mythical-ctl state repair': %w", product, role, ferr)
	}

	for ; p <= PhaseLast; p++ {
		if err := Run(ctx, l, d, product, role, dest, p); err != nil {
			return err
		}
	}
	return nil
}
