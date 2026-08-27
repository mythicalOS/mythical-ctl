package verbs

// REPAIR — §6b.1: the way out of a ledger that no longer matches reality.
//
// This is the most dangerous read-then-write surface in the tool. It decides WHICH runtime objects
// belong to this installation using nothing but the objects' own labels — because the ledger, which
// WAS the identity authority, is the very record being repaired — and a wrong answer either adopts
// another installation's containers or destroys the record of your own. Every read here therefore
// splits three ways and never two: the object is GONE (an answer a later run may act on), the
// question was ANSWERED (possibly with an empty value, which is itself an answer), or the runtime
// COULD NOT BE ASKED — and the last one never, anywhere, becomes "no label", "a different
// identity", or "nothing to record".
//
// The invariants this file exists to hold, all of them ported rather than re-derived:
//
//   - candidate discovery REFUSES rather than reporting a partial list. A listing that leaves out
//     the one object it could not read is how a repair reports "exactly one identity" over a set
//     that had two.
//   - EXACTLY ONE candidate is still shown and still confirmed. Silently adopting the only visible
//     identity is how a second user's containers get claimed on a shared daemon.
//   - ZERO candidates offers a confirmed REINITIALIZATION rather than deadlocking — and
//     reinitialization is REFUSED whenever any candidate exists.
//   - a label is VALIDATED before it is treated as an identity: a Docker label value can contain a
//     newline, and an unvalidated one forges two candidates out of one object.
//   - the ledger is destroyed ONLY on positively confirmed corruption. A read that merely failed
//     says nothing about the bytes underneath it, and destroying on that guess costs the trust
//     anchor and every rollback floor for nothing.
//
// LOCK AND WRITE MODEL. Repair runs inside one held family lock from its first read to its last
// write, exactly as the reference's `_mi_with_lock` wrapper does. What differs is only the
// mechanism the rest of this tree already uses: the ledger edits are IN MEMORY and the session's
// single write persists them, so "provenance in, state committed, ONE ledger write" is structural
// here rather than a discipline.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/bringup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// THE RECORD KINDS REPAIR WRITES THAT NO OTHER PACKAGE EXPOSES A WRITER FOR.
//
// Three of the four are the owning package's own unexported constant, and repair needs to write a
// row that package's public API cannot express:
//
//	identity  internal/ledger MINTS an identity (IdentEnsure) but cannot be told to record a
//	          CHOSEN one, which is precisely what adopting a candidate is.
//	netref    internal/netref's RefCommit refuses a reference that is not where MYTHICAL_NET now
//	          resolves — correct for every ordinary caller, and exactly wrong for the one case
//	          repair must record: the reference naming the network the containers are OBSERVED on,
//	          beside a migration intent that will move them to the configured one.
//	netmig    the phase-1 intent must be written in the SAME edit as that reference, so the pair
//	          cannot half-exist.
//	object    provenance records are enumerated back by kind; internal/prov exposes lookup by name
//	          and nothing that walks them.
//
// EACH IS PINNED BY A ROUND TRIP against the owning package's own reader (TestRepairRecordKinds).
// A constant copied here would otherwise drift silently the day the owner renamed its kind: the
// writes would still succeed, into rows nothing reads.
const (
	kindIdentity = "identity"
	kindNetRef   = "netref"
	kindNetMig   = "netmig"
	kindProvObj  = "object"

	// trustAnchorKind is internal/trust's own row. It is NOT written here — its field grammar
	// carries a '-' the typed ledger editors refuse, which is why trust keeps a raw-line writer —
	// but the reset gate must COUNT and VALIDATE the anchors before deciding to keep one.
	trustAnchorKind = "trust-anchor"
)

// reinitialize is the operand that asks for a brand-new identity instead of adopting a candidate.
const reinitialize = "--reinitialize"

// --- the runtime read seams ----------------------------------------------------------------------

// repairSeams is every question repair asks the container runtime, gathered in ONE place.
//
// It is a seam because the failure this module is built around — "the runtime could not answer THIS
// read" — has to be reachable for exactly one read at a time. The reference's shell suite reached
// it by counting daemon invocations and knocking the fake over after the nth, which pins the
// behaviour to a call count that any refactor silently invalidates: the knob then lands on a
// DIFFERENT read and the test goes on passing while proving something else. Naming the read
// directly is the same test without that failure mode.
type repairSeams struct {
	// objs answers the installation and nonce labels, and lists objects of a kind unfiltered.
	objs prov.Objects
	// nets resolves a network reference to its id.
	nets netref.Objects
	// live answers a container's RESOLVED network attachments and its aliases on each.
	live bringup.Objects
	// state answers whether a container is running.
	state state.Objects
}

var repairReads = func(c *engine.Client) repairSeams {
	return repairSeams{
		objs:  prov.Engine(c),
		nets:  netref.Engine(c),
		live:  bringupObjects{c: c},
		state: state.Engine(c),
	}
}

// provRecord is the provenance writer the rebuild loop uses, behind a seam.
//
// A container-class record with no `name=` field is a shape prov.Record itself never produces — it
// always writes one — but the verify loop below reads records back and must FAIL CLOSED on one, and
// the only way to reach that path is to write one. The reference stubbed its own writer for exactly
// this; the seam is the same stub with a type.
var provRecord = prov.Record

// The reset gate's two ledger questions, behind a seam of their own.
//
// The distinction that gate turns on — "positively confirmed corrupt" versus "the read merely
// failed" — is only observable when the SECOND happens over bytes that are perfectly good, and in
// this process there is no way to arrange that from outside. The reference arranged it by breaking
// the external hashing tool on PATH; the Go checksum is computed in-process, and every remaining
// natural cause (a mid-read I/O error on the storage this home lives on) is an operating-system
// fault a hermetic suite cannot stage. The seam stages exactly the answer pair such a failure
// produces — NOT corrupt, and could not be read — over a ledger whose bytes are provably intact,
// which is the whole of what must not be destroyed.
var (
	ledgerRead             = ledger.Read
	ledgerConfirmedCorrupt = ledger.ConfirmedCorrupt
)

// --- schema migration (D35) ----------------------------------------------------------------------

// SchemaMigrate migrates an OLDER ledger forward, under the lock, in one atomic replace.
//
// A ledger NEWER than this build understands is refused by ledger.Read itself, and that gate must
// stay there: every caller goes through the reader, and an older CLI that MISREADS a newer ledger
// deletes objects it misidentifies.
//
// A MIGRATION MUST STATE A VALUE FOR EVERY FIELD THE OLDER SCHEMA LACKS — omitting one is how a
// "migrated" ledger becomes one that fails every read. At schema 1 there is nothing to migrate, so
// this is a no-op that exists to be the single place a future bump lands, with the three fields
// §6b.1 enumerates already documented:
//
//	desired state  absent from any pre-D43 ledger. Initialized from OBSERVATION (running ⇒ running,
//	               stopped ⇒ stopped), reported as inferred rather than known, and listed.
//	outstanding    absent from any pre-D50 ledger, and a BOOLEAN in any pre-D52 one. A pre-D50
//	               ledger initializes to {alias} for every container.
//	network ref    absent from any pre-D44 ledger. Re-resolved from mythical.conf — through
//	               repairNetref below, which every path that changes which network the ledger names
//	               must go through.
func SchemaMigrate(h famlock.Held, st ledger.Store) error {
	if err := famlock.Assert(h, "migrate the ledger schema"); err != nil {
		return err
	}
	_, err := ledger.Read(st)
	if errors.Is(err, ledger.ErrMissingLedger) {
		return nil
	}
	if err != nil {
		return err
	}
	// ledger.Read has already refused anything newer, and there is no older schema in existence
	// yet. A future bump adds its arm HERE, writes EVERY new field, and lets ledger.Write's atomic
	// rename keep the prior file until the replacement commits.
	return nil
}

// --- candidate discovery -------------------------------------------------------------------------

// Candidates lists the DISTINCT installation identities present in object labels, one per entry.
//
// A nil error means the listing is COMPLETE (possibly empty). An error means the runtime could not
// be asked about one of the three kinds, or could not be asked for one particular object's
// installation label — REFUSED rather than silently reporting a partial candidate set. A
// fewer-candidates answer here is how a repair adopts the wrong identity, or offers reinitialization
// while a real candidate exists whose label merely could not be read.
func Candidates(ctx context.Context, d Deps) ([]string, error) {
	if d.Engine == nil {
		return nil, errors.New("verbs: no container runtime connection — the identities present on this daemon cannot be established")
	}
	return candidates(ctx, d, repairReads(d.Engine).objs)
}

func candidates(ctx context.Context, d Deps, objs prov.Objects) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, class := range []prov.Class{prov.ClassContainer, prov.ClassVolume, prov.ClassNetwork} {
		names, err := objs.Names(ctx, class)
		if err != nil {
			return nil, fmt.Errorf("repair: the container runtime could not be asked which %ss exist, so the identities\n"+
				"  present on this daemon cannot be fully established. Refusing to report a partial list: %w", class, err)
		}
		for _, name := range names {
			if name == "" {
				continue
			}
			id, err := installOf(ctx, objs, class, name)
			if errors.Is(err, prov.ErrGone) {
				continue // gone since the listing was taken — nothing to count
			}
			if err != nil {
				return nil, fmt.Errorf("repair: %q (%s) could not be asked for its installation label, so candidate\n"+
					"  discovery cannot prove which identities are present on this daemon, or that there is\n"+
					"  only one. Refusing rather than silently omitting it — start the container runtime (or\n"+
					"  otherwise make it answer) and re-run: %w", name, class, err)
			}
			if id == "" {
				continue
			}
			// VALIDATE BEFORE TREATING IT AS A CANDIDATE — A LABEL VALUE CAN CONTAIN A NEWLINE.
			//
			// installOf reads the label verbatim and constrains nothing about its charset, only
			// that the runtime answered. The reference built this list by APPENDING each value
			// newline-terminated, so an unvalidated value was a direct injection: an object
			// labelled `installation=$'foreign\nvictim'` was reported as TWO candidates, "foreign"
			// AND "victim", and "victim" then passed the exact-line membership test for an
			// operator's choice even though no real object's label is the bare string "victim".
			// Choosing the forged half reset the ledger and recorded that identity — while the
			// rebuild loop, comparing the SAME raw label against the choice, found no object whose
			// label equalled it: state reset, and an identity adopted that owns nothing.
			//
			// Go's slice carries no delimiter to forge, so the injection cannot survive the append
			// here — but the membership test and the rebuild loop's comparison are still two reads
			// of one raw value, and validating at the source is what makes them agree. docfmt.IdentOK
			// is the SAME `ident` validator every minted identity, product name, role and volume name
			// already passes through; a minted identity ("i" + 10 lowercase hex) always satisfies it,
			// and nothing a forged or hand-edited label could carry that is not itself one clean
			// identity does.
			if !docfmt.IdentOK(id) {
				d.warn("repair: %q (%s) carries an installation label that is not a single\n"+
					"  well-formed identity. It is not reported as a candidate — a label that does not\n"+
					"  parse as exactly one identity cannot be trusted as one, forged or not. This object\n"+
					"  needs manual attention: inspect and relabel or remove it with the container\n"+
					"  runtime directly.", name, class)
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// installOf is THE ONE READER of an object's installation label, for every caller in this file that
// decides something from it — candidate discovery, the show listing, the post-reset rebuild loop and
// the network reconstruction.
//
// One implementation rather than the same read spelled four times, because the shape that gets
// spelled wrong is always the same: folding "the runtime could not answer" into an empty value
// indistinguishable from "no label". That is the exact silent miss this module exists to close — a
// second installation's object goes missing from candidate discovery instead of making discovery
// refuse to say "exactly one".
//
// nil error: the label is returned, and EMPTY is a real answer — an unlabelled object that is still
// present. prov.ErrGone: the object is gone (a listing/inspect race; a later run, or this same run's
// next step, may act on it). Any other error: the runtime could not answer. EVERY CALLER MUST FAIL
// CLOSED on the last one.
func installOf(ctx context.Context, objs prov.Objects, class prov.Class, name string) (string, error) {
	return labelOf(ctx, objs, class, name, prov.LabelInstall)
}

// nonceOf is the other half of provenance, with the same three-way split for the same reason: a
// nonce read that could not be answered must never be recorded as an empty or missing nonce, which
// is exactly the misidentification a nonce exists to prevent (§6a).
func nonceOf(ctx context.Context, objs prov.Objects, class prov.Class, name string) (string, error) {
	return labelOf(ctx, objs, class, name, prov.LabelNonce)
}

func labelOf(ctx context.Context, objs prov.Objects, class prov.Class, name, label string) (string, error) {
	v, err := objs.Label(ctx, class, name, label)
	if errors.Is(err, engine.ErrAbsent) {
		return "", prov.ErrGone
	}
	if err != nil {
		return "", err
	}
	return prov.NormalizeLabel(v), nil
}

// showCandidate lists one candidate's objects, ports and observed state, so the operator can tell
// which is theirs.
//
// BEST-EFFORT DISPLAY, and deliberately so: a listing or label-read failure for one kind or object
// is reported and skipped rather than aborting the whole report. The caller has already refused the
// OPERATION itself through Candidates, which applies the fail-closed rule this function does not
// need to repeat.
func showCandidate(ctx context.Context, d Deps, rd repairSeams, id string) {
	d.say("repair", "  identity %s", id)
	for _, class := range []prov.Class{prov.ClassContainer, prov.ClassVolume, prov.ClassNetwork} {
		names, err := rd.objs.Names(ctx, class)
		if err != nil {
			d.warn("repair: the container runtime could not be asked which %ss exist; this identity's\n"+
				"  %s objects are not listed.", class, class)
			continue
		}
		for _, name := range names {
			if name == "" {
				continue
			}
			lid, lerr := installOf(ctx, rd.objs, class, name)
			if errors.Is(lerr, prov.ErrGone) {
				continue
			}
			if lerr != nil {
				d.warn("repair: %q (%s) could not be asked for its installation label; it may or may\n"+
					"  not belong to identity %q and is left out of this listing.", name, class, id)
				continue
			}
			if lid != id {
				continue
			}
			if class != prov.ClassContainer {
				d.say("repair", "    %s %s", class, name)
				continue
			}
			obs := "?"
			if o, oerr := state.Observe(ctx, rd.state, name); oerr == nil {
				obs = string(o)
			}
			d.say("repair", "    %s %s  (%s, ports: %s)", class, name, obs, portsOf(ctx, d.Engine, name))
		}
	}
}

// portsOf renders a container's published ports the way the reference's inspect template did —
// `<port>=<hostip>:<hostport>;` per binding — or "?" when it could not be asked. Display only.
func portsOf(ctx context.Context, c *engine.Client, name string) string {
	if c == nil {
		return "?"
	}
	info, err := c.ContainerInspect(ctx, name)
	if err != nil {
		return "?"
	}
	var b strings.Builder
	for _, p := range runtime.Ports(info) {
		b.WriteString(p.ContainerPort + "=" + p.HostIP + ":" + p.HostPort + ";")
	}
	return b.String()
}

// --- state repair ---------------------------------------------------------------------------------

// StateRepair rebuilds what is reconstructible and is honest about what is not.
//
// THE ARITY IS CHECKED HERE, AT THE LIBRARY BOUNDARY, and the operand arrives as a SLICE precisely
// so it can be wrong. The reference accepted `<index> [identity|--reinitialize]` and once bounded
// that only from below, so a surplus third operand passed the check and was silently discarded —
// with MI_CONFIRM=yes already set, a malformed call that still reset the ledger and adopted an
// identity. The dispatcher rejects it too, but the operator-verb contract (a wrong argument count is
// refused, nothing attempted) has to hold for a caller of the library verb directly as well, not
// only through the CLI in front of it. A fixed `choice string` parameter would make the malformed
// call inexpressible and the refusal untestable — which is not the same as making it safe.
func StateRepair(ctx context.Context, d Deps, operands []string) int {
	if len(operands) > 1 {
		d.warn("verbs: state repair needs an <index> [identity|--reinitialize]")
		return cliio.ExitUsage
	}
	choice := ""
	if len(operands) == 1 {
		choice = operands[0]
	}
	if rc := daemonReady(ctx, d); rc != cliio.ExitOK {
		return rc
	}
	s, err := openRepairSession(d)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	defer s.close()
	return s.repair(ctx, choice)
}

// openRepairSession is openSession's ledger-tolerant sibling.
//
// IT DOES NOT READ THE LEDGER, and that is the whole difference. openSession reloads at the end and
// refuses when the read fails — correct for every other verb, and fatal here: repair exists to
// recover from ledgers the reader refuses, so opening through that door would make the one command
// that can fix a corrupt ledger the one command a corrupt ledger stops. The in-memory ledger starts
// EMPTY and is filled from disk only after the reset gate has decided what to do with the file.
func openRepairSession(d Deps) (*session, error) {
	if d.Engine == nil {
		return nil, errors.New("verbs: no container runtime connection — nothing can be created, started or verified")
	}
	h, err := famlock.Acquire(d.Home)
	if err != nil {
		return nil, err
	}
	st, lerr := ledger.Live(h)
	if lerr != nil {
		_ = famlock.Release(h)
		return nil, lerr
	}
	rt, rerr := runtime.New(h, d.Engine)
	if rerr != nil {
		_ = famlock.Release(h)
		return nil, rerr
	}
	return &session{d: d, h: h, st: st, rt: rt, objs: intent.Engine(d.Engine), l: &ledger.Ledger{}}, nil
}

func (s *session) repair(ctx context.Context, choice string) int {
	d := s.d
	rd := repairReads(d.Engine)

	cands, err := candidates(ctx, d, rd.objs)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	if len(cands) == 0 {
		// ZERO CANDIDATES IS NOT "NOTHING TO REPAIR": host state can exist with no labelled runtime
		// objects at all — a restore that carried the family home but no containers, or an operator
		// who removed them. Refusing here would deadlock the exact case §6b sends to repair.
		if choice != "" && choice != reinitialize {
			d.warn("repair: no runtime object carries identity %q.", choice)
			return cliio.ExitFail
		}
		d.warn("repair: no runtime object carries a mythicalOS installation label.")
		d.warn("  A new identity will be minted and the ledger rebuilt from host state alone.")
		d.warn("  CONSEQUENCES, in plain terms:")
		d.warn("    * EVERY TRUST FLOOR IS RESET. A withdrawn manifest could be replayed until new floors")
		d.warn("      are established. This is a real rollback window you are accepting.")
		d.warn("    * Any pre-existing runtime objects will not be recognised as this installation's. They")
		d.warn("      will be listed as unattributed and never touched.")
		if !d.ask("repair: reinitialize this installation?") {
			d.warn("repair: not confirmed.")
			return cliio.ExitFail
		}
		if err := s.resetLedger(); err != nil {
			d.warnErr(err)
			return cliio.ExitFail
		}
		nid, ierr := s.l.IdentEnsure()
		if ierr != nil {
			d.warnErr(ierr)
			return cliio.ExitFail
		}
		if perr := s.persist(); perr != nil {
			d.warnErr(perr)
			return cliio.ExitFail
		}
		d.say("repair", "repair: reinitialized with identity %s.", nid)
		reportResidual(d)
		return cliio.ExitOK
	}

	if choice == reinitialize {
		d.warn("repair: refusing to reinitialize — %d installation identity/identities were found, so", len(cands))
		d.warn("  the right answer is to choose one rather than mint a new one and strand these objects:")
		for _, c := range cands {
			showCandidate(ctx, d, rd, c)
		}
		return cliio.ExitFail
	}

	if choice == "" {
		// EXACTLY ONE CANDIDATE IS STILL SHOWN AND STILL CONFIRMED — silently adopting the only one
		// visible is how a second user's containers get claimed on a shared daemon.
		d.say("repair", "repair: found %d installation identity/identities on this daemon:", len(cands))
		for _, c := range cands {
			showCandidate(ctx, d, rd, c)
		}
		d.warn("repair: choose one explicitly: 'mythical-ctl state repair <identity>'.")
		d.warn("  Nothing has been changed. The other identities' objects are untouched.")
		return cliio.ExitFail
	}

	found := false
	for _, c := range cands {
		if c == choice {
			found = true
		}
	}
	if !found {
		d.warn("repair: %q is not one of the identities found on this daemon.", choice)
		return cliio.ExitFail
	}

	// TRUST FLOORS ARE NOT RECONSTRUCTIBLE. They are a record of history, and history is not in the
	// runtime. Repair RESETS them, which is a rollback window the operator explicitly accepts.
	d.warn("repair: rebuilding installer state for identity %q.", choice)
	d.warn("  WHAT IS RECOVERED: provenance for containers, volumes and networks, from their labels.")
	d.warn("  WHAT IS NOT:")
	d.warn("    * TRUST FLOORS. They record history, and history is not in the runtime. They are RESET,")
	d.warn("      which reopens a rollback window: a withdrawn manifest becomes acceptable again until")
	d.warn("      new floors are established.")
	d.warn("    * DESIRED STATE. It is set from what is observed now and reported as inferred, not")
	d.warn("      recovered — repair cannot know whether a stopped container was stopped deliberately.")
	d.warn("    * IMAGE PROVENANCE. Images cannot carry the label, so repair neither rebuilds it nor")
	d.warn("      enumerates the images — that list lived in the ledger being repaired.")
	if !d.ask("repair: proceed, accepting the reset of every trust floor?") {
		d.warn("repair: not confirmed. Nothing has been changed.")
		return cliio.ExitFail
	}
	return s.rebuild(ctx, rd, choice)
}

// rebuild is everything after the operator has chosen an identity and accepted the reset.
func (s *session) rebuild(ctx context.Context, rd repairSeams, choice string) int {
	d := s.d
	if err := s.resetLedger(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if err := s.l.Put(kindIdentity, "id", choice, []ledger.Field{{Key: "id", Value: choice}}); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	var inferred []string
	// NETWORKS, THEN VOLUMES, THEN CONTAINERS — the reference's order, and the containers' own
	// state commit reads attachments that the networks' records make sense of.
	for _, class := range []prov.Class{prov.ClassNetwork, prov.ClassVolume, prov.ClassContainer} {
		names, err := rd.objs.Names(ctx, class)
		if err != nil {
			d.warn("repair: the container runtime could not be asked which %ss exist, so provenance for", class)
			d.warn("  identity %q cannot be fully rebuilt. Stopping rather than reporting a repair that", choice)
			d.warn("  silently omitted some of its objects. The ledger already carries the new identity;")
			d.warn("  re-run 'mythical-ctl state repair %s' once the runtime answers.", choice)
			d.warnErr(err)
			return s.repairStop()
		}
		for _, name := range names {
			if name == "" {
				continue
			}
			// THIS RUNS AFTER THE LEDGER HAS BEEN RESET. A read that cannot be answered here is
			// more serious than the same read failing during candidate discovery: the OLD ledger is
			// already gone, so a silent skip does not leave provenance stale, it leaves it MISSING
			// — permanently, unless the operator is told to re-run. FAIL CLOSED, always, never
			// "skip this one and carry on".
			lid, lerr := installOf(ctx, rd.objs, class, name)
			if errors.Is(lerr, prov.ErrGone) {
				continue // gone since the listing was taken — nothing to rebuild
			}
			if lerr != nil {
				d.warn("repair: %q (%s) could not be asked for its installation label. The ledger has", name, class)
				d.warn("  already been reset for identity %q, and this object's provenance would be", choice)
				d.warn("  silently missing from the rebuild rather than merely stale. Stopping — re-run")
				d.warn("  'mythical-ctl state repair %s' once the runtime answers for it.", choice)
				d.warnErr(lerr)
				return s.repairStop()
			}
			if lid != choice {
				continue
			}
			nonce, nerr := nonceOf(ctx, rd.objs, class, name)
			if errors.Is(nerr, prov.ErrGone) {
				continue
			}
			if nerr != nil {
				d.warn("repair: %q (%s) carries identity %q, but its nonce could not be read.", name, class, choice)
				d.warn("  Recording provenance with no nonce — or the wrong one — is exactly the")
				d.warn("  misidentification a nonce exists to prevent (§6a). Stopping.")
				d.warnErr(nerr)
				return s.repairStop()
			}
			// PRESENT-BUT-EMPTY IS NOT THE SAME ANSWER AS UNREADABLE, AND NEITHER MAY BE ADOPTED.
			//
			// nonceOf answers with nil and an EMPTY value for an object whose nonce label was
			// successfully asked about and simply is not set — a real, reachable case for an object
			// this installer's own create path never labelled, or one whose label was stripped.
			// Recording provenance for it anyway writes `nonce=` (empty), a record every later
			// reader treats as unowned: prov.Authority refuses an empty-nonce record outright, so
			// the object this repair just claimed to recover becomes permanently unownable — no
			// deletion, no state commit, nothing can ever act on it through this installer again.
			if nonce == "" {
				d.warn("repair: %q (%s) carries identity %q, but no nonce label at all — the", name, class, choice)
				d.warn("  question was answered, and the answer was empty. A nonce is the only thing that")
				d.warn("  distinguishes this object from a different one that happens to carry the same")
				d.warn("  installation label, so an object without one cannot be proven ours. Recording")
				d.warn("  provenance for it would write a record every later authority check refuses to use —")
				d.warn("  it would be adopted and then permanently unownable. Resolve it with the container")
				d.warn("  runtime directly (re-create it under this installer, or remove it), then re-run.")
				return s.repairStop()
			}
			var extra []ledger.Field
			if class == prov.ClassNetwork {
				nid, iderr := rd.nets.NetworkID(ctx, name)
				if errors.Is(iderr, engine.ErrAbsent) {
					continue
				}
				if iderr != nil {
					d.warn("repair: %q (network) carries identity %q, but its id could not be read.", name, choice)
					d.warn("  A network is recorded BY its id (§6a), so there is nothing to record without one,")
					d.warn("  and recording an empty one would name a network that does not exist. Stopping.")
					d.warnErr(iderr)
					return s.repairStop()
				}
				extra = append(extra, ledger.Field{Key: "id", Value: nid})
			}
			if err := provRecord(s.l, class, name, nonce, extra...); err != nil {
				d.warnErr(err)
				return s.repairStop()
			}
			if class != prov.ClassContainer {
				continue
			}
			want, ierr := s.recoverContainerState(ctx, rd, name)
			if errors.Is(ierr, prov.ErrGone) {
				continue // gone since the label read a moment ago
			}
			if ierr != nil {
				d.warnErr(ierr)
				return s.repairStop()
			}
			inferred = append(inferred, fmt.Sprintf("    %s → %s (observed)", name, want))
		}
	}

	// The non-owned reference, from HOST CONFIG rather than the corrupt ledger — the one piece of
	// ledger content that is genuinely rebuildable, precisely because it never carried provenance.
	// It gains no deletion authority in the process; the class has none to grant.
	if err := s.repairNetref(ctx, rd, choice); err != nil {
		d.warnErr(err)
		return s.repairStop()
	}

	if len(inferred) > 0 {
		d.say("repair", "repair: desired state was inferred from observation, not recovered. Correct any that are wrong:")
		for _, line := range inferred {
			d.say("repair", "%s", line)
		}
	}

	// THE REBUILD IS MADE DURABLE BEFORE THE VERIFY LOOP RUNS, and this is not tidiness.
	//
	// Live verification goes through the probe arm, which writes the ledger FILE itself (it opens a
	// probe intent on disk before its container exists) — so the session ADOPTS the disk back after
	// every probe call, or it would persist its own copy straight over that intent. Adoption
	// replaces this session's ledger with what is on disk: everything the rebuild established in
	// memory and had not yet written would be silently discarded, and the repair would report
	// success over an empty rebuild. Writing first makes memory and disk agree before anything can
	// adopt, which is also exactly where the reference stood — it wrote every record as it made it.
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}

	if rc := s.repairVerifyRunning(ctx, rd, choice); rc != cliio.ExitOK {
		return rc
	}

	d.say("repair", "repair: no image is deleted, and repair cannot say which images were this installer's —")
	d.say("repair", "  that list lived in the ledger being repaired. Reporting it from a record just declared")
	d.say("repair", "  untrustworthy would be inventing the answer.")
	reportResidual(d)
	return cliio.ExitOK
}

// repairStop is the refusal path of a rebuild that has already reset the ledger: it PERSISTS what
// the rebuild established so far and reports operational failure.
//
// PERSISTING ON THE WAY OUT IS THE POINT, not an oversight. The reference wrote each record to the
// ledger file as it went, so a refusal partway through left the identity — and every object already
// rebuilt — on disk, which is exactly what its "the ledger already carries the new identity; re-run"
// message promises the operator. Discarding the in-memory edits here would leave the file EMPTY
// after a reset that already destroyed the old one, and the re-run the message names would then find
// no identity at all.
//
// A write that itself fails is reported and does not become success.
func (s *session) repairStop() int {
	if err := s.persist(); err != nil {
		s.d.warnErr(err)
	}
	return cliio.ExitFail
}

// recoverContainerState sets one recovered container's desired state and the checks it owes.
//
// OUTSTANDING CHECKS ARE INITIALIZED TO {alias} FOR EVERY RECOVERED CONTAINER — the same honest
// default as a schema migration: a rebuilt ledger cannot know whether any container's alias was ever
// verified on its current network, and defaulting to empty asserts a check that may never have
// happened.
//
// DESIRED STATE IS SET FROM OBSERVATION. The conservative failure is a container that crashed before
// the repair staying down; that is visible and fixable, where the opposite error silently restarts
// something deliberately stopped.
func (s *session) recoverContainerState(ctx context.Context, rd repairSeams, name string) (state.Desired, error) {
	obs, err := state.Observe(ctx, rd.state, name)
	if err != nil {
		return "", err
	}
	want := state.Stopped
	if obs == state.ObsRunning {
		want = state.Running
	}
	// `+none` DECLARES NO LIVE VERIFICATION IS OWED. That is only true when the container genuinely
	// HAS no network attachment, which requires having actually read its attachments — never a
	// failed read defaulted to empty. Recording `+none` from a question that was never answered
	// would assert nothing needs verifying for a container that may well be attached and running.
	nets, nerr := rd.live.Attachments(ctx, name)
	if errors.Is(nerr, engine.ErrAbsent) {
		return "", prov.ErrGone // gone since the label read a moment ago
	}
	if nerr != nil {
		return "", fmt.Errorf("repair: %q is recorded, but its network attachments could not be read, so whether\n"+
			"  it owes a live alias verification cannot be established.\n"+
			"  Recording '+none' from an unread state would assert no check is owed when one may be. Stopping: %w", name, nerr)
	}
	if len(nets) == 0 {
		// The attachment question WAS answered, and the answer was "none" — genuinely nothing to
		// check, unlike the failed-read case above.
		if err := state.Commit(s.l, name, want, nil, true); err != nil {
			return "", err
		}
		return want, nil
	}
	check := state.Check{Kind: state.CheckAlias, Param: nets[0].NetworkID}
	if err := state.Commit(s.l, name, want, []state.Check{check}, false); err != nil {
		return "", err
	}
	return want, nil
}

// repairVerifyRunning live-verifies the containers this run just recorded that are already RUNNING.
//
// They have addresses, so there is nothing to wait for; only stopped ones carry the entry forward to
// their next start.
func (s *session) repairVerifyRunning(ctx context.Context, rd repairSeams, choice string) int {
	d := s.d
	// THE LISTING'S OWN STATUS IS CHECKED BEFORE THE LOOP. A listing that cannot read one of its
	// records REFUSES rather than silently shortening (ledger.All's contract), and reading it as an
	// empty listing would leave every running container's outstanding check silently uncleared.
	recs, err := s.l.All(kindProvObj)
	if err != nil {
		d.warn("repair: the object records just written could not be read back, so running containers are")
		d.warn("  not live-verified this run. Their outstanding alias checks remain and are retried at their")
		d.warn("  next explicit start. Run 'mythical-ctl state repair %s' again.", choice)
		d.warnErr(err)
		return s.repairStop()
	}
	bd, berr := s.bringupDeps(nil, choice)
	if berr != nil {
		d.warnErr(berr)
		return s.repairStop()
	}
	for _, rec := range recs {
		if class, _ := ledger.FieldOf(rec, "class"); class != string(prov.ClassContainer) {
			continue
		}
		// FAIL CLOSED, not "skip it and carry on". These records were written by THIS run, so a
		// container-class record with no readable name is a malformed record this same run just
		// produced — and silently skipping one is silently skipping ITS observed-state and alias
		// verification while the repair as a whole still reports success. That is the same "reports
		// success while skipping a container's verification" gap a missing name would leave in
		// status, stop or restart, with no way to tell it apart from a container that was
		// legitimately never checked.
		c, ok := ledger.FieldOf(rec, "name")
		if !ok || c == "" {
			d.warn("repair: a container-class record this run just wrote carries no readable name, so its")
			d.warn("  observed state and alias cannot be live-verified. The ledger rebuild otherwise")
			d.warn("  completed; this is reported rather than silently skipped. Run 'mythical-ctl state")
			d.warn("  repair %s' again, and if it recurs, treat the ledger as damaged.", choice)
			return s.repairStop()
		}
		obs, oerr := state.Observe(ctx, rd.state, c)
		if oerr != nil {
			d.warn("repair: %q could not be asked whether it is running, so this run cannot live-verify it.", c)
			d.warn("  Its outstanding alias check, if any, is left exactly as recorded — never cleared on an")
			d.warn("  unread state.")
			continue
		}
		if obs != state.ObsRunning {
			continue
		}
		// "COULD NOT DETERMINE WHAT IS OWED" IS NEVER "NOTHING IS OWED" — the same rc-1-vs-rc-3
		// conflation this whole module exists to close, one reader over.
		checks, cerr := state.Outstanding(s.l, c)
		if cerr != nil {
			d.warn("repair: %q is running, but its outstanding checks could not be read, so what it owes", c)
			d.warn("  cannot be established. Left running; not live-verified this run.")
			continue
		}
		if len(checks) == 0 || checks[0].Param == "" {
			continue
		}
		netID := checks[0].Param
		alias, arerr := s.repairAlias(ctx, rd, c, netID)
		if arerr != nil {
			d.warnErr(arerr)
			continue
		}
		if alias == "" {
			continue
		}
		if verr := bringup.VerifyLive(ctx, s.l, bd, c, netID, alias); verr != nil {
			d.warn("repair: %q is running but its alias did not verify. Left running, still outstanding.", c)
			continue
		}
		if err := state.OutstandingClear(s.l, c, state.CheckAlias, netID); err != nil {
			d.warnErr(err)
			return s.repairStop()
		}
		// PERSISTED PER CONTAINER, for the same reason the rebuild is persisted before this loop:
		// the NEXT container's probe adopts the disk, and a clear left only in memory would be
		// adopted away — the check would silently come back outstanding on a container this run had
		// actually verified.
		if err := s.persist(); err != nil {
			d.warnErr(err)
			return cliio.ExitFail
		}
	}
	return cliio.ExitOK
}

// repairAlias derives the alias a running recovered container's outstanding check names.
//
// PREFER THE CANONICAL FAMILY ALIAS derived from the container's own product label — the value a
// normal bring-up would have used. Fall back to whatever alias the container actually carries on
// this network only when there was NO product label to derive from: a repaired object may carry none
// at all (D37), and this codebase does not require every recovered object to be reachable through
// the manifest to be live-verified.
//
// A PRESENT BUT INVALID PRODUCT LABEL IS NOT THE SAME CASE AS NO PRODUCT LABEL AT ALL, AND MUST NOT
// SHARE THAT FALLBACK. Swallowing the derivation failure and falling through verifies WHATEVER alias
// the container happens to carry, not necessarily the canonical family one its siblings actually
// resolve — and if that happened to verify, the outstanding check was cleared as "confirmed" from a
// malformed label, without ever checking the alias that matters.
//
// An empty return with a nil error means "nothing to verify this run", which the caller skips.
func (s *session) repairAlias(ctx context.Context, rd repairSeams, c, netID string) (string, error) {
	product, perr := rd.live.Label(ctx, c, "product")
	if errors.Is(perr, engine.ErrAbsent) {
		return "", nil // the container itself is gone
	}
	if perr == nil {
		product = prov.NormalizeLabel(product)
	} else {
		// Could not ask. NOT read as "no product label" — set it empty and fall straight to the
		// aliases-based reconstruction below, which is independently guarded on its OWN read.
		product = ""
	}
	if product != "" {
		alias, aerr := manifest.Alias(product)
		if aerr != nil {
			return "", fmt.Errorf("repair: %q carries a product label (%q) that is not a valid identifier, so the\n"+
				"  canonical family alias cannot be derived from it. Falling back to whatever alias\n"+
				"  happens to be registered would verify a different name than siblings actually resolve.\n"+
				"  Left running, still outstanding.", c, product)
		}
		return alias, nil
	}
	// THE ALIAS READ ITSELF MUST FAIL CLOSED — a container whose network aliases could not be asked
	// about is not "carries no alias on this network" (which skips harmlessly, leaving the check
	// outstanding for a legitimate reason); it is "this run could not attempt live verification at
	// all", and the difference is worth saying so the operator does not read silence as "nothing was
	// owed".
	nets, nerr := rd.live.Attachments(ctx, c)
	if errors.Is(nerr, engine.ErrAbsent) {
		return "", nil // gone since the observation a moment ago
	}
	if nerr != nil {
		return "", fmt.Errorf("repair: %q is running, but its network aliases could not be read, so live\n"+
			"  verification cannot be attempted this run. Left running, still outstanding: %w", c, nerr)
	}
	for _, n := range nets {
		if n.NetworkID != netID {
			continue
		}
		if len(n.Aliases) == 0 {
			return "", nil
		}
		return n.Aliases[0], nil
	}
	return "", nil
}

// reportResidual re-states, at the end of every repair, what repair cannot prove.
//
// A dead client's lock is broken automatically (§4b.3a), but the DAEMON may still be completing a
// create that client had already issued — so an object can appear after repair's snapshot and be
// absent from the rebuilt ledger.
//
// THE ORDINARY RECONCILIATION CANNOT RESCUE A LATE ARRIVAL AFTER A REPAIR: rebuilding the ledger
// destroys the intent the object would have been matched against, and a zero-candidate
// reinitialization mints a NEW identity, so an object labelled with the old one can never match.
// Such an object is STRANDED.
func reportResidual(d Deps) {
	d.warn("repair: stated residual — repair cannot prove nothing is in flight.")
	d.warn("  The lock excludes other mythical-ctl processes, but the daemon may still be completing a")
	d.warn("  create that a dead client already issued. Such an object appears after this snapshot and")
	d.warn("  is absent from the rebuilt ledger — and ordinary reconciliation cannot rescue it, because")
	d.warn("  the intent it would have matched is gone.")
	d.warn("  It shows up in 'status' as an unattributed or unrecorded object. Reattaching one is a")
	d.warn("  distinct operation and is OUT OF SCOPE — adopting a different installation identity into a")
	d.warn("  healthy ledger must not be improvised, because getting it wrong adopts another user's")
	d.warn("  containers. Until it is designed, the remedy is the container runtime directly.")
}

// --- the network reference, reconstructed from host config -----------------------------------------

// repairNetref re-resolves MYTHICAL_NET and records it — but only after COMPARING it against where
// the containers actually are.
//
// D46: any path that changes which network the ledger names goes through D45's phased migration —
// rebind, repair, OR a schema migration. Re-resolving a name during a repair and recording it IS a
// network change: if the name now identifies a DIFFERENT network, the ledger moves while the FLEET
// stays, which is precisely the silent DNS split D45 exists to prevent, entered through the repair
// door instead of the rebind door and with no confirmation anywhere on it.
func (s *session) repairNetref(ctx context.Context, rd repairSeams, ident string) error {
	d := s.d
	name, set, cerr := familyNet(d.Home)
	if cerr != nil {
		return fmt.Errorf("repair: mythical.conf could not be read, so which network this family joins cannot be\n"+
			"  established. Nothing recorded: %w", cerr)
	}
	if !set {
		return nil // no override: the installer's own network, nothing to rebuild
	}
	resolved, rerr := netref.RefResolve(ctx, rd.nets, name)
	if rerr != nil {
		return rerr
	}

	names, lerr := rd.objs.Names(ctx, prov.ClassContainer)
	if lerr != nil {
		return fmt.Errorf("repair: the container runtime could not be asked which containers exist, so whether the\n"+
			"  fleet agrees about its network cannot be established. Nothing recorded: %w", lerr)
	}

	var fleet []string
	common, first := "", ""
	disagree, sawHome := false, false
	for _, c := range names {
		if c == "" {
			continue
		}
		lid, lidErr := installOf(ctx, rd.objs, prov.ClassContainer, c)
		if errors.Is(lidErr, prov.ErrGone) {
			continue // gone since the listing — not a vote either way
		}
		if lidErr != nil {
			return fmt.Errorf("repair: %q could not be asked for its installation label, so whether the fleet agrees\n"+
				"  about its network cannot be established. Recording a reference on an incomplete answer\n"+
				"  is how the ledger ends up naming a network a container may still be split from.\n"+
				"  Nothing recorded: %w", c, lidErr)
		}
		if lid != ident {
			continue
		}
		// THE FLEET THIS RECONSTRUCTED MIGRATION WILL ACT ON — every container carrying this
		// identity's label, unconditionally. Recorded BEFORE the network-agreement check below, so a
		// container with no attachments at all (which contributes no vote) is still part of the
		// fleet a migration would have to move.
		fleet = append(fleet, c)

		nets, nerr := rd.live.Attachments(ctx, c)
		if errors.Is(nerr, engine.ErrAbsent) {
			continue // gone since the label read a moment ago
		}
		if nerr != nil {
			return fmt.Errorf("repair: %q carries this identity's label, but its network attachments could not be\n"+
				"  read. A container that may still be on a DIFFERENT network cannot be ruled out on an\n"+
				"  unanswered question. Nothing recorded: %w", c, nerr)
		}
		// THE CONTAINER'S FULL DISTINCT ATTACHMENT SET, NOT JUST ITS FIRST ENTRY. A container
		// mid-migration (interrupted between D45 phases 2 and 4) is attached to BOTH the old network
		// and the configured target at once. Taking only the first entry silently dropped the other:
		// if the target happened to be listed first for every container — no runtime guarantees
		// attachment order — every container's "one" value was the target, the common network came
		// out equal to the resolved one, and a CLEAN reference was recorded with no migration
		// intent. The old attachment then had no record anywhere: the ledger reported the migration
		// complete while it had not even been recorded as started.
		set := map[string]bool{}
		var ids []string
		for _, n := range nets {
			if n.NetworkID == "" || set[n.NetworkID] {
				continue
			}
			set[n.NetworkID] = true
			ids = append(ids, n.NetworkID)
		}
		if len(ids) == 0 {
			continue // unattached — not a vote either way
		}
		// CLASSIFY THE SET AGAINST THE RESOLVED TARGET rather than trusting whichever id came first.
		// Exactly {resolved} is "already home" and contributes no source signal. Exactly one OTHER
		// id — alone, or alongside resolved — is this container's SOURCE signal, whether it has not
		// been touched yet or is already mid-migration; rebind's own phase 2 is idempotent for a
		// container already connected to the target, so both shapes enter the SAME migration with
		// the SAME source. Anything else (two ids, neither resolved; or three or more at all) does
		// not fit the single-source, single-target shape D45 assumes and is a disagreement in its
		// own right, not something to resolve by picking one.
		source := ""
		anomalous := len(ids) > 2
		for _, id := range ids {
			if id == resolved {
				continue
			}
			if source == "" {
				source = id
			} else {
				anomalous = true
			}
		}
		if anomalous {
			disagree = true
			continue
		}
		if source == "" {
			sawHome = true
			continue
		}
		if first == "" {
			first, common = source, source
		} else if source != first {
			disagree = true
		}
	}

	// AN ALL-HOME FLEET (every attached container's set was exactly {resolved}, so none ever
	// contributed a source signal) is the clean case, not "no attachments at all" — the
	// empty-fleet-vs-unattached distinction below depends on an empty `common` meaning "nothing to
	// compare", which is not true here.
	if common == "" && sawHome {
		common = resolved
	}

	if disagree {
		return errors.New("repair: the containers do not agree about which network they are on. The fleet is already split\n" +
			"  and a migration cannot pick a side. Stopping.\n" +
			"  Resolve it with the container runtime — attach them all to one network — then re-run.")
	}

	if common == "" {
		// AN EMPTY `common` IS NOT ONE FACT. It means "no containers carry this identity" ONLY when
		// the fleet is ALSO empty — the fleet is recorded unconditionally for every matching
		// container, before the per-container attachment check, so a container that exists but is
		// UNATTACHED (or whose attachments could not be resolved to one common network) leaves the
		// fleet non-empty while `common` stays empty. Recording the configured name as a clean
		// reference in THAT case would make it the family network while the recovered containers are
		// not attached to it at all — the exact split D46 exists to prevent, arrived at from the
		// empty-fleet branch instead of the disagreement branch above.
		if len(fleet) > 0 {
			return errors.New("repair: this identity has containers, but none of them share a single attached\n" +
				"  network — each is either unattached, or its attachments could not be resolved to one.\n" +
				"  Recording a clean reference here would make it the family network while\n" +
				"  the recovered containers are not attached to it — a split state repair must not create.\n" +
				"  Attach them to a network with the container runtime (or start them — bring-up attaches\n" +
				"  at creation) and re-run.")
		}
		// Genuinely no containers carry this identity at all: record it; there is nothing to migrate.
		return s.putNetRef(resolved, name)
	}

	if common == resolved {
		return s.putNetRef(resolved, name)
	}

	d.warn("repair: MYTHICAL_NET names %q, which resolves to %s — but the containers are", name, resolved)
	d.warn("  actually on %s. That differs, so the reference is NOT simply recorded.", common)
	d.warn("  Recording the resolved ID alone would move the ledger while the fleet stayed put: every")
	d.warn("  product would report healthy while no product resolved any sibling.")
	if !d.ask(fmt.Sprintf("repair: enter the phased network migration (%s → %s)?", common, resolved)) {
		return errors.New("repair: not confirmed. Nothing recorded.")
	}

	// THE MIGRATION MUST NOT CLAIM AN EMPTY FLEET, AND MUST NOT CLAIM A PARTIAL ONE EITHER. The
	// fleet is structurally non-empty whenever `common` is (both come out of the same loop), but a
	// migration record with an empty container set, or holding only SOME of the fleet, is one
	// netref.MigResume can never finish correctly: its own fleet is read straight back FROM this
	// field, never re-enumerated, so 'net rebind' would migrate only the containers this field
	// happens to name and leave the rest on the source network while still committing the new
	// reference as if the move were complete.
	if len(fleet) == 0 {
		return errors.New("repair: the fleet for this migration could not be enumerated as non-empty, so recording a\n" +
			"  migration intent that claims one would leave 'net rebind' nothing to actually move.\n" +
			"  Nothing recorded.")
	}

	// BOTH WRITES, IN ONE ATOMIC STEP is what §6b.1 requires — the reference set to the OBSERVED id,
	// and a D45 intent naming that same id as SOURCE and the resolved id as target. Recording only
	// the resolved target would leave the ledger claiming a network the containers are not on, with
	// no source recorded to migrate them FROM. Repair's job is to reach a RESUMABLE state, not a
	// finished one. Here the pair is two in-memory edits the session's single write persists, so a
	// crash between them cannot happen — there is no between.
	if err := s.putNetRef(common, name); err != nil {
		return err
	}
	if err := s.l.Put(kindNetMig, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "phase", Value: "1"},
		{Key: "source", Value: common},
		{Key: "target", Value: resolved},
		{Key: "containers", Value: strings.Join(fleet, ",")},
	}); err != nil {
		return err
	}
	d.warn("repair: recorded the observed network as the reference and a migration intent to move the")
	d.warn("  fleet onto %q. Resume it with 'mythical-ctl net rebind'.", name)
	return nil
}

// putNetRef records the operator-supplied network reference. It is written directly rather than
// through netref.RefCommit because the migration branch above must record the network the
// containers are OBSERVED on, which RefCommit refuses by design (it accepts only a target that
// matches where MYTHICAL_NET resolves right now).
//
// `owned=no` is not decoration: an operator-supplied network is ATTACH-ONLY, and repair confers no
// deletion authority it did not have — the class has none to grant.
func (s *session) putNetRef(id, name string) error {
	return s.l.Put(kindNetRef, "key", "family", []ledger.Field{
		{Key: "key", Value: "family"},
		{Key: "id", Value: id},
		{Key: "name", Value: name},
		{Key: "owned", Value: "no"},
	})
}

// --- the reset gate --------------------------------------------------------------------------------

// resetLedger empties the ledger of everything EXCEPT the trust anchor, keeping the file valid.
//
// THE ANCHOR SURVIVES; EVERYTHING ELSE DOES NOT — and that is not a smaller reset, it is the correct
// one. The anchor names the specific index digest this installation authenticated over TLS from a
// known origin (D21/§8.1); that fact is not runtime history the way the version FLOORS are, and the
// index file itself is untouched by a repair. Dropping it would force a fresh online bootstrap for
// no security benefit AND make live verification impossible for the rest of this same repair run,
// since the probe's image comes from an accepted index and accepting refuses outright with no anchor
// recorded. The FLOORS genuinely cannot be reconstructed from anything outside the ledger being
// repaired — that is the real rollback window this repair opens, stated to the operator — and
// dropping them does not touch what the anchor protects: an attacker still cannot swap the index
// itself for a different one without failing digest verification.
//
// "THE READ FAILED" IS NOT ONE FACT, and this gate is the only place in the tree that gets the finer
// distinction. ledger.ConfirmedCorrupt answers the ONE question this gate needs answered — "is this
// positively, provably corrupt, or not?" — and reaches "yes" only once it holds a complete, faithful
// copy of the bytes on disk whose own checksum disagrees with what they claim, or which fail to
// parse as a ledger at all. That is evidence about the ledger's CONTENT. A transient I/O failure
// while this call was probing a perfectly good ledger is not, and destroying on it would discard the
// trust anchor and every rollback floor on nothing more than "the read failed once".
//
// THE HEADER IS PEEKED AT FIRST, ahead of either ledger call, and it is not merely a nicer
// diagnostic. A ledger written by a NEWER build carries a schema this one refuses — but an operator
// arriving here has usually also disturbed the file, so its checksum need not still match, and
// ledger.Read gates the schema only AFTER integrity. Such a file would reach the destroy branch as
// "confirmed corrupt" and be renamed aside, discarding everything a newer mythical-ctl recorded,
// through the repair door instead of the read door. The peek reads ONLY the header line's schema
// number and says nothing whatever about the checksum or the body.
func (s *session) resetLedger() error {
	home, herr := famlock.HomeOf(s.h)
	if herr != nil {
		return herr
	}
	path := filepath.Join(home, ".state", "ledger")

	// PRESENT means what the reference's `[ -f ]` means: a regular file, symlinks followed.
	present := false
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		present = true
	}

	if present {
		if f, err := os.Open(path); err != nil {
			if os.IsPermission(err) {
				// A PERMISSIONS PROBLEM IS AN OPERATIONAL FACT ABOUT THIS PROCESS, not evidence
				// about the ledger's CONTENT — the bytes underneath may be perfectly valid.
				// Refusing (never touching, never moving) is the only honest answer to a question we
				// structurally cannot ask.
				return errors.New("repair: the ledger exists but is not readable by this process. That is a permissions or\n" +
					"  ownership problem, not evidence the ledger's content is corrupt — nothing here has been\n" +
					"  touched or moved. Fix the permission (or re-run as the user that owns the family home)\n" +
					"  and re-run.")
			}
		} else {
			_ = f.Close()
		}

		if schema, ok := ledgerSchemaOf(path); ok && decGTSchema(schema, ledger.Schema) {
			return fmt.Errorf("repair: this ledger's schema (%s) is newer than this build of mythical-ctl\n"+
				"  understands (%s). That is not corruption — it is D35's own gate doing\n"+
				"  its job — and repairing over it would rename a STILL-VALID ledger aside and replace\n"+
				"  it with an empty one, discarding everything a newer mythical-ctl already recorded.\n"+
				"  Install the current mythical-ctl release and re-run. Nothing here has been touched.", schema, ledger.Schema)
		}
		// A header this function does not recognise at all (empty file, no header line, non-numeric
		// schema) falls through to the ordinary corrupt-ledger path below, which is the right answer
		// for every one of them: none is "valid, just newer".

		switch {
		case ledgerConfirmedCorrupt(s.st):
			// POSITIVELY CONFIRMED corrupt content — the ONLY failure this function treats as
			// licence to destroy.
			aside := fmt.Sprintf("%s.corrupt.%d", path, os.Getpid())
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf("repair: cannot move the corrupt ledger aside: %w", err)
			}
			s.d.warn("repair: the corrupt ledger has been PRESERVED at %s — it is evidence, not rubbish.", aside)
			s.d.warn("  Its trust anchor could not be salvaged either — nothing here was readable to salvage it")
			s.d.warn("  from — so this installation will need to be online once to re-establish it.")
			if err := ledger.Write(s.h, s.st, &ledger.Ledger{}); err != nil {
				return err
			}
			return s.reload()
		default:
			if _, err := ledgerRead(s.st); err != nil {
				// Present, a regular file, NOT positively confirmed corrupt, and still could not be
				// read — a transient read/IO failure while THIS call was copying or hashing an
				// otherwise-perfectly-good file looks, from here, indistinguishable from real
				// damage. Asking ConfirmedCorrupt FIRST is precisely so we do not guess: renaming
				// this aside or replacing it would destroy a possibly-still-valid ledger, and its
				// trust anchor and rollback floors along with it, on exactly that guess.
				return fmt.Errorf("repair: the ledger exists but could not be read, and nothing here positively confirms\n"+
					"  its content is corrupt — this can be a transient read or I/O failure rather than actual\n"+
					"  damage. Refusing to move it aside or replace it on a guess; nothing has been touched.\n"+
					"  Re-run; if this persists, investigate the filesystem/storage this installation's state\n"+
					"  lives on before repairing further: %w", err)
			}
		}
	}

	// From here the ledger is absent or reads clean. Decide what to keep.
	kept := ""
	l, err := ledgerRead(s.st)
	if err != nil && !errors.Is(err, ledger.ErrMissingLedger) {
		// Unreachable in practice — the guard above already proved a present ledger reads clean —
		// but refusing on an unrecognised outcome is the direction the rest of this module answers.
		return err
	}
	if err == nil {
		anchors := anchorRows(l)
		// VALIDATE, DON'T JUST COPY. The whole-ledger checksum proves the bytes were not altered
		// after they were written; it proves nothing about whether the ROW ITSELF is one this
		// codebase's own writer produced. A restored or hand-assembled ledger can carry TWO
		// trust-anchor rows (checksum-valid, still ambiguous — the exact shape a later trust read
		// refuses on) or ONE whose digest field is empty or malformed. Blindly preserving either
		// shape reports the repair a success, and the FIRST later trust read — at the very next
		// probe or install — then refuses the anchor, wedging an installation this repair had just
		// claimed to fix.
		switch {
		case len(anchors) > 1:
			s.d.warn("repair: this ledger recorded %d trust anchors, not one — an ambiguous record", len(anchors))
			s.d.warn("  a later trust read would refuse to guess between. Dropping all of them rather than")
			s.d.warn("  silently preserving a record that would only wedge the next command that reads it.")
			s.d.warn("  GUARANTEE LOST: the authenticated root of trust. This installation will need to be")
			s.d.warn("  online once to re-establish it — the same requirement a first install has.")
		case len(anchors) == 1 && !hex64OK(anchors[0]):
			s.d.warn("repair: this ledger's trust anchor is recorded but is not a usable digest (empty or")
			s.d.warn("  malformed) — the whole-ledger checksum proves the bytes were not altered after they")
			s.d.warn("  were written, not that this record is one this installer's own writer ever produced.")
			s.d.warn("  Dropping it rather than preserving a record every later trust read would refuse.")
			s.d.warn("  GUARANTEE LOST: the authenticated root of trust. This installation will need to be")
			s.d.warn("  online once to re-establish it — the same requirement a first install has.")
		case len(anchors) == 1:
			kept = anchors[0]
		}
	}

	if err := ledger.Write(s.h, s.st, &ledger.Ledger{}); err != nil {
		return err
	}
	// THE ANCHOR IS RE-RECORDED THROUGH ITS OWN WRITER, in a second write.
	//
	// The trust module keeps a raw-line record shape whose kind the typed ledger editors refuse
	// ('-' is not in their grammar), so there is no way to place the anchor row into the replacement
	// ledger before it is written; trust.AnchorSet is the only door, and it performs its own
	// read-modify-write. RESIDUAL, stated rather than hidden: a crash in the window between these
	// two writes loses the anchor, and this installation then needs to be online once to
	// re-establish it — the same requirement a first install has, and strictly smaller than the
	// trust-floor reset the operator has already accepted on this path. It is never worse than that:
	// the anchor is dropped, never replaced by an unverified one.
	if kept != "" {
		if err := trust.AnchorSet(s.h, s.st, kept); err != nil {
			return err
		}
	}
	return s.reload()
}

// anchorRows returns the digest of every trust-anchor row, INCLUDING rows that carry no usable one
// (as the empty string) — a count that skipped them would read two anchors as one.
//
// A ROW MUST CARRY EXACTLY ONE `digest=` FIELD to have a digest at all. Taking the last of several
// would resolve an ambiguity by picking one, which is the single thing this module never does — and
// it would resolve it INVISIBLY: the rebuilt ledger would carry one clean anchor row, so nothing
// downstream could ever tell that the record it came from named two different digests. The
// authoritative reader refuses such a ledger outright (it collects every `digest=` value across
// every anchor row and refuses more than one), so preserving a guess here would also disagree with
// the only code that has to live with the answer.
func anchorRows(l *ledger.Ledger) []string {
	var out []string
	for _, line := range l.Lines() {
		rest, ok := strings.CutPrefix(line, trustAnchorKind+"\t")
		if !ok {
			continue
		}
		digest, seen := "", 0
		for _, tok := range strings.Split(rest, "\t") {
			if v, ok := strings.CutPrefix(tok, "digest="); ok {
				digest = v
				seen++
			}
		}
		if seen != 1 {
			digest = ""
		}
		out = append(out, digest)
	}
	return out
}

// hex64OK: 64 lowercase hex characters, the shape trust's own writer validates before it ever
// records one. Repeated here rather than imported because internal/trust keeps it unexported;
// TestRepairAnchorValidatorMatchesTrust pins the two against each other.
func hex64OK(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

// ledgerSchemaOf peeks at the ledger's header WITHOUT going through the fail-closed reader.
//
// Repair's whole point is to recover from files that reader refuses, and the one thing it must not
// do is treat "refused because it is NEWER" the same as "refused because it is corrupt". This reads
// and validates ONLY the header line's schema number; it says nothing about the checksum or the
// body, and a caller MUST NOT read its success as "the ledger is valid".
//
// ok=false means the file has no header this function recognises as one (missing, empty, malformed,
// non-numeric schema) — the caller's cue to fall through to the ordinary corrupt-ledger handling.
func ledgerSchemaOf(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	header, _, _ := strings.Cut(string(data), "\n")
	schema, ok := strings.CutPrefix(header, "#mythical-ctl-ledger schema=")
	if !ok || schema == "" {
		return "", false
	}
	for i := 0; i < len(schema); i++ {
		if schema[i] < '0' || schema[i] > '9' {
			return "", false
		}
	}
	return schema, true
}

// decGTSchema compares two all-digit decimal strings, a > b, without integer conversion — an
// arbitrarily long schema must refuse as NEWER, never overflow into a parse.
func decGTSchema(a, b string) bool {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

// --- state abandon-intent --------------------------------------------------------------------------

// AbandonIntent ages out a write-ahead intent whose object never appeared (D39's bounded retention).
//
// It does NOT guarantee the object will never appear: the installer cannot distinguish "never
// created" from "not yet visible", so this is a bounded, confirmed give-up, and the next operation
// stops and reports the object if it does turn up.
func AbandonIntent(ctx context.Context, d Deps, class, name string) int {
	if class == "" || name == "" {
		d.warn("verbs: state abandon-intent needs <class> <name>")
		return cliio.ExitUsage
	}
	grace, gerr := intentGrace(d.Env)
	if gerr != nil {
		d.warnErr(gerr)
		return cliio.ExitFail
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

	// THE CLASS IS NOT VALIDATED HERE. intent.Abandonable refuses an unknown one itself, and the
	// reference delegates it the same way — refusing here as a USAGE error instead would answer the
	// same malformed invocation with a different exit code than the reference gives it.
	c := prov.Class(class)
	if err := intent.Abandonable(ctx, s.l, s.objs, c, name, timeNow(), grace); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	d.warn("verbs: abandoning the intent for %s %q.", class, name)
	d.warn("  The installer cannot distinguish 'never created' from 'not yet visible', so this does NOT")
	d.warn("  guarantee the object will never appear. If it does, the next operation stops and reports it.")
	if !d.ask("verbs: abandon this intent?") {
		d.warn("verbs: not confirmed.")
		return cliio.ExitFail
	}
	advisory, aerr := intent.Abandon(ctx, s.l, s.objs, c, name, timeNow(), grace)
	if aerr != nil {
		d.warnErr(aerr)
		return cliio.ExitFail
	}
	if err := s.persist(); err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	if advisory != "" {
		d.warn("%s", advisory)
	}
	return cliio.ExitOK
}

// intentGrace reads MI_INTENT_GRACE, the operator-facing knob RECOVERY.md documents beside this
// verb: how long an intent must have been open before it may be aged out.
//
// A MALFORMED VALUE REFUSES, and that direction is the whole reason this is parsed rather than
// compared. The reference compared with `[ N -lt "$G" ]`, which on a non-numeric threshold prints
// "integer expression expected" and returns 2 — read by an `if` as FALSE, so a mistyped threshold
// silently made EVERY intent immediately abandonable. Parsing to a typed duration removes the
// comparison failure entirely; what survives is the refusal of a value that is not a count of
// seconds, and of a negative one, which fails open in exactly the same direction.
func intentGrace(env []string) (time.Duration, error) {
	for _, kv := range env {
		v, ok := strings.CutPrefix(kv, "MI_INTENT_GRACE=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("verbs: MI_INTENT_GRACE is %q, which is not a number of seconds. Refusing rather than\n"+
				"  aging out every intent from a threshold nothing could read.", v)
		}
		return time.Duration(n) * time.Second, nil
	}
	return intent.DefaultGrace, nil
}

// --- net rebind ---------------------------------------------------------------------------------

// The two migration entry points, behind a seam.
//
// It exists for ONE test, and for a real reason: both of these end by re-reading a migration record
// they were just told exists, and an operational race in that window (the daemon completing
// something under a lock that excludes other mythical-ctl processes but not the daemon itself) makes
// that inner read answer ABSENT. The reference leaked that answer out of the verb unchanged as rc 3
// — "not launched" at this CLI's contract boundary, which is the wrong meaning for a race during a
// rebind this call itself just started: automation reading it that way would think nothing happened
// while the fleet may already be partway migrated. The race is not constructible from outside a
// single synchronous call, so the seam lets a test hand back exactly what a raced call answers.
var (
	netRebindFn = netref.Rebind
	netResumeFn = netref.MigResume
)

// NetRebind moves this installation onto the network MYTHICAL_NET names, or resumes a migration
// already recorded.
func NetRebind(ctx context.Context, d Deps) int {
	if rc := daemonReady(ctx, d); rc != cliio.ExitOK {
		return rc
	}
	s, err := openSession(d)
	if err != nil {
		d.warnErr(err)
		return cliio.ExitFail
	}
	defer s.close()
	return s.netRebind(ctx)
}

func (s *session) netRebind(ctx context.Context) int {
	d := s.d

	// A RECORDED MIGRATION RESUMES RATHER THAN STARTING A NEW ONE, and the three-way answer matters:
	// found · genuinely absent · unreadable-or-ambiguous. Treating the last like the second falls
	// through to starting a FRESH rebind — writing phase 1 over an in-flight migration record nobody
	// could read, discarding the only account of where the fleet came from.
	_, merr := s.l.Find(kindNetMig, "key", "family")
	switch {
	case merr == nil:
		// CONFIRMATION COVERS RESUME TOO, NOT ONLY A FRESH REBIND. Resuming is not a read:
		// depending on the recorded phase it can connect containers to the target, DETACH them from
		// the source, and commit the new reference — the same destructive, fleet-mutating steps a
		// fresh rebind performs, picked up partway through. Skipping the gate here would let an
		// explicit refusal be silently overridden the moment a migration was already recorded.
		d.warn("verbs: a network migration is already recorded and will be resumed from its saved phase.")
		d.warn("  Depending on where it stopped, resuming can connect containers to the target network,")
		d.warn("  detach them from the source, and commit the new reference. This is never automatic.")
		if !d.ask("verbs: resume the recorded migration?") {
			d.warn("verbs: not confirmed.")
			return cliio.ExitFail
		}
		d.say("netrebind", "verbs: resuming the recorded network migration.")
		md, derr := s.migDeps()
		if derr != nil {
			d.warnErr(derr)
			return cliio.ExitFail
		}
		return s.finishMigration(netResumeFn(ctx, s.l, md))
	case errors.Is(merr, ledger.ErrAbsentRecord):
		// Genuinely nothing to resume.
	default:
		d.warn("verbs: whether a network migration is already recorded could not be read from the")
		d.warn("  ledger. Starting a fresh rebind now could write over an in-flight migration's intent")
		d.warn("  — the only record of where the fleet came from. Nothing is started.")
		d.warnErr(merr)
		return cliio.ExitFail
	}

	name, set, cerr := familyNet(d.Home)
	if cerr != nil {
		d.warn("verbs: mythical.conf could not be read, so whether MYTHICAL_NET is set cannot be")
		d.warn("  established — this is not the same as it being unset. Nothing is started.")
		d.warnErr(cerr)
		return cliio.ExitFail
	}
	if !set {
		d.warn("verbs: MYTHICAL_NET is not set, so there is no operator-supplied network to rebind onto.")
		return cliio.ExitFail
	}
	rd := repairReads(d.Engine)
	id, rerr := netref.RefResolve(ctx, rd.nets, name)
	if rerr != nil {
		d.warnErr(rerr)
		return cliio.ExitFail
	}
	d.warn("verbs: rebinding this installation onto network %q (%s).", name, id)
	d.warn("  Every existing container will be connected to it and verified BEFORE any is detached from")
	d.warn("  the old one, so no step leaves the family partitioned. This is never automatic: a silent")
	d.warn("  rebind is how a container gets joined to a network you did not intend.")
	if !d.ask(fmt.Sprintf("verbs: rebind onto %q?", name)) {
		d.warn("verbs: not confirmed.")
		return cliio.ExitFail
	}
	md, derr := s.migDeps()
	if derr != nil {
		d.warnErr(derr)
		return cliio.ExitFail
	}
	return s.finishMigration(netRebindFn(ctx, s.l, md, id))
}

// finishMigration persists whatever the migration machine established and NORMALIZES its outcome to
// the CLI's own contract.
//
// THE LEDGER IS PERSISTED ON BOTH OUTCOMES. The migration machine writes its own phase markers ahead
// of the two destructive phases, but the others are in-memory edits on the session's ledger — so a
// run that advanced through phase 5 and then refused at phase 6 has real, resumable progress in hand
// that must reach disk, exactly as the reference's per-record writes left it there.
//
// ONLY 0, 1 AND 2 LEAVE THIS VERB. Exit 3 means "not launched", which is a manifest concept with no
// meaning here — see the seam above for the race that produces the "absent" answer being normalized.
func (s *session) finishMigration(advisory string, err error) int {
	perr := s.persist()
	if err != nil {
		s.d.warnErr(err)
		if perr != nil {
			s.d.warnErr(perr)
		}
		return cliio.ExitFail
	}
	if perr != nil {
		s.d.warnErr(perr)
		return cliio.ExitFail
	}
	if advisory != "" {
		s.d.warn("%s", advisory)
	}
	return cliio.ExitOK
}

// migDeps assembles the migration machine's dependencies from the session's own seams.
func (s *session) migDeps() (netref.MigDeps, error) {
	ident, err := s.l.IdentGet()
	if err != nil {
		return netref.MigDeps{}, fmt.Errorf("verbs: the installation identity could not be read, so which containers this migration\n"+
			"  would move cannot be established. Nothing is started: %w", err)
	}
	name, _, cerr := familyNet(s.d.Home)
	if cerr != nil {
		return netref.MigDeps{}, cerr
	}
	p, perr := s.prober(ident)
	if perr != nil {
		return netref.MigDeps{}, perr
	}
	bd, berr := s.bringupDeps(nil, ident)
	if berr != nil {
		return netref.MigDeps{}, berr
	}
	rd := repairReads(s.d.Engine)
	return netref.MigDeps{
		Deps: netref.Deps{
			Intent:     s.objs,
			Configured: name,
			NewNonce:   intent.NonceNew,
			Now:        time.Now,
			Persist:    s.persistFn(),
		},
		Objs:   rd.nets,
		Mut:    s.rt,
		Probe:  migProber{sessionProber: sessionProber{p: p, s: s}, full: p},
		Attach: bringup.Verifier{D: bd},
		Live:   bringup.Verifier{D: bd},
		State:  rd.state,
	}, nil
}

// migProber is sessionProber's netref-shaped sibling.
//
// It exists because netref's phases need an EGRESS check that bringup.Prober does not declare, and
// because the disk-adoption discipline sessionProber documents applies to that call for exactly the
// same reason it applies to the other two: the probe arm writes the ledger FILE itself, so a session
// that persisted its own copy afterwards would write the probe's intent back out of existence.
type migProber struct {
	sessionProber
	full *probe.Prober
}

func (mp migProber) Egress(ctx context.Context, ix *trust.Index, netID string) error {
	ix, err := mp.indexFor(ix)
	if err != nil {
		return err
	}
	perr := mp.full.Egress(ctx, ix, netID)
	if aerr := mp.s.adoptDisk(); aerr != nil && perr == nil {
		return aerr
	}
	return perr
}
