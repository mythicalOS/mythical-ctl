// Package verbs is the lifecycle layer: install, start, stop, restart, recreate — and the batch
// driver that runs one of them over several products.
//
// DELIBERATELY THIN. Every verb holds the family lock for its whole duration, walks a sequence the
// earlier packages define, and reports. The sequence, the reconciler and the recovery tables are
// not here.
//
// EVERY VERB DECLARES ITS EFFECT ON DESIRED STATE — there is no default (the verb table). Two rules
// with no exception: a verb that stops a container as a MEANS (recreate) must not overwrite what
// the operator wants — only install/start/stop express intent — and every transition that leaves a
// container running ends in a live verification, because "it started" is not evidence its alias
// resolves.
//
// VERBS ARE SYNCHRONOUS AND STAY SYNCHRONOUS. A verb returns the EXIT CODE, never a channel and
// never a goroutine of its own. The two places a verb needs to talk to a human — asking before
// something destructive, and narrating progress — are the two function seams in Deps, so a verb
// never knows whether it is being driven by a terminal or by an interactive front-end that runs it
// on a goroutine and answers Confirm from an overlay. Refusal semantics are then ONE implementation
// used by both, rather than two that drift.
package verbs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/bringup"
	"mythicalos.ai/ctl/internal/cliio"
	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/probe"
	"mythicalos.ai/ctl/internal/prov"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/state"
	"mythicalos.ai/ctl/internal/trust"
)

// ProgressEvent is one step a verb narrates while it works. Stage names the step in the verb's own
// vocabulary; Detail is the operator-facing line. The default Progress writes Detail and nothing
// else, so the plain CLI's output is exactly what the reference printed.
type ProgressEvent struct{ Stage, Detail string }

// Deps is everything a verb needs from the process it runs in: the daemon connection, the family
// home, the streams, the environment, and the two human-facing seams.
//
// THE CONFIRMATION AND PROGRESS SEAMS ARE DEFINED HERE, in the wave that first calls them, rather
// than retrofitted by whatever later grows a second front-end. Confirm is asked before anything
// destructive and BLOCKS until it answers; Progress is told what is happening. A front-end that
// runs a verb on a goroutine supplies a Confirm that posts an overlay request and blocks on its
// reply, and a Progress that posts messages — and the verb is unchanged, because it never learns
// which world it is in.
//
// Nil seams are legal and mean "the plain CLI defaults": Confirm wraps cliio.Confirm over
// Env/Stdin/Stderr, Progress writes plain lines to Stdout.
type Deps struct {
	Engine         *engine.Client
	Home           string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Env            []string
	// Confirm is asked before an action that destroys data. nil ⇒ cliio.Confirm over Env/Stdin/Stderr.
	Confirm cliio.ConfirmFunc
	// Progress receives every narration step. nil ⇒ Detail is written as a plain line to Stdout.
	Progress func(event ProgressEvent)

	// The authenticated documents, located.
	//
	// THESE ARE HERE RATHER THAN IN EACH VERB'S OPTIONS because Batch's signature carries a verb
	// name and a product list and nothing else — it dispatches five different verbs whose options
	// differ, so the one thing they all need had to live somewhere they all reach. The CLI resolves
	// them (its --index/--policy/--manifest-dir defaults are relative to Home) and every verb reads
	// them; nothing here defaults them silently, because a verb that invented a document path would
	// be authenticating against a file the operator did not name.
	IndexPath, PolicyPath, ManifestDir string
}

func (d Deps) out() io.Writer {
	if d.Stdout == nil {
		return io.Discard
	}
	return d.Stdout
}

func (d Deps) errw() io.Writer {
	if d.Stderr == nil {
		return io.Discard
	}
	return d.Stderr
}

func (d Deps) in() io.Reader {
	if d.Stdin == nil {
		// An absent stdin is a CLOSED stdin, not an empty accept: every read fails, and
		// cliio.Confirm refuses on a failed read. The default falls the safe way.
		return strings.NewReader("")
	}
	return d.Stdin
}

// ask routes a confirmation through the seam, or through the plain-CLI default.
func (d Deps) ask(prompt string) bool {
	if d.Confirm != nil {
		return d.Confirm(prompt)
	}
	return cliio.Confirm(d.Env, d.in(), d.errw(), prompt)
}

// say narrates one step.
func (d Deps) say(stage, format string, a ...any) {
	ev := ProgressEvent{Stage: stage, Detail: fmt.Sprintf(format, a...)}
	if d.Progress != nil {
		d.Progress(ev)
		return
	}
	fmt.Fprintln(d.out(), ev.Detail)
}

// warn writes one diagnostic line to stderr, the way the reference's mi_warn does — the message
// carries its own module prefix, so nothing is added here.
func (d Deps) warn(format string, a ...any) {
	fmt.Fprintf(d.errw(), format+"\n", a...)
}

// warnErr reports an error to stderr. Errors in this tree already carry their originating module's
// prefix and their own explanation, so they are relayed verbatim.
func (d Deps) warnErr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(d.errw(), err.Error())
}

// --- the bring-up read seam ----------------------------------------------------------------------

// bringupObjects adapts the engine client to bringup.Objects. It lives HERE, in the verb layer,
// because the verb layer is the one place that holds every seam at once — the same reason
// bringup.Verifier is handed to netref from here rather than constructed by either of them.
type bringupObjects struct{ c *engine.Client }

// Attachments resolves every empty endpoint id by name before answering: a container that has
// never started reports an EMPTY NetworkID while its name key is present, so an unresolved read
// mis-identifies every network as "" and an exact-set check would compare nothing to something.
func (b bringupObjects) Attachments(ctx context.Context, container string) ([]bringup.Attachment, error) {
	info, err := b.c.ContainerInspect(ctx, container)
	if err != nil {
		return nil, err
	}
	pairs, err := runtime.ResolveNetPairs(ctx, b.c, info)
	if err != nil {
		return nil, err
	}
	out := make([]bringup.Attachment, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, bringup.Attachment{NetworkID: p.ID, Address: p.Addr, Aliases: p.Aliases})
	}
	return out, nil
}

func (b bringupObjects) Label(ctx context.Context, container, label string) (string, error) {
	return prov.Engine(b.c).Label(ctx, prov.ClassContainer, container, label)
}

func (b bringupObjects) Image(ctx context.Context, container string) (string, error) {
	info, err := b.c.ContainerInspect(ctx, container)
	if err != nil {
		return "", err
	}
	return info.Image, nil
}

// --- the session ---------------------------------------------------------------------------------

// session is one mutating verb's held resources: the family lock, the ledger store, the in-memory
// ledger, and the runtime facade bound to that lock.
//
// THE LOCK IS HELD ACROSS THE WHOLE VERB, acquired at the top and released on every return path.
type session struct {
	d    Deps
	h    famlock.Held
	st   ledger.Store
	l    *ledger.Ledger
	rt   *runtime.Runtime
	objs intent.Objects
}

// openSession takes the family lock and wires everything that needs it.
func openSession(d Deps) (*session, error) {
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
	s := &session{d: d, h: h, st: st, rt: rt, objs: intent.Engine(d.Engine)}
	if err := s.reload(); err != nil {
		_ = famlock.Release(h)
		return nil, err
	}
	return s, nil
}

func (s *session) close() { _ = famlock.Release(s.h) }

// reload re-reads the ledger from disk into the session.
//
// IT IS NOT OPTIONAL AFTER A DISK-WRITING HELPER. The trust acceptors and the probe accounting each
// perform their own read-modify-write against the ledger FILE (they take the lock token, not a
// ledger), so an in-memory copy taken before them is stale the moment they return — and persisting
// that stale copy afterwards would silently erase the floor or the intent they just recorded.
func (s *session) reload() error {
	l, err := ledger.Read(s.st)
	if errors.Is(err, ledger.ErrMissingLedger) {
		s.l = &ledger.Ledger{}
		return nil
	}
	if err != nil {
		return err
	}
	s.l = l
	return nil
}

func (s *session) persist() error { return ledger.Write(s.h, s.st, s.l) }

// persistFn is the write-ahead seam bringup and netref REQUIRE. It takes the ledger it is given
// rather than closing over one: a closure bound to the copy that existed at construction would,
// after a reload, write the OLD copy, report success, and let the runtime mutation proceed with the
// new copy's record never written — the failure the seam exists to prevent, wearing its own success.
func (s *session) persistFn() func(*ledger.Ledger) error {
	return func(l *ledger.Ledger) error { return ledger.Write(s.h, s.st, l) }
}

// prober builds the probe arm for this installation, or reports that the identity is unreadable.
// A probe's every removal is scoped by the identity, so a ledger that cannot say which installation
// this is cannot say which probe containers are ours.
func (s *session) prober(ident string) (*probe.Prober, error) {
	acct, err := intent.NewProbeAccounting(s.h, time.Now)
	if err != nil {
		return nil, err
	}
	p, err := probe.New(s.rt, acct, ident, intent.NonceNew)
	if err != nil {
		return nil, err
	}
	if s.d.Stderr != nil {
		if err := p.SetDiagnostics(s.d.Stderr); err != nil {
			return nil, err
		}
	} else if err := p.SetDiagnostics(io.Discard); err != nil {
		return nil, err
	}
	return p, nil
}

// sessionProber wraps the probe arm so the session's in-memory ledger cannot fall behind it.
//
// THE PROBE ARM WRITES THE LEDGER FILE ITSELF. Its accounting holds the family-lock token rather
// than a ledger, so it opens a probe intent on DISK before the probe container exists and retires
// it on disk afterwards — and on a reap it could not settle it deliberately RETAINS that intent,
// because the container may still be standing and the intent is the only record that would ever
// authorize removing it.
//
// The session, meanwhile, is holding a ledger it read before any of that. Persisting that copy
// afterwards would write the probe intent straight back out of existence: the probe container
// stays, nothing accounts for it, and the next verb's unaccounted gate wedges the installation
// over an object no record points at. So the disk is adopted back INTO THE SESSION'S OWN LEDGER
// after every probe call — including the failing ones, which are the only ones that leave
// anything behind.
//
// It adopts IN PLACE rather than replacing the pointer: the bring-up sequence is holding that
// same *ledger.Ledger and goes on editing it after the probe returns, so a fresh pointer here
// would leave those edits on an object nothing persists.
type sessionProber struct {
	p bringup.Prober
	s *session
}

func (sp sessionProber) SelfCheck(ctx context.Context, ix *trust.Index, netID string) error {
	err := sp.p.SelfCheck(ctx, ix, netID)
	if aerr := sp.s.adoptDisk(); aerr != nil && err == nil {
		return aerr
	}
	return err
}

func (sp sessionProber) Resolve(ctx context.Context, ix *trust.Index, netID, alias string) (string, error) {
	addr, err := sp.p.Resolve(ctx, ix, netID, alias)
	if aerr := sp.s.adoptDisk(); aerr != nil && err == nil {
		return addr, aerr
	}
	return addr, err
}

// adoptDisk re-reads the ledger from disk INTO the session's existing ledger object.
//
// It is reload's in-place sibling, and the difference matters: reload publishes a NEW ledger, so
// anyone already holding the old one keeps editing a copy nothing will persist. Use this one
// whenever something wrote the ledger file while a caller downstream is mid-sequence with the
// session's ledger in hand.
func (s *session) adoptDisk() error {
	fresh, err := ledger.Read(s.st)
	if errors.Is(err, ledger.ErrMissingLedger) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.l.Adopt(fresh)
}

// probeCleanup reconciles leftover probe containers before a verb mutates anything.
//
// A cleanup that could not verify or remove a stale probe leaves an UNRESOLVED probe intent, and
// proceeding to mutate installation state on top of it is the "act on a question that could not be
// answered" fold this codebase refuses everywhere else — so a failed cleanup STOPS the verb.
//
// No identity recorded is first use: nothing of ours can exist, so there is nothing to clean up.
// Any OTHER failure to read it refuses.
func (s *session) probeCleanup(ctx context.Context) error {
	ident, err := s.l.IdentGet()
	if errors.Is(err, ledger.ErrAbsentRecord) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("probe: the installation identity could not be read, so no probe container can be shown to\n"+
			"  be this installation's. Nothing is removed and nothing is forgotten: %w", err)
	}
	p, err := s.prober(ident)
	if err != nil {
		return err
	}
	if err := p.Cleanup(ctx); err != nil {
		return err
	}
	return s.reload()
}

// prepare is the preamble every mutating verb runs INSIDE the lock: layout, probe cleanup, and the
// unaccounted-object gate that stops a verb before it touches anything.
func (s *session) prepare(ctx context.Context) error {
	if err := layout.Ensure(s.d.Home); err != nil {
		return err
	}
	if err := s.probeCleanup(ctx); err != nil {
		return err
	}
	return intent.UnaccountedGate(ctx, s.l, s.objs)
}

// netTarget resolves THE network this family joins for this operation.
//
// MYTHICAL_NET is read HERE and handed down, because the configuration reader is the one authority
// on what that file says and a second reader inside netref would be a second answer. An absent key
// is "not set" (the installer's own network); a file that could not be READ refuses — silently
// taking the owned-network branch would join the family to a network nobody named.
func (s *session) netTarget(ctx context.Context) (string, error) {
	name, set, err := familyNet(s.d.Home)
	if err != nil {
		return "", fmt.Errorf("netref: mythical.conf could not be read, so which network this family joins cannot be\n"+
			"  established. Nothing is created and nothing is attached: %w", err)
	}
	nd := netref.Deps{
		Intent:     s.objs,
		Configured: name,
		NewNonce:   intent.NonceNew,
		Now:        time.Now,
		Persist:    s.persistFn(),
	}
	return netref.Target(ctx, s.l, netref.Engine(s.d.Engine), s.rt, name, set, nd)
}

// familyNet reads MYTHICAL_NET. (value, set, error) — a missing FILE is "not set", a file that
// cannot be parsed is an error, and an empty value is SET (netref refuses it, deliberately: an
// operator who wrote the key meant something by it, and "" is not the installer's own network).
func familyNet(home string) (string, bool, error) {
	v, err := conf.Get(conf.FamilyPath(home), "MYTHICAL_NET")
	if errors.Is(err, conf.ErrAbsent) || errors.Is(err, conf.ErrMissing) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// bringupDeps assembles the bring-up sequence's dependencies, Persist INCLUDED.
//
// PERSIST IS NOT OPTIONAL and a nil one is refused by bringup itself: the intent must be durable
// before the container exists, and only the holder of the family lock can write it — which is this
// session, not that package.
func (s *session) bringupDeps(ix *trust.Index, ident string) (bringup.Deps, error) {
	p, err := s.prober(ident)
	if err != nil {
		return bringup.Deps{}, err
	}
	return bringup.Deps{
		Objs:     bringupObjects{c: s.d.Engine},
		Mut:      s.rt,
		Probe:    sessionProber{p: p, s: s},
		State:    state.Engine(s.d.Engine),
		Index:    ix,
		NewNonce: intent.NonceNew,
		Now:      time.Now,
		Persist:  s.persistFn(),
	}, nil
}

// --- the product context -------------------------------------------------------------------------

// productContext is everything a verb needs about one product, derived once from the AUTHENTICATED
// documents. The reference flattened this into one tab-separated line because its callers read it
// with a field splitter; a struct carries the same relation without the encoding, and without the
// encoding's failure mode (a blob that decodes to nothing reads as "no volumes, mounts or secrets"
// and launches an incomplete container).
type productContext struct {
	Product   string
	Launched  bool
	Container string // empty when no identity exists yet — a not-launched read on a fresh machine
	Alias     string
	Image     string
	Manifest  *manifest.Manifest
	Policy    *policy.Policy
	Index     *trust.Index
}

// productCtx walks the ONE door: index vouches → digest verified → parse → product identity →
// freshness → entitlements → min_core → trust floor → launch state. Nothing here re-implements any
// of it.
//
// It returns trust.ErrNotLaunched WITH the context filled in — a caller reporting "not launched
// yet" legitimately wants it, and the trust floor has already been recorded (the enumerated exempt
// side effect) before the launch-state branch, so a withdrawn `launched` manifest cannot be
// replayed later against a machine that never established one.
//
// IDENTITY IS INSTALLATION STATE, AND A NOT-LAUNCHED RESULT MINTS NONE OF IT. Learning from an
// authentic manifest that a product is unpublished must not be the act that turns a fresh machine
// into an installation. On the LAUNCHED path the identity is minted; on the not-launched path only
// whatever identity already exists is READ, and the container name, which needs one, is left empty.
func (s *session) productCtx(product, manifestPath string) (*productContext, error) {
	m, merr := trust.AcceptManifest(s.h, s.st, s.d.IndexPath, s.d.PolicyPath, manifestPath, product)
	notLaunched := errors.Is(merr, trust.ErrNotLaunched)
	if merr != nil && !notLaunched {
		// The acceptors write floors to the ledger FILE even on some refusal paths, so the
		// in-memory copy is re-read before anything else uses it.
		_ = s.reload()
		return nil, merr
	}
	pol, perr := trust.AcceptPolicy(s.h, s.st, s.d.IndexPath, s.d.PolicyPath)
	if perr != nil {
		_ = s.reload()
		return nil, perr
	}
	ix, ierr := trust.CheckIndex(s.st, s.d.IndexPath)
	if ierr != nil {
		_ = s.reload()
		return nil, ierr
	}
	// The acceptors above wrote the trust floors straight to disk; adopt what they wrote before
	// this session edits the ledger again.
	if err := s.reload(); err != nil {
		return nil, err
	}

	pc := &productContext{
		Product:  product,
		Launched: !notLaunched,
		Image:    m.Image(),
		Manifest: m,
		Policy:   pol,
		Index:    ix,
	}
	alias, aerr := manifest.Alias(product)
	if aerr != nil {
		return nil, aerr
	}
	pc.Alias = alias

	var ident string
	if pc.Launched {
		id, err := s.l.IdentEnsure()
		if err != nil {
			return nil, err
		}
		ident = id
		if err := s.persist(); err != nil {
			return nil, err
		}
	} else {
		id, err := s.l.IdentGet()
		if err != nil && !errors.Is(err, ledger.ErrAbsentRecord) {
			return nil, err
		}
		if err == nil {
			ident = id
		}
	}
	if ident != "" {
		c, cerr := manifest.ContainerName(ident, product)
		if cerr != nil {
			return nil, cerr
		}
		pc.Container = c
	}
	if notLaunched {
		return pc, trust.ErrNotLaunched
	}
	return pc, nil
}

// hostPorts maps each declared container port to the host port to publish it at.
//
// ONLY AN ABSENT KEY falls back to the manifest's port. Any other status means the file did not
// parse or the value did not validate, and quietly publishing a different port than the operator
// configured is the wrong answer to "I could not read your configuration".
func hostPorts(home, product string, m *manifest.Manifest) (map[uint16]uint16, error) {
	ports := m.Ports()
	if len(ports) == 0 {
		return nil, nil
	}
	key := "MYTHICAL_" + confKey(product) + "_PORT"
	v, err := conf.Get(conf.FamilyPath(home), key)
	switch {
	case errors.Is(err, conf.ErrAbsent) || errors.Is(err, conf.ErrMissing):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("verbs: could not read %s from mythical.conf — refusing rather than\n"+
			"  silently publishing the manifest's default port instead of your configured one: %w", key, err)
	}
	hp, perr := portOf(v)
	if perr != nil {
		return nil, fmt.Errorf("verbs: %s in mythical.conf is not a port number: %w", key, perr)
	}
	out := map[uint16]uint16{}
	for _, cp := range ports {
		out[cp] = hp
	}
	return out, nil
}

func portOf(v string) (uint16, error) {
	if v == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, fmt.Errorf("%q is not a number", v)
		}
		n = n*10 + int(v[i]-'0')
		if n > 65535 {
			return 0, fmt.Errorf("%q is out of range", v)
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("%q is out of range", v)
	}
	return uint16(n), nil
}

// timeNow is the clock every intent's creation time comes from — one source, so a test that needed
// to stop it would have one thing to replace.
func timeNow() time.Time { return time.Now() }

// confKey maps a product name into the configuration-key alphabet: lower→upper, and `-`→`_`.
func confKey(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 32
		case r == '-':
			return '_'
		}
		return r
	}, s)
}
