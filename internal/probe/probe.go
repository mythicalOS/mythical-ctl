// Package probe is D49 — the probe: a real artifact with a real contract.
//
//	Image     a single, minimal, DIGEST-PINNED image, named in the family index and verified
//	          through the same chain as everything else (§8.1) — the *trust.Index parameter
//	          is constructible only by the trust acceptors, so an unverified index cannot
//	          reach this package at all.
//	Commands  a fixed, closed set (engine.HelperCommand) — nothing configurable, nothing
//	          manifest-supplied. A probe that takes instructions is an execution primitive.
//	Offline   if the pinned image is not present and cannot be fetched, verification CANNOT
//	          BE PERFORMED — the caller stops rather than proceeding unverified.
//	Lifecycle created under write-ahead intent and labelled like any other object (§6b), so a
//	          crash mid-probe leaves a reconcilable record rather than a stray container.
//
// ONE RULE RUNS THROUGH EVERY FUNCTION HERE: "I COULD NOT ASK" IS NEVER "THERE IS NOTHING
// THERE". The engine's typed errors split "the object is genuinely gone" (ErrAbsent) from
// "the runtime could not answer" (ErrDaemonDown), and both halves are consumed below — a
// probe container that might still be standing keeps the intent that accounts for it,
// because dropping the record of an object nobody could ask about is how §6b.2's unaccounted
// class is manufactured.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// ErrNotResolved — the probe LOOKED and the name did not resolve (the rc-3 analogue). It is
// load-bearing for D48: a running sibling that does not resolve is a verification FAILURE,
// while a probe that could not run is a reason to stop before detaching anything — a probe
// that malfunctioned must never be read as a probe that looked and found nothing.
var ErrNotResolved = errors.New("the alias did not resolve")

// ErrUnaccounted — the probe's container could not be accounted for afterwards (the rc-4
// analogue). SEPARATE ON PURPOSE: folding it into the check's own failure would make a caller
// report a verification verdict it never obtained — "DNS is broken" for a daemon that stopped
// answering after the probe had already resolved its alias. It takes precedence over the
// check's verdict: an outstanding object is what the caller must act on.
var ErrUnaccounted = errors.New("the probe container could not be accounted for; its intent is preserved — run 'mythical-ctl state repair'")

// ProbeIntent is one write-ahead record for a probe container.
type ProbeIntent struct {
	Name  string
	Nonce string
}

// Accounting is the write-ahead intent seam: the record exists BEFORE the container does, so
// a crash mid-probe is reconcilable. The intent layer provides the durable implementation;
// this package defines only what a probe needs of it.
type Accounting interface {
	// OpenProbe records intent for a probe container before it is created.
	OpenProbe(name, nonce string) error
	// DropProbe retires the record — called ONLY once the runtime has said the object is
	// gone, or it has been removed here.
	DropProbe(name string) error
	// ProbeIntents lists every recorded probe intent; a store that does not exist yet is an
	// empty list (first use — nothing of ours can exist).
	ProbeIntents() ([]ProbeIntent, error)
}

// Prober runs the closed probe commands. Read-only checks use the engine client directly;
// probe containers run through the runtime facade's helper method, so probes that launch
// helpers require the family lock, as the reference's probe arm does under its verbs.
type Prober struct {
	rt       *runtime.Runtime
	acct     Accounting
	ident    string
	newNonce func() (string, error)
	// diag receives every helper's STDERR, verbatim, on EVERY run — success, failure, or a run
	// that errored after its logs were read. The reference's `$(mi_rt_run_helper …)` captured
	// stdout and let stderr pass straight through to the operator's terminal; this is that
	// pass-through. Defaults to os.Stderr; SetDiagnostics redirects it.
	diag io.Writer
}

// New wires a Prober. The installation identity is REQUIRED and validated here: every
// removal a probe ever performs is scoped by it — a caller that cannot read which
// installation this is cannot say which objects are ours, so it cannot construct a Prober at
// all (the reference's "cleanup refuses when the identity cannot be read", moved to the
// door).
func New(rt *runtime.Runtime, acct Accounting, ident string, newNonce func() (string, error)) (*Prober, error) {
	if rt == nil || acct == nil || newNonce == nil {
		return nil, errors.New("probe: a Prober needs the runtime facade, the intent store and a nonce mint")
	}
	if !docfmt.TypeOK("ident", ident) {
		return nil, fmt.Errorf("probe: %q is not a usable installation identity — no probe container can be shown to be this installation's, so nothing is removed and nothing is forgotten", ident)
	}
	return &Prober{rt: rt, acct: acct, ident: ident, newNonce: newNonce, diag: os.Stderr}, nil
}

// SetDiagnostics redirects the helpers' stderr pass-through (see Prober.diag). A nil writer
// is refused rather than silently discarding — losing the diagnostics is the failure this
// seam exists to prevent.
func (p *Prober) SetDiagnostics(w io.Writer) error {
	if w == nil {
		return errors.New("probe: a nil diagnostics writer would discard the helpers' stderr")
	}
	p.diag = w
	return nil
}

// Image is the probe image, from the VERIFIED family index and nowhere else: the Index type
// is constructible only by the trust acceptors, so an index that did not verify cannot yield
// a probe image here — there is no path on which one exists.
func (p *Prober) Image(ix *trust.Index) (string, error) {
	if ix == nil {
		return "", errors.New("probe: no verified index")
	}
	ref := ix.ProbeImage()
	if ref == "" {
		return "", errors.New("probe: the verified index names no probe image")
	}
	return ref, nil
}

// Available: rc 0 the image is usable; otherwise it cannot be obtained, REPORTED, and the
// operation STOPS. Present-then-pull, not pull-always: a machine that already has the digest
// must not need the network. The registry's own words ride a pull failure (§7.3) — §10a
// requires auth and network failures never to be folded into one message.
func (p *Prober) Available(ctx context.Context, ix *trust.Index) error {
	ref, err := p.Image(ix)
	if err != nil {
		return err
	}
	if _, ierr := p.rt.Client().ImageInspect(ctx, ref); ierr == nil {
		return nil
	} else if !errors.Is(ierr, engine.ErrAbsent) {
		return ierr
	}
	if perr := p.rt.ImagePull(ctx, ref); perr != nil {
		return fmt.Errorf("probe: the pinned probe image cannot be obtained: %s — verification cannot be performed, so the operation STOPS here rather than continuing unverified; there is deliberately no substitute image (%w)", ref, perr)
	}
	return nil
}

// probeName is `mythical-<identity>-probe-<nonce>`: the nonce has to be IN the name — a probe
// is created per run, so a fixed name would make two runs contend for one name and make a
// leftover indistinguishable from the run happening now — and the `mythical-<identity>-`
// shape is what makes §6b.2's classifier read a leaked probe as a name this installer would
// create rather than a stranger's object.
func (p *Prober) probeName(nonce string) (string, error) {
	if !docfmt.TypeOK("ident", nonce) {
		return "", fmt.Errorf("probe: cannot derive a probe container name from %q", nonce)
	}
	return "mythical-" + p.ident + "-probe-" + nonce, nil
}

// reap: IS OUR PROBE CONTAINER STILL STANDING, AND IF SO REMOVE IT — asked in ONE place, for
// BOTH callers (the run that has just finished, and a leftover from a run that never did).
// nil: nothing of ours stands at the name any more — never there, gone, or ours and now
// removed; the caller may drop the intent. An error: it could not be settled — the caller
// must PRESERVE the intent.
//
// A NONCE SAYS WHICH OBJECT, NEVER WHOSE (§6a): the installation label is the only evidence
// an object is ours, and an UNLABELLED container is not weaker evidence — it is none.
func (p *Prober) reap(ctx context.Context, name, nonce string) error {
	info, err := p.rt.Client().ContainerInspect(ctx, name)
	if errors.Is(err, engine.ErrAbsent) {
		return nil // genuinely gone — the ordinary path
	}
	if err != nil {
		return fmt.Errorf("probe: whether a container stands at %q could not be asked: %w", name, err)
	}
	owner := runtime.InstallLabel(info)
	if owner == "" || owner != p.ident {
		return fmt.Errorf("probe: a container stands at %q, which is the name this installation's probe intent records, but it is labelled for installation %q rather than %q — a name can be reassigned, so the name alone proves nothing; it is NOT removed and the intent is PRESERVED rather than dropped for an object that was never accounted for", name, owner, p.ident)
	}
	actual := runtime.Nonce(info)
	if nonce == "" || actual != nonce {
		return fmt.Errorf("probe: the container at %q carries nonce %q, which is not the %q this intent recorded — it is a different object standing at the same name; it is NOT removed and the intent is PRESERVED", name, actual, nonce)
	}
	if rerr := p.rt.ContainerRemove(ctx, name); rerr != nil {
		return fmt.Errorf("probe: the leftover probe container %q is this installation's and could not be removed — its intent is preserved, so the object stays accounted for until it can be: %w", name, rerr)
	}
	return nil
}

// run executes one closed command under write-ahead intent and accounts for the container
// afterwards. Returns the helper's key=value output. A nil error means the helper's check
// PASSED and the container is accounted for; a failed check, a launch failure, and
// ErrUnaccounted are all distinct errors.
func (p *Prober) run(ctx context.Context, ix *trust.Index, netID, netalias string, cmd engine.HelperCommand, args ...string) ([]byte, error) {
	ref, err := p.Image(ix)
	if err != nil {
		return nil, err
	}
	nonce, err := p.newNonce()
	if err != nil {
		return nil, err
	}
	name, err := p.probeName(nonce)
	if err != nil {
		return nil, err
	}
	prov, err := engine.NewProvenance(p.ident, nonce)
	if err != nil {
		return nil, err
	}
	spec, err := engine.NewHelperSpec(ref, name, cmd, prov, engine.HelperOpts{
		Network: netID,
		Alias:   netalias,
		Args:    args,
	})
	if err != nil {
		return nil, err
	}
	// Write-ahead: the intent exists before the container does.
	if err := p.acct.OpenProbe(name, nonce); err != nil {
		return nil, err
	}
	res, runErr := p.rt.HelperRun(ctx, spec)
	// The helper's stderr reaches the operator on EVERY path — before any verdict is formed, so
	// no branch below can drop it (a run that errored after its logs were read carries it too).
	if len(res.Stderr) > 0 {
		_, _ = p.diag.Write(res.Stderr)
	}
	// The ANSWER is stdout alone — the reference captured `$(mi_rt_run_helper …)`, which is
	// stdout, and let stderr through to the operator. Stderr rides the verdict text below as
	// diagnostics and is never read for a field.
	code, out := res.Code, res.Stdout

	// The helper's contract is 0 (ran and passed) · 1 (ran and FAILED) · 2 (the command word
	// is not implemented). ANYTHING ELSE IS OUT OF CONTRACT and is a FAILED CHECK — loudly,
	// and never this installer's own accounting failure.
	var checkErr error
	switch {
	case runErr != nil:
		checkErr = runErr
	case code == 0:
	case code == 1 || code == 2:
		checkErr = fmt.Errorf("probe: the %s probe reported failure (exit %d)%s", cmd, code, diagnostics(res.Stderr))
	default:
		checkErr = fmt.Errorf("probe: the probe exited %d, which is not a status the helper contract defines (0 the check passed · 1 the check FAILED · 2 the command is not implemented) — treated as a FAILED CHECK, never as this installer's own accounting failure%s", code, diagnostics(res.Stderr))
	}

	// The intent goes only once the runtime has SAID the object is gone (or it was removed
	// here). A question that could not be asked leaves both the container and its record
	// exactly where they are — and A FAILED REAP IS NOT A SUCCESSFUL RUN: it takes precedence
	// over the check's own verdict.
	if reapErr := p.reap(ctx, name, nonce); reapErr != nil {
		return nil, fmt.Errorf("%w (%v)", ErrUnaccounted, reapErr)
	}
	if dropErr := p.acct.DropProbe(name); dropErr != nil {
		return nil, fmt.Errorf("%w (%v)", ErrUnaccounted, dropErr)
	}
	if checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// diagnostics renders the helper's stderr for a verdict message — the operator-facing words
// the reference let pass straight through. Bounded, trimmed, and NEVER parsed as an answer.
func diagnostics(stderr []byte) string {
	const limit = 2048
	s := strings.TrimSpace(string(stderr))
	if s == "" {
		return ""
	}
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return " — the helper said: " + s
}

// field reads one field out of the helper's answer. THE DUPLICATE RULE IS THE READER'S, NOT
// EACH CALLER'S: the flat response format gives a repeated key no meaning — an answer that
// says `selfcheck=ok` and then `selfcheck=fail` does not say `ok`, it says two things, and it
// is malformed evidence. Every line is read, never stopping at the first hit: a reader that
// returns early cannot see the second copy, which is precisely the evidence it must refuse
// on. found=false: the answer carries no such field at all (an EMPTY value is a real answer).
func field(out []byte, key string) (val string, found bool, err error) {
	seen := 0
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			val = v
			seen++
		}
	}
	if seen == 0 {
		return "", false, nil
	}
	if seen > 1 {
		return "", true, fmt.Errorf("probe: the probe's answer states %q more than once (%d times), and the answer format gives a repeated field no meaning — an answer that says a thing twice says two things; it is REFUSED as ambiguous rather than read down to whichever copy came first", key+"=", seen)
	}
	return val, true, nil
}

// asserted: AN EXIT STATUS IS NOT A RESULT — the check passes only when the answer STATES
// `<key>=ok`. A pinned image that regressed to exiting 0 while printing nothing, or printing
// `<key>=fail`, would otherwise be accepted as proof. FAIL CLOSED: the absence of the
// expected result is never the presence of a pass.
func asserted(out []byte, key string) error {
	val, found, err := field(out, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("probe: the probe exited 0 but its answer carries no %q field at all, so nothing in it says the check was performed — an exit status is not a result; it is REFUSED rather than read as a pass", key+"=")
	}
	if val != "ok" {
		return fmt.Errorf("probe: the probe exited 0 but reported %q rather than %q — the STATED result governs, not the status beside it; it is REFUSED", key+"="+val, key+"=ok")
	}
	return nil
}

// address extracts THE ADDRESS OUT OF AN ANSWER TO ONE QUESTION. ErrNotResolved: the probe
// LOOKED and the name did not resolve. Any other error: the answer is not an answer to this
// question. The three gates are not interchangeable: the alias ECHO (a reply about another
// name is a malfunctioning probe, and returning its address would hand the rebind the address
// of a different container entirely); a MISSING address field is not an EMPTY one (no field
// at all means the probe did not answer the question); and the address ITSELF is
// sanity-gated — the value is printed to callers that compare and log it, and 45 characters
// is the longest textual IPv6 form.
func address(out []byte, wantAlias string) (string, error) {
	answered, found, err := field(out, "alias")
	if err != nil {
		return "", err
	}
	if !found || answered != wantAlias {
		return "", fmt.Errorf("probe: the probe answered about alias %q when it was asked about %q — an answer to another question is not this alias's address, so nothing is returned", answered, wantAlias)
	}
	addr, found, err := field(out, "address")
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.New("probe: the probe's answer carries no address at all — it did not answer the question")
	}
	if addr == "" {
		return "", ErrNotResolved
	}
	if len(addr) > 45 || strings.IndexFunc(addr, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.')
	}) >= 0 {
		return "", fmt.Errorf("probe: the probe reported %q, which is not an address — nothing is returned", addr)
	}
	return addr, nil
}

// SelfCheck is THE DNS-mechanism check. The probe's OWN per-run alias is what separates "DNS
// on this network is broken" from "that product is simply not running" — and it is what makes
// the check a check: a probe asked "is DNS working?" can answer yes without doing anything; a
// probe asked "what address does <a name minted after your image was built> have?" cannot.
// The caller registers the alias with the network itself immediately before asking, so no
// hosts file — the image's or the daemon's — can contain it: a network ALIAS is answered by
// the network's embedded resolver and nothing else, so a conforming selfcheck MUST query the
// resolver. `selfcheck=ok` is required AS WELL: it is the probe's opinion of the evidence,
// and a probe that looked and considers the result wrong is not overruled.
func (p *Prober) SelfCheck(ctx context.Context, ix *trust.Index, netID string) error {
	if err := p.Available(ctx, ix); err != nil {
		return err
	}
	nonce, err := p.newNonce()
	if err != nil {
		return fmt.Errorf("probe: cannot mint a selfcheck alias: %w", err)
	}
	// The freshness of the QUESTION, not the identity of an object — deliberately not the
	// container's nonce: this caller has to know the name it is about to ask about without
	// waiting for the run to hand it back.
	alias := "probe-selfcheck-" + nonce
	if !docfmt.TypeOK("ident", alias) {
		return fmt.Errorf("probe: %q is not a usable network alias", alias)
	}
	// The alias is passed TWICE on purpose, and the two are different things: the first
	// registers the container under that name with the network, the second asks the probe to
	// look that name up. The check is exactly "resolve the name I have just registered you
	// under".
	out, err := p.run(ctx, ix, netID, alias, engine.HelperSelfcheck, alias)
	if err != nil {
		// ErrUnaccounted is NOT a DNS verdict: the probe may well have resolved its alias
		// before the runtime stopped answering, and calling DNS broken would send an operator
		// to debug a network never shown to be at fault.
		if errors.Is(err, ErrUnaccounted) {
			return err
		}
		return fmt.Errorf("%w — %s", errDNSBroken(netID, alias), err)
	}
	// ErrNotResolved — the probe looked and the resolver had no answer — IS the broken-DNS
	// finding, and the only thing here that is. Everything else (no echo, no address, a reply
	// about another name) is a broken PROBE: a malfunctioning verifier is not a verification
	// result.
	if _, aerr := address(out, alias); aerr != nil {
		if errors.Is(aerr, ErrNotResolved) {
			return errDNSBroken(netID, alias)
		}
		return aerr
	}
	return asserted(out, "selfcheck")
}

// One wording, at both doors that reach it — a verdict this load-bearing spelled twice is a
// verdict that gets edited once.
func errDNSBroken(netID, alias string) error {
	return fmt.Errorf("probe: the probe could not resolve its OWN per-run alias %q on network %q — DNS on this network is not working; this is not about any one product being stopped", alias, netID)
}

// Resolve resolves <alias> on <netID>: the address, or ErrNotResolved (the alias did not
// resolve — a verification failure the caller keeps its outstanding entry for), or any other
// error (the probe itself could not run, or answered something that is not an answer to this
// question — a reason to stop before detaching anything). A run that did not finish never
// LOOKED, so ErrUnaccounted and launch failures land on the generic side, never on
// ErrNotResolved. No alias of our own is registered: the question is about a SIBLING's name.
func (p *Prober) Resolve(ctx context.Context, ix *trust.Index, netID, alias string) (string, error) {
	if err := p.Available(ctx, ix); err != nil {
		return "", err
	}
	out, err := p.run(ctx, ix, netID, "", engine.HelperResolve, alias)
	if err != nil {
		return "", err
	}
	return address(out, alias)
}

// Egress checks outbound reachability from the network. `egress=ok` is this check's stated
// result — an answer about a DIFFERENT check is no more this one's answer than a resolve
// reply about another alias is that alias's address.
func (p *Prober) Egress(ctx context.Context, ix *trust.Index, netID string) error {
	if err := p.Available(ctx, ix); err != nil {
		return err
	}
	out, err := p.run(ctx, ix, netID, "", engine.HelperEgress)
	if err != nil {
		if errors.Is(err, ErrUnaccounted) {
			return err
		}
		return fmt.Errorf("probe: egress from network %q is not working: %w", netID, err)
	}
	return asserted(out, "egress")
}

// Cleanup reconciles leftovers: a probe container from an earlier crash is OURS — labelled
// with this installation's identity and a nonce we recorded — so it is removed, not reported
// as an unrecorded object (§6b.2's unrecorded class STOPS every operation, and a stray probe
// would wedge the installation over a container whose whole purpose was to be temporary).
// Nothing that could not be settled is dropped, so a later run sees exactly what this one
// did.
func (p *Prober) Cleanup(ctx context.Context) error {
	records, err := p.acct.ProbeIntents()
	if err != nil {
		return fmt.Errorf("probe: the intent records could not be listed, so no leftover probe can be shown to exist or not to — nothing is removed and nothing is forgotten: %w", err)
	}
	var failures []string
	for _, rec := range records {
		if rec.Name == "" {
			// A record that says a container was about to be created without saying which
			// identifies nothing the runtime can be asked about.
			failures = append(failures, "a probe intent carries no name — it is PRESERVED and reported; run 'mythical-ctl state repair'")
			continue
		}
		if rec.Nonce == "" {
			failures = append(failures, fmt.Sprintf("the probe intent for %q carries no nonce — it is PRESERVED and reported", rec.Name))
			continue
		}
		// Remove by NAME only after confirming the label — §6a's rule everywhere: a name can
		// be reassigned to something the installer never created.
		if rerr := p.reap(ctx, rec.Name, rec.Nonce); rerr != nil {
			failures = append(failures, rerr.Error())
			continue
		}
		if derr := p.acct.DropProbe(rec.Name); derr != nil {
			failures = append(failures, derr.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("probe: cleanup could not settle every probe intent:\n  %s", strings.Join(failures, "\n  "))
	}
	return nil
}
