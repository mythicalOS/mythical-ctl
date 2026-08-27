// Package copyfill is the privileged copy, in the pinned container that is the only thing able
// to read a named volume (D54/D58/D59).
//
// WHY A CONTAINER AND NOT A HOST-SIDE WALK. A named volume is daemon-managed: the daemon
// reports its mountpoint under /var/lib/docker/volumes/<name>/_data, and on Docker Desktop that
// path does not exist on the host at all — it lives inside the VM — while on Linux it is
// root-owned and explicitly unsupported as a host-access path. A host-side filesystem walk over
// the volume's mountpoint could not have read the source on the platform most operators run.
//
// THE HOST CLI HAS NO ACL CODE AT ALL. `setfacl` is not on the dependency floor and does not
// exist on macOS; the copy container's image is OURS, so the ownership mapping, the ACL
// application and the empirical preflight all happen there.
//
// ONE RULE RUNS THROUGH EVERY READER HERE: AN ABSENT OBSERVATION IS A REFUSAL, NEVER A PASS. A
// helper that ran, exited 0 and printed nothing would otherwise satisfy every contract check on
// no evidence at all — the destination declared able to hold ownership, permissions, symlinks
// and inherited ACLs because nobody said it could not. Unmeasured is not measured-clean. It is
// enforced in ONE place (stated) rather than at each of the eight call sites, because a rule
// every caller must remember is a rule that gets forgotten once, and the copy that is forgotten
// is the door nobody thought about.
package copyfill

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// Copier runs the pinned copy container's closed commands. Every mutation goes through the
// runtime facade, so a copy requires the family lock exactly as the reference's does under its
// verbs.
type Copier struct {
	rt       *runtime.Runtime
	ident    string
	newNonce func() (string, error)
	// out receives the operator-facing NARRATION — the per-entry notes the reference emits
	// with mi_log (a symlink preserved, privileged bits stripped, a foreign uid mapped, the
	// entry count verified). Defaults to os.Stdout.
	out io.Writer
	// diag receives the helper's STDERR verbatim on EVERY run, plus the non-fatal advisories
	// the reference emits with mi_warn (the ACL-enforcement context note). Both are the
	// operator's terminal in the reference — a helper that could not be LAUNCHED and a check
	// that ran and failed are different facts, and the runtime's own words are what tell them
	// apart. Defaults to os.Stderr.
	diag io.Writer
	// endpoint answers "which daemon endpoint is this". Injected so the ACL-context statement
	// is testable without a daemon; defaults to the same resolution the client dials with.
	endpoint func() (string, error)
}

// New wires a Copier. The installation identity is REQUIRED and validated here: every copy
// container this creates is labelled with it, and an anonymous helper — one carrying only a
// nonce — could never be shown to be ours, so nothing would be authorized to remove a leaked
// one. (The reference launched its copy helper with the nonce label alone; the identity label
// is added here, matching every other object this installer creates.)
func New(rt *runtime.Runtime, ident string, newNonce func() (string, error)) (*Copier, error) {
	if rt == nil || newNonce == nil {
		return nil, errors.New("copy: a Copier needs the runtime facade and a nonce mint")
	}
	if !docfmt.TypeOK("ident", ident) {
		return nil, fmt.Errorf("copy: %q is not a usable installation identity — no copy container could be shown to be this installation's", ident)
	}
	return &Copier{
		rt: rt, ident: ident, newNonce: newNonce,
		out: os.Stdout, diag: os.Stderr,
		endpoint: defaultEndpoint,
	}, nil
}

// SetOutput redirects the operator-facing narration. A nil writer is refused rather than
// silently discarding: the per-entry notes are the report an operator reads a copy from.
func (c *Copier) SetOutput(w io.Writer) error {
	if w == nil {
		return errors.New("copy: a nil output writer would discard the copy's own report")
	}
	c.out = w
	return nil
}

// SetDiagnostics redirects the helper's stderr pass-through and the non-fatal advisories. A nil
// writer is refused — losing the diagnostics is the failure this seam exists to prevent.
func (c *Copier) SetDiagnostics(w io.Writer) error {
	if w == nil {
		return errors.New("copy: a nil diagnostics writer would discard the helper's stderr")
	}
	c.diag = w
	return nil
}

// SetEndpoint overrides the daemon-endpoint reader the ACL-context statement is derived from.
// A nil function is refused: with no reader at all every run would be reported UNKNOWN, which
// is an honest answer to a question that was never asked and a dishonest one here.
func (c *Copier) SetEndpoint(f func() (string, error)) error {
	if f == nil {
		return errors.New("copy: a nil endpoint reader would report every daemon as UNKNOWN")
	}
	c.endpoint = f
	return nil
}

// defaultEndpoint resolves the endpoint the client itself dials — the same precedence, so the
// ACL-context statement can never describe a different daemon than the one the copy runs on.
func defaultEndpoint() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return engine.ResolveEndpoint(os.Environ(), home)
}

// Image is the copy image, from the VERIFIED family index and nowhere else. The *trust.Index
// type is constructible only by the trust acceptors, so an index that merely PARSED cannot
// reach here: reading the copy image out of an unauthenticated index would let anyone with
// local write access to the cached index name the image that is about to be handed every byte
// of a product's data with a writable mount.
func (c *Copier) Image(ix *trust.Index) (string, error) {
	if ix == nil {
		return "", errors.New("copy: no verified index")
	}
	ref := ix.CopyImage()
	if ref == "" {
		return "", errors.New("copy: the verified index names no copy image")
	}
	return ref, nil
}

// Available: nil the image is usable; otherwise it cannot be obtained, REPORTED, and the
// operation STOPS. Present-then-pull, not pull-always: a machine that already has the digest
// must not need the network. The registry's own words ride a pull failure — auth and network
// failures must never be folded into one message, because "denied" and "no such host" send an
// operator to two different places.
func (c *Copier) Available(ctx context.Context, ix *trust.Index) error {
	ref, err := c.Image(ix)
	if err != nil {
		return err
	}
	if _, ierr := c.rt.Client().ImageInspect(ctx, ref); ierr == nil {
		return nil
	} else if !errors.Is(ierr, engine.ErrAbsent) {
		return ierr
	}
	if perr := c.rt.ImagePull(ctx, ref); perr != nil {
		return fmt.Errorf("copy: the pinned copy image cannot be obtained:\n    %s\n"+
			"  The migration STOPS. There is deliberately no fallback to an unverified copy path — a copy\n"+
			"  performed by something we did not pin is a copy whose confinement nothing guarantees: %w", ref, perr)
	}
	return nil
}

// helper runs ONE closed command in the pinned copy container.
//
// PRIVATE NETWORKING, ALWAYS. The copy needs no network, and a privileged container reading
// every byte of a product's data is precisely what should not also be able to reach one. This
// is the ONE legitimate use of `none` in the design — unlike a product container, the
// connect-later problem never arises, because this container never joins a network.
//
// The returned error is a RUN failure (the helper could not be launched, or its container could
// not be accounted for) — never a failed check. Stderr is deliberately not folded into the
// answer: a helper that could not be LAUNCHED and a check that ran and failed are different
// facts, and only the answer is parsed.
func (c *Copier) helper(ctx context.Context, ix *trust.Index, cmd engine.HelperCommand, runAs string, args []string, mounts []engine.Mount) ([]byte, int64, error) {
	return c.helperStdin(ctx, ix, cmd, runAs, args, mounts, nil)
}

// helperStdin is helper with the ONE extra knob the restore direction needs: bytes handed to the
// helper on its STDIN.
//
// IT EXISTS SO THE MANIFEST IS NOT A THIRD HOST MOUNT. Verifying a just-filled volume against the
// backup's per-entry manifest has to get that manifest INTO the container, and the alternative the
// design explicitly refuses is binding a third, operator-named host path to carry it — the helper's
// mount vocabulary is closed precisely so no caller can hand it an extra host tree. stdin carries
// the bytes and adds no mount at all. (The reference spells the same thing `stdin=1` in its helper
// spec vocabulary; see lib/runtime.sh's mi_rt_run_helper.)
//
// AN EMPTY stdin IS NOT AN OPENED-AND-NEVER-WRITTEN STREAM: the engine opens the container's stdin
// only when there are bytes to write, so every caller that passes none keeps exactly the launch it
// had before this parameter existed, and an EMPTY manifest — which is legal — reaches the helper as
// an immediately-closed stdin, the same EOF-at-once the reference's redirect from an empty file
// produces.
func (c *Copier) helperStdin(ctx context.Context, ix *trust.Index, cmd engine.HelperCommand, runAs string, args []string, mounts []engine.Mount, stdin []byte) ([]byte, int64, error) {
	ref, err := c.Image(ix)
	if err != nil {
		return nil, 0, err
	}
	nonce, err := c.newNonce()
	if err != nil {
		return nil, 0, err
	}
	if !docfmt.TypeOK("ident", nonce) {
		return nil, 0, fmt.Errorf("copy: cannot derive a copy container name from %q", nonce)
	}
	name := "mythical-" + c.ident + "-copy-" + nonce
	prov, err := engine.NewProvenance(c.ident, nonce)
	if err != nil {
		return nil, 0, err
	}
	spec, err := engine.NewHelperSpec(ref, name, cmd, prov, engine.HelperOpts{
		RunAs:  runAs,
		Args:   args,
		Mounts: mounts,
		Stdin:  stdin,
	})
	if err != nil {
		return nil, 0, err
	}
	res, runErr := c.rt.HelperRun(ctx, spec)
	// The helper's stderr reaches the operator on EVERY path — before any verdict is formed,
	// so no branch below can drop it.
	if len(res.Stderr) > 0 {
		_, _ = c.diag.Write(res.Stderr)
	}
	// AND SO DOES A LAUNCH FAILURE. In the reference the runtime's own words are on the
	// terminal's stderr, inherited, so an operator sees "permission denied" BESIDE the
	// missing-observation refusal that follows from it. Here the failure is a value, and a
	// caller that forms its verdict from the observations alone would drop it — leaving the
	// operator told "the helper stated nothing about ownership" when the truth is that no
	// helper ever ran. "I could not ask" and "it answered badly" are different facts.
	if runErr != nil {
		fmt.Fprintf(c.diag, "copy: the %s helper could not be run: %v\n", cmd, runErr)
	}
	return res.Stdout, res.Code, runErr
}

// aclContextNote is THE HONEST THREE-WAY STATEMENT of whether the dual-principal ACL machinery
// is MEANINGFULLY ENFORCED on this daemon. SHARED by preflight — which SETS the default entries
// — and verify — which checks they were APPLIED — so the two halves cannot tell the operator
// different stories about the same daemon.
//
// Docker Desktop translates ownership at the file-sharing layer, so the gid/ACL path is bypassed
// there; native Linux enforces it (the silent default); and an endpoint that could not be read
// at all is UNKNOWN — neither claimed nor dismissed, because "I could not ask" is never "there
// is nothing there", and silence there would let the run be read as the native-Linux case where
// the step IS enforced. <subject> names the step so the one message fits both callers.
func (c *Copier) aclContextNote(subject string) {
	ep, err := c.endpoint()
	if err != nil {
		ep = ""
	}
	switch {
	case ep != "" && (strings.HasSuffix(ep, "/.docker/run/docker.sock") || strings.HasPrefix(ep, "npipe://")):
		fmt.Fprintf(c.diag, "copy: this is Docker Desktop, where ownership is translated at the file-sharing layer, so\n"+
			"  %s is not meaningfully enforced here. It is exercised and reported, but passing on\n"+
			"  Docker Desktop proves NOTHING about the gid/ACL path — that is exercised on native Linux.\n", subject)
	case ep == "":
		fmt.Fprintf(c.diag, "copy: the active daemon endpoint could not be read, so whether %s is meaningfully\n"+
			"  enforced on this daemon is UNKNOWN. It is neither claimed nor dismissed: it is enforced\n"+
			"  on native Linux and bypassed by Docker Desktop's file-sharing layer, and nothing here\n"+
			"  established which of those this is.\n", subject)
	}
}

// uidOK: a uid PRINCIPAL is a bare decimal in the kernel's range — uid_t is 32-bit, so
// 0..4294967295. Validated HERE, in this module, before EVERY helper call that carries a uid,
// and in ONE place rather than per call site. The runtime adapter validates a `--user` value,
// but the runtime and operator uids also reach the helper as ordinary arguments it does not
// type-check, and both are written into destination ACL entries and named in every message
// below. A non-numeric or out-of-range principal would have the ownership/ACL contract claimed
// for a uid no step ever ran as.
//
// Leading zeros are stripped before the range test so the digit count means what it says: a
// digit string too long for a machine integer must be refused by LENGTH first, not handed to a
// parser whose overflow an `if` would read as false.
func uidOK(uid, what string) error {
	if !allDigits(uid) {
		return fmt.Errorf("copy: %s '%s' is not a numeric uid", what, uid)
	}
	n := strings.TrimLeft(uid, "0")
	if n == "" {
		n = "0"
	}
	if len(n) > 10 {
		return fmt.Errorf("copy: %s '%s' is out of range — a uid is 0..4294967295", what, uid)
	}
	var v uint64
	for i := 0; i < len(n); i++ {
		v = v*10 + uint64(n[i]-'0')
	}
	if v > 4294967295 {
		return fmt.Errorf("copy: %s '%s' is out of range — a uid is 0..4294967295", what, uid)
	}
	return nil
}

// Preflight is the EMPIRICAL destination preflight, probed rather than inferred from the
// filesystem's name: create, chown, link, stat, set a default ACL, create a child AS EACH UID,
// read it as the other. A destination that cannot represent the contract is REFUSED, naming
// what failed — a silent best-effort copy is a copy that lies.
//
// THE PREFLIGHT WRITES PROBE FILES INTO THIS SAME STAGING and the pinned image MUST remove them
// before returning, or the copy that follows will refuse it as non-empty: a preflight that
// leaves droppings has corrupted the tree it was validating.
func (c *Copier) Preflight(ctx context.Context, ix *trust.Index, staging, runtimeUID, operatorUID string) error {
	if err := uidOK(runtimeUID, "the product's runtime uid"); err != nil {
		return err
	}
	if err := uidOK(operatorUID, "the operator uid"); err != nil {
		return err
	}
	if err := c.Available(ctx, ix); err != nil {
		return err
	}
	// Whether the ACL step below is meaningfully enforced on this daemon — Docker Desktop
	// bypasses it, native Linux enforces it, an unreadable endpoint is UNKNOWN. Shared with
	// verify, so the two halves cannot tell different stories.
	c.aclContextNote("the ACL step")

	if runtimeUID == operatorUID {
		fmt.Fprintf(c.out, "copy: the product's runtime uid equals the operator's (%s), so the ACL step is a no-op\n"+
			"  (same uid) and is skipped.\n", runtimeUID)
	}

	mount, err := engine.NewHelperStaging(staging)
	if err != nil {
		return err
	}
	out, code, runErr := c.helper(ctx, ix, engine.HelperPreflight, "",
		[]string{"/dst", runtimeUID, operatorUID}, []engine.Mount{mount})
	// A REFUSAL FORMED FROM THE ANSWER MUST STILL CARRY WHY THERE WAS NO ANSWER. The reference
	// checks the observations before the exit status, and so does this — but a helper that never
	// LAUNCHED produces an empty transcript, and every observation is then missing for one
	// reason: the run failed. Joined rather than reordered, so the operator gets the same
	// message the reference gives AND the cause the reference put on stderr.
	because := func(err error) error {
		if runErr != nil {
			return errors.Join(err, runErr)
		}
		return err
	}
	if err := grammarOK(out, "ownership", "permissions", "symlink", "acl", "inherit", "done"); err != nil {
		return because(err)
	}

	for _, k := range []string{"ownership", "permissions", "symlink", "inherit"} {
		v, err := stated(out, k, "preflight", "")
		if err != nil {
			return because(err)
		}
		if v != "ok" {
			return fmt.Errorf("copy: the destination did not pass the '%s' check of the copy contract (%s=%s).\n"+
				"  Refusing: a destination that cannot represent the copy contract would give you a\n"+
				"  best-effort copy that reports success while dropping what it could not carry.", k, k, orEmpty(v))
		}
	}

	v, err := stated(out, "acl", "preflight", "")
	if err != nil {
		return because(err)
	}
	switch v {
	case "ok":
	case "skipped":
		// `skipped` is a no-op ONLY where the two principals are one. Accepting it
		// unconditionally — the obvious `ok|skipped` arm — lets a helper skip the single step
		// the dual-owner problem turns on and still be believed, on exactly the installations
		// where it matters.
		if runtimeUID != operatorUID {
			return fmt.Errorf("copy: the preflight reports the ACL step SKIPPED, but the product's runtime uid (%s)\n"+
				"  is not the operator's (%s) — and equal uids are the only condition under which\n"+
				"  skipping it is a no-op. Refusing: a load-bearing step reported as skipped is a step\n"+
				"  that did not run.", runtimeUID, operatorUID)
		}
	default:
		return fmt.Errorf("copy: the destination cannot hold or inherit ACLs (acl=%s).\n"+
			"  Refusing, like one that cannot hold ownership: without default entries naming BOTH the\n"+
			"  operator and the runtime uid, the first file the product writes after migration is\n"+
			"  unreadable by you — the failure reappears on the first post-migration write.", orEmpty(v))
	}

	if runErr != nil {
		return fmt.Errorf("copy: the destination preflight failed: %w", runErr)
	}
	if code != 0 {
		return errors.New("copy: the destination preflight failed")
	}
	return nil
}

// Options carries what a copy varies. The reference parsed `--map-foreign-to-operator` and
// REFUSED any other option; a typed field makes an unknown option unrepresentable here, and the
// verb's own dispatch keeps the refusal for what the operator actually typed.
type Options struct {
	// MapForeignToOperator folds a foreign uid into the operator's. OPT-IN, because folding
	// foreign ownership is a decision only the operator can make; an unrequested mapping the
	// copier reports anyway is REFUSED, never logged-and-accepted.
	MapForeignToOperator bool
}

// Run is the copy itself: a named source volume, read-only at /src, into a staging directory
// that is the only writable mount. It returns THE COPY'S OWN ENUMERATION OF THE SOURCE — the
// number that binds verification, derived from the copier's `entry=` lines and from nothing a
// caller invents.
//
// Entry types and metadata are a stated contract, not a tool's defaults:
//
//	regular file, directory   copied; mtime preserved; ownership and mode per the policy below
//	symlink                   recreated as a SYMLINK with its target string VERBATIM, never
//	                          resolved. An absolute or escaping target is REFUSED (see below).
//	hardlink                  link structure preserved WITHIN the copy — breaking it silently
//	                          doubles disk use and de-couples files a product expects to be the
//	                          same inode
//	device, socket, FIFO      REFUSED, naming the path
//
// Ownership: uid/gid are MAPPED, not copied, and access is GRANTED, not assumed. Existing files
// are chowned to the operator with an access entry for the runtime uid; and every directory
// carries DEFAULT entries for BOTH principals, because the problem is symmetric across time —
// the first file the PRODUCT writes after migration is owned by the runtime uid, and a default
// ACL naming only that uid grants it what it already has and the operator nothing.
func (c *Copier) Run(ctx context.Context, ix *trust.Index, sourceVolume, staging, runtimeUID, operatorUID string, opts Options) (int, error) {
	src, err := engine.NewHelperSrcVolume(sourceVolume)
	if err != nil {
		return 0, err
	}
	dst, err := engine.NewHelperStaging(staging)
	if err != nil {
		return 0, err
	}
	return c.do(ctx, ix, runtimeUID, operatorUID, opts, []engine.Mount{src, dst})
}

// Fill is THE REVERSE DIRECTION: fill a freshly created, freshly-labelled volume from a HOST
// backup directory — restore's fill phase. Mount roles are exactly reversed from Run's: the
// untrusted backup tree is read-only at /src (a bind, not a volume — nothing here is a docker
// volume yet), and the volume being filled is the only writable mount, at /dst.
//
// Everything else — the entry contract, the refusal vocabulary, the count that binds
// verification — is IDENTICAL, because the copy container's command has no notion of which
// physical thing backs either mount point. ONE parsing implementation, reused rather than
// duplicated: two copies of the entry/refusal/count-binding checks would be exactly the kind of
// drift the "one implementation of a security check" rule exists to prevent.
func (c *Copier) Fill(ctx context.Context, ix *trust.Index, sourceDir, destVolume, runtimeUID, operatorUID string, opts Options) (int, error) {
	src, err := engine.NewHelperSrcBind(sourceDir)
	if err != nil {
		return 0, err
	}
	dst, err := engine.NewHelperDstVolume(destVolume)
	if err != nil {
		return 0, err
	}
	return c.do(ctx, ix, runtimeUID, operatorUID, opts, []engine.Mount{src, dst})
}

// do is THE SHARED BODY of Run and Fill: everything from here down operates on the copy
// container's TRANSCRIPT and does not care which mount specs produced it.
func (c *Copier) do(ctx context.Context, ix *trust.Index, runtimeUID, operatorUID string, opts Options, mounts []engine.Mount) (int, error) {
	if err := uidOK(runtimeUID, "the product's runtime uid"); err != nil {
		return 0, err
	}
	if err := uidOK(operatorUID, "the operator uid"); err != nil {
		return 0, err
	}
	if err := c.Available(ctx, ix); err != nil {
		return 0, err
	}

	args := []string{"/src", "/dst", runtimeUID, operatorUID}
	if opts.MapForeignToOperator {
		args = append(args, "--map-foreign")
	}
	out, code, runErr := c.helper(ctx, ix, engine.HelperCopy, "", args, mounts)
	if err := grammarOK(out, "entry", "linktarget", "stripped", "mapped", "refused", "mismatch", "done"); err != nil {
		return 0, err
	}

	// Report the contract observations BEFORE deciding, so a refusal still tells the operator
	// what the copier saw.
	for _, v := range values(out, "linktarget") {
		if v == "" {
			continue
		}
		if p, target, ok := linktargetSplit(v); ok {
			fmt.Fprintf(c.out, "  symlink preserved verbatim: %s -> %s\n", p, target)
		} else {
			fmt.Fprintf(c.out, "  symlink target logged in a form this core could not read: %s\n", v)
		}
	}
	for _, v := range values(out, "stripped") {
		if v == "" {
			continue
		}
		fmt.Fprintf(c.out, "  privileged bits stripped: %s\n"+
			"    Nothing a product legitimately stores needs setuid/setgid/sticky on the host.\n", v)
	}

	var refused []string
	// A `mapped=` observation is honoured ONLY when the operator opted in. The flag changes the
	// helper's argv, but a regressed or hostile copier can report a mapping on a DEFAULT
	// invocation — and folding foreign ownership into the operator's is exactly the decision
	// the opt-in exists to gate. So an UNREQUESTED mapping is REFUSED, never
	// logged-and-accepted; a requested one is reported with its numeric value preserved.
	for _, v := range values(out, "mapped") {
		if v == "" {
			continue
		}
		if !opts.MapForeignToOperator {
			refused = append(refused, fmt.Sprintf("copy: REFUSED %s — the copier reports folding a foreign uid into the operator's on a\n"+
				"  copy that did NOT request it. Mapping foreign ownership is opt-in: re-run with\n"+
				"  --map-foreign-to-operator if that is your intent, or investigate the foreign uid\n"+
				"  first. An unrequested mapping is refused, never applied silently.", v))
			continue
		}
		fmt.Fprintf(c.out, "  foreign uid mapped to the operator: %s (the numeric value is preserved here in text)\n", v)
	}
	// An EMPTY `mapped=` is MALFORMED whether or not mapping was requested — it reports a
	// mapping that names no uid, which the value loop above skips. Refused regardless: on a copy
	// that did not opt in it is an unrequested mapping, and on one that did it is a mapping
	// record with nothing to preserve.
	if hasEmpty(out, "mapped") {
		refused = append(refused, "copy: the copier reported a foreign-uid mapping that names no uid (an empty 'mapped='\n"+
			"  record). A mapping is refused whether or not it names the uid — an empty one is malformed.")
	}
	// An EMPTY `stripped=` names no path whose privileged bits were removed — a stripped-bits
	// observation of nothing. Malformed like the others, and caught by presence.
	if hasEmpty(out, "stripped") {
		refused = append(refused, "copy: the copier reported a 'stripped=' record that names no path. A privileged-bits\n"+
			"  observation of nothing is malformed — refused rather than logged.")
	}

	// One path, one message: the two sources of a refusal (an explicit `refused=` line and an
	// `entry=` line whose type is `special`) legitimately name the same path.
	seen := map[string]bool{}
	for _, v := range refusals(out, "/src") {
		if v == "" {
			continue
		}
		reason, path, detail := classifyRefusal(v)
		if seen[path] {
			continue
		}
		seen[path] = true
		refused = append(refused, refusalMessage(reason, path, detail, v))
	}

	// An EMPTY `refused=` line (no path) is a stated refusal the loop above skips, because it
	// is passed through as an empty value and the consumer drops empties. Its PRESENCE is the
	// problem, so it is caught here by the key — a copier that refuses without naming what is
	// still a copier that refused.
	if hasKey(out, "refused") && len(refused) == 0 {
		refused = append(refused, "copy: the copier stated a refusal that named nothing (an empty 'refused=' record). A\n"+
			"  refusal is a refusal whether or not it says what — the copy is abandoned.")
	}
	// A `mismatch=` from the COPY step is as fatal as a refusal — the copier saw an entry that
	// does not match and said so. The copy step reads `refused=`; a `mismatch=` line (even
	// empty) is caught here by PRESENCE, so a mismatch reported during the copy cannot be
	// reached only in verify.
	if hasKey(out, "mismatch") {
		for _, v := range values(out, "mismatch") {
			refused = append(refused, "copy: the copier reported a MISMATCH "+orNamed(v))
		}
	}

	if len(refused) > 0 {
		return 0, errors.New(strings.Join(refused, "\n"))
	}
	if runErr != nil {
		return 0, fmt.Errorf("copy: the copy did not complete: %w", runErr)
	}
	if code != 0 {
		return 0, errors.New("copy: the copy did not complete")
	}
	v, err := stated(out, "done", "copy", "completion")
	if err != nil {
		return 0, err
	}
	if v != "ok" {
		return 0, fmt.Errorf("copy: the copier reported 'done=%s' rather than completion — treating that as a\n"+
			"  failure. An exit status is not a result.", orEmpty(v))
	}

	// THE COPY'S OWN ENUMERATION OF THE SOURCE is the number that binds verification. Every
	// `entry=` line is one source entry the copier read; their count is a source-derived number
	// no caller invents, and it is RETURNED for the verify half to be measured against.
	//
	// An EMPTY `entry=` line is a malformed entry the value loop below cannot see, so it is
	// detected on the raw lines first: a copier that claims an entry naming nothing is refused,
	// not counted.
	if hasEmpty(out, "entry") {
		return 0, errors.New("copy: the copier enumerated an empty 'entry=' record — a claimed entry that names nothing.\n" +
			"  Refusing rather than counting it toward a completed copy.")
	}
	// An EMPTY `linktarget=` is the same malformed shape one key over — the value-iterating
	// refusal pass skips it, so it is neither escape-checked nor association-checked. A
	// disclosed target that discloses nothing is refused; it cannot be shown not to escape.
	if hasEmpty(out, "linktarget") {
		return 0, errors.New("copy: the copier disclosed an empty 'linktarget=' record — a symlink target that names\n" +
			"  nothing. An undisclosed target cannot be shown not to escape the tree — refused.")
	}

	entries := 0
	eseen := map[string]bool{}
	for _, v := range values(out, "entry") {
		if v == "" {
			continue
		}
		epath := ""
		if i := strings.Index(v, ":"); i >= 0 {
			epath = v[i+1:]
		}
		if epath == "" {
			return 0, fmt.Errorf("copy: the copier enumerated an entry line with no path ('%s'). Refusing rather than\n"+
				"  counting a claim that names nothing toward a completed copy.", v)
		}
		// The path must be CANONICAL under /src, so two spellings of one file cannot be counted
		// as two entries — a copier could otherwise pad the count that binds verification with
		// spellings while omitting a dangerous entry.
		if !entryPathOK(epath) {
			return 0, fmt.Errorf("copy: the copier enumerated '%s', which is not a canonical path under /src (a '.',\n"+
				"  '..', empty or trailing component, or a path outside /src). A non-canonical path lets one\n"+
				"  source object be counted under several spellings — refused rather than counted.", epath)
		}
		// The count binds verification, so it must be a count of DISTINCT source entries. A
		// repeated path pads the count: emit one valid entry N times and OMIT an escaping
		// symlink or a special entry, and `checked=N` then matches a total that never included
		// the dangerous one. The PATH is the identity of a source entry (a path is one
		// filesystem object whatever type is claimed for it), so duplicates are detected on the
		// path, not the raw line.
		if eseen[epath] {
			return 0, fmt.Errorf("copy: the copier enumerated '%s' more than once. A repeated source path pads the\n"+
				"  entry count without adding a distinct entry — and a padded count can match a 'checked='\n"+
				"  total that omitted a dangerous entry. Refusing rather than binding verification to a\n"+
				"  count of duplicated claims.", epath)
		}
		eseen[epath] = true
		entries++
	}
	// A copy that reports done=ok having enumerated ZERO entries is a vacuous completion —
	// unmeasured is not measured-clean, and over a non-empty source it is exactly that
	// fail-open — so it is REFUSED here rather than recorded as a success measured on nothing.
	if entries == 0 {
		return 0, errors.New("copy: the copier reported done=ok having enumerated ZERO source entries. A completed copy\n" +
			"  that measured nothing is not evidence of a copy — refusing rather than recording a\n" +
			"  vacuous success over what may be a non-empty source.")
	}
	return entries, nil
}

// RunVerify is THE REAL CALL SITE THAT BINDS THE COPY TO ITS VERIFICATION. It runs the copy and
// then verifies it against the source using the count the COPY ITSELF enumerated, never a
// number chosen here or at any call site. Without a caller that threads that count, the
// "checked matches the source" gate is a convention nobody honours: the count degenerates to
// "whatever the caller invents", the tests hard-code it, and the vacuity simply moves. The
// migrate verb calls THIS — the two halves are never wired by hand with a caller-chosen count.
//
// The runtime and operator uids are threaded on to verification so it can confirm the
// dual-principal default ACL was actually APPLIED to the copied tree, not merely possible.
func (c *Copier) RunVerify(ctx context.Context, ix *trust.Index, sourceVolume, staging, runtimeUID, operatorUID string, opts Options) error {
	n, err := c.Run(ctx, ix, sourceVolume, staging, runtimeUID, operatorUID, opts)
	if err != nil {
		return err
	}
	// Belt and braces around the one number this whole gate rests on. Run cannot return a
	// non-positive count on a nil error today; asserting it here means a future edit that
	// makes it possible cannot silently turn verification into a comparison against nothing.
	if n < 1 {
		return errors.New("copy: the copy did not report how many source entries it enumerated, so verification\n" +
			"  cannot be bound to the source. Refusing rather than verifying against a count no step\n" +
			"  derived.")
	}
	return c.Verify(ctx, ix, sourceVolume, staging, n, runtimeUID, operatorUID)
}

// Verify is VERIFICATION OVER THE CONTRACT, NOT A BYTE COUNT: every source entry has a
// counterpart of the same TYPE at the destination, regular-file contents match by DIGEST,
// symlink targets match AS STRINGS, hardlink topology is preserved, and the preserved metadata
// matches. A copy that "succeeded" while dropping modes is a copy that hands the product a
// directory it cannot write.
//
// The destination is mounted READ-ONLY here: a verifier that can repair what it finds cannot
// report it.
//
// <expect> is the source's entry count, derived by the CALLER from the copy step's own
// enumeration — an INDEPENDENT, source-derived number the verifier is measured against, and the
// thing that binds `checked` to the source. Without it, `checked=0 done=ok` is a completion
// claim over no evidence, and a large `checked` is a claim to have compared entries that were
// never there. Neither the count nor the verdict may come from the verifier alone.
func (c *Copier) Verify(ctx context.Context, ix *trust.Index, sourceVolume, dst string, expect int, runtimeUID, operatorUID string) error {
	if expect < 0 {
		return fmt.Errorf("copy: Verify's expected-entry count '%d' is not a count", expect)
	}
	// The uids are validated HERE too (not only in the adapter's --user gate): they are passed
	// to the verifier so it can check the copied tree for the default entries naming BOTH
	// principals, and are named in the messages below.
	if err := uidOK(runtimeUID, "the product's runtime uid"); err != nil {
		return err
	}
	if err := uidOK(operatorUID, "the operator uid"); err != nil {
		return err
	}
	if err := c.Available(ctx, ix); err != nil {
		return err
	}
	// Whether the default-ACL application check below is meaningfully enforced on THIS daemon —
	// the same honest three-way statement preflight makes, shared so verify never claims
	// enforcement Docker Desktop does not give.
	c.aclContextNote("the default-ACL application check")

	src, err := engine.NewHelperSrcVolume(sourceVolume)
	if err != nil {
		return err
	}
	ro, err := engine.NewHelperDstRO(dst)
	if err != nil {
		return err
	}
	out, code, runErr := c.helper(ctx, ix, engine.HelperVerify, "",
		[]string{"/src", "/dst", runtimeUID, operatorUID}, []engine.Mount{src, ro})
	if err := grammarOK(out, "mismatch", "refused", "checked", "acl", "done"); err != nil {
		return err
	}

	var bad []string
	for _, v := range values(out, "mismatch") {
		if v == "" {
			continue
		}
		bad = append(bad, "copy: VERIFICATION MISMATCH "+v)
	}
	// ANY refused= OR mismatch= LINE FAILS THE COPY, DETECTED BY PRESENCE. The verifier can
	// report a refusal exactly as the copy step can — a device it met while walking the
	// destination, an entry it could not compare — and an EMPTY problem record is a stated
	// problem too: the value loop above skips it, so it is caught here by the key. A problem is
	// a problem by being reported, whatever it says.
	if hasKey(out, "refused") {
		for _, v := range values(out, "refused") {
			bad = append(bad, "copy: the verifier REFUSED "+orNamed(v))
		}
	}
	if hasKey(out, "mismatch") && len(bad) == 0 {
		bad = append(bad, "copy: the verifier reported a MISMATCH it did not name")
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s\ncopy: the copy does not match the source over the per-entry contract.", strings.Join(bad, "\n"))
	}

	if runErr != nil {
		return fmt.Errorf("copy: verification did not run to completion: %w", runErr)
	}
	if code != 0 {
		return errors.New("copy: verification did not run to completion")
	}
	v, err := stated(out, "done", "verify", "completion")
	if err != nil {
		return err
	}
	if v != "ok" {
		return fmt.Errorf("copy: verification reported 'done=%s' rather than completion — treating that as\n"+
			"  a failure.", orEmpty(v))
	}

	// A COUNT IS PART OF THE RESULT. "done=ok" with no count is a verification claim on no
	// evidence: a verifier that walked zero entries and exited 0 would otherwise report the copy
	// good.
	n, err := stated(out, "checked", "verify", "how many entries it checked")
	if err != nil {
		return err
	}
	// BELT AND BRACES, and ordered so the clearer message wins. A stated `checked=` that is not
	// a number can only ever differ from the source's own count, so the binding check below
	// would refuse it too — but it would refuse it by SAYING "the verifier checked many entries
	// but the source has 5", which describes the wrong problem. Measured: mutating this branch
	// away leaves the copy refused, with that worse message. It stays for the message, and
	// because a reader must not have to prove the next check is exhaustive to know this one is
	// safe. (Mutation-verified as subsumed-for-the-verdict, not for the diagnosis.)
	if !allDigits(n) {
		return fmt.Errorf("copy: verification did not say how many entries it checked (checked=%s).\n"+
			"  Refusing: a completion claim with no count is not evidence that anything was compared.", orEmpty(n))
	}
	// BIND THE COUNT TO THE SOURCE. The verifier must have checked EXACTLY the source's entries
	// — not zero of them (a vacuous pass over a non-empty source), and not a fabricated surplus.
	// A count that differs from the source's own means the per-entry walk did not cover the
	// source the copy read, so the copy is not verified. Compared as STRINGS: both are validated
	// digit strings, and string equality sidesteps any overflow trap on an absurd stated count.
	if n != fmt.Sprint(expect) {
		return fmt.Errorf("copy: the verifier checked %s entries but the source has %d — the per-entry walk did\n"+
			"  not cover exactly the source the copy read, so the copy is NOT verified. (A count of\n"+
			"  zero against a non-empty source is this failure's most important shape.)", n, expect)
	}

	// THE DUAL-PRINCIPAL DEFAULT ACL WAS ACTUALLY APPLIED to the copied tree — checked
	// empirically here, not inferred from preflight capability (capability is not application).
	// A missing default entry on a copied directory is reported as a `default-acl` mismatch
	// above, like any other attribute; this REQUIRES the positive observation on top, because a
	// verifier that never looked emits no acl mismatch and would otherwise pass on no evidence —
	// the very vacuity this closes, one level down. Absent is a refusal; `skipped` is a no-op
	// ONLY when the two principals are one uid, exactly as preflight's acl step.
	da, err := stated(out, "acl", "verify", "the default-ACL application")
	if err != nil {
		return err
	}
	switch da {
	case "ok":
	case "skipped":
		if runtimeUID != operatorUID {
			return fmt.Errorf("copy: verification reports the default-ACL check SKIPPED, but the product's runtime uid\n"+
				"  (%s) is not the operator's (%s) — the only condition under which it is a no-op.\n"+
				"  Refusing: a load-bearing check reported as skipped is a check that did not run.", runtimeUID, operatorUID)
		}
	default:
		return fmt.Errorf("copy: the copied tree did not pass the default-ACL application check (acl=%s).\n"+
			"  Refusing: capability at preflight is not proof of application. Without the default\n"+
			"  entries naming BOTH the operator and the runtime uid, the first file the product writes\n"+
			"  after migration is unreadable by you — the failure reappears on the first post-migration\n"+
			"  write.", orEmpty(da))
	}
	fmt.Fprintf(c.out, "copy: verified %s entries against the source over the per-entry contract.\n", n)
	return nil
}

// --- the three READ-ONLY modes of `verify` (the backup/restore direction) ---------------------
//
// THREE MORE MODES OF THE SAME CLOSED COMMAND WORD, never a new one (D49): new command
// ARGUMENTS. They are distinguished from the ordinary four-argument `verify` by their SECOND
// argument, which can never be the literal `/dst` every ordinary caller passes. All three read a
// single volume, mounted READ-ONLY at /src, and take no destination, no uids and no ACL step —
// they enumerate or compare, they never map ownership and they never write.
//
// THEY HAND BACK THE TRANSCRIPT UNREAD, and that is deliberate rather than lazy. The refusals
// these three feed are specified against the transcript — which observation was missing, which
// mismatch names nothing, and the count that binds a verification to the manifest it claims to
// have checked — and those refusals belong to the backup/restore module, whose own tests pin
// them. A second reading of the same lines here would be a second implementation of the same
// rules, which is the drift this codebase's one-implementation rule exists to prevent. What this
// module owes them is the LAUNCH: the pinned image, the read-only volume mount, private
// networking, the provenance labels, and — for the third — the manifest on stdin rather than as a
// third host mount.
//
// AN ERROR MEANS THE HELPER COULD NOT BE RUN, exactly as everywhere else here; a helper that ran
// and failed reports itself in the returned exit status, and a caller that formed its verdict
// from the transcript alone would still see the launch failure on the diagnostics stream.
//
// `Available` IS NOT RE-ASKED HERE. Every caller of these three asks it immediately before, as
// the reference's own three callers do; a second image inspect is not a second guarantee, and
// duplicating it would put the same question in two places to drift.

// Enumerate is `verify <src> --manifest`: the BACKUP MANIFEST for one volume — per entry its
// TYPE, and per type the content digest, the verbatim link target, the hardlink group, mode,
// ownership and mtime. The transcript IS the manifest the backup stores; nothing here reshapes
// it, because a manifest that is re-rendered on the way out is not the evidence the helper
// produced.
func (c *Copier) Enumerate(ctx context.Context, ix *trust.Index, volume string) (string, int, error) {
	return c.readOnlyVerify(ctx, ix, volume, "--manifest", nil)
}

// Count is `verify <src> --count`: how many entries a volume holds, which is how a restore
// establishes that a volume it has just created is EMPTY before it fills it. Emptiness must be
// observed THROUGH the daemon — the host cannot read a named volume at all (D54) — so it is a
// helper run and not a directory listing.
func (c *Copier) Count(ctx context.Context, ix *trust.Index, volume string) (string, int, error) {
	return c.readOnlyVerify(ctx, ix, volume, "--count", nil)
}

// VerifyAgainstManifest is `verify <src> --against-stdin`: compare a filled volume against the
// backup's OWN per-entry manifest, handed to the helper on stdin.
//
// IT IS A DIFFERENT QUESTION FROM Verify, and the two must not be confused. Verify compares a
// VOLUME at /src against a HOST tree at /dst over a count the copy step itself derived — the
// copy→verify pair. This one has no /dst at all: the evidence is the manifest bytes, and the
// count that binds it is the manifest's own entry count, established by the caller that holds
// the manifest.
func (c *Copier) VerifyAgainstManifest(ctx context.Context, ix *trust.Index, volume string, manifest []byte) (string, int, error) {
	return c.readOnlyVerify(ctx, ix, volume, "--against-stdin", manifest)
}

// readOnlyVerify is the shared launch of the three modes above: the volume READ-ONLY at /src and
// NOTHING ELSE mounted, the mode as the second argument, private networking, and no `--user` —
// these modes read, and a reader that ran as a mapped principal would be answering a question
// about that principal rather than about the volume.
func (c *Copier) readOnlyVerify(ctx context.Context, ix *trust.Index, volume, mode string, stdin []byte) (string, int, error) {
	src, err := engine.NewHelperSrcVolume(volume)
	if err != nil {
		return "", 0, err
	}
	out, code, runErr := c.helperStdin(ctx, ix, engine.HelperVerify, "",
		[]string{"/src", mode}, []engine.Mount{src}, stdin)
	return string(out), int(code), runErr
}

// AccessCheck is CONTAINER-SIDE EFFECTIVE ACCESS, by OUR helper running AS THE PRODUCT'S
// RUNTIME UID.
//
// ACL PRESENCE IS NOT EFFECTIVE ACCESS — a restrictive ACL mask silently limits a present entry
// — and the rule that forbids requiring tools in PRODUCT images does not reach the pinned
// helper, which is ours. So it mounts the destination, actually traverses, reads, and writes a
// probe file, then removes it. That is effective-access verification without asking anything of
// the product image.
//
// WHAT REMAINS UNCLAIMED is only the product's OWN runtime behaviour: the filesystem access
// itself is tested, not constructed-and-hoped.
func (c *Copier) AccessCheck(ctx context.Context, ix *trust.Index, dst, runtimeUID string) error {
	// Checked HERE as well as in the runtime adapter, because the value is also printed in
	// every message below and a non-numeric one would name a uid this check never ran as.
	if err := uidOK(runtimeUID, "the runtime uid"); err != nil {
		return err
	}
	if err := c.Available(ctx, ix); err != nil {
		return err
	}
	mount, err := engine.NewHelperStaging(dst)
	if err != nil {
		return err
	}
	out, code, runErr := c.helper(ctx, ix, engine.HelperAccess, runtimeUID, []string{"/dst"}, []engine.Mount{mount})
	// See Preflight: an empty transcript from a helper that never launched must not be reported
	// as an answer that merely omitted something.
	because := func(err error) error {
		if runErr != nil {
			return errors.Join(err, runErr)
		}
		return err
	}
	if err := grammarOK(out, "traverse", "read", "write"); err != nil {
		return because(err)
	}
	for _, k := range []string{"traverse", "read", "write"} {
		v, err := stated(out, k, "access", "")
		if err != nil {
			return because(err)
		}
		if v != "ok" {
			return fmt.Errorf("copy: as uid %s, the destination failed the '%s' check (%s=%s).\n"+
				"  ACL presence is not effective access — a restrictive mask silently limits an entry that\n"+
				"  is present — which is why this is TESTED as that uid rather than inferred from the\n"+
				"  entries we set. Refusing.", runtimeUID, k, k, orEmpty(v))
		}
	}
	if runErr != nil {
		return fmt.Errorf("copy: the container-side access check did not run to completion: %w", runErr)
	}
	if code != 0 {
		return errors.New("copy: the container-side access check did not run to completion")
	}
	return nil
}

// HostAccessCheck is the HOST-SIDE half: the operator can traverse and read the tree. Done on
// the host, with no container, because it is the operator's own access that is in question.
//
// DIRECTORIES AND FILES BOTH, in one walk. A tree whose directories are all traversable but
// whose FILES cannot be read is exactly as unusable as the other way round, and checking only
// one of them is the most common defect shape here: a rule applied to some of the things that
// reach it.
//
// SYMLINKS ARE NOT FOLLOWED, deliberately. The copy preserves a symlink target as TEXT and
// never follows it; following one here would report on whatever it points at rather than on the
// migrated tree, and could refuse a perfectly good copy because of something outside it
// entirely.
//
// A DIRECTORY THAT COULD NOT BE DESCENDED INTO IS A FINDING, not a subtree quietly skipped: "I
// could not look" is never "there is nothing wrong there". (The reference folds `find`'s own
// stderr into its findings for the same reason.)
//
// THE BOUND ON WHAT THIS PROVES, stated rather than implied: the mode bits read are the OWNER's,
// which is the operator's own permission on a tree this copy has just chowned to the operator,
// and is not the same question as "can this process open it" on a tree owned by someone else.
func HostAccessCheck(dst string) error {
	info, err := os.Stat(dst)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("copy: '%s' is not a directory", dst)
	}
	var bad []string
	_ = filepath.WalkDir(dst, func(p string, d fs.DirEntry, walkErr error) error {
		// "I COULD NOT LOOK" IS NEVER "THERE IS NOTHING WRONG THERE" — a subtree that could not
		// be descended into is a subtree nobody checked, so it is a FINDING and the walk goes
		// on rather than stopping (one unreadable subtree must not hide the rest).
		//
		// STATED RESIDUAL: on every state POSIX mode bits can describe, the permission check
		// below fires on the very entry this error is about — a directory that cannot be listed
		// is also a directory missing r or x — so mutating this branch away does not change any
		// verdict reachable with chmod, and no test here can isolate it. It is kept for the
		// states mode bits cannot describe: an entry removed mid-walk, an I/O error, a
		// filesystem refusing for a reason of its own. Removing it would turn exactly those into
		// a silently shortened listing, which is the one outcome this whole module refuses.
		if walkErr != nil {
			bad = append(bad, fmt.Sprintf("copy: the migrated tree could not be fully examined: %s (%v)", p, walkErr))
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil {
			bad = append(bad, fmt.Sprintf("copy: the migrated tree could not be fully examined: %s (%v)", p, ierr))
			return nil
		}
		switch {
		case d.IsDir():
			if fi.Mode().Perm()&0o500 != 0o500 {
				bad = append(bad, "copy: the migrated tree is not fully readable by you: "+p)
			}
		case fi.Mode().IsRegular():
			if fi.Mode().Perm()&0o400 != 0o400 {
				bad = append(bad, "copy: the migrated tree is not fully readable by you: "+p)
			}
		}
		return nil
	})
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "\n"))
	}
	return nil
}

// orEmpty renders an empty stated value as the reference's `<empty>` placeholder, so a message
// about a value that was stated-but-blank cannot read as a message about a missing one.
func orEmpty(v string) string {
	if v == "" {
		return "<empty>"
	}
	return v
}

// orNamed is the same idea for a problem record whose value is blank: a refusal that named
// nothing is still a refusal, and the message says so instead of trailing off.
func orNamed(v string) string {
	if v == "" {
		return "<an entry it did not name>"
	}
	return v
}
