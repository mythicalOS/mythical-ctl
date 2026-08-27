package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"mythicalos.ai/ctl/internal/backup"
	"mythicalos.ai/ctl/internal/copyfill"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/intent"
	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/runtime"
	"mythicalos.ai/ctl/internal/trust"
)

// This file is the PRODUCTION WIRING of the two seams the backup/restore verbs are specified
// against — nothing more. It holds no rule of its own: every refusal a backup or a restore can
// make is written in internal/backup, and every observation about a volume is made by
// internal/copyfill. What lives here is the assembly the two modules deliberately do not do for
// themselves, because a module that constructed its own dependencies could not be tested against
// a different one.

// copyAdapter satisfies backup.Copier over internal/copyfill.
//
// THE TRANSCRIPT CROSSES THE SEAM UNREAD, which is the whole shape of it. The copy module owns
// the LAUNCH (the pinned image, the read-only volume mount, private networking, the provenance
// labels, the manifest on stdin); the backup module owns the READING (which observation was
// missing, which mismatch names nothing, the count that binds a verification to the manifest it
// claims to have checked). This adapter carries bytes and an exit status between them and adds
// no judgement, because a judgement made here would be a second copy of a rule that already has
// exactly one home.
type copyAdapter struct{ c *copyfill.Copier }

// answer folds the copy module's three-value return into the seam's transcript. An error still
// means the helper COULD NOT BE RUN — never a failed check — and the transcript is handed back
// beside it rather than discarded, so a caller that wants to report both can.
func answer(text string, code int, err error) (backup.Transcript, error) {
	return backup.Transcript{Text: text, Code: code}, err
}

func (a copyAdapter) Available(ctx context.Context, ix *trust.Index) error {
	return a.c.Available(ctx, ix)
}

func (a copyAdapter) Enumerate(ctx context.Context, ix *trust.Index, volume string) (backup.Transcript, error) {
	return answer(a.c.Enumerate(ctx, ix, volume))
}

func (a copyAdapter) Count(ctx context.Context, ix *trust.Index, volume string) (backup.Transcript, error) {
	return answer(a.c.Count(ctx, ix, volume))
}

func (a copyAdapter) Verify(ctx context.Context, ix *trust.Index, volume string, manifest []byte) (backup.Transcript, error) {
	return answer(a.c.VerifyAgainstManifest(ctx, ix, volume, manifest))
}

// Run and Fill DISCARD the copy's own source-entry count, and that is correct here rather than a
// dropped result. The count exists to bind a copy to the verification that immediately re-reads
// the SAME source — the migration's copy→verify pair. A backup's verification happens later, on
// another machine, against the per-entry MANIFEST the backup carries; that manifest's own entry
// count is what binds it, and it is established by the module that holds the manifest. Threading
// the copy's count into that comparison would bind a restore to a number from the backup run,
// which is not evidence about the restore. (The reference discards it in exactly these two call
// sites, and nowhere else.)
//
// NEITHER OPTS IN TO FOREIGN-UID MAPPING. Folding a foreign uid into the operator's is a decision
// only the operator can make, and neither verb offers the option — the dispatcher refuses
// `--map-foreign-to-operator` on both. Passing the zero Options is therefore not a default that
// happens to be safe: it is the reason an unrequested `mapped=` observation from the copier is
// REFUSED rather than logged.
func (a copyAdapter) Run(ctx context.Context, ix *trust.Index, volume, dstHostDir, runtimeUID, operatorUID string) error {
	_, err := a.c.Run(ctx, ix, volume, dstHostDir, runtimeUID, operatorUID, copyfill.Options{})
	return err
}

func (a copyAdapter) Fill(ctx context.Context, ix *trust.Index, srcHostDir, volume, runtimeUID, operatorUID string) error {
	_, err := a.c.Fill(ctx, ix, srcHostDir, volume, runtimeUID, operatorUID, copyfill.Options{})
	return err
}

// buildCopier is the production `newCopier`. The narration and the helper's stderr are routed to
// the verb's own streams rather than the process globals, so an in-process caller sees everything
// the operator would.
func buildCopier(rt *runtime.Runtime, ident string, out, diag io.Writer) (backup.Copier, error) {
	c, err := copyfill.New(rt, ident, intent.NonceNew)
	if err != nil {
		return nil, err
	}
	if err := c.SetOutput(out); err != nil {
		return nil, err
	}
	if err := c.SetDiagnostics(diag); err != nil {
		return nil, err
	}
	return copyAdapter{c: c}, nil
}

// copierIdent answers WHOSE the copy helper containers are.
//
// EVERY OBJECT THIS INSTALLER CREATES CARRIES THE INSTALLATION IT BELONGS TO, and the copy
// container is no exception: a helper carrying only a nonce is anonymous — a nonce says WHICH
// object, never WHOSE — so a leaked one could never be shown to be ours. On a backup the answer
// is simply the recorded installation identity.
//
// A RESTORE HAS NO INSTALLATION IDENTITY TO CARRY, and inventing one would be worse than saying
// so. Restore REQUIRES that no active ledger exists — it is a recovery operation, and activating
// a restored ledger beside a live installation would orphan every running container of the
// installation that is there now — so on the only path that reaches this with no identity, there
// genuinely is no installation yet. The incoming one lives in the STAGED ledger, which this
// process cannot open at all: the staging store is pinned by the build's boundary gate to the
// backup module alone, precisely so no lifecycle path can read a not-yet-verified restore as live
// state. So a fresh per-run token stands in, and it is deliberately NONCE-SHAPED ("n" + hex): it
// cannot be confused with an installation identity ("i" + hex), and a helper container leaked by
// a killed process therefore reads as ANOTHER party's object — a note — rather than as this
// installation's unrecorded one, which would block every later verb until repaired. That is what
// the reference did for every copy helper it ever ran; here it is the narrow fallback rather than
// the rule.
//
// AN UNREADABLE LEDGER IS A REFUSAL, NEVER A STAND-IN. "There is no identity recorded" and "the
// ledger could not be read" are different facts: the first is an answer this function may act on,
// the second means a real installation may be standing right here, and labelling its copy
// containers as a stranger's would hide them from its own accounting.
func copierIdent(h famlock.Held) (string, error) {
	st, err := ledger.Live(h)
	if err != nil {
		return "", err
	}
	l, rerr := ledger.Read(st)
	switch {
	case rerr == nil:
	case errors.Is(rerr, ledger.ErrMissingLedger):
		return intent.NonceNew()
	default:
		return "", fmt.Errorf("mythical-ctl: the installer state ledger could not be read, so the copy container\n"+
			"  cannot be labelled with the installation it belongs to. Refusing rather than running a\n"+
			"  privileged helper nothing could later prove is ours: %w", rerr)
	}
	id, ierr := l.IdentGet()
	switch {
	case ierr == nil:
		return id, nil
	case errors.Is(ierr, ledger.ErrAbsentRecord):
		return intent.NonceNew()
	default:
		return "", fmt.Errorf("mythical-ctl: the recorded installation identity could not be read, so the copy\n"+
			"  container cannot be labelled with the installation it belongs to. Refusing rather than\n"+
			"  running a privileged helper nothing could later prove is ours: %w", ierr)
	}
}
