package bringup

import (
	"context"

	"mythicalos.ai/ctl/internal/ledger"
	"mythicalos.ai/ctl/internal/netref"
	"mythicalos.ai/ctl/internal/trust"
)

// Verifier adapts this package's two verification functions to the seams internal/netref declares.
//
// THE DEPENDENCY RUNS ONE WAY, and this type is why. bringup's exact-set check consumes netref's
// migration record (during a migration the permitted set is {source, target}), so bringup imports
// netref. The migration machine in turn needs those same two checks in phase 3. Importing back
// would be a cycle, so netref declares the two INTERFACES it needs and the caller — the verb layer,
// which holds both — hands it this adapter.
//
// IT CARRIES NO LEDGER. An earlier revision captured one, and the comment here claimed that was
// what stopped phase 3 verifying against a different ledger than the one it commits to — but
// capturing is exactly HOW that happens: reload the ledger, reuse the Deps, and the verifier
// answers from the stale copy while the phase advances the fresh one. The ledger now arrives as an
// argument on both seam methods, so there is no second one to hold.
type Verifier struct {
	D Deps
}

var (
	_ netref.AttachVerifier = Verifier{}
	_ netref.LiveVerifier   = Verifier{}
)

// VerifyAttach satisfies netref.AttachVerifier.
func (v Verifier) VerifyAttach(ctx context.Context, l *ledger.Ledger, container, netID, alias string) error {
	return VerifyAttach(ctx, l, v.D, container, netID, alias)
}

// VerifyLive satisfies netref.LiveVerifier. The probe-unavailable distinction is preserved across
// the seam: phase 3 stops WITHOUT detaching when the probe did not run, and netref recognizes that
// case by netref.ErrProbeUnavailable — which is the same error this package re-exports.
func (v Verifier) VerifyLive(ctx context.Context, l *ledger.Ledger, ix *trust.Index, container, netID, alias string) error {
	d := v.D
	if ix != nil {
		d.Index = ix
	}
	return VerifyLive(ctx, l, d, container, netID, alias)
}
