package bringup

import (
	"context"
	"errors"

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
// It is a struct rather than two loose functions because both seams need the same ledger and Deps,
// and a caller that constructed them separately could hand phase 3 a verifier reading a different
// ledger than the one it is committing to.
type Verifier struct {
	L *ledger.Ledger
	D Deps
}

var (
	_ netref.AttachVerifier = Verifier{}
	_ netref.LiveVerifier   = Verifier{}
)

// VerifyAttach satisfies netref.AttachVerifier.
func (v Verifier) VerifyAttach(ctx context.Context, container, netID, alias string) error {
	return VerifyAttach(ctx, v.L, v.D, container, netID, alias)
}

// VerifyLive satisfies netref.LiveVerifier. The probe-unavailable distinction is preserved across
// the seam: phase 3 stops WITHOUT detaching when the probe did not run, and netref recognizes that
// case by netref.ErrProbeUnavailable — which is the same error this package re-exports.
func (v Verifier) VerifyLive(ctx context.Context, ix *trust.Index, container, netID, alias string) error {
	d := v.D
	if ix != nil {
		d.Index = ix
	}
	err := VerifyLive(ctx, v.L, d, container, netID, alias)
	if err != nil && errors.Is(err, ErrProbeUnavailable) {
		// Already wraps netref.ErrProbeUnavailable — ErrProbeUnavailable IS that error.
		return err
	}
	return err
}
