// Package preflight is §4b — the preconditions that make the rest of the design's guarantees
// true. Every check REFUSES rather than degrading: publishing anyway and calling it loopback
// would be the design claiming a wall it does not have.
//
// Endpoint LOCALITY (D30/§4b.3) is not here: engine.ResolveEndpoint enforces it fail-closed
// before a client exists to preflight — a daemon this package is asked about is already a
// local unix socket.
//
// `allow-direct-routing` is a DAEMON setting that re-exposes published ports, and it is
// deliberately absent from this package: it is NOT DETECTABLE from any API the CLI can reach.
// It is a stated precondition, not an enforced check — only a positive active probe could
// refuse on it, and a negative probe proves nothing, so nothing here claims to have looked.
// Saying "verified" about a setting we cannot read would be the one thing worse than not
// checking it.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mythicalos.ai/ctl/internal/engine"
)

// MinEngine is D29's floor: Engine 28+ is what makes the loopback publish a WALL. Before
// Engine 28, a port published to 127.0.0.1 is still reachable from the same L2 segment —
// so an older daemon is refused, never accommodated.
const MinEngine = 28

// engineMajorOK compares the engine's MAJOR against MinEngine numerically. Docker versions
// are `28.1.4`, sometimes with a suffix (`28.0.0-beta.1`); only the leading integer matters.
//
// An UNPARSEABLE version is a REFUSAL, not a pass: a daemon reporting `dev` or an empty
// string is one we cannot place on either side of the gate, and treating unknown as
// new-enough is the same error as treating an unmeasured thing as measured-clean.
//
// A COMPLETE grammar, not a prefix check (the reference closed this class after three
// rounds of next-malformed-string): `<digits>(.<digits>)*` with an OPTIONAL non-empty
// pre-release/build suffix introduced by the first `-` or `+`, its first byte alphanumeric.
// So `28`, `28.1.4`, `2025.1`, `28.0.0-beta.1`, `28.0.0+build.7` pass; `28.`, `28..`,
// `28.0..`, `28.0__`, `28.0-`, `28.0.0--`, `.28`, `-28.0`, `dev` and “ are refused. The
// suffix is deliberately NOT parsed beyond that: its contents are Docker's business, and
// inventing a grammar for them risks REFUSING a legitimate future version — a false refusal
// strands every install on a supported daemon, the more expensive error when only the major
// decides the gate.
func engineMajorOK(v string) bool {
	if v == "" {
		return false
	}
	core := v
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		core = v[:i]
		suffix := v[i+1:]
		if suffix == "" {
			return false
		}
		b := suffix[0]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z') {
			return false
		}
	}
	major := 0
	for _, comp := range strings.Split(core, ".") {
		if comp == "" || len(comp) > 9 {
			return false
		}
		for i := 0; i < len(comp); i++ {
			if comp[i] < '0' || comp[i] > '9' {
				return false
			}
		}
		if major == 0 {
			for i := 0; i < len(comp); i++ {
				major = major*10 + int(comp[i]-'0')
			}
			// A major of literal 0 stays 0 and compares below the floor, which is right.
			if major == 0 {
				major = -1 // mark parsed-but-zero so a "0.x" is not re-parsed from the minor
			}
		}
	}
	if major == -1 {
		return false
	}
	return major >= MinEngine
}

// Daemon checks the daemon half: reachable, ROOTFUL, and Engine >= MinEngine.
func Daemon(ctx context.Context, c *engine.Client) error {
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("preflight: the container runtime did not answer — start Docker (or Docker Desktop) and try again: %w", err)
	}

	// Rootless (D29/§4b.2) — THREE outcomes, and "could not ask" is NOT "rootful": the
	// answer comes from Info's SecurityOptions, and a daemon whose info call errors, or whose
	// info carries no such field, is refused rather than assumed.
	info, err := c.Info(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("preflight: cannot determine whether the daemon is rootless — refusing rather than assuming: %w", err)
	case rootless(info):
		return errors.New("preflight: this is a ROOTLESS docker daemon, which mythical-ctl refuses — the loopback publishing guarantee (D26) depends on rootful port publishing, so on a rootless daemon this installation would be claiming a wall it does not have")
	case len(info.SecurityOptions) == 0:
		// An Info shape missing the field entirely is the second face of "could not ask".
		return errors.New("preflight: the daemon reported no security options at all, so whether it is rootless cannot be determined — refusing rather than assuming")
	}

	v, _, err := c.ServerVersion(ctx)
	if err != nil {
		return fmt.Errorf("preflight: cannot read the engine version: %w", err)
	}
	if !engineMajorOK(v) {
		return fmt.Errorf("preflight: docker Engine %q is not supported — mythical-ctl requires Engine %d or newer: before Engine %d, a port published to 127.0.0.1 is still reachable from the same L2 segment, and publishing anyway would be a false claim", v, MinEngine, MinEngine)
	}
	return nil
}

func rootless(info *engine.DaemonInfo) bool {
	for _, opt := range info.SecurityOptions {
		if opt == "name=rootless" || strings.HasPrefix(opt, "name=rootless,") {
			return true
		}
	}
	return false
}

// Network is the topology half (D29/§4b.2), for ONE network — by ID or name: it must exist,
// its driver must be the NAT-mode bridge, and `trusted_host_interfaces` must be unset.
func Network(ctx context.Context, c *engine.Client, network string) error {
	info, err := c.NetworkInspect(ctx, network)
	if errors.Is(err, engine.ErrAbsent) {
		return fmt.Errorf("preflight: network %q does not exist", network)
	}
	if err != nil {
		return err
	}
	switch info.Driver {
	case "bridge":
	case "macvlan", "ipvlan":
		return fmt.Errorf("preflight: network %q uses the %s driver, which mythical-ctl refuses — %s places the container directly on the physical network, so publishing to 127.0.0.1 constrains nothing; use a NAT-mode user-defined bridge", network, info.Driver, info.Driver)
	default:
		// An unknown driver is refused for the same reason an unparseable engine version is:
		// we cannot place it on either side of D29's guarantee.
		return fmt.Errorf("preflight: network %q uses the %q driver; mythical-ctl requires a NAT-mode bridge", network, info.Driver)
	}
	// `trusted_host_interfaces` (Engine 28+) re-exposes loopback-published ports on the named
	// interfaces. ANY non-empty value is a refusal — there is no safe subset, and enumerating
	// "acceptable" interfaces would be this installer deciding which of the operator's
	// networks are trustworthy.
	if thi := info.Options["com.docker.network.bridge.trusted_host_interfaces"]; thi != "" {
		return fmt.Errorf("preflight: network %q has trusted_host_interfaces set to %q — that re-exposes 127.0.0.1-published ports on those interfaces, defeating D26's wall; recreate the network without the option, or point MYTHICAL_NET at one that has it unset", network, thi)
	}
	return nil
}

// All runs both halves — the entry every mutating verb calls before it touches anything. An
// EMPTY network explicitly skips the network half: a first install has no network until it is
// created (and is checked immediately after), and stop/uninstall must work when the network
// is gone.
func All(ctx context.Context, c *engine.Client, network string) error {
	if err := Daemon(ctx, c); err != nil {
		return err
	}
	if network == "" {
		return nil
	}
	return Network(ctx, c, network)
}
