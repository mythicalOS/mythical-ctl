package runtime

import (
	"context"
	"fmt"
	"sort"

	"mythicalos.ai/ctl/internal/engine"
)

// Closed inspect accessors, replacing the reference's closed Go-template map. Read-only —
// free functions over engine.Client results, because status must read without the lock. Each
// carries the behavioral note its template carried; the templates' rule ("no caller can
// supply a template, callers name a symbolic field") is now the type system's.

// Running answers `{{.State.Running}}`.
func Running(info *engine.ContainerInfo) bool { return info.Running }

// Nonce answers the object's nonce label. A nonce says WHICH object, never WHOSE (§6a).
func Nonce(info *engine.ContainerInfo) string { return info.Labels[engine.LabelNS+"nonce"] }

// InstallLabel answers the object's installation label — the only evidence an object is ours.
func InstallLabel(info *engine.ContainerInfo) string {
	return info.Labels[engine.LabelNS+"installation"]
}

// ProductLabel answers the object's product label.
func ProductLabel(info *engine.ContainerInfo) string {
	return info.Labels[engine.LabelNS+"product"]
}

// NetAttachment is one attachment in the id-keyed view every running-container comparison
// uses. A STOPPED container has an empty Addr — the daemon releases the address, so "a
// stopped container has no endpoint" is a property tests observe rather than assume (D48).
type NetAttachment struct {
	ID   string
	Addr string
}

// NamedNetAttachment is the NAME-carrying view (the inspect map KEY), for the PRE-START
// attach check: a container that has NEVER started reports an EMPTY ID for every endpoint —
// the runtime assigns the endpoint id at first start, and it then persists across stop — so
// only the network NAME, present from creation, identifies the attachment. The type carries
// both, plus the aliases and gateway priority the endpoint registered.
type NamedNetAttachment struct {
	Name       string
	ID         string
	Addr       string
	Aliases    []string
	GwPriority int
}

// Nets answers `c.nets`: the id-keyed attachment set. Deterministic order (by name) so two
// reads of one container compare equal.
func Nets(info *engine.ContainerInfo) []NetAttachment {
	var out []NetAttachment
	for _, p := range NetPairs(info) {
		out = append(out, NetAttachment{ID: p.ID, Addr: p.Addr})
	}
	return out
}

// NetPairs answers `c.netpairs`/`c.aliaspairs`: the name-keyed view with everything the
// endpoint carries.
func NetPairs(info *engine.ContainerInfo) []NamedNetAttachment {
	names := make([]string, 0, len(info.Networks))
	for name := range info.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []NamedNetAttachment
	for _, name := range names {
		ep := info.Networks[name]
		out = append(out, NamedNetAttachment{
			Name:       name,
			ID:         ep.NetworkID,
			Addr:       ep.IPAddress,
			Aliases:    ep.Aliases,
			GwPriority: ep.GwPriority,
		})
	}
	return out
}

// MountsOf answers `c.mounts`.
func MountsOf(info *engine.ContainerInfo) []engine.MountRecord { return info.Mounts }

// Ports answers `c.ports`. The HostIP in each record exists so a caller can ASSERT the
// loopback wall, never to choose it.
func Ports(info *engine.ContainerInfo) []engine.PortBinding { return info.Ports }

// ResolveNetPairs returns the attachment set with EVERY empty endpoint id RESOLVED by looking
// the network NAME up — the reader install/recreate's pre-start check, state repair and
// network migration use in place of a bare read, which on a created-but-not-started container
// mis-identifies every network as "".
//
// FAIL CLOSED, and it is not a name-substitution fallback: a network may LEGALLY be named a
// 64-hex string — the exact spelling of an expected id — so emitting the name when resolution
// fails would let a stray attachment named the expected id pass an exact-set check on a
// transient inspect hiccup. If an endpoint reports no id AND its name cannot be resolved to
// one, the whole read fails and the caller refuses rather than guessing.
func ResolveNetPairs(ctx context.Context, c *engine.Client, info *engine.ContainerInfo) ([]NamedNetAttachment, error) {
	pairs := NetPairs(info)
	for i, p := range pairs {
		if p.ID != "" {
			continue
		}
		ni, err := c.NetworkInspect(ctx, p.Name)
		if err != nil || ni.ID == "" {
			return nil, fmt.Errorf("runtime: an attachment (%q) on %q reports no id and its name could not be resolved to one, so the container's exact network set cannot be established — refusing rather than guessing: a guessed id could match an expected network it is not on (%v)", p.Name, info.Name, err)
		}
		pairs[i].ID = ni.ID
	}
	return pairs, nil
}
