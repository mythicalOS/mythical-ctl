package runtime

import (
	"context"
	"fmt"

	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/famlock"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
)

// Runtime is the lock-bound facade. It is the only holder of an engine.Mutator (check.sh's
// NewMutator boundary rule), so every road to a runtime mutation passes the family lock —
// and stays passed: the Mutator re-asserts the token on every call, so a Runtime retained
// across Release stops working exactly like a retained Mutator does.
type Runtime struct {
	h famlock.Held
	c *engine.Client
	m *engine.Mutator
}

// New builds the facade. It returns an error because it constructs the Mutator, whose
// NewMutator asserts the lock and can refuse.
func New(h famlock.Held, c *engine.Client) (*Runtime, error) {
	m, err := engine.NewMutator(h, c)
	if err != nil {
		return nil, err
	}
	return &Runtime{h: h, c: c, m: m}, nil
}

func (r *Runtime) assert() error { return famlock.Assert(r.h, "drive the container runtime") }

func (r *Runtime) home() (string, error) { return famlock.HomeOf(r.h) }

// Client is the read side, for callers holding a Runtime that also need to inspect.
func (r *Runtime) Client() *engine.Client { return r.c }

// --- thin mutation delegates -----------------------------------------------------------------
// Every mutating engine operation, surfaced as a facade method so verbs, probes and data
// movement never hold a Mutator of their own. The engine layer validates arguments and
// asserts the lock; these add no policy of their own.

func (r *Runtime) ContainerStart(ctx context.Context, id string) error {
	return r.m.ContainerStart(ctx, id)
}

func (r *Runtime) ContainerStop(ctx context.Context, id string) error {
	return r.m.ContainerStop(ctx, id)
}

func (r *Runtime) ContainerRemove(ctx context.Context, id string) error {
	return r.m.ContainerRemove(ctx, id)
}

func (r *Runtime) VolumeCreate(ctx context.Context, name string, prov engine.Provenance) error {
	return r.m.VolumeCreate(ctx, name, prov)
}

func (r *Runtime) VolumeRemove(ctx context.Context, name string) error {
	return r.m.VolumeRemove(ctx, name)
}

func (r *Runtime) NetworkCreate(ctx context.Context, name string, prov engine.Provenance) (string, error) {
	return r.m.NetworkCreate(ctx, name, prov)
}

func (r *Runtime) NetworkRemove(ctx context.Context, ref string) error {
	return r.m.NetworkRemove(ctx, ref)
}

func (r *Runtime) NetworkConnect(ctx context.Context, networkID, containerID, alias string, gwPriority int) error {
	return r.m.NetworkConnect(ctx, networkID, containerID, alias, gwPriority)
}

func (r *Runtime) NetworkDisconnect(ctx context.Context, networkID, containerID string) error {
	return r.m.NetworkDisconnect(ctx, networkID, containerID)
}

func (r *Runtime) ImagePull(ctx context.Context, refWithDigest string) error {
	return r.m.ImagePull(ctx, refWithDigest)
}

// HelperRun is the facade's helper door — probes and volume copies launch their pinned
// helpers through here, which is why probe runs require the lock, exactly as the reference's
// probe arm does under its verbs.
func (r *Runtime) HelperRun(ctx context.Context, h engine.HelperSpec) (int64, []byte, error) {
	return r.m.HelperRun(ctx, h)
}

// LaunchConfig carries what a launch varies beyond the authenticated documents: the
// installation identity and the per-object nonce (§6a's WHOSE and WHICH), the family network,
// the per-key bootstrap secrets the verb layer selected (§4.3 — they ride the request body,
// never argv), and any host-port overrides the operator configured.
type LaunchConfig struct {
	Identity  string
	Nonce     string
	NetworkID string
	// Generation, when non-empty, is recorded as the generation label.
	Generation string
	// Env is KEY=value bootstrap secrets — per-key and explicit, exactly the keys the
	// product's manifest declares, never the whole family file.
	Env []string
	// HostPorts maps a declared container port to the host port to publish it at; a declared
	// port with no entry publishes at its own number. The host IP is not here and not
	// anywhere: the engine serializer emits 127.0.0.1 unconditionally.
	HostPorts map[uint16]uint16
}

// LaunchProduct is THE ONE CALL SITE THAT CREATES PRODUCT CONTAINERS (check.sh's sole-launch
// gate enforces that on every commit, not only at cutover). The ContainerSpec is assembled
// INSIDE the facade from the authenticated manifest + policy — a Launch(spec) that accepted a
// pre-built spec would let a caller assemble valid-looking mounts around MountsFor.
//
// The container is created STOPPED, attached to the target network AT CREATION with the
// product's family alias (D42 step 1) — the verify/start/verify-live protocol around it is
// the bring-up layer's, which calls back down through the facade's other methods.
func (r *Runtime) LaunchProduct(ctx context.Context, m *manifest.Manifest, p *policy.Policy, cfg LaunchConfig) (string, error) {
	if err := r.assert(); err != nil {
		return "", err
	}
	// The manifest must be inside its policy envelope — every violation reported, before
	// anything is derived from either.
	if err := manifest.Check(m, p); err != nil {
		return "", err
	}
	product := m.Product()
	name, err := manifest.ContainerName(cfg.Identity, product)
	if err != nil {
		return "", err
	}
	alias, err := manifest.Alias(product)
	if err != nil {
		return "", err
	}
	raw, bound, err := r.mountsFor(m, p)
	if err != nil {
		return "", err
	}
	// Every role the operator did not bind rides its NAMED VOLUME (D6: storage defaults to
	// named volumes), at the target the manifest places it.
	seen := map[string]bool{}
	for _, v := range m.Volumes() {
		if seen[v.Role] || bound[v.Role] {
			seen[v.Role] = true
			continue
		}
		seen[v.Role] = true
		volName, verr := manifest.VolumeName(cfg.Identity, product, v.Role)
		if verr != nil {
			return "", verr
		}
		target, terr := RoleTarget(m, v.Role)
		if terr != nil {
			return "", terr
		}
		raw = append(raw, rawMount{volume: true, source: volName, target: target})
	}
	mounts, err := buildMounts(raw)
	if err != nil {
		return "", err
	}

	var ports []engine.PortPublish
	for _, cp := range m.Ports() {
		hp := cfg.HostPorts[cp]
		if hp == 0 {
			hp = cp
		}
		pub, perr := engine.NewPortPublish(cp, hp)
		if perr != nil {
			return "", perr
		}
		ports = append(ports, pub)
	}

	labels := map[string]string{
		"installation": cfg.Identity,
		"nonce":        cfg.Nonce,
		"product":      product,
	}
	if cfg.Generation != "" {
		labels["generation"] = cfg.Generation
	}
	attach, err := engine.NewNetworkAttach(cfg.NetworkID, alias)
	if err != nil {
		return "", err
	}
	spec, err := engine.NewContainerSpec(name, m.Image(), engine.SpecOpts{
		Network: attach,
		Labels:  labels,
		Env:     cfg.Env,
		Mounts:  mounts,
		Ports:   ports,
	})
	if err != nil {
		return "", err
	}
	id, err := r.m.ContainerCreate(ctx, spec)
	if err != nil {
		return "", fmt.Errorf("runtime: creating %q: %w", name, err)
	}
	return id, nil
}
