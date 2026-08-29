// Package engine is the ONLY place mythical-ctl speaks to the container runtime.
//
// Two invariants live here rather than at the call sites, because a rule every caller must
// remember is a rule that gets forgotten once (the reference adapter states both and this port
// keeps them):
//
//   - NO CALLER CAN EXPRESS AN UNSAFE LAUNCH. Every wire struct in this file has unexported
//     fields and is constructible ONLY through a validating constructor, so a caller cannot
//     hand-assemble a spec that skips a rule. The publish serializer emits the 127.0.0.1 host
//     IP unconditionally (D26/§4b.1) — there is no HostIP parameter to misuse; the network
//     modes `host`, `none` and `container:<id>` are refused at the one place an attachment is
//     named (D26/§4b.2, D42); mounts are typed, with the path rules applied in the
//     constructor. (The bash adapter also closed Docker's comma-separated `--mount` option
//     grammar; on the HTTP API a mount is a JSON object per field, so that class is
//     structurally dead — the path rules are what still carry.)
//   - NO CALLER CAN REACH A MUTATION WITHOUT THE FAMILY LOCK. Every mutating method lives on
//     Mutator (client.go), which stores the famlock token and asserts it before EVERY request.
//
// The transport endpoint is resolved by ResolveEndpoint (endpoint.go) and is deliberately not
// otherwise configurable: an env override consulted here would be a way to point the CLI's
// requests — argv, mounts, secrets — at an arbitrary listener. Tests dial their per-test fake
// socket explicitly.
package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/volatile"
)

// LabelNS is the label namespace every object this installer creates is marked with. Also
// spelled literally in tests, as the reference adapter spells it in its templates.
const LabelNS = "mythicalos."

// APIVersion is the floor Engine API version every request is issued at. NOT v1.44:
// NetworkConnect must carry GwPriority, which the Engine API added in v1.48 — the
// net-migration phases depend on the source network staying the default route while the
// target is attached at LOWER priority, so gw-priority is a required argument, not a default
// (re-verified against a real daemon in the acceptance lane).
const APIVersion = "v1.48"

// ErrAbsent — the object does not exist (a 404 from a daemon that is answering). The rc-3
// analogue: "the object is gone" authorizes reconciliation.
var ErrAbsent = errors.New("no such object")

// ErrDaemonDown — the daemon could not be reached at all (a transport failure). The rc-1
// analogue: "the question could not be asked" authorizes NOTHING. The bash adapter had to
// disambiguate a failed inspect by asking `version` afterwards; on the HTTP API the two are
// distinct at the source — a 404 is an answer, a refused connection is not — so the split is
// made where the failure happens rather than re-derived.
var ErrDaemonDown = errors.New("the container runtime did not answer")

// argOK ports the reference's argument hygiene: a control byte in a value that reaches the
// runtime is either a bug or an injection attempt — it can forge a field in a label and no
// legitimate name, digest, alias or port contains one. Bytes 0x00–0x1F and 0x7F, the C-locale
// [[:cntrl:]] set the reference pins.
func argOK(v string) bool {
	if v == "" || len(v) > 4096 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7F {
			return false
		}
	}
	return true
}

// pathOK: a bind SOURCE or mount TARGET — absolute and `..`-free, on top of argOK. `what`
// names the field in the refusal so the operator is told which component was rejected.
func pathOK(p, what string) error {
	if !argOK(p) {
		return fmt.Errorf("engine: %s is empty, over-long, or contains a control byte", what)
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("engine: %s %q is not absolute", what, p)
	}
	for _, comp := range strings.Split(p, "/") {
		if comp == ".." {
			return fmt.Errorf("engine: %s %q contains a .. component", what, p)
		}
	}
	return nil
}

// volumeNameOK: a volume SOURCE is a NAME, not a path. A `/`-leading "name" is a bind mount
// wearing the volume spec's clothes, and the whole point of the two constructors is that the
// caller cannot choose which one it gets.
func volumeNameOK(n string) error {
	if strings.HasPrefix(n, "/") {
		return fmt.Errorf("engine: %q is an absolute path, not a volume name", n)
	}
	if !argOK(n) {
		return errors.New("engine: volume name is empty, over-long, or contains a control byte")
	}
	return nil
}

// Mount is one container mount — a host bind or a named volume, at a target, read-only or
// not. Constructible only below; there is no options field and no propagation field on the
// type, so `bind-propagation=rshared` and friends are inexpressible.
type Mount struct {
	typ      string // "bind" | "volume" | "tmpfs"
	source   string // host path (bind) or volume name (volume); empty for tmpfs — RAM has no source
	target   string
	readOnly bool
	// opts is the tmpfs kernel option string, and is set ONLY by NewTmpfsMount, ONLY to the
	// frozen set. It exists as a field rather than being fetched at serialization time so that
	// what the constructor validated is literally what the serializer emits — and so that
	// NewContainerSpec can re-check it, exactly as it re-checks the `ok` bit below, against a
	// Mount hand-assembled INSIDE this package where the constructors can be bypassed.
	opts string
	// ok is set ONLY by the constructors below. A zero-value Mount is constructible anywhere
	// (`var m engine.Mount`), and without this bit NewContainerSpec/NewHelperSpec could not
	// tell it from a validated one — the serializer would then emit an empty mount, which is a
	// wire value that never passed a constructor. Every sealed request type carries the same
	// bit for the same reason.
	ok bool
	// helper marks the five-word helper vocabulary. A helper spec accepts ONLY helper mounts
	// (the general NewBindMount would otherwise put an arbitrary writable host tree in a
	// helper, exactly what the closed vocabulary exists to forbid); a product spec accepts
	// only NON-helper mounts (the read-only volume variants are helper-only by design).
	helper bool
}

// NewBindMount validates a host-path bind. The doc-of-record reason binds are expressed as
// typed mounts (not `-v`): the daemon REFUSES a bind whose source does not exist, where `-v`
// silently creates a directory — which is how a single-file bind stops being the file the
// product writes (§4.1a). The refusal itself is the daemon's; the path rules are ours.
func NewBindMount(source, target string, readOnly bool) (Mount, error) {
	if err := pathOK(source, "bind source"); err != nil {
		return Mount{}, err
	}
	if err := pathOK(target, "mount target"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: source, target: target, readOnly: readOnly, ok: true}, nil
}

// NewVolumeMount validates a named-volume mount. Product volume mounts are read-write; the
// read-only variants exist only in the closed helper vocabulary below, which is the one place
// the reference grants them.
func NewVolumeMount(volumeName, target string) (Mount, error) {
	if err := volumeNameOK(volumeName); err != nil {
		return Mount{}, err
	}
	if err := pathOK(target, "mount target"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "volume", source: volumeName, target: target, readOnly: false, ok: true}, nil
}

// NewTmpfsMount validates the credential-home mount: a NON-PERSISTENT, RAM-backed tmpfs at a
// bounded absolute container path, carrying the frozen hardening.
//
// A TMPFS, NOT A TYPED MOUNT, AND THE DIFFERENCE IS THE WHOLE POINT. A tmpfs is the one mount
// form that carries the kernel security flags; a Mounts entry has nowhere to put nodev, nosuid or
// noexec, so the same mount expressed that way would exist with its hardening SILENTLY ABSENT —
// no error, no missing mount, just a credential home that permits device nodes, setuid binaries
// and execution. It is also why the mount is not a named volume: a tmpfs is disposable by
// construction, so removing the container discards it and its contents, and no backup or removal
// sweep can enumerate it because there is no volume to find.
//
// There is NO options parameter. The hardening is not the caller's to choose — the target is the
// only thing that varies, which is exactly the closure the manifest field's bare-path grammar
// exists to guarantee, carried through to the launch site.
func NewTmpfsMount(target string) (Mount, error) {
	// The wire's own grammar, not the looser pathOK above: the credential-home mount point is a
	// bounded safe-segment path, and this is the launch-site half of the same rule the manifest
	// door applies. Called, never restated, so the two cannot drift into accepting different
	// paths.
	if !volatile.PathOK(target) {
		return Mount{}, fmt.Errorf("engine: tmpfs mount point %q is not a bounded absolute container path", target)
	}
	return Mount{typ: "tmpfs", target: target, opts: volatile.TmpfsSecOpts(), ok: true}, nil
}

// The closed helper-mount vocabulary (D49/D54/D59). The reference adapter's helper arm takes
// five spec kinds and nothing else — each pins its target AND its writability, so a caller
// cannot mount the source writable or stage anywhere but /dst. These are the same five, as
// constructors. STAGING IS THE ONLY WRITABLE HOST MOUNT; the source volume is read-only
// because a bug or a hostile payload that mutates the source destroys the original before the
// copy is verified (D54); the reverse pair (D59 restore) is a read-only host bind at /src and
// a writable VOLUME at /dst.

// NewHelperSrcVolume — the volume being preserved, read-only at /src.
func NewHelperSrcVolume(volumeName string) (Mount, error) {
	if err := volumeNameOK(volumeName); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "volume", source: volumeName, target: "/src", readOnly: true, ok: true, helper: true}, nil
}

// NewHelperStaging — the staging tree being filled, the only writable host mount, at /dst.
func NewHelperStaging(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper staging source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/dst", readOnly: false, ok: true, helper: true}, nil
}

// NewHelperDstRO — a host tree the helper only verifies, read-only at /dst.
func NewHelperDstRO(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper read-only source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/dst", readOnly: true, ok: true, helper: true}, nil
}

// NewHelperSrcBind — a backup's untrusted host tree being restored FROM, read-only at /src.
func NewHelperSrcBind(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper read-only bind source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/src", readOnly: true, ok: true, helper: true}, nil
}

// NewHelperDstVolume — the fresh volume being filled, writable at /dst.
func NewHelperDstVolume(volumeName string) (Mount, error) {
	if err := volumeNameOK(volumeName); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "volume", source: volumeName, target: "/dst", readOnly: false, ok: true, helper: true}, nil
}

// PortPublish is one published port. THE loopback wall (D26/§4b.1): there is NO HostIP
// parameter and no field — the serializer emits 127.0.0.1 unconditionally, so a caller that
// wanted 0.0.0.0 has no way to say it.
type PortPublish struct {
	containerPort uint16
	hostPort      uint16
	ok            bool // constructor-set; see Mount.ok
}

// NewPortPublish refuses only the port the uint16 type cannot: zero. The reference's
// digit-string and range checks are what the parameter TYPE now carries.
func NewPortPublish(containerPort, hostPort uint16) (PortPublish, error) {
	if containerPort == 0 || hostPort == 0 {
		return PortPublish{}, errors.New("engine: port 0 is not a publishable port")
	}
	return PortPublish{containerPort: containerPort, hostPort: hostPort, ok: true}, nil
}

// NetworkAttach names the ONE network a container is created attached to, and the aliases it
// registers there. Created attached, not bare-created-then-connected: Docker attaches the
// default bridge when no network is named, and connecting the family network afterwards
// leaves the container on BOTH — quietly breaking the isolation §4b.4 depends on while every
// "is it attached to our network?" check still passes (D42 step 1).
type NetworkAttach struct {
	network string
	aliases []string
	ok      bool // constructor-set; see Mount.ok
}

// netmodeOK ports the reference's refusal of the three modes no product container may ever
// use (D26/§4b.2, D42): `host` shares the host's network namespace outright,
// `container:<name>` joins another container's, and `none` cannot later be connected to any
// network at all (the daemon refuses, so a container created that way can never join the
// family network). Refused HERE, at the type, so no call site can omit the check.
func netmodeOK(network string) error {
	if network == "host" || network == "none" || strings.HasPrefix(network, "container:") {
		return fmt.Errorf("engine: network mode %q is rejected by design (D26/D42) — the family network is a user-defined bridge", network)
	}
	if !argOK(network) {
		return errors.New("engine: network reference is empty, over-long, or contains a control byte")
	}
	return nil
}

// NewNetworkAttach validates the network reference and every alias. The alias is REQUIRED at
// the call sites that launch products (§6b.2): the daemon infers no alias, and without one
// the container joins under its own installation-scoped name, which no sibling can guess —
// family DNS then fails silently, indistinguishable from an absent peer (§9). The type takes
// a list so the runtime facade can state exactly one.
func NewNetworkAttach(network string, aliases ...string) (NetworkAttach, error) {
	if err := netmodeOK(network); err != nil {
		return NetworkAttach{}, err
	}
	for _, a := range aliases {
		if !argOK(a) {
			return NetworkAttach{}, errors.New("engine: invalid network alias")
		}
	}
	return NetworkAttach{network: network, aliases: append([]string(nil), aliases...), ok: true}, nil
}

// Provenance is the closed label pair every resource this installer creates carries: WHOSE
// (the installation identity) and WHICH (the nonce). There is no raw label map on volume or
// network creation — absent or arbitrary provenance labels are inexpressible there exactly as
// they are on containers. A nonce says WHICH object, never WHOSE; the installation label is
// the only evidence an object is ours (§6a), which is why the pair is one type.
type Provenance struct {
	installation string
	nonce        string
	ok           bool // constructor-set; see Mount.ok
}

// NewProvenance validates both halves.
func NewProvenance(installation, nonce string) (Provenance, error) {
	if !argOK(installation) {
		return Provenance{}, errors.New("engine: invalid installation identity")
	}
	if !argOK(nonce) {
		return Provenance{}, errors.New("engine: invalid nonce")
	}
	return Provenance{installation: installation, nonce: nonce, ok: true}, nil
}

func (p Provenance) labels() map[string]string {
	return map[string]string{
		LabelNS + "installation": p.installation,
		LabelNS + "nonce":        p.nonce,
	}
}

// containerLabelKeys is the closed label-key set the reference adapter's create arm permits.
// `generation` is create-only vocabulary; the list surfaces (labelKeys, client.go) have their
// own, smaller closed set, exactly as the reference splits them.
var containerLabelKeys = map[string]bool{
	"installation": true, "nonce": true, "product": true, "role": true, "generation": true,
}

// SpecOpts carries everything a container creation may vary. Secrets ride Env in the request
// body over the unix socket — never argv, never a temp file. This supersedes the reference's
// `--env-file` vehicle and is equivalent on the property that vehicle existed for: argv is
// world-readable through `ps` on the host, and an env file was the way to keep secrets out of
// it; a request body on the daemon's local socket is visible only to the daemon.
type SpecOpts struct {
	Network NetworkAttach     // required — see NewNetworkAttach
	Labels  map[string]string // closed key set; values validated
	Env     []string          // KEY=value pairs, validated below
	Mounts  []Mount
	Ports   []PortPublish
}

// ContainerSpec is a validated product-container creation. Constructible only through
// NewContainerSpec; network MODE is not expressible (no host/none/container: — the D26/D42
// wall stays a type property), labels only from the closed set, ports only via the
// loopback-only serializer.
type ContainerSpec struct {
	name   string
	image  string
	attach NetworkAttach
	labels map[string]string
	env    []string
	mounts []Mount
	ports  []PortPublish
}

// NewContainerSpec validates the whole shape. An arbitrary label key is a constructor error,
// so provenance labels cannot be forged; a spec with no network is a constructor error, so a
// default-bridge attachment cannot happen by omission.
func NewContainerSpec(name, imageRef string, opts SpecOpts) (ContainerSpec, error) {
	if !argOK(name) {
		return ContainerSpec{}, errors.New("engine: invalid container name")
	}
	if !argOK(imageRef) {
		return ContainerSpec{}, errors.New("engine: invalid image reference")
	}
	if !opts.Network.ok {
		return ContainerSpec{}, errors.New("engine: a container spec must name its network attachment via NewNetworkAttach (a bare create would join the default bridge)")
	}
	labels := map[string]string{}
	for k, v := range opts.Labels {
		if !containerLabelKeys[k] {
			return ContainerSpec{}, fmt.Errorf("engine: %q is not a label this installer sets", k)
		}
		if !argOK(v) {
			return ContainerSpec{}, fmt.Errorf("engine: invalid value for label %q", k)
		}
		labels[LabelNS+k] = v
	}
	for _, e := range opts.Env {
		key, _, found := strings.Cut(e, "=")
		if !found || key == "" || !argOK(e) {
			return ContainerSpec{}, errors.New("engine: env entries must be KEY=value with no control bytes")
		}
	}
	// Nested values are re-checked for their constructor bit: a zero-value Mount or
	// PortPublish is constructible anywhere, and copying it through would let a wire value
	// reach the daemon that no constructor validated.
	for _, mt := range opts.Mounts {
		if !mt.ok {
			return ContainerSpec{}, errors.New("engine: a zero-value Mount — use NewBindMount or NewVolumeMount")
		}
		if mt.helper {
			return ContainerSpec{}, errors.New("engine: a helper-vocabulary mount is not a product mount (product volume mounts are read-write and target where the manifest says)")
		}
		// THE HARDENING IS RE-CHECKED, for the same reason the `ok` bit is: a Mount assembled
		// inside this package bypasses the constructors, and a tmpfs whose options were anything
		// but the frozen set would be a weaker mount reaching the daemon under the credential
		// home's name. Fail-closed — refused, never downgraded.
		if mt.typ == "tmpfs" && !volatile.SecOptsOK(mt.opts) {
			return ContainerSpec{}, fmt.Errorf("engine: a tmpfs mount carrying %q is not the frozen credential-home hardening — use NewTmpfsMount", mt.opts)
		}
	}
	for _, p := range opts.Ports {
		if !p.ok {
			return ContainerSpec{}, errors.New("engine: a zero-value PortPublish — use NewPortPublish")
		}
	}
	return ContainerSpec{
		name:   name,
		image:  imageRef,
		attach: opts.Network,
		labels: labels,
		env:    append([]string(nil), opts.Env...),
		mounts: append([]Mount(nil), opts.Mounts...),
		ports:  append([]PortPublish(nil), opts.Ports...),
	}, nil
}

// HelperCommand is the closed command word set (D49): a helper that took instructions would
// be an execution primitive, so the command is chosen from this fixed vocabulary and the
// client passes nothing else as the argv head.
type HelperCommand string

const (
	HelperResolve   HelperCommand = "resolve"
	HelperSelfcheck HelperCommand = "selfcheck"
	HelperEgress    HelperCommand = "egress"
	HelperPreflight HelperCommand = "preflight"
	HelperCopy      HelperCommand = "copy"
	HelperVerify    HelperCommand = "verify"
	HelperACL       HelperCommand = "acl"
	HelperAccess    HelperCommand = "access"
)

var helperCommands = map[HelperCommand]bool{
	HelperResolve: true, HelperSelfcheck: true, HelperEgress: true, HelperPreflight: true,
	HelperCopy: true, HelperVerify: true, HelperACL: true, HelperAccess: true,
}

// HelperOpts carries the knobs the reference helper arm actually has — including which it
// deliberately lacks: no ports, no free-form argv, no generic mount, no env.
type HelperOpts struct {
	// Network is the network ID the helper joins, or "" for private (`none`) mode — the copy
	// container's mode (D54, the one legitimate use of `none` in the design: the copy never
	// joins a network). The probe passes the family network.
	Network string
	// Alias is the helper's own per-run DNS name on Network (D49's selfcheck resolves the
	// name it was registered under). A constructor error without a network: a container in
	// private mode has no resolver for a name to be registered with, and refusing here means
	// no caller can build that call at all.
	Alias string
	// RunAs is a numeric uid, or "" to keep the image's user (D58's effective-access check
	// runs AS the product's runtime uid).
	RunAs string
	// Args are arguments to the CLOSED command word, INSIDE the container — never daemon
	// flags. Every value passed this way is a container-internal path or an alias this code
	// computed.
	Args []string
	// Stdin, when non-empty, is handed to the helper on its stdin — restore's per-entry
	// manifest verify reads the manifest there rather than from a THIRD host mount.
	Stdin []byte
	// Mounts must ALL come from the five-word helper vocabulary (NewHelperSrcVolume,
	// NewHelperStaging, NewHelperDstRO, NewHelperSrcBind, NewHelperDstVolume) — NewHelperSpec
	// refuses a general NewBindMount/NewVolumeMount here, because the vocabulary's whole point
	// is that a helper cannot be handed an arbitrary writable host tree.
	Mounts []Mount
}

// HelperSpec is a validated helper launch (D49/D54): digest-pinned image, closed command,
// provenance labels, a name the caller's own record can speak for. No helper outlives its own
// invocation — HelperRun enforces that; see its doc.
type HelperSpec struct {
	image string
	name  string
	cmd   HelperCommand
	prov  Provenance
	opts  HelperOpts
}

// NewHelperSpec validates the whole shape. The name and provenance are REQUIRED: a helper
// carrying only a nonce is anonymous — a nonce says WHICH object, never WHOSE — so a leaked
// one could never be shown to be ours and nothing would be authorized to remove it (§6a/§6b).
func NewHelperSpec(image, name string, cmd HelperCommand, prov Provenance, opts HelperOpts) (HelperSpec, error) {
	if !argOK(image) {
		return HelperSpec{}, errors.New("engine: invalid image reference")
	}
	if !argOK(name) {
		return HelperSpec{}, errors.New("engine: invalid helper container name")
	}
	if !helperCommands[cmd] {
		return HelperSpec{}, fmt.Errorf("engine: %q is not a helper command", cmd)
	}
	if !prov.ok {
		return HelperSpec{}, errors.New("engine: a helper needs provenance (installation + nonce) from NewProvenance")
	}
	if opts.Network != "" {
		if err := netmodeOK(opts.Network); err != nil {
			return HelperSpec{}, err
		}
	}
	if opts.Alias != "" {
		if opts.Network == "" {
			return HelperSpec{}, errors.New("engine: a network alias cannot be registered on a helper with no network")
		}
		if !argOK(opts.Alias) {
			return HelperSpec{}, errors.New("engine: invalid helper network alias")
		}
	}
	if opts.RunAs != "" {
		// The reference's rule is digits-only (`*[!0-9]*` refused) with no length cap; the
		// ceiling is the manifest's own `runtime_uid` type, int:0:4294967295 — the only source
		// of a RunAs value — so a 32-bit uid is accepted in full and 2^32 is refused.
		for i := 0; i < len(opts.RunAs); i++ {
			if opts.RunAs[i] < '0' || opts.RunAs[i] > '9' {
				return HelperSpec{}, errors.New("engine: helper uid must be numeric")
			}
		}
		if _, perr := strconv.ParseUint(opts.RunAs, 10, 32); perr != nil {
			return HelperSpec{}, errors.New("engine: helper uid out of range (0..4294967295)")
		}
	}
	for _, a := range opts.Args {
		if !argOK(a) {
			return HelperSpec{}, errors.New("engine: invalid helper argument")
		}
	}
	// THE CLOSED VOCABULARY IS ENFORCED HERE, not merely offered: a mount that did not come
	// from one of the five helper constructors — a general bind, a general volume, or a
	// zero value — is refused, so no helper can be handed a mount whose target or writability
	// the vocabulary did not pin.
	for _, mt := range opts.Mounts {
		if !mt.ok || !mt.helper {
			return HelperSpec{}, errors.New("engine: helper mounts come only from the closed vocabulary (NewHelperSrcVolume, NewHelperStaging, NewHelperDstRO, NewHelperSrcBind, NewHelperDstVolume)")
		}
	}
	o := opts
	o.Args = append([]string(nil), opts.Args...)
	o.Mounts = append([]Mount(nil), opts.Mounts...)
	o.Stdin = append([]byte(nil), opts.Stdin...)
	return HelperSpec{image: image, name: name, cmd: cmd, prov: prov, opts: o}, nil
}

// --- read-side result types ------------------------------------------------------------------
// These are RESPONSES — data the daemon reported — so their fields are exported; the
// unexported-fields rule above is about REQUESTS, where construction is the security boundary.

// DaemonInfo is the typed subset of `/info` the preflight consumes.
type DaemonInfo struct {
	ServerVersion   string
	SecurityOptions []string
}

// NetEndpoint is one network attachment as the daemon reports it. A container that has NEVER
// started reports an EMPTY NetworkID (the endpoint id is assigned at first start, then
// persists across stop — the 2026-08-04 real-daemon lesson); the map KEY in
// ContainerInfo.Networks is the network NAME, present from creation, which is why the
// name-keyed map is the shape callers get. A STOPPED container has an empty IPAddress —
// Docker releases the address (D48).
type NetEndpoint struct {
	NetworkID  string
	IPAddress  string
	Aliases    []string
	GwPriority int
}

// MountRecord is one mount as the daemon reports it.
type MountRecord struct {
	Type        string // "bind" | "volume"
	Name        string // volume name, "" for binds
	Source      string
	Destination string
	RW          bool
}

// PortBinding is one published port as the daemon reports it. HostIP is reported so a caller
// can ASSERT the loopback wall, not so one could choose it.
type PortBinding struct {
	ContainerPort string // "7480/tcp"
	HostIP        string
	HostPort      string
}

// ContainerInfo is the typed inspect subset, replacing the reference's closed Go-template map.
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	Running bool
	Status  string // "created" | "running" | "exited"
	Labels  map[string]string
	// Env is the container's environment as the daemon reports it — the injected bootstrap
	// secrets INCLUDED (visible in `docker inspect`, the documented and accepted exposure of
	// §4.3): exposed so a test can assert the injected set is EXACTLY the declared keys.
	Env      []string
	Networks map[string]NetEndpoint // keyed by network NAME (the inspect map key)
	Mounts   []MountRecord
	Ports    []PortBinding
	// Tmpfs is HostConfig.Tmpfs — the tmpfs mount points and their kernel option strings, keyed
	// by mount point. Mounts above does NOT carry those flags, so this is the only surface on
	// which a mount's hardening is verifiable at all: without it "the mount is present" and "the
	// mount is hardened" are indistinguishable.
	Tmpfs map[string]string
}

// VolumeInfo is the typed volume-inspect subset.
type VolumeInfo struct {
	Name   string
	Driver string
	Labels map[string]string
}

// NetworkInfo is the typed network-inspect subset. Options is where Docker keeps
// `com.docker.network.bridge.trusted_host_interfaces`, which the preflight refuses on
// (§4b.2/§10a).
type NetworkInfo struct {
	ID      string
	Name    string
	Driver  string
	Labels  map[string]string
	Options map[string]string
}

// ImageInfo is the typed image-inspect subset.
type ImageInfo struct {
	ID          string
	RepoDigests []string
}

// ContainerSummary is one row of a label-filtered listing.
type ContainerSummary struct {
	ID     string
	Names  []string
	State  string
	Labels map[string]string
}

// VolumeSummary is one row of a label-filtered volume listing.
type VolumeSummary struct {
	Name   string
	Labels map[string]string
}

// NetworkSummary is one row of a label-filtered network listing.
type NetworkSummary struct {
	ID     string
	Name   string
	Labels map[string]string
}
