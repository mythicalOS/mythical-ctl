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
	"strings"
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
	typ      string // "bind" | "volume"
	source   string // host path (bind) or volume name (volume)
	target   string
	readOnly bool
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
	return Mount{typ: "bind", source: source, target: target, readOnly: readOnly}, nil
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
	return Mount{typ: "volume", source: volumeName, target: target, readOnly: false}, nil
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
	return Mount{typ: "volume", source: volumeName, target: "/src", readOnly: true}, nil
}

// NewHelperStaging — the staging tree being filled, the only writable host mount, at /dst.
func NewHelperStaging(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper staging source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/dst", readOnly: false}, nil
}

// NewHelperDstRO — a host tree the helper only verifies, read-only at /dst.
func NewHelperDstRO(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper read-only source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/dst", readOnly: true}, nil
}

// NewHelperSrcBind — a backup's untrusted host tree being restored FROM, read-only at /src.
func NewHelperSrcBind(hostPath string) (Mount, error) {
	if err := pathOK(hostPath, "helper read-only bind source"); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "bind", source: hostPath, target: "/src", readOnly: true}, nil
}

// NewHelperDstVolume — the fresh volume being filled, writable at /dst.
func NewHelperDstVolume(volumeName string) (Mount, error) {
	if err := volumeNameOK(volumeName); err != nil {
		return Mount{}, err
	}
	return Mount{typ: "volume", source: volumeName, target: "/dst", readOnly: false}, nil
}

// PortPublish is one published port. THE loopback wall (D26/§4b.1): there is NO HostIP
// parameter and no field — the serializer emits 127.0.0.1 unconditionally, so a caller that
// wanted 0.0.0.0 has no way to say it.
type PortPublish struct {
	containerPort uint16
	hostPort      uint16
}

// NewPortPublish refuses only the port the uint16 type cannot: zero. The reference's
// digit-string and range checks are what the parameter TYPE now carries.
func NewPortPublish(containerPort, hostPort uint16) (PortPublish, error) {
	if containerPort == 0 || hostPort == 0 {
		return PortPublish{}, errors.New("engine: port 0 is not a publishable port")
	}
	return PortPublish{containerPort: containerPort, hostPort: hostPort}, nil
}

// NetworkAttach names the ONE network a container is created attached to, and the aliases it
// registers there. Created attached, not bare-created-then-connected: Docker attaches the
// default bridge when no network is named, and connecting the family network afterwards
// leaves the container on BOTH — quietly breaking the isolation §4b.4 depends on while every
// "is it attached to our network?" check still passes (D42 step 1).
type NetworkAttach struct {
	network string
	aliases []string
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
	return NetworkAttach{network: network, aliases: append([]string(nil), aliases...)}, nil
}

// Provenance is the closed label pair every resource this installer creates carries: WHOSE
// (the installation identity) and WHICH (the nonce). There is no raw label map on volume or
// network creation — absent or arbitrary provenance labels are inexpressible there exactly as
// they are on containers. A nonce says WHICH object, never WHOSE; the installation label is
// the only evidence an object is ours (§6a), which is why the pair is one type.
type Provenance struct {
	installation string
	nonce        string
}

// NewProvenance validates both halves.
func NewProvenance(installation, nonce string) (Provenance, error) {
	if !argOK(installation) {
		return Provenance{}, errors.New("engine: invalid installation identity")
	}
	if !argOK(nonce) {
		return Provenance{}, errors.New("engine: invalid nonce")
	}
	return Provenance{installation: installation, nonce: nonce}, nil
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
	if opts.Network.network == "" {
		return ContainerSpec{}, errors.New("engine: a container spec must name its network attachment (a bare create would join the default bridge)")
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
	Stdin  []byte
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
	if prov.installation == "" {
		return HelperSpec{}, errors.New("engine: a helper needs provenance (installation + nonce)")
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
		if len(opts.RunAs) > 9 {
			return HelperSpec{}, errors.New("engine: helper uid out of range")
		}
		for i := 0; i < len(opts.RunAs); i++ {
			if opts.RunAs[i] < '0' || opts.RunAs[i] > '9' {
				return HelperSpec{}, errors.New("engine: helper uid must be numeric")
			}
		}
	}
	for _, a := range opts.Args {
		if !argOK(a) {
			return HelperSpec{}, errors.New("engine: invalid helper argument")
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
	ID       string
	Name     string
	Image    string
	Running  bool
	Status   string // "created" | "running" | "exited"
	Labels   map[string]string
	Networks map[string]NetEndpoint // keyed by network NAME (the inspect map key)
	Mounts   []MountRecord
	Ports    []PortBinding
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
