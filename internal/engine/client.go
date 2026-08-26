package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mythicalos.ai/ctl/internal/famlock"
)

// Client is the READ side of the Engine API: everything on it observes and nothing mutates.
// The read/mutate split is a lock boundary — every mutating method lives on Mutator,
// obtainable only through NewMutator with the family lock held. Status must read without the
// lock, exactly as the reference does.
type Client struct {
	socket   string
	http     *http.Client
	authEnv  []string
	authHome string
	hasAuth  bool
}

// Dial builds a client for the daemon socket. Production passes only what ResolveEndpoint
// returned; the test fake passes its per-test socket. There is deliberately no URL form and
// no TLS form — the resolver already refused everything non-local.
func Dial(socketPath string) *Client {
	return &Client{
		socket: socketPath,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// SetDockerConfig hands the client the environment and user home its REGISTRY AUTH resolution
// reads (auth.go) — the same inputs ResolveEndpoint took, so the credentials presented are
// the ones the docker CLI at that config would present. Without it, pulls are anonymous.
func (c *Client) SetDockerConfig(env []string, home string) {
	c.authEnv = append([]string(nil), env...)
	c.authHome = home
	c.hasAuth = true
}

// daemonMessage is the error envelope the daemon answers refusals with.
type daemonMessage struct {
	Message string `json:"message"`
}

// do issues one versioned request. Transport failure wraps ErrDaemonDown — "the question
// could not be asked", which authorizes NOTHING; a 404 wraps ErrAbsent — an ANSWER, from a
// daemon that is up, which is what authorizes reconciliation. The reference had to split the
// two by asking `version` after a failed inspect; HTTP splits them at the source.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := "http://docker/" + APIVersion + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("engine: %w: %v", ErrDaemonDown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		var dm daemonMessage
		_ = json.NewDecoder(resp.Body).Decode(&dm)
		return fmt.Errorf("engine: %w: %s", ErrAbsent, dm.Message)
	}
	if resp.StatusCode >= 300 {
		// The daemon's own words are preserved (§7.3): an operator needs "denied" or "volume
		// is in use", never a generic refusal.
		var dm daemonMessage
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if json.Unmarshal(raw, &dm) != nil || dm.Message == "" {
			dm.Message = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("engine: the daemon refused (%d): %s", resp.StatusCode, dm.Message)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Ping asks whether the daemon answers at all, depending on no object existing.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("engine: %w: %v", ErrDaemonDown, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("engine: %w: ping answered %d", ErrDaemonDown, resp.StatusCode)
	}
	return nil
}

// ServerVersion reports the SERVER's version and API version. The distinction is the pinned
// lesson from the reference harness: `docker version` mixes client and server fields in one
// document, and an adapter reading the client's own version would compare the wrong number in
// the engine-version gate with every test green. The API's /version document is the server's.
func (c *Client) ServerVersion(ctx context.Context) (string, string, error) {
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		return "", "", err
	}
	if v.Version == "" {
		return "", "", errors.New("engine: the daemon reported an empty version")
	}
	return v.Version, v.APIVersion, nil
}

// Info reports the typed daemon-info subset. SecurityOptions is what the rootless preflight
// reads; a daemon that cannot be asked is an error the caller must treat as "could not ask",
// never as "rootful".
func (c *Client) Info(ctx context.Context) (*DaemonInfo, error) {
	var raw struct {
		ServerVersion   string   `json:"ServerVersion"`
		SecurityOptions []string `json:"SecurityOptions"`
	}
	if err := c.do(ctx, http.MethodGet, "/info", nil, nil, &raw); err != nil {
		return nil, err
	}
	return &DaemonInfo{ServerVersion: raw.ServerVersion, SecurityOptions: raw.SecurityOptions}, nil
}

// rawContainerInspect is the wire shape of a container inspect, decoded to the typed subset.
type rawContainerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID  string   `json:"NetworkID"`
			IPAddress  string   `json:"IPAddress"`
			Aliases    []string `json:"Aliases"`
			GwPriority int      `json:"GwPriority"`
		} `json:"Networks"`
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// ContainerInspect reads one container. errors.Is(err, ErrAbsent) is "the object is gone";
// errors.Is(err, ErrDaemonDown) is "the question could not be asked" — the two authorize
// completely different things and are never folded.
func (c *Client) ContainerInspect(ctx context.Context, id string) (*ContainerInfo, error) {
	if !argOK(id) {
		return nil, errors.New("engine: refusing to inspect a name containing a control byte")
	}
	var raw rawContainerInspect
	if err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &raw); err != nil {
		return nil, err
	}
	info := &ContainerInfo{
		ID:      raw.ID,
		Name:    strings.TrimPrefix(raw.Name, "/"),
		Image:   raw.Image,
		Running: raw.State.Running,
		Status:  raw.State.Status,
		Labels:  raw.Config.Labels,
	}
	if len(raw.NetworkSettings.Networks) > 0 {
		info.Networks = map[string]NetEndpoint{}
		for name, ep := range raw.NetworkSettings.Networks {
			info.Networks[name] = NetEndpoint{
				NetworkID:  ep.NetworkID,
				IPAddress:  ep.IPAddress,
				Aliases:    ep.Aliases,
				GwPriority: ep.GwPriority,
			}
		}
	}
	for _, m := range raw.Mounts {
		info.Mounts = append(info.Mounts, MountRecord{
			Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination, RW: m.RW,
		})
	}
	for port, binds := range raw.NetworkSettings.Ports {
		for _, b := range binds {
			info.Ports = append(info.Ports, PortBinding{ContainerPort: port, HostIP: b.HostIP, HostPort: b.HostPort})
		}
	}
	return info, nil
}

// ContainerWait blocks until the container exits and reports its exit code.
func (c *Client) ContainerWait(ctx context.Context, id string) (int64, error) {
	var w struct {
		StatusCode int64 `json:"StatusCode"`
	}
	if err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait", nil, nil, &w); err != nil {
		return 0, err
	}
	return w.StatusCode, nil
}

// ContainerLogs reads a stopped container's output, stdout and stderr SEPARATELY. The daemon
// multiplexes non-TTY output in 8-byte-framed records that carry the stream id; the two are
// kept apart because the reference captured `$(mi_rt_run_helper …)` — STDOUT ONLY — as the
// helper's answer, with stderr passing through to the operator. A merged view would let a
// diagnostic line on stderr satisfy a protocol field on stdout.
func (c *Client) ContainerLogs(ctx context.Context, id string) (stdout, stderr []byte, err error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}}
	u := "http://docker/" + APIVersion + "/containers/" + url.PathEscape(id) + "/logs?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: %w: %v", ErrDaemonDown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("engine: %w", ErrAbsent)
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		return nil, nil, fmt.Errorf("engine: the daemon refused logs (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return demuxLogs(resp.Body)
}

// demuxLogs splits the daemon's framed stream: [stream:1][0 0 0][len:4 BE][payload], where
// stream 1 is stdout and 2 is stderr (0, stdin, is written back on stdout by the daemon and is
// treated as stdout). Any other stream id is a malformed stream, refused rather than guessed.
func demuxLogs(r io.Reader) (stdout, stderr []byte, err error) {
	br := bufio.NewReader(r)
	var out, errOut bytes.Buffer
	var hdr [8]byte
	for {
		if _, rerr := io.ReadFull(br, hdr[:]); rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return out.Bytes(), errOut.Bytes(), nil
			}
			return nil, nil, fmt.Errorf("engine: malformed log stream: %v", rerr)
		}
		dst := &out
		switch hdr[0] {
		case 0, 1:
		case 2:
			dst = &errOut
		default:
			return nil, nil, fmt.Errorf("engine: malformed log stream: unknown stream id %d", hdr[0])
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if _, cerr := io.CopyN(dst, br, int64(n)); cerr != nil {
			return nil, nil, fmt.Errorf("engine: truncated log frame: %v", cerr)
		}
	}
}

// listLabelKeys is the closed key set the reference list surface permits — smaller than the
// container-create set on purpose ("generation" is create-only vocabulary there too).
var listLabelKeys = map[string]bool{"installation": true, "nonce": true, "product": true, "role": true}

func labelFilter(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "", errors.New("engine: a listing needs at least one label to select on — discovery is by label, never by name (§6a)")
	}
	var terms []string
	for k, v := range labels {
		if !listLabelKeys[k] {
			return "", fmt.Errorf("engine: %q is not a label this installer selects on", k)
		}
		if !argOK(v) {
			return "", errors.New("engine: refusing a label filter containing a control byte")
		}
		terms = append(terms, LabelNS+k+"="+v)
	}
	f, err := json.Marshal(map[string][]string{"label": terms})
	if err != nil {
		return "", err
	}
	return string(f), nil
}

// ContainerList lists containers by label — INCLUDING stopped ones, always: without that a
// stopped container is invisible, recovery finds zero matches, reissues, and collides with
// the container it could not see (the reference's `-a` lesson).
func (c *Client) ContainerList(ctx context.Context, labels map[string]string) ([]ContainerSummary, error) {
	f, err := labelFilter(labels)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	q := url.Values{"all": {"1"}, "filters": {f}}
	if err := c.do(ctx, http.MethodGet, "/containers/json", q, nil, &raw); err != nil {
		return nil, err
	}
	var out []ContainerSummary
	for _, r := range raw {
		names := make([]string, 0, len(r.Names))
		for _, n := range r.Names {
			names = append(names, strings.TrimPrefix(n, "/"))
		}
		out = append(out, ContainerSummary{ID: r.ID, Names: names, State: r.State, Labels: r.Labels})
	}
	return out, nil
}

// VolumeList lists volumes by label.
func (c *Client) VolumeList(ctx context.Context, labels map[string]string) ([]VolumeSummary, error) {
	f, err := labelFilter(labels)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Volumes []struct {
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
		} `json:"Volumes"`
	}
	if err := c.do(ctx, http.MethodGet, "/volumes", url.Values{"filters": {f}}, nil, &raw); err != nil {
		return nil, err
	}
	var out []VolumeSummary
	for _, v := range raw.Volumes {
		out = append(out, VolumeSummary{Name: v.Name, Labels: v.Labels})
	}
	return out, nil
}

// NetworkList lists networks by label.
func (c *Client) NetworkList(ctx context.Context, labels map[string]string) ([]NetworkSummary, error) {
	f, err := labelFilter(labels)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID     string            `json:"Id"`
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.do(ctx, http.MethodGet, "/networks", url.Values{"filters": {f}}, nil, &raw); err != nil {
		return nil, err
	}
	var out []NetworkSummary
	for _, n := range raw {
		out = append(out, NetworkSummary{ID: n.ID, Name: n.Name, Labels: n.Labels})
	}
	return out, nil
}

// VolumeInspect reads one volume.
func (c *Client) VolumeInspect(ctx context.Context, name string) (*VolumeInfo, error) {
	if !argOK(name) {
		return nil, errors.New("engine: refusing to inspect a name containing a control byte")
	}
	var raw struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.do(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, nil, &raw); err != nil {
		return nil, err
	}
	return &VolumeInfo{Name: raw.Name, Driver: raw.Driver, Labels: raw.Labels}, nil
}

// NetworkInspect reads one network, by ID or name.
func (c *Client) NetworkInspect(ctx context.Context, ref string) (*NetworkInfo, error) {
	if !argOK(ref) {
		return nil, errors.New("engine: refusing to inspect a name containing a control byte")
	}
	var raw struct {
		ID      string            `json:"Id"`
		Name    string            `json:"Name"`
		Driver  string            `json:"Driver"`
		Labels  map[string]string `json:"Labels"`
		Options map[string]string `json:"Options"`
	}
	if err := c.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(ref), nil, nil, &raw); err != nil {
		return nil, err
	}
	return &NetworkInfo{ID: raw.ID, Name: raw.Name, Driver: raw.Driver, Labels: raw.Labels, Options: raw.Options}, nil
}

// ImageInspect reads one image. errors.Is(err, ErrAbsent) is "not present locally" — the
// present-then-pull split the probe's availability check needs.
func (c *Client) ImageInspect(ctx context.Context, ref string) (*ImageInfo, error) {
	if !argOK(ref) {
		return nil, errors.New("engine: refusing to inspect a reference containing a control byte")
	}
	var raw struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := c.do(ctx, http.MethodGet, "/images/"+url.PathEscape(ref)+"/json", nil, nil, &raw); err != nil {
		return nil, err
	}
	return &ImageInfo{ID: raw.ID, RepoDigests: raw.RepoDigests}, nil
}

// --- the mutation side -----------------------------------------------------------------------

// Mutator carries every method that CHANGES runtime state. It stores the family-lock token
// and EVERY method asserts it before issuing any request: a constructor-only assert would let
// a retained Mutator keep mutating after Release, so the check is per-call, exactly like the
// sealed stores in the ledger layer.
type Mutator struct {
	c *Client
	h famlock.Held
}

// NewMutator is the ONLY way to a Mutator, and check.sh's boundary gate pins its callers to
// the runtime facade — probes, verbs and data movement reach mutations only through there.
func NewMutator(h famlock.Held, c *Client) (*Mutator, error) {
	if err := famlock.Assert(h, "construct an engine mutator"); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("engine: NewMutator needs a client")
	}
	return &Mutator{c: c, h: h}, nil
}

func (m *Mutator) assert() error {
	return famlock.Assert(m.h, "issue an engine mutation")
}

// ContainerCreate creates a product container STOPPED and attached to its target network AT
// CREATION (D42 step 1) — the spec type makes a bare create inexpressible. The one caller is
// the runtime facade's launch path; check.sh's sole-launch gate enforces that every commit.
func (m *Mutator) ContainerCreate(ctx context.Context, spec ContainerSpec) (string, error) {
	if err := m.assert(); err != nil {
		return "", err
	}
	if spec.name == "" {
		return "", errors.New("engine: an empty ContainerSpec — use NewContainerSpec")
	}
	// The attach reference is resolved to the network NAME before the request is built
	// (MEASURED 2026-08-25, Engine 28.4.0/API 1.51): the daemon records a never-started
	// endpoint under WHATEVER STRING keyed EndpointsConfig, and only normalizes to the name
	// at start — so an id-keyed create would leave the pre-start inspect with no name key,
	// which is the one identifier the never-started attach check has. Resolving here also
	// answers an absent network with ErrAbsent before anything is created.
	ni, err := m.c.NetworkInspect(ctx, spec.attach.network)
	if err != nil {
		return "", err
	}
	body := containerCreateBody(spec, ni.Name)
	var resp struct {
		ID string `json:"Id"`
	}
	q := url.Values{"name": {spec.name}}
	if err := m.c.do(ctx, http.MethodPost, "/containers/create", q, body, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// containerCreateBody serializes a validated spec. THE loopback wall lives here: the host IP
// in every port binding is the constant 127.0.0.1 (D26/§4b.1).
func containerCreateBody(spec ContainerSpec, networkName string) map[string]any {
	exposed := map[string]struct{}{}
	bindings := map[string][]map[string]string{}
	for _, p := range spec.ports {
		key := fmt.Sprintf("%d/tcp", p.containerPort)
		exposed[key] = struct{}{}
		bindings[key] = append(bindings[key], map[string]string{
			"HostIp":   "127.0.0.1",
			"HostPort": fmt.Sprintf("%d", p.hostPort),
		})
	}
	mounts := make([]map[string]any, 0, len(spec.mounts))
	for _, mt := range spec.mounts {
		mounts = append(mounts, map[string]any{
			"Type": mt.typ, "Source": mt.source, "Target": mt.target, "ReadOnly": mt.readOnly,
		})
	}
	body := map[string]any{
		"Image":  spec.image,
		"Labels": spec.labels,
		"Env":    spec.env,
		"HostConfig": map[string]any{
			"Mounts":       mounts,
			"PortBindings": bindings,
		},
		"NetworkingConfig": map[string]any{
			"EndpointsConfig": map[string]any{
				networkName: map[string]any{"Aliases": spec.attach.aliases},
			},
		},
	}
	if len(exposed) > 0 {
		body["ExposedPorts"] = exposed
	}
	return body
}

// ContainerStart starts a created or stopped container.
func (m *Mutator) ContainerStart(ctx context.Context, id string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(id) {
		return errors.New("engine: invalid container reference")
	}
	return m.c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// ContainerStop stops a running container.
func (m *Mutator) ContainerStop(ctx context.Context, id string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(id) {
		return errors.New("engine: invalid container reference")
	}
	return m.c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop", nil, nil, nil)
}

// ContainerRemove force-removes, running or not — the reference always passes `-f`, because
// reconciliation must be able to clear a live container.
func (m *Mutator) ContainerRemove(ctx context.Context, id string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(id) {
		return errors.New("engine: invalid container reference")
	}
	return m.c.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), url.Values{"force": {"1"}}, nil, nil)
}

// VolumeCreate creates a labelled volume. THE REAL SEMANTICS THIS PRESERVES (verified against
// a real daemon, reproduced by the fake): create against an EXISTING name SUCCEEDS and does
// NOT apply the new labels — so a create is never evidence of creation, and every caller must
// re-inspect the nonce (D56/§6b).
func (m *Mutator) VolumeCreate(ctx context.Context, name string, prov Provenance) error {
	if err := m.assert(); err != nil {
		return err
	}
	if err := volumeNameOK(name); err != nil {
		return err
	}
	if prov.installation == "" {
		return errors.New("engine: a volume needs provenance — use NewProvenance")
	}
	body := map[string]any{"Name": name, "Labels": prov.labels()}
	return m.c.do(ctx, http.MethodPost, "/volumes/create", nil, body, nil)
}

// VolumeRemove removes a volume. The daemon refuses one a container still mounts.
func (m *Mutator) VolumeRemove(ctx context.Context, name string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if err := volumeNameOK(name); err != nil {
		return err
	}
	return m.c.do(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), nil, nil, nil)
}

// NetworkCreate creates the family network with the NAT-mode bridge driver EXPLICITLY (D29):
// the default is already `bridge`, but relying on a default for a security property means a
// daemon-level default change silently removes the wall. The driver is not a parameter.
func (m *Mutator) NetworkCreate(ctx context.Context, name string, prov Provenance) (string, error) {
	if err := m.assert(); err != nil {
		return "", err
	}
	if !argOK(name) {
		return "", errors.New("engine: invalid network name")
	}
	if prov.installation == "" {
		return "", errors.New("engine: a network needs provenance — use NewProvenance")
	}
	body := map[string]any{"Name": name, "Driver": "bridge", "Labels": prov.labels()}
	var resp struct {
		ID string `json:"Id"`
	}
	if err := m.c.do(ctx, http.MethodPost, "/networks/create", nil, body, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// NetworkRemove removes a network. The daemon refuses one with active endpoints.
func (m *Mutator) NetworkRemove(ctx context.Context, ref string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(ref) {
		return errors.New("engine: invalid network reference")
	}
	return m.c.do(ctx, http.MethodDelete, "/networks/"+url.PathEscape(ref), nil, nil, nil)
}

// NetworkConnect attaches a container by ID, with the alias passed EXPLICITLY (§6b.2): the
// daemon infers no alias, and without one the container joins under its own
// installation-scoped name, which no sibling can guess — family DNS then fails silently,
// indistinguishable from an absent peer (§9). gwPriority is REQUIRED, not defaulted: the
// net-migration phases depend on the target being attached at a LOWER priority than the
// source so the route does not move before the final phase (v1.48's GwPriority).
func (m *Mutator) NetworkConnect(ctx context.Context, networkID, containerID, alias string, gwPriority int) error {
	if err := m.assert(); err != nil {
		return err
	}
	if err := netmodeOK(networkID); err != nil {
		return err
	}
	if !argOK(containerID) {
		return errors.New("engine: invalid container reference")
	}
	if !argOK(alias) {
		return errors.New("engine: invalid network alias")
	}
	body := map[string]any{
		"Container": containerID,
		"EndpointConfig": map[string]any{
			"Aliases":    []string{alias},
			"GwPriority": gwPriority,
		},
	}
	return m.c.do(ctx, http.MethodPost, "/networks/"+url.PathEscape(networkID)+"/connect", nil, body, nil)
}

// NetworkDisconnect detaches a container. A container that is not attached is the daemon's
// error, never a no-op — "everything is detached" and "this was never attached" are the same
// answer only to a fake.
func (m *Mutator) NetworkDisconnect(ctx context.Context, networkID, containerID string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(networkID) || !argOK(containerID) {
		return errors.New("engine: invalid network or container reference")
	}
	body := map[string]any{"Container": containerID}
	return m.c.do(ctx, http.MethodPost, "/networks/"+url.PathEscape(networkID)+"/disconnect", nil, body, nil)
}

// ImagePull pulls a reference, resolving registry authentication per auth.go and keeping
// every failure LOUD and distinguishable (§7.3): the registry's own words ride the error, and
// auth and network failures are never folded into one message (§10a).
func (m *Mutator) ImagePull(ctx context.Context, refWithDigest string) error {
	if err := m.assert(); err != nil {
		return err
	}
	if !argOK(refWithDigest) {
		return errors.New("engine: invalid image reference")
	}
	q := url.Values{}
	if name, digest, found := strings.Cut(refWithDigest, "@"); found {
		q.Set("fromImage", name)
		q.Set("tag", digest)
	} else {
		name, tag := refWithDigest, "latest"
		if i := strings.LastIndexByte(refWithDigest, ':'); i > strings.LastIndexByte(refWithDigest, '/') {
			name, tag = refWithDigest[:i], refWithDigest[i+1:]
		}
		q.Set("fromImage", name)
		q.Set("tag", tag)
	}
	u := "http://docker/" + APIVersion + "/images/create?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	if m.c.hasAuth {
		hdr, err := resolveRegistryAuth(m.c.authEnv, m.c.authHome, refWithDigest)
		if err != nil {
			return err
		}
		if hdr != "" {
			req.Header.Set("X-Registry-Auth", hdr)
		}
	}
	resp, err := m.c.http.Do(req)
	if err != nil {
		return fmt.Errorf("engine: %w: %v", ErrDaemonDown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		var dm daemonMessage
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &dm) == nil && dm.Message != "" {
			msg = dm.Message
		}
		return fmt.Errorf("engine: pull refused (%d): %s", resp.StatusCode, msg)
	}
	// The pull is a progress stream, and FAILURE CAN ARRIVE MID-STREAM after a 200: each
	// record is JSON, and an `error` record is the registry's refusal in its own words.
	dec := json.NewDecoder(resp.Body)
	for {
		var rec struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("engine: the pull stream broke off: %v", err)
		}
		if rec.Error != "" {
			return fmt.Errorf("engine: pull failed: %s", rec.Error)
		}
	}
}

// HelperResult is what a helper run reports. Stdout is the helper's ANSWER — the `key=value`
// protocol lines the reference read from `$(…)`; Stderr is its diagnostics, which the
// reference let pass through to the operator's terminal and never parsed. Callers that read
// protocol fields read Stdout and nothing else.
type HelperResult struct {
	Code   int64
	Stdout []byte
	Stderr []byte
}

// HelperRun runs one pinned helper container (D49/D54): closed command word, validated spec,
// provenance labels — and NO HELPER OUTLIVES ITS OWN INVOCATION. The reference expressed that
// with `--rm`; this client enforces the same guarantee itself — create, start, wait, read the
// output, then FORCE-REMOVE, on every path that created a container — because an
// AutoRemove'd container races its own log read on the API. A removal that fails leaves the
// error in the result, never a silent survivor; the probe layer's accounting (write-ahead
// intent) covers the crash window exactly as it does in the reference.
func (m *Mutator) HelperRun(ctx context.Context, h HelperSpec) (HelperResult, error) {
	var none HelperResult
	if err := m.assert(); err != nil {
		return none, err
	}
	if h.name == "" {
		return none, errors.New("engine: an empty HelperSpec — use NewHelperSpec")
	}
	mounts := make([]map[string]any, 0, len(h.opts.Mounts))
	for _, mt := range h.opts.Mounts {
		mounts = append(mounts, map[string]any{
			"Type": mt.typ, "Source": mt.source, "Target": mt.target, "ReadOnly": mt.readOnly,
		})
	}
	hostConfig := map[string]any{"Mounts": mounts}
	body := map[string]any{
		"Image":  h.image,
		"Cmd":    append([]string{string(h.cmd)}, h.opts.Args...),
		"Labels": h.prov.labels(),
	}
	if h.opts.RunAs != "" {
		body["User"] = h.opts.RunAs
	}
	if len(h.opts.Stdin) > 0 {
		body["OpenStdin"] = true
		body["StdinOnce"] = true
	}
	if h.opts.Network == "" {
		// Private mode — the copy container's mode (D54): the one legitimate use of `none`.
		hostConfig["NetworkMode"] = "none"
	} else {
		// Same name resolution as ContainerCreate, for the same measured reason.
		ni, nerr := m.c.NetworkInspect(ctx, h.opts.Network)
		if nerr != nil {
			return none, nerr
		}
		ep := map[string]any{}
		if h.opts.Alias != "" {
			ep["Aliases"] = []string{h.opts.Alias}
		}
		body["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{ni.Name: ep},
		}
	}
	body["HostConfig"] = hostConfig

	var created struct {
		ID string `json:"Id"`
	}
	q := url.Values{"name": {h.name}}
	if err := m.c.do(ctx, http.MethodPost, "/containers/create", q, body, &created); err != nil {
		return none, err
	}
	// From here on the container EXISTS: every return path below must have tried to remove
	// it. A removal error is reported on otherwise-successful paths and never masks the
	// primary error on failing ones.
	remove := func() error {
		// DETACHED from the caller's context on purpose: a cancelled or expired ctx is exactly
		// the moment a container is most likely to be left behind, and a removal that inherited
		// the cancellation would fail before it reached the daemon — a survivor created by the
		// very mechanism meant to prevent one. Bounded by its own deadline so a dead daemon
		// cannot hang the caller either.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), helperRemoveTimeout)
		defer cancel()
		return m.c.do(rctx, http.MethodDelete, "/containers/"+url.PathEscape(created.ID), url.Values{"force": {"1"}}, nil, nil)
	}
	if len(h.opts.Stdin) > 0 {
		if err := m.c.attachStdin(created.ID, h.opts.Stdin); err != nil {
			rmErr := remove()
			return none, errors.Join(err, rmErr)
		}
	}
	if err := m.c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil); err != nil {
		rmErr := remove()
		return none, errors.Join(err, rmErr)
	}
	code, err := m.c.ContainerWait(ctx, created.ID)
	if err != nil {
		rmErr := remove()
		return none, errors.Join(err, rmErr)
	}
	stdout, stderr, err := m.c.ContainerLogs(ctx, created.ID)
	if err != nil {
		rmErr := remove()
		return none, errors.Join(err, rmErr)
	}
	res := HelperResult{Code: code, Stdout: stdout, Stderr: stderr}
	if err := remove(); err != nil {
		return res, fmt.Errorf("engine: the helper ran but its container could not be removed: %w", err)
	}
	return res, nil
}

// helperRemoveTimeout bounds the detached force-remove in HelperRun.
const helperRemoveTimeout = 30 * time.Second

// attachStdin hands bytes to a created container's stdin over a hijacked attach connection,
// then half-closes so the process sees EOF. This is the API's one stdin vehicle; the
// alternative the reference design explicitly refuses is a THIRD host mount just to carry
// input.
func (c *Client) attachStdin(id string, data []byte) error {
	conn, err := net.DialTimeout("unix", c.socket, 10*time.Second)
	if err != nil {
		return fmt.Errorf("engine: %w: %v", ErrDaemonDown, err)
	}
	defer conn.Close()
	req := fmt.Sprintf("POST /%s/containers/%s/attach?stdin=1&stream=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
		APIVersion, url.PathEscape(id))
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("engine: attach failed: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("engine: attach failed: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine: attach refused (%d)", resp.StatusCode)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("engine: writing helper stdin failed: %v", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("engine: attach connection is not a unix socket")
	}
	return uc.CloseWrite()
}
