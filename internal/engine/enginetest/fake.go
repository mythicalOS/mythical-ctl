// Package enginetest is the fake container runtime for the hermetic Go suite (test-only;
// never shipped). It serves the Engine API over a per-test unix socket, so the REAL client —
// transport, routing, serialization, error mapping — is what every test exercises.
//
// Fidelity is the whole point, so the behaviors the design of record calls out as verified
// are reproduced here even where a simpler fake would pass the tests (the bash harness's
// header list, ported as API-level behaviors):
//
//   - `volume create` on an existing name SUCCEEDS and does NOT apply the new labels (D56).
//   - A STOPPED container has NO address; start assigns one and stop releases it (D48). A
//     container that has NEVER started reports an EMPTY NetworkID while the network-NAME map
//     key is present — the endpoint id is assigned at first start (the 2026-08-04 real-daemon
//     lesson; this fake is the regression test for it).
//   - inspect of an absent object is a 404 while /_ping still answers — the absent-vs-down
//     split the typed errors carry.
//   - `container create` REFUSES an image that was never pulled, as a real daemon does.
//   - A bind mount REFUSES a source that does not exist (the documented reason the client
//     uses typed mounts, not `-v` semantics); a NAMED VOLUME that does not exist is CREATED,
//     carrying no labels — the asymmetry is real and deliberate on Docker's part, and the
//     unlabelled volume is invisible to every find-by-label sweep, which is why it is worth
//     seeing.
//   - A resource that is still referenced cannot be removed: a network with a RUNNING
//     container attached (measured 2026-08-25: a created-or-stopped attachment holds no
//     active endpoint and does not block), a volume a container mounts (any state), a running
//     container without force.
//   - A container joins a network under its own NAME as well as any explicit alias, so an
//     omitted alias is observable rather than invisible (§9's silent-DNS failure).
//   - Connecting the SAME network twice to a RUNNING container is a conflict (on a non-running
//     one the daemon updates the endpoint config — measured 2026-08-25); a private (`none`)
//     mode container cannot be connected to any network — the daemon's own refusal, in its
//     words.
//   - `network create` records the driver it was ASKED for; the duplicate-name knob models
//     D38 (Docker does not guarantee name-conflict detection there).
//   - The two name-RESOLUTION surfaces a container has are modelled SEPARATELY: the network
//     resolver answers names and aliases; the hosts file holds only the container's own
//     HOSTNAME. A selfcheck answered out of the wrong one is observably different (D49).
//   - THE CLOSED SURFACE: an unimplemented route is a HARD ERROR, never a silent no-op — a
//     fake that ignores a request is worse than one that lacks it. Names are validated on
//     every create against the real daemon's own class, so this fake is never MORE PERMISSIVE
//     than the daemon it stands in for.
package enginetest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"mythicalos.ai/ctl/internal/engine"
)

// HelperNetView is what a helper fixture sees of its container's two name-resolution
// surfaces, plus its own hostname. DNS is the network's embedded resolver — every running
// container's name and aliases on the helper's network; Hosts is the container-local file —
// localhost and the container's own HOSTNAME, nothing else.
type HelperNetView struct {
	DNS      map[string]string
	Hosts    map[string]string
	Hostname string
}

// preStartStdinCap is the fake's bound on stdin drained before the container starts — the
// daemon's buffering is likewise finite, which is why stdin must stream to a RUNNING process.
const preStartStdinCap = 32 * 1024

// HelperEntryFunc is the helper fixture: the closed command word, its arguments, the network
// views, and any stdin bytes. It answers with an exit code and the container's output.
type HelperEntryFunc func(cmd string, args []string, view HelperNetView, stdin []byte) (int, []byte)

type fakeEndpoint struct {
	netID   string
	netName string
	// key is the string the endpoint is REPORTED under while the container has never started.
	// MEASURED 2026-08-25 (Engine 28.4.0 / API 1.51): the daemon stores a create-time endpoint
	// under WHATEVER string keyed EndpointsConfig — id or name, as submitted — and normalizes
	// to the network name only at first start. Preserved here so a client that stopped
	// resolving its attach reference to the NAME before creating fails the never-started
	// inspect exactly as it would against the real daemon, instead of being quietly forgiven.
	key     string
	aliases []string // explicit first, then the container's own name
	gw      int
}

type fakeContainer struct {
	id        string
	name      string
	image     string
	state     string // "created" | "running" | "exited"
	labels    map[string]string
	env       []string
	endpoints []*fakeEndpoint
	mounts    []mountRec
	ports     []portRec
	netmode   string // "none" for private-mode helpers, else ""
	cmd       []string
	user      string
	stdin     []byte
	openStdin bool
	// awaitingStdin: started in the CLI-parity sequence (stdin arrives AFTER start); the
	// entry runs at attach-EOF and waiters are woken through the fake's cond.
	awaitingStdin bool
	stdinDone     bool
	ran           bool
	exitCode      int64
	output        []byte // the helper's stdout (stream 1)
	stderr        []byte // the helper's stderr (stream 2), from the HelperStderr knob
}

type mountRec struct {
	typ, name, source, target string
	rw                        bool
}

type portRec struct {
	containerPort    string // "7480/tcp"
	hostIP, hostPort string
}

type fakeVolume struct {
	name   string
	driver string
	labels map[string]string
}

type fakeNetwork struct {
	id     string
	name   string
	driver string
	labels map[string]string
	thi    string
}

// Fake is the in-memory daemon. Knobs are exported fields, set by tests; every knob is inert
// unless set. The knob pairs the bash harness keeps distinct stay distinct here, because
// folding them was measured to mask refusals:
//
//   - Down fails EVERY request, /_ping included — the client reports ErrDaemonDown.
//   - DownAfter answers the first N requests and then fails every one, /_ping included — the
//     daemon going down BETWEEN two questions of one operation.
//   - InfoFail breaks /info ALONE while /_ping and /version keep answering — the only way the
//     rootless "could not ask" refusal is reachable past a successful ping.
//   - InspectMissing makes inspects of ONE named object 404 while everything else answers —
//     an object that vanished, which is a fact a later run may act on; with
//     InspectMissingAfter, it survives its first N inspections first.
//   - RemoveMissing makes the DELETE for ONE named object 404 — container, volume or network,
//     whichever class carries that name — while every INSPECT of it still answers. That is the one
//     window InspectMissing cannot reach: an object a verb has just proved is its own, removed by
//     something else before the verb gets to the removal. The daemon answers 404 there, and a
//     caller that reads that as "the removal failed" keeps a record for an object the runtime says
//     does not exist.
type Fake struct {
	mu   sync.Mutex
	cond *sync.Cond // signals helper completion to blocked waiters (waitContainer)

	dir    string
	socket string
	srv    *http.Server

	Down                  bool
	DownAfter             int
	DownFrom              string // "METHOD /path": answers until that request, then EVERYTHING dies (latched)
	InterruptOn           string // "METHOD /path": THAT request dies before doing its work; everything else answers
	downFromLatched       bool
	InfoFail              bool
	InspectMissing        string
	InspectMissingAfter   int
	RemoveMissing         string
	inspectMissingCount   int
	ServerVersionValue    string
	Rootless              bool
	PullOutcome           string // "" or "ok" | "notfound" | "auth" | "neterr" | "streamerr"
	DuplicateNetworkNames bool
	NetDriverOverride     string // fabricate a driver the client cannot legitimately request
	NetDefaultDriver      string // the daemon default when the request names no driver
	NetTHI                string // trusted_host_interfaces on every created network
	ConnectFail           bool
	DisconnectSilent      bool
	HelperFail            string
	HelperEntry           HelperEntryFunc
	// HelperStderr is emitted on the helper's STDERR stream (frame id 2) at start; the entry
	// fixture answers stdout only. It exists so a test can prove stderr is never read as the
	// protocol answer.
	HelperStderr []byte
	// CreateResponseLost fabricates the ambiguous-create window: the container IS created and
	// recorded, and then the connection is aborted before the response carries its id — the
	// caller cannot tell a refused create from one that succeeded silently.
	CreateResponseLost bool
	// StdinAfterStart records, at attach-EOF, whether the container had already been started —
	// the CLI-parity property (stdin streams to a RUNNING process) a test can assert.
	StdinAfterStart bool

	// Requests logs "METHOD /path" for every request, INCLUDING ones the Down knobs then
	// refuse — the post-release Mutator test's "the fake recorded NO request" reads this.
	Requests []string
	reqCount int

	// LastPullRef and LastPullAuth record the most recent pull: the ref the daemon was asked
	// for and the DECODED X-Registry-Auth AuthConfig (nil when the header was absent) — so a
	// test compares the exact credentials, not mere header presence.
	LastPullRef  string
	LastPullAuth map[string]string

	// helperLaunches records every helper CREATE — see HelperLaunch. Read it through
	// HelperLaunches(), which copies under the fake's lock.
	helperLaunches []HelperLaunch

	containers map[string]*fakeContainer
	volumes    map[string]*fakeVolume
	networks   []*fakeNetwork
	images     map[string]string // ref -> image id
	nextID     int
}

// SetDown flips the Down knob under the fake's lock — the form a test MUST use when it
// toggles the knob after traffic has flowed, because a handler goroutine from an earlier
// request can still be reading it (a bare field write is a data race under -race).
func (f *Fake) SetDown(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Down = v
}

// RequestLog returns a COPY of the request log, taken under the fake's own lock.
//
// It is the only safe way to read it. Requests is appended to from the handler goroutines, so a
// bare read of the field races with any request still in flight — including one the Down knobs are
// about to abort, since the log entry is written before the abort. (Measured under -race by a
// caller counting image pulls right after a verb returned.)
func (f *Fake) RequestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Requests...)
}

// SetDownFrom is SetDown's counterpart for the DownFrom knob, for the same reason.
func (f *Fake) SetDownFrom(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DownFrom = v
}

// NewFake starts a fake daemon on a fresh unix socket. Callers own Close.
func NewFake() *Fake {
	dir, err := os.MkdirTemp("", "enginetest")
	if err != nil {
		panic(err)
	}
	f := &Fake{
		dir:        dir,
		socket:     filepath.Join(dir, "docker.sock"),
		containers: map[string]*fakeContainer{},
		volumes:    map[string]*fakeVolume{},
		images:     map[string]string{},
	}
	f.cond = sync.NewCond(&f.mu)
	ln, err := net.Listen("unix", f.socket)
	if err != nil {
		panic(err)
	}
	f.srv = &http.Server{Handler: http.HandlerFunc(f.handle)}
	go func() { _ = f.srv.Serve(ln) }()
	return f
}

// Close tears the fake down and removes its socket directory.
func (f *Fake) Close() {
	_ = f.srv.Close()
	_ = os.RemoveAll(f.dir)
}

// Client dials the fake through the REAL engine client.
func (f *Fake) Client() *engine.Client { return engine.Dial(f.socket) }

// Socket is the fake's unix socket path, for tests that speak raw HTTP.
func (f *Fake) Socket() string { return f.socket }

// --- test-visible state helpers --------------------------------------------------------------

// PullImage marks a reference as locally present, as a prior pull would have.
func (f *Fake) PullImage(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registerImage(ref)
}

func (f *Fake) registerImage(ref string) {
	if _, ok := f.images[ref]; !ok {
		f.images[ref] = fmt.Sprintf("sha256:%064d", f.mintID())
	}
}

// HelperMount is one mount as the daemon received it on a helper create.
type HelperMount struct {
	Type     string // "bind" | "volume"
	Source   string // host path (bind) or volume name (volume)
	Target   string
	ReadOnly bool
}

// HelperLaunch is one helper create, recorded AS SUBMITTED — the analogue of the reference
// harness's `calls.log` line for the `docker run` a helper is.
//
// IT EXISTS BECAUSE NO HELPER OUTLIVES ITS OWN INVOCATION: the client force-removes the
// container on every path that created one, so by the time a test can look, there is nothing
// to inspect. The launch contract — the source mounted READ-ONLY, staging the ONLY writable
// mount, NOTHING ELSE from the host mounted at all, private (`none`) networking, and the uid
// an effective-access check runs as — is therefore asserted from this record.
type HelperLaunch struct {
	Image   string
	Name    string
	Cmd     []string // the closed command word, then its own arguments
	User    string   // the `--user` uid, "" when the image's own user is kept
	NetMode string   // "none" for private-mode helpers, else ""
	Network string   // the network reference submitted at create, "" in private mode
	Aliases []string // the network aliases submitted at create
	Mounts  []HelperMount
}

// HelperLaunches returns every helper create so far, oldest first.
func (f *Fake) HelperLaunches() []HelperLaunch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HelperLaunch(nil), f.helperLaunches...)
}

// ContainerCount reports how many containers the daemon holds, in any state.
func (f *Fake) ContainerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.containers)
}

// Snapshot renders the whole runtime world deterministically — the analogue of the bash
// harness's runtime snapshot, for "nothing partial survives" assertions.
func (f *Fake) Snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	var vnames []string
	for n := range f.volumes {
		vnames = append(vnames, n)
	}
	sort.Strings(vnames)
	for _, n := range vnames {
		fmt.Fprintf(&b, "volume %s labels=%s\n", n, renderLabels(f.volumes[n].labels))
	}
	nets := append([]*fakeNetwork(nil), f.networks...)
	sort.Slice(nets, func(i, j int) bool { return nets[i].id < nets[j].id })
	for _, n := range nets {
		fmt.Fprintf(&b, "network %s driver=%s labels=%s\n", n.name, n.driver, renderLabels(n.labels))
	}
	var cnames []string
	for n := range f.containers {
		cnames = append(cnames, n)
	}
	sort.Strings(cnames)
	for _, n := range cnames {
		c := f.containers[n]
		fmt.Fprintf(&b, "container %s state=%s image=%s labels=%s\n", n, c.state, c.image, renderLabels(c.labels))
	}
	return b.String()
}

func renderLabels(labels map[string]string) string {
	var keys []string
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

func (f *Fake) mintID() int {
	f.nextID++
	return f.nextID
}

func (f *Fake) longID() string { return fmt.Sprintf("%064d", f.mintID()) }

// checkName is the real daemon's own name class (moby: names against
// `^/?[a-zA-Z0-9][a-zA-Z0-9_.-]+$`). Applied on every create, so this fake is never MORE
// PERMISSIVE than the daemon it stands in for — a guard that only ever runs against a fake
// that accepts what Docker rejects is decoration.
func checkName(n string) bool {
	if len(n) < 2 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 {
			if !alnum {
				return false
			}
			continue
		}
		if !alnum && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func addrFor(containerName, netID string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(containerName + netID))
	v := h.Sum32()
	return fmt.Sprintf("10.88.%d.%d", v%250+1, len(containerName)%250+2)
}

func shortID(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%012x", h.Sum32())
}

// --- HTTP plumbing ---------------------------------------------------------------------------

func fail(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf(format, args...)})
}

func ok(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if body == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *Fake) handle(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/"+engine.APIVersion)
	f.mu.Lock()
	f.reqCount++
	f.Requests = append(f.Requests, r.Method+" "+r.URL.Path)
	// InterruptOn fabricates the process dying AT a named step, BEFORE its work happens — the
	// object it would have created never exists, while the daemon stays up for everything
	// else: the write-ahead window recovery must close.
	interrupted := f.InterruptOn != "" && key == f.InterruptOn
	// DownFrom latches the daemon's failure to a SPECIFIC operation: it answers until the
	// matching request, and from THAT request onward every command dies, /_ping included —
	// unlike DownAfter, no call counting is involved.
	if f.DownFrom != "" && key == f.DownFrom {
		f.downFromLatched = true
	}
	down := f.Down || f.downFromLatched || (f.DownAfter > 0 && f.reqCount > f.DownAfter)
	f.mu.Unlock()
	if down {
		// A down daemon fails EVERY request at the transport, /_ping included — that is what
		// makes the absent-vs-unreachable split observable. Aborting the connection is the
		// HTTP-level spelling of "nothing answered".
		panic(http.ErrAbortHandler)
	}
	if interrupted {
		fail(w, 500, "fake engine: interrupted at '%s'", key)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/"+engine.APIVersion)
	if path == "/_ping" || r.URL.Path == "/_ping" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// The attach route is served OUTSIDE the dispatch lock: its read blocks until the client
	// half-closes, which — in the CLI-parity sequence — happens only after /start has been
	// ANSWERED, and /start needs the lock this dispatcher would still be holding.
	if hseg := strings.Split(strings.TrimPrefix(path, "/"), "/"); r.Method == http.MethodPost &&
		len(hseg) == 3 && hseg[0] == "containers" && hseg[2] == "attach" {
		f.attachContainer(w, r, hseg[1])
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && path == "/version":
		v := f.ServerVersionValue
		if v == "" {
			v = "28.0.0"
		}
		ok(w, map[string]string{"Version": v, "ApiVersion": strings.TrimPrefix(engine.APIVersion, "v")})
	case r.Method == http.MethodGet && path == "/info":
		if f.InfoFail {
			fail(w, 500, "system info is unavailable")
			return
		}
		sec := []string{"name=seccomp", "name=apparmor"}
		if f.Rootless {
			sec = []string{"name=rootless", "name=seccomp"}
		}
		v := f.ServerVersionValue
		if v == "" {
			v = "28.0.0"
		}
		ok(w, map[string]any{"ServerVersion": v, "SecurityOptions": sec})

	case r.Method == http.MethodGet && path == "/containers/json":
		f.listContainers(w, r)
	case r.Method == http.MethodPost && path == "/containers/create":
		f.createContainer(w, r)
	case len(seg) == 3 && seg[0] == "containers" && r.Method == http.MethodGet && seg[2] == "json":
		f.inspectContainer(w, seg[1])
	case len(seg) == 3 && seg[0] == "containers" && r.Method == http.MethodPost && seg[2] == "start":
		f.startContainer(w, seg[1])
	case len(seg) == 3 && seg[0] == "containers" && r.Method == http.MethodPost && seg[2] == "stop":
		f.stopContainer(w, seg[1])
	case len(seg) == 3 && seg[0] == "containers" && r.Method == http.MethodPost && seg[2] == "wait":
		f.waitContainer(w, seg[1])
	case len(seg) == 3 && seg[0] == "containers" && r.Method == http.MethodGet && seg[2] == "logs":
		f.logsContainer(w, seg[1])
	case len(seg) == 2 && seg[0] == "containers" && r.Method == http.MethodDelete:
		f.removeContainer(w, r, seg[1])

	case r.Method == http.MethodGet && path == "/volumes":
		f.listVolumes(w, r)
	case r.Method == http.MethodPost && path == "/volumes/create":
		f.createVolume(w, r)
	case len(seg) == 2 && seg[0] == "volumes" && r.Method == http.MethodGet:
		f.inspectVolume(w, seg[1])
	case len(seg) == 2 && seg[0] == "volumes" && r.Method == http.MethodDelete:
		f.removeVolume(w, seg[1])

	case r.Method == http.MethodGet && path == "/networks":
		f.listNetworks(w, r)
	case r.Method == http.MethodPost && path == "/networks/create":
		f.createNetwork(w, r)
	case len(seg) == 2 && seg[0] == "networks" && r.Method == http.MethodGet:
		f.inspectNetwork(w, seg[1])
	case len(seg) == 2 && seg[0] == "networks" && r.Method == http.MethodDelete:
		f.removeNetwork(w, seg[1])
	case len(seg) == 3 && seg[0] == "networks" && r.Method == http.MethodPost && seg[2] == "connect":
		f.connectNetwork(w, r, seg[1])
	case len(seg) == 3 && seg[0] == "networks" && r.Method == http.MethodPost && seg[2] == "disconnect":
		f.disconnectNetwork(w, r, seg[1])

	case r.Method == http.MethodPost && path == "/images/create":
		f.pullImage(w, r)
	// Prefix/suffix, not segments: an image REFERENCE legitimately contains `/` (and the
	// server decodes the client's escaping before routing), so the ref is everything between.
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		f.inspectImage(w, strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json"))

	default:
		// THE CLOSED SURFACE: an unimplemented route dies loudly. The message says `fake
		// engine:` rather than borrowing the daemon's wording — this fake cannot tell "the
		// API has no such route" from "this fake does not implement it".
		fail(w, 500, "fake engine: unimplemented route: %s %s", r.Method, path)
	}
}

// vanished implements the InspectMissing knob for one inspect of one named object.
func (f *Fake) vanished(name string) bool {
	if f.InspectMissing == "" || name != f.InspectMissing {
		return false
	}
	f.inspectMissingCount++
	return f.inspectMissingCount > f.InspectMissingAfter
}

func pathName(seg string) string {
	n, err := url.PathUnescape(seg)
	if err != nil {
		return seg
	}
	return n
}

// --- containers ------------------------------------------------------------------------------

func (f *Fake) findContainer(ref string) *fakeContainer {
	if c, ok := f.containers[ref]; ok {
		return c
	}
	for _, c := range f.containers {
		if c.id == ref {
			return c
		}
	}
	return nil
}

func (f *Fake) findNetwork(ref string) *fakeNetwork {
	for _, n := range f.networks {
		if n.id == ref || n.name == ref {
			return n
		}
	}
	return nil
}

type createBody struct {
	Image      string            `json:"Image"`
	Cmd        []string          `json:"Cmd"`
	Env        []string          `json:"Env"`
	User       string            `json:"User"`
	Labels     map[string]string `json:"Labels"`
	OpenStdin  bool              `json:"OpenStdin"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
		Mounts      []struct {
			Type     string `json:"Type"`
			Source   string `json:"Source"`
			Target   string `json:"Target"`
			ReadOnly bool   `json:"ReadOnly"`
		} `json:"Mounts"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkingConfig struct {
		EndpointsConfig map[string]struct {
			Aliases    []string `json:"Aliases"`
			GwPriority int      `json:"GwPriority"`
		} `json:"EndpointsConfig"`
	} `json:"NetworkingConfig"`
}

func (f *Fake) createContainer(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var body createBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "fake engine: unreadable create body: %v", err)
		return
	}
	if name == "" {
		fail(w, 500, "fake engine: a create with no name is not implemented")
		return
	}
	if !checkName(name) {
		fail(w, 400, "Invalid container name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed", name)
		return
	}
	// Real Docker's order: the image is resolved first, then the name conflict, then the
	// mount config. Every refusal precedes the record write, or a refused create would leave
	// a container behind for the next assertion to find.
	if _, ok := f.images[body.Image]; !ok {
		// The API's own wording and status — a 404, so the client reports ErrAbsent. (The
		// CLI's "Unable to find image … locally" is its wrapper, not the daemon's answer.)
		fail(w, 404, "No such image: %s", body.Image)
		return
	}
	if f.findContainer(name) != nil {
		fail(w, 409, "Conflict. The container name \"/%s\" is already in use", name)
		return
	}
	c := &fakeContainer{
		name:      name,
		image:     body.Image,
		state:     "created",
		labels:    body.Labels,
		env:       body.Env,
		cmd:       body.Cmd,
		user:      body.User,
		openStdin: body.OpenStdin,
	}
	switch {
	case body.HostConfig.NetworkMode == "none":
		c.netmode = "none"
	case len(body.NetworkingConfig.EndpointsConfig) == 1:
		for ref, ep := range body.NetworkingConfig.EndpointsConfig {
			n := f.findNetwork(ref)
			if n == nil {
				fail(w, 404, "network %s not found", ref)
				return
			}
			// The container's own NAME joins the alias list, as a real daemon adds it on a
			// user-defined network — an omitted alias leaves the list holding the name ALONE,
			// which is §9's observable failure, not an empty list.
			c.endpoints = append(c.endpoints, &fakeEndpoint{
				netID:   n.id,
				netName: n.name,
				key:     ref, // as submitted — see fakeEndpoint.key
				aliases: append(append([]string(nil), ep.Aliases...), name),
				gw:      ep.GwPriority,
			})
		}
	case len(body.NetworkingConfig.EndpointsConfig) > 1:
		fail(w, 400, "Container cannot be connected to network endpoints: more than one endpoint at create")
		return
	default:
		fail(w, 500, "fake engine: a create with no network attachment is not implemented (the real daemon would join the default bridge; no caller of this fake may)")
		return
	}
	for _, m := range body.HostConfig.Mounts {
		switch m.Type {
		case "bind":
			// The daemon refuses a bind whose source does not exist — the stated reason the
			// client uses typed mounts at all.
			if _, err := os.Stat(m.Source); err != nil {
				fail(w, 400, "invalid mount config for type \"bind\": bind source path does not exist: %s", m.Source)
				return
			}
			c.mounts = append(c.mounts, mountRec{typ: "bind", source: m.Source, target: m.Target, rw: !m.ReadOnly})
		case "volume":
			// The daemon's name class applies to the auto-create exactly as to an explicit
			// one — a comma-bearing "name" is refused here, never adopted (the bash fake's
			// create_missing_volumes calls the same check_name).
			if !checkName(m.Source) {
				fail(w, 400, "create %s: %q includes invalid characters for a local volume name, only \"[a-zA-Z0-9][a-zA-Z0-9_.-]\" are allowed", m.Source, m.Source)
				return
			}
			if _, ok := f.volumes[m.Source]; !ok {
				// Auto-created by the daemon, carrying NO labels — invisible to every
				// find-by-label sweep, exactly like the real orphan it models.
				f.volumes[m.Source] = &fakeVolume{name: m.Source, driver: "local", labels: map[string]string{}}
			}
			c.mounts = append(c.mounts, mountRec{typ: "volume", name: m.Source, target: m.Target, rw: !m.ReadOnly})
		default:
			fail(w, 400, "fake engine: unsupported mount type %q", m.Type)
			return
		}
	}
	for port, binds := range body.HostConfig.PortBindings {
		for _, b := range binds {
			hip := b.HostIP
			if hip == "" {
				// An empty HostIp binds ALL interfaces, which the daemon reports as
				// 0.0.0.0 — the very address the loopback wall exists to prevent, reported
				// as what it is rather than hidden.
				hip = "0.0.0.0"
			}
			c.ports = append(c.ports, portRec{containerPort: port, hostIP: hip, hostPort: b.HostPort})
		}
	}
	c.id = f.longID()
	f.containers[name] = c
	// A helper carries a command; a product container does not. Recorded HERE — at create,
	// where the launch is decided, and BEFORE the CreateResponseLost unwind below — so an
	// ambiguous create is still visible as the launch it was.
	if len(c.cmd) > 0 {
		rec := HelperLaunch{
			Image: c.image, Name: c.name, Cmd: append([]string(nil), c.cmd...),
			User: c.user, NetMode: c.netmode,
		}
		if len(c.endpoints) == 1 {
			rec.Network = c.endpoints[0].netName
			rec.Aliases = append([]string(nil), c.endpoints[0].aliases...)
		}
		for _, m := range c.mounts {
			src := m.source
			if m.typ == "volume" {
				src = m.name
			}
			rec.Mounts = append(rec.Mounts, HelperMount{Type: m.typ, Source: src, Target: m.target, ReadOnly: !m.rw})
		}
		f.helperLaunches = append(f.helperLaunches, rec)
	}
	if f.CreateResponseLost {
		// The record is written; the answer never arrives. The dispatcher's deferred unlock
		// runs during the unwind, so the fake stays answerable for the sweep that follows.
		panic(http.ErrAbortHandler)
	}
	ok(w, map[string]string{"Id": c.id})
}

func (f *Fake) inspectContainer(w http.ResponseWriter, seg string) {
	name := pathName(seg)
	if f.vanished(name) {
		fail(w, 404, "No such object: %s", name)
		return
	}
	c := f.findContainer(name)
	if c == nil {
		fail(w, 404, "No such container: %s", name)
		return
	}
	networks := map[string]any{}
	for _, ep := range c.endpoints {
		// NEVER-STARTED fidelity: while the container is `created`, the endpoint reports an
		// EMPTY NetworkID — only the map key (the network NAME) identifies the attachment.
		// A STOPPED container keeps the id but has NO address.
		id := ep.netID
		if c.state == "created" {
			id = ""
		}
		addr := ""
		if c.state == "running" {
			addr = addrFor(c.name, ep.netID)
		}
		// The map KEY is the network name once the container has started; before that it is
		// the submitted EndpointsConfig key, verbatim (measured — see fakeEndpoint.key).
		key := ep.netName
		if c.state == "created" {
			key = ep.key
		}
		networks[key] = map[string]any{
			"NetworkID": id, "IPAddress": addr, "Aliases": ep.aliases, "GwPriority": ep.gw,
		}
	}
	mounts := []map[string]any{}
	for _, m := range c.mounts {
		mounts = append(mounts, map[string]any{
			"Type": m.typ, "Name": m.name, "Source": m.source, "Destination": m.target, "RW": m.rw,
		})
	}
	ports := map[string][]map[string]string{}
	for _, p := range c.ports {
		ports[p.containerPort] = append(ports[p.containerPort], map[string]string{"HostIp": p.hostIP, "HostPort": p.hostPort})
	}
	ok(w, map[string]any{
		"Id":    c.id,
		"Name":  "/" + c.name,
		"Image": c.image,
		"State": map[string]any{"Running": c.state == "running", "Status": c.state},
		"Config": map[string]any{
			"Labels": c.labels,
			"Env":    c.env,
		},
		"NetworkSettings": map[string]any{"Networks": networks, "Ports": ports},
		"Mounts":          mounts,
	})
}

func (f *Fake) startContainer(w http.ResponseWriter, seg string) {
	c := f.findContainer(pathName(seg))
	if c == nil {
		fail(w, 404, "No such container: %s", pathName(seg))
		return
	}
	if len(c.cmd) > 0 {
		// A helper: it runs its closed command and exits. The HelperFail knob fabricates a
		// daemon-side launch failure; the fixture entrypoint produces the answer.
		if f.HelperFail != "" {
			fail(w, 500, "helper: %s", f.HelperFail)
			return
		}
		if f.HelperEntry == nil {
			fail(w, 500, "fake engine: no helper fixture is set (Fake.HelperEntry)")
			return
		}
		if c.openStdin && !c.stdinDone {
			// CLI-parity sequence: the payload arrives AFTER start — the entry runs at
			// attach-EOF (attachContainer), which wakes any blocked waiter via the cond.
			c.state = "running"
			c.awaitingStdin = true
			f.cond.Broadcast() // wake an attach reader parked at the pre-start cap
			ok(w, nil)
			return
		}
		c.state = "running"
		f.runHelperEntry(c)
		ok(w, nil)
		return
	}
	c.state = "running"
	f.cond.Broadcast()
	ok(w, nil)
}

// runHelperEntry executes the fixture entry for a running helper and marks it exited.
// CALLED UNDER f.mu; wakes waiters blocked in waitContainer.
func (f *Fake) runHelperEntry(c *fakeContainer) {
	view := f.helperView(c)
	code, out := f.HelperEntry(c.cmd[0], c.cmd[1:], view, c.stdin)
	c.exitCode = int64(code)
	c.output = out
	c.stderr = append([]byte(nil), f.HelperStderr...)
	c.ran = true
	c.awaitingStdin = false
	c.state = "exited"
	f.cond.Broadcast()
}

// helperView builds the two name-resolution surfaces for a helper at START time: the DNS view
// holds every RUNNING container's aliases on the helper's network plus the helper's own
// registrations; the hosts view holds localhost and the helper's HOSTNAME — the daemon-minted
// short id, deliberately NOT its name and NOT any alias (that distinction is the whole of the
// selfcheck property).
func (f *Fake) helperView(c *fakeContainer) HelperNetView {
	view := HelperNetView{
		DNS:      map[string]string{},
		Hosts:    map[string]string{"localhost": "127.0.0.1"},
		Hostname: shortID(c.name),
	}
	if c.netmode == "none" || len(c.endpoints) == 0 {
		return view
	}
	netID := c.endpoints[0].netID
	for _, other := range f.containers {
		if other == c || other.state != "running" {
			continue
		}
		for _, ep := range other.endpoints {
			if ep.netID != netID {
				continue
			}
			addr := addrFor(other.name, netID)
			for _, a := range ep.aliases {
				view.DNS[a] = addr
			}
		}
	}
	own := addrFor(c.name, netID)
	for _, a := range c.endpoints[0].aliases {
		view.DNS[a] = own
	}
	view.Hosts[view.Hostname] = own
	return view
}

func (f *Fake) stopContainer(w http.ResponseWriter, seg string) {
	c := f.findContainer(pathName(seg))
	if c == nil {
		fail(w, 404, "No such container: %s", pathName(seg))
		return
	}
	c.state = "exited"
	// Predicates changed — wake anything blocked on them (a waitContainer for a helper that
	// never got its stdin, an attach reader parked at the pre-start cap).
	f.cond.Broadcast()
	ok(w, nil)
}

func (f *Fake) waitContainer(w http.ResponseWriter, seg string) {
	c := f.findContainer(pathName(seg))
	if c == nil {
		fail(w, 404, "No such container: %s", pathName(seg))
		return
	}
	// A helper still waiting for its stdin: block until the attach-EOF path has run the
	// entry (cond.Wait releases the dispatch lock while waiting, so that path can take it).
	for c.awaitingStdin && c.state == "running" {
		f.cond.Wait()
	}
	if !c.ran && c.state == "running" {
		fail(w, 500, "fake engine: wait on a running non-helper container is not implemented")
		return
	}
	ok(w, map[string]int64{"StatusCode": c.exitCode})
}

func (f *Fake) logsContainer(w http.ResponseWriter, seg string) {
	c := f.findContainer(pathName(seg))
	if c == nil {
		fail(w, 404, "No such container: %s", pathName(seg))
		return
	}
	w.WriteHeader(http.StatusOK)
	// The daemon's non-TTY framing: one 8-byte header per record, stream id in byte 0 —
	// 1 stdout, 2 stderr. Both streams are emitted so the client's demultiplexer is exercised
	// on the split, not just on the framing.
	frame := func(stream byte, payload []byte) {
		if len(payload) == 0 {
			return
		}
		var hdr [8]byte
		hdr[0] = stream
		binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
		_, _ = w.Write(hdr[:])
		_, _ = w.Write(payload)
	}
	frame(1, c.output)
	frame(2, c.stderr)
}

// attachContainer runs OUTSIDE the dispatch lock (see handle): the blocking read happens
// unlocked, and the lock is taken only to record the payload and — for a helper started in
// the CLI-parity sequence — to run its entry at EOF.
func (f *Fake) attachContainer(w http.ResponseWriter, r *http.Request, seg string) {
	f.mu.Lock()
	c := f.findContainer(pathName(seg))
	f.mu.Unlock()
	if c == nil {
		fail(w, 404, "No such container: %s", pathName(seg))
		return
	}
	hj, okCast := w.(http.Hijacker)
	if !okCast {
		fail(w, 500, "fake engine: attach needs a hijackable connection")
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = rw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = rw.Flush()
	// BOUNDED pre-start buffering, as the daemon has: while the container has never started,
	// at most preStartStdinCap bytes are drained off the wire — the rest waits for start.
	// This is the mechanism that made write-everything-before-start a structural deadlock,
	// and modelling it is what lets a test KILL that sequence deterministically (a client
	// writing a large payload before /start blocks here until its context deadline snaps).
	var data []byte
	buf := make([]byte, 4096)
	for {
		if len(data) >= preStartStdinCap {
			f.mu.Lock()
			for c.state == "created" {
				f.cond.Wait()
			}
			f.mu.Unlock()
		}
		n, rerr := rw.Read(buf)
		data = append(data, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c.stdin = data
	c.stdinDone = true
	f.StdinAfterStart = c.state != "created"
	if c.awaitingStdin && c.state == "running" {
		f.runHelperEntry(c)
	}
}

func (f *Fake) removeContainer(w http.ResponseWriter, r *http.Request, seg string) {
	name := pathName(seg)
	c := f.findContainer(name)
	if c == nil || (f.RemoveMissing != "" && name == f.RemoveMissing) {
		fail(w, 404, "No such container: %s", name)
		return
	}
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	if c.state == "running" && !force {
		fail(w, 409, "You cannot remove a running container %s. Stop the container before attempting removal or force remove", c.id)
		return
	}
	// Terminalize BEFORE deleting: a waiter blocked on this container holds the pointer, not
	// the map entry — without flipping the predicates and broadcasting, a force-remove would
	// strand it (and any attach reader parked at the pre-start cap) forever.
	c.state = "exited"
	c.awaitingStdin = false
	f.cond.Broadcast()
	delete(f.containers, c.name)
	ok(w, nil)
}

func (f *Fake) listContainers(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
	labels, err := parseLabelFilters(r.URL.Query().Get("filters"))
	if err != nil {
		fail(w, 400, "%v", err)
		return
	}
	out := []map[string]any{}
	var names []string
	for n := range f.containers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := f.containers[n]
		// Without all, only RUNNING containers are listed — the real daemon's rule, kept so
		// the client's always-all listing is observably load-bearing.
		if !all && c.state != "running" {
			continue
		}
		if !labelsMatch(c.labels, labels) {
			continue
		}
		out = append(out, map[string]any{
			"Id": c.id, "Names": []string{"/" + c.name}, "State": c.state, "Labels": c.labels,
		})
	}
	ok(w, out)
}

// parseLabelFilters honours `label=` filters ONLY — a filter kind this fake does not
// implement is a hard error, never an empty match (the emptiest possible wrong answer).
func parseLabelFilters(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var m map[string][]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("fake engine: unreadable filters: %v", err)
	}
	for k := range m {
		if k != "label" {
			return nil, fmt.Errorf("fake engine: only label= filters are implemented, not %q", k)
		}
	}
	return m["label"], nil
}

// labelsMatch ANDs every term, as the real daemon does.
func labelsMatch(have map[string]string, terms []string) bool {
	for _, t := range terms {
		k, v, found := strings.Cut(t, "=")
		if !found {
			return false
		}
		if have[k] != v {
			return false
		}
	}
	return true
}

// --- volumes ---------------------------------------------------------------------------------

func (f *Fake) createVolume(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "fake engine: unreadable volume create body: %v", err)
		return
	}
	if !checkName(body.Name) {
		fail(w, 400, "create %s: %q includes invalid characters for a local volume name, only \"[a-zA-Z0-9][a-zA-Z0-9_.-]\" are allowed", body.Name, body.Name)
		return
	}
	// REAL semantics (D56): an existing name SUCCEEDS and the new labels are NOT applied — a
	// create is never evidence of creation.
	if _, exists := f.volumes[body.Name]; !exists {
		labels := body.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		f.volumes[body.Name] = &fakeVolume{name: body.Name, driver: "local", labels: labels}
	}
	v := f.volumes[body.Name]
	ok(w, map[string]any{"Name": v.name, "Driver": v.driver, "Labels": v.labels})
}

func (f *Fake) inspectVolume(w http.ResponseWriter, seg string) {
	name := pathName(seg)
	if f.vanished(name) {
		fail(w, 404, "No such object: %s", name)
		return
	}
	v, exists := f.volumes[name]
	if !exists {
		fail(w, 404, "no such volume: %s", name)
		return
	}
	ok(w, map[string]any{"Name": v.name, "Driver": v.driver, "Labels": v.labels})
}

func (f *Fake) removeVolume(w http.ResponseWriter, seg string) {
	name := pathName(seg)
	v, exists := f.volumes[name]
	if !exists || (f.RemoveMissing != "" && name == f.RemoveMissing) {
		fail(w, 404, "no such volume: %s", name)
		return
	}
	// A volume a container MOUNTS cannot be removed — the daemon refuses and the container
	// keeps its data. Containers in ANY state count: a stopped container still holds its
	// mount config.
	for _, c := range f.containers {
		for _, m := range c.mounts {
			if m.typ == "volume" && m.name == name {
				fail(w, 409, "remove %s: volume is in use - [%s]", name, c.id)
				return
			}
		}
	}
	delete(f.volumes, v.name)
	ok(w, nil)
}

func (f *Fake) listVolumes(w http.ResponseWriter, r *http.Request) {
	labels, err := parseLabelFilters(r.URL.Query().Get("filters"))
	if err != nil {
		fail(w, 400, "%v", err)
		return
	}
	out := []map[string]any{}
	var names []string
	for n := range f.volumes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := f.volumes[n]
		if !labelsMatch(v.labels, labels) {
			continue
		}
		out = append(out, map[string]any{"Name": v.name, "Labels": v.labels})
	}
	ok(w, map[string]any{"Volumes": out})
}

// --- networks --------------------------------------------------------------------------------

func (f *Fake) createNetwork(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "fake engine: unreadable network create body: %v", err)
		return
	}
	if !checkName(body.Name) {
		fail(w, 400, "invalid network name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed", body.Name)
		return
	}
	// D38: Docker does NOT guarantee name-conflict detection for networks, so a delayed
	// original and a reissue can both succeed with the same name AND nonce — reproduced
	// under the knob; refused otherwise, as the common case observes.
	if f.findNetwork(body.Name) != nil && !f.DuplicateNetworkNames {
		fail(w, 409, "network with name %s already exists", body.Name)
		return
	}
	// The driver actually recorded: the REQUEST first (so `bridge`-explicit is observable),
	// the daemon default when the request names none (D29's stated threat: a daemon whose
	// default is not a NAT bridge), and the fabrication knob on top of both — it exists to
	// produce a network the client cannot legitimately create, for the preflight refusals to
	// refuse.
	driver := body.Driver
	if driver == "" {
		driver = f.NetDefaultDriver
		if driver == "" {
			driver = "bridge"
		}
	}
	if f.NetDriverOverride != "" {
		driver = f.NetDriverOverride
	}
	labels := body.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	n := &fakeNetwork{id: f.longID(), name: body.Name, driver: driver, labels: labels, thi: f.NetTHI}
	f.networks = append(f.networks, n)
	ok(w, map[string]string{"Id": n.id})
}

func (f *Fake) inspectNetwork(w http.ResponseWriter, seg string) {
	ref := pathName(seg)
	if f.vanished(ref) {
		fail(w, 404, "No such object: %s", ref)
		return
	}
	n := f.findNetwork(ref)
	if n == nil {
		fail(w, 404, "network %s not found", ref)
		return
	}
	options := map[string]string{}
	if n.thi != "" {
		options["com.docker.network.bridge.trusted_host_interfaces"] = n.thi
	}
	ok(w, map[string]any{
		"Id": n.id, "Name": n.name, "Driver": n.driver, "Labels": n.labels, "Options": options,
	})
}

func (f *Fake) removeNetwork(w http.ResponseWriter, seg string) {
	ref := pathName(seg)
	n := f.findNetwork(ref)
	if n == nil || (f.RemoveMissing != "" && ref == f.RemoveMissing) {
		fail(w, 404, "network %s not found", ref)
		return
	}
	// A network with an ACTIVE endpoint cannot be removed — the state the teardown ordering
	// (detach, then remove) exists to avoid. MEASURED 2026-08-25 (Engine 28.4.0): only a
	// RUNNING container holds an active endpoint; a created-or-stopped attachment does not
	// block removal — the daemon released (or never materialized) its endpoint.
	for _, c := range f.containers {
		if c.state != "running" {
			continue
		}
		for _, ep := range c.endpoints {
			if ep.netID == n.id {
				fail(w, 409, "error while removing network: network %s id %s has active endpoints", ref, n.id)
				return
			}
		}
	}
	for i, cand := range f.networks {
		if cand == n {
			f.networks = append(f.networks[:i], f.networks[i+1:]...)
			break
		}
	}
	ok(w, nil)
}

func (f *Fake) connectNetwork(w http.ResponseWriter, r *http.Request, seg string) {
	ref := pathName(seg)
	var body struct {
		Container      string `json:"Container"`
		EndpointConfig struct {
			Aliases    []string `json:"Aliases"`
			GwPriority int      `json:"GwPriority"`
		} `json:"EndpointConfig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "fake engine: unreadable connect body: %v", err)
		return
	}
	// The knob fabricates a daemon-side attach failure and is answered BEFORE the lookup —
	// either way the command fails; the knob can only change which error, never whether the
	// attach happens.
	if f.ConnectFail {
		fail(w, 500, "failed to connect %s to %s", body.Container, ref)
		return
	}
	n := f.findNetwork(ref)
	if n == nil {
		fail(w, 404, "network %s not found", ref)
		return
	}
	c := f.findContainer(body.Container)
	if c == nil {
		fail(w, 404, "No such container: %s", body.Container)
		return
	}
	// A container in PRIVATE (none) mode cannot join a network — the daemon says so in these
	// words, and the reference cites that refusal as the reason `none` is rejected at
	// creation.
	if c.netmode == "none" {
		fail(w, 403, "container cannot be connected to multiple networks with one of the networks in private (none) mode")
		return
	}
	// Connecting the SAME network twice: for a RUNNING container it is a conflict, not a
	// second endpoint — a reconnect-every-pass loop must error here as it does against a real
	// daemon. MEASURED 2026-08-25 (Engine 28.4.0): on a NON-running container the daemon
	// accepts the call and updates the stored endpoint config instead (no error observed;
	// modelled as a config replace).
	for i, ep := range c.endpoints {
		if ep.netID != n.id {
			continue
		}
		if c.state == "running" {
			fail(w, 403, "endpoint with name %s already exists in network %s", c.name, ref)
			return
		}
		// Connect-time endpoints are stored under the network NAME (the daemon resolves the
		// reference at connect; measured on a running container by the acceptance gw-priority
		// case — the never-started connect key is unmeasured and modelled the same way).
		c.endpoints[i] = &fakeEndpoint{
			netID:   n.id,
			netName: n.name,
			key:     n.name,
			aliases: append(append([]string(nil), body.EndpointConfig.Aliases...), c.name),
			gw:      body.EndpointConfig.GwPriority,
		}
		ok(w, nil)
		return
	}
	c.endpoints = append(c.endpoints, &fakeEndpoint{
		netID:   n.id,
		netName: n.name,
		key:     n.name,
		aliases: append(append([]string(nil), body.EndpointConfig.Aliases...), c.name),
		gw:      body.EndpointConfig.GwPriority,
	})
	ok(w, nil)
}

func (f *Fake) disconnectNetwork(w http.ResponseWriter, r *http.Request, seg string) {
	ref := pathName(seg)
	var body struct {
		Container string `json:"Container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "fake engine: unreadable disconnect body: %v", err)
		return
	}
	n := f.findNetwork(ref)
	if n == nil {
		fail(w, 404, "network %s not found", ref)
		return
	}
	c := f.findContainer(body.Container)
	if c == nil {
		fail(w, 404, "No such container: %s", body.Container)
		return
	}
	idx := -1
	for i, ep := range c.endpoints {
		if ep.netID == n.id {
			idx = i
			break
		}
	}
	// Not attached is an ERROR, not a no-op: "everything is detached" and "this was never
	// attached" are the same answer only to a fake.
	if idx < 0 {
		fail(w, 500, "container %s is not connected to network %s", c.name, ref)
		return
	}
	// DisconnectSilent reproduces "one detach silently fails": success reported, attachment
	// survives — answered AFTER the checks above so it fabricates a failed detach of a REAL
	// attachment and nothing else.
	if !f.DisconnectSilent {
		c.endpoints = append(c.endpoints[:idx], c.endpoints[idx+1:]...)
	}
	ok(w, nil)
}

func (f *Fake) listNetworks(w http.ResponseWriter, r *http.Request) {
	labels, err := parseLabelFilters(r.URL.Query().Get("filters"))
	if err != nil {
		fail(w, 400, "%v", err)
		return
	}
	out := []map[string]any{}
	for _, n := range f.networks {
		if !labelsMatch(n.labels, labels) {
			continue
		}
		out = append(out, map[string]any{"Id": n.id, "Name": n.name, "Labels": n.labels})
	}
	ok(w, out)
}

// --- images ----------------------------------------------------------------------------------

func (f *Fake) pullImage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, tag := q.Get("fromImage"), q.Get("tag")
	ref := name
	switch {
	case strings.HasPrefix(tag, "sha256:"):
		ref = name + "@" + tag
	case tag != "":
		ref = name + ":" + tag
	}
	f.LastPullRef = ref
	f.LastPullAuth = nil
	if hdr := r.Header.Get("X-Registry-Auth"); hdr != "" {
		raw, err := base64.URLEncoding.DecodeString(hdr)
		if err != nil {
			fail(w, 400, "invalid X-Registry-Auth: %v", err)
			return
		}
		var ac map[string]string
		if err := json.Unmarshal(raw, &ac); err != nil {
			fail(w, 400, "invalid X-Registry-Auth payload: %v", err)
			return
		}
		f.LastPullAuth = ac
	}
	switch f.PullOutcome {
	case "", "ok":
		f.registerImage(ref)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "Pulling from " + name})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "Status: Downloaded newer image for " + ref})
	case "notfound":
		fail(w, 404, "manifest for %s not found: manifest unknown", ref)
	case "auth":
		fail(w, 500, "denied: requested access to the resource is denied")
	case "neterr":
		fail(w, 500, "dial tcp: lookup registry: no such host")
	case "streamerr":
		// Failure ARRIVING MID-STREAM after a 200 — the shape only the stream reader catches.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "Pulling from " + name})
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unexpected EOF from registry"})
	default:
		fail(w, 500, "fake engine: unknown PullOutcome %q", f.PullOutcome)
	}
}

func (f *Fake) inspectImage(w http.ResponseWriter, seg string) {
	ref := pathName(seg)
	if f.vanished(ref) {
		fail(w, 404, "No such object: %s", ref)
		return
	}
	id, exists := f.images[ref]
	if !exists {
		fail(w, 404, "No such image: %s", ref)
		return
	}
	ok(w, map[string]any{"Id": id, "RepoDigests": []string{ref}})
}
