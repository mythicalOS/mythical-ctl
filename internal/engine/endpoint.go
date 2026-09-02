package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultSocket is the platform default daemon socket. This arc ships darwin/linux binaries
// only, so there is exactly one.
const defaultSocket = "/var/run/docker.sock"

// envValue reads KEY from an environment in []string{"KEY=value", ...} form. The LAST
// occurrence wins, matching what a real exec environment does.
func envValue(env []string, key string) (string, bool) {
	val, found := "", false
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			val, found = e[len(prefix):], true
		}
	}
	return val, found
}

// dockerConfigRoot is the Docker CLI config directory: `$DOCKER_CONFIG` when set, else
// `<user home>/.docker`. "User home" is the operating user's home — never the mythical home:
// this is where the DOCKER CLI keeps its state, and the point of reading it is to dial the
// same daemon and present the same credentials that CLI would.
func dockerConfigRoot(env []string, home string) string {
	if v, ok := envValue(env, "DOCKER_CONFIG"); ok && v != "" {
		return v
	}
	return filepath.Join(home, ".docker")
}

// dockerConfig is the subset of `<config root>/config.json` this package reads.
type dockerConfig struct {
	CurrentContext string                     `json:"currentContext"`
	Auths          map[string]configAuthEntry `json:"auths"`
	CredsStore     string                     `json:"credsStore"`
	CredHelpers    map[string]string          `json:"credHelpers"`
}

// loadDockerConfig reads the config file. A MISSING file is an empty config — a machine that
// has never run `docker login` has none and everything still works anonymously against the
// default socket. A file that exists but cannot be parsed is an error: guessing at a config
// that IS there is how the wrong daemon gets dialed.
func loadDockerConfig(env []string, home string) (*dockerConfig, error) {
	p := filepath.Join(dockerConfigRoot(env, home), "config.json")
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &dockerConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("engine: cannot read the docker config at %s: %w", p, err)
	}
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("engine: the docker config at %s is not valid JSON: %w", p, err)
	}
	return &cfg, nil
}

// notLocal is the one refusal wording for every non-local endpoint, ported from the
// reference preflight: host paths you bind are resolved on the DAEMON's filesystem, so a
// remote daemon would validate one machine's paths and mount another's (D30/§4b.3).
func notLocal(endpoint string) error {
	return fmt.Errorf("engine: the docker daemon at %q is not local, and mythical-ctl requires a local one — "+
		"host paths you bind are resolved on the DAEMON's filesystem, so a remote daemon would "+
		"validate one machine's paths and mount another's (Docker Desktop's managed VM is fine)", endpoint)
}

// socketFromEndpoint accepts ONLY local `unix://` endpoints.
//
// The reference accepted the LOCAL form of a Windows named pipe as well
// (`npipe:////./…` — Docker Desktop on Windows), but this arc ships no Windows binary, so the
// resolver refuses `npipe://` NAMING the platform gap rather than silently lumping it in with
// remote daemons: an operator on Windows should read "not built for this platform", not "your
// daemon is remote". Everything else — tcp (INCLUDING tcp://127.0.0.1: a loopback TCP daemon
// can be an SSH-forwarded port to another machine, and the endpoint string cannot tell us
// which), ssh, an unparseable value — is refused with the daemon-filesystem warning.
func socketFromEndpoint(endpoint string) (string, error) {
	if strings.HasPrefix(endpoint, "unix://") {
		p := strings.TrimPrefix(endpoint, "unix://")
		if p == "" {
			return "", fmt.Errorf("engine: the endpoint %q names no socket path", endpoint)
		}
		return p, nil
	}
	if strings.HasPrefix(endpoint, "npipe://") {
		return "", fmt.Errorf("engine: the endpoint %q is a Windows named pipe, and this build ships no Windows binary — a Docker Desktop npipe endpoint is local, but this platform gap is a refusal, not a fallback", endpoint)
	}
	return "", notLocal(endpoint)
}

// ResolveEndpoint resolves the local daemon socket the way the docker CLI would, FAIL-CLOSED.
//
// Precedence, MEASURED by the reference implementation (its comment ports; do not reorder
// without re-measuring): `DOCKER_HOST` wins when set — a remote DOCKER_HOST beside a local
// context must refuse, so it is checked FIRST and the context only when it is unset. Otherwise
// the context selected by `DOCKER_CONTEXT` when that is set; otherwise the config's
// `currentContext`; with no context selected at all, the platform default socket. (The `-c` /
// `--context` FLAG does outrank DOCKER_HOST in the docker CLI; this code never passes one, and
// a flag we do not pass is not a bypass.)
//
// The context named `default` is synthesized by the CLI and has NO metadata entry — it
// resolves straight to the platform default socket. Any other named context's endpoint is
// read from the context store on disk (`<config root>/contexts/meta/<sha256(name)>/meta.json`
// — this binary cannot shell out to the docker CLI, so the store is read directly), and a
// non-default context that cannot be read resolves to REFUSE, never to a default: a context
// the operator selected and we cannot interpret is one we cannot place on either side of the
// locality guarantee.
func ResolveEndpoint(env []string, home string) (string, error) {
	if v, ok := envValue(env, "DOCKER_HOST"); ok && v != "" {
		return socketFromEndpoint(v)
	}

	ctxName, _ := envValue(env, "DOCKER_CONTEXT")
	if ctxName == "" {
		cfg, err := loadDockerConfig(env, home)
		if err != nil {
			return "", err
		}
		ctxName = cfg.CurrentContext
	}
	if ctxName == "" || ctxName == "default" {
		return defaultSocket, nil
	}

	sum := sha256.Sum256([]byte(ctxName))
	metaPath := filepath.Join(dockerConfigRoot(env, home), "contexts", "meta", hex.EncodeToString(sum[:]), "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return "", fmt.Errorf("engine: the selected docker context %q cannot be read from the context store (%s): %v — refusing rather than guessing at a default", ctxName, metaPath, err)
	}
	var meta struct {
		Endpoints struct {
			Docker struct {
				Host string `json:"Host"`
			} `json:"docker"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("engine: the docker context %q has an unreadable metadata record: %v", ctxName, err)
	}
	if meta.Endpoints.Docker.Host == "" {
		return "", fmt.Errorf("engine: the docker context %q names no docker endpoint", ctxName)
	}
	return socketFromEndpoint(meta.Endpoints.Docker.Host)
}
