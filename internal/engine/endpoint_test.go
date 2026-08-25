package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The endpoint-locality rows of tests/unit/preflight.bats are inventoried in Task 16's
// preflight_test.go (they are that file's tests); the resolver they now exercise lives here.
// runtime.bats's "the daemon endpoint is read from the active context (D30)" is inventoried in
// client_test.go -> TestResolveEndpointContextSelection below.

// writeContext puts a context's meta.json where the docker CLI's store keeps it.
func writeContext(t *testing.T, root, name, host string) {
	t.Helper()
	sum := sha256.Sum256([]byte(name))
	dir := filepath.Join(root, "contexts", "meta", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"Name":"` + name + `","Endpoints":{"docker":{"Host":"` + host + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, root, body string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveEndpointDockerHost(t *testing.T) {
	home := t.TempDir()
	// A unix DOCKER_HOST is accepted — including Docker Desktop's per-user socket.
	p, err := ResolveEndpoint([]string{"DOCKER_HOST=unix:///var/run/docker.sock"}, home)
	if err != nil || p != "/var/run/docker.sock" {
		t.Fatalf("%q %v", p, err)
	}
	p, err = ResolveEndpoint([]string{"DOCKER_HOST=unix://" + home + "/.docker/run/docker.sock"}, home)
	if err != nil || p != home+"/.docker/run/docker.sock" {
		t.Fatalf("desktop per-user socket: %q %v", p, err)
	}
	// tcp is refused EVEN ON LOOPBACK — an SSH-forwarded port looks local and is not
	// necessarily so — and the refusal carries the daemon-filesystem reason.
	for _, ep := range []string{"tcp://192.0.2.9:2376", "tcp://127.0.0.1:2375", "ssh://user@host", "garbage"} {
		_, err := ResolveEndpoint([]string{"DOCKER_HOST=" + ep}, home)
		if err == nil || !strings.Contains(err.Error(), "DAEMON's filesystem") {
			t.Errorf("%s: %v", ep, err)
		}
	}
	// npipe is a DECLARED platform gap, not a remote daemon: the refusal names the platform,
	// for the local and the remote spelling alike (no Windows binary ships from this arc).
	for _, ep := range []string{"npipe:////./pipe/dockerDesktopLinuxEngine", "npipe:////remote-host/pipe/docker_engine"} {
		_, err := ResolveEndpoint([]string{"DOCKER_HOST=" + ep}, home)
		if err == nil || !strings.Contains(err.Error(), "Windows") {
			t.Errorf("%s: %v", ep, err)
		}
	}
}

// The MEASURED precedence: DOCKER_HOST wins when set; the context is consulted only when it
// is unset. Do not reorder without re-measuring (the reference measured it against a live
// CLI: a local DOCKER_HOST beside a remote context reached the LOCAL daemon).
func TestResolveEndpointPrecedence(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	writeContext(t, root, "remote-ctx", "tcp://192.0.2.9:2376")
	// Local DOCKER_HOST + remote context: the LOCAL daemon answers.
	p, err := ResolveEndpoint([]string{
		"DOCKER_HOST=unix:///var/run/docker.sock", "DOCKER_CONTEXT=remote-ctx",
	}, home)
	if err != nil || p != "/var/run/docker.sock" {
		t.Fatalf("DOCKER_HOST must win: %q %v", p, err)
	}
	// Remote DOCKER_HOST + local context: refused — the context must not launder it.
	writeContext(t, root, "local-ctx", "unix:///var/run/docker.sock")
	if _, err := ResolveEndpoint([]string{
		"DOCKER_HOST=tcp://192.0.2.9:2376", "DOCKER_CONTEXT=local-ctx",
	}, home); err == nil {
		t.Fatal("a remote DOCKER_HOST beside a local context must refuse")
	}
	// The control: the remote context alone IS consulted, and refused as remote.
	if _, err := ResolveEndpoint([]string{"DOCKER_CONTEXT=remote-ctx"}, home); err == nil {
		t.Fatal("the remote context alone must refuse")
	}
}

func TestResolveEndpointContextSelection(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	writeContext(t, root, "desktop", "unix://"+home+"/desktop.sock")
	// DOCKER_CONTEXT selects from the store.
	p, err := ResolveEndpoint([]string{"DOCKER_CONTEXT=desktop"}, home)
	if err != nil || p != home+"/desktop.sock" {
		t.Fatalf("DOCKER_CONTEXT: %q %v", p, err)
	}
	// currentContext from config.json when DOCKER_CONTEXT is unset.
	writeConfig(t, root, `{"currentContext":"desktop"}`)
	p, err = ResolveEndpoint(nil, home)
	if err != nil || p != home+"/desktop.sock" {
		t.Fatalf("currentContext: %q %v", p, err)
	}
	// The `default` context is SYNTHESIZED — no metadata entry exists, and none is read.
	writeConfig(t, root, `{"currentContext":"default"}`)
	p, err = ResolveEndpoint(nil, home)
	if err != nil || p != "/var/run/docker.sock" {
		t.Fatalf("default context: %q %v", p, err)
	}
	// No context selected at all: the platform default socket.
	p, err = ResolveEndpoint(nil, t.TempDir())
	if err != nil || p != "/var/run/docker.sock" {
		t.Fatalf("no context: %q %v", p, err)
	}
	// An ssh:// context endpoint is refused.
	writeContext(t, root, "sshctx", "ssh://user@host")
	if _, err := ResolveEndpoint([]string{"DOCKER_CONTEXT=sshctx"}, home); err == nil {
		t.Fatal("ssh context must refuse")
	}
}

// A NON-DEFAULT context that cannot be read resolves to REFUSE, never to a default: a context
// the operator selected and we cannot interpret cannot be placed on either side of the
// locality guarantee.
func TestResolveEndpointUnreadableContextRefuses(t *testing.T) {
	home := t.TempDir()
	if _, err := ResolveEndpoint([]string{"DOCKER_CONTEXT=ghost"}, home); err == nil ||
		!strings.Contains(err.Error(), "refusing rather than guessing") {
		t.Fatalf("missing context store entry must refuse: %v", err)
	}
	// And so does a config.json that exists but cannot be parsed.
	root := filepath.Join(home, ".docker")
	writeConfig(t, root, `{not json`)
	if _, err := ResolveEndpoint(nil, home); err == nil {
		t.Fatal("an unparseable config that IS there must refuse")
	}
}

// DOCKER_CONFIG relocates the config root — the CLI honors it, so the resolver must too, for
// the context store and the currentContext alike.
func TestResolveEndpointDockerConfigRoot(t *testing.T) {
	home := t.TempDir()
	altRoot := filepath.Join(t.TempDir(), "custom-docker")
	writeContext(t, altRoot, "alt", "unix://"+home+"/alt.sock")
	writeConfig(t, altRoot, `{"currentContext":"alt"}`)
	p, err := ResolveEndpoint([]string{"DOCKER_CONFIG=" + altRoot}, home)
	if err != nil || p != home+"/alt.sock" {
		t.Fatalf("DOCKER_CONFIG root: %q %v", p, err)
	}
}
