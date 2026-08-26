package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Registry authentication, resolved the way the docker CLI the reference shells out to does.
// An API pull without `X-Registry-Auth` fails on authenticated registries the bash handles
// transparently, so the client resolves credentials from the SAME Docker config root the
// endpoint resolver uses, with the CLI's full precedence, pinned EXACTLY:
//
//	a registry-specific `credHelpers` entry wins, then `credsStore`, and only otherwise the
//	inline `auths` — with `DOCKER_AUTH_CONFIG` overlaying that FALLBACK when set (it overlays
//	the inline auths, never the helpers).
//
// Helpers execute as the named `docker-credential-<name>` from PATH — the CLI's own
// mechanism, no new trust surface. Anonymous when nothing names the registry.

// hubAuthKey is the config key Docker Hub credentials are stored under — a legacy URL, kept
// because every `docker login` ever run against Hub wrote it.
const hubAuthKey = "https://index.docker.io/v1/"

// configAuthEntry is one inline `auths` record.
type configAuthEntry struct {
	Auth          string `json:"auth"` // base64(user:password)
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// authConfig is the moby AuthConfig wire shape carried in X-Registry-Auth.
type authConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
}

// registryOf extracts the registry host from an image reference. The first path component is
// a registry only when it can be one — it contains a dot or a port, or is `localhost`;
// otherwise the reference is a Hub repository (`busybox`, `library/busybox`) and the registry
// is Docker Hub, normalized to `index.docker.io`.
func registryOf(ref string) string {
	host, _, found := strings.Cut(ref, "/")
	if !found || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return "index.docker.io"
	}
	return normalizeRegistryHost(host)
}

// normalizeRegistryHost folds the spellings one registry hides behind: a config key may be a
// bare host, a scheme-prefixed URL, or the Hub legacy URL, and the CLI matches them by
// HOSTNAME. `docker.io` and `registry-1.docker.io` are Hub's pull endpoint spellings; the
// canonical auth hostname is `index.docker.io`.
func normalizeRegistryHost(key string) string {
	h := key
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if h == "docker.io" || h == "registry-1.docker.io" {
		return "index.docker.io"
	}
	return h
}

// serverAddressFor is the ServerAddress the daemon (and a credential helper) is handed: the
// Hub legacy URL for Hub, the plain host for everything else.
func serverAddressFor(host string) string {
	if host == "index.docker.io" {
		return hubAuthKey
	}
	return host
}

// lookPathIn resolves an executable name against the PATH in the GIVEN environment — not the
// process's — so credential-helper resolution is exactly as hermetic as the config reading
// beside it.
func lookPathIn(env []string, name string) (string, error) {
	pathVal, _ := envValue(env, "PATH")
	for _, dir := range filepath.SplitList(pathVal) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("engine: credential helper %q not found on PATH", name)
}

// errCredentialsNotFound is the standardized message every docker-credential-* helper emits
// (docker-credential-helpers, credentials.ErrCredentialsNotFound) when the store holds no
// entry for the server; the CLI matches it verbatim.
const errCredentialsNotFound = "credentials not found in native keychain"

// runCredHelper executes `docker-credential-<name> get` with the server address on stdin and
// reads the CLI's helper protocol back. A helper answering Username `<token>` is handing back
// an identity token, not a password — the CLI's own convention.
func runCredHelper(env []string, helper, serverAddress string) (*authConfig, error) {
	bin, err := lookPathIn(env, "docker-credential-"+helper)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "get")
	cmd.Env = append([]string(nil), env...)
	cmd.Stdin = strings.NewReader(serverAddress)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		// The CLI's own convention (docker/cli, native_store.go): a helper exiting non-zero
		// with EXACTLY the standardized not-found message is reporting an ABSENCE, and the
		// pull proceeds ANONYMOUSLY — a configured credsStore with no entry for a public
		// registry is the everyday case (Docker Desktop's keychain helper on a public pull).
		// Inline `auths` are NOT consulted afterwards, exactly as the CLI does not: the store
		// is authoritative for the host once configured. Every OTHER failure is fatal, in the
		// helper's own words (§7.3) — never a silent fall-through to weaker credentials.
		if strings.TrimSpace(out.String()) == errCredentialsNotFound || strings.TrimSpace(stderr.String()) == errCredentialsNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("engine: credential helper %q failed: %v: %s", helper, err, strings.TrimSpace(stderr.String()+out.String()))
	}
	var got struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		return nil, fmt.Errorf("engine: credential helper %q answered something that is not the helper protocol: %v", helper, err)
	}
	if got.Username == "<token>" {
		return &authConfig{IdentityToken: got.Secret, ServerAddress: serverAddress}, nil
	}
	return &authConfig{Username: got.Username, Password: got.Secret, ServerAddress: serverAddress}, nil
}

// inlineAuthFor finds the inline `auths` record for a host, matching keys by normalized
// hostname the way the CLI does, and decodes the base64 `auth` pair when that is the spelling
// present.
func inlineAuthFor(auths map[string]configAuthEntry, host string) (*authConfig, error) {
	key, err := lookupKey(keysOf(auths), host, "inline auths")
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, nil
	}
	{
		entry := auths[key]
		ac := &authConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			IdentityToken: entry.IdentityToken,
			ServerAddress: serverAddressFor(host),
		}
		if entry.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return nil, fmt.Errorf("engine: the stored auth for %q is not valid base64: %v", key, err)
			}
			user, pass, found := strings.Cut(string(raw), ":")
			if !found {
				return nil, fmt.Errorf("engine: the stored auth for %q is not a user:password pair", key)
			}
			ac.Username, ac.Password = user, pass
		}
		return ac, nil
	}
}

// keysOf lists a map's keys, SORTED — every lookup below walks keys in one order, so two runs
// over the same config give the same answer.
func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookupKey ports the docker CLI's lookup order and closes its one open door. The CLI tries
// the EXACT config key first (`AuthConfigs[serverAddress]`, `CredentialHelpers[hostname]`)
// and only then falls back to matching keys by normalized hostname — where it iterates a Go
// map, so a config carrying both a canonical and a legacy spelling of one registry answers
// NONDETERMINISTICALLY. Here: the exact key wins; a normalized fallback is taken only when it
// is UNIQUE; two legacy spellings that disagree are a REFUSAL, never a coin toss.
func lookupKey(keys []string, host, what string) (string, error) {
	exact := serverAddressFor(host)
	var candidates []string
	for _, k := range keys {
		if k == exact || k == host {
			return k, nil
		}
		if normalizeRegistryHost(k) == host {
			candidates = append(candidates, k)
		}
	}
	switch len(candidates) {
	case 0:
		return "", nil
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("engine: the docker config's %s name registry %q under %d equivalent keys (%s) and no exact one — refusing to guess which credentials apply; keep one entry", what, host, len(candidates), strings.Join(candidates, ", "))
	}
}

// resolveRegistryAuth resolves the X-Registry-Auth header value for a pull of `ref`, or ""
// for an anonymous pull. The header is the moby contract: base64url-encoded AuthConfig JSON.
func resolveRegistryAuth(env []string, home string, ref string) (string, error) {
	host := registryOf(ref)
	cfg, err := loadDockerConfig(env, home)
	if err != nil {
		return "", err
	}

	var ac *authConfig
	helperKey, err := lookupKey(keysOf(cfg.CredHelpers), host, "credHelpers")
	if err != nil {
		return "", err
	}
	helper := cfg.CredHelpers[helperKey]
	switch {
	case helper != "":
		ac, err = runCredHelper(env, helper, serverAddressFor(host))
	case cfg.CredsStore != "":
		ac, err = runCredHelper(env, cfg.CredsStore, serverAddressFor(host))
	default:
		// The inline-auths FALLBACK, with DOCKER_AUTH_CONFIG overlaying it when set. The
		// overlay wins per-registry; registries it does not name still resolve from the file.
		auths := cfg.Auths
		if overlay, ok := envValue(env, "DOCKER_AUTH_CONFIG"); ok && overlay != "" {
			var oc struct {
				Auths map[string]configAuthEntry `json:"auths"`
			}
			if err := json.Unmarshal([]byte(overlay), &oc); err != nil {
				return "", fmt.Errorf("engine: DOCKER_AUTH_CONFIG is set but is not valid JSON: %v", err)
			}
			if hit, herr := inlineAuthFor(oc.Auths, host); herr != nil {
				return "", herr
			} else if hit != nil {
				ac = hit
				break
			}
		}
		ac, err = inlineAuthFor(auths, host)
	}
	if err != nil {
		return "", err
	}
	if ac == nil || (ac.Username == "" && ac.Password == "" && ac.IdentityToken == "") {
		return "", nil // anonymous: nothing names this registry
	}
	payload, err := json.Marshal(ac)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(payload), nil
}
