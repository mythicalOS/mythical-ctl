package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Registry authentication, resolved the way the docker CLI the reference shells out to does.
// An API pull without `X-Registry-Auth` fails on authenticated registries the bash handles
// transparently, so the client resolves credentials from the SAME Docker config root the
// endpoint resolver uses, with the CLI's full precedence, pinned EXACTLY against
// docker/cli v28.4.0 (configfile.GetCredentialsStore + memorystore):
//
//	`DOCKER_AUTH_CONFIG`, when set, is a memory store WRAPPED AROUND whichever store the
//	config selects — so an entry there wins over EVERYTHING below it, by exact key; then a
//	registry-specific `credHelpers` entry (exact key), then `credsStore`, and only otherwise
//	the inline `auths` (exact key, then a unique legacy spelling).
//
// (An earlier reading, and the plan text it produced, had the overlay touching only the
// inline fallback; the CLI source says otherwise, and this is corrected at the source.)
// One deliberate sharpening: an unparseable DOCKER_AUTH_CONFIG is a REFUSAL here, where the
// CLI logs a warning and continues with the store — an operator who set it meant it.
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
func inlineAuthFor(auths map[string]configAuthEntry, host, what string, legacyFallback bool) (*authConfig, error) {
	key, err := lookupKey(keysOf(auths), host, what, legacyFallback)
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

// parseEnvAuthConfig is docker/cli v28.4.0's parseEnvConfig, ported field for field: the
// overlay's SCHEMA is strict — exactly one JSON object, only `auths` at the top level, only
// `auth` per entry (DisallowUnknownFields on both), `auth` REQUIRED and non-empty, decoded as
// standard base64 `user:password` with a non-empty user and NUL-trimmed password. A lenient
// reading (accepting `username`/`password`, ignoring extra keys) would let an overlay the CLI
// REJECTS outrank the operator's helpers and store. The CLI reports a rejected overlay on
// stderr and continues with the store; here it is a refusal — the documented sharpening.
func parseEnvAuthConfig(v string) (map[string]authConfig, error) {
	var env struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	dec := json.NewDecoder(strings.NewReader(v))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("engine: DOCKER_AUTH_CONFIG is set but is not the CLI's schema ({\"auths\":{\"<registry>\":{\"auth\":\"<base64 user:password>\"}}}): %v", err)
	}
	if dec.More() {
		return nil, errors.New("engine: DOCKER_AUTH_CONFIG does not support more than one JSON object")
	}
	out := make(map[string]authConfig, len(env.Auths))
	for addr, e := range env.Auths {
		if e.Auth == "" {
			return nil, fmt.Errorf("engine: DOCKER_AUTH_CONFIG is missing key `auth` for %s", addr)
		}
		user, pass, err := decodeAuthPair(e.Auth)
		if err != nil {
			return nil, fmt.Errorf("engine: DOCKER_AUTH_CONFIG entry for %s: %v", addr, err)
		}
		out[addr] = authConfig{Username: user, Password: pass, ServerAddress: addr}
	}
	return out, nil
}

// decodeAuthPair is the CLI's decodeAuth: standard base64, `user:password`, user non-empty,
// password trimmed of NULs (a padding artifact the CLI strips too).
func decodeAuthPair(s string) (string, string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", fmt.Errorf("the stored auth is not valid base64: %v", err)
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" {
		return "", "", errors.New("the stored auth is not a user:password pair")
	}
	return user, strings.Trim(pass, "\x00"), nil
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

// lookupKey ports the docker CLI's lookup order and closes its one open door. The CLI's
// EXACT key is the server address — `AuthConfigs[serverAddress]` for inline auths (the Hub
// legacy URL for Hub, the bare host otherwise) and `CredentialHelpers[hostname]` for helpers
// — and the two tables differ AFTER that: inline auths fall back to matching keys by
// normalized hostname (file_store's legacy path), where the CLI iterates a Go map and a
// config carrying both a canonical and a legacy spelling answers NONDETERMINISTICALLY;
// credHelpers get NO fallback at all (getConfiguredCredentialStore is a plain map lookup).
// Here: the exact key wins; with legacyFallback, a normalized match is taken only when it is
// UNIQUE and two legacy spellings that disagree are a REFUSAL, never a coin toss; without
// it, a URL-spelled helper key is simply not a match — exactly as the CLI would not run it.
func lookupKey(keys []string, host, what string, legacyFallback bool) (string, error) {
	exact := serverAddressFor(host)
	var candidates []string
	for _, k := range keys {
		if k == exact {
			return k, nil
		}
		if legacyFallback && normalizeRegistryHost(k) == host {
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
	// 1. DOCKER_AUTH_CONFIG — the CLI's memory store, wrapped around the selected store: an
	//    entry for this registry wins over helpers, credsStore and the file alike (exact key,
	//    as memorystore.Get is); registries it does not name fall through to the rest.
	if overlay, ok := envValue(env, "DOCKER_AUTH_CONFIG"); ok && overlay != "" {
		entries, perr := parseEnvAuthConfig(overlay)
		if perr != nil {
			return "", perr
		}
		key, kerr := lookupKey(keysOf(entries), host, "DOCKER_AUTH_CONFIG", false)
		if kerr != nil {
			return "", kerr
		}
		if key != "" {
			e := entries[key]
			ac = &e
		}
	}
	if ac == nil {
		// 2. a registry-specific helper (exact key), 3. the store, 4. the inline file entries.
		helperKey, err := lookupKey(keysOf(cfg.CredHelpers), host, "credHelpers", false)
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
			ac, err = inlineAuthFor(cfg.Auths, host, "inline auths", true)
		}
		if err != nil {
			return "", err
		}
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
