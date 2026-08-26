package engine

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Registry-auth resolution has no bats analogue (the bash shelled to the docker CLI, which
// resolved credentials itself); the plan's round-8/round-10 corrections pin the CLI's
// precedence here instead: credHelpers > credsStore > inline auths, with DOCKER_AUTH_CONFIG
// overlaying only the inline fallback. The wire half (the fake decoding X-Registry-Auth and
// comparing the exact AuthConfig) is TestPullAuthHeader in client_test.go.

func decodeHeader(t *testing.T, hdr string) map[string]string {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(hdr)
	if err != nil {
		t.Fatalf("header is not base64url: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("header is not AuthConfig JSON: %v", err)
	}
	return m
}

func TestRegistryOf(t *testing.T) {
	for ref, want := range map[string]string{
		"busybox":                        "index.docker.io",
		"library/busybox:1.36":           "index.docker.io",
		"docker.io/library/busybox":      "index.docker.io",
		"registry-1.docker.io/library/b": "index.docker.io",
		"reg.example/probe@sha256:abc":   "reg.example",
		"localhost:5000/x":               "localhost:5000",
		"my.registry:8443/team/img:v1":   "my.registry:8443",
	} {
		if got := registryOf(ref); got != want {
			t.Errorf("%s: got %q want %q", ref, got, want)
		}
	}
}

func TestInlineAuths(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	// The Hub legacy key answers a bare Hub reference — hostname normalization, not literal
	// key match. The stored `auth` pair is base64(user:password).
	pair := base64.StdEncoding.EncodeToString([]byte("hubuser:hubpass"))
	writeConfig(t, root, `{"auths":{"https://index.docker.io/v1/":{"auth":"`+pair+`"},"reg.example":{"username":"ru","password":"rp"}}}`)
	hdr, err := resolveRegistryAuth(nil, home, "busybox:latest")
	if err != nil {
		t.Fatal(err)
	}
	ac := decodeHeader(t, hdr)
	if ac["username"] != "hubuser" || ac["password"] != "hubpass" || ac["serveraddress"] != "https://index.docker.io/v1/" {
		t.Fatalf("hub auth: %v", ac)
	}
	hdr, err = resolveRegistryAuth(nil, home, "reg.example/img@sha256:0")
	if err != nil {
		t.Fatal(err)
	}
	ac = decodeHeader(t, hdr)
	if ac["username"] != "ru" || ac["password"] != "rp" {
		t.Fatalf("registry auth: %v", ac)
	}
	// Anonymous when nothing names the registry — and anonymous is an EMPTY header, not an
	// empty credential pair.
	hdr, err = resolveRegistryAuth(nil, home, "other.example/img")
	if err != nil || hdr != "" {
		t.Fatalf("anonymous: %q %v", hdr, err)
	}
	// A missing config file entirely is anonymous too.
	hdr, err = resolveRegistryAuth(nil, t.TempDir(), "busybox")
	if err != nil || hdr != "" {
		t.Fatalf("no config: %q %v", hdr, err)
	}
}

// writeHelper installs a fake docker-credential-<name> on a PATH dir and returns the env.
func writeHelper(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "docker-credential-"+name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCredHelperPrecedence(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	// EVERY source names the registry: the registry-specific helper must win over the store
	// AND the inline entry (the round-10 order, pinned exactly).
	helperDir := writeHelper(t, "specific", `echo '{"Username":"from-helper","Secret":"hs"}'`)
	storeDir := writeHelper(t, "store", `echo '{"Username":"from-store","Secret":"ss"}'`)
	pair := base64.StdEncoding.EncodeToString([]byte("inline:ip"))
	writeConfig(t, root, `{
		"credHelpers":{"reg.example":"specific"},
		"credsStore":"store",
		"auths":{"reg.example":{"auth":"`+pair+`"}}
	}`)
	env := []string{"PATH=" + helperDir + string(os.PathListSeparator) + storeDir}
	hdr, err := resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "from-helper" {
		t.Fatalf("credHelpers must win: %v", ac)
	}
	// A registry the helpers do NOT name falls to credsStore, past the inline entry.
	writeConfig(t, root, `{
		"credHelpers":{"other.example":"specific"},
		"credsStore":"store",
		"auths":{"reg.example":{"auth":"`+pair+`"}}
	}`)
	hdr, err = resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "from-store" {
		t.Fatalf("credsStore beats inline auths: %v", ac)
	}
	// The store's standardized NOT-FOUND is an absence, not a failure: the pull goes
	// ANONYMOUS (the CLI's convention) — and the inline entry for the same host is NOT
	// consulted, because a configured store is authoritative for the host. Helpers print the
	// message on stdout; the stderr spelling is accepted too.
	for _, script := range []string{
		`echo "credentials not found in native keychain"; exit 1`,
		`echo "credentials not found in native keychain" >&2; exit 1`,
	} {
		nfDir := writeHelper(t, "nf", script)
		writeConfig(t, root, `{"credsStore":"nf","auths":{"reg.example":{"auth":"`+pair+`"}}}`)
		hdr, err = resolveRegistryAuth([]string{"PATH=" + nfDir}, home, "reg.example/img")
		if err != nil {
			t.Fatalf("a store miss must mean anonymous, not failure: %v", err)
		}
		if hdr != "" {
			t.Fatalf("a store miss must not fall through to the inline entry: %q", hdr)
		}
	}
	// Any OTHER helper failure is an ERROR carrying the helper's own words — never a silent
	// fall-through to weaker credentials, never anonymous.
	badDir := writeHelper(t, "bad", `echo "keychain is locked" >&2; exit 1`)
	writeConfig(t, root, `{"credsStore":"bad","auths":{"reg.example":{"auth":"`+pair+`"}}}`)
	_, err = resolveRegistryAuth([]string{"PATH=" + badDir}, home, "reg.example/img")
	if err == nil || !strings.Contains(err.Error(), "keychain is locked") {
		t.Fatalf("a failing helper must surface its words, not fall through: %v", err)
	}
}

// The CLI's lookup ORDER, ported and closed: the EXACT config key wins over a legacy spelling
// of the same registry; a legacy spelling is honored when it is the only one; two legacy
// spellings that could both apply, with no exact key, are a REFUSAL — the CLI iterates a Go
// map there and answers nondeterministically, which is the one thing a credential lookup
// must never do.
func TestLookupOrderExactBeatsLegacy(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	exact := base64.StdEncoding.EncodeToString([]byte("exact:e"))
	legacy := base64.StdEncoding.EncodeToString([]byte("legacy:l"))
	other := base64.StdEncoding.EncodeToString([]byte("other:o"))
	// Exact key present alongside a legacy spelling: exact wins, every time.
	for i := 0; i < 20; i++ {
		writeConfig(t, root, `{"auths":{"https://reg.example":{"auth":"`+legacy+`"},"reg.example":{"auth":"`+exact+`"}}}`)
		hdr, err := resolveRegistryAuth(nil, home, "reg.example/img")
		if err != nil {
			t.Fatal(err)
		}
		if ac := decodeHeader(t, hdr); ac["username"] != "exact" {
			t.Fatalf("run %d: the exact key must win over a legacy spelling: %v", i, ac)
		}
	}
	// A single legacy spelling and no exact key: honored (the CLI's fallback).
	writeConfig(t, root, `{"auths":{"https://reg.example":{"auth":"`+legacy+`"}}}`)
	hdr, err := resolveRegistryAuth(nil, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "legacy" {
		t.Fatalf("a unique legacy spelling is honored: %v", ac)
	}
	// Two legacy spellings, no exact key: REFUSED, never a coin toss.
	writeConfig(t, root, `{"auths":{"https://reg.example":{"auth":"`+legacy+`"},"http://reg.example/v1/":{"auth":"`+other+`"}}}`)
	if _, err := resolveRegistryAuth(nil, home, "reg.example/img"); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("ambiguous legacy spellings must refuse: %v", err)
	}
	// credHelpers are EXACT-ONLY, as the CLI's plain map lookup is: the hostname key is used;
	// a URL-spelled key is not a match at all — it neither runs nor refuses, the lookup falls
	// through to credsStore / inline exactly as the CLI would.
	hExact := writeHelper(t, "hexact", `echo '{"Username":"from-exact","Secret":"x"}'`)
	hLegacy := writeHelper(t, "hlegacy", `echo '{"Username":"from-legacy","Secret":"y"}'`)
	env := []string{"PATH=" + hExact + string(os.PathListSeparator) + hLegacy}
	writeConfig(t, root, `{"credHelpers":{"https://reg.example":"hlegacy","reg.example":"hexact"}}`)
	hdr, err = resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "from-exact" {
		t.Fatalf("credHelpers: exact key must win: %v", ac)
	}
	writeConfig(t, root, `{"credHelpers":{"https://reg.example":"hlegacy"},"auths":{"reg.example":{"auth":"`+exact+`"}}}`)
	hdr, err = resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "exact" {
		t.Fatalf("a URL-spelled helper key is not a helper match; the inline entry applies: %v", ac)
	}
	// Hub: the legacy URL IS the exact key (what every `docker login` wrote); the bare
	// hostnames are legacy spellings — two of them with no exact key refuse.
	writeConfig(t, root, `{"auths":{"docker.io":{"auth":"`+legacy+`"},"https://index.docker.io/v1/":{"auth":"`+exact+`"}}}`)
	hdr, err = resolveRegistryAuth(nil, home, "busybox")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "exact" {
		t.Fatalf("Hub: the legacy URL is the exact key: %v", ac)
	}
	writeConfig(t, root, `{"auths":{"docker.io":{"auth":"`+legacy+`"},"index.docker.io":{"auth":"`+other+`"}}}`)
	if _, err := resolveRegistryAuth(nil, home, "busybox"); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("Hub: two legacy hostnames and no exact key must refuse: %v", err)
	}
}

func TestCredHelperIdentityToken(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	// The CLI convention: Username `<token>` means the Secret is an identity token.
	dir := writeHelper(t, "tok", `echo '{"Username":"<token>","Secret":"idtok123"}'`)
	writeConfig(t, root, `{"credHelpers":{"reg.example":"tok"}}`)
	hdr, err := resolveRegistryAuth([]string{"PATH=" + dir}, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	ac := decodeHeader(t, hdr)
	if ac["identitytoken"] != "idtok123" || ac["username"] != "" || ac["password"] != "" {
		t.Fatalf("identity token: %v", ac)
	}
}

func TestDockerAuthConfigOverlay(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".docker")
	pair := base64.StdEncoding.EncodeToString([]byte("filed:fp"))
	writeConfig(t, root, `{"auths":{"reg.example":{"auth":"`+pair+`"},"other.example":{"username":"of","password":"op"}}}`)
	overlayPair := base64.StdEncoding.EncodeToString([]byte("overlaid:vp"))
	env := []string{`DOCKER_AUTH_CONFIG={"auths":{"reg.example":{"auth":"` + overlayPair + `"}}}`}
	// The overlay wins for the registry it names…
	hdr, err := resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "overlaid" {
		t.Fatalf("overlay must win for its registry: %v", ac)
	}
	// …the file still answers for registries the overlay does not name…
	hdr, err = resolveRegistryAuth(env, home, "other.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "of" {
		t.Fatalf("file fallback: %v", ac)
	}
	// …and the overlay touches ONLY the inline fallback — a credHelpers entry still wins.
	dir := writeHelper(t, "hlp", `echo '{"Username":"from-helper","Secret":"s"}'`)
	writeConfig(t, root, `{"credHelpers":{"reg.example":"hlp"}}`)
	env = append(env, "PATH="+dir)
	hdr, err = resolveRegistryAuth(env, home, "reg.example/img")
	if err != nil {
		t.Fatal(err)
	}
	if ac := decodeHeader(t, hdr); ac["username"] != "from-helper" {
		t.Fatalf("the overlay must not outrank a helper: %v", ac)
	}
	// A set-but-unparseable overlay is an ERROR, not a silently-ignored one.
	if _, err := resolveRegistryAuth([]string{"DOCKER_AUTH_CONFIG={bad"}, home, "reg.example/img"); err == nil {
		t.Fatal("bad overlay must refuse")
	}
}
