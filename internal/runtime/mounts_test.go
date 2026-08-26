package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/runtime"
)

// Inventory — tests/unit/mounts.bats:
// PORTED: tests/unit/mounts.bats: "canonicalization resolves symlinks and works on macOS and Linux alike" -> TestCanon
// PORTED: tests/unit/mounts.bats: "canonicalization of a non-existent leaf still resolves its parent" -> TestCanon
// PORTED: tests/unit/mounts.bats: "canonicalization refuses a relative path — every comparison must be on absolute paths" -> TestCanon
// PORTED: tests/unit/mounts.bats: "a symlink LOOP is refused rather than followed for ever" -> TestCanonLoop
// PORTED: tests/unit/mounts.bats: "the three core-fixed mounts pass on a healthy home" -> TestCheckFixedHealthy
// PORTED: tests/unit/mounts.bats: "they pass when MYTHICAL_HOME sits under a SYMLINKED component — /var on macOS" -> TestCheckFixedSymlinkedHome
// PORTED: tests/unit/mounts.bats: "a <product>.conf that is a SYMLINK is refused" -> TestCheckFixedRefusals
// PORTED: tests/unit/mounts.bats: "a <product>.conf HARDLINKED to mythical.conf is refused — symlink tests alone pass this" -> TestCheckFixedHardlinks
// PORTED: tests/unit/mounts.bats: "a <product>.conf HARDLINKED to bin/mythical-ctl is refused" -> TestCheckFixedHardlinks
// PORTED: tests/unit/mounts.bats: "a home with no mythical.conf yet still passes — absence is not a failed identity read" -> TestCheckFixedHealthy
// PORTED: tests/unit/mounts.bats: "a core-fixed mount of the wrong TYPE is refused" -> TestCheckFixedRefusals
// PORTED: tests/unit/mounts.bats: "a product name that cannot make a path REFUSES, never checks nothing and passes" -> TestNameRefusals
// PORTED: tests/unit/mounts.bats: "the overlap check refuses the same way rather than comparing against an empty set" -> TestNameRefusals
// PORTED: tests/unit/mounts.bats: "a bind naming the family home is rejected" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "a bind naming ~/.mythical/bin directly is rejected" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "a bind naming ~/.mythical/<product>/ is rejected" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "the host-tool slot is not in the core-fixed mount set" -> TestHostToolSlotNotFixed
// PORTED: tests/unit/mounts.bats: "an operator bind cannot reach the host-tool slot, nor the directory holding it" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "a SYMLINK whose target resolves inside the family home is rejected" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "an ANCESTOR path containing the family home is rejected — containment is symmetric" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "a bind that is genuinely outside is accepted" -> TestCheckOverlap
// PORTED: tests/unit/mounts.bats: "two WRITABLE binds where one is an ancestor of the other are rejected" -> TestCheckPairwise
// PORTED: tests/unit/mounts.bats: "two overlapping binds are rejected when EITHER is writable" -> TestCheckPairwise
// PORTED: tests/unit/mounts.bats: "two read-only overlapping binds are permitted" -> TestCheckPairwise
// PORTED: tests/unit/mounts.bats: "two non-overlapping writable binds are permitted" -> TestCheckPairwise
// PORTED: tests/unit/mounts.bats: "identical canonical sources are rejected, however they were spelled" -> TestCheckPairwise (the callers canonicalize first — two spellings of one directory arrive equal)
// N/A: tests/unit/mounts.bats: "a bind spec whose mode is neither ro nor rw is refused, never read as read-only" -- the mode is a bool on the typed Bind; an unrecognised third field is unrepresentable
// N/A: tests/unit/mounts.bats: "a bind spec with a fourth field is refused, never re-cut into a mode it does not have" -- no spec string exists to re-cut
// N/A: tests/unit/mounts.bats: "a bind spec with no mode field at all is refused rather than read as two fields" -- same: the colon-separated grammar is gone
// N/A: tests/unit/mounts.bats: "a source path containing a colon is refused rather than emitted as an ambiguous spec" -- a mount crosses the API as one JSON field per component, so a colon moves no boundary (see runtime_invariants_test.go for the comma sibling, demonstrated live)
// PORTED: tests/unit/mounts.bats: "the VALIDATED canonical path is what reaches the spec — never the operator's string" -> TestLaunchProductMounts (launch_test.go: the inspect shows the resolved path; the operator's spelling appears nowhere)
// PORTED: tests/unit/mounts.bats: "mi_mount_binds applies the pairwise rule to the whole set it emits" -> TestMountsForPairwise (launch_test.go)
// PORTED: tests/unit/mounts.bats: "the emitted bind spec is one the runtime adapter accepts, and mounts the declared path" -> TestLaunchProductMounts (launch_test.go; the cross-seam case — what MountsFor emits is what the engine mounts)
// N/A: tests/unit/mounts.bats: "a bound role the manifest declares but does not PLACE is refused, never given a target" -- an unplaced role is unrepresentable: the rolemount grammar requires <role>:<absolute path>, so a manifest declaring one refuses at parse (RoleTarget still refuses a role the manifest does not declare — TestRoleTarget)
// PORTED: tests/unit/mounts.bats: "a role the policy index does not make bindable cannot be bound by naming its key" -> TestMountsForUnbindableKeySet (launch_test.go)
// PORTED: tests/unit/mounts.bats: "a role with no bind key falls through to a named volume rather than failing" -> TestLaunchProductMounts (launch_test.go: the unbound role rides its named volume)
// PORTED: tests/unit/mounts.bats: "the product key spec names the port and every BINDABLE role, and nothing else" -> TestProductKeys
// PORTED: tests/unit/mounts.bats: "no bindable_role entitlement means no bind key at all" -> TestProductKeys
// PORTED: tests/unit/mounts.bats: "the operation's spec is the core vocabulary PLUS this product's" -> TestConfSpecFor

// man builds a valid manifest; pol a valid policy — the same fixtures the manifest tests use.
func man(t *testing.T, overrides map[string]string, extra ...string) *manifest.Manifest {
	t.Helper()
	base := map[string]string{
		"version": "1", "expires": "99999999999", "product": "brokkr",
		"launched": "true",
		"image":    "ghcr.io/mythicalos/brokkr@sha256:" + strings.Repeat("ab", 32),
		"min_core": "0.1.0", "runtime_uid": "900",
	}
	for k, v := range overrides {
		if v == "" {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	var b strings.Builder
	b.WriteString("mythical-manifest 1\n")
	for _, k := range []string{"version", "expires", "product", "launched", "image", "min_core", "runtime_uid"} {
		if v, ok := base[k]; ok {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	for _, line := range extra {
		b.WriteString(line + "\n")
	}
	m, err := manifest.ParseVerified([]byte(b.String()), "t")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pol(t *testing.T, lines ...string) *policy.Policy {
	t.Helper()
	base := []string{"version=1", "expires=99999999999", "family_gid=20"}
	p, err := policy.ParseVerified([]byte("mythical-policy 1\n"+strings.Join(append(base, lines...), "\n")+"\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mkHome builds a healthy family home for a product: the three core-fixed sources plus bin/.
func mkHome(t *testing.T, product string) string {
	t.Helper()
	home := t.TempDir()
	for _, d := range []string{"transcripts", "logs", "bin"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, product+".conf"), []byte("#conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "mythical-ctl"), []byte("#!x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestCanon(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	wantReal, err := runtime.Canon(real)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtime.Canon(link)
	if err != nil || got != wantReal {
		t.Fatalf("symlink dir: %q want %q (%v)", got, wantReal, err)
	}
	// A non-existent LEAF still resolves its parent — a bind source is often created later.
	got, err = runtime.Canon(link + "/newfile")
	if err != nil || got != wantReal+"/newfile" {
		t.Fatalf("missing leaf: %q %v", got, err)
	}
	// Trailing slashes canonicalize identically.
	got, err = runtime.Canon(link + "/")
	if err != nil || got != wantReal {
		t.Fatalf("trailing slash: %q %v", got, err)
	}
	// Relative is refused outright.
	if _, err := runtime.Canon("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
	// A symlink LEAF is followed too — that is the "target resolves inside" defeat.
	fileLink := filepath.Join(dir, "leaf")
	target := filepath.Join(real, "t.txt")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, fileLink); err != nil {
		t.Fatal(err)
	}
	got, err = runtime.Canon(fileLink)
	if err != nil || got != wantReal+"/t.txt" {
		t.Fatalf("symlink leaf: %q %v", got, err)
	}
}

func TestCanonLoop(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	_, err := runtime.Canon(a)
	if err == nil || !strings.Contains(err.Error(), "40 symbolic links") {
		t.Fatalf("a loop must be refused with the stated bound: %v", err)
	}
}

func TestCheckFixedHealthy(t *testing.T) {
	home := mkHome(t, "brokkr")
	// No mythical.conf yet: absence is not a failed identity read — refusing would refuse
	// every first install.
	if err := runtime.CheckFixed(home, "brokkr"); err != nil {
		t.Fatalf("healthy home without mythical.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "mythical.conf"), []byte("MYTHICAL_NET=n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckFixed(home, "brokkr"); err != nil {
		t.Fatalf("healthy home with mythical.conf: %v", err)
	}
}

func TestCheckFixedSymlinkedHome(t *testing.T) {
	// The macOS case: the home path itself passes through a symlinked component (/var ->
	// /private/var). Comparing canonical sources against a RAW home would refuse every such
	// install; the check canonicalizes the home first.
	realHome := mkHome(t, "brokkr")
	linkParent := t.TempDir()
	linkedHome := filepath.Join(linkParent, "home-link")
	if err := os.Symlink(realHome, linkedHome); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckFixed(linkedHome, "brokkr"); err != nil {
		t.Fatalf("a home under a symlinked component must pass: %v", err)
	}
}

func TestCheckFixedRefusals(t *testing.T) {
	// A symlinked <product>.conf — an attack, not a configuration.
	home := mkHome(t, "brokkr")
	conf := filepath.Join(home, "brokkr.conf")
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "private-key")
	if err := os.WriteFile(secret, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, conf); err != nil {
		t.Fatal(err)
	}
	err := runtime.CheckFixed(home, "brokkr")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked conf: %v", err)
	}
	// The wrong TYPE: transcripts as a file.
	home2 := mkHome(t, "brokkr")
	if err := os.RemoveAll(filepath.Join(home2, "transcripts")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home2, "transcripts"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err = runtime.CheckFixed(home2, "brokkr")
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("wrong type: %v", err)
	}
}

func TestCheckFixedHardlinks(t *testing.T) {
	// Hardlinked to mythical.conf: every symlink test passes, and mounting it read-write
	// hands the container the host-only file the two-file split depends on being unreachable.
	home := mkHome(t, "brokkr")
	fam := filepath.Join(home, "mythical.conf")
	if err := os.WriteFile(fam, []byte("MYTHICAL_NET=n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(home, "brokkr.conf")
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fam, conf); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckFixed(home, "brokkr"); err == nil {
		t.Fatal("a conf hardlinked to mythical.conf must refuse")
	}
	// Hardlinked to bin/mythical-ctl: hands over the CLI.
	home2 := mkHome(t, "brokkr")
	conf2 := filepath.Join(home2, "brokkr.conf")
	if err := os.Remove(conf2); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home2, "bin", "mythical-ctl"), conf2); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckFixed(home2, "brokkr"); err == nil {
		t.Fatal("a conf hardlinked to the CLI must refuse")
	}
}

func TestNameRefusals(t *testing.T) {
	home := mkHome(t, "brokkr")
	// A product name that cannot make a path REFUSES — it never checks nothing and passes.
	for _, bad := range []string{"../x", "a/b", "UPPER", ""} {
		if err := runtime.CheckFixed(home, bad); err == nil {
			t.Errorf("CheckFixed(%q) passed", bad)
		}
		if err := runtime.CheckOverlap(home, bad, home+"/../outside"); err == nil {
			t.Errorf("CheckOverlap(%q) passed", bad)
		}
	}
}

func TestCheckOverlap(t *testing.T) {
	home := mkHome(t, "brokkr")
	homeCanon, err := runtime.Canon(home)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	refuse := []string{
		home,                          // the family home itself
		filepath.Join(home, "bin"),    // the CLI's directory
		filepath.Join(home, "brokkr"), // the product dir (holds the host-tool slot)
		filepath.Join(home, "brokkr", "cli.toml"),       // the host-tool slot itself
		filepath.Join(home, "transcripts", "somewhere"), // inside a core-fixed mount
		filepath.Dir(homeCanon),                         // an ANCESTOR containing the home — symmetric containment
		// The ROOT: the ancestor of EVERYTHING. `<p>/` as the strictly-inside prefix is "//"
		// for "/", a prefix no path has — without the root-aware join, a configured `/` bind
		// passed every protected check and mounted the host filesystem read-write (gate
		// round-4 P1; the frozen bash's _mi_path_overlaps has the same latent blind spot).
		"/",
	}
	for _, src := range refuse {
		if err := runtime.CheckOverlap(home, "brokkr", src); err == nil {
			t.Errorf("bind %q must be refused", src)
		}
	}
	// A SYMLINK whose target resolves inside the family home.
	link := filepath.Join(outside, "innocent")
	if err := os.Symlink(filepath.Join(homeCanon, "bin"), link); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckOverlap(home, "brokkr", link); err == nil {
		t.Fatal("a symlink resolving inside the home must be refused")
	}
	// A genuinely outside bind is accepted.
	ok := filepath.Join(outside, "work")
	if err := os.MkdirAll(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runtime.CheckOverlap(home, "brokkr", ok); err != nil {
		t.Fatalf("an outside bind must pass: %v", err)
	}
}

// The root bind must ALSO fall to the pairwise rule: "/" overlaps every other bind, so with
// either side writable the combination is refused. (Two read-only overlapping binds are
// permitted by the rule — the root's unconditional refusal is CheckOverlap's job, which the
// "/" case in TestCheckOverlap asserts.)
func TestPairwiseRootOverlapsEverything(t *testing.T) {
	err := runtime.CheckPairwise([]runtime.Bind{
		{Source: "/", ReadOnly: false},
		{Source: "/somewhere/else", ReadOnly: true},
	})
	if err == nil {
		t.Fatal("a writable root bind overlaps every other bind and must be refused pairwise")
	}
}

func TestHostToolSlotNotFixed(t *testing.T) {
	fixed, err := runtime.CoreFixed("/canon/home", "brokkr")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 3 {
		t.Fatalf("the core-fixed set is a fixed list of three: %v", fixed)
	}
	for _, fm := range fixed {
		if strings.Contains(fm.Source, "/brokkr/") || strings.HasSuffix(fm.Source, "cli.toml") {
			t.Fatalf("the user-owned host-tool slot must not be core-fixed: %v", fm)
		}
	}
}

func TestCheckPairwise(t *testing.T) {
	rw := func(s string) runtime.Bind { return runtime.Bind{Source: s} }
	ro := func(s string) runtime.Bind { return runtime.Bind{Source: s, ReadOnly: true} }
	// A writable ancestor: the container replaces the other bind's source with a symlink.
	if err := runtime.CheckPairwise([]runtime.Bind{rw("/work"), rw("/work/project")}); err == nil {
		t.Fatal("two writable, one an ancestor")
	}
	// EITHER writable is enough.
	if err := runtime.CheckPairwise([]runtime.Bind{ro("/work"), rw("/work/project")}); err == nil {
		t.Fatal("ro ancestor + rw child")
	}
	if err := runtime.CheckPairwise([]runtime.Bind{rw("/work"), ro("/work/project")}); err == nil {
		t.Fatal("rw ancestor + ro child")
	}
	// Two read-only overlapping binds are permitted.
	if err := runtime.CheckPairwise([]runtime.Bind{ro("/work"), ro("/work/project")}); err != nil {
		t.Fatalf("two ro: %v", err)
	}
	// Two non-overlapping writable binds are permitted.
	if err := runtime.CheckPairwise([]runtime.Bind{rw("/a"), rw("/b")}); err != nil {
		t.Fatalf("disjoint rw: %v", err)
	}
	// Identical canonical sources: however they were spelled, the callers canonicalize before
	// this rule, so equality arrives as equality — and equal writable sources are refused.
	if err := runtime.CheckPairwise([]runtime.Bind{rw("/same"), rw("/same")}); err == nil {
		t.Fatal("identical sources")
	}
}

func TestRoleTarget(t *testing.T) {
	m := man(t, nil, "volume=state:/var/lib/p", "volume=work:/work")
	got, err := runtime.RoleTarget(m, "state")
	if err != nil || got != "/var/lib/p" {
		t.Fatalf("%q %v", got, err)
	}
	// A role the manifest does not declare has no target — refused, never invented.
	if _, err := runtime.RoleTarget(m, "ghost"); err == nil || !strings.Contains(err.Error(), "no mount point") {
		t.Fatalf("undeclared role: %v", err)
	}
	// A role placed twice is ambiguous. (The manifest grammar permits repeated volume records;
	// two placements of ONE role are two answers to a question with one.)
	m2 := man(t, nil, "volume=state:/a", "volume=state:/b")
	if _, err := runtime.RoleTarget(m2, "state"); err == nil || !strings.Contains(err.Error(), "2 different paths") {
		t.Fatalf("duplicate placement: %v", err)
	}
}

func TestProductKeys(t *testing.T) {
	m := man(t, map[string]string{"product": "p1"}, "volume=state:/var/lib/p1", "volume=secrets:/run/secrets")
	p := pol(t, "p1.permitted_role=state", "p1.permitted_role=secrets", "p1.bindable_role=state")
	spec, err := runtime.ProductKeys("p1", m, p)
	if err != nil {
		t.Fatal(err)
	}
	if spec["MYTHICAL_P1_PORT"] != "int:1:65535" {
		t.Fatalf("port key: %v", spec)
	}
	if spec["MYTHICAL_P1_STATE_BIND"] != "path:4096" {
		t.Fatalf("bindable role key: %v", spec)
	}
	if _, present := spec["MYTHICAL_P1_SECRETS_BIND"]; present {
		t.Fatal("a role the policy does not make bindable became a bind key")
	}
	if len(spec) != 2 {
		t.Fatalf("and nothing else: %v", spec)
	}
	// No bindable_role entitlement at all: no bind key at all — recognising a role is not
	// authorizing it.
	p2 := pol(t, "p1.permitted_role=state")
	spec, err = runtime.ProductKeys("p1", m, p2)
	if err != nil {
		t.Fatal(err)
	}
	for k := range spec {
		if strings.HasSuffix(k, "_BIND") {
			t.Fatalf("an unentitled role became bindable: %v", spec)
		}
	}
}

func TestConfSpecFor(t *testing.T) {
	m := man(t, map[string]string{"product": "p1"}, "volume=state:/var/lib/p1")
	p := pol(t, "p1.permitted_role=state", "p1.bindable_role=state")
	spec, err := runtime.ConfSpecFor("p1", m, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"MYTHICAL_NET", "MYTHICAL_TELEMETRY_KEY", "MYTHICAL_P1_PORT", "MYTHICAL_P1_STATE_BIND"} {
		if _, present := spec[k]; !present {
			t.Errorf("missing %s: %v", k, spec)
		}
	}
}
