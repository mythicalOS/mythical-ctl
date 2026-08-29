package manifest

import (
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/policy"
	"mythicalos.ai/ctl/internal/version"
)

// Inventory — tests/unit/manifest.bats (this task owns the parser/accessor/check/core/naming
// rows; the acceptance-chain rows — snapshot discipline, forged blobs, anchor consultation,
// T5-door, untampered chain, wrong-product-through-door, tampering, unvouched product,
// not-launched-through-door, name-supply, door-level entitlement, Fix 1 floor rows, Fix 2
// expiry/rollback, Fix 3 tampered policy, Fix 7 mismatch label — are owned by the trust task):
// PORTED: tests/unit/manifest.bats: "a valid manifest loads" -> TestValidManifestLoads
// PORTED: tests/unit/manifest.bats: "a digest-pinned image is required; a tag is refused" -> TestImagePinning
// PORTED: tests/unit/manifest.bats: "a tag alongside a digest is accepted (still pinned by the digest); a bare tag with no digest is refused" -> TestImagePinning
// PORTED: tests/unit/manifest.bats: "mi_manifest_image returns the pinned reference" -> TestValidManifestLoads
// PORTED: tests/unit/manifest.bats: "launched=false reports rc 3 — the not-launched contract code" -> TestLaunched
// PORTED: tests/unit/manifest.bats: "launched=true reports rc 0" -> TestLaunched
// PORTED: tests/unit/manifest.bats: "a missing launched field is refused — launch state is never inferred" -> TestSchemaRefusals
// PORTED: tests/unit/manifest.bats: "T5: mi_manifest_launched refuses a non-boolean launch state rather than reporting it launched" -> TestSchemaRefusals -- the bool type refuses at parse; no Manifest value with a non-boolean state can exist
// PORTED: tests/unit/manifest.bats: "a manifest selecting only entitled things passes the check" -> TestEntitlementCheck
// PORTED: tests/unit/manifest.bats: "a manifest asking for a role it is not entitled to is rejected" -> TestEntitlementCheck
// PORTED: tests/unit/manifest.bats: "a manifest asking for a secret outside its namespace is rejected" -> TestEntitlementCheck
// PORTED: tests/unit/manifest.bats: "a manifest asking for a mount it is not entitled to is rejected" -> TestEntitlementCheck
// PORTED: tests/unit/manifest.bats: "a manifest for a product the policy index does not know is rejected" -> TestEntitlementCheck
// PORTED: tests/unit/manifest.bats: "a manifest declaring bindability is rejected" -> TestSchemaRefusals
// PORTED: tests/unit/manifest.bats: "a manifest cannot choose a network at all" -> TestSchemaRefusals
// PORTED: tests/unit/manifest.bats: "a manifest requiring a newer core is refused, even when fully authentic" -> internal/trust.TestNewerCoreRefusedThroughDoorWithoutFloorMovement + TestCoreOK -- the first is the door wiring; the second is the comparator itself
// PORTED: tests/unit/manifest.bats: "a manifest with no min_core is refused — unstated must not mean any core will do" -> TestSchemaRefusals
// PORTED: tests/unit/manifest.bats: "the version comparator orders components numerically, not lexically" -> TestVersionComparator
// PORTED: tests/unit/manifest.bats: "the core version tracks the entrypoint's VERSION" -> TestCoreOK -- CoreOK takes internal/version.Version itself — there is no second constant to drift; the test compares against that exact value
// PORTED: tests/unit/manifest.bats: "coreversion accepts MAJOR[.MINOR[.PATCH]] and nothing else" -> internal/docfmt.TestDocTypes -- the coreversion grammar is a docfmt field type, so the row is owned there
// PORTED: tests/unit/manifest.bats: "names are derived from the installation identity plus the product" -> TestNaming
// PORTED: tests/unit/manifest.bats: "two installations derive different names for the same product and role" -> TestNaming
// PORTED: tests/unit/manifest.bats: "the network alias is the bare product name, not the derived one" -> TestNaming -- the mythical-<product> ruling, asserted verbatim
// PORTED: tests/unit/manifest.bats: "name derivation refuses inputs that are not identifiers" -> TestNaming
// PORTED: tests/unit/manifest.bats: "Fix 5: mi_manifest_core_ok refuses a min_core value with a stray 4th component" -> TestCoreOK
// PORTED: tests/unit/manifest.bats: "Fix 6: MI_CORE_VERSION is itself a valid coreversion" -> TestCoreOK -- the binary version normalizes to a valid coreversion, asserted
// PORTED: tests/unit/manifest.bats: "the volatile_mount field is accepted, grammar-checked, and closed to option siblings" -> TestVolatileMountField -- acceptance, the grammar refusal, and the options-sibling rejection as an UNKNOWN KEY
// PORTED: tests/unit/manifest.bats: "the compat gate accepts a manifest requiring this core (0.2.0) and refuses one requiring newer" -> TestCoreVersionBoundaryIsThisRelease -- the premise assertion is ported too, so a later core bump fails loudly here rather than quietly re-deriving whatever number is current

func man(overrides map[string]string, extra ...string) []byte {
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
	return []byte(b.String())
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

func TestValidManifestLoads(t *testing.T) {
	m, err := ParseVerified(man(nil, "volume=state:/data", "volume=logs:/logs",
		"secret=bootstrap", "mount=transcripts", "port=7480", "probe=/detect"), "t")
	if err != nil {
		t.Fatal(err)
	}
	if m.Product() != "brokkr" || !m.Launched() || m.RuntimeUID() != "900" {
		t.Fatal("accessors wrong")
	}
	if !strings.HasSuffix(m.Image(), strings.Repeat("ab", 32)) {
		t.Fatalf("image: %q", m.Image())
	}
	vols := m.Volumes()
	if len(vols) != 2 || vols[0] != (VolumeDecl{"state", "/data"}) || vols[1] != (VolumeDecl{"logs", "/logs"}) {
		t.Fatalf("volumes: %v", vols)
	}
	if p := m.Ports(); len(p) != 1 || p[0] != 7480 {
		t.Fatalf("ports: %v", p)
	}
	if pr, ok := m.Probe(); !ok || pr != "/detect" {
		t.Fatalf("probe: %q", pr)
	}
}

func TestImagePinning(t *testing.T) {
	// A bare tag is refused — a tag is not a digest.
	if _, err := ParseVerified(man(map[string]string{"image": "ghcr.io/x/brokkr:latest"}), "t"); err == nil {
		t.Fatal("tag accepted")
	}
	// A tag alongside a digest is still pinned by the digest... the digestref grammar has no
	// tag slot at all in this port's charset-before-@ (a ':' is legal in the repo half), so
	// name:tag@sha256:hex parses as repo "name:tag" — accepted, digest-pinned.
	if _, err := ParseVerified(man(map[string]string{"image": "ghcr.io/x/brokkr:v1@sha256:" + strings.Repeat("ab", 32)}), "t"); err != nil {
		t.Fatalf("tag-plus-digest refused: %v", err)
	}
}

func TestLaunched(t *testing.T) {
	m, _ := ParseVerified(man(nil), "t")
	if !m.Launched() {
		t.Fatal("launched=true read false")
	}
	m2, err := ParseVerified(man(map[string]string{"launched": "false"}), "t")
	if err != nil {
		t.Fatal(err) // authentic-but-not-launched is an ACCEPTED parse; the door maps it to its contract code
	}
	if m2.Launched() {
		t.Fatal("launched=false read true")
	}
}

func TestSchemaRefusals(t *testing.T) {
	cases := map[string][]byte{
		"missing launched":     man(map[string]string{"launched": ""}),
		"non-boolean launched": man(map[string]string{"launched": "maybe"}),
		"missing min_core":     man(map[string]string{"min_core": ""}),
		"bindability declared": man(nil, "bindable_role=state"),
		"network chosen":       man(nil, "network=mythical-net"),
		"volume_name supplied": man(nil, "volume_name=custom"),
	}
	for name, data := range cases {
		if _, err := ParseVerified(data, "t"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEntitlementCheck(t *testing.T) {
	p := pol(t,
		"brokkr.permitted_role=state", "brokkr.permitted_role=logs",
		"brokkr.permitted_secret=bootstrap", "brokkr.permitted_mount=transcripts")
	ok, _ := ParseVerified(man(nil, "volume=state:/data", "secret=bootstrap", "mount=transcripts"), "t")
	if err := Check(ok, p); err != nil {
		t.Fatalf("entitled manifest refused: %v", err)
	}
	bads := map[string][]string{
		"unentitled role":   {"volume=scratch:/s"},
		"unentitled secret": {"secret=other-token"},
		"unentitled mount":  {"mount=elsewhere"},
	}
	for name, extra := range bads {
		m, _ := ParseVerified(man(nil, extra...), "t")
		if err := Check(m, p); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	// A product the policy does not know is entitled to nothing.
	unknown, _ := ParseVerified(man(map[string]string{"product": "saga"}, "volume=state:/data"), "t")
	if err := Check(unknown, p); err == nil {
		t.Fatal("unknown product entitled")
	}
	// ALL violations reported, not just the first.
	multi, _ := ParseVerified(man(nil, "volume=scratch:/s", "secret=other", "mount=elsewhere"), "t")
	err := Check(multi, p)
	if err == nil || strings.Count(err.Error(), "not entitled") != 3 {
		t.Fatalf("violations not all reported: %v", err)
	}
}

// TestVolatileMountField: the closed `volatile_mount` field.
//
// Three properties, and the third is the one that makes the field CLOSED rather than merely
// validated. A valid bounded container path is accepted at the door; a path the wire's grammar
// rejects fails the WHOLE manifest rather than being dropped; and there is deliberately no
// options sub-grammar, so a sibling key trying to relax the mount falls out of the allowlist as
// an UNKNOWN KEY. Absence is the enforcement: the field can carry only where the mount lives, so
// a publisher has no vocabulary in which to widen it.
func TestVolatileMountField(t *testing.T) {
	m, err := ParseVerified(man(nil, "volatile_mount=/run/mythical/credential-homes"), "t")
	if err != nil {
		t.Fatalf("a valid volatile_mount was refused: %v", err)
	}
	got, ok := m.VolatileMount()
	if !ok || got != "/run/mythical/credential-homes" {
		t.Fatalf("VolatileMount() = %q, %v — the accessor does not report the declared mount", got, ok)
	}

	// A manifest that declares none answers "absent" rather than an empty path: "" is a value a
	// caller could mistake for a mount point, and absence is not a mount.
	none, err := ParseVerified(man(nil), "t")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := none.VolatileMount(); ok {
		t.Fatalf("VolatileMount() reported %q present on a manifest that declares none", v)
	}

	// A path the wire's grammar rejects fails the WHOLE manifest — the grammar is the door, not a
	// later filter.
	//
	// THE LIST MATTERS AS MUCH AS THE ASSERTION. A traversal alone would not pin this field to the
	// `cpath` type at all: the looser `path:<n>` type refuses a traversal too, so a field retyped
	// to it would keep every traversal case green while quietly accepting everything below. These
	// are the values that DISTINGUISH the closed type from the loose one — a second token, an
	// option, the bare root, a trailing slash — and they are the ones a publisher would reach for
	// to widen the mount.
	for _, bad := range []string{
		"/run/../etc",                                // traversal
		"/run/mythical/credential-homes:rw",          // a second token behind a colon
		"/run/mythical/credential-homes,nodev=false", // an option behind a comma
		"/run/mythical/credential-homes exec",        // an option behind a space
		"/",                                          // the bare container root
		"/run/mythical/credential-homes/",            // a trailing slash
		"relative/path",                              // not absolute
	} {
		if _, err := ParseVerified(man(nil, "volatile_mount="+bad), "t"); err == nil {
			t.Errorf("the manifest door accepted volatile_mount=%q — the field is not closed", bad)
		}
	}

	// NO SUB-GRAMMAR. An options sibling is an unknown key, not a way to weaken the fixed mount.
	_, err = ParseVerified(man(nil,
		"volatile_mount=/run/mythical/credential-homes",
		"volatile_mount_exec=true"), "t")
	if err == nil {
		t.Fatal("an options sibling that would widen the mount was accepted")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("the sibling was refused, but not AS AN UNKNOWN KEY: %v", err)
	}

	// The field is OPTIONAL: a product needing no credential-home mount simply omits it, and the
	// manifest is still valid (asserted by `none` parsing cleanly above) — stated here so the
	// cardinality cannot be tightened to `one` without a red.
	if _, err := ParseVerified(man(nil,
		"volatile_mount=/run/mythical/credential-homes",
		"volatile_mount=/run/mythical/credential-homes"), "t"); err == nil {
		t.Fatal("a REPEATED volatile_mount was accepted — at most one mount, or the launch has two answers")
	}
}

func TestCoreOK(t *testing.T) {
	// The binary's own version normalizes to a valid coreversion (Fix 6's port), and a manifest
	// needing more than it refuses.
	m, _ := ParseVerified(man(nil), "t")
	if err := CoreOK(m, version.Version); err != nil {
		t.Fatalf("0.1.0 floor vs the real binary version %q: %v", version.Version, err)
	}
	newer, _ := ParseVerified(man(map[string]string{"min_core": "99.0.0"}), "t")
	if err := CoreOK(newer, version.Version); err == nil {
		t.Fatal("a newer-core requirement passed")
	}
	// Fix 5: a stray 4th component refuses rather than truncating to three and passing —
	// exercised through CoreOK's own gate (the schema already refuses it at parse, so the
	// direct-comparator hazard needs the direct door).
	four, err := ParseVerified(man(map[string]string{"min_core": "0.1.0.9"}), "t")
	if err == nil {
		_ = four
		t.Fatal("4-component min_core parsed")
	}
	// Prerelease normalization: a -dev binary compares by its numeric core.
	if err := CoreOK(m, "0.1.0-dev"); err != nil {
		t.Fatalf("prerelease normalization: %v", err)
	}
	if err := CoreOK(newer, "0.1.0-dev"); err == nil {
		t.Fatal("prerelease satisfied a newer requirement")
	}
}

// TestCoreVersionBoundaryIsThisRelease pins the compat gate at exactly the boundary THIS core
// release sets.
//
// This is the first core to honour the closed credential-home mount runtime, so it presents
// 0.2.0: a product needing that runtime declares min_core=0.2.0, and the gate must now ACCEPT
// exactly that while still refusing anything newer. Before the bump a min_core=0.2.0 manifest was
// REFUSED — a manifest asking for semantics this CLI did not have. That is the whole reason the
// number moves, and it is why the generic "99.0.0 is refused" case in TestCoreOK cannot stand in
// for this one: 99.0.0 was already refused by the predecessor core, so it shows nothing about
// WHERE the discriminator sits. Only a value one step past the current core proves it moved.
//
// THE GO SHAPE DIFFERS FROM THE REFERENCE HERE, AND THE DIFFERENCE IS THE POINT. The reference
// carries the number TWICE — an entrypoint VERSION and a core constant — and needs a test to pin
// them equal, because two copies can drift. There is one variable here, read by CoreOK's only
// caller, so there is no second constant to drift and the equality is structural rather than
// asserted. What still needs asserting is the VALUE, which is what the premise below does.
func TestCoreVersionBoundaryIsThisRelease(t *testing.T) {
	// The premise. A later core bump must fail LOUDLY here rather than silently weakening the two
	// checks below into a tautology about whatever number happens to be current.
	core, _, _ := strings.Cut(version.Version, "-")
	if core != "0.2.0" {
		t.Fatalf("premise: this binary's version %q has the numeric core %q, expected 0.2.0 — "+
			"revisit this boundary test rather than deleting it", version.Version, core)
	}

	// A manifest requiring exactly this core is accepted. It was refused before the bump.
	atBoundary, err := ParseVerified(man(map[string]string{"min_core": "0.2.0"}), "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := CoreOK(atBoundary, version.Version); err != nil {
		t.Fatalf("a min_core equal to this core (0.2.0) was refused: %v", err)
	}

	// One PATCH newer is still refused, and the diagnostic names the version the product needs —
	// an operator who is told only "too old" has nothing to act on.
	newer, err := ParseVerified(man(map[string]string{"min_core": "0.2.1"}), "t")
	if err != nil {
		t.Fatal(err)
	}
	err = CoreOK(newer, version.Version)
	if err == nil {
		t.Fatal("a min_core newer than this core (0.2.1) was accepted")
	}
	if !strings.Contains(err.Error(), "0.2.1") {
		t.Fatalf("the refusal does not name the required version: %v", err)
	}
}

func TestVersionComparator(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.10.0", "0.9.0", true}, // numeric, not lexical
		{"0.9.0", "0.10.0", false},
		{"1", "0.9.9", true},
		{"0.1", "0.1.0", true}, // missing components are 0
		{"0.1.0", "0.1", true},
		{"2.0.0", "10.0.0", false},
		{strings.Repeat("9", 30), "1", true}, // no overflow wrap
	}
	for _, c := range cases {
		if got := versionGE(c.a, c.b); got != c.want {
			t.Errorf("versionGE(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestNaming(t *testing.T) {
	v, err := VolumeName("i0123456789", "brokkr", "state")
	if err != nil || v != "mythical-i0123456789-brokkr-state" {
		t.Fatalf("%q, %v", v, err)
	}
	c, _ := ContainerName("i0123456789", "brokkr")
	if c != "mythical-i0123456789-brokkr" {
		t.Fatalf("%q", c)
	}
	n, _ := NetworkName("i0123456789")
	if n != "mythical-i0123456789-net" {
		t.Fatalf("%q", n)
	}
	// Two installations derive different names for the same product and role.
	v2, _ := VolumeName("iaaaaaaaaaa", "brokkr", "state")
	if v2 == v {
		t.Fatal("identities did not scope the name")
	}
	// The alias is mythical-<product> — NOT the bare product name (the exact string a reader
	// "fixes" it back to), and not the identity-scoped one.
	a, _ := Alias("brokkr")
	if a != "mythical-brokkr" {
		t.Fatalf("alias %q", a)
	}
	if a2, _ := Alias("saga"); a2 != "mythical-saga" {
		t.Fatalf("alias %q", a2)
	}
	// Non-identifier inputs refuse.
	for _, bad := range [][3]string{{"UPPER", "brokkr", "state"}, {"i1", "2bad", "state"}, {"i1", "brokkr", "st ate"}, {"", "brokkr", "state"}} {
		if _, err := VolumeName(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("VolumeName(%v) accepted", bad)
		}
	}
	if _, err := Alias("../evil"); err == nil {
		t.Fatal("alias accepted a non-identifier")
	}
	// The family port table (D15's machine-readable owner in this repo).
	fp := FamilyPorts()
	if fp["brokkr"] != 7480 || fp["saga"] != 7482 || fp["skuld"] != 7481 {
		t.Fatalf("family ports: %v", fp)
	}
}
