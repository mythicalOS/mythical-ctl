// Package manifest is the per-product manifest (D8/D21/D22, §8) and the core's name
// derivation (D32).
//
// A manifest declares ROLES; the core derives NAMES. The manifest says "I have a state volume
// mounted at /data", never "mythical-brokkr-state" — so a manifest has no vocabulary in which
// to name a sibling's resources. That is why the grammar has no key for a volume name, a
// network name, or a config path: ABSENCE IS THE ENFORCEMENT, and each such key falls out of
// the allowlist as an unknown-key rejection — louder than ignoring, so a product shipping one
// learns immediately instead of shipping a silently dead field.
package manifest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/policy"
)

// Spec is the manifest schema. Deliberately ABSENT (their absence is the enforcement, §8.1):
// bindable_role (bindability comes from the policy index, never the product — D53), network
// (joining a network is the cross-product reach D21 prevents), volume_name (the core derives
// names).
func Spec() docfmt.Schema {
	return docfmt.Schema{
		Type: "manifest",
		Fixed: map[string]docfmt.KeySpec{
			"version": docfmt.Typed(docfmt.One, "docver"),
			"expires": docfmt.Typed(docfmt.One, "epoch"),
			"product": docfmt.Typed(docfmt.One, "ident"),
			// §7.3: launch state is DECLARED, not inferred — inferring it from a registry 404
			// turns a broken publication into a reassuring "not launched yet" notice.
			"launched": docfmt.Typed(docfmt.One, "bool"),
			"image":    docfmt.Typed(docfmt.One, "digestref"),
			"volume":   docfmt.Typed(docfmt.Many, "rolemount"),
			"secret":   docfmt.Typed(docfmt.Many, "str:128"),
			"mount":    docfmt.Typed(docfmt.Many, "ident"),
			"port":     docfmt.Typed(docfmt.Many, "int:1:65535"),
			"probe":    docfmt.Typed(docfmt.Opt, "str:256"),
			// The credential-bearing isolated-home mount. AT MOST ONE, and only for a product
			// that needs a file-based credential materialized per session. Its value is a bare
			// bounded container path (`cpath`) — every hardening property of the mount is fixed
			// by the wire and is NOT declarable, so a manifest carries only WHERE the mount
			// lives and can never widen it.
			//
			// Optional: a product needing no such mount omits it. And there is deliberately no
			// options sibling in this allowlist — an attempt to add one (`volatile_mount_exec`
			// and its kind) falls out as an UNKNOWN KEY rather than relaxing the mount. Absence
			// is the enforcement, exactly as it is for bindable_role and network above.
			"volatile_mount": docfmt.Typed(docfmt.Opt, "cpath"),
			// §8: REQUIRED — a manifest that does not declare its minimum core cannot be
			// checked, and "unstated" silently meaning "any core will do" is the one answer
			// that is never safe.
			"min_core": docfmt.Typed(docfmt.One, "coreversion"),
			// D58/D60: the copy's ownership policy maps TO this principal — read from the
			// authenticated manifest, never guessed, never read out of the image, never
			// defaulted. A wrong value fails quietly, on the first start after the source is
			// retired.
			"runtime_uid": docfmt.Typed(docfmt.One, "int:0:4294967295"),
		},
	}
}

// Manifest is a parsed manifest, constructible ONLY through ParseVerified — which the trust
// acceptors alone may call (check.sh's boundary gate) — so lifecycle code cannot hold a
// manifest that did not pass through the chain.
type Manifest struct {
	doc *docfmt.Doc
}

// VolumeDecl is one `volume=<role>:<target>` declaration, both halves — role names alone lose
// the target the launch mounts to.
type VolumeDecl struct{ Role, Target string }

// ParseVerified parses already-digest-verified bytes.
func ParseVerified(data []byte, label string) (*Manifest, error) {
	doc, err := docfmt.Parse(data, label, Spec())
	if err != nil {
		return nil, err
	}
	return &Manifest{doc: doc}, nil
}

// Product is the identity the trust chain matches against the requested product.
func (m *Manifest) Product() string { v, _ := m.doc.Value("product"); return v }

// Image is the digest-pinned reference (the type refused anything unpinned at parse).
func (m *Manifest) Image() string { v, _ := m.doc.Value("image"); return v }

// Launched: the declared launch state. The schema's bool type already refused anything but
// true/false, so a parsed manifest always answers.
func (m *Manifest) Launched() bool { v, _ := m.doc.Value("launched"); return v == "true" }

// RuntimeUID is the uid the product's container runs as — the principal ownership mapping
// maps TO.
func (m *Manifest) RuntimeUID() string { v, _ := m.doc.Value("runtime_uid"); return v }

// Volumes returns every declared volume, role AND target.
func (m *Manifest) Volumes() []VolumeDecl {
	var out []VolumeDecl
	for _, v := range m.doc.Values("volume") {
		role, target, _ := strings.Cut(v, ":") // shape proven by the rolemount type
		out = append(out, VolumeDecl{Role: role, Target: target})
	}
	return out
}

// Secrets returns every declared bootstrap secret name.
func (m *Manifest) Secrets() []string { return m.doc.Values("secret") }

// Mounts returns every declared fixed mount.
func (m *Manifest) Mounts() []string { return m.doc.Values("mount") }

// Ports returns every declared publish, parsed (the int:1:65535 type proved the range).
func (m *Manifest) Ports() []uint16 {
	var out []uint16
	for _, v := range m.doc.Values("port") {
		n, _ := strconv.Atoi(v)
		out = append(out, uint16(n))
	}
	return out
}

// Probe returns the optional probe declaration.
func (m *Manifest) Probe() (string, bool) { return m.doc.Value("probe") }

// VolatileMount returns the declared credential-home mount point and whether one was declared.
// The second result is not decoration: ABSENCE IS NOT A MOUNT, and an accessor that answered ""
// for "none declared" would hand a caller a value it could mistake for a mount point.
func (m *Manifest) VolatileMount() (string, bool) { return m.doc.Value("volatile_mount") }

// MinCore returns the declared minimum core version.
func (m *Manifest) MinCore() string { v, _ := m.doc.Value("min_core"); return v }

// Expired proxies the document's freshness check for the acceptors.
func (m *Manifest) Expired(nowUnix int64) (bool, error) { return m.doc.Expired(nowUnix) }

// Version returns the document version, for the trust floor.
func (m *Manifest) Version() string { v, _ := m.doc.Version(); return v }

// Doc exposes the underlying immutable document for the trust gate's freshness checks.
func (m *Manifest) Doc() *docfmt.Doc { return m.doc }

// Check enforces entitlements: every role, secret and mount the manifest selects must already
// be granted to its product by the policy index. ALL violations are reported, not just the
// first — a product author fixing one at a time otherwise learns the next only after another
// release cycle.
func Check(m *Manifest, p *policy.Policy) error {
	product := m.Product()
	var errs []string
	for _, v := range m.Volumes() {
		if !p.PermitsRole(product, v.Role) {
			errs = append(errs, fmt.Sprintf("manifest: %s is not entitled to the volume role %q", product, v.Role))
		}
	}
	for _, s := range m.Secrets() {
		if !p.PermitsSecret(product, s) {
			errs = append(errs, fmt.Sprintf("manifest: %s is not entitled to the bootstrap secret %q", product, s))
		}
	}
	for _, mt := range m.Mounts() {
		if !p.PermitsMount(product, mt) {
			errs = append(errs, fmt.Sprintf("manifest: %s is not entitled to the fixed mount %q", product, mt))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// CoreOK: does the RUNNING core satisfy the manifest's declared minimum? binaryVersion is the
// binary's own version (internal/version.Version at call sites — a min_core check against a
// stale constant is worse than none). Its comparator: any `-suffix` is STRIPPED before the
// numeric core comparison (the dev default `0.1.0-dev` and release-candidate stamps compare by
// their numeric core), components compared as bounded decimal strings — never a raw integer
// parse that a long component could overflow — with missing components as 0. A min_core value
// that is not a valid coreversion (a stray 4th component included) refuses rather than
// silently truncating to three components and appearing satisfied.
func CoreOK(m *Manifest, binaryVersion string) error {
	need := m.MinCore()
	if need == "" {
		return errors.New("manifest: no minimum core version declared")
	}
	if !docfmt.CoreVersionOK(need) {
		return fmt.Errorf("manifest: %q is not a valid core version (MAJOR[.MINOR[.PATCH]]) — refusing rather than comparing it", need)
	}
	core, _, _ := strings.Cut(binaryVersion, "-")
	if !docfmt.CoreVersionOK(core) {
		return fmt.Errorf("manifest: this binary's own version %q does not normalize to a core version — refusing to compare", binaryVersion)
	}
	if versionGE(core, need) {
		return nil
	}
	return fmt.Errorf("manifest: this product needs mythical-ctl %s or newer; this core is %s — upgrade mythical-ctl", need, core)
}

// versionGE: a >= b, MAJOR.MINOR.PATCH component-wise, missing components 0, decimal-STRING
// comparison (leading-zero-stripped, length-then-lexical) so overflow cannot wrap.
func versionGE(a, b string) bool {
	pa := strings.SplitN(a, ".", 3)
	pb := strings.SplitN(b, ".", 3)
	for i := 0; i < 3; i++ {
		ca, cb := "0", "0"
		if i < len(pa) {
			ca = pa[i]
		}
		if i < len(pb) {
			cb = pb[i]
		}
		if decGT(ca, cb) {
			return true
		}
		if decGT(cb, ca) {
			return false
		}
	}
	return true
}

func decGT(a, b string) bool {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}
