// Package runtime is the lock-bound facade over the engine: every mutation the CLI performs
// on the container runtime is a method on *Runtime, which is the ONLY holder of an
// engine.Mutator (check.sh's boundary gate pins NewMutator here) — probes, verbs and data
// movement all come through it. Read-only inspection stays free functions over engine.Client
// results, because status must read without the lock, exactly as the reference does.
//
// This file is §4.1a — mount validation AT THE LAUNCH SITE: canonicalization, the core-fixed
// set, the protected identities nothing may share, the overlap rules, and the derivation of
// operator binds from the authenticated manifest + policy + mythical.conf.
package runtime

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/docfmt"
	"mythicalos.ai/ctl/internal/engine"
	"mythicalos.ai/ctl/internal/manifest"
	"mythicalos.ai/ctl/internal/policy"
)

// Canon canonicalizes an absolute path the way the reference does — resolve every symlink in
// the DIRECTORY chain, then follow a symlink LEAF iteratively with a stated bound. The leaf
// may not exist (a bind source is often created later), so the directory is resolved and the
// basename appended. §4.1a: "Compare canonical paths, never the strings a user typed"; §10a:
// identical behaviour on macOS and Linux — a portability gap here is a security bug (macOS
// homes under /var sit beneath a symlinked component).
//
// IT ITERATES RATHER THAN RECURSING, and the bound is the reason: `a -> b`, `b -> a` is a
// pair an operator can create by accident, and following it for ever is a hang with no
// message on the one code path an operator reaches through their own configuration.
func Canon(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("runtime: %q is not an absolute path — every path comparison is on absolute paths", path)
	}
	p := path
	for hops := 0; ; {
		for len(p) > 1 && strings.HasSuffix(p, "/") {
			p = strings.TrimSuffix(p, "/")
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil {
				return "", fmt.Errorf("runtime: cannot resolve %q: %v", path, err)
			}
			return resolved, nil
		}
		d := filepath.Dir(p)
		b := filepath.Base(p)
		rd, err := filepath.EvalSymlinks(d)
		if err != nil {
			return "", fmt.Errorf("runtime: cannot resolve the parent of %q: %v", path, err)
		}
		leaf := filepath.Join(rd, b)
		st, lerr := os.Lstat(leaf)
		if lerr == nil && st.Mode()&fs.ModeSymlink != 0 {
			hops++
			if hops > 40 {
				return "", fmt.Errorf("runtime: %q passes through more than 40 symbolic links — that is a loop or a chain no legitimate path needs, and following it further would never terminate; refusing", path)
			}
			t, rerr := os.Readlink(leaf)
			if rerr != nil {
				return "", fmt.Errorf("runtime: cannot read the link at %q: %v", path, rerr)
			}
			if filepath.IsAbs(t) {
				p = t
			} else {
				p = filepath.Join(rd, t)
			}
			continue
		}
		return leaf, nil
	}
}

// pathOverlaps: is a equal to, inside, or containing b? Both must already be canonical.
// CONTAINMENT IS SYMMETRIC: checking one direction only lets an ancestor through, and an
// ancestor contains everything below it.
func pathOverlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, withSep(b)) || strings.HasPrefix(b, withSep(a))
}

// withSep is the prefix that means "strictly inside p": `<p>/` — except for the ROOT, whose
// descendants all begin with exactly "/". Appending another separator there would produce
// "//", a prefix NO canonical path has, silently declaring the one path that contains
// EVERYTHING disjoint from everything — a configured `/` bind would then pass every protected
// check and mount the host filesystem read-write. (The reference's `_mi_path_overlaps` has the
// same blind spot — `case ... in "$2"/*` builds `//*` for root; latent there, recorded rather
// than fixed because the bash is frozen.)
func withSep(p string) string {
	if p == "/" {
		return "/"
	}
	return p + "/"
}

// nameOK: a product or role name before it is joined into a path or a configuration key. Both
// joins are string concatenation, so a `/` or `..` here is a path escape. The SAME `ident`
// document type every runtime name in this installer is checked against.
func nameOK(what, v string) error {
	if docfmt.TypeOK("ident", v) {
		return nil
	}
	return fmt.Errorf("runtime: %q is not a usable %s name", v, what)
}

// FixedMount is one core-fixed mount: a host source, a container target, read-write, of a
// stated filesystem type.
type FixedMount struct {
	IsDir  bool
	Source string
	Target string
}

// CoreFixed is the CLOSED, EXACT allowlist the core computes itself (§4.1a):
// <home>/<product>.conf, <home>/transcripts, <home>/logs. Never derived from configuration,
// never extended by a manifest — and <home> ITSELF is never mounted, because it contains
// mythical.conf, and a directory mount would hand every secret in it to everything inside.
// (Binding one directory is simpler than binding N files, and it silently defeats the
// host-only split with no visible symptom — which is why this is stated.) The host-tool slot
// (<home>/<product>/cli.toml) is user-owned and deliberately NOT here.
//
// homeCanon must be the CANONICALIZED family home: every comparison downstream is
// canonical-to-canonical, and comparing against a raw home refuses any install whose home
// sits under a symlinked component — on macOS that is every home under /var or /tmp.
func CoreFixed(homeCanon, product string) ([]FixedMount, error) {
	if err := nameOK("product", product); err != nil {
		return nil, err
	}
	return []FixedMount{
		{IsDir: false, Source: homeCanon + "/" + product + ".conf", Target: "/etc/mythical/" + product + ".conf"},
		{IsDir: true, Source: homeCanon + "/transcripts", Target: "/home/mythical/transcripts"},
		{IsDir: true, Source: homeCanon + "/logs", Target: "/home/mythical/logs"},
	}, nil
}

// identity is a path's `device:inode` pair, by Lstat — a FAILURE to read it is reported as
// one, never as "no conflict".
func identity(p string) (string, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("runtime: cannot read the identity of %q", p)
	}
	return fmt.Sprintf("%d:%d", sys.Dev, sys.Ino), nil
}

func nlinkOf(p string) (uint64, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("runtime: cannot read the link count of %q", p)
	}
	return uint64(sys.Nlink), nil
}

// protectedIdentities is the set NOTHING mounted into a container may share: mythical.conf,
// and everything under bin/. A path that EXISTS and whose identity cannot be read is a
// refusal, not one fewer member. An ABSENT mythical.conf is not that case: a family home that
// has never been configured has no such file, and refusing would refuse every first install.
func protectedIdentities(homeCanon string) (map[string]bool, error) {
	out := map[string]bool{}
	confPath := homeCanon + "/mythical.conf"
	if _, err := os.Lstat(confPath); err == nil {
		ino, ierr := identity(confPath)
		if ierr != nil {
			return nil, errors.New("runtime: the family configuration file exists but its identity cannot be read — nothing can then be shown NOT to be it, so this refuses rather than assuming")
		}
		out[ino] = true
	}
	entries, err := os.ReadDir(homeCanon + "/bin")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("runtime: cannot list %s/bin: %v", homeCanon, err)
	}
	for _, e := range entries {
		p := homeCanon + "/bin/" + e.Name()
		ino, ierr := identity(p)
		if ierr != nil {
			return nil, fmt.Errorf("runtime: %q is under the installer-managed bin/ directory and its identity cannot be read — refusing rather than leaving it out of the protected set", p)
		}
		out[ino] = true
	}
	return out, nil
}

// CheckFixed checks every core-fixed mount for a product against the launch-site rules:
// exact canonical location, expected TYPE, not a SYMLINK, and — because symlink checks are
// not sufficient — DISTINCT IDENTITY against mythical.conf, against everything under bin/,
// and against every other core-fixed mount.
//
// A hardlink is not a link at the path level: it is a second name for the same inode, and
// every symlink test passes it. A <product>.conf hardlinked to mythical.conf mounts the
// host-only file §4.1 depends on being unreachable; hardlinked to bin/mythical-ctl, it hands
// over the CLI — the entire two-file split bypassed without a single symlink existing.
//
// THE IDENTITY CHECK IS NOT THE LINK-COUNT CHECK REPEATED. A hardlink to a regular file
// raises its link count, so for the `file` mount the count catches it first. A BIND MOUNT
// does not: two paths share a device+inode with a link count of 1 apiece, and it works for
// DIRECTORIES, which cannot be hardlinked at all. The count answers "how many names does
// this file have"; the identity answers "is this the same object as that one", and only the
// second covers the directory mounts.
func CheckFixed(home, product string) error {
	homeCanon, err := Canon(home)
	if err != nil {
		return err
	}
	fixed, err := CoreFixed(homeCanon, product)
	if err != nil {
		return err
	}
	protected, err := protectedIdentities(homeCanon)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var failures []string
	for _, fm := range fixed {
		// The SYMLINK test comes FIRST, before canonical equality: "this path is a symlink"
		// is the actionable message, and a symlinked <product>.conf is an attack, not a
		// configuration.
		if st, lerr := os.Lstat(fm.Source); lerr == nil && st.Mode()&fs.ModeSymlink != 0 {
			failures = append(failures, fmt.Sprintf("%q is a symlink — core-fixed mounts are never followed", fm.Source))
			continue
		}
		canon, cerr := Canon(fm.Source)
		if cerr != nil {
			failures = append(failures, cerr.Error())
			continue
		}
		if canon != fm.Source {
			failures = append(failures, fmt.Sprintf("core-fixed mount %q resolves to %q — it must be exactly where the core expects it", fm.Source, canon))
			continue
		}
		if fm.IsDir {
			st, serr := os.Stat(fm.Source)
			if serr != nil || !st.IsDir() {
				failures = append(failures, fmt.Sprintf("%q is not a directory", fm.Source))
				continue
			}
		} else {
			st, serr := os.Stat(fm.Source)
			if serr != nil || !st.Mode().IsRegular() {
				failures = append(failures, fmt.Sprintf("%q is not a regular file", fm.Source))
				continue
			}
			n, nerr := nlinkOf(fm.Source)
			if nerr != nil {
				failures = append(failures, fmt.Sprintf("cannot read the link count of %q — refusing rather than assuming", fm.Source))
				continue
			}
			if n > 1 {
				failures = append(failures, fmt.Sprintf("%q has a link count of %d — the installer created this file and nothing legitimate shares its inode, so a second name for it is unexplainable", fm.Source, n))
				continue
			}
		}
		ino, ierr := identity(fm.Source)
		if ierr != nil {
			failures = append(failures, fmt.Sprintf("cannot read the identity of %q — refusing rather than assuming", fm.Source))
			continue
		}
		if protected[ino] {
			failures = append(failures, fmt.Sprintf("%q is the same object as mythical.conf or a file under bin/ — that would mount the host-only file, or the CLI itself, into the container", fm.Source))
			continue
		}
		if seen[ino] {
			failures = append(failures, fmt.Sprintf("%q is the same object as another core-fixed mount", fm.Source))
			continue
		}
		seen[ino] = true
	}
	if len(failures) > 0 {
		return fmt.Errorf("runtime: refusing the core-fixed mounts:\n  %s", strings.Join(failures, "\n  "))
	}
	return nil
}

// CheckOverlap: is this ONE operator bind source acceptable? It may not be, contain, or sit
// inside the family home (that would hand the container write access to the CLI it will later
// be launched by), and it may not overlap any core-fixed mount. A core-fixed path that cannot
// be canonicalized fails the whole check — a comparison silently skipped is a bind accepted.
func CheckOverlap(home, product, src string) error {
	homeCanon, err := Canon(home)
	if err != nil {
		return err
	}
	canon, err := Canon(src)
	if err != nil {
		return err
	}
	if pathOverlaps(canon, homeCanon) {
		note := ""
		if canon != homeCanon && strings.HasPrefix(homeCanon, withSep(canon)) {
			note = " (the source CONTAINS the family home — containment is checked in both directions)"
		}
		return fmt.Errorf("runtime: bind source %q resolves to %q, which is, is inside, or contains the family home %q%s — that would hand the container write access to the CLI it will later be launched by, or to the generated artifacts that inform that launch", src, canon, homeCanon, note)
	}
	fixed, err := CoreFixed(homeCanon, product)
	if err != nil {
		return err
	}
	for _, fm := range fixed {
		fc, cerr := Canon(fm.Source)
		if cerr != nil {
			return fmt.Errorf("runtime: the core-fixed mount %q cannot be canonicalized, so no bind can be shown not to overlap it — refusing rather than skipping the comparison", fm.Source)
		}
		if pathOverlaps(canon, fc) {
			return fmt.Errorf("runtime: bind source %q overlaps the core-fixed mount %q", canon, fc)
		}
	}
	return nil
}

// Bind is one bind for the pairwise rule: an already-CANONICAL source and its writability.
type Bind struct {
	Source   string
	ReadOnly bool
}

// CheckPairwise applies the combination rule: binds must be checked AGAINST EACH OTHER, not
// only against protected paths. With /work bound read-write, the container replaces
// /work/project — the source of a second bind — with a symlink into the family home, and the
// NEXT launch follows it. Two binds may not overlap when EITHER is writable; two read-only
// binds may.
func CheckPairwise(binds []Bind) error {
	for i := 0; i < len(binds); i++ {
		for j := i + 1; j < len(binds); j++ {
			if !pathOverlaps(binds[i].Source, binds[j].Source) {
				continue
			}
			if !binds[i].ReadOnly || !binds[j].ReadOnly {
				return fmt.Errorf("runtime: binds %q and %q overlap and at least one is writable — a writable ancestor lets the container replace the other bind's source with a symlink, which the next launch would follow", binds[i].Source, binds[j].Source)
			}
		}
	}
	return nil
}

// RoleTarget: WHERE THIS ROLE IS MOUNTED INSIDE THE CONTAINER, out of the AUTHENTICATED
// manifest — the only document that says. A role the manifest does not PLACE has no target,
// and that is a refusal rather than a guess: the core derives NAMES, never mount points, and
// inventing one would mount an operator's directory somewhere the product does not read. A
// role placed TWICE is ambiguous — two answers to a question with one, and picking the first
// would let record order decide which directory is exposed at which path.
func RoleTarget(m *manifest.Manifest, role string) (string, error) {
	found, n := "", 0
	for _, v := range m.Volumes() {
		if v.Role != role {
			continue
		}
		n++
		found = v.Target
	}
	switch {
	case n == 0:
		return "", fmt.Errorf("runtime: the manifest declares no mount point for the %q volume, so there is nowhere inside the container to bind it to", role)
	case n > 1:
		return "", fmt.Errorf("runtime: the manifest places the %q volume at %d different paths — two answers to a question with one", role, n)
	}
	return found, nil
}

// upperKey maps a product or role name into the configuration-key alphabet the way the
// reference does: lower→upper, and `-`→`_`.
func upperKey(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 32
		case r == '-':
			return '_'
		}
		return r
	}, s)
}

// ProductKeys derives the product-scoped mythical.conf vocabulary FROM THE AUTHENTICATED
// manifest and policy (D53): MYTHICAL_<PRODUCT>_PORT, plus MYTHICAL_<PRODUCT>_<ROLE>_BIND for
// every role the POLICY INDEX makes bindable — policy, not manifest: recognising a role is
// not authorizing it, and rejecting only unknown roles would make every known one bindable,
// including the secrets role whose whole protection is its named volume.
func ProductKeys(product string, m *manifest.Manifest, p *policy.Policy) (conf.Spec, error) {
	if err := nameOK("product", product); err != nil {
		return nil, err
	}
	up := upperKey(product)
	spec := conf.Spec{"MYTHICAL_" + up + "_PORT": "int:1:65535"}
	for _, v := range m.Volumes() {
		if err := nameOK("role", v.Role); err != nil {
			return nil, err
		}
		if !p.Bindable(product, v.Role) {
			continue
		}
		spec["MYTHICAL_"+up+"_"+upperKey(v.Role)+"_BIND"] = "path:4096"
	}
	return spec, nil
}

// ConfSpecFor is the full mythical.conf spec for an operation on this product: the core
// vocabulary plus this product's keys.
func ConfSpecFor(product string, m *manifest.Manifest, p *policy.Policy) (conf.Spec, error) {
	spec, err := ProductKeys(product, m, p)
	if err != nil {
		return nil, err
	}
	for k, v := range conf.FamilySpec() {
		spec[k] = v
	}
	return spec, nil
}

// rawMount is a validated mount before it becomes an engine.Mount — the checks run on these,
// because the engine type's fields are sealed (which is the point of it).
type rawMount struct {
	volume   bool // named volume, not bind
	source   string
	target   string
	readOnly bool
}

// mountsFor assembles and VALIDATES the launch's bind set: the core-fixed mounts plus every
// operator-bound role, each judged by §4.1a's rules, with the pairwise rule applied to the
// WHOLE set — the only place the combination exists. It also reports which roles were bound,
// so the launch path can put every other role on its named volume. A refused combination
// yields nothing at all, never a prefix a caller might act on.
func (r *Runtime) mountsFor(m *manifest.Manifest, p *policy.Policy) ([]rawMount, map[string]bool, error) {
	if err := r.assert(); err != nil {
		return nil, nil, err
	}
	home, err := r.home()
	if err != nil {
		return nil, nil, err
	}
	product := m.Product()
	if err := nameOK("product", product); err != nil {
		return nil, nil, err
	}
	if err := CheckFixed(home, product); err != nil {
		return nil, nil, err
	}
	homeCanon, err := Canon(home)
	if err != nil {
		return nil, nil, err
	}
	fixed, err := CoreFixed(homeCanon, product)
	if err != nil {
		return nil, nil, err
	}
	var mounts []rawMount
	for _, fm := range fixed {
		mounts = append(mounts, rawMount{source: fm.Source, target: fm.Target})
	}

	spec, err := ProductKeys(product, m, p)
	if err != nil {
		return nil, nil, err
	}
	famPath := conf.FamilyPath(home)
	famExists := true
	if _, serr := os.Lstat(famPath); errors.Is(serr, fs.ErrNotExist) {
		famExists = false // a home never configured has no family file — every key is absent
	}
	bound := map[string]bool{}
	seenRole := map[string]bool{}
	up := upperKey(product)
	for _, v := range m.Volumes() {
		if seenRole[v.Role] {
			continue // a duplicate placement is refused by RoleTarget below, once
		}
		seenRole[v.Role] = true
		if err := nameOK("role", v.Role); err != nil {
			return nil, nil, err
		}
		key := "MYTHICAL_" + up + "_" + upperKey(v.Role) + "_BIND"
		val, gerr := "", error(nil)
		if famExists {
			val, gerr = conf.Get(famPath, key)
		} else {
			gerr = conf.ErrAbsent
		}
		if _, bindable := spec[key]; !bindable {
			// Not bindable. Falling through to the named volume is right when the operator
			// said nothing — but SILENTLY, while the file names the key, would leave them
			// believing a bind is in effect when the role's whole protection is that it is
			// not one (D53).
			if gerr == nil {
				return nil, nil, fmt.Errorf("runtime: %s sets %q, but the authenticated policy index does not make %q bindable for %q — recognising a role is not authorizing it: a role kept on a named volume is kept there deliberately; refusing rather than ignoring the setting", famPath, key, v.Role, product)
			}
			if !errors.Is(gerr, conf.ErrAbsent) {
				return nil, nil, gerr
			}
			continue
		}
		if errors.Is(gerr, conf.ErrAbsent) {
			continue // not bound: the named volume is used instead (D6)
		}
		if gerr != nil {
			return nil, nil, gerr
		}
		canon, cerr := Canon(val)
		if cerr != nil {
			return nil, nil, cerr
		}
		if err := CheckOverlap(home, product, canon); err != nil {
			return nil, nil, err
		}
		target, terr := RoleTarget(m, v.Role)
		if terr != nil {
			return nil, nil, terr
		}
		// THE VALIDATED CANONICAL SOURCE is what reaches the launch — never the operator's
		// original string: validate and launch against the same resolved path.
		mounts = append(mounts, rawMount{source: canon, target: target})
		bound[v.Role] = true
	}
	var pair []Bind
	for _, mt := range mounts {
		if !mt.volume {
			pair = append(pair, Bind{Source: mt.source, ReadOnly: mt.readOnly})
		}
	}
	if err := CheckPairwise(pair); err != nil {
		return nil, nil, err
	}
	return mounts, bound, nil
}

// MountsFor is the exported §4.1a producer: the complete validated bind set for a launch of
// this manifest — a LOCK-BOUND METHOD. The home comes from the Runtime's token (never a
// caller string, so home B cannot be mounted under home A's lock); the product comes
// EXCLUSIVELY from m.Product() (a separate parameter could derive another product's names,
// policy queries and config keys from this manifest — the mismatch is inexpressible); the
// role set is enumerated INTERNALLY from the authenticated manifest's Volumes() (a caller
// cannot omit a role and produce incomplete mounts); and the AUTHENTICATED POLICY is an input
// because bindability is ITS entitlement — without it a policy-forbidden role could become a
// host bind.
func (r *Runtime) MountsFor(m *manifest.Manifest, p *policy.Policy) ([]engine.Mount, error) {
	raw, _, err := r.mountsFor(m, p)
	if err != nil {
		return nil, err
	}
	return buildMounts(raw)
}

func buildMounts(raw []rawMount) ([]engine.Mount, error) {
	var out []engine.Mount
	for _, mt := range raw {
		var em engine.Mount
		var err error
		if mt.volume {
			em, err = engine.NewVolumeMount(mt.source, mt.target)
		} else {
			em, err = engine.NewBindMount(mt.source, mt.target, mt.readOnly)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, em)
	}
	return out, nil
}
