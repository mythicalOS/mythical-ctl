package docfmt

import (
	"strings"

	"mythicalos.ai/ctl/internal/conf"
	"mythicalos.ai/ctl/internal/volatile"
)

// TypeOK is the document type vocabulary: the doc-specific types here, everything else
// delegated to the config engine — ONE implementation of str/int/enum/bool/path/netname, not a
// second that can drift (the bash's _mi_doc_type_ok default branch, verbatim in spirit).
func TypeOK(typ, v string) bool {
	switch typ {
	case "docver", "epoch":
		// Non-negative, non-empty, bounded digits.
		return digitsOK(v)
	case "ident":
		return IdentOK(v)
	case "sha256":
		return sha256OK(v)
	case "digestref":
		return digestrefOK(v)
	case "productdigest":
		// <product>:<64 hex> — the family index's flat encoding of "this product's manifest
		// must hash to this". Exactly one colon (redundant by construction — ':' is not hex —
		// and kept as the explicit statement of the rule).
		p, h, ok := strings.Cut(v, ":")
		if !ok || strings.Contains(h, ":") {
			return false
		}
		return IdentOK(p) && sha256OK(h)
	case "coreversion":
		return CoreVersionOK(v)
	case "cpath":
		// A bounded absolute CONTAINER path of safe segments — the value of a field that names a
		// single mount point and nothing else. Stricter than `path:<n>`: safe-segment charset
		// only, a 2..512-byte bound, no trailing slash and no bare root, so the field can carry
		// no second token and no options sub-grammar.
		//
		// THE RULE IS CALLED, NOT COPIED. It lives in internal/volatile — the package that also
		// owns the mount's fixed hardening — so the manifest DOOR and the LAUNCH SITE cannot
		// drift into accepting different paths. A second copy here would be a validator that
		// agrees today and diverges the first time either is touched.
		return volatile.PathOK(v)
	case "rolemount":
		// <role>:<absolute path> — the flat encoding of what a nested format would object-ify.
		role, path, ok := strings.Cut(v, ":")
		if !ok || strings.Contains(path, ":") {
			return false
		}
		if !IdentOK(role) || !strings.HasPrefix(path, "/") || len(path) > 4096 {
			return false
		}
		return !strings.Contains("/"+path+"/", "/../")
	}
	return conf.TypeOK(typ, v)
}

func digitsOK(v string) bool {
	if v == "" || len(v) > 18 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// IdentOK: lowercase letter, then [a-z0-9-], at most 64 — the name grammar every component of
// a runtime name satisfies.
func IdentOK(v string) bool {
	if v == "" || len(v) > 64 || v[0] < 'a' || v[0] > 'z' {
		return false
	}
	for i := 1; i < len(v); i++ {
		b := v[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
			return false
		}
	}
	return true
}

func sha256OK(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

// digestrefOK: <repository>@sha256:<64 hex>. A TAG IS NOT A DIGEST (D22) — no floating
// reference is accepted at all, so the check is for the pinned shape. The repository half
// carries only a sanity bound (the digest half carries the security property): lowercase,
// digits, `. _ - / :`, ≤255, not starting/ending on a separator, and no EMPTY segment
// (`a//b`, `repo::5000`, `a:/b`, `a/:b` all bracket a blank component and are not valid
// references — better refused at the door than at run time).
func digestrefOK(v string) bool {
	repo, hex, ok := strings.Cut(v, "@sha256:")
	if !ok || repo == "" {
		return false
	}
	// Exactly one @ — redundant by construction ('@' is outside the charset below) and kept
	// as the explicit rule, so relaxing the charset cannot silently drop it.
	if strings.Contains(repo, "@") || strings.Contains(hex, "@") {
		return false
	}
	if len(repo) > 255 {
		return false
	}
	for i := 0; i < len(repo); i++ {
		b := repo[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '.' && b != '_' && b != '-' && b != '/' && b != ':' {
			return false
		}
	}
	if strings.HasPrefix(repo, "/") || strings.HasPrefix(repo, ":") ||
		strings.HasSuffix(repo, "/") || strings.HasSuffix(repo, ":") {
		return false
	}
	for _, bad := range []string{"//", "::", ":/", "/:"} {
		if strings.Contains(repo, bad) {
			return false
		}
	}
	return sha256OK(hex)
}

// CoreVersionOK: MAJOR[.MINOR[.PATCH]] — bounded numeric components, nothing else.
// Deliberately not full semver: pre-release ordering rules are machinery a minimum-core
// requirement has no need of.
func CoreVersionOK(v string) bool {
	if v == "" {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !digitsOK(p) {
			return false
		}
	}
	return true
}

// Typed returns a KeySpec whose Validate is TypeOK for typ — the convenience every schema
// definition site uses, so the type vocabulary stays in one place.
func Typed(card Card, typ string) KeySpec {
	return KeySpec{Card: card, Validate: func(v string) bool { return TypeOK(typ, v) }}
}
