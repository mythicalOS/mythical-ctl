package manifest

import (
	"fmt"

	"mythicalos.ai/ctl/internal/docfmt"
)

// Core-derived naming (D32): runtime identifiers are computed from the INSTALLATION identity
// plus the product identity. ~/.mythical/ is per-user but container and volume names are
// daemon-GLOBAL — two OS users on one daemon would otherwise compute the same names and adopt
// or delete each other's containers.
//
// NOT INJECTIVE, stated: `-` is inside the ident charset, so the flat join is ambiguous about
// where one part ends and the next begins. A manifest alone cannot exploit it (the colliding
// role must be policy-granted and the colliding product index-vouched), but two INSTALLATION
// IDENTITIES that collide under this join are a precondition on the identity string — which is
// why the ledger's mint is `i`+10 hex with NO hyphen and fixed length; whatever else ever
// produces an identity inherits that discipline.
//
// BOUNDED, BUT NOT HERE: a 64-byte ident can push a derived name past the 63-character DNS
// label limit; the identity producer respects the bound, and failing loudly at the container
// runtime is a known, later concern rather than a security hole to close here.

// NamePrefix opens every derived runtime name.
const NamePrefix = "mythical"

func partOK(s string) bool { return docfmt.IdentOK(s) }

// VolumeName derives mythical-<identity>-<product>-<role>.
func VolumeName(identity, product, role string) (string, error) {
	if !partOK(identity) || !partOK(product) || !partOK(role) {
		return "", fmt.Errorf("manifest: cannot derive a volume name from %q/%q/%q", identity, product, role)
	}
	return NamePrefix + "-" + identity + "-" + product + "-" + role, nil
}

// ContainerName derives mythical-<identity>-<product>.
func ContainerName(identity, product string) (string, error) {
	if !partOK(identity) || !partOK(product) {
		return "", fmt.Errorf("manifest: cannot derive a container name from %q/%q", identity, product)
	}
	return NamePrefix + "-" + identity + "-" + product, nil
}

// NetworkName derives mythical-<identity>-net.
func NetworkName(identity string) (string, error) {
	if !partOK(identity) {
		return "", fmt.Errorf("manifest: cannot derive a network name from %q", identity)
	}
	return NamePrefix + "-" + identity + "-net", nil
}

// Alias is the STABLE cross-product DNS name: `mythical-<product>` — the one name the whole
// family already agrees on (maintainer ruling 2026-07-29). It exists because the container
// name embeds an installation identity a sibling has no way to know. Two different names, and
// conflating them is what once put the bare form here: the DNS name is `mythical-<product>`;
// the `product` string each sibling reports at /detect is the BARE key. A bare ALIAS would
// have made service-DNS discovery miss on every deployment that publishes no host ports —
// with every component reporting healthy.
func Alias(product string) (string, error) {
	if !partOK(product) {
		return "", fmt.Errorf("manifest: %q is not a product identifier", product)
	}
	return NamePrefix + "-" + product, nil
}

// FamilyPorts is the family UI-port table (D15) — this repo's machine-readable single source
// of truth, one of THREE independent owners of the same numbers (the sibling products carry
// their own copies); a cross-repo contract test reconciles them, never a vendored shared copy.
func FamilyPorts() map[string]uint16 {
	return map[string]uint16{
		"brokkr": 7480,
		"saga":   7482,
		"skuld":  7481,
	}
}
