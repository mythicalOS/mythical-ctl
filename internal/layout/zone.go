package layout

import "strings"

// Zone is a home-relative path's §6c ownership class. Deletion and backup rules key on this:
// the installer deletes only what it created, by name, and `user-owned` is the class it
// promises never to touch.
type Zone int

const (
	// ZoneUnknown — a top-level path the layout does not know. Callers treat unknown as
	// untouchable.
	ZoneUnknown Zone = iota
	// ZoneInstallerState — .state/: the lock and the ledger. The installer's, not an editing
	// surface.
	ZoneInstallerState
	// ZoneInstallerManaged — bin/ and generated per-product artifacts. The installer creates
	// and removes these by name.
	ZoneInstallerManaged
	// ZoneUserData — transcripts/ and logs/: product data the installer never creates and
	// never removes.
	ZoneUserData
	// ZoneUserOwned — the operator's files: the two top-level .conf files, and the host-tool
	// slot `<product>/cli.toml`.
	ZoneUserOwned
)

func (z Zone) String() string {
	switch z {
	case ZoneInstallerState:
		return "installer-state"
	case ZoneInstallerManaged:
		return "installer-managed"
	case ZoneUserData:
		return "user-data"
	case ZoneUserOwned:
		return "user-owned"
	}
	return "unknown"
}

// ZoneOf classifies one home-relative path. The arm ORDER is the bash's and it is
// load-bearing: every nested path must be decided before the top-level `*.conf` rule, or
// `brokkr/generated.conf` would read as user-owned across the flat/nested boundary.
//
// THE HOST-TOOL SLOT (docs/CONFIG-FORMAT.md, "Amendment: the host-tool slot") is the one leaf
// carved out of the installer-managed product directory: `<product>/cli.toml` is where a
// product's HOST-SIDE tool keeps its own configuration, including host-only credentials, and
// it is user-owned — the installer never creates, reads, writes or removes it. It is not
// `<product>.conf`, because that file is bind-mounted into the product's container
// read-write, which is the last place a host-only bearer token may live.
//
// The slot decision has two halves, both fail-closed: the LEAF must be exactly `cli.toml` at
// exactly one level (so `brokkr/generated/cli.toml` and `../cli.toml` fall back to
// installer-managed — the class the path carried before the carve-out existed), and the
// leading component must satisfy the FULL product-name grammar via ProductNameOK — its one
// authority — so `fooBAR/cli.toml`, `9lives/cli.toml` and an over-long name are refused.
// Three product names can never carry a slot — `bin`, `logs`, `transcripts` — because their
// arms sit above this one; that limit is pinned by the published document and by tests.
//
// The bash version carried nocasematch/BASH_ENV defenses here (a shell option could make its
// `case` globs match case-insensitively); Go string comparison has no ambient collation, so
// those defenses have nothing to defend against — the case-sensitivity TESTS still port, the
// machinery does not.
func ZoneOf(p string) Zone {
	switch {
	case strings.HasPrefix(p, ".state/"):
		return ZoneInstallerState
	case p == "bin" || strings.HasPrefix(p, "bin/"):
		return ZoneInstallerManaged
	case p == "transcripts" || strings.HasPrefix(p, "transcripts/") ||
		p == "logs" || strings.HasPrefix(p, "logs/"):
		return ZoneUserData
	case strings.HasSuffix(p, "/cli.toml"):
		// Candidate slot. Exactly one level: everything after the FIRST separator must be the
		// reserved leaf itself.
		first, rest, _ := strings.Cut(p, "/")
		if rest == "cli.toml" && ProductNameOK(first) {
			return ZoneUserOwned
		}
		return ZoneInstallerManaged
	case strings.Contains(p, "/"):
		// Any other nested path = generated artifacts (brokkr/compose.yaml,
		// brokkr/generated.conf).
		return ZoneInstallerManaged
	case p == "mythical.conf" || strings.HasSuffix(p, ".conf"):
		// Top-level confs only — no slash reaches here.
		return ZoneUserOwned
	}
	return ZoneUnknown
}
