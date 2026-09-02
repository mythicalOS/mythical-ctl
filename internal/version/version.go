// Package version carries the binary's version string.
//
// The default is a dev marker; a release build stamps the real version via
// -ldflags "-X mythicalos.ai/ctl/internal/version.Version=<v>". It is a variable, not a
// constant, for exactly that reason — and nothing else in the tree may write it.
package version

// Version is the version `--version` and `-v` print. SemVer, with a `-suffix` permitted
// (the dev default below, release-candidate stamps); consumers that compare numeric cores
// (the manifest min_core gate) strip the suffix first.
//
// IT IS ALSO THE CORE VERSION THE min_core GATE COMPARES AGAINST — manifest.CoreOK is handed
// this exact variable at its one call site, so there is no second constant to drift from it. A
// min_core check against a stale number is worse than none: it passes while the CLI lacks the
// semantics the manifest asked for. Raising it is therefore a statement that this core HONOURS
// something a previous one did not, and a product may now require it.
//
// 0.2.0 is the first core carrying the closed credential-home mount runtime. The boundary is
// pinned by internal/manifest's TestCoreVersionBoundaryIsThisRelease, which fails loudly on the
// next bump rather than quietly re-deriving whatever number is current.
var Version = "0.2.0-dev"
