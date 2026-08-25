// Package version carries the binary's version string.
//
// The default is a dev marker; a release build stamps the real version via
// -ldflags "-X mythicalos.ai/ctl/internal/version.Version=<v>". It is a variable, not a
// constant, for exactly that reason — and nothing else in the tree may write it.
package version

// Version is the version `--version` and `-v` print. SemVer, with a `-suffix` permitted
// (the dev default below, release-candidate stamps); consumers that compare numeric cores
// (the manifest min_core gate) strip the suffix first.
var Version = "0.1.0-dev"
