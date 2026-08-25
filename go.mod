// MODULE PATH. `mythicalos.ai/ctl` is the product's own domain, the same convention the
// family's first Go module established: the import path does not encode where the source
// happens to be hosted. No vanity-import meta tag is served, `go install ...@latest` is not a
// supported channel, and nothing here needs the path to resolve over the network — the binary
// ships as a prebuilt, digest-verified release asset.
//
// DEPENDENCIES. Direct requires are added only by the tasks the rewrite plan names: the three
// Charm packages (the TUI wave) and golang.org/x/sys (flock, isatty). Everything else in this
// file's future `// indirect` block is their tool-managed transitive closure. Adding any other
// DIRECT dependency is a plan violation — stop and escalate rather than require it.
module mythicalos.ai/ctl

go 1.24.0
