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

require (
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/x/ansi v0.10.1
	golang.org/x/sys v0.36.0
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/text v0.3.8 // indirect
)
