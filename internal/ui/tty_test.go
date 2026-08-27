// NO BATS INVENTORY — see confirm_test.go's header. The reference has no interface to choose
// between, so it makes no such decision and has no test of one.
package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// fakeStream carries a file descriptor without being a file, so the decision can be driven from
// either side without a terminal.
type fakeStream struct{ fd uintptr }

func (f fakeStream) Fd() uintptr               { return f.fd }
func (fakeStream) Read([]byte) (int, error)    { return 0, nil }
func (fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func alwaysTTY(any) bool                       { return true }
func neverTTY(any) bool                        { return false }
func ttyIf(want any) func(any) bool            { return func(s any) bool { return s == want } }

// TestInteractiveNeedsBothStreams. stdout alone is not enough: a piped or redirected stdin means
// nobody is at the keyboard, and an overlay asking a question of a pipe is a modal that can never be
// dismissed. A redirected stdout means something is capturing the output and must keep seeing
// exactly the lines the plain path prints.
func TestInteractiveNeedsBothStreams(t *testing.T) {
	in, out := fakeStream{fd: 1}, fakeStream{fd: 2}
	if !interactive(nil, in, out, alwaysTTY) {
		t.Fatal("two terminals and no MI_CONFIRM must select the interface")
	}
	if interactive(nil, in, out, neverTTY) {
		t.Fatal("neither stream is a terminal and the interface was selected")
	}
	if interactive(nil, in, out, ttyIf(out)) {
		t.Fatal("stdout alone selected the interface — a piped stdin must never meet an overlay")
	}
	if interactive(nil, in, out, ttyIf(in)) {
		t.Fatal("stdin alone selected the interface — a redirected stdout must keep the plain lines")
	}
}

// TestInteractiveRefusesWheneverMIConfirmIsSet is the parity guard the plan names: MI_CONFIRM=yes
// and MI_CONFIRM=no must never reach an overlay, so the tri-state in cliio.Confirm decides them
// exactly as it always has. The test is PRESENCE, not value — a harness that exports an
// unrecognised value is still not a person at a keyboard.
func TestInteractiveRefusesWheneverMIConfirmIsSet(t *testing.T) {
	in, out := fakeStream{fd: 1}, fakeStream{fd: 2}
	for _, v := range []string{"yes", "no", "", "maybe", "YES", "1"} {
		env := []string{"HOME=/tmp", "MI_CONFIRM=" + v, "TERM=xterm"}
		if interactive(env, in, out, alwaysTTY) {
			t.Errorf("MI_CONFIRM=%q reached the interface", v)
		}
	}
	// A variable that merely CONTAINS the name is not MI_CONFIRM.
	for _, kv := range []string{"XMI_CONFIRM=yes", "MI_CONFIRMED=yes", "MI_CONFIRM", "NOT_MI_CONFIRM=no"} {
		if !interactive([]string{kv}, in, out, alwaysTTY) {
			t.Errorf("%q was mistaken for MI_CONFIRM", kv)
		}
	}
}

// TestIsTerminalRejectsWhatIsNotATerminal. /dev/null is the case that proves the probe is a real
// isatty rather than "does this have a descriptor": it is a character device with a perfectly good
// fd and it is not a terminal.
func TestIsTerminalRejectsWhatIsNotATerminal(t *testing.T) {
	if IsTerminal(&bytes.Buffer{}) {
		t.Fatal("a buffer reported as a terminal")
	}
	if IsTerminal(nil) {
		t.Fatal("nil reported as a terminal")
	}
	if IsTerminal(strings.NewReader("y\n")) {
		t.Fatal("a string reader reported as a terminal")
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if IsTerminal(devnull) {
		t.Fatal("/dev/null reported as a terminal — the probe is not an isatty")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(r) || IsTerminal(w) {
		t.Fatal("a pipe reported as a terminal")
	}

	// A closed file's descriptor is -1 once converted; the probe must answer false rather than
	// panic or take the error as a yes.
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if IsTerminal(closed) {
		t.Fatal("a closed file reported as a terminal")
	}
}

// TestIsTerminalAcceptsARealTerminal, when this process has one. A test binary is routinely run
// with no controlling terminal (CI, and this project's own agent shells), so the positive case is
// SKIPPED rather than faked: asserting it against a stub would only prove the stub.
func TestIsTerminalAcceptsARealTerminal(t *testing.T) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no controlling terminal in this process: %v", err)
	}
	defer f.Close()
	if !IsTerminal(f) {
		t.Fatal("/dev/tty was not recognised as a terminal — the ioctl request constant is wrong for this platform")
	}
	if !Interactive(nil, f, f) {
		t.Fatal("a real terminal on both streams did not select the interface")
	}
}

// TestInteractiveUsesTheRealProbe — the exported entry point must be wired to IsTerminal, not left
// pointing at something more permissive.
func TestInteractiveUsesTheRealProbe(t *testing.T) {
	if Interactive(nil, &bytes.Buffer{}, &bytes.Buffer{}) {
		t.Fatal("two buffers selected the interface")
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	// A stream that carries a perfectly good descriptor but is not a terminal.
	if Interactive(nil, fakeStream{fd: devnull.Fd()}, fakeStream{fd: devnull.Fd()}) {
		t.Fatal("a non-terminal descriptor selected the interface")
	}
}
