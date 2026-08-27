package ui

import (
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

// fder is what a stream must be to possibly be a terminal: something backed by a file descriptor.
// An in-process buffer, a strings.Reader, an io.Pipe — none of them are, and none of them get the
// interface.
type fder interface{ Fd() uintptr }

// IsTerminal reports whether a stream is a terminal.
//
// The question is asked of the kernel, with the same ioctl every isatty in existence uses: fetching
// the terminal attributes of a descriptor succeeds on a tty and fails on anything else. Guessing
// from the environment (TERM, CI, a --plain flag) answers a DIFFERENT question and answers it wrong
// in both directions.
func IsTerminal(s any) bool {
	f, ok := s.(fder)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// Interactive decides whether this invocation is driven by the terminal interface.
//
// BOTH STREAMS MUST BE TERMINALS. stdout alone is not enough: a piped or redirected stdin means
// there is no operator at the keyboard, and an overlay asking a question of a pipe is a modal
// nobody can dismiss. And a redirected stdout means something is capturing the output, which must
// keep seeing exactly the lines the plain path prints.
//
// MI_CONFIRM DECIDES THE OTHER WAY. If it is present in the environment AT ALL, this invocation
// takes the plain path — so a `yes` or a `no` is honoured by cliio.Confirm exactly as it always was
// and never reaches an overlay. The test is PRESENCE, not value: MI_CONFIRM is set by scripts and
// by test harnesses, and a value the tri-state does not recognise still says "this is not a person
// at a keyboard". Reading it as "only yes/no counts" would put a harness that exports
// MI_CONFIRM= (empty) in front of a modal it cannot answer.
func Interactive(env []string, stdin io.Reader, stdout io.Writer) bool {
	return interactive(env, stdin, stdout, IsTerminal)
}

// interactive is Interactive with the terminal probe injected. The DECISION — both streams, and
// MI_CONFIRM deciding the other way — is the part that must never be wrong, and a real terminal is
// not available to a test process; separating the two is what lets every branch of it be asserted
// rather than reasoned about.
func interactive(env []string, stdin io.Reader, stdout io.Writer, isTTY func(any) bool) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, "MI_CONFIRM=") {
			return false
		}
	}
	return isTTY(stdin) && isTTY(stdout)
}
