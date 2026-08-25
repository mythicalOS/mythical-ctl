package cliio

import (
	"bufio"
	"io"
	"strings"
)

// An action that destroys data asks first. MI_CONFIRM short-circuits the prompt
// non-interactively — `yes` to proceed, `no` to refuse — so both outcomes are testable without
// a tty; with neither set, the operator is prompted and anything but an explicit yes refuses.
// Note which way the default falls: a bare newline, EOF, a closed stdin, and a read error all
// REFUSE, so a purge cannot be carried by a pipe that happened to be empty.
//
// This is the ONE confirmation implementation in the tree. The TUI overlay collects a complete
// line and resolves it through AcceptedReply below; there is no second contract to drift.

// ConfirmFunc is the seam the verbs carry in their Deps: the plain path wraps Confirm over the
// process env and streams, the TUI path routes the same contract through an overlay.
type ConfirmFunc func(prompt string) bool

// AcceptedReply reports whether one complete reply line is an explicit yes. Exactly the bash
// accept-set — y, Y, yes, Yes, YES — and nothing else: no trimming, no prefix matching, so
// "yess" and " y" both refuse.
func AcceptedReply(line string) bool {
	switch line {
	case "y", "Y", "yes", "Yes", "YES":
		return true
	}
	return false
}

// Confirm is the mi_confirm tri-state. env is the process environment (os.Environ() shape,
// "KEY=value"); r is the operator's stdin, w the stream the prompt renders on (stderr at call
// sites, as bash does — the prompt is not output).
func Confirm(env []string, r io.Reader, w io.Writer, prompt string) bool {
	switch confirmEnv(env) {
	case "yes":
		return true
	case "no":
		return false
	}
	if prompt == "" {
		prompt = "Proceed?"
	}
	if _, err := io.WriteString(w, prompt+" [y/N] "); err != nil {
		return false
	}
	// ANY failed read refuses — including data-then-EOF: bash's `read -r` fails (rc 1) on a
	// line with no terminating newline even though it filled the variable, and mi_confirm
	// returns refusal on that failure. An unterminated "y" is not consent there, so it is not
	// consent here.
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return AcceptedReply(line)
}

// confirmEnv extracts MI_CONFIRM from an environ slice. Only the exact values `yes` and `no`
// are decisions; anything else means "not set" and the prompt decides — the same reading the
// bash `case "${MI_CONFIRM:-}"` performs.
func confirmEnv(env []string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "MI_CONFIRM="); ok {
			if v == "yes" || v == "no" {
				return v
			}
		}
	}
	return ""
}
