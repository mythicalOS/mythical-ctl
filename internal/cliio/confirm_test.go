package cliio

import (
	"errors"
	"strings"
	"testing"
)

// Inventory — tests/unit/exit.bats (this package owns only the vocabulary test; the batch
// worst-wins aggregate is verbs-wave scope and inventoried there):
// (exit.bats: "the four codes are exactly §7.3's" — the machine-readable PORTED line lives in exit_test.go, its one owner)
// (exit.bats: "batch precedence is worst-wins: all success is 0" — owned by the verbs wave)
// (exit.bats: "success plus not-launched is 3" — owned by the verbs wave)
// (exit.bats: "any operational failure wins over not-launched" — owned by the verbs wave)
// (exit.bats: "a usage error is never aggregated, wherever it sits in the batch" — verbs wave)
// (exit.bats: "an empty batch is a usage error, not a success" — owned by the verbs wave)
// (exit.bats: "an unknown code is refused rather than mapped to failure, wherever it sits in the batch" — verbs wave)
// (exit.bats: "every code has a human name, for reports" — owned by the verbs wave)
//
// The confirmation contract has no dedicated bats file — it is exercised through verbs.bats'
// purge tests (verbs-wave inventory); these direct tests pin the tri-state itself.

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestConfirmTriState(t *testing.T) {
	cases := []struct {
		name  string
		env   []string
		stdin string
		want  bool
	}{
		{"MI_CONFIRM=yes proceeds unprompted", []string{"MI_CONFIRM=yes"}, "n\n", true},
		{"MI_CONFIRM=no refuses unprompted", []string{"MI_CONFIRM=no"}, "y\n", false},
		{"MI_CONFIRM other value falls through to the prompt", []string{"MI_CONFIRM=YES"}, "\n", false},
		{"y accepts", nil, "y\n", true},
		{"Y accepts", nil, "Y\n", true},
		{"yes accepts", nil, "yes\n", true},
		{"Yes accepts", nil, "Yes\n", true},
		{"YES accepts", nil, "YES\n", true},
		{"bare newline refuses", nil, "\n", false},
		{"n refuses", nil, "n\n", false},
		{"no refuses", nil, "no\n", false},
		{"arbitrary text refuses", nil, "please\n", false},
		{"a suffix refuses (yess)", nil, "yess\n", false},
		{"leading space refuses", nil, " y\n", false},
		{"immediate EOF refuses", nil, "", false},
		{"CRLF refuses — bash read -r keeps the carriage return", nil, "y\r\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var w strings.Builder
			got := Confirm(c.env, strings.NewReader(c.stdin), &w, "Really?")
			if got != c.want {
				t.Fatalf("Confirm = %v, want %v", got, c.want)
			}
		})
	}
}

func TestConfirmPromptShape(t *testing.T) {
	var w strings.Builder
	Confirm(nil, strings.NewReader("y\n"), &w, "Remove volume v1?")
	if w.String() != "Remove volume v1? [y/N] " {
		t.Fatalf("prompt %q, want the bash's exact '<prompt> [y/N] ' shape", w.String())
	}
	// MI_CONFIRM decisions never render a prompt at all.
	var w2 strings.Builder
	Confirm([]string{"MI_CONFIRM=yes"}, strings.NewReader(""), &w2, "Remove?")
	if w2.Len() != 0 {
		t.Fatalf("MI_CONFIRM=yes still prompted: %q", w2.String())
	}
}

func TestConfirmReaderErrorRefuses(t *testing.T) {
	var w strings.Builder
	if Confirm(nil, errReader{}, &w, "Really?") {
		t.Fatal("a read error was accepted as consent")
	}
}

// A final line WITHOUT a trailing newline (EOF ends it) still carries the operator's answer —
// bash's `read -r` fails on it (rc 1) BUT still fills the variable... and mi_confirm returns 1
// on the failed read, refusing. Match the bash: data-then-EOF refuses.
func TestConfirmDataThenEOFRefusesLikeBash(t *testing.T) {
	var w strings.Builder
	if Confirm(nil, strings.NewReader("y"), &w, "Really?") {
		t.Fatal("unterminated 'y' accepted; bash's read -r fails on missing newline and refuses")
	}
}

// Two sequential confirmations on ONE reader must each get their own line — a buffering
// reader would swallow the second answer with the first read.
func TestConfirmReadsExactlyOneLine(t *testing.T) {
	r := strings.NewReader("y\nn\n")
	var w strings.Builder
	if !Confirm(nil, r, &w, "First?") {
		t.Fatal("first confirm refused a plain y")
	}
	if Confirm(nil, r, &w, "Second?") {
		t.Fatal("second confirm consumed the first read's leftover and accepted")
	}
}

func TestSHA256HexMatchesKnownVector(t *testing.T) {
	// sha256("") — the well-known vector; also the memory-hazard sentinel: seeing this digest
	// for real content means you hashed nothing.
	if got := SHA256Hex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("SHA256Hex(nil) = %s", got)
	}
	// PORTED: tests/unit/layout.bats: "mi_digest matches a known sha256" -> TestSHA256HexMatchesKnownVector
	// — the bats vector, verbatim: sha256("abc").
	if got := SHA256Hex([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA256Hex(abc) = %s", got)
	}
}

func TestWarnfShape(t *testing.T) {
	var w strings.Builder
	Warnf(&w, "lock: cannot create %q", "/x")
	if w.String() != "mythical-ctl: lock: cannot create \"/x\"\n" {
		t.Fatalf("Warnf output %q", w.String())
	}
}
