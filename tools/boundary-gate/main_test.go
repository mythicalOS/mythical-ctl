package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree lays a fixture module on disk: map of relative path -> content.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const fixtureGoMod = "module example.test/mod\n\ngo 1.24.0\n"

const guardedPkg = `package engine

func NewMutator() int { return 1 }
func Benign() int     { return 2 }
`

// The self-test the plan requires per rule: an INDIRECT reference (function value, no call
// parentheses) must fail the gate — the exact form a grep for "NewMutator(" misses.
func TestIndirectReferenceIsCaught(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                    fixtureGoMod,
		"internal/engine/engine.go": guardedPkg,
		"internal/rogue/rogue.go": `package rogue

import "example.test/mod/internal/engine"

var f = engine.NewMutator // no call: a bare function value
`,
	})
	v, err := run(root, []string{"example.test/mod/internal/engine:NewMutator=example.test/mod/internal/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "NewMutator referenced outside its boundary") {
		t.Fatalf("want 1 indirect-reference violation, got %v", v)
	}
}

func TestDirectCallIsCaughtAndAllowedPackagePasses(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                    fixtureGoMod,
		"internal/engine/engine.go": guardedPkg,
		"internal/runtime/ok.go": `package runtime

import "example.test/mod/internal/engine"

var n = engine.NewMutator() // the allowlisted caller
`,
		"internal/rogue/rogue.go": `package rogue

import "example.test/mod/internal/engine"

var n = engine.NewMutator()
`,
	})
	v, err := run(root, []string{"example.test/mod/internal/engine:NewMutator=example.test/mod/internal/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "rogue") {
		t.Fatalf("want exactly the rogue violation, got %v", v)
	}
}

func TestUnguardedIdentifierAndTestFilesAreExempt(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                    fixtureGoMod,
		"internal/engine/engine.go": guardedPkg,
		"internal/rogue/rogue.go": `package rogue

import "example.test/mod/internal/engine"

var n = engine.Benign() // not the guarded identifier
`,
		"internal/rogue/rogue_test.go": `package rogue

import "example.test/mod/internal/engine"

var m = engine.NewMutator() // tests may exercise boundaries deliberately
`,
	})
	v, err := run(root, []string{"example.test/mod/internal/engine:NewMutator=example.test/mod/internal/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("want no violations, got %v", v)
	}
}

func TestDotImportOfGuardedPackageIsRefused(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                    fixtureGoMod,
		"internal/engine/engine.go": guardedPkg,
		"internal/rogue/rogue.go": `package rogue

import . "example.test/mod/internal/engine"

var n = NewMutator() // unattributable through a dot-import; the import itself is the violation
`,
	})
	v, err := run(root, []string{"example.test/mod/internal/engine:NewMutator=example.test/mod/internal/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "dot-import") {
		t.Fatalf("want the dot-import violation, got %v", v)
	}
}

func TestMalformedRuleIsAnError(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": fixtureGoMod})
	if _, err := run(root, []string{"no-separators"}); err == nil {
		t.Fatal("malformed rule accepted")
	}
}

// The method: rule form — the round-fix for the finding that a method call or method value has
// a variable receiver and evades import-alias attribution.
func TestMethodRuleCatchesCallAndValue(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": fixtureGoMod,
		"internal/rogue/rogue.go": `package rogue

type mut struct{}

func (mut) ContainerCreate() int { return 1 }

var m mut
var a = m.ContainerCreate()  // method CALL through a variable receiver
var b = m.ContainerCreate    // method VALUE
`,
		"internal/runtime/launch.go": `package runtime

type mut struct{}

func (mut) ContainerCreate() int { return 1 }

var m mut
var ok = m.ContainerCreate() // the allowlisted file
`,
	})
	v, err := run(root, []string{"method:ContainerCreate=example.test/mod/internal/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 2 {
		t.Fatalf("want the rogue call AND the rogue value flagged, got %v", v)
	}
	for _, s := range v {
		if !strings.Contains(s, "rogue") {
			t.Fatalf("flagged outside rogue: %v", v)
		}
	}
}

// A `.go` allow entry pins a symbol to ONE FILE within a package: the same package's other
// file is a violation.
func TestFileLevelAllowancePinsToOneFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": fixtureGoMod,
		"internal/runtime/launch.go": `package runtime

type mut struct{}

func (mut) ContainerCreate() int { return 1 }

var m mut
var ok = m.ContainerCreate()
`,
		"internal/runtime/other.go": `package runtime

var also = m.ContainerCreate() // same package, WRONG file
`,
	})
	v, err := run(root, []string{"method:ContainerCreate=internal/runtime/launch.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "other.go") {
		t.Fatalf("want exactly the other.go violation, got %v", v)
	}
}
