// Command boundary-gate enforces reference boundaries: a guarded identifier of one package may
// be referenced only from an allowlisted set of packages.
//
// Why an AST walk and not a grep: a grep for `Name(` misses a function VALUE — in
// `f := engine.NewMutator; f(...)` the guarded name never appears with a parenthesis. This
// tool resolves REFERENCES: any selector use of the guarded identifier through an import of
// the guarded package counts, call or not. A dot-import of a guarded package is refused
// outright, because it makes references unattributable at this level of analysis.
//
// Usage: boundary-gate <rule>...
// Rule grammar, two forms:
//
//	<guarded-import-path>:<Identifier>=<allowed>[,<more>]   package-level symbol
//	method:<Identifier>=<allowed>[,<more>]                  METHOD name, receiver-independent
//
// The `method:` form exists because a method call — `m.ContainerCreate(...)` — or a method
// value has a VARIABLE receiver, which import-alias resolution cannot attribute; such a rule
// therefore flags ANY selector use of the identifier in a non-allowed file. That deliberately
// overmatches (a same-named method on an unrelated type would trip it); for a gate, a loud
// false positive beats a silent bypass, and the guarded names are chosen distinctive.
//
// An `<allowed>` entry is an import path — or, when it ends in `.go`, a single FILE
// (module-relative path), so a rule can pin a symbol to one file within a package.
// THE GUARDED PACKAGE ITSELF IS NOT EXEMPT: a bare in-package reference to the guarded
// identifier (`NewMutator(...)`, or a function value) is a violation unless that package is
// allowlisted explicitly — only the declaration itself is not a reference. Otherwise a
// production file added inside the guarded package could build the guarded thing with no
// gate ever seeing it. *_test.go files are exempt (tests exercise boundaries deliberately).
//
// Stdlib only — this tool guards the dependency-minimal tree and must not itself add to it.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type rule struct {
	pkgPath string          // the guarded package's import path; "" for a method: rule
	ident   string          // the guarded identifier (or method name)
	allowed map[string]bool // import paths — or `.go` file paths — permitted to reference it
}

// isMethod reports the receiver-independent form.
func (r rule) isMethod() bool { return r.pkgPath == "" }

// allows answers for a file, by its package path and its module-relative file path.
func (r rule) allows(filePkgPath, fileRel string) bool {
	return r.allowed[filePkgPath] || r.allowed[filepath.ToSlash(fileRel)]
}

func parseRule(s string) (rule, error) {
	colon := strings.LastIndex(strings.SplitN(s, "=", 2)[0], ":")
	eq := strings.Index(s, "=")
	if colon < 0 || eq < 0 || eq < colon {
		return rule{}, fmt.Errorf("malformed rule %q (want [method|<pkg-path>]:<Ident>=<allowed>[,<allowed>])", s)
	}
	r := rule{pkgPath: s[:colon], ident: s[colon+1 : eq], allowed: map[string]bool{}}
	if r.ident == "" {
		return rule{}, fmt.Errorf("malformed rule %q (empty identifier)", s)
	}
	if r.pkgPath == "method" {
		r.pkgPath = ""
	} else if r.pkgPath == "" {
		return rule{}, fmt.Errorf("malformed rule %q (empty package; use the method: form for receiver-independent rules)", s)
	}
	// No implicit allowance for the defining package — see the package doc.
	for _, a := range strings.Split(s[eq+1:], ",") {
		if a = strings.TrimSpace(a); a != "" {
			r.allowed[a] = true
		}
	}
	return r, nil
}

// modulePath reads the module path from go.mod at root, so file paths map to import paths
// without loading the build system.
func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("no module line in go.mod")
}

// check walks one file and reports each rule violation as "<pos>: <message>".
// declared maps a module-local import path to its DECLARED package name — which Go binds for
// an unaliased import, and which need not equal the path basename (`package daemon` living at
// .../engine imports as `daemon`). Falling back to the basename is only for paths the module
// does not own, which no rule can guard anyway.
func check(fset *token.FileSet, f *ast.File, filePkgPath, fileRel string, declared map[string]map[string]bool, rules []rule) []string {
	var out []string
	// alias -> SET of import paths, for this file. A set, not a single path: two imports can
	// bind the same name (a build-tagged decoy file can declare the guarded package's active
	// name for a harmless path), and last-write-wins would let the guarded binding be
	// shadowed. A selector matches a rule if ANY path bound to its receiver name is guarded —
	// overmatch-safe, shadow-proof.
	imports := map[string]map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		var names []string
		if imp.Name != nil {
			names = []string{imp.Name.Name}
		} else if ds := declared[path]; len(ds) > 0 {
			// EVERY declared name in the directory binds: a build-constrained or ignored file
			// with a different package name must widen the match, never shadow it — for a
			// gate, overmatching is safe and undermatching is the failure mode.
			for d := range ds {
				names = append(names, d)
			}
		} else {
			names = []string{path[strings.LastIndex(path, "/")+1:]}
		}
		for _, r := range rules {
			if !r.isMethod() && path == r.pkgPath && !r.allows(filePkgPath, fileRel) {
				for _, name := range names {
					if name == "." {
						out = append(out, fmt.Sprintf("%s: dot-import of guarded package %s",
							fset.Position(imp.Pos()), r.pkgPath))
					}
				}
			}
		}
		for _, name := range names {
			if name != "_" && name != "." {
				if imports[name] == nil {
					imports[name] = map[string]bool{}
				}
				imports[name][path] = true
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// Method rules first: receiver-independent, so ANY selector spelling of the name in a
		// non-allowed file trips — method call, method value, or package selector alike.
		for _, r := range rules {
			if r.isMethod() && sel.Sel.Name == r.ident && !r.allows(filePkgPath, fileRel) {
				out = append(out, fmt.Sprintf("%s: method %s referenced outside its boundary (allowed: %s)",
					fset.Position(sel.Pos()), r.ident, strings.Join(allowedList(r), ", ")))
			}
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		paths, ok := imports[x.Name]
		if !ok {
			return true
		}
		for _, r := range rules {
			if !r.isMethod() && paths[r.pkgPath] && sel.Sel.Name == r.ident && !r.allows(filePkgPath, fileRel) {
				out = append(out, fmt.Sprintf("%s: %s.%s referenced outside its boundary (allowed: %s)",
					fset.Position(sel.Pos()), r.pkgPath, r.ident, strings.Join(allowedList(r), ", ")))
			}
		}
		return true
	})
	// The DEFINING package: an in-package reference is a bare identifier, never a selector
	// through an import, so the walk above cannot see it. Every use of the guarded name in a
	// non-allowlisted file of the guarded package is a violation — except the declaration.
	for _, r := range rules {
		if r.isMethod() || filePkgPath != r.pkgPath || r.allows(filePkgPath, fileRel) {
			continue
		}
		decls := declaredNames(f)
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && id.Name == r.ident && !decls[id] {
				out = append(out, fmt.Sprintf("%s: %s referenced inside its defining package %s, which is not allowlisted (allowed: %s)",
					fset.Position(id.Pos()), r.ident, r.pkgPath, strings.Join(allowedList(r), ", ")))
			}
			return true
		})
	}
	return out
}

// declaredNames collects the identifiers a file DECLARES at package level — function, type
// and value names — so the in-package check can tell a declaration from a reference.
// Methods are excluded on purpose: a method named like a guarded package-level symbol is a
// different identifier in Go, but for a gate the overmatch is the safe side.
func declaredNames(f *ast.File) map[*ast.Ident]bool {
	names := map[*ast.Ident]bool{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				names[d.Name] = true
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					names[s.Name] = true
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names[n] = true
					}
				}
			}
		}
	}
	return names
}

func allowedList(r rule) []string {
	var out []string
	for p := range r.allowed {
		out = append(out, p)
	}
	return out
}

// run performs the whole scan so tests can call it in-process against a fixture tree.
func run(root string, ruleArgs []string) (violations []string, err error) {
	rules := make([]rule, 0, len(ruleArgs))
	for _, s := range ruleArgs {
		r, err := parseRule(s)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	type parsed struct {
		f           *ast.File
		filePkgPath string
		rel         string
	}
	var files []parsed
	declared := map[string]map[string]bool{} // module-local import path -> declared package NAMES (a set: build-constrained files may declare differently)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		filePkgPath := mod
		if dir != "." {
			filePkgPath = mod + "/" + dir
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if f.Name != nil {
			if declared[filePkgPath] == nil {
				declared[filePkgPath] = map[string]bool{}
			}
			declared[filePkgPath][f.Name.Name] = true
		}
		files = append(files, parsed{f: f, filePkgPath: filePkgPath, rel: rel})
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, pf := range files {
		violations = append(violations, check(fset, pf.f, pf.filePkgPath, pf.rel, declared, rules)...)
	}
	return violations, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "boundary-gate: no rules given")
		os.Exit(2)
	}
	violations, err := run(".", os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundary-gate: %v\n", err)
		os.Exit(2)
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, v)
		}
		fmt.Fprintf(os.Stderr, "boundary-gate: %d violation(s)\n", len(violations))
		os.Exit(1)
	}
	fmt.Println("boundary-gate: clean")
}
