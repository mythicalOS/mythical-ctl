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
// The guarded package itself is always allowed (package-level form); *_test.go files are
// exempt (tests exercise boundaries deliberately).
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
	} else {
		r.allowed[r.pkgPath] = true // the defining package always may
	}
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
func check(fset *token.FileSet, f *ast.File, filePkgPath, fileRel string, rules []rule) []string {
	var out []string
	// alias -> import path, for this file.
	imports := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			name = path[strings.LastIndex(path, "/")+1:]
		}
		for _, r := range rules {
			if !r.isMethod() && path == r.pkgPath && !r.allows(filePkgPath, fileRel) {
				if name == "." {
					out = append(out, fmt.Sprintf("%s: dot-import of guarded package %s",
						fset.Position(imp.Pos()), r.pkgPath))
				}
			}
		}
		if name != "_" && name != "." {
			imports[name] = path
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
		path, ok := imports[x.Name]
		if !ok {
			return true
		}
		for _, r := range rules {
			if !r.isMethod() && path == r.pkgPath && sel.Sel.Name == r.ident && !r.allows(filePkgPath, fileRel) {
				out = append(out, fmt.Sprintf("%s: %s.%s referenced outside its boundary (allowed: %s)",
					fset.Position(sel.Pos()), r.pkgPath, r.ident, strings.Join(allowedList(r), ", ")))
			}
		}
		return true
	})
	return out
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
		violations = append(violations, check(fset, f, filePkgPath, rel, rules)...)
		return nil
	})
	return violations, err
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
