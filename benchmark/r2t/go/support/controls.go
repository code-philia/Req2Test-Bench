// Read-only, compiler-resolved declarations for approved Go empty/noop controls.
// Original source is never rewritten here; no subject tests execute.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Context struct {
	Root        string   `json:"root"`
	PackageDir  string   `json:"package_dir"`
	PackageName string   `json:"package_name"`
	Files       []string `json:"files"`
	Primary     string   `json:"primary"`
	Test        string   `json:"test_name"`
	Tags        []string `json:"go_build_tags"`
	Feature     string   `json:"feature_path"`
	GodogTags   string   `json:"godog_tags"`
	Wrapper     string   `json:"wrapper"`
}
type Pkg struct {
	ImportPath, Name, Dir, Export string
	GoFiles                       []string
	ImportMap                     map[string]string
}
type Span struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}
type ConstantEvidence struct {
	Name         string `json:"name"`
	Origin       Span   `json:"origin"`
	Value        string `json:"compiler_value"`
	ControlValue string `json:"control_value"`
	References   []Span `json:"required_by"`
}
type FileOutput struct {
	Path          string             `json:"path"`
	OriginalSHA   string             `json:"original_sha256"`
	Source        string             `json:"source"`
	Declarations  string             `json:"declarations"`
	SHA           string             `json:"sha256"`
	Functions     map[string]string  `json:"expected_function_bodies"`
	ZeroVariables []string           `json:"zero_variables"`
	Constants     []ConstantEvidence `json:"required_constants"`
	TypeCount     int                `json:"type_count"`
}
type Output struct {
	Context     Context         `json:"context"`
	Files       []FileOutput    `json:"files"`
	TestVariant string          `json:"test_variant"`
	Checks      map[string]bool `json:"checks"`
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func show(fs *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	must(format.Node(&b, fs, n))
	return b.String()
}
func parseBody(s string) *ast.BlockStmt {
	f, e := parser.ParseFile(token.NewFileSet(), "body.go", "package p\nfunc f() "+s, 0)
	must(e)
	return f.Decls[0].(*ast.FuncDecl).Body
}
func main() {
	input := flag.String("context", "", "trusted context JSON")
	flag.Parse()
	b, e := os.ReadFile(*input)
	must(e)
	var c Context
	must(json.Unmarshal(b, &c))
	out, e := plan(c)
	must(e)
	must(json.NewEncoder(os.Stdout).Encode(out))
}
func plan(c Context) (out Output, err error) {
	// Convert bounded unsupported source shapes into an explicit preparation refusal.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("inert declaration preparation refused: %v", r)
		}
	}()
	if len(c.Files) == 0 || c.Root == "" || c.Test == "" || c.Wrapper == "" {
		panic("incomplete trusted context")
	}
	args := []string{"list", "-deps", "-export", "-test", "-json", "-p=1"}
	if len(c.Tags) > 0 {
		args = append(args, "-tags", strings.Join(c.Tags, ","))
	}
	args = append(args, "./"+c.PackageDir)
	cmd := exec.Command("go", args...)
	cmd.Dir = c.Root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if e := cmd.Run(); e != nil {
		panic("go list export: " + e.Error() + "\n" + stderr.String())
	}
	exports := map[string]string{}
	var chosen *Pkg
	dec := json.NewDecoder(&stdout)
	for {
		var p Pkg
		e := dec.Decode(&p)
		if e == io.EOF {
			break
		}
		must(e)
		exports[p.ImportPath] = p.Export
		if p.Name != c.PackageName || filepath.Clean(p.Dir) != filepath.Join(c.Root, c.PackageDir) {
			continue
		}
		set := map[string]bool{}
		for _, f := range p.GoFiles {
			set[filepath.Base(f)] = true
		}
		all := true
		for _, f := range c.Files {
			if !set[filepath.Base(f)] {
				all = false
			}
		}
		if all {
			cp := p
			chosen = &cp
		}
	}
	if chosen == nil {
		panic("full original closure absent from selected test variant")
	}
	fs := token.NewFileSet()
	files := []*ast.File{}
	byPath := map[string]*ast.File{}
	original := map[string][]byte{}
	for _, name := range chosen.GoFiles {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(chosen.Dir, name)
		}
		b, e := os.ReadFile(path)
		must(e)
		f, e := parser.ParseFile(fs, path, b, 0)
		must(e)
		files = append(files, f)
		rel, e := filepath.Rel(c.Root, path)
		must(e)
		byPath[rel] = f
		original[rel] = b
	}
	lookup := func(path string) (io.ReadCloser, error) {
		if m := chosen.ImportMap[path]; m != "" {
			path = m
		}
		if exports[path] == "" {
			return nil, fmt.Errorf("missing export %s", path)
		}
		return os.Open(exports[path])
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Implicits: map[ast.Node]types.Object{}}
	cfg := types.Config{Importer: importer.ForCompiler(fs, "gc", lookup), GoVersion: "go1.25"}
	pkg, e := cfg.Check(chosen.ImportPath, fs, files, info)
	must(e)
	return transform(c, fs, byPath, original, info, pkg, chosen.ImportPath), nil
}
func transform(c Context, fs *token.FileSet, byPath map[string]*ast.File, original map[string][]byte, info *types.Info, pkg *types.Package, variant string) Output {
	closure := map[string]bool{}
	for _, f := range c.Files {
		closure[f] = true
		if byPath[f] == nil {
			panic("missing closure AST")
		}
	}
	for _, n := range []string{"r2tControlHelperCalls", "r2tControlWitness", "r2tControlNoopCalls", "r2tControlCheck"} {
		if pkg.Scope().Lookup(n) != nil {
			panic("reserved control helper name collision")
		}
	}
	span := func(n ast.Node) Span {
		p := fs.PositionFor(n.Pos(), false)
		rel, e := filepath.Rel(c.Root, p.Filename)
		must(e)
		return Span{rel, p.Line, p.Column}
	}
	needed := map[*types.Const][]Span{}
	visit := func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok {
				if co, ok := info.Uses[id].(*types.Const); ok && co.Pkg() == pkg {
					pos := fs.PositionFor(co.Pos(), false)
					rel, e := filepath.Rel(c.Root, pos.Filename)
					must(e)
					if closure[rel] {
						needed[co] = append(needed[co], span(id))
					}
				}
			}
			return true
		})
	}
	// Only retained source and surviving type/signature syntax justify a constant.
	for path, f := range byPath {
		if !closure[path] {
			visit(f)
			continue
		}
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				visit(x.Type)
				if x.Recv != nil {
					visit(x.Recv)
				}
			case *ast.GenDecl:
				if x.Tok == token.TYPE {
					for _, s := range x.Specs {
						visit(s)
					}
				}
			}
		}
	}
	out := Output{Context: c, TestVariant: variant, Checks: map[string]bool{}}
	selectedCount := 0
	for _, path := range c.Files {
		f := byPath[path]
		fr := FileOutput{Path: path, OriginalSHA: hash(original[path]), Functions: map[string]string{}}
		aliases := map[string]string{}
		aliasOwner := map[string]string{}
		used := map[string]string{}
		for _, i := range f.Imports {
			p, e := strconv.Unquote(i.Path.Value)
			must(e)
			var obj types.Object
			if i.Name != nil {
				obj = info.Defs[i.Name]
			} else {
				obj = info.Implicits[i]
			}
			pn, ok := obj.(*types.PkgName)
			if !ok {
				panic("unresolved import")
			}
			name := pn.Name()
			if name == "." || name == "_" {
				panic("unobserved dot/blank import")
			}
			aliases[p] = name
			aliasOwner[name] = p
		}
		qualifier := func(p *types.Package) string {
			if p == pkg {
				return ""
			}
			name := aliases[p.Path()]
			if name == "" {
				name = p.Name()
			}
			if prev := aliasOwner[name]; prev != "" && prev != p.Path() {
				panic("inferred-type import alias collision")
			}
			aliasOwner[name] = p.Path()
			used[p.Path()] = name
			return name
		}
		keepImports := func(n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					if pn, ok := info.Uses[id].(*types.PkgName); ok {
						used[pn.Imported().Path()] = pn.Name()
					}
				}
				return true
			})
		}
		parts := []string{}
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if x.Name.Name == "init" || x.Body == nil || x.Type.TypeParams != nil {
					panic("unobserved init/bodyless/generic function")
				}
				if path == c.Primary && x.Recv == nil && x.Name.Name == c.Test {
					selectedCount++
					continue
				}
				keepImports(x.Type)
				if x.Recv != nil {
					keepImports(x.Recv)
				}
				obj, ok := info.Defs[x.Name].(*types.Func)
				if !ok {
					panic("function object missing")
				}
				sig := obj.Type().(*types.Signature)
				body := "{ r2tControlWitness(" + strconv.Quote(fmt.Sprintf("%s:%d:%s", path, span(x).Line, x.Name.Name)) + ");"
				returns := []string{}
				// Generated local names must not collide with original signature names.
				for i := 0; i < sig.Results().Len(); i++ {
					name := fmt.Sprintf("r2tControlZero%d", i)
					for j := 0; j < sig.Params().Len(); j++ {
						if sig.Params().At(j).Name() == name {
							panic("zero local parameter collision")
						}
					}
					for j := 0; j < sig.Results().Len(); j++ {
						if sig.Results().At(j).Name() == name {
							panic("zero local result collision")
						}
					}
					body += "var " + name + " " + types.TypeString(sig.Results().At(i).Type(), qualifier) + ";"
					returns = append(returns, name)
				}
				if len(returns) > 0 {
					body += "return " + strings.Join(returns, ",") + ";"
				}
				body += "}"
				copy := *x
				copy.Body = parseBody(body)
				copy.Doc = nil
				rendered := show(fs, &copy)
				parts = append(parts, rendered)
				key := x.Name.Name
				if x.Recv != nil {
					key = show(fs, x.Recv.List[0].Type) + "." + key
				}
				fr.Functions[key] = show(token.NewFileSet(), copy.Body)
			case *ast.GenDecl:
				switch x.Tok {
				case token.IMPORT:
				case token.TYPE:
					for _, s := range x.Specs {
						t := s.(*ast.TypeSpec)
						if t.Assign.IsValid() || t.TypeParams != nil {
							panic("unobserved alias/generic type")
						}
						keepImports(t)
						parts = append(parts, "type "+show(fs, t))
						fr.TypeCount++
					}
				case token.VAR:
					for _, s := range x.Specs {
						v := s.(*ast.ValueSpec)
						for _, name := range v.Names {
							obj, ok := info.Defs[name].(*types.Var)
							if !ok || name.Name == "_" {
								panic("unobserved blank/unresolved variable")
							}
							parts = append(parts, "var "+name.Name+" "+types.TypeString(obj.Type(), qualifier))
							fr.ZeroVariables = append(fr.ZeroVariables, name.Name)
						}
					}
				case token.CONST:
					for _, s := range x.Specs {
						v := s.(*ast.ValueSpec)
						for _, name := range v.Names {
							co, ok := info.Defs[name].(*types.Const)
							if !ok {
								panic("constant object missing")
							}
							refs := needed[co]
							sort.Slice(refs, func(i, j int) bool {
								if refs[i].File != refs[j].File {
									return refs[i].File < refs[j].File
								}
								if refs[i].Line != refs[j].Line {
									return refs[i].Line < refs[j].Line
								}
								return refs[i].Column < refs[j].Column
							})
							if len(refs) == 0 {
								continue
							}
							// The only approved surviving constant is needed as a
							// string-compatible name, never for its reference value.
							origin := span(name)
							if path != "internal/agent/bdd_loop_guard_test.go" || name.Name != "bddLoopedSentence" || origin.Line != 26 || co.Val().Kind() != constant.String || co.Val().ExactString() != strconv.Quote("Still writing validation logic... ") || len(refs) != 2 {
								panic("unreviewed required constant")
							}
							for i, ref := range refs {
								if ref.File != "internal/agent/react_test.go" || ref.Line != 1409+i {
									panic("unreviewed retained constant reference")
								}
							}
							parts = append(parts, "const "+name.Name+` = ""`)
							fr.Constants = append(fr.Constants, ConstantEvidence{name.Name, origin, co.Val().ExactString(), `""`, refs})
						}
					}
				default:
					panic("unexpected declaration kind")
				}
			}
		}
		prefix := ""
		for _, line := range strings.Split(string(original[path]), "\n") {
			if strings.HasPrefix(line, "package ") {
				break
			}
			if strings.HasPrefix(line, "//go:build ") || strings.HasPrefix(line, "// +build ") {
				prefix += line + "\n"
			}
		}
		if prefix != "" {
			prefix += "\n"
		}
		prefix += "package " + f.Name.Name + "\n"
		// Preserve an auditable declaration-only rendering separately from
		// the trusted wrapper added to the original primary answer path.
		fr.Declarations = render(prefix, used, parts)
		fr.Source = fr.Declarations
		audit(fr)
		if path == c.Primary {
			wrapper, err := parser.ParseFile(token.NewFileSet(), "control.go", c.Wrapper, 0)
			must(err)
			testingName := qualifier(types.NewPackage("testing", "testing"))
			godogName := qualifier(types.NewPackage("github.com/cucumber/godog", "godog"))
			for _, declaration := range wrapper.Decls {
				if imports, ok := declaration.(*ast.GenDecl); ok && imports.Tok == token.IMPORT {
					continue
				}
				ast.Inspect(declaration, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok {
						if id.Name == "r2tControlTesting" {
							id.Name = testingName
						}
						if id.Name == "r2tControlGodog" {
							id.Name = godogName
						}
					}
					return true
				})
				parts = append(parts, show(token.NewFileSet(), declaration))
			}
			fr.Source = render(prefix, used, parts)
		}
		fr.SHA = hash([]byte(fr.Source))
		out.Files = append(out.Files, fr)
	}
	if selectedCount != 1 {
		panic("selected original wrapper absent/duplicate")
	}
	out.Checks = map[string]bool{"original_function_bodies_absent": true, "original_variable_initializers_absent": true, "only_reviewed_empty_string_constant": true, "helper_bodies_exact_witness_plus_zero_returns": true}
	return out
}
func render(prefix string, used map[string]string, parts []string) string {
	keys := []string{}
	for p := range used {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		prefix += "import (\n"
		for _, p := range keys {
			prefix += used[p] + " " + strconv.Quote(p) + "\n"
		}
		prefix += ")\n"
	}
	source, e := format.Source([]byte(prefix + strings.Join(parts, "\n\n") + "\n"))
	must(e)
	return string(source)
}

func audit(f FileOutput) {
	fs := token.NewFileSet()
	a, e := parser.ParseFile(fs, f.Path, f.Source, 0)
	must(e)
	seen := map[string]bool{}
	for _, d := range a.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			key := x.Name.Name
			if x.Recv != nil {
				key = show(fs, x.Recv.List[0].Type) + "." + key
			}
			want, ok := f.Functions[key]
			if !ok || show(token.NewFileSet(), x.Body) != want {
				panic("helper body differs from generated witness/zero template")
			}
			seen[key] = true
		case *ast.GenDecl:
			if x.Tok == token.VAR {
				for _, s := range x.Specs {
					if len(s.(*ast.ValueSpec).Values) != 0 {
						panic("original variable initializer survived")
					}
				}
			}
			if x.Tok == token.CONST {
				for _, s := range x.Specs {
					ast.Inspect(s, func(n ast.Node) bool {
						if _, ok := n.(*ast.CallExpr); ok {
							panic("constant call survived")
						}
						return true
					})
				}
			}
		}
	}
	if len(seen) != len(f.Functions) {
		panic("missing inert helper")
	}
}
