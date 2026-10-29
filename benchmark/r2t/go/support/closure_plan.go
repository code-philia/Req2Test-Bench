// Standalone source inventory for closure preparation; never runs subject code.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type Input struct {
	Root        string   `json:"root"`
	PackageDir  string   `json:"package_dir"`
	PackageName string   `json:"package_name"`
	Tags        []string `json:"tags"`
	Files       []string `json:"files"`
}
type Span struct {
	File  string `json:"file"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Line  int    `json:"line"`
	Text  string `json:"text"`
}
type Owner struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Declaration Span   `json:"declaration"`
	Identifier  Span   `json:"identifier"`
}
type Edge struct {
	Caller   Span   `json:"caller"`
	Handler  Span   `json:"handler"`
	Selector Span   `json:"selector"`
	Owner    Span   `json:"owner"`
	Name     string `json:"name"`
}
type Output struct {
	Toolchain string   `json:"toolchain"`
	Files     []string `json:"active_files"`
	Owners    []Owner  `json:"owners"`
	Edges     []Edge   `json:"runtime_edges"`
}

const module = "github.com/EvilFreelancer/coddy-agent"
const hookPackage = module + "/internal/hooks/hooktest"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	var in Input
	must(json.NewDecoder(os.Stdin).Decode(&in))
	if runtime.Version() != "go1.25.0" {
		panic("closure inventory requires Go 1.25.0")
	}
	fs := token.NewFileSet()
	parsed := map[string]*ast.File{}
	source := map[string][]byte{}
	bc := build.Default
	bc.GOOS = "linux"
	bc.GOARCH = "amd64"
	bc.BuildTags = in.Tags
	for _, rel := range in.Files {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir != in.PackageDir && dir != "internal/hooks/hooktest" {
			continue
		}
		full := filepath.Join(in.Root, filepath.FromSlash(rel))
		active, err := bc.MatchFile(filepath.Dir(full), filepath.Base(full))
		must(err)
		if !active {
			continue
		}
		raw, err := os.ReadFile(full)
		must(err)
		f, err := parser.ParseFile(fs, full, raw, parser.AllErrors)
		must(err)
		if dir == in.PackageDir && f.Name.Name != in.PackageName {
			continue
		}
		parsed[rel] = f
		source[rel] = raw
	}
	span := func(n ast.Node) Span {
		p := fs.PositionFor(n.Pos(), false)
		q := fs.PositionFor(n.End(), false)
		rel, err := filepath.Rel(in.Root, p.Filename)
		must(err)
		rel = filepath.ToSlash(rel)
		return Span{rel, p.Offset, q.Offset, p.Line, string(source[rel][p.Offset:q.Offset])}
	}
	imports := func(f *ast.File) map[string]string {
		m := map[string]string{}
		for _, v := range f.Imports {
			path, err := strconv.Unquote(v.Path.Value)
			must(err)
			name := filepath.Base(path)
			if v.Name != nil {
				name = v.Name.Name
			}
			m[name] = path
		}
		return m
	}
	// Parser object links distinguish an imported qualifier from a local shadow.
	imported := func(expr ast.Expr, names map[string]string, pkg, name string) bool {
		s, ok := expr.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != name {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Obj == nil && names[id.Name] == pkg
	}
	out := Output{runtime.Version(), []string{}, []Owner{}, []Edge{}}
	functions := map[string][]*ast.FuncDecl{}
	functionFile := map[*ast.FuncDecl]string{}
	for rel, f := range parsed {
		if filepath.ToSlash(filepath.Dir(rel)) != in.PackageDir {
			continue
		}
		out.Files = append(out.Files, rel)
		for _, d := range f.Decls {
			switch n := d.(type) {
			case *ast.FuncDecl:
				if n.Recv == nil {
					out.Owners = append(out.Owners, Owner{n.Name.Name, "func", span(n), span(n.Name)})
					functions[n.Name.Name] = append(functions[n.Name.Name], n)
					functionFile[n] = rel
				}
			case *ast.GenDecl:
				for _, spec := range n.Specs {
					switch v := spec.(type) {
					case *ast.TypeSpec:
						out.Owners = append(out.Owners, Owner{v.Name.Name, "type", span(v), span(v.Name)})
					case *ast.ValueSpec:
						for _, name := range v.Names {
							out.Owners = append(out.Owners, Owner{name.Name, n.Tok.String(), span(v), span(name)})
						}
					}
				}
			}
		}
	}
	var handler *ast.FuncDecl
	var selector *ast.BasicLit
	var handlerFile string
	// Qualify only the observed exec-form Handler shape, when the package uses it.
	callers := []ast.Node{}
	for rel, f := range parsed {
		if filepath.ToSlash(filepath.Dir(rel)) != in.PackageDir {
			continue
		}
		names := imports(f)
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if ok && imported(c.Fun, names, hookPackage, "Handler") {
				callers = append(callers, c)
			}
			return true
		})
	}
	if len(callers) > 0 {
		for rel, f := range parsed {
			if filepath.ToSlash(filepath.Dir(rel)) != "internal/hooks/hooktest" {
				continue
			}
			for _, d := range f.Decls {
				n, ok := d.(*ast.FuncDecl)
				if ok && n.Recv == nil && n.Name.Name == "Handler" {
					if handler != nil {
						panic("ambiguous hooktest.Handler")
					}
					handler = n
					handlerFile = rel
				}
			}
		}
		if handler == nil || handler.Body == nil {
			panic("missing hooktest.Handler")
		}
		names := imports(parsed[handlerFile])
		valid := false
		if len(handler.Body.List) == 1 {
			if ret, ok := handler.Body.List[0].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				if lit, ok := ret.Results[0].(*ast.CompositeLit); ok && imported(lit.Type, names, module+"/internal/hooks", "Handler") {
					commandOK, argsOK, execOK, typeOK := false, false, false, false
					for _, entry := range lit.Elts {
						kv, ok := entry.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}
						switch key.Name {
						case "Command":
							idx, ok := kv.Value.(*ast.IndexExpr)
							if ok && imported(idx.X, names, "os", "Args") {
								v, ok := idx.Index.(*ast.BasicLit)
								commandOK = ok && v.Value == "0"
							}
						case "ExecForm":
							v, ok := kv.Value.(*ast.Ident)
							execOK = ok && v.Name == "true"
						case "Type":
							typeOK = imported(kv.Value, names, module+"/internal/hooks", "HandlerCommand")
						case "Args":
							call, ok := kv.Value.(*ast.CallExpr)
							if !ok || len(call.Args) != 2 || !call.Ellipsis.IsValid() {
								continue
							}
							fn, ok := call.Fun.(*ast.Ident)
							if !ok || fn.Name != "append" || fn.Obj != nil {
								continue
							}
							array, ok := call.Args[0].(*ast.CompositeLit)
							if !ok || len(array.Elts) != 3 {
								continue
							}
							typ, ok := array.Type.(*ast.ArrayType)
							if !ok || typ.Len != nil {
								continue
							}
							elem, ok := typ.Elt.(*ast.Ident)
							if !ok || elem.Name != "string" {
								continue
							}
							v, ok := array.Elts[0].(*ast.BasicLit)
							if !ok || v.Kind != token.STRING {
								continue
							}
							text, err := strconv.Unquote(v.Value)
							must(err)
							if text != "-test.run=^TestHelperHook$" {
								panic("unsupported hook child selector")
							}
							sentinel, ok := array.Elts[1].(*ast.Ident)
							if !ok || sentinel.Name != "Sentinel" {
								continue
							}
							mode, ok := array.Elts[2].(*ast.Ident)
							if !ok || mode.Name != "mode" {
								continue
							}
							params, ok := call.Args[1].(*ast.Ident)
							if !ok || params.Name != "params" {
								continue
							}
							selector = v
							argsOK = true
						}
					}
					valid = commandOK && argsOK && execOK && typeOK
				}
			}
		}
		if !valid {
			panic("unsupported hooktest.Handler exec shape")
		}
		owners := functions["TestHelperHook"]
		if len(owners) != 1 {
			panic("missing/ambiguous TestHelperHook owner")
		}
		owner := owners[0]
		names = imports(parsed[functionFile[owner]])
		sig := owner.Type
		sigOK := sig.Params != nil && len(sig.Params.List) == 1 && (sig.Results == nil || len(sig.Results.List) == 0)
		if sigOK {
			star, ok := sig.Params.List[0].Type.(*ast.StarExpr)
			sigOK = ok && imported(star.X, names, "testing", "T")
		}
		mainCall := false
		ast.Inspect(owner, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 1 || !imported(c.Fun, names, hookPackage, "Main") {
				return true
			}
			args, ok := c.Args[0].(*ast.CallExpr)
			if ok && len(args.Args) == 0 && imported(args.Fun, names, "flag", "Args") {
				mainCall = true
			}
			return true
		})
		if !sigOK || !mainCall {
			panic("unsupported TestHelperHook declaration")
		}
		for _, call := range callers {
			out.Edges = append(out.Edges, Edge{span(call), span(handler), span(selector), span(owner), "TestHelperHook"})
		}
	}
	sort.Strings(out.Files)
	sort.Slice(out.Owners, func(i, j int) bool {
		a, b := out.Owners[i], out.Owners[j]
		if a.Declaration.File != b.Declaration.File {
			return a.Declaration.File < b.Declaration.File
		}
		if a.Declaration.Start != b.Declaration.Start {
			return a.Declaration.Start < b.Declaration.Start
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Edges, func(i, j int) bool {
		a, b := out.Edges[i].Caller, out.Edges[j].Caller
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Start < b.Start
	})
	if len(out.Files) == 0 {
		panic(fmt.Sprintf("no active source files for %s", in.PackageDir))
	}
	must(json.NewEncoder(os.Stdout).Encode(out))
}
