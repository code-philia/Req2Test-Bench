// Approved Go declared surface: no inferred receiver/return-type candidates.
// Loader: existing interpose.go go-list/export + importer/go-types pattern.
// Canonical declaration names: existing prod_index.go packageKey + TypeName.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type Pkg struct {
	ImportPath, Name, Dir, Export string
	GoFiles                       []string
	ImportMap                     map[string]string
}
type Handler struct {
	File, Name, Kind, Signature string
	Line                        int
	Start                       int `json:"start_byte"`
	End                         int `json:"end_byte"`
}
type Query struct {
	Label       string
	PackageDir  string   `json:"package_dir"`
	PackageName string   `json:"package_name"`
	GluePath    string   `json:"glue_path"`
	Tags        []string `json:"go_build_tags"`
	Files       []string
	Handlers    []Handler
}
type Request struct {
	Root    string
	Go      string
	Queries []Query
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func key(p string) string { return strings.Split(p, " [")[0] }
func full(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}
func text(t types.Type) string {
	if t == nil {
		return ""
	}
	return types.TypeString(t, func(p *types.Package) string { return key(p.Path()) })
}
func inspect(root, goBinary string, q Query) map[string]any {
	argv := []string{"list", "-p=1", "-deps", "-export", "-test", "-json"}
	if len(q.Tags) > 0 {
		argv = append(argv, "-tags="+strings.Join(q.Tags, ","))
	}
	argv = append(argv, "./"+q.PackageDir)
	command := exec.Command(goBinary, argv...)
	command.Dir = root
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		panic(fmt.Sprintf("go list/export: %v: %s", err, stderr.String()))
	}
	exports := map[string]string{}
	var chosen *Pkg
	count := 0
	dec := json.NewDecoder(&stdout)
	for {
		var p Pkg
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		must(err)
		exports[p.ImportPath] = p.Export
		if p.Name != q.PackageName {
			continue
		}
		for _, name := range p.GoFiles {
			if filepath.Clean(full(p.Dir, name)) == filepath.Join(root, q.GluePath) {
				c := p
				chosen = &c
				count++
			}
		}
	}
	if count != 1 {
		panic(fmt.Sprintf("exact package/glue attribution: %d matches", count))
	}
	fs := token.NewFileSet()
	files := []*ast.File{}
	for _, name := range chosen.GoFiles {
		f, err := parser.ParseFile(fs, full(chosen.Dir, name), nil, parser.ParseComments|parser.AllErrors)
		must(err)
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Instances: map[*ast.Ident]types.Instance{}}
	cfg := types.Config{GoVersion: "go1.25.0", Importer: importer.ForCompiler(fs, "gc", func(path string) (io.ReadCloser, error) {
		if mapped := chosen.ImportMap[path]; mapped != "" {
			path = mapped
		}
		p := exports[path]
		if p == "" {
			return nil, fmt.Errorf("missing cached export: %s", path)
		}
		return os.Open(p)
	})}
	_, err := cfg.Check(key(chosen.ImportPath), fs, files, info)
	must(err)
	span := func(n ast.Node) map[string]any {
		a, b := fs.PositionFor(n.Pos(), false), fs.PositionFor(n.End(), false)
		rel, err := filepath.Rel(root, a.Filename)
		must(err)
		return map[string]any{"file": filepath.ToSlash(rel), "line": a.Line, "start_byte": a.Offset, "end_byte": b.Offset}
	}
	object := func(obj *types.TypeName) map[string]any {
		p := fs.PositionFor(obj.Pos(), false)
		path := p.Filename
		if filepath.IsAbs(path) {
			rel, err := filepath.Rel(root, path)
			must(err)
			path = filepath.ToSlash(rel)
		}
		name := obj.Name()
		if obj.Pkg() != nil {
			name = key(obj.Pkg().Path()) + "." + name
		}
		_, parameter := obj.Type().(*types.TypeParam)
		return map[string]any{"name": name, "alias": obj.IsAlias(), "file": path, "line": p.Line, "type_parameter": parameter}
	}
	var constituents func(types.Type) []map[string]any
	constituents = func(t types.Type) []map[string]any {
		out := []map[string]any{}
		switch t := t.(type) {
		case *types.Alias:
			out = append(out, object(t.Origin().Obj()))
		case *types.Named:
			out = append(out, object(t.Origin().Obj()))
		case *types.Pointer:
			out = append(out, constituents(t.Elem())...)
		case *types.Array:
			out = append(out, constituents(t.Elem())...)
		case *types.Slice:
			out = append(out, constituents(t.Elem())...)
		case *types.Map:
			out = append(out, constituents(t.Key())...)
			out = append(out, constituents(t.Elem())...)
		case *types.Chan:
			out = append(out, constituents(t.Elem())...)
		case *types.Struct:
			for i := 0; i < t.NumFields(); i++ {
				out = append(out, constituents(t.Field(i).Type())...)
			}
		case *types.Signature:
			for _, tuple := range []*types.Tuple{t.Params(), t.Results()} {
				for i := 0; i < tuple.Len(); i++ {
					out = append(out, constituents(tuple.At(i).Type())...)
				}
			}
		}
		return out
	}
	allowed := map[string]bool{}
	for _, path := range q.Files {
		allowed[path] = true
	}
	nodes := []ast.Node{}
	declarations := map[*types.Func]*ast.FuncDecl{}
	typesDeclared := []map[string]any{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				declarations[info.Defs[n.Name].(*types.Func)] = n
				nodes = append(nodes, n)
			case *ast.FuncLit:
				nodes = append(nodes, n)
			case *ast.TypeSpec:
				row := object(info.Defs[n.Name].(*types.TypeName))
				row["decl"] = fs.PositionFor(n.Pos(), false).Line
				typesDeclared = append(typesDeclared, row)
			}
			return true
		})
	}
	members := []map[string]any{}
	for _, node := range nodes {
		identity := span(node)
		if !allowed[identity["file"].(string)] {
			continue
		}
		var typ types.Type
		switch n := node.(type) {
		case *ast.FuncDecl:
			identity["name"] = n.Name.Name
			identity["kind"] = "function_or_method"
			typ = info.Defs[n.Name].Type()
		case *ast.FuncLit:
			identity["name"] = fmt.Sprintf("func@%d", identity["start_byte"])
			identity["kind"] = "function_literal"
			typ = info.TypeOf(n)
		}
		identity["signature"] = text(typ)
		explicit := []map[string]any{}
		fields := []map[string]any{}
		calls := []map[string]any{}
		visit := func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if obj, ok := info.Uses[n].(*types.TypeName); ok {
					row := object(obj)
					row["use"] = span(n)
					explicit = append(explicit, row)
				}
			case *ast.SelectorExpr:
				if selected := info.Selections[n]; selected != nil && selected.Kind() == types.FieldVal {
					row := span(n)
					row["field"] = selected.Obj().Name()
					row["declared_type"] = text(selected.Obj().Type())
					row["named_constituents"] = constituents(selected.Obj().Type())
					fields = append(fields, row)
				}
			case *ast.CallExpr:
				row := span(n)
				var fn *types.Func
				funExpr := n.Fun
				for {
					switch f := funExpr.(type) {
					case *ast.IndexExpr:
						funExpr = f.X
					case *ast.IndexListExpr:
						funExpr = f.X
					case *ast.ParenExpr:
						funExpr = f.X
					default:
						goto resolvedFun
					}
				}
			resolvedFun:
				switch fun := funExpr.(type) {
				case *ast.Ident:
					fn, _ = info.Uses[fun].(*types.Func)
				case *ast.SelectorExpr:
					if selected := info.Selections[fun]; selected != nil {
						fn, _ = selected.Obj().(*types.Func)
					} else {
						fn, _ = info.Uses[fun.Sel].(*types.Func)
					}
				}
				if fn != nil {
					fn = fn.Origin()
					row["resolved_function"] = fn.FullName()
					if decl := declarations[fn]; decl != nil {
						row["declaration"] = span(decl)
						row["in_allowed_files"] = allowed[span(decl)["file"].(string)]
					}
				} else {
					row["static_function_target"] = false
				}
				calls = append(calls, row)
			}
			return true
		}
		// Receiver declarations do not automatically contribute a state type.
		// Signatures include T1/T2 constraints; lexical bodies supply T3/T5/T6.
		switch n := node.(type) {
		case *ast.FuncDecl:
			ast.Inspect(n.Type, visit)
			if n.Body != nil {
				ast.Inspect(n.Body, visit)
			}
		case *ast.FuncLit:
			ast.Inspect(n, visit)
		}
		members = append(members, map[string]any{"identity": identity, "explicit_type_uses": explicit, "selected_fields": fields, "calls": calls})
	}
	sort.Slice(members, func(i, j int) bool {
		a, _ := json.Marshal(members[i]["identity"])
		b, _ := json.Marshal(members[j]["identity"])
		return string(a) < string(b)
	})
	bind := func(h Handler) bool {
		count := 0
		for _, member := range members {
			id := member["identity"].(map[string]any)
			if id["file"] == h.File && id["start_byte"] == h.Start && id["end_byte"] == h.End && id["line"] == h.Line && id["name"] == h.Name && id["kind"] == h.Kind && id["signature"] == h.Signature {
				count++
			}
		}
		return count == 1
	}
	for _, h := range q.Handlers {
		if !bind(h) {
			panic(fmt.Sprintf("native handler is stale or ambiguous: %+v", h))
		}
	}
	sourceFiles := map[string]string{}
	for _, name := range chosen.GoFiles {
		path := full(chosen.Dir, name)
		rel, err := filepath.Rel(root, path)
		must(err)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			panic("compiled source outside original view")
		}
		raw, err := os.ReadFile(path)
		must(err)
		sourceFiles[filepath.ToSlash(rel)] = fmt.Sprintf("%x", sha256.Sum256(raw))
	}

	return map[string]any{"label": q.Label, "package_import_path": key(chosen.ImportPath), "compiled_package_name": chosen.Name, "compiled_files": chosen.GoFiles, "export_packages": len(exports), "go_list_argv": argv, "bound_native_handlers": len(q.Handlers), "source_files": sourceFiles, "type_declarations": typesDeclared, "members": members}
}
func main() {
	if runtime.Version() != "go1.25.0" {
		panic("qualified Go 1.25.0 required")
	}
	var req Request
	must(json.NewDecoder(os.Stdin).Decode(&req))
	results := []map[string]any{}
	for _, q := range req.Queries {
		results = append(results, inspect(req.Root, req.Go, q))
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "r2t.go-interface-attribution/1", "toolchain": runtime.Version(), "queries": results}))
}
