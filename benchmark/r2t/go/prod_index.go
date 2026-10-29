// Trusted declaration analysis: parses and type-checks original source only.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
)

type Module struct {
	Dir  string
	Main bool
}
type Package struct {
	Dir, ImportPath, Name, ForTest, Export string
	GoFiles, CgoFiles                      []string
	ImportMap                              map[string]string
	Module                                 *Module
	Error                                  any
	DepsErrors                             []any
}
type Request struct {
	OriginalRoot string    `json:"original_root"`
	Root         string    `json:"root"`
	Paths        []string  `json:"paths"`
	PackageDir   string    `json:"package_dir"`
	PackageName  string    `json:"package_name"`
	GluePath     string    `json:"glue_path"`
	Packages     []Package `json:"packages"`
}
type Method struct {
	Name   string `json:"name"`
	Decl   int    `json:"decl"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Public bool   `json:"public"`
}
type Class struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Decl    int      `json:"decl,omitempty"`
	Alias   bool     `json:"alias,omitempty"`
	Methods []Method `json:"methods"`
}
type File struct {
	Classes []*Class `json:"classes"`
}
type Result struct {
	Files   map[string]File `json:"files"`
	Runtime map[string]any  `json:"runtime"`
}

func relative(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("source outside original root: %s", path)
	}
	return filepath.ToSlash(rel), nil
}
func sourcePath(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}
func within(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}
func packageKey(path string) string { return strings.Split(path, " [")[0] }

func analyze(req Request) (Result, error) {
	if !filepath.IsAbs(req.OriginalRoot) {
		return Result{}, fmt.Errorf("missing original source root")
	}
	result := Result{Files: map[string]File{}, Runtime: map[string]any{
		"toolchain": runtime.Version(), "goos": build.Default.GOOS, "goarch": build.Default.GOARCH,
		"cgo_enabled": build.Default.CgoEnabled, "release_tags": build.Default.ReleaseTags, "tool_tags": build.Default.ToolTags}}
	exports := map[string]string{}
	found := false
	for _, pkg := range req.Packages {
		if pkg.Error != nil || len(pkg.DepsErrors) != 0 {
			return result, fmt.Errorf("unresolved package %s", pkg.ImportPath)
		}
		if pkg.Export != "" {
			exports[pkg.ImportPath] = pkg.Export
		}
		rel, err := relative(req.Root, pkg.Dir)
		if err == nil && rel == req.PackageDir && pkg.Name == req.PackageName {
			for _, name := range pkg.GoFiles {
				path, err := relative(req.Root, sourcePath(pkg.Dir, name))
				if err == nil && path == req.GluePath {
					found = true
				}
			}
		}
	}
	if !found {
		return result, fmt.Errorf("selected glue/package is not compiled in the explicit Go context: %s (%s)", req.GluePath, req.PackageName)
	}
	for _, pkg := range req.Packages {
		if pkg.Module == nil || !pkg.Module.Main || filepath.Clean(pkg.Module.Dir) != filepath.Clean(req.Root) {
			continue
		}
		relDir, err := relative(req.Root, pkg.Dir)
		if err != nil || !within(relDir, req.Paths) {
			continue
		}
		originals := map[string]bool{}
		for _, name := range pkg.GoFiles {
			path, err := relative(req.Root, sourcePath(pkg.Dir, name))
			if err == nil && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") && within(path, req.Paths) {
				originals[path] = true
			}
		}
		if len(pkg.CgoFiles) > 0 {
			return result, fmt.Errorf("first-party cgo source requires a qualified original-source mapping: %s", pkg.ImportPath)
		}
		if len(originals) == 0 {
			continue
		}
		fs := token.NewFileSet()
		files := []*ast.File{}
		paths := []string{}
		for _, name := range pkg.GoFiles {
			full := sourcePath(pkg.Dir, name)
			path, err := relative(req.Root, full)
			if err != nil || !strings.HasSuffix(path, ".go") {
				return result, fmt.Errorf("generated input in first-party package %s: %s", pkg.ImportPath, name)
			}
			compiled, err := os.ReadFile(full)
			if err != nil {
				return result, err
			}
			raw, err := os.ReadFile(filepath.Join(req.OriginalRoot, filepath.FromSlash(path)))
			if err != nil {
				return result, err
			}
			if !bytes.Equal(raw, compiled) {
				return result, fmt.Errorf("compiled Go source differs from original: %s", path)
			}
			file, err := parser.ParseFile(fs, path, raw, parser.ParseComments|parser.AllErrors|parser.SkipObjectResolution)
			if err != nil {
				return result, fmt.Errorf("parse %s: %w", path, err)
			}
			files = append(files, file)
			paths = append(paths, path)
		}
		info := &types.Info{Defs: map[*ast.Ident]types.Object{}}
		config := types.Config{GoVersion: "go1.25.0", Importer: importer.ForCompiler(fs, "gc", func(path string) (io.ReadCloser, error) {
			key := path
			if mapped := pkg.ImportMap[path]; mapped != "" {
				key = mapped
			}
			file := exports[key]
			if file == "" {
				return nil, fmt.Errorf("missing export for %s (%s)", path, key)
			}
			return os.Open(file)
		})}
		owner := packageKey(pkg.ImportPath)
		if _, err := config.Check(owner, fs, files, info); err != nil {
			return result, fmt.Errorf("type-check %s: %w", pkg.ImportPath, err)
		}
		for index, file := range files {
			path := paths[index]
			if !originals[path] {
				continue
			}
			classes := map[string]*Class{}
			get := func(name, kind string) *Class {
				if cls := classes[name]; cls != nil {
					return cls
				}
				cls := &Class{Name: name, Kind: kind, Methods: []Method{}}
				classes[name] = cls
				return cls
			}
			for _, decl := range file.Decls {
				group, ok := decl.(*ast.GenDecl)
				if !ok || group.Tok != token.TYPE {
					continue
				}
				for _, spec := range group.Specs {
					named, ok := spec.(*ast.TypeSpec)
					if !ok {
						return result, fmt.Errorf("unknown type declaration in %s", path)
					}
					object, ok := info.Defs[named.Name].(*types.TypeName)
					if !ok {
						return result, fmt.Errorf("unresolved type in %s", path)
					}
					cls := get(owner+"."+object.Name(), "type")
					cls.Decl = fs.PositionFor(named.Pos(), false).Line
					cls.Alias = object.IsAlias()
				}
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if fn.Recv == nil && fn.Name.Name == "init" {
					continue
				}
				if fn.Body == nil {
					return result, fmt.Errorf("bodyless production function needs an original-body mapping: %s:%d", path, fs.PositionFor(fn.Pos(), false).Line)
				}
				object, ok := info.Defs[fn.Name].(*types.Func)
				if !ok {
					return result, fmt.Errorf("unresolved function in %s", path)
				}
				signature, ok := object.Type().(*types.Signature)
				if !ok {
					return result, fmt.Errorf("unresolved signature in %s", path)
				}
				name, kind := owner, "module"
				if receiver := signature.Recv(); receiver != nil {
					typ := types.Unalias(receiver.Type())
					if pointer, ok := typ.(*types.Pointer); ok {
						typ = types.Unalias(pointer.Elem())
					}
					named, ok := typ.(*types.Named)
					if !ok {
						return result, fmt.Errorf("unresolved receiver in %s", path)
					}
					object := named.Origin().Obj()
					name = object.Pkg().Path() + "." + object.Name()
					kind = "type"
				}
				cls := get(name, kind)
				method := Method{Name: fn.Name.Name, Decl: fs.PositionFor(fn.Pos(), false).Line,
					Start: fs.PositionFor(fn.Body.Lbrace, false).Line, End: fs.PositionFor(fn.Body.Rbrace, false).Line, Public: ast.IsExported(fn.Name.Name)}
				for _, previous := range cls.Methods {
					if previous.Name == method.Name {
						return result, fmt.Errorf("duplicate method identity %s.%s in %s", name, method.Name, path)
					}
				}
				cls.Methods = append(cls.Methods, method)
			}
			names := []string{}
			for name := range classes {
				names = append(names, name)
			}
			sort.Strings(names)
			row := File{Classes: []*Class{}}
			for _, name := range names {
				row.Classes = append(row.Classes, classes[name])
			}
			if previous, exists := result.Files[path]; exists && !reflect.DeepEqual(previous, row) {
				return result, fmt.Errorf("conflicting original declarations across package variants: %s", path)
			}
			result.Files[path] = row
		}
	}
	return result, nil
}
func main() {
	var request Request
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := analyze(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
