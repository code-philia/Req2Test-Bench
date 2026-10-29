// Native-qualified Then body/blank-import planner; no writes or test execution.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
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
	"sort"
	"strings"
)

type pkgInfo struct {
	ImportPath, Name, Dir, Export, ForTest string
	GoFiles, CompiledGoFiles               []string
	ImportMap                              map[string]string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	root := flag.String("root", "", "copy root")
	pkg := flag.String("package", "", "package directory")
	file := flag.String("file", "", "glue path")
	tags := flag.String("tags", "", "Go user tags")
	requestPath := flag.String("request", "", "selected native handlers JSON")

	flag.Parse()
	path := filepath.Join(*root, *file)
	original, err := os.ReadFile(path)
	must(err)
	fset := token.NewFileSet()
	target, err := parser.ParseFile(fset, path, original, parser.ParseComments|parser.AllErrors)
	must(err)
	args := []string{"list", "-p=1", "-deps", "-export", "-test", "-json"}
	if *tags != "" {
		args = append(args, "-tags", *tags)
	}
	args = append(args, "./"+*pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = *root
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		panic("go list/export refused: " + err.Error() + "\n" + stderr.String())
	}
	exports := map[string]string{}
	var chosen *pkgInfo
	dec := json.NewDecoder(&out)
	for {
		var p pkgInfo
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		must(err)
		exports[p.ImportPath] = p.Export
		for _, name := range p.GoFiles {
			full := name
			if !filepath.IsAbs(full) {
				full = filepath.Join(p.Dir, name)
			}
			if filepath.Clean(full) == filepath.Clean(path) && p.Name == target.Name.Name {
				copy := p
				chosen = &copy
			}
		}
	}
	if chosen == nil {
		panic("selected glue is inactive under actual go list build context")
	}
	lookup := func(importPath string) (io.ReadCloser, error) {
		if mapped := chosen.ImportMap[importPath]; mapped != "" {
			importPath = mapped
		}
		p := exports[importPath]
		if p == "" {
			return nil, fmt.Errorf("missing export data for %s", importPath)
		}
		return os.Open(p)
	}
	info := &types.Info{Implicits: map[ast.Node]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	files := []*ast.File{target}
	for _, name := range chosen.GoFiles {
		full := name
		if !filepath.IsAbs(full) {
			full = filepath.Join(chosen.Dir, name)
		}
		if filepath.Clean(full) == filepath.Clean(path) {
			continue
		}
		f, err := parser.ParseFile(fset, full, nil, parser.ParseComments|parser.AllErrors)
		must(err)
		files = append(files, f)
	}
	cfg := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup), GoVersion: "go1.25"}
	_, err = cfg.Check(chosen.ImportPath, fset, files, info)
	must(err)
	var request struct {
		Handlers []struct {
			File      string `json:"file"`
			Start     int    `json:"start_byte"`
			End       int    `json:"end_byte"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Signature string `json:"signature"`
		}
	}
	requestFile, err := os.Open(*requestPath)
	must(err)
	defer requestFile.Close()
	must(json.NewDecoder(requestFile).Decode(&request))
	if len(request.Handlers) == 0 {
		panic("no selected handlers")
	}
	type edit struct {
		Start       int    `json:"start_byte"`
		End         int    `json:"end_byte"`
		Replacement string `json:"replacement"`
		Kind        string `json:"kind"`
	}
	type result struct {
		File  string `json:"file"`
		Edits []edit `json:"edits"`
	}
	results := []result{}
	found := 0
	for _, f := range files {
		filename := fset.PositionFor(f.Pos(), false).Filename
		rel, err := filepath.Rel(*root, filename)
		must(err)
		rel = filepath.ToSlash(rel)
		original, err := os.ReadFile(filename)
		must(err)
		edits := []edit{}
		bodies := []*ast.BlockStmt{}
		for _, selected := range request.Handlers {
			if selected.File != rel {
				continue
			}
			var body *ast.BlockStmt
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil || fset.PositionFor(n.Pos(), false).Offset != selected.Start || fset.PositionFor(n.End(), false).Offset != selected.End {
					return true
				}
				var sig *types.Signature
				var name, kind string
				switch fn := n.(type) {
				case *ast.FuncDecl:
					body = fn.Body
					sig = info.Defs[fn.Name].Type().(*types.Signature)
					name = fn.Name.Name
					kind = "function_or_method"
				case *ast.FuncLit:
					body = fn.Body
					sig = info.TypeOf(fn).(*types.Signature)
					name = fmt.Sprintf("func@%d", selected.Start)
					kind = "function_literal"
				default:
					return true
				}
				if name != selected.Name || kind != selected.Kind || types.TypeString(sig, nil) != selected.Signature {
					panic("handler signature/source identity differs")
				}
				if sig.TypeParams() != nil && sig.TypeParams().Len() != 0 {
					panic("generic handler unsupported")
				}
				replacement := ""
				if sig.Results().Len() == 1 && types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type()) {
					replacement = "return nil"
				} else if sig.Results().Len() != 0 {
					panic("unsupported native handler return signature")
				}
				if body == nil {
					panic("missing handler body")
				}
				start, end := fset.PositionFor(body.Pos(), false).Offset, fset.PositionFor(body.End(), false).Offset
				edits = append(edits, edit{start, end, "{" + strings.Repeat("\n", bytes.Count(original[start:end], []byte("\n"))) + replacement + "}", "then_body"})
				bodies = append(bodies, body)
				found++
				return false
			})
			if body == nil {
				panic("selected handler span not found")
			}
		}
		if len(edits) == 0 {
			continue
		}
		// Preserve package initialization when every typed use occurs inside a selected body.
		// Every other declaration/initializer/helper and all registration syntax remain.
		inside := func(pos token.Pos) bool {
			for _, body := range bodies {
				if body.Pos() <= pos && pos < body.End() {
					return true
				}
			}
			return false
		}
		for _, decl := range f.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.IMPORT {
				continue
			}
			for _, spec := range group.Specs {
				imp := spec.(*ast.ImportSpec)
				var obj types.Object
				if imp.Name != nil {
					if imp.Name.Name == "_" {
						continue
					}
					if imp.Name.Name == "." {
						panic("dot import unsupported")
					}
					obj = info.Defs[imp.Name]
				} else {
					obj = info.Implicits[imp]
				}
				pkg, ok := obj.(*types.PkgName)
				if !ok {
					panic("missing typed import")
				}
				surviving := false
				uses := 0
				for ident, used := range info.Uses {
					if used == pkg {
						uses++
						if !inside(ident.Pos()) {
							surviving = true
						}
					}
				}
				if uses == 0 {
					panic("original unused import")
				}
				if surviving {
					continue
				}
				var node ast.Node = imp
				if !group.Lparen.IsValid() {
					node = group
				}
				start, end := fset.PositionFor(node.Pos(), false).Offset, fset.PositionFor(node.End(), false).Offset
				replacement := "_ " + imp.Path.Value
				if !group.Lparen.IsValid() {
					replacement = "import " + replacement
				}
				replacement += strings.Repeat("\n", bytes.Count(original[start:end], []byte("\n")))
				edits = append(edits, edit{start, end, replacement, "blank_import"})
			}
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].Start < edits[j].Start })
		for i, e := range edits {
			if i > 0 && edits[i-1].End > e.Start {
				panic("overlapping edits")
			}
		}
		results = append(results, result{rel, edits})
	}
	if found != len(request.Handlers) {
		panic("selected handler ownership not in compiled test variant")
	}
	sort.Slice(results, func(i, j int) bool { return results[i].File < results[j].File })
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "r2t.go-assertion-strip/1", "root": *root, "package_dir": *pkg, "glue_path": *file, "go_build_tags": *tags, "handlers": request.Handlers, "files": results}))
}
