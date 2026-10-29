// Read-only, type-resolved Run preparation planner; never executes subject tests.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type pkgInfo struct {
	ImportPath, Name, Dir, Export, ForTest string
	GoFiles, CompiledGoFiles               []string
	ImportMap                              map[string]string
	Incomplete                             bool
	Error                                  json.RawMessage
	DepsErrors                             []json.RawMessage
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

var runtimeDiagnostics bool

// Runtime opts in to a closed diagnostic frame. Default admission behavior and
// successful plan bytes are unchanged; unknown tool/export errors still panic.
func candidateFailure(stage, file, message string) {
	if !runtimeDiagnostics {
		panic(message)
	}
	fmt.Println("R2T_GO_PLANNER_DIAGNOSTIC/1")
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema": "r2t.go-planner-diagnostic/1", "attribution": "candidate",
		"stage": stage, "file": file, "message": message,
	}))
	fmt.Println("R2T_GO_PLANNER_DIAGNOSTIC_END")
	os.Exit(1)
}

type compileDiagnostic struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Offset  int    `json:"offset"`
	Message string `json:"message"`
	Kind    string `json:"kind"`
	Soft    bool   `json:"soft"`
}

type trackingImporter struct {
	base     types.Importer
	failures []error
}

func (i *trackingImporter) Import(path string) (*types.Package, error) {
	return i.ImportFrom(path, "", 0)
}
func (i *trackingImporter) ImportFrom(path, dir string, mode types.ImportMode) (*types.Package, error) {
	var pkg *types.Package
	var err error
	if from, ok := i.base.(types.ImporterFrom); ok {
		pkg, err = from.ImportFrom(path, dir, mode)
	} else {
		pkg, err = i.base.Import(path)
	}
	if err != nil {
		i.failures = append(i.failures, fmt.Errorf("import %s: %w", path, err))
	}
	return pkg, err
}

func runtimePackage(fs *token.FileSet, chosen *pkgInfo, target *ast.File, root, pkg, primary string,
	lookup func(string) (io.ReadCloser, error), info *types.Info) []*ast.File {
	if chosen.ForTest == "" || filepath.Clean(chosen.Dir) != filepath.Join(root, pkg) {
		panic("runtime diagnostics lack an exact selected test-package variant")
	}
	sources := map[string]string{}
	contents := map[string][]byte{}
	files := []*ast.File{target}
	diagnostics := []compileDiagnostic{}
	physical := func(pos token.Pos, message, kind string, soft bool) compileDiagnostic {
		p := fs.PositionFor(pos, false)
		rel, err := filepath.Rel(root, p.Filename)
		must(err)
		rel = filepath.ToSlash(rel)
		raw, known := contents[rel]
		if !known || p.Line <= 0 || p.Column <= 0 || p.Offset < 0 || p.Offset > len(raw) {
			panic("typed diagnostic lacks a valid selected physical source position")
		}
		return compileDiagnostic{rel, p.Line, p.Column, p.Offset, message, kind, soft}
	}
	for _, name := range chosen.GoFiles {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(chosen.Dir, path)
		}
		path = filepath.Clean(path)
		rel, err := filepath.Rel(root, path)
		must(err)
		rel = filepath.ToSlash(rel)
		if filepath.ToSlash(filepath.Dir(rel)) != pkg || !strings.HasSuffix(rel, ".go") {
			panic("selected diagnostic source escapes its package")
		}
		if _, exists := sources[rel]; exists {
			panic("duplicate selected diagnostic source")
		}
		raw, err := os.ReadFile(path)
		must(err)
		sources[rel], contents[rel] = digest(raw), raw
		if rel == primary {
			continue
		}
		f, err := parser.ParseFile(fs, path, raw, parser.ParseComments|parser.AllErrors)
		if f != nil {
			files = append(files, f)
		}
		if err != nil {
			list, ok := err.(scanner.ErrorList)
			if !ok {
				panic(err)
			}
			var file *token.File
			fs.Iterate(func(f *token.File) bool {
				if f.Name() == path {
					file = f
					return false
				}
				return true
			})
			if file == nil {
				panic("missing parser physical source")
			}
			for _, e := range list {
				if e.Pos.Offset < 0 || e.Pos.Offset > file.Size() {
					panic("invalid scanner offset")
				}
				diagnostics = append(diagnostics, physical(file.Pos(e.Pos.Offset), e.Msg, "scanner.Error", false))
			}
		}
	}
	if _, exists := sources[primary]; !exists {
		panic("primary missing from selected sources")
	}
	tracked := &trackingImporter{base: importer.ForCompiler(fs, "gc", lookup)}
	unknown := []error{}
	var checked error
	if len(diagnostics) > 0 {
		// A partial AST cannot be type checked. Resolve its available import
		// declarations without another compiler pass before attributing syntax.
		for _, f := range files {
			for _, imp := range f.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					continue
				}
				_, _ = tracked.ImportFrom(path, chosen.Dir, 0)
			}
		}
	} else {
		cfg := types.Config{Importer: tracked, GoVersion: "go1.25", Error: func(err error) {
			e, ok := err.(types.Error)
			if !ok {
				unknown = append(unknown, err)
				return
			}
			diagnostics = append(diagnostics, physical(e.Pos, e.Msg, "types.Error", e.Soft))
		}}
		_, checked = cfg.Check(chosen.ImportPath, fs, files, info)
	}
	// Importer failures include corrupt export data that opened successfully;
	// a types.Error at the import site must not turn them into candidate blame.
	if len(tracked.failures) > 0 || len(unknown) > 0 || len(chosen.DepsErrors) > 0 {
		panic(fmt.Sprintf("unqualified imports/type checking: %v %v %s", tracked.failures, unknown, chosen.DepsErrors))
	}
	if len(diagnostics) > 0 {
		fmt.Println("R2T_GO_PLANNER_DIAGNOSTIC/1")
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": "r2t.go-planner-diagnostic/1", "attribution": "candidate", "stage": "compile",
			"file": primary, "message": "selected Go package does not type-check",
			"package_dir": pkg, "package_name": chosen.Name, "sources": sources, "diagnostics": diagnostics,
		}))
		fmt.Println("R2T_GO_PLANNER_DIAGNOSTIC_END")
		os.Exit(1)
	}
	if checked != nil || chosen.Incomplete || len(chosen.Error) > 0 {
		panic(fmt.Sprintf("unexplained package/type-check failure: %v %s", checked, chosen.Error))
	}
	return files
}

func main() {
	root := flag.String("root", "", "copy root")
	pkg := flag.String("package", "", "package directory")
	file := flag.String("file", "", "glue path")
	test := flag.String("test", "", "exact test name")
	tags := flag.String("tags", "", "Go user tags")
	helper := flag.String("helper", "", "helper template")
	flag.BoolVar(&runtimeDiagnostics, "runtime-diagnostics", false, "emit attributed runtime candidate failures")

	flag.Parse()
	path := filepath.Join(*root, *file)
	original, err := os.ReadFile(path)
	must(err)
	fset := token.NewFileSet()
	target, err := parser.ParseFile(fset, path, original, parser.ParseComments|parser.AllErrors)
	if err != nil {
		candidateFailure("parse", *file, err.Error())
	}
	var selected *ast.FuncDecl
	for _, d := range target.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == *test {
			if selected != nil {
				candidateFailure("scaffold", *file, "duplicate selected wrapper")
			}
			selected = f
		}
	}
	if selected == nil || selected.Body == nil {
		candidateFailure("scaffold", *file, "missing selected wrapper")
	}
	args := []string{"list", "-deps", "-export", "-test", "-json"}
	if runtimeDiagnostics {
		args = append(args, "-e", "-p=1")
	}
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
	matches := 0
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
				matches++
			}
		}
	}
	if chosen == nil {
		panic("selected glue is inactive under actual go list build context")
	}
	if runtimeDiagnostics && matches != 1 {
		panic("ambiguous runtime package metadata")
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
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	var files []*ast.File
	if runtimeDiagnostics {
		files = runtimePackage(fset, chosen, target, *root, *pkg, *file, lookup, info)
	} else {
		files = []*ast.File{target}
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
	}
	if len(selected.Type.Params.List) != 1 || len(selected.Type.Params.List[0].Names) != 1 {
		candidateFailure("scaffold", *file, "selected wrapper does not have one named testing.T parameter")
	}
	param := selected.Type.Params.List[0].Names[0]
	pt, ok := info.TypeOf(selected.Type.Params.List[0].Type).(*types.Pointer)
	if !ok {
		candidateFailure("scaffold", *file, "wrapper parameter not pointer")
	}
	named, ok := pt.Elem().(*types.Named)
	if !ok || named.Obj().Name() != "T" || named.Obj().Pkg().Path() != "testing" {
		candidateFailure("scaffold", *file, "wrapper parameter not testing.T")
	}
	var calls []*ast.CallExpr
	ast.Inspect(selected.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Run" {
			return true
		}
		selection := info.Selections[sel]
		if selection == nil {
			return true
		}
		fn, ok := selection.Obj().(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "github.com/cucumber/godog" {
			return true
		}
		sig := fn.Type().(*types.Signature)
		recv := sig.Recv().Type()
		if p, ok := recv.(*types.Pointer); ok {
			recv = p.Elem()
		}
		nrecv, ok := recv.(*types.Named)
		if ok && nrecv.Obj().Name() == "TestSuite" {
			calls = append(calls, call)
		}
		return true
	})
	if len(calls) != 1 {
		candidateFailure("scaffold", *file, fmt.Sprintf("expected exactly one type-resolved godog.TestSuite.Run; got %d", len(calls)))
	}
	call := calls[0]
	sel := call.Fun.(*ast.SelectorExpr)
	receiver, ok := sel.X.(*ast.Ident)
	if !ok || len(call.Args) != 0 {
		candidateFailure("scaffold", *file, "unsupported corpus Run receiver shape")
	}
	start := fset.PositionFor(call.Pos(), false).Offset
	end := fset.PositionFor(call.End(), false).Offset
	// Run accepts both a value variable and a pointer variable. The actual
	// receiver expression type, not the method signature's receiver, decides
	// whether the helper needs its address. Aliases keep that distinction.
	receiverType := types.Unalias(info.TypeOf(receiver))
	argument := "&" + receiver.Name
	if pointer, ok := receiverType.(*types.Pointer); ok {
		argument = receiver.Name
		receiverType = types.Unalias(pointer.Elem())
	}
	suiteType, ok := receiverType.(*types.Named)
	if !ok || suiteType.Obj().Pkg() == nil ||
		suiteType.Obj().Pkg().Path() != "github.com/cucumber/godog" ||
		suiteType.Obj().Name() != "TestSuite" {
		candidateFailure("scaffold", *file, "Run receiver is not a named Godog suite variable")
	}
	// Newlines go inside the argument list, where Go never inserts a
	// semicolon. Later declarations retain their physical source lines even
	// when a candidate splits its selector or empty argument list across lines.
	replacement := []byte("r2tRun(" + strings.Repeat("\n", bytes.Count(original[start:end], []byte("\n"))) + argument + "," + param.Name + ")")
	transformed := append(append(append([]byte{}, original[:start]...), replacement...), original[end:]...)
	template, err := os.ReadFile(*helper)
	must(err)
	template = bytes.Replace(template, []byte("package r2tbench"), []byte("package "+target.Name.Name), 1)
	support := filepath.Join(*root, *pkg, "zz_r2t_harness_test.go")
	if _, err := os.Stat(support); err == nil {
		panic("reserved helper already exists")
	}

	declarations := map[types.Object]ast.Node{}
	for _, sourceFile := range files {
		for _, d := range sourceFile.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				declarations[info.Defs[fn.Name]] = fn
			}
		}
	}
	span := func(n ast.Node) map[string]any {
		p := fset.PositionFor(n.Pos(), false)
		q := fset.PositionFor(n.End(), false)
		rel, _ := filepath.Rel(*root, p.Filename)
		return map[string]any{"file": filepath.ToSlash(rel), "line": p.Line, "column": p.Column, "start_byte": p.Offset, "end_byte": q.Offset}
	}
	registrations := []map[string]any{}
	for _, sourceFile := range files {
		ast.Inspect(sourceFile, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 2 {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			selection := info.Selections[sel]
			if selection == nil {
				return true
			}
			obj := selection.Obj()
			if obj.Pkg() == nil || obj.Pkg().Path() != "github.com/cucumber/godog" {
				return true
			}
			if obj.Name() != "Step" && obj.Name() != "Given" && obj.Name() != "When" && obj.Name() != "Then" {
				return true
			}
			row := map[string]any{"registration": span(c), "registration_method": obj.Name()}
			logical := fset.PositionFor(c.Pos(), true)
			physical := fset.PositionFor(c.Pos(), false)
			if logical.Filename != physical.Filename || logical.Line != physical.Line {
				// go/parser makes relative directive filenames absolute; runtime.Caller
				// retains the compiler's literal spelling. Keep that join key separate.
				filename := physical.Filename
				for _, group := range sourceFile.Comments {
					for _, comment := range group.List {
						if comment.End() > c.Pos() {
							continue
						}
						text := comment.Text
						if strings.HasPrefix(text, "//line ") && fset.PositionFor(comment.Pos(), false).Column == 1 {
							text = strings.TrimPrefix(text, "//line ")
						} else if strings.HasPrefix(text, "/*line ") {
							text = strings.TrimSuffix(strings.TrimPrefix(text, "/*line "), "*/")
						} else {
							continue
						}
						last := strings.LastIndex(text, ":")
						if last < 0 {
							continue
						}
						if _, err := strconv.Atoi(text[last+1:]); err != nil {
							continue
						}
						name := text[:last]
						if previous := strings.LastIndex(name, ":"); previous >= 0 {
							if _, err := strconv.Atoi(name[previous+1:]); err == nil {
								name = name[:previous]
							}
						}
						if name != "" {
							filename = name
						}
					}
				}
				row["runtime_registration"] = map[string]any{"file": filename, "line": logical.Line}
			}
			var declaration types.Object
			var node ast.Node
			name := ""
			kind := "unresolved_value"
			switch h := c.Args[1].(type) {
			case *ast.SelectorExpr:
				if selected := info.Selections[h]; selected != nil {
					declaration = selected.Obj()
				} else {
					declaration = info.Uses[h.Sel]
				}
			case *ast.Ident:
				declaration = info.Uses[h]
			case *ast.FuncLit:
				node = h
				kind = "function_literal"
				name = fmt.Sprintf("func@%d", fset.PositionFor(h.Pos(), false).Offset)
			}
			if declaration != nil {
				if _, ok := declaration.(*types.Func); ok {
					node = declarations[declaration]
					name = declaration.Name()
					kind = "function_or_method"
				}
			}
			if node != nil {
				h := span(node)
				h["name"] = name
				h["kind"] = kind
				h["signature"] = types.TypeString(info.TypeOf(c.Args[1]), nil)
				row["handler"] = h
			}
			registrations = append(registrations, row)
			return true
		})
	}
	dependencies := []string{}
	seen := map[string]bool{}
	ast.Inspect(target, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Uses[id]
		if obj == nil || !obj.Pos().IsValid() {
			return true
		}
		p := fset.PositionFor(obj.Pos(), false)
		rel, err := filepath.Rel(*root, p.Filename)
		if err == nil && rel != *file && !strings.HasPrefix(rel, "../") && !seen[rel] {
			dependencies = append(dependencies, filepath.ToSlash(rel))
			seen[rel] = true
		}
		return true
	})
	report := map[string]any{"file": *file, "test_name": *test, "package_name": target.Name.Name, "type_resolution": "go/types with real go list -deps -export -test in selected build context", "resolved_method": "github.com/cucumber/godog.TestSuite.Run", "original_sha256": digest(original), "transformed_sha256": digest(transformed), "start_byte": start, "end_byte": end, "replacement": string(replacement), "original_start_line": fset.PositionFor(call.Pos(), false).Line, "line_delta": 0, "byte_delta": len(replacement) - (end - start), "original_source_lines_preserved": strings.Count(string(original), "\n") == strings.Count(string(transformed), "\n"), "helper": "zz_r2t_harness_test.go", "registration_declarations": registrations, "source_dependencies": dependencies}
	raw, err := json.MarshalIndent(map[string]any{"map": report, "transformed_source": string(transformed), "helper_source": string(template)}, "", "  ")
	must(err)
	fmt.Println(string(raw))
}
