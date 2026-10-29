// One read-only planner: existing typed interposition plus native coverage then entry hooks.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var root, pkg, glue, test, tags, helper string
var runtimeDiagnostics bool

type Edit struct {
	Start, End int
	Text       string
}
type Decl struct {
	Name             string
	Line, Start, End int
	Public           bool
	Receiver         string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func sha(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
func command(args ...string) []byte {
	c := exec.Command("/usr/local/go/bin/go", args...)
	c.Dir = root
	c.Env = append(os.Environ(), "GOFLAGS=-mod=readonly -p=1")
	var out, errout bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errout
	if err := c.Run(); err != nil {
		if runtimeDiagnostics && bytes.HasPrefix(out.Bytes(), []byte("R2T_GO_PLANNER_DIAGNOSTIC/1\n")) {
			_, _ = os.Stdout.Write(out.Bytes())
			os.Exit(1)
		}
		panic(fmt.Sprintf("%v: %v\n%s", args, err, errout.String()))
	}
	return out.Bytes()
}
func receiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverName(e.X)
	case *ast.IndexExpr:
		return receiverName(e.X)
	case *ast.IndexListExpr:
		return receiverName(e.X)
	case *ast.ParenExpr:
		return receiverName(e.X)
	default:
		panic("unsupported production receiver syntax")
	}
}
func main() {
	flag.StringVar(&root, "root", "", "execution copy root")
	flag.StringVar(&pkg, "package", "", "selected package directory")
	flag.StringVar(&glue, "file", "", "selected answer file")
	flag.StringVar(&test, "test", "", "selected Test function")
	flag.StringVar(&tags, "tags", "", "selected Go tags")
	flag.StringVar(&helper, "helper", "", "runtime helper template")
	flag.BoolVar(&runtimeDiagnostics, "runtime-diagnostics", false, "preserve trusted candidate diagnostics")
	flag.Parse()
	if root != "/r2t-go/run/work" || pkg == "" || glue == "" || test == "" || helper == "" {
		panic("invalid measurement context")
	}
	// Interpose first so its source/parser failures retain their trusted
	// diagnostic frame before a metadata-only census can fail on that source.
	args := []string{"run", "-p=1", "./_bench/go/support/interpose.go", "-root", root, "-package", pkg, "-file", glue, "-test", test, "-tags", tags, "-helper", helper}
	if runtimeDiagnostics {
		args = append(args, "-runtime-diagnostics")
	}
	var plan map[string]any
	must(json.Unmarshal(command(args...), &plan))
	// A metadata-only compile fence query, within this SAME trusted planner.
	census := command("list", "-p=1", "-deps", "-test", "-json", "-tags="+tags, "./"+pkg)
	decoder := json.NewDecoder(bytes.NewReader(census))
	active := map[string]bool{}
	modulePath := ""
	for {
		var p struct {
			Dir     string
			GoFiles []string
			Module  *struct {
				Path, Dir string
				Main      bool
			}
			CgoFiles []string
		}
		err := decoder.Decode(&p)
		if err == io.EOF {
			break
		}
		must(err)
		if p.Module != nil && p.Module.Main && filepath.Clean(p.Module.Dir) == root {
			modulePath = p.Module.Path
		}
		if !strings.HasPrefix(p.Dir, root+"/") {
			continue
		}
		if len(p.CgoFiles) > 0 {
			panic("first-party cgo measurement is unqualified")
		}
		for _, name := range p.GoFiles {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			full := name
			if !filepath.IsAbs(full) {
				full = filepath.Join(p.Dir, name)
			}
			rel, err := filepath.Rel(root, full)
			must(err)
			if strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "external/") {
				active[filepath.ToSlash(rel)] = true
			}
		}
	}
	var productions []string
	for p := range active {
		productions = append(productions, p)
	}
	sort.Strings(productions)
	if modulePath == "" || len(productions) == 0 {
		panic("missing compiled first-party production inventory")
	}
	recImport := modulePath + "/_bench/go/measure"
	template, ok := plan["helper_source"].(string)
	if !ok || strings.Count(template, "R2T_MEASUREMENT_IMPORT") != 1 {
		panic("runtime helper import placeholder differs")
	}
	plan["helper_source"] = strings.Replace(template, "R2T_MEASUREMENT_IMPORT", recImport, 1)

	// Package-level generated counter names must avoid identifiers from every
	// compiled first-party source, including sibling files in the same package.
	identifiers := map[string]bool{}
	for _, path := range productions {
		raw, err := os.ReadFile(filepath.Join(root, path))
		must(err)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, raw, parser.ParseComments)
		must(err)
		ast.Inspect(parsed, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				identifiers[id.Name] = true
			}
			return true
		})
	}

	var results []map[string]any
	for fileNumber, path := range productions {
		counterName := fmt.Sprintf("R2TGoCover%d", fileNumber)
		for identifiers[counterName] {
			counterName += "x"
		}
		identifiers[counterName] = true
		hookName := "r2tmeasurehook"
		for identifiers[hookName] {
			hookName += "x"
		}
		original, err := os.ReadFile(filepath.Join(root, path))
		must(err)
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, path, original, parser.ParseComments)
		must(err)
		decls := map[string]Decl{}
		var excluded []string
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name.Name == "init" || fn.Body == nil {
				excluded = append(excluded, fn.Name.Name)
				continue
			}
			recv := ""
			if fn.Recv != nil {
				recv = receiverName(fn.Recv.List[0].Type)
			}

			name := fn.Name.Name
			if recv != "" {
				name = recv + "." + name
			}
			if _, ok := decls[name]; ok {
				panic("duplicate production declaration")
			}
			decls[name] = Decl{name, fs.PositionFor(fn.Pos(), false).Line, fs.PositionFor(fn.Body.Pos(), false).Line, fs.PositionFor(fn.Body.End(), false).Line, ast.IsExported(fn.Name.Name), recv}
		}
		// Original source directives need a physical/logical map; no pinned
		// coddy production source has one. Refuse rather than credit false paths.
		for _, group := range f.Comments {
			for _, c := range group.List {
				if strings.HasPrefix(c.Text, "//line ") || strings.HasPrefix(c.Text, "/*line ") {
					panic("production source directive needs qualified physical mapping")
				}
			}
		}

		temp, err := os.CreateTemp("/r2t-go/tmp", "native-cover-*.go")
		must(err)
		out := temp.Name()
		must(temp.Close())
		command("tool", "cover", "-mode=atomic", "-var="+counterName, "-o", out, filepath.Join(root, path))
		covered, err := os.ReadFile(out)
		must(err)
		must(os.Remove(out))
		cs := token.NewFileSet()
		cf, err := parser.ParseFile(cs, path, covered, parser.ParseComments)
		must(err)
		edits := []Edit{{cs.PositionFor(cf.Name.End(), false).Offset, cs.PositionFor(cf.Name.End(), false).Offset, "; import " + hookName + " " + strconv.Quote(recImport)}}
		declarations := []Decl{}
		for _, d := range cf.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "init" || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil {
				name = receiverName(fn.Recv.List[0].Type) + "." + name
			}
			orig, ok := decls[name]
			if !ok {
				panic("coverage invented function")
			}
			if cs.PositionFor(fn.Pos(), true).Line != orig.Line || cs.PositionFor(fn.Pos(), true).Filename != filepath.Join(root, path) {
				panic("native cover lost original position")
			}
			pos := cs.PositionFor(fn.Body.Lbrace, false).Offset + 1
			edits = append(edits, Edit{pos, pos, fmt.Sprintf(" %s.Enter(%q,%d,%q);", hookName, path, orig.Line, name)})
			declarations = append(declarations, orig)
		}
		// Keep native block metadata and replace only its atomic increment
		// with the recorder's shared-cut increment. No second coverage pass.
		counterEdits := []Edit{}
		ast.Inspect(cf, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "_cover_atomic_" || sel.Sel.Name != "AddUint32" {
				return true
			}
			if len(c.Args) != 2 {
				panic("unexpected native coverage increment")
			}
			start := cs.PositionFor(c.Pos(), false).Offset
			end := cs.PositionFor(c.End(), false).Offset
			a := cs.PositionFor(c.Args[0].Pos(), false).Offset
			b := cs.PositionFor(c.Args[0].End(), false).Offset
			arg := string(covered[a:b])
			if !strings.HasPrefix(arg, "&"+counterName+".Count[") {
				panic("native counter target differs")
			}
			e := Edit{start, end, hookName + ".Hit(" + arg + ")"}
			counterEdits = append(counterEdits, e)
			edits = append(edits, e)
			return true
		})
		sort.Slice(edits, func(i, j int) bool {
			if edits[i].Start == edits[j].Start {
				return edits[i].End < edits[j].End
			}
			return edits[i].Start < edits[j].Start
		})
		transformed := append([]byte(nil), covered...)
		for i := len(edits) - 1; i >= 0; i-- {
			e := edits[i]
			transformed = append(append(append([]byte{}, transformed[:e.Start]...), []byte(e.Text)...), transformed[e.End:]...)
		}
		atomicUse := ""
		if len(counterEdits) > 0 {
			atomicUse = "var _ = _cover_atomic_.AddUint32;"
		}
		suffix := fmt.Sprintf("\n%sfunc init(){%s.Register(%q,%s.Count[:],%s.Pos[:],%s.NumStmt[:])}\n", atomicUse, hookName, path, counterName, counterName, counterName)
		transformed = append(transformed, []byte(suffix)...)
		if strings.Count(string(covered), "\n") != strings.Count(string(transformed), "\n")-2 {
			panic("entry edits moved original lines")
		}
		_, err = parser.ParseFile(token.NewFileSet(), path, transformed, parser.ParseComments)
		must(err)
		sort.Slice(declarations, func(i, j int) bool { return declarations[i].Line < declarations[j].Line })
		results = append(results, map[string]any{"file": path, "original_sha256": sha(original), "original_source": string(original), "native_covered_source": string(covered), "edits": edits, "counter_edits": counterEdits, "counter_name": counterName, "hook_name": hookName, "suffix": suffix, "transformed_source": string(transformed), "declarations": declarations, "excluded": excluded, "native_cover_command": []string{"go", "tool", "cover", "-mode=atomic", "-var=" + counterName, "-o", "<owned-temp>", filepath.Join(root, path)}})
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"interposition": plan, "production_plans": results, "production_files": productions, "compile_census_json_stream": string(census), "module_path": modulePath, "recorder_import": recImport, "coverage_order": "native-original-coverage-before-api-entry-hooks"}))
}
