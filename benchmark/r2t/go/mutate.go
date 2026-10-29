// Original-source Go mutation candidates and re-enumerating byte applier.
// The toolkit facade owns pristine/candidate compilation before population emission.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

const ENGINE = "r2t-mutate-go"
const ENGINE_VERSION = "1.0"
const ENUMERATOR_REV = "r2t-mutate-go/typed-validity-1"
const CONSTRUCTION_CACHE_BATCH = 32
const OPERATOR_ORDER = "ConditionalBoundary,NegateConditional,Increment,ArithmeticOperator,TrueValue,FalseValue,ReturnValue,MethodCallRemoval,LogicalConnector,RemoveNegation,ConstantReplacement"

type Context struct {
	Root        string   `json:"root"`
	PackageDir  string   `json:"package_dir"`
	PackageName string   `json:"package_name"`
	GluePath    string   `json:"glue_path"`
	Tags        []string `json:"go_build_tags"`
	CacheDir    string   `json:"-"`
}
type Request struct {
	Contexts    []Context         `json:"contexts"`
	SourceFiles map[string]string `json:"source_files"`
}
type Package struct {
	Dir, ImportPath, Name, Export, ForTest string
	GoFiles, CgoFiles                      []string
	ImportMap                              map[string]string
	Module                                 *struct {
		Dir  string
		Main bool
	}
	Error      any
	DepsErrors []any
}
type Row struct {
	File      string `json:"file"`
	Operator  string `json:"operator"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
	Original  string `json:"original"`
	Mutated   string `json:"mutated"`
}
type Node struct {
	AST       ast.Node
	Signature *types.Signature
}
type Unit struct {
	Path       string
	Raw        []byte
	FS         *token.FileSet
	Info       *types.Info
	Package    *types.Package
	Nodes      []Node
	ByPosition map[string]Node
}
type Loaded struct {
	Context         Context
	Files           map[string]*Unit
	DiagnosticFiles map[string]bool
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	must(err)
	if rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		panic("source outside original root")
	}
	return filepath.ToSlash(rel)
}
func full(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}
func production(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") && (strings.HasPrefix(path, "cmd/") || strings.HasPrefix(path, "internal/") || strings.HasPrefix(path, "external/"))
}
func canonicalPath(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.ToSlash(filepath.Clean(path)) == path && !strings.HasPrefix(path, "../")
}
func nodeKey(fs *token.FileSet, node ast.Node) string {
	return fmt.Sprintf("%T:%d:%d", node, fs.PositionFor(node.Pos(), false).Offset, fs.PositionFor(node.End(), false).Offset)
}
func load(original string, req Request, c Context) Loaded {
	if !filepath.IsAbs(c.Root) || !canonicalPath(c.PackageDir) || !canonicalPath(c.GluePath) || filepath.Dir(c.GluePath) != c.PackageDir || c.PackageName == "" {
		panic("invalid explicit build context")
	}
	if !(len(c.Tags) == 0 || len(c.Tags) == 1 && (c.Tags[0] == "http" || c.Tags[0] == "cli")) {
		panic("unqualified Go build tags")
	}
	argv := []string{"list", "-p=1", "-deps", "-export", "-test", "-json", "-tags=" + strings.Join(c.Tags, ","), "./" + c.PackageDir}
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), argv...)
	cmd.Dir = c.Root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("pristine go list/export failed: %v: %s", err, stderr.String()))
	}
	exports := map[string]string{}
	packages := []Package{}
	selected := 0
	decoder := json.NewDecoder(&stdout)
	for {
		var p Package
		err := decoder.Decode(&p)
		if err == io.EOF {
			break
		}
		must(err)
		if p.Error != nil || len(p.DepsErrors) != 0 {
			panic("unresolved pristine package: " + p.ImportPath)
		}
		if p.Export != "" {
			exports[p.ImportPath] = p.Export
		}
		if p.Name == c.PackageName {
			for _, n := range p.GoFiles {
				if filepath.Clean(full(p.Dir, n)) == filepath.Join(c.Root, c.GluePath) {
					selected++
				}
			}
		}
		packages = append(packages, p)
	}
	if selected != 1 {
		panic(fmt.Sprintf("exact selected package/glue has %d matches", selected))
	}
	// A test binary compiles the augmented package, not both variants as two sources.
	chosen := map[string]Package{}
	for _, p := range packages {
		if p.Module == nil || !p.Module.Main || filepath.Clean(p.Module.Dir) != filepath.Clean(c.Root) {
			continue
		}
		key := strings.Split(p.ImportPath, " [")[0]
		old, exists := chosen[key]
		if !exists || old.ForTest == "" && p.ForTest != "" {
			chosen[key] = p
		}
	}
	result := Loaded{c, map[string]*Unit{}, map[string]bool{}}
	keys := []string{}
	for k := range chosen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := chosen[key]
		wanted := map[string]bool{}
		for _, n := range p.GoFiles {
			path := full(p.Dir, n)
			rel, err := filepath.Rel(c.Root, path)
			if err == nil && production(filepath.ToSlash(rel)) {
				wanted[filepath.ToSlash(rel)] = true
			}
		}
		if len(wanted) == 0 {
			continue
		}
		if len(p.CgoFiles) != 0 {
			panic("first-party cgo needs a qualified original-source mapping: " + p.ImportPath)
		}
		fs := token.NewFileSet()
		files := []*ast.File{}
		paths := []string{}
		raws := map[string][]byte{}
		for _, n := range p.GoFiles {
			path := full(p.Dir, n)
			rel := relative(c.Root, path)
			if !strings.HasSuffix(rel, ".go") {
				panic("generated first-party compiler input")
			}
			raw, err := os.ReadFile(filepath.Join(original, rel))
			must(err)
			copied, err := os.ReadFile(path)
			must(err)
			if !bytes.Equal(raw, copied) || req.SourceFiles[rel] != digest(raw) {
				panic("compiled original bytes differ: " + rel)
			}
			f, err := parser.ParseFile(fs, rel, raw, parser.ParseComments|parser.AllErrors|parser.SkipObjectResolution)
			must(err)
			result.DiagnosticFiles[rel] = true
			for _, group := range f.Comments {
				for _, comment := range group.List {
					text := ""
					if strings.HasPrefix(comment.Text, "//line ") && fs.PositionFor(comment.Pos(), false).Column == 1 {
						text = strings.TrimPrefix(comment.Text, "//line ")
					}
					if strings.HasPrefix(comment.Text, "/*line ") && strings.HasSuffix(comment.Text, "*/") {
						text = strings.TrimSuffix(strings.TrimPrefix(comment.Text, "/*line "), "*/")
					}
					if text == "" {
						continue
					}
					// The Go parser has already validated directive syntax. Keep its
					// literal spelling as well as parser-relative spelling because
					// compiler diagnostics retain the literal directive filename.
					for count := 0; count < 2; count++ {
						colon := strings.LastIndex(text, ":")
						if colon < 0 {
							break
						}
						if _, err := strconv.Atoi(text[colon+1:]); err != nil {
							break
						}
						text = text[:colon]
					}
					if text != "" {
						result.DiagnosticFiles[text] = true
						result.DiagnosticFiles[filepath.ToSlash(full(filepath.Dir(rel), text))] = true
					}
				}
			}
			files = append(files, f)
			paths = append(paths, rel)
			raws[rel] = raw
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Scopes: map[ast.Node]*types.Scope{}}
		config := types.Config{GoVersion: "go1.25.0", Importer: importer.ForCompiler(fs, "gc", func(path string) (io.ReadCloser, error) {
			if mapped := p.ImportMap[path]; mapped != "" {
				path = mapped
			}
			if exports[path] == "" {
				return nil, fmt.Errorf("missing cached export: %s", path)
			}
			return os.Open(exports[path])
		})}
		typed, err := config.Check(key, fs, files, info)
		must(err)
		for i, f := range files {
			path := paths[i]
			if !wanted[path] {
				continue
			}
			if result.Files[path] != nil {
				panic("duplicate compiled production file: " + path)
			}
			u := &Unit{Path: path, Raw: raws[path], FS: fs, Info: info, Package: typed, ByPosition: map[string]Node{}}
			var walk func(ast.Node, *types.Signature)
			walk = func(root ast.Node, sig *types.Signature) {
				if root == nil {
					return
				}
				ast.Inspect(root, func(n ast.Node) bool {
					if n == nil {
						return false
					}
					switch f := n.(type) {
					case *ast.FuncDecl:
						obj, ok := info.Defs[f.Name].(*types.Func)
						if !ok {
							panic("unresolved function signature")
						}
						walk(f.Type, nil)
						if f.Body != nil {
							walk(f.Body, obj.Type().(*types.Signature))
						}
						return false
					case *ast.FuncLit:
						resolved, ok := info.TypeOf(f).(*types.Signature)
						if !ok {
							panic("unresolved literal signature")
						}
						walk(f.Type, nil)
						walk(f.Body, resolved)
						return false
					}
					node := Node{n, sig}
					u.Nodes = append(u.Nodes, node)
					u.ByPosition[nodeKey(fs, n)] = node
					return true
				})
			}
			walk(f, nil)
			result.Files[path] = u
		}
	}
	return result
}
func (u *Unit) builtin(name string, pos token.Pos) bool {
	scope := u.Package.Scope()
	for _, candidate := range u.Info.Scopes {
		if candidate.Contains(pos) && (scope == u.Package.Scope() || candidate.Pos() >= scope.Pos() && candidate.End() <= scope.End()) {
			scope = candidate
		}
	}
	_, object := scope.LookupParent(name, pos)
	return object == types.Universe.Lookup(name)
}

// Type-parameter unions/intersections restrict possible underlying basic kinds.
// Method constraints do not invent an underlying numeric type.
func numericKinds(t types.Type, seen map[types.Type]bool) uint64 {
	const all = ^uint64(0)
	if seen[t] {
		return all
	}
	seen[t] = true
	defer delete(seen, t)
	switch t := t.(type) {
	case *types.Basic:
		return uint64(1) << uint(t.Kind())
	case *types.Alias:
		return numericKinds(types.Unalias(t), seen)
	case *types.Named:
		return numericKinds(t.Underlying(), seen)
	case *types.TypeParam:
		return numericKinds(t.Constraint(), seen)
	case *types.Union:
		var out uint64
		for i := 0; i < t.Len(); i++ {
			out |= numericKinds(t.Term(i).Type(), seen)
		}
		return out
	case *types.Interface:
		out := all
		for i := 0; i < t.NumEmbeddeds(); i++ {
			out &= numericKinds(t.EmbeddedType(i), seen)
		}
		return out
	default:
		return uint64(1) << 63
	}
}
func (u *Unit) numeric(expr ast.Expr) bool {
	t := u.Info.TypeOf(expr)
	if t == nil {
		panic("missing arithmetic operand type")
	}
	kinds := numericKinds(t, map[types.Type]bool{})
	var numeric uint64
	for _, kind := range []types.BasicKind{types.Int, types.Int8, types.Int16, types.Int32, types.Int64, types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64, types.Uintptr, types.Float32, types.Float64, types.Complex64, types.Complex128, types.UntypedInt, types.UntypedRune, types.UntypedFloat, types.UntypedComplex} {
		numeric |= uint64(1) << uint(kind)
	}
	return kinds != 0 && kinds & ^numeric == 0
}

func (u *Unit) candidate(node Node, operator string) *Row {
	var a, b token.Pos
	replacement := ""
	eligible := false
	switch n := node.AST.(type) {
	case *ast.BinaryExpr:
		switch operator {
		case "ConditionalBoundary":
			replacement = map[token.Token]string{token.LSS: "<=", token.LEQ: "<", token.GTR: ">=", token.GEQ: ">"}[n.Op]
		case "NegateConditional":
			replacement = map[token.Token]string{token.EQL: "!=", token.NEQ: "==", token.LSS: ">=", token.LEQ: ">", token.GTR: "<=", token.GEQ: "<"}[n.Op]
		case "ArithmeticOperator":
			replacement = map[token.Token]string{token.ADD: "-", token.SUB: "+", token.MUL: "/", token.QUO: "*", token.REM: "*"}[n.Op]
			if replacement != "" && (!u.numeric(n.X) || !u.numeric(n.Y)) {
				replacement = ""
			}
		case "LogicalConnector":
			replacement = map[token.Token]string{token.LAND: "||", token.LOR: "&&"}[n.Op]
		}
		eligible = replacement != ""
		a = n.OpPos
		b = a + token.Pos(len(n.Op.String()))
	case *ast.IncDecStmt:
		if operator == "Increment" {
			eligible = true
			replacement = "++"
			if n.Tok == token.INC {
				replacement = "--"
			}
			a = n.TokPos
			b = a + 2
		}
	case *ast.Ident:
		if operator == "TrueValue" && n.Name == "true" {
			replacement = "false"
		}
		if operator == "FalseValue" && n.Name == "false" {
			replacement = "true"
		}
		eligible = replacement != "" && u.Info.Uses[n] == types.Universe.Lookup(n.Name) && u.builtin(replacement, n.Pos())
		a = n.Pos()
		b = n.End()
	case *ast.ReturnStmt:
		if operator == "ReturnValue" && node.Signature != nil && node.Signature.Results().Len() == 1 && len(n.Results) == 1 {
			expression := n.Results[0]
			for {
				p, ok := expression.(*ast.ParenExpr)
				if !ok {
					break
				}
				expression = p.X
			}
			id, isID := expression.(*ast.Ident)
			alreadyNil := isID && u.Info.Uses[id] == types.Universe.Lookup("nil")
			eligible = !alreadyNil && u.builtin("nil", n.Pos()) && types.AssignableTo(types.Typ[types.UntypedNil], node.Signature.Results().At(0).Type())
			a = n.Pos()
			b = n.End()
			replacement = "return nil"
		}
	case *ast.ExprStmt:
		_, call := n.X.(*ast.CallExpr)
		if operator == "MethodCallRemoval" && call {
			eligible = true
			a = n.Pos()
			b = n.End()
			replacement = ";"
		}
	case *ast.UnaryExpr:
		if operator == "RemoveNegation" && n.Op == token.NOT {
			eligible = true
			a = n.OpPos
			b = a + 1
		}
	case *ast.BasicLit:
		if operator == "ConstantReplacement" && n.Kind == token.INT {
			value := constant.MakeFromLiteral(n.Value, token.INT, 0)
			if value.Kind() != constant.Int {
				panic("unresolved integer literal")
			}
			replacement = constant.BinaryOp(value, token.ADD, constant.MakeInt64(1)).ExactString()
			eligible = true
			a = n.Pos()
			b = n.End()
		}
	}
	if !eligible {
		return nil
	}
	first, last := u.FS.PositionFor(a, false), u.FS.PositionFor(b-1, false)
	start, end := u.FS.File(a).Offset(a), u.FS.File(b).Offset(b)
	if start < 0 || end <= start || end > len(u.Raw) {
		panic("invalid physical mutation span")
	}
	return &Row{u.Path, operator, first.Line, first.Column, last.Line, last.Column, string(u.Raw[start:end]), replacement}
}
func candidates(loaded []Loaded, onlyFile string) []Row {
	first := map[string]*Unit{}
	for _, context := range loaded {
		for file, u := range context.Files {
			if onlyFile == "" || onlyFile == file {
				if first[file] == nil {
					first[file] = u
				}
			}
		}
	}
	paths := []string{}
	for p := range first {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	rows := []Row{}
	seen := map[Row]bool{}
	// Emit from one original-file traversal. Other contexts only validate each
	// proposed original position with their own compiler objects; no raw-row dedup.
	for _, file := range paths {
		u := first[file]
		for _, node := range u.Nodes {
			for _, operator := range strings.Split(OPERATOR_ORDER, ",") {
				row := u.candidate(node, operator)
				if row == nil {
					continue
				}
				eligible := true
				for _, context := range loaded {
					other := context.Files[file]
					if other == nil {
						continue
					}
					corresponding, ok := other.ByPosition[nodeKey(u.FS, node.AST)]
					if !ok {
						panic("same original file has different syntax")
					}
					candidate := other.candidate(corresponding, operator)
					if candidate == nil || *candidate != *row {
						eligible = false
						break
					}
				}
				if eligible {
					if seen[*row] {
						panic("duplicate raw mutation descriptor")
					}
					seen[*row] = true
					rows = append(rows, *row)
				}
			}
		}
	}
	return rows
}
func splice(raw []byte, row Row) []byte {
	lines := bytes.SplitAfter(raw, []byte("\n"))
	offset := func(line, column int) int {
		if line < 1 || line > len(lines) || column < 1 || column > len(lines[line-1]) {
			panic("invalid mutation byte coordinate")
		}
		total := column - 1
		for _, p := range lines[:line-1] {
			total += len(p)
		}
		return total
	}
	a, b := offset(row.StartLine, row.StartCol), offset(row.EndLine, row.EndCol)+1
	if a >= b || !bytes.Equal(raw[a:b], []byte(row.Original)) {
		panic("stale original mutation span")
	}
	return append(append(append([]byte{}, raw[:a]...), []byte(row.Mutated)...), raw[b:]...)
}

func writeJSON(path string, value any) {
	raw, err := json.MarshalIndent(value, "", " ")
	must(err)
	must(os.WriteFile(path, append(raw, '\n'), 0600))
}
func compile(c Context, output, prefix string) (int, string) {
	argv := []string{filepath.Join(runtime.GOROOT(), "bin/go"), "test", "-c", "-vet=off", "-p=1", "-tags=" + strings.Join(c.Tags, ","), "-o", output, "./" + c.PackageDir}
	writeJSON(prefix+".command.json", map[string]any{"argv": argv, "cwd": c.Root})
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = c.Root
	if c.CacheDir != "" {
		command.Env = append(os.Environ(), "GOCACHE="+c.CacheDir)
	}
	// The outer analysis deadline can terminate this engine during Run.
	// Persist compiler writes directly, before diagnostic export and retirement.
	stdout, err := os.OpenFile(prefix+".stdout", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	must(err)
	defer stdout.Close()
	stderr, err := os.OpenFile(prefix+".stderr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	must(err)
	defer stderr.Close()
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	must(stdout.Close())
	must(stderr.Close())
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			panic("compiler launch failed: " + err.Error())
		}
		code = exit.ExitCode()
	}
	stdoutBytes, err := os.ReadFile(prefix + ".stdout")
	must(err)
	stderrBytes, err := os.ReadFile(prefix + ".stderr")
	must(err)
	writeJSON(prefix+".result.json", map[string]any{"returncode": code})
	// Only compiler diagnostics are evidence; the disposable binary never runs.
	if err := os.Remove(output); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	return code, string(stdoutBytes) + string(stderrBytes)
}

var sourceDiagnostic = regexp.MustCompile(`^([^:\n]+\.go):[0-9]+(?::[0-9]+)?: `)

func compilerFailureKind(code int, text string, known map[string]bool) string {
	if code != 1 {
		return "tool"
	}
	saw := false
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "FAIL") {
			continue
		}
		// Related source locations (previous case/declaration) are tab-indented.
		// Normalize indentation but still validate their file and failure kind.
		diagnostic := strings.TrimLeft(line, " \t")
		match := sourceDiagnostic.FindStringSubmatch(diagnostic)
		if match != nil {
			message := diagnostic[len(match[0]):]
			// cmd/compile/internal/types2 emits BrokenImport at the importing source
			// position. These failures concern the export/tool input, not the splice:
			// none of the eleven approved operators changes import/package declarations.
			if strings.HasPrefix(message, "could not import ") || strings.HasPrefix(message, "can't find import:") {
				return "dependency"
			}
			if strings.HasPrefix(message, "internal compiler error:") {
				return "compiler"
			}
			if !known[strings.TrimPrefix(match[1], "./")] {
				return "unclassified"
			}
			saw = true
		} else if !(saw && (strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " "))) {
			return "unclassified"
		}
	}
	if saw {
		return "source"
	}
	return "unclassified"
}
func compilerRejection(code int, text string, known map[string]bool) bool {
	return compilerFailureKind(code, text, known) == "source"
}

func compileMutant(c Context, row Row, pristine []byte, output, prefix string) (int, string) {
	target := filepath.Join(c.Root, row.File)
	before, err := os.Lstat(target)
	must(err)
	if !before.Mode().IsRegular() {
		panic("candidate target is not regular")
	}
	current, err := os.ReadFile(target)
	must(err)
	if !bytes.Equal(current, pristine) {
		panic("candidate copy was not restored")
	}
	changed := splice(pristine, row)
	// Every compiler invocation is over a disposable analysis view. Restoration
	// is mandatory on ordinary errors/panics; the owner discards the view after a
	// killed process and never emits a completed population from partial output.
	defer func() {
		must(os.WriteFile(target, pristine, before.Mode().Perm()))
		must(os.Chmod(target, before.Mode()))
		restored, err := os.ReadFile(target)
		must(err)
		after, err := os.Lstat(target)
		must(err)
		if !bytes.Equal(restored, pristine) || metadata(before) != metadata(after) {
			panic("candidate restoration failed")
		}
	}()
	must(os.WriteFile(target, changed, before.Mode().Perm()))
	current, err = os.ReadFile(target)
	must(err)
	after, err := os.Lstat(target)
	must(err)
	if !bytes.Equal(current, changed) || metadata(before) != metadata(after) {
		panic("candidate splice or metadata differs")
	}
	code, text := compile(c, output, prefix)
	current, err = os.ReadFile(target)
	must(err)
	after, err = os.Lstat(target)
	must(err)
	if !bytes.Equal(current, changed) || metadata(before) != metadata(after) {
		panic("compiler changed candidate source")
	}
	return code, text
}

type FamilyCount struct {
	Operator    string  `json:"operator"`
	Candidates  int     `json:"candidates"`
	Invalid     int     `json:"invalid"`
	Eligible    int     `json:"eligible"`
	EmptyReason *string `json:"empty_reason"`
}
type ContextCount struct {
	Context       int  `json:"context"`
	PristineValid bool `json:"pristine_valid"`
	Candidates    int  `json:"candidates"`
	Invalid       int  `json:"invalid"`
	Eligible      int  `json:"eligible"`
}

// Snapshot only after every pristine compile and typed package load. The
// constructor's warm cache then remains unchanged except harmless read mtimes.
// Each active context owns its additions and prunes them with no compile active.
// Payloads are content-addressed; Go may rewrite action indexes, so copy those.
type WarmCache struct {
	Root    string
	Entries map[string]fs.DirEntry
	Names   []string
}

func snapshotWarmCache() WarmCache {
	root := os.Getenv("GOCACHE")
	if root == "" {
		raw, err := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "env", "GOCACHE").Output()
		must(err)
		root = strings.TrimSpace(string(raw))
	}
	warm := WarmCache{Root: root, Entries: map[string]fs.DirEntry{}}
	must(filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		warm.Entries[rel] = entry
		warm.Names = append(warm.Names, rel)
		return nil
	}))
	return warm
}

func (warm WarmCache) seed(parent string, index int) string {
	root, err := os.MkdirTemp(parent, fmt.Sprintf("compile-cache-%d-", index))
	must(err)
	ready := false
	defer func() {
		if !ready {
			must(os.RemoveAll(root))
		}
	}()
	// WalkDir's lexical order also ensures parents precede children.
	for _, name := range warm.Names {
		entry := warm.Entries[name]
		source, target := filepath.Join(warm.Root, name), filepath.Join(root, name)
		if entry.IsDir() {
			must(os.Mkdir(target, 0700))
		} else if strings.HasSuffix(name, "-d") || strings.HasSuffix(filepath.Dir(name), "-d") {
			must(os.Link(source, target))
		} else {
			raw, err := os.ReadFile(source)
			must(err)
			must(os.WriteFile(target, raw, 0600))
		}
	}
	ready = true
	return root
}

func (warm WarmCache) prune(root string) {
	must(filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if _, exists := warm.Entries[rel]; exists {
			return nil
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}))
}

// Start the largest independent views first to avoid leaving expensive views
// queued behind a full wave of small ones. Original indexes remain identities.
func contextOrder(loaded []Loaded, rows []Row) []int {
	byFile := map[string]int{}
	for _, row := range rows {
		byFile[row.File]++
	}
	order := make([]int, len(loaded))
	counts := make([]int, len(loaded))
	for i, context := range loaded {
		order[i] = i
		for path, unit := range context.Files {
			if unit != nil {
				counts[i] += byFile[path]
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	return order
}

// Each context owns a distinct disposable source view. A context is serial;
// only disjoint views compile concurrently. Join all workers before propagating
// a refusal, so every in-flight compileMutant restores its source first.
func runContexts(order []int, workers int, work func(int, func() bool)) {
	var stopped atomic.Bool
	var group sync.WaitGroup
	slots := make(chan struct{}, workers)
	failures := make([]any, len(order))
	for _, i := range order {
		if stopped.Load() {
			break
		}
		slots <- struct{}{}
		group.Add(1)
		go func(i int) {
			defer group.Done()
			defer func() { <-slots }()
			defer func() {
				if failure := recover(); failure != nil {
					failures[i] = failure
					stopped.Store(true)
				}
			}()
			if !stopped.Load() {
				work(i, stopped.Load)
			}
		}(i)
	}
	group.Wait()
	for _, failure := range failures {
		if failure != nil {
			panic(failure)
		}
	}
}

func validateCandidates(loaded []Loaded, rows []Row, outdir string, workers int) ([]Row, int) {
	// Index results by original context and row, never completion order.
	warm := snapshotWarmCache()
	verdicts := make([][]uint8, len(loaded))
	runContexts(contextOrder(loaded, rows), workers, func(i int, stopped func() bool) {
		context := loaded[i]
		context.Context.CacheDir = warm.seed(outdir, i)
		defer func() { must(os.RemoveAll(context.Context.CacheDir)) }()
		completed := 0
		verdicts[i] = make([]uint8, len(rows))
		for number, row := range rows {
			if stopped() {
				return
			}
			unit := context.Files[row.File]
			if unit == nil {
				continue
			}
			prefix := filepath.Join(outdir, fmt.Sprintf("mutant-%d-%d", number, i))
			code, text := compileMutant(context.Context, row, unit.Raw, prefix+".test", prefix)
			completed++
			if completed%CONSTRUCTION_CACHE_BATCH == 0 {
				warm.prune(context.Context.CacheDir)
			}
			verdicts[i][number] = 1
			if code != 0 {
				kind := compilerFailureKind(code, text, context.DiagnosticFiles)
				writeJSON(prefix+".failure-kind.json", map[string]any{"kind": kind})
				if kind != "source" {
					panic("unknown compiler/infrastructure failure: " + text)
				}
				verdicts[i][number] = 2
			}
		}
	})
	families := []FamilyCount{}
	index := map[string]int{}
	for _, name := range strings.Split(OPERATOR_ORDER, ",") {
		index[name] = len(families)
		families = append(families, FamilyCount{Operator: name})
	}
	contexts := make([]ContextCount, len(loaded))
	for i := range contexts {
		contexts[i] = ContextCount{Context: i, PristineValid: true}
	}
	invalid := []map[string]any{}
	valid := []Row{}
	for number, row := range rows {
		families[index[row.Operator]].Candidates++
		rejected := []int{}
		for i := range loaded {
			switch verdicts[i][number] {
			case 1:
				contexts[i].Candidates++
				contexts[i].Eligible++
			case 2:
				contexts[i].Candidates++
				contexts[i].Invalid++
				rejected = append(rejected, i)
			}
		}
		if len(rejected) > 0 {
			families[index[row.Operator]].Invalid++
			invalid = append(invalid, map[string]any{"descriptor": row, "rejected_contexts": rejected})
		} else {
			families[index[row.Operator]].Eligible++
			valid = append(valid, row)
		}
	}
	for i := range families {
		if families[i].Eligible == 0 {
			reason := "no compile-valid eligible candidate"
			families[i].EmptyReason = &reason
		}
	}
	writeJSON(filepath.Join(outdir, "validity.json"), map[string]any{"operators": families, "contexts": contexts, "invalid": invalid})
	return valid, len(invalid)
}

func contextAuthority(loaded []Loaded) []map[string]any {
	rows := []map[string]any{}
	seen := map[string]bool{}
	for _, context := range loaded {
		paths := []string{}
		for p := range context.Files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		row := map[string]any{"package_dir": context.Context.PackageDir, "go_build_tags": context.Context.Tags, "production_files": paths}
		key := context.Context.PackageDir + "\x00" + strings.Join(context.Context.Tags, "\x00") + "\x01" + strings.Join(paths, "\x00")
		if !seen[key] {
			seen[key] = true
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a["package_dir"] != b["package_dir"] {
			return a["package_dir"].(string) < b["package_dir"].(string)
		}
		at, bt := strings.Join(a["go_build_tags"].([]string), "\x00"), strings.Join(b["go_build_tags"].([]string), "\x00")
		if at != bt {
			return at < bt
		}
		return strings.Join(a["production_files"].([]string), "\x00") < strings.Join(b["production_files"].([]string), "\x00")
	})
	return rows
}

type FileMetadata struct {
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

func metadata(info os.FileInfo) FileMetadata {
	details, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic("missing Linux file metadata")
	}
	return FileMetadata{details.Mode, details.Uid, details.Gid}
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintln(os.Stderr, "REFUSED:", err)
			os.Exit(1)
		}
	}()
	root := flag.String("root", "", "original source root")
	contexts := flag.String("build-contexts", "", "coordinator-owned exact context request")
	out := flag.String("out", "", "output path")
	profile := flag.String("operator-profile", "v2", "approved operator profile")
	apply := flag.String("apply-file", "", "re-enumerate and apply one original file")
	line := flag.Int("start-line", 0, "physical byte line")
	column := flag.Int("start-col", 0, "physical byte column")
	operator := flag.String("operator", "", "operator family")
	original := flag.String("original", "", "exact original span")
	mutated := flag.String("mutated", "", "replacement")
	workers := flag.Int("compile-workers", 1, "concurrent disposable compilation views (1..32)")
	record := flag.Bool("record-enumerator-rev", false, "record exact producer revision")
	flag.Parse()
	if *workers < 1 || *workers > 32 {
		panic("compile-workers must be between 1 and 32")
	}
	if flag.NArg() != 0 || *profile != "v2" || !filepath.IsAbs(*root) || *contexts == "" || *out == "" || runtime.Version() != "go1.25.0" || runtime.GOOS != "linux" {
		panic("explicit original root, context request, output and qualified v2 Go1.25/Linux required")
	}
	var req Request
	raw, err := os.ReadFile(*contexts)
	must(err)
	must(json.Unmarshal(raw, &req))
	if len(req.Contexts) == 0 || len(req.SourceFiles) == 0 {
		panic("missing original source/context authority")
	}
	for _, path := range []string{"go.mod", "go.sum"} {
		if expected, ok := req.SourceFiles[path]; ok {
			raw, err := os.ReadFile(filepath.Join(*root, path))
			must(err)
			if digest(raw) != expected {
				panic("module authority changed")
			}
		}
	}
	destination, err := filepath.Abs(*out)
	must(err)
	if *apply == "" {
		if rel, err := filepath.Rel(*root, destination); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			panic("enumeration output must be outside original source")
		}
		for i, c := range req.Contexts {
			rel, err := filepath.Rel(*root, c.Root)
			must(err)
			if rel == "." || !strings.HasPrefix(rel, "../") {
				panic("enumeration needs disposable contexts outside original source")
			}
			code, text := compile(c, filepath.Join(filepath.Dir(destination), fmt.Sprintf("pristine-%d.test", i)), filepath.Join(filepath.Dir(destination), fmt.Sprintf("pristine-%d", i)))
			if code != 0 {
				panic("pristine compilation failed; census cannot continue: " + text)
			}
		}
	}
	loaded := []Loaded{}
	for _, c := range req.Contexts {
		loaded = append(loaded, load(*root, req, c))
	}
	rows := candidates(loaded, *apply)
	if *apply != "" {
		if !canonicalPath(*apply) || !production(*apply) {
			panic("applier target outside original production")
		}
		target := filepath.Join(*root, *apply)
		destination := *out
		if !filepath.IsAbs(destination) {
			destination = filepath.Join(*root, destination)
		}
		if filepath.Clean(destination) != target {
			panic("applier may write only its selected target")
		}
		var chosen *Row
		for i, row := range rows {
			if row.File == *apply && row.Operator == *operator && row.StartLine == *line && row.StartCol == *column && row.Original == *original && row.Mutated == *mutated {
				if chosen != nil {
					panic("ambiguous applier descriptor")
				}
				chosen = &rows[i]
			}
		}
		if chosen == nil {
			panic("descriptor is absent under supplied original build contexts")
		}
		before, err := os.Lstat(target)
		must(err)
		if !before.Mode().IsRegular() {
			panic("applier target is not regular")
		}
		raw, err := os.ReadFile(target)
		must(err)
		if digest(raw) != req.SourceFiles[*apply] {
			panic("applier original file differs from authority")
		}
		changed := splice(raw, *chosen)
		fd, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0)
		must(err)
		_, writeErr := fd.Write(changed)
		closeErr := fd.Close()
		must(writeErr)
		must(closeErr)
		after, err := os.Lstat(target)
		must(err)
		if !os.SameFile(before, after) || metadata(before) != metadata(after) {
			panic("applier changed file identity or mode")
		}
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"file": *apply, "applied": true, "original_sha256": digest(raw), "mutated_sha256": digest(changed), "metadata": metadata(after)}))
		return
	}
	authorities := []map[string]any{}
	diagnosticFiles := map[string]bool{}
	union := map[string]bool{}
	for _, context := range loaded {
		for p := range context.DiagnosticFiles {
			diagnosticFiles[p] = true
		}
		paths := []string{}
		for p := range context.Files {
			paths = append(paths, p)
			union[p] = true
		}
		sort.Strings(paths)
		authorities = append(authorities, map[string]any{"package_dir": context.Context.PackageDir, "go_build_tags": context.Context.Tags, "production_files": paths})
	}
	aliases := []string{}
	for p := range diagnosticFiles {
		aliases = append(aliases, p)
	}
	sort.Strings(aliases)
	report := map[string]any{"schema": "r2t.go-mutation-candidates/1", "engine": ENGINE, "engine_version": ENGINE_VERSION, "parser": "go version " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, "files": len(union), "candidates": rows, "diagnostic_files": aliases, "contexts": authorities, "operators": strings.Split(OPERATOR_ORDER, ",")}
	if *record {
		report["enumerator_rev"] = ENUMERATOR_REV
	}
	writeJSON(filepath.Join(filepath.Dir(destination), "typed-candidates.json"), report)
	valid, invalid := validateCandidates(loaded, rows, filepath.Dir(destination), *workers)
	envelope := map[string]any{"engine": ENGINE, "engine_version": ENGINE_VERSION, "parser": report["parser"], "files": len(union), "errors": map[string]string{}, "mutants": valid, "go_build_contexts": contextAuthority(loaded)}
	if *record {
		envelope["enumerator_rev"] = ENUMERATOR_REV
	}
	if invalid > 0 {
		envelope["n_invalid"] = invalid
	}
	writeJSON(destination, envelope)
}
