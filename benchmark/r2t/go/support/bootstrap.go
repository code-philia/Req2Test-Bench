// Source-only primary suite context discovery; never imports the subject.
package main

import (
	"encoding/json"
	"go/ast"
	"go/build"
	"go/build/constraint"
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
	Root  string   `json:"root"`
	Files []string `json:"files"`
}
type Span struct {
	File  string `json:"file"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Line  int    `json:"line"`
	Text  string `json:"text"`
}
type Origin struct {
	Kind string `json:"kind"`
	Line int    `json:"line"`
}
type Suite struct {
	Glue       string          `json:"glue_path"`
	Dir        string          `json:"package_dir"`
	Package    string          `json:"package_name"`
	Test       string          `json:"test_name"`
	Line       int             `json:"suite_line"`
	Expression string          `json:"go_build_expression"`
	BuildTags  []string        `json:"go_build_tags"`
	Feature    string          `json:"feature_path"`
	Tags       string          `json:"godog_tags"`
	Origin     Origin          `json:"godog_tags_origin"`
	Proof      map[string]Span `json:"source"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func need(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func imported(expr ast.Expr, imports map[string]string, pkg, name string) bool {
	s, ok := expr.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Obj == nil && imports[id.Name] == pkg
}
func importsOf(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, i := range f.Imports {
		p, e := strconv.Unquote(i.Path.Value)
		must(e)
		n := filepath.Base(p)
		if i.Name != nil {
			n = i.Name.Name
		}
		out[n] = p
	}
	return out
}
func fields(lit *ast.CompositeLit) map[string]*ast.KeyValueExpr {
	out := map[string]*ast.KeyValueExpr{}
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		need(ok, "unkeyed suite/options literal")
		k, ok := kv.Key.(*ast.Ident)
		need(ok, "nonidentifier option key")
		need(out[k.Name] == nil, "duplicate option")
		out[k.Name] = kv
	}
	return out
}
func text(expr ast.Expr) string {
	s, ok := expr.(*ast.BasicLit)
	need(ok && s.Kind == token.STRING, "nonliteral source string")
	v, e := strconv.Unquote(s.Value)
	must(e)
	return v
}
func unwrap(e ast.Expr) ast.Expr {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		return u.X
	}
	return e
}
func resolve(e ast.Expr) ast.Expr {
	e = unwrap(e)
	id, ok := e.(*ast.Ident)
	if !ok {
		return e
	}
	need(id.Obj != nil, "unresolved options variable")
	switch n := id.Obj.Decl.(type) {
	case *ast.AssignStmt:
		need(len(n.Lhs) == 1 && len(n.Rhs) == 1 && n.Tok == token.DEFINE, "unsupported options assignment")
		return unwrap(n.Rhs[0])
	case *ast.ValueSpec:
		need(len(n.Names) == 1 && len(n.Values) == 1, "unsupported options variable")
		return unwrap(n.Values[0])
	}
	panic("unsupported options owner")
}
func main() {
	need(runtime.Version() == "go1.25.0", "bootstrap AST requires Go 1.25.0")
	var in Input
	must(json.NewDecoder(os.Stdin).Decode(&in))
	fs := token.NewFileSet()
	source := map[string][]byte{}
	span := func(rel string, n ast.Node) Span {
		p := fs.PositionFor(n.Pos(), false)
		q := fs.PositionFor(n.End(), false)
		return Span{rel, p.Offset, q.Offset, p.Line, string(source[rel][p.Offset:q.Offset])}
	}
	suites := []Suite{}
	inactive := []string{}
	for _, rel := range in.Files {
		full := filepath.Join(in.Root, filepath.FromSlash(rel))
		raw, e := os.ReadFile(full)
		must(e)
		source[rel] = raw
		f, e := parser.ParseFile(fs, full, raw, parser.ParseComments|parser.AllErrors)
		must(e)
		im := importsOf(f)
		expr := ""
		for _, g := range f.Comments {
			for _, c := range g.List {
				if strings.HasPrefix(c.Text, "//go:build ") {
					need(expr == "", "multiple go:build directives")
					v, e := constraint.Parse(c.Text)
					must(e)
					expr = v.String()
				}
			}
		}
		var tags []string
		for _, try := range [][]string{{}, {"http"}, {"cli"}} {
			bc := build.Default
			bc.GOOS = "linux"
			bc.GOARCH = "amd64"
			bc.BuildTags = try
			active, e := bc.MatchFile(filepath.Dir(full), filepath.Base(full))
			must(e)
			if active {
				if tags == nil {
					tags = append([]string{}, try...)
				} else if len(tags) > 0 {
					panic("ambiguous explicit build context")
				}
			}
		}
		if tags == nil {
			inactive = append(inactive, rel)
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
				continue
			}
			var literals []*ast.CompositeLit
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				if lit, ok := n.(*ast.CompositeLit); ok && imported(lit.Type, im, "github.com/cucumber/godog", "TestSuite") {
					literals = append(literals, lit)
				}
				return true
			})
			if len(literals) == 0 {
				continue
			}
			need(len(literals) == 1, "multiple original suites in wrapper")
			need(fn.Type.Params != nil && len(fn.Type.Params.List) == 1 && len(fn.Type.Params.List[0].Names) == 1, "unsupported test parameters")
			param, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
			need(ok && imported(param.X, im, "testing", "T"), "wrapper does not take testing.T")
			lit := literals[0]
			sf := fields(lit)
			need(sf["Options"] != nil, "suite lacks explicit options")
			optionExpr := sf["Options"].Value
			options, ok := resolve(optionExpr).(*ast.CompositeLit)
			need(ok && imported(options.Type, im, "github.com/cucumber/godog", "Options"), "options do not name imported godog.Options")
			of := fields(options)
			need(of["Paths"] != nil, "missing original feature paths")
			paths, ok := of["Paths"].Value.(*ast.CompositeLit)
			need(ok && len(paths.Elts) == 1, "requires exactly one literal feature path")
			arr, ok := paths.Type.(*ast.ArrayType)
			need(ok && arr.Len == nil, "feature paths are not a string slice")
			elem, ok := arr.Elt.(*ast.Ident)
			need(ok && elem.Name == "string", "feature paths are not strings")
			feature := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(rel), text(paths.Elts[0]))))
			need(strings.HasPrefix(feature, "features/") && strings.HasSuffix(feature, ".feature"), "feature path outside original features")
			s := Suite{Glue: rel, Dir: filepath.ToSlash(filepath.Dir(rel)), Package: f.Name.Name, Test: fn.Name.Name, Line: fs.PositionFor(lit.Pos(), false).Line,
				Expression: expr, BuildTags: tags, Feature: feature, Origin: Origin{"default", fs.PositionFor(options.Pos(), false).Line}, Proof: map[string]Span{
					"test": span(rel, fn), "suite": span(rel, lit), "options": span(rel, options), "path": span(rel, paths.Elts[0])}}
			if of["Tags"] != nil {
				s.Tags = text(of["Tags"].Value)
				s.Origin = Origin{"literal", fs.PositionFor(of["Tags"].Pos(), false).Line}
				s.Proof["tags"] = span(rel, of["Tags"])
			}
			// The one existing Options variable has a source-defined Linux override.
			// Match that exact control-flow shape; never execute an environment probe.
			if id, variable := optionExpr.(*ast.Ident); variable {
				var overrides []*ast.IfStmt
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, ok := n.(*ast.FuncLit); ok {
						return false
					}
					a, ok := n.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, left := range a.Lhs {
						if sel, ok := left.(*ast.SelectorExpr); ok {
							if owner, ok := sel.X.(*ast.Ident); ok && owner.Obj == id.Obj {
								need(sel.Sel.Name == "Tags" && len(a.Lhs) == 1 && len(a.Rhs) == 1 && text(a.Rhs[0]) == "~@windows", "unsupported options mutation")
								var found *ast.IfStmt
								ast.Inspect(fn.Body, func(parent ast.Node) bool {
									if cond, ok := parent.(*ast.IfStmt); ok && cond.Pos() < a.Pos() && cond.End() > a.End() {
										found = cond
									}
									return true
								})
								need(found != nil, "unconditional options mutation")
								overrides = append(overrides, found)
							}
						}
					}
					return true
				})
				need(len(overrides) == 1 && rel == "internal/session/bdd_attachment_encoding_test.go" && fn.Name.Name == "TestPromptAttachmentEncodingFeature", "unqualified options variable shape")
				cond := overrides[0]
				not, ok := cond.Cond.(*ast.UnaryExpr)
				need(ok && not.Op == token.NOT && cond.Init == nil && cond.Else == nil && len(cond.Body.List) == 1, "unqualified Linux override condition")
				call, ok := not.X.(*ast.CallExpr)
				need(ok && len(call.Args) == 0, "unqualified ANSI predicate call")
				pred, ok := call.Fun.(*ast.Ident)
				need(ok && pred.Name == "systemANSIReadsCyrillic" && pred.Obj != nil, "unqualified ANSI predicate")
				predicate, ok := pred.Obj.Decl.(*ast.FuncDecl)
				need(ok && len(predicate.Body.List) == 2, "unqualified ANSI predicate body")
				assign, ok := predicate.Body.List[0].(*ast.AssignStmt)
				need(ok && len(assign.Lhs) == 3 && len(assign.Rhs) == 1, "unqualified ANSI result assignment")
				decode, ok := assign.Rhs[0].(*ast.CallExpr)
				need(ok && imported(decode.Fun, im, "github.com/EvilFreelancer/coddy-agent/internal/platform", "DecodeANSI"), "unqualified ANSI decoder")
				ret, ok := predicate.Body.List[1].(*ast.ReturnStmt)
				need(ok && len(ret.Results) == 1, "unqualified ANSI result")
				conjunction, ok := ret.Results[0].(*ast.BinaryExpr)
				need(ok && conjunction.Op == token.LAND, "ANSI result must require successful decode")
				success, ok := conjunction.X.(*ast.Ident)
				bound, ok2 := assign.Lhs[2].(*ast.Ident)
				need(ok && ok2 && success.Obj == bound.Obj, "ANSI result not bound to decoder success")
				platformRel := "internal/platform/output_other.go"
				platformPath := filepath.Join(in.Root, filepath.FromSlash(platformRel))
				platformRaw, e := os.ReadFile(platformPath)
				must(e)
				source[platformRel] = platformRaw
				platform, e := parser.ParseFile(fs, platformPath, platformRaw, parser.ParseComments|parser.AllErrors)
				must(e)
				bc := build.Default
				bc.GOOS = "linux"
				bc.GOARCH = "amd64"
				active, e := bc.MatchFile(filepath.Dir(platformPath), filepath.Base(platformPath))
				must(e)
				need(active, "Linux ANSI implementation inactive")
				var decoder *ast.FuncDecl
				for _, d := range platform.Decls {
					if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "DecodeANSI" {
						decoder = f
					}
				}
				need(decoder != nil && decoder.Body != nil && len(decoder.Body.List) == 1, "unqualified Linux ANSI implementation")
				result, ok := decoder.Body.List[0].(*ast.ReturnStmt)
				need(ok && len(result.Results) == 3, "unqualified Linux ANSI return")
				no, ok := result.Results[2].(*ast.Ident)
				need(ok && no.Name == "false", "Linux ANSI decode no longer always fails")
				assignment := cond.Body.List[0].(*ast.AssignStmt)
				s.Tags = "~@windows"
				s.Origin = Origin{"linux_ansi_override", fs.PositionFor(assignment.Pos(), false).Line}
				s.Proof["tags"] = span(rel, assignment)
				s.Proof["linux_condition"] = span(rel, cond)
				s.Proof["ansi_predicate"] = span(rel, predicate)
				s.Proof["linux_decoder"] = span(platformRel, decoder)
			}
			suites = append(suites, s)
		}
	}
	sort.Slice(suites, func(i, j int) bool {
		if suites[i].Glue != suites[j].Glue {
			return suites[i].Glue < suites[j].Glue
		}
		return suites[i].Line < suites[j].Line
	})
	sort.Strings(inactive)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "r2t.go-bootstrap-ast/1", "toolchain": runtime.Version(), "suites": suites, "inactive_files": inactive}))
}
