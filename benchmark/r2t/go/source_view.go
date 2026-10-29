// Trusted Go syntax inventory. Parses supplied bytes; never loads subject packages.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Request struct {
	Path      string   `json:"path"`
	Raw       []byte   `json:"raw"`
	BuildTags []string `json:"build_tags"`
}
type Issue struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Node        string `json:"node"`
	Reason      string `json:"reason"`
	Declaration string `json:"declaration"`
}
type Body struct {
	ID               string `json:"declaration_id"`
	Kind             string `json:"kind"`
	Start            int    `json:"start_byte"`
	End              int    `json:"end_byte"`
	DeclarationStart int    `json:"declaration_start_byte"`
	DeclarationLine  int    `json:"declaration_line"`
}
type Result struct {
	Error       string   `json:"error,omitempty"`
	Package     string   `json:"package"`
	Bodies      []Body   `json:"bodies"`
	Issues      []Issue  `json:"issues"`
	Active      bool     `json:"active"`
	Toolchain   string   `json:"toolchain"`
	GOOS        string   `json:"goos"`
	GOARCH      string   `json:"goarch"`
	CGO         bool     `json:"cgo_enabled"`
	ReleaseTags []string `json:"release_tags"`
	ToolTags    []string `json:"tool_tags"`
}

func dotted(e ast.Expr) bool {
	switch n := e.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return dotted(n.X)
	}
	return false
}
func constant(e ast.Expr) bool {
	switch n := e.(type) {
	case *ast.BasicLit, *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return dotted(n)
	case *ast.ParenExpr:
		return constant(n.X)
	case *ast.UnaryExpr:
		return (n.Op == token.ADD || n.Op == token.SUB || n.Op == token.XOR || n.Op == token.NOT) && constant(n.X)
	case *ast.BinaryExpr:
		return constant(n.X) && constant(n.Y)
	}
	return false
}
func fields(f *ast.FieldList) bool {
	if f == nil {
		return true
	}
	for _, v := range f.List {
		if !typ(v.Type) {
			return false
		}
	}
	return true
}
func typ(e ast.Expr) bool {
	if e == nil {
		return true
	}
	switch n := e.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return dotted(n)
	case *ast.ParenExpr:
		return typ(n.X)
	case *ast.StarExpr:
		return typ(n.X)
	case *ast.ArrayType:
		return (n.Len == nil || constant(n.Len)) && typ(n.Elt)
	case *ast.MapType:
		return typ(n.Key) && typ(n.Value)
	case *ast.ChanType:
		return typ(n.Value)
	case *ast.Ellipsis:
		return typ(n.Elt)
	case *ast.FuncType:
		return constraints(n.TypeParams) && fields(n.Params) && fields(n.Results)
	case *ast.StructType:
		return fields(n.Fields)
	case *ast.InterfaceType:
		return constraints(n.Methods)
	case *ast.IndexExpr:
		return typ(n.X) && typ(n.Index)
	case *ast.IndexListExpr:
		if !typ(n.X) {
			return false
		}
		for _, e := range n.Indices {
			if !typ(e) {
				return false
			}
		}
		return true
	}
	return false
}
func variable(e ast.Expr) bool {
	switch n := e.(type) {
	case *ast.BasicLit, *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return dotted(n)
	case *ast.ParenExpr:
		return variable(n.X)
	case *ast.UnaryExpr:
		_, lit := n.X.(*ast.BasicLit)
		return lit && (n.Op == token.ADD || n.Op == token.SUB)
	case *ast.FuncLit:
		return typ(n.Type)
	}
	return false
}

func constraint(e ast.Expr) bool {
	switch n := e.(type) {
	case *ast.UnaryExpr:
		return n.Op == token.TILDE && typ(n.X)
	case *ast.BinaryExpr:
		return n.Op == token.OR && constraint(n.X) && constraint(n.Y)
	case *ast.ParenExpr:
		return constraint(n.X)
	default:
		return typ(e)
	}
}
func constraints(f *ast.FieldList) bool {
	if f == nil {
		return true
	}
	for _, field := range f.List {
		if !constraint(field.Type) {
			return false
		}
	}
	return true
}

func inspect(req Request) Result {
	ctx := build.Default
	ctx.BuildTags = append([]string{}, req.BuildTags...)
	result := Result{Bodies: []Body{}, Issues: []Issue{}, Toolchain: runtime.Version(),
		GOOS: ctx.GOOS, GOARCH: ctx.GOARCH, CGO: ctx.CgoEnabled,
		ReleaseTags: ctx.ReleaseTags, ToolTags: ctx.ToolTags}
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, req.Path, req.Raw, parser.ParseComments|parser.AllErrors|parser.SkipObjectResolution)
	if err != nil {
		messages := []string{}
		if errors, ok := err.(scanner.ErrorList); ok {
			for _, failure := range errors {
				offset := failure.Pos.Offset
				if offset < 0 || offset > len(req.Raw) {
					result.Error = "invalid parse-error offset"
					return result
				}
				line := 1 + bytes.Count(req.Raw[:offset], []byte("\n"))
				messages = append(messages, fmt.Sprintf("%s:%d: parse_error: %s", req.Path, line, failure.Msg))
			}
		} else {
			messages = append(messages, err.Error())
		}
		result.Error = strings.Join(messages, "; ")
		return result
	}
	result.Package = file.Name.Name
	// MatchFile receives exactly the supplied bytes, never a pathname's current contents.
	ctx.OpenFile = func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(req.Raw)), nil }
	result.Active, err = ctx.MatchFile("/source", filepath.Base(req.Path))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	physical := fs.File(file.Pos())
	issue := func(node ast.Node, reason, name string) {
		result.Issues = append(result.Issues, Issue{req.Path, fs.PositionFor(node.Pos(), false).Line,
			fmt.Sprintf("%T", node), reason, name})
	}
	ranges := [][2]token.Pos{}
	addBody := func(node ast.Node, block *ast.BlockStmt, id, kind string) {
		if block == nil {
			return
		}
		start, end := physical.Offset(block.Pos()), physical.Offset(block.End())
		if start < 0 || start >= end || end > len(req.Raw) || req.Raw[start] != '{' || req.Raw[end-1] != '}' {
			result.Error = "invalid physical body span"
			return
		}
		ranges = append(ranges, [2]token.Pos{block.Pos(), block.End()})
		result.Bodies = append(result.Bodies, Body{id, kind, start, end,
			physical.Offset(node.Pos()), fs.PositionFor(node.Pos(), false).Line})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncDecl:
			id, kind := result.Package+"#"+node.Name.Name, "function"
			if node.Recv != nil {
				if len(node.Recv.List) != 1 {
					result.Error = "unsupported receiver"
					return false
				}
				var receiver bytes.Buffer
				if err := format.Node(&receiver, fs, node.Recv.List[0].Type); err != nil {
					result.Error = err.Error()
					return false
				}
				name := strings.Map(func(r rune) rune {
					if unicode.IsSpace(r) {
						return -1
					}
					return r
				}, receiver.String())
				id, kind = result.Package+"#("+name+")."+node.Name.Name, "method"
			} else if node.Name.Name == "init" {
				id, kind = fmt.Sprintf("%s#init@%d", result.Package, physical.Offset(node.Pos())), "initializer"
			}
			addBody(node, node.Body, id, kind)
		case *ast.FuncLit:
			addBody(node, node.Body, fmt.Sprintf("%s#func_literal@%d", result.Package, physical.Offset(node.Pos())), "lambda")
		}
		return true
	})
	for _, group := range file.Comments {
		for _, comment := range group.List {
			inside := false
			for _, span := range ranges {
				if comment.Pos() >= span[0] && comment.End() <= span[1] {
					inside = true
					break
				}
			}
			words := strings.Fields(comment.Text)
			if !inside && strings.HasPrefix(comment.Text, "//go:") && (len(words) == 0 || words[0] != "//go:build") {
				issue(comment, "unreviewed_go_directive", comment.Text)
			}
		}
	}
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if !typ(declaration.Type) || !fields(declaration.Recv) {
				issue(declaration, "unsupported_signature", declaration.Name.Name)
			}
			if declaration.Body == nil {
				issue(declaration, "bodyless_function", declaration.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.ImportSpec:
					path, _ := strconv.Unquote(spec.Path.Value)
					if path == "C" {
						issue(spec, "cgo_import", "C")
					}
				case *ast.TypeSpec:
					if !typ(spec.Type) || !constraints(spec.TypeParams) {
						issue(spec, "unsupported_type", spec.Name.Name)
					}
				case *ast.ValueSpec:
					names := []string{}
					for _, name := range spec.Names {
						names = append(names, name.Name)
					}
					name := strings.Join(names, ",")
					if !typ(spec.Type) {
						issue(spec, "unsupported_type", name)
					}
					for _, value := range spec.Values {
						allowed := false
						switch declaration.Tok {
						case token.CONST:
							allowed = constant(value)
						case token.VAR:
							allowed = variable(value)
						}
						if !allowed {
							reason := "computed_var_initializer"
							if declaration.Tok == token.CONST {
								reason = "unsupported_const_expression"
							} else if _, ok := value.(*ast.CompositeLit); ok {
								reason = "compound_var_initializer"
							}
							issue(value, reason, name)
						}
					}
				default:
					issue(spec, "unknown_spec", "")
				}
			}
		default:
			issue(declaration, "unknown_declaration", "")
		}
	}
	sort.SliceStable(result.Issues, func(i, j int) bool { return result.Issues[i].Line < result.Issues[j].Line })
	return result
}

func main() {
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	for {
		var req Request
		if err := decoder.Decode(&req); err == io.EOF {
			return
		} else if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := encoder.Encode(inspect(req)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
