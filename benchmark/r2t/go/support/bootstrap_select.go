// Native Godog feature selection only; no subject package or initializer runs.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"testing/fstest"

	"github.com/cucumber/godog"
)

type Suite struct {
	GluePath    string `json:"glue_path"`
	TestName    string `json:"test_name"`
	FeaturePath string `json:"feature_path"`
	Tags        string `json:"godog_tags"`
}
type Request struct {
	Features map[string]string `json:"features"`
	Suites   []Suite           `json:"suites"`
}
type Pickle struct {
	HeaderLine int64    `json:"header_line"`
	RowLine    int64    `json:"row_line"`
	ASTNodeIDs []string `json:"ast_node_ids"`
	Tags       []string `json:"tags"`
	StepLines  []int64  `json:"step_lines"`
}
type Selection struct {
	Suite         Suite    `json:"suite"`
	FeatureSHA256 string   `json:"feature_sha256"`
	Document      any      `json:"document"`
	Pickles       []Pickle `json:"pickles"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if runtime.Version() != "go1.25.0" {
		panic("bootstrap selection requires Go 1.25.0")
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		panic("missing native build identity")
	}
	version := ""
	for _, dep := range build.Deps {
		if dep.Path == "github.com/cucumber/godog" && dep.Replace == nil {
			version = dep.Version
		}
	}
	if version != "v0.15.1" {
		panic("bootstrap selection requires unreplaced Godog v0.15.1")
	}
	var request Request
	must(json.NewDecoder(os.Stdin).Decode(&request))
	files := fstest.MapFS{}
	for path, raw := range request.Features {
		files[path] = &fstest.MapFile{Data: []byte(raw), Mode: 0444}
	}
	selections := []Selection{}
	for _, suite := range request.Suites {
		raw, ok := request.Features[suite.FeaturePath]
		if !ok {
			panic("missing original feature")
		}
		selected := Selection{Suite: suite, FeatureSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(raw))), Pickles: []Pickle{}}
		// RetrieveFeatures calls Godog's parser, Gherkin pickle compiler and
		// ApplyTagFilter. It does not invoke TestSuite.Run or any initializer.
		features, err := (godog.TestSuite{Options: &godog.Options{
			FS: files, Paths: []string{suite.FeaturePath}, Tags: suite.Tags,
		}}).RetrieveFeatures()
		must(err)
		if len(features) > 1 {
			panic("one original feature produced multiple documents")
		}
		for _, feature := range features {
			if feature.Uri != suite.FeaturePath {
				panic("native feature path differs")
			}
			selected.Document = feature.GherkinDocument
			for _, pickle := range feature.Pickles {
				if len(pickle.AstNodeIds) < 1 || len(pickle.AstNodeIds) > 2 {
					panic("unexpected native pickle IDs")
				}
				scenario := feature.FindScenario(pickle.AstNodeIds[0])
				if scenario == nil {
					panic("missing native scenario join")
				}
				row := Pickle{HeaderLine: scenario.Location.Line, RowLine: scenario.Location.Line,
					ASTNodeIDs: pickle.AstNodeIds, Tags: []string{}, StepLines: []int64{}}
				if len(pickle.AstNodeIds) == 2 {
					_, example := feature.FindExample(pickle.AstNodeIds[1])
					if example == nil {
						panic("missing native Examples row join")
					}
					row.RowLine = example.Location.Line
				}
				for _, tag := range pickle.Tags {
					row.Tags = append(row.Tags, tag.Name)
				}
				for _, step := range pickle.Steps {
					if len(step.AstNodeIds) < 1 {
						panic("missing native step ID")
					}
					original := feature.FindStep(step.AstNodeIds[0])
					if original == nil {
						panic("missing native step join")
					}
					row.StepLines = append(row.StepLines, original.Location.Line)
				}
				selected.Pickles = append(selected.Pickles, row)
			}
		}
		selections = append(selections, selected)
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "r2t.go-bootstrap-selection/1",
		"toolchain": runtime.Version(), "godog_version": version, "selections": selections}))
}
