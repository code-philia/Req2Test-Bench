package r2tbench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/formatters"
	messages "github.com/cucumber/messages/go/v21"
)

type r2tConfig struct {
	Paths    []string
	Tags     string
	Output   string
	TestName string
}
type r2tFormatter struct {
	*godog.BaseFmt
	enc    *json.Encoder
	starts map[string]time.Time
}

func (f *r2tFormatter) event(v any) {
	if err := f.enc.Encode(v); err != nil {
		panic(err)
	}
}
func (f *r2tFormatter) TestRunStarted() {
	f.BaseFmt.TestRunStarted()
	f.event(map[string]any{"event": "run_started"})
}
func (f *r2tFormatter) Feature(doc *messages.GherkinDocument, path string, raw []byte) {
	f.BaseFmt.Feature(doc, path, raw)
	f.event(map[string]any{"event": "feature", "path": path, "document": doc})
}
func (f *r2tFormatter) Pickle(p *messages.Pickle) {
	f.BaseFmt.Pickle(p)
	f.event(map[string]any{"event": "pickle", "pickle": p})
}
func (f *r2tFormatter) Defined(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition) {
	f.BaseFmt.Defined(p, s, d)
	f.starts[p.Id+"/"+s.Id] = time.Now()
	row := map[string]any{"event": "defined", "pickle_id": p.Id, "uri": p.Uri, "step": s, "matched": d != nil}
	if d != nil {
		matched := f.Storage.MustGetStepDefintionMatch(s.AstNodeIds[0])
		row["registration_file"] = matched.File
		row["registration_line"] = matched.Line
		row["native_arguments"] = matched.Args
		row["expression"] = d.Expr.String()
		row["handler_type"] = reflect.TypeOf(d.Handler).String()
		row["keyword"] = d.Keyword
	}
	f.event(row)
}
func (f *r2tFormatter) Passed(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition) {
	f.BaseFmt.Passed(p, s, d)
	row := map[string]any{"event": "status", "status": "passed", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	f.event(row)
}
func (f *r2tFormatter) Failed(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition, err error) {
	f.BaseFmt.Failed(p, s, d, err)
	row := map[string]any{"event": "status", "status": "failed", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	row["error"] = err.Error()
	f.event(row)
}
func (f *r2tFormatter) Skipped(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition) {
	f.BaseFmt.Skipped(p, s, d)
	row := map[string]any{"event": "status", "status": "skipped", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	f.event(row)
}
func (f *r2tFormatter) Undefined(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition) {
	f.BaseFmt.Undefined(p, s, d)
	row := map[string]any{"event": "status", "status": "undefined", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	f.event(row)
}
func (f *r2tFormatter) Pending(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition) {
	f.BaseFmt.Pending(p, s, d)
	row := map[string]any{"event": "status", "status": "pending", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	f.event(row)
}
func (f *r2tFormatter) Ambiguous(p *messages.Pickle, s *messages.PickleStep, d *formatters.StepDefinition, err error) {
	f.BaseFmt.Ambiguous(p, s, d, err)
	row := map[string]any{"event": "status", "status": "ambiguous", "pickle_id": p.Id, "step_id": s.Id, "seconds": time.Since(f.starts[p.Id+"/"+s.Id]).Seconds()}
	row["error"] = err.Error()
	f.event(row)
}
func (f *r2tFormatter) Summary() { f.BaseFmt.Summary(); f.event(map[string]any{"event": "summary"}) }

// r2tSetStep receives the index of the executing step, or -1 between steps.
// The measurement build binds it to the recorder's SetStep; a run without the
// recorder keeps the no-op, because a build without measurement records no
// entries to attribute (r2t/go/measurement.py, runtime_helper).
var r2tSetStep = func(int) {}

// r2tAttributeSteps makes every direct-call entry name the step that made it
// (TARGET_INTERFACES_V2_SPEC.md section 4). The counter is the position of the
// step in the pickle godog is running -- the Background's steps first, then the
// scenario's own -- which is exactly the order the record's step list is built
// in, and godog runs the before-step hook for every step of the pickle,
// including the ones it skips after a failure.
//
// Registration order is the fix, not an accident: godog runs both step-hook
// lists forward in registration order, so the harness must bracket the
// candidate's hooks from the outside. The clearing after-step hook is
// registered before the candidate's initializer runs, so it clears the index
// first on the way out; the two setters are registered after it, so they set
// the index last on the way in. A production call made from a candidate hook
// on either side therefore sees no step and carries null, as does one made
// during glue construction.
func r2tAttributeSteps(s *godog.TestSuite) {
	original := s.ScenarioInitializer
	s.ScenarioInitializer = func(sc *godog.ScenarioContext) {
		index := 0
		// The incoming step error is godog's to carry; a hook returning it
		// again would append it to itself.
		sc.StepContext().After(func(ctx context.Context, _ *godog.Step, _ godog.StepResultStatus, _ error) (context.Context, error) {
			r2tSetStep(-1)
			return ctx, nil
		})
		if original != nil {
			original(sc)
		}
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			index = 0
			r2tSetStep(-1)
			return ctx, nil
		})
		sc.StepContext().Before(func(ctx context.Context, _ *godog.Step) (context.Context, error) {
			r2tSetStep(index)
			index++
			return ctx, nil
		})
	}
}
func r2tRun(s *godog.TestSuite, t *testing.T) int {
	var cfg r2tConfig
	raw, err := os.ReadFile("/r2t-go/run/work/_bench/go/context.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TestName != t.Name() {
		t.Fatal("context test differs")
	}
	if err = os.MkdirAll(filepath.Dir(cfg.Output), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	enc := json.NewEncoder(output)
	if s.Options == nil {
		t.Fatal("selected suite requires explicit Options")
	}
	if err = enc.Encode(map[string]any{"event": "interposed", "test": t.Name(), "original_options": map[string]any{"paths": s.Options.Paths, "tags": s.Options.Tags, "concurrency": s.Options.Concurrency, "strict": s.Options.Strict, "testing_t_present": s.Options.TestingT != nil}}); err != nil {
		t.Fatal(err)
	}
	formatters.Format("r2t-godog-native", "native Defined qualification", func(name string, w io.Writer) formatters.Formatter {
		return &r2tFormatter{godog.NewBaseFmt(name, io.Discard), enc, map[string]time.Time{}}
	})
	opts := godog.Options{}
	if s.Options != nil {
		opts = *s.Options
	}
	opts.Paths = append([]string(nil), cfg.Paths...)
	opts.FeatureContents = nil
	opts.FS = nil
	opts.Tags = cfg.Tags
	opts.Concurrency = 1
	opts.Randomize = 0
	opts.StopOnFailure = false
	opts.TestingT = t
	opts.Strict = true
	opts.ShowStepDefinitions = false
	opts.ShowHelp = false
	opts.Format = "r2t-godog-native"
	opts.Output = output
	s.Options = &opts
	r2tAttributeSteps(s)
	code := s.Run()
	if err = enc.Encode(map[string]any{"event": "exit", "code": code, "frozen_paths": opts.Paths, "frozen_tags": opts.Tags, "serial": opts.Concurrency, "testing_t": opts.TestingT == t}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("R2T_GODOG_EXIT", t.Name(), code)
	return code
}
