package fixture

import (
	"context"
	"fmt"
	"github.com/cucumber/godog"
	"testing"
)

func TestHarnessFixture(t *testing.T) {
	fmt.Println("PROBE_WRAPPER_SETUP")
	defer fmt.Println("PROBE_WRAPPER_DEFER")
	t.Cleanup(func() { fmt.Println("PROBE_WRAPPER_T_CLEANUP") })
	init := func(sc *godog.ScenarioContext) {
		value := 0
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			fmt.Println("PROBE_SUBJECT_BEFORE_HOOK")
			return ctx, nil
		})
		sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
			fmt.Println("PROBE_SUBJECT_AFTER_HOOK")
			return ctx, nil
		})
//line fake_registration.go:700
		sc.Step(`^a retained background helper$`, func() error {
			fmt.Println("PROBE_REAL_STEP_HANDLER")
			if retainedHelper() != 42 {
				return fmt.Errorf("retained helper differs")
			}
			return nil
		})
		sc.Step(`^the probe value is (\d+)$`, func(v int) error { value = v; t.Log("PROBE_CAPTURED_T", v); return nil })
		sc.Step(`^the probe table:$`, func(table *godog.Table) error {
			if table.Rows[1].Cells[1].Value != "42" {
				return fmt.Errorf("table differs")
			}
			return nil
		})
		sc.Step(`^the probe docstring:$`, func(doc *godog.DocString) error {
			if doc.Content != "alpha\nbeta" {
				return fmt.Errorf("docstring differs")
			}
			return nil
		})
		sc.Step(`^the probe value equals (\d+)$`, func(v int) error {
			if value != v {
				return fmt.Errorf("value differs")
			}
			return nil
		})
	}
	opts := &godog.Options{Paths: []string{"features/incorrect.feature"}, Tags: "@wrong", Concurrency: 7, Format: "pretty"}
	suite := godog.TestSuite{Name: "original-shape", ScenarioInitializer: init, Options: opts}
	opts.Tags = "@mutated_before_run"
	if suite.Run() != 0 {
		t.Fatal("fixture suite failed")
	}
}
func TestForeignSuiteSentinel(t *testing.T) { t.Fatal("PROBE_FOREIGN_SUITE_MUST_NOT_RUN") }
