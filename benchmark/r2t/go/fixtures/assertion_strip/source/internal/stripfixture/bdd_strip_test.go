package stripfixture

import (
 "context"
 "fmt"
 "testing"
 "github.com/cucumber/godog"
)

func TestStripFixture(t *testing.T) {
 fmt.Println("PRESERVED wrapper setup")
 defer fmt.Println("PRESERVED wrapper defer")
 t.Cleanup(func() { fmt.Println("PRESERVED wrapper cleanup") })
 init := func(sc *godog.ScenarioContext) {
  setup, assertion := &setupState{}, &assertionState{}
  sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
   fmt.Println("PRESERVED before hook")
   return ctx, nil
  })
  sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
   fmt.Println("PRESERVED after hook")
   return ctx, nil
  })
  sc.Given(`^a preserved setup$`, setup.Assert)
  sc.When(`^a preserved action$`, func() error {
   assertion.value = originalHelper(setup.value)
   if assertion.value != 43 { return fmt.Errorf("action did not preserve helper result") }
   fmt.Println("PRESERVED action", assertion.value)
   return nil
  })
  sc.Then(`^a method assertion$`, assertion.Assert)
  registerLiteral(sc)
 }
 opts := &godog.Options{Paths: []string{"../../features/strip.feature"}, Tags: "", Format: "pretty"}
 suite := godog.TestSuite{Name: "strip-native", ScenarioInitializer: init, Options: opts}
 if suite.Run() != 0 { t.Fatal("native assertion failed") }
}
func TestUnselected(t *testing.T) { t.Fatal("FORBIDDEN unselected test") }
