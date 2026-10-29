package stripfixture

import (
 "errors"
 "fmt"
 "github.com/cucumber/godog"
 "github.com/EvilFreelancer/coddy-agent/internal/stripinit"
)

type assertionState struct { value int }
func (s *assertionState) Assert() error {
 if s.value != 43 { return fmt.Errorf("assertion value differs: %d", s.value) }
 fmt.Println("REMOVED method assertion")
 return nil
}
func registerLiteral(sc *godog.ScenarioContext) {
 sc.Then(`^a deliberately false literal assertion$`, func() error {
  fmt.Println("REMOVED literal assertion")
  sideeffect.AssertionMarker()
  return errors.New("EXPECTED false assertion")
 })
}
