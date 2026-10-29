package stripfixture

import "fmt"

type setupState struct { value int }
func (s *setupState) Assert() error {
 s.value = 42
 fmt.Println("PRESERVED given", s.value)
 return nil
}
func originalHelper(value int) int {
 fmt.Println("PRESERVED original helper", value)
 return value + 1
}
// Keep this unselected assertion body intact.
func unselectedAssertion() error { return fmt.Errorf("UNSELECTED assertion stays") }
