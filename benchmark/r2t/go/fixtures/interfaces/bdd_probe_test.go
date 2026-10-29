package r2tinterfacesprobe

import "testing"

type state struct { selected *Store; unused Untouched }
func (s *state) Fields() { s.selected.Save() }
func FactoryOnly() { Factory().Save() }
func InferredReceiver() { value := Factory(); value.Save() }
func Explicit(p *Param) ([]Result, error) {
 var _ Alias
 var _ Box[Param]
 var _ *localType
 _ = (*Store).Save
 _ = func(value map[Alias][]*Param) *Result { return nil }
 var value any
 _ = value.(*Store)
 switch value.(type) { case Box[Result]: }
 return nil, nil
}
func AliasOnly() { var _ Alias }
func Generic[T Constraint](value *Box[T]) *Box[T] { return value }
func FirstHelper() { SecondHelper() }
func SecondHelper() { var _ Param; FirstHelper(); RetainedHelper() }
func Captured(s *state) func() { return func() { s.selected.Save() } }
func TestNeverRun(t *testing.T) { panic("subject tests must never execute") }
func Dynamic() { indirect := FirstHelper; indirect() }
type inner struct{}
func (*inner) Promoted() { var _ Param }
type outer struct { *inner }
func (s *outer) ViaPromotion() { s.Promoted() }
