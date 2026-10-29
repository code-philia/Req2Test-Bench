package r2tinterfacesprobe

type Hidden struct{}
type Store struct { NeverRead Hidden }
type Param struct{}
type Result struct{}
type Untouched struct{}
type FactoryType struct{}
type localType struct{}
type Alias = Store
type Box[T any] struct { Value T }
type Constraint interface { marker() }
func (*Store) Save() {}
func (*FactoryType) Save() {}
func Factory() *FactoryType { panic("factory must never execute") }
var initialized = func() bool { panic("production initialization must never execute") }()
