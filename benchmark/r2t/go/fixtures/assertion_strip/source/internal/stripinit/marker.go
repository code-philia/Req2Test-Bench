package sideeffect

import "fmt"

func init() { fmt.Println("PRESERVED imported package init") }
func AssertionMarker() { fmt.Println("REMOVED imported assertion") }
