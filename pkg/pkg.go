// Package pkg contains standalone utility functions that do not depend on
// anything except themselves.
package pkg

import (
	"fmt"
)

// Panicf functions like printf, but for constructing a string sent to panic. Do
// not use if you think that fmt.Sprintf would also panic, e.g. if you are
// already inside a panic handler.
func Panicf(msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	panic(s)
}
