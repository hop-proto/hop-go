// Package must contains functions from the stdlib that panic on error instead
// of returning the error.
package must

import (
	"crypto/rand"

	"hop.computer/hop/pkg"
)

// ReadRandom reads cryptographically-secure random into b. It panics on
// failure.
func ReadRandom(b []byte) {
	_, err := rand.Read(b)
	if err != nil {
		pkg.Panicf("unable to read from random: %s", err.Error())
	}
}

// Do takes any value and error pair, and panics if the error is non-nil. Use it
// wrapping another function call that returns two values, to get a single
// statement that only returns one value.
//
// Example:
//
//	f := must.Do(os.Open("somefile.txt"))
//	defer f.Close()
func Do[T any](v T, err error) T {
	if err != nil {
		pkg.Panicf("expected nil-error, got %s", err)
	}
	return v
}
