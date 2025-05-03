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
