package keys

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

type PublicKey [32]byte
type PrivateKey [32]byte

// X25519KeyPair contains a Public and Private X25519 key.
type X25519KeyPair struct {
	Public  PublicKey
	Private PrivateKey
}

// Generate overwrites x with a randomly generated new key pair.
func (x *X25519KeyPair) Generate() {
	n, err := rand.Read(x.Private[:])
	if n != curve25519.PointSize || err != nil {
		panic("unable to read random bytes")
	}
	curve25519.ScalarBaseMult((*[32]byte)(&x.Public), (*[32]byte)(&x.Private))
}

// PublicFromPrivate recalculates the Public key based on the current Private
// key.
func (x *X25519KeyPair) PublicFromPrivate() {
	curve25519.ScalarBaseMult((*[32]byte)(&x.Public), (*[32]byte)(&x.Private))
}

// GenerateNewX25519KeyPair allocates a new X25519KeyPair and calls generate.
func GenerateNewX25519KeyPair() *X25519KeyPair {
	x := new(X25519KeyPair)
	x.Generate()
	return x
}

// DH performs Diffie-Hellman key exchange with the provided Public key.
func (x *X25519KeyPair) DH(other []byte) ([]byte, error) {
	// TODO(dadrian): Do a variant that's operable with a preallocated array
	return curve25519.X25519(x.Private[:], other)
}
