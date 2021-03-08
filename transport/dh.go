package transport

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// X25519KeyPair contains a public and private X25519 key.
type X25519KeyPair struct {
	public  [32]byte
	private [32]byte
}

// Generate overwrites x with a randomly generated new key pair.
func (x *X25519KeyPair) Generate() {
	n, err := rand.Read(x.private[:])
	if n != curve25519.PointSize || err != nil {
		panic("unable to read random bytes")
	}
	curve25519.ScalarBaseMult(&x.public, &x.private)
}

// PublicFromPrivate recalculates the public key based on the current Private
// key.
func (x *X25519KeyPair) PublicFromPrivate() {
	curve25519.ScalarBaseMult(&x.public, &x.private)
}

// GenerateNewX25519KeyPair allocates a new X25519KeyPair and calls generate.
func GenerateNewX25519KeyPair() *X25519KeyPair {
	x := new(X25519KeyPair)
	x.Generate()
	return x
}

// DH performs Diffie-Hellman key exchange with the provided public key.
func (x *X25519KeyPair) DH(other []byte) ([]byte, error) {
	// TODO(dadrian): Do a variant that's operable with a preallocated array
	return curve25519.X25519(x.private[:], other)
}
