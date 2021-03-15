package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"

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

// String encodes a PublicKey to a custom format.
//
// TODO(dadrian): Is this even a good format?
func (p *PublicKey) String() string {
	b64 := base64.StdEncoding.EncodeToString(p[:])
	return fmt.Sprintf("hop-dh-v1-%s", b64)
}

// String encodes a PrivateKey to PEM.
func (k *PrivateKey) String() string {
	block := pem.Block{
		Type:  "HOP PROTOCOL DH PRIVATE KEY V1",
		Bytes: k[:],
	}
	return string(pem.EncodeToMemory(&block))
}
