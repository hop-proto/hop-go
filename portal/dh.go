package portal

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

type PublicDH struct {
	Ephemeral []byte
	Static    []byte
}

type DHGenerator interface {
	GenerateKeypair() (string, error)
	GetPublicKey(string) []byte
}

type X25519KeyPair struct {
	public  [32]byte
	private [32]byte
}

func (x *X25519KeyPair) Generate() {
	n, err := rand.Read(x.private[:])
	if n != curve25519.PointSize || err != nil {
		panic("unable to read random bytes")
	}
	curve25519.ScalarBaseMult(&x.public, &x.private)
}

func GenerateNewX25519Keypair() *X25519KeyPair {
	x := new(X25519KeyPair)
	x.Generate()
	return x
}

type RandomInMemoryKeyGenerator struct {
	keys map[string]*X25519KeyPair
}
