package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/sirupsen/logrus"
)

// SigningPublicKey is an Ed25519 public key used for signature verification. It is present in intermediate and root certificates.
type SigningPublicKey [32]byte

// SigningPrivateKey is an Ed25519 private key used for signing. It corresponds to a public key stored in an intermediate or root certificate.
type SigningPrivateKey [32]byte

// SigningKeyPair is an Ed25519 key pair.
//
// TODO(dadrian): Should this just use the crypto.Ed25519 types directly?
type SigningKeyPair struct {
	Public  SigningPublicKey
	Private SigningPrivateKey
}

// GenerateNewSigningKeyPair allocates a new SigningKeyPair and calls Generate.
func GenerateNewSigningKeyPair() *SigningKeyPair {
	out := new(SigningKeyPair)
	out.Generate()
	return out
}

// Generate populates e with a randomly generated Ed25519 key.
func (e *SigningKeyPair) Generate() {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logrus.Panicf("unable to generate Ed25519 signing key: %s", err)
	}
	n := copy(e.Private[:], private.Seed())
	if n != 32 {
		logrus.Panicf("unable to store Ed25519 public key: only got %d bytes, expected 32", n)
	}
	n = copy(e.Public[:], public)
	if n != 32 {
		logrus.Panicf("unable to store Ed25519 public key: only got %d bytes, expected 32", n)
	}
}

// PublicFromPrivate populates e.Public based on e.Private.
func (e *SigningKeyPair) PublicFromPrivate() {
	k := ed25519.NewKeyFromSeed(e.Private[:])
	pk := k.Public().(ed25519.PublicKey)
	n := copy(e.Public[:], pk)
	if n != 32 {
		logrus.Panicf("unable to calculate Ed25519 public key: only got %d bytes, expected 32", n)
	}
}

// String encodes a SigningPublicKey to a custom format.
func (p *SigningPublicKey) String() string {
	b64 := base64.StdEncoding.EncodeToString(p[:])
	return fmt.Sprintf("hop-sign-%s", b64)
}

// String encodes a SigningPrivateKey to PEM.
func (k *SigningPrivateKey) String() string {
	block := pem.Block{
		Type: "HOP PROTOCOL SIGNING PRIVATE KEY V1",
		Bytes: k[:],
	}
	return string(pem.EncodeToMemory(&block))
}