package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// SigningPublicKey is an Ed25519 public key used for signature verification. It is present in intermediate and root certificates.
type SigningPublicKey [32]byte

// SigningPrivateKey is an Ed25519 private key used for signing. It corresponds to a public key stored in an intermediate or root certificate.
type SigningPrivateKey [32]byte

// SigningKeyPair is an Ed25519 key pair. In Hop, a SigningKeyPair is used to
// sign data in certificates.
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

// VerifySignature verifies the signature corresponds to the data, using the provided public key.
func VerifySignature(publicKey *SigningPublicKey, data []byte, signature *[64]byte) bool {
	internal := ed25519.PublicKey(publicKey[:])
	return ed25519.Verify(internal, data, signature[:])
}

// SigningPublicKeyPrefix is the prefix used in public key files for signing keys.
const SigningPublicKeyPrefix = "hop-sign-v1-"

// String encodes a SigningPublicKey to a custom format.
func (p *SigningPublicKey) String() string {
	b64 := base64.StdEncoding.EncodeToString(p[:])
	return fmt.Sprintf("%s%s", SigningPublicKeyPrefix, b64)
}

// PEMTypeSigningPrivate is the PEM header for private keys used for signing.
const PEMTypeSigningPrivate = "HOP PROTOCOL SIGNING PRIVATE KEY V1"

// String encodes a SigningPrivateKey to PEM.
func (k *SigningPrivateKey) String() string {
	block := pem.Block{
		Type:  PEMTypeSigningPrivate,
		Bytes: k[:],
	}
	return string(pem.EncodeToMemory(&block))
}

// SigningKeyFromPEM reads a SigninKeyPair from a PEM block. The PEM must have
// the correct header.
func SigningKeyFromPEM(p *pem.Block) (*SigningKeyPair, error) {
	if p.Type != PEMTypeSigningPrivate {
		return nil, fmt.Errorf("wront PEM type %q, want %q", p.Type, PEMTypeSigningPrivate)
	}
	if len(p.Bytes) != 32 {
		return nil, fmt.Errorf("invalid private key length. expected %d bytes, got %d", 32, len(p.Bytes))
	}
	out := new(SigningKeyPair)
	copy(out.Private[:], p.Bytes)
	out.PublicFromPrivate()
	return out, nil
}

// ParseSigningPublicKey parses a text public signing key. It must have the
// expected prefix for Hop signing public keys.
func ParseSigningPublicKey(encoded string) (*SigningPublicKey, error) {
	if !strings.HasPrefix(encoded, SigningPublicKeyPrefix) {
		return nil, fmt.Errorf("bad prefix, expected %s", SigningPublicKeyPrefix)
	}
	rest := encoded[len(SigningPublicKeyPrefix):]
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid key length, got %d, expected 32", len(b))
	}
	out := new(SigningPublicKey)
	copy(out[:], b)
	return out, nil
}
