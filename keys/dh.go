package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

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

const DHPublicKeyPrefix = "hop-dh-v1-"

// String encodes a PublicKey to a custom format.
//
// TODO(dadrian): Is this even a good format?
func (p *PublicKey) String() string {
	b64 := base64.StdEncoding.EncodeToString(p[:])
	return fmt.Sprintf("%s%s", DHPublicKeyPrefix, b64)
}

const PEMTypeDHPrivate = "HOP PROTOCOL DH PRIVATE KEY V1"

// String encodes a PrivateKey to PEM.
func (k *PrivateKey) String() string {
	block := pem.Block{
		Type:  PEMTypeDHPrivate,
		Bytes: k[:],
	}
	return string(pem.EncodeToMemory(&block))
}

func DHKeyFromPEM(p *pem.Block) (*X25519KeyPair, error) {
	if p.Type != PEMTypeDHPrivate {
		return nil, fmt.Errorf("wront PEM type %q, want %q", p.Type, PEMTypeDHPrivate)
	}
	out := new(X25519KeyPair)
	n := copy(out.Private[:], p.Bytes)
	if n != 32 {
		return nil, fmt.Errorf("unexpected key length (got %d, expected 32)", n)
	}
	out.PublicFromPrivate()
	return out, nil
}

// ReadDHKeyFromPEMFile reads the first PEM-encoded Hop DH key at the provided
// path.
func ReadDHKeyFromPEMFile(path string) (*X25519KeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("not a PEM file")
	}
	return DHKeyFromPEM(p)
}

func ParseDHPublicKey(encoded string) (*PublicKey, error) {
	if !strings.HasPrefix(encoded, DHPublicKeyPrefix) {
		return nil, fmt.Errorf("bad prefix, expected %s", DHPublicKeyPrefix)
	}
	rest := encoded[len(DHPublicKeyPrefix):]
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid public key length, got %d, expected 32", len(b))
	}
	out := new(PublicKey)
	copy(out[:], b)
	return out, nil
}
