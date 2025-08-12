package keys

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
	"github.com/sirupsen/logrus"

	cpapke "github.com/cloudflare/circl/pke/kyber/kyber512"
)

// This kem implementation is using the Cloudflare CIRCL ML-KEM 512 implementation,
// is highly inspired by the work done in the following repository
// https://gitlab.com/yawning/nyquist/-/blob/experimental/pqnoise/kem/kem.go?ref_type=heads
// and has been adapted to Hop use.

var (
	MlKem512 = schemes.ByName("ML-KEM-512")
)

const (
	// MlKem512KeySeedSize Size of seed for NewKeyFromSeed
	MlKem512KeySeedSize = cpapke.KeySeedSize + 32

	// MlKem512CiphertextSize Size of the encapsulated shared key.
	MlKem512CiphertextSize = cpapke.CiphertextSize

	// MlKem512PublicKeySize Size of a packed public key.
	MlKem512PublicKeySize = cpapke.PublicKeySize

	// MlKem512PrivateKeySize Size of a packed private key.
	MlKem512PrivateKeySize = cpapke.PrivateKeySize + cpapke.PublicKeySize + 64

	MlKem512SharedKeySize = 32
)

type KEMPublicKey struct {
	inner      kem.PublicKey
	innerBytes []byte
}
type KEMPrivateKey kem.PrivateKey
type KEMSeed []byte

type KEMKeyPair struct {
	Public  KEMPublicKey
	Private KEMPrivateKey
	Seed    KEMSeed
}

func GenerateKEMKeyPair(rng io.Reader) (*KEMKeyPair, error) {
	seed := make([]byte, 64)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, err
	}

	pub, priv := MlKem512.DeriveKeyPair(seed)

	return &KEMKeyPair{
		Private: priv,
		Public:  *mustCirclToPublic(pub),
		Seed:    KEMSeed(seed),
	}, nil
}

func GenerateKEMKeyPairFromSeed(seed []byte) (*KEMKeyPair, error) {
	pub, priv := MlKem512.DeriveKeyPair(seed)

	return &KEMKeyPair{
		Private: priv,
		Public:  *mustCirclToPublic(pub),
		Seed:    KEMSeed(seed),
	}, nil
}

func Encapsulate(rng io.Reader, dest *KEMPublicKey) ([]byte, []byte, error) {
	pubTo := dest.inner

	seed := make([]byte, MlKem512.EncapsulationSeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, nil, err
	}

	ct, ss, err := MlKem512.EncapsulateDeterministically(pubTo, seed)
	if err != nil {
		// This should NEVER happen.
		panic("KEM: failed to encapsulate: " + err.Error())
	}

	return ct, ss, nil
}

func ParseKEMPrivateKeyFromBytes(data []byte) (*KEMKeyPair, error) {
	priv, err := MlKem512.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, errors.New("KEM: malformed public key")
	}

	kp := &KEMKeyPair{
		Private: priv,
		Public:  *mustCirclToPublic(priv.Public()),
	}

	return kp, nil
}

func ParseKEMPublicKeyFromBytes(data []byte) (*KEMPublicKey, error) {
	pub, err := MlKem512.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, errors.New("KEM: public key cannot be parsed from the buffer")
	}

	return mustCirclToPublic(pub), nil
}

// mustCirclToPublic converts a circl KEM PublicKey into the wrapper type KEMPublicKey.
// It marshals the inner public key into bytes and stores both the original key and its byte representation.
func mustCirclToPublic(inner kem.PublicKey) *KEMPublicKey {
	innerBytes, err := inner.MarshalBinary()
	if err != nil {
		return nil
	}
	return &KEMPublicKey{
		inner:      inner,
		innerBytes: innerBytes,
	}
}

func (kp *KEMKeyPair) MarshalBinary() ([]byte, error) {
	return kp.Private.MarshalBinary()
}

func (kp *KEMKeyPair) Decapsulate(ct []byte) ([]byte, error) {
	kpScheme := kp.Private.Scheme()

	if len(ct) != kpScheme.CiphertextSize() {
		return nil, errors.New("KEM: malformed ciphertext")
	}

	ss, err := kpScheme.Decapsulate(kp.Private, ct)
	if err != nil {
		// This should NEVER happen, all KEMs that are currently still
		// in the NIST competition return a deterministic random value
		// on decapsulation failure.
		panic("KEM: failed to decapsulate: " + err.Error())
	}

	return ss, nil
}

func (pubKey KEMPublicKey) MarshalBinary() ([]byte, error) {
	return pubKey.inner.MarshalBinary()
}

func (pubKey KEMPublicKey) Bytes() []byte {
	return pubKey.innerBytes
}

// KEMPublicKeyPrefix is the prefix used in public key files for Hop KEM keys.
const KEMPublicKeyPrefix = "hop-kem-v1-"

// String encodes a KEMPublicKey to a custom format.
func (pubKey KEMPublicKey) String() string {
	b64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())
	return fmt.Sprintf("%s%s", KEMPublicKeyPrefix, b64)
}

// PEMTypeKEMSeed is the PEM header for Hop KEM seed
const PEMTypeKEMSeed = "HOP PROTOCOL ML-KEM SEED V1"

// String encodes a PrivateKey to PEM.
func (seed KEMSeed) String() string {
	block := pem.Block{
		Type:  PEMTypeKEMSeed,
		Bytes: seed[:],
	}
	return string(pem.EncodeToMemory(&block))
}

// KEMKeyFromPEM parses a PEM block into a KEMKeyPair. The header must match,
// and the data must be the correct length.
func KEMKeyFromPEM(p *pem.Block) (*KEMKeyPair, error) {
	if p.Type != PEMTypeKEMSeed {
		return nil, fmt.Errorf("wront PEM type %q, want %q", p.Type, PEMTypeKEMSeed)
	}
	if len(p.Bytes) != MlKem512KeySeedSize { // TODO check the size of the seed
		return nil, fmt.Errorf("invalid key length, got %d, expected 64", len(p.Bytes))
	}
	out, err := GenerateKEMKeyPairFromSeed(p.Bytes)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadKEMKeyFromPEMFile reads the first PEM-encoded Hop KEM key at the provided
// path.
func ReadKEMKeyFromPEMFile(path string) (*KEMKeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("not a PEM file")
	}
	return KEMKeyFromPEM(p)
}

// ReadKEMKeyFromPEMFileFS reads the first PEM-encoded Hop KEM key from the
// file.
func ReadKEMKeyFromPEMFileFS(path string, fs fs.FS) (*KEMKeyPair, error) {
	if fs == nil {
		return ReadKEMKeyFromPEMFile(path)
	}
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("not a PEM file")
	}
	return KEMKeyFromPEM(p)
}

func ReadKEMKeyFromPubFile(serverPublicKeyPath string) (*KEMPublicKey, error) {
	pubKeyBytes, err := os.ReadFile(serverPublicKeyPath)
	if err != nil {
		logrus.Errorf("could not read public key file: %s", err)
		return nil, err
	}
	pubKey, err := ParseKEMPublicKey(string(pubKeyBytes))
	if err != nil {
		logrus.Errorf("client: unable to parse the server public key file: %s", err)
		return nil, err
	}
	return pubKey, nil
}

// ParseKEMPublicKey reads a text-encoded ML-KEM 512 Hop public key.
func ParseKEMPublicKey(encoded string) (*KEMPublicKey, error) {
	if !strings.HasPrefix(encoded, KEMPublicKeyPrefix) {
		return nil, fmt.Errorf("bad prefix, expected %s", KEMPublicKeyPrefix)
	}
	rest := encoded[len(KEMPublicKeyPrefix):]
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, err
	}
	if len(b) != 800 {
		return nil, fmt.Errorf("invalid key length, got %d, expected 800", len(b))
	}
	out, err := ParseKEMPublicKeyFromBytes(b)
	if err != nil {
		return nil, err
	}
	return out, nil
}
