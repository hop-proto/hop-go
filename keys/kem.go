package keys

import (
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

var (
	MlKem512 = mustCirclToKEM("ML-KEM-512")
)

// TODO paul: this entire file is the following implementation resulting form https://gitlab.com/yawning/nyquist/-/blob/experimental/pqnoise/kem/kem.go?ref_type=heads and using cloudflare circl kem schemes

// TODO paul: I did not implement Static-Ephemeral Entropy-Combination (SEEC) that has been implemented in that commit https://gitlab.com/yawning/nyquist/-/commit/5c086730589948e0429ec5f441141157f4112deb

// TODO paul: ask david about "SEECGenKey is optional, and just using the raw entropy device is supported."

// KEM is a Key Encapsulation Mechanism algorithm.
type KEM interface {
	fmt.Stringer

	// GenerateKeypair generates a new KEM keypair using the provided
	// entropy source.
	GenerateKeypair(rng io.Reader) (KEMKeypair, error)

	// GenerateKeypairFromSeed generates a new KEM keypair using the
	// provided seed
	GenerateKeypairFromSeed(seed []byte) (KEMKeypair, error)

	// Enc generates a shared key and ciphertext that encapsulates it
	// for the provided public key using the provided entropy source,
	// and returns the shared key and ciphertext.
	Enc(rng io.Reader, dest PublicKey) ([]byte, []byte, error)

	// ParsePrivateKey parses a binary encoded private key.
	ParsePrivateKey(data []byte) (KEMKeypair, error)

	// ParsePublicKey parses a binary encoded public key.
	ParsePublicKey(data []byte) (PublicKey, error)

	// PrivateKeySize returns the size of private keys in bytes.
	PrivateKeySize() int

	// PublicKeySize returns the size of public keys in bytes.
	PublicKeySize() int

	// CiphertextSize returns the size of encapsualted ciphertexts in bytes.
	CiphertextSize() int

	// SharedKeySize returns the size of the shared output in bytes.
	SharedKeySize() int
}

// keys.KEMKeypair is a KEM keypair.
type KEMKeypair interface {
	encoding.BinaryMarshaler

	// Public returns the public key of the keypair.
	Public() PublicKey

	Seed() []byte // TODO create a constant for that

	// Dec decapsulates the ciphertext and returns the encapsulated key.
	Dec(ct []byte) ([]byte, error)
}

// PublicKey is a KEM public key.
type PublicKey interface {
	encoding.BinaryMarshaler

	// Bytes returns the binary serialized public key.
	//
	// Warning: Altering the returned slice is unsupported and will lead
	// to unexpected behavior.
	Bytes() []byte
}

// kemCIRCL is a generic wrapper around a KEM scheme provided by CIRCL.
type kemCIRCL struct {
	name   string
	scheme kem.Scheme
}

func (impl *kemCIRCL) String() string {
	return impl.name
}

func (impl *kemCIRCL) GenerateKeypair(rng io.Reader) (KEMKeypair, error) {
	seed := make([]byte, impl.scheme.SeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, err
	}

	pub, priv := impl.scheme.DeriveKeyPair(seed)

	return &keypairCIRCL{
		privateKey: priv,
		publicKey:  mustCirclToPublic(pub),
		seed:       seed,
	}, nil
}

func (impl *kemCIRCL) GenerateKeypairFromSeed(seed []byte) (KEMKeypair, error) {
	pub, priv := impl.scheme.DeriveKeyPair(seed)

	return &keypairCIRCL{
		privateKey: priv,
		publicKey:  mustCirclToPublic(pub),
		seed:       seed,
	}, nil
}

func (impl *kemCIRCL) Enc(rng io.Reader, dest PublicKey) ([]byte, []byte, error) {
	pubTo, ok := dest.(*publicKeyCIRCL)
	if !ok || pubTo.inner.Scheme() != impl.scheme {
		return nil, nil, errors.New("KEM: mismatched public key")
	}

	seed := make([]byte, impl.scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, nil, err
	}

	ct, ss, err := impl.scheme.EncapsulateDeterministically(pubTo.inner, seed)
	if err != nil {
		// This should NEVER happen.
		panic("KEM: failed to encapsulate: " + err.Error())
	}

	return ct, ss, nil
}

func (impl *kemCIRCL) ParsePrivateKey(data []byte) (KEMKeypair, error) {
	priv, err := impl.scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, errors.New("KEM: malformed public key")
	}

	kp := &keypairCIRCL{
		privateKey: priv,
		publicKey:  mustCirclToPublic(priv.Public()),
		seed:       nil,
	}

	return kp, nil
}

func (impl *kemCIRCL) ParsePublicKey(data []byte) (PublicKey, error) {
	pub, err := impl.scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, errors.New("KEM: public key cannot be parsed from the buffer")
	}

	return mustCirclToPublic(pub), nil
}

func (impl *kemCIRCL) PrivateKeySize() int {
	return impl.scheme.PrivateKeySize()
}

func (impl *kemCIRCL) PublicKeySize() int {
	return impl.scheme.PublicKeySize()
}

func (impl *kemCIRCL) CiphertextSize() int {
	return impl.scheme.CiphertextSize()
}

func (impl *kemCIRCL) SharedKeySize() int {
	return impl.scheme.SharedKeySize()
}

// keypairCIRCL is a generic wrapper around a keypair backed by CIRCL.
type keypairCIRCL struct {
	privateKey kem.PrivateKey
	publicKey  *publicKeyCIRCL
	// The seed should only be used in the context of ephemeral keys.
	// Is set to nil for static keypair
	seed []byte
}

func (kp *keypairCIRCL) Seed() []byte {
	return kp.seed
}

func (kp *keypairCIRCL) MarshalBinary() ([]byte, error) {
	return kp.privateKey.MarshalBinary()
}

func (kp *keypairCIRCL) Dec(ct []byte) ([]byte, error) {
	kpScheme := kp.privateKey.Scheme()

	if len(ct) != kpScheme.CiphertextSize() {
		return nil, errors.New("KEM: malformed ciphertext")
	}

	ss, err := kpScheme.Decapsulate(kp.privateKey, ct)
	if err != nil {
		// This should NEVER happen, all KEMs that are currently still
		// in the NIST competition return a deterministic random value
		// on decapsulation failure.
		panic("KEM: failed to decapsulate: " + err.Error())
	}

	return ss, nil
}

func (kp *keypairCIRCL) Public() PublicKey {
	return kp.publicKey
}

// publicKeyCIRCL is a generic wrapper around a public key backed by CIRCL.
type publicKeyCIRCL struct {
	inner      kem.PublicKey
	innerBytes []byte
}

func (pubKey *publicKeyCIRCL) MarshalBinary() ([]byte, error) {
	return pubKey.inner.MarshalBinary()
}

func (pubKey *publicKeyCIRCL) Bytes() []byte {
	return pubKey.innerBytes
}

func mustCirclToKEM(s string) *kemCIRCL {
	scheme := schemes.ByName(s)
	if scheme == nil {
		panic("KEM: invalid scheme: " + s)
	}
	return &kemCIRCL{
		name:   s,
		scheme: scheme,
	}
}

func mustCirclToPublic(inner kem.PublicKey) *publicKeyCIRCL {
	innerBytes, _ := inner.MarshalBinary()
	return &publicKeyCIRCL{
		inner:      inner,
		innerBytes: innerBytes,
	}
}
