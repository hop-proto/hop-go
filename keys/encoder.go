package keys

import (
	"encoding/pem"
	"io"
)

// EncodeDHKeyToPEM writes a X25519 private key to PEM format.
func EncodeDHKeyToPEM(w io.Writer, key *X25519KeyPair) error {
	p := pem.Block{
		Type:  PEMTypeDHPrivate,
		Bytes: key.Private[:],
	}
	return pem.Encode(w, &p)
}

// EncodeSigningKeyToPEM writes a signing (Ed25519) private key to PEM format.
func EncodeSigningKeyToPEM(w io.Writer, key *SigningKeyPair) error {
	p := pem.Block{
		Type:  PEMTypeSigningPrivate,
		Bytes: key.Private[:],
	}
	return pem.Encode(w, &p)
}
