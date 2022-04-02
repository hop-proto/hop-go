package keys

// Exchangable is an interface capturing one side of Diffie-Hellman style key
// exchanges.
type Exchangable interface {
	Share() []byte
	Agree(other []byte) ([]byte, error)
}

var _ Exchangable = &X25519KeyPair{}

// Share returns the public key as a slice.
func (x *X25519KeyPair) Share() []byte {
	return x.Public[:]
}

// Agree is a wrapper for DH to make X25519KeyPair Exchangable.
func (x *X25519KeyPair) Agree(other []byte) ([]byte, error) {
	return x.DH(other)
}
