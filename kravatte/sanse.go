package kravatte

import "crypto/cipher"

const (
	KravatteSANSETagSize = 32
)

type sanse struct {
	kravatte *Kravatte
	e        uint32
}

var _ cipher.AEAD = &sanse{}

func (s *sanse) NonceSize() int {
	return 0
}

func (s *sanse) Overhead() int {
	return KravatteSANSETagSize
}

func (s *sanse) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// This has a specific slice behavior that we need to match, look at what GCM does.
	panic("implement me")
}

func (s *sanse) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	panic("implement me")
}

func (k *Kravatte) NewSANSE() cipher.AEAD {
	return &sanse{
		kravatte: k,
		e:        0,
	}
}

func (s *sanse) addToHistory(data []byte, appendix byte) int {
	// TODO(dadrian): Implement
	if s.kravatte.Kra(data, len(data)*8, FlagNone) != 0 {
		return 1
	}
	panic("unimplemented")
}

// wrap assumes all of these buffers have been preallocated to the correct length
func (s *sanse) wrap(plaintext []byte, ciphertext []byte, ad []byte, tag []byte) int {
	// TODO(dadrian): Implement
	return 1
}

// unwrap assumes all of these buffers have been preallocated to the correct length
func (s *sanse) unwrap(ciphertext []byte, plaintext []byte, ad []byte, tag []byte) int {
	// TODO(dadrian): Implement
	return 1
}
