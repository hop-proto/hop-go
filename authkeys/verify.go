package authkeys

import (
	"errors"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// AuthKeySet is a set of trusted keys
type AuthKeySet struct {
	keySet map[keys.PublicKey]bool
}

// NewAuthKeySet returns a new store
func NewAuthKeySet() AuthKeySet {
	return AuthKeySet{
		keySet: make(map[keys.PublicKey]bool),
	}
}

// AddKey adds a key to set of trusted keys
func (s *AuthKeySet) AddKey(pk keys.PublicKey) {
	s.keySet[pk] = true
}

// RemoveKey deletes key from trusted set
func (s *AuthKeySet) RemoveKey(pk keys.PublicKey) {
	delete(s.keySet, pk)
}

// VerifyLeaf checks that the leaf cert is properly formatted and the static key is in the set of authorized Keys
func (s *AuthKeySet) VerifyLeaf(leaf *certs.Certificate, opts certs.VerifyOptions) error {
	err := certs.VerifyLeafFormat(leaf, opts)
	if err != nil {
		return err
	}

	if _, isPresent := s.keySet[leaf.PublicKey]; !isPresent {
		return errors.New("client static not found in authorized key set")
	}
	return nil
}
