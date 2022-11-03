package authkeys

import "hop.computer/hop/keys"

// AuthKeyStore is a set of trusted keys
type AuthKeyStore struct {
	keys map[keys.PublicKey]bool
}

// NewAuthKeyStore returns a new store
func NewAuthKeyStore() AuthKeyStore {
	return AuthKeyStore{
		keys: make(map[keys.PublicKey]bool),
	}
}

// AddKey adds a key to set of trusted keys
func (s *AuthKeyStore) AddKey(pk keys.PublicKey) {
	s.keys[pk] = true
}

// RemoveKey deletes key from trusted set
func (s *AuthKeyStore) RemoveKey(pk keys.PublicKey) {
	delete(s.keys, pk)
}
