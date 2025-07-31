package authkeys

import (
	"errors"
	"sync"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// SyncAuthKeySet is a set of trusted keys
type SyncAuthKeySet struct {
	// +checklocks:lock
	keySet map[keys.DHPublicKey]bool
	// +checklocks:lock
	lock sync.Mutex
}

// NewSyncAuthKeySet returns a new store
func NewSyncAuthKeySet() *SyncAuthKeySet {
	return &SyncAuthKeySet{
		keySet: make(map[keys.DHPublicKey]bool),
		lock:   sync.Mutex{},
	}
}

// AddKey adds a key to set of trusted keys
func (s *SyncAuthKeySet) AddKey(pk keys.DHPublicKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.keySet[pk] = true
}

// RemoveKey deletes key from trusted set
func (s *SyncAuthKeySet) RemoveKey(pk keys.DHPublicKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.keySet, pk)
}

// VerifyLeaf checks that the leaf cert is properly formatted and the static key is in the set of authorized Keys
func (s *SyncAuthKeySet) VerifyLeaf(leaf *certs.Certificate, opts certs.VerifyOptions) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	err := certs.VerifyLeafFormat(leaf, opts)
	if err != nil {
		return err
	}

	if _, isPresent := s.keySet[keys.DHPublicKey(leaf.PublicKey)]; !isPresent {
		return errors.New("client static not found in authorized key set")
	}
	return nil
}
