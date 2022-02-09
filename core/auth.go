package core

import (
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

// Authenticator is an interface that exposes the crypto operations necessary to
// authenticate a Hop channel.
//
// TODO(dadrian): To avoid having to edit the transport and tube layers, I'm
// making this a getter for now. In reality, it should be something that exposes
// a DH and certificate verify API.
type Authenticator interface {

	// TODO(dadrian): This isn't actually the interface we want
	GetKeyPair() *keys.X25519KeyPair
	GetVerifyConfig() transport.VerifyConfig
}

// InMemoryAuthenticator implements Authenticator using keys where the private
// key is backed by an in-memory Go structure.
type InMemoryAuthenticator struct {
	KeyPair      *keys.X25519KeyPair
	VerifyConfig transport.VerifyConfig
}

// GetKeyPair implements Authenticator.
func (a InMemoryAuthenticator) GetKeyPair() *keys.X25519KeyPair {
	return a.KeyPair
}

// GetVerifyConfig implements Authenticator.
func (a InMemoryAuthenticator) GetVerifyConfig() transport.VerifyConfig {
	return a.VerifyConfig
}

var _ Authenticator = InMemoryAuthenticator{}
