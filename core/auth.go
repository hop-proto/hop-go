package core

import (
	"hop.computer/hop/agent"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

// Authenticator is an interface that exposes the crypto operations necessary to
// authenticate a Hop channel.
//
// TODO(dadrian): To avoid having to edit the transport and tube layers, I'm
// making this a getter for now. In reality, it should be something that exposes
// a DH and certificate verify API.
type Authenticator interface {
	keys.Exchangable
	// TODO(dadrian): This isn't actually the interface we want
	GetVerifyConfig() transport.VerifyConfig
	GetLeaf() *certs.Certificate
	GetServerKEMKey() *keys.KEMPublicKey
}

// TODO(baumanl): add another implementation of Authenticator for selfsign?

// InMemoryAuthenticator implements Authenticator using keys where the private
// key is backed by an in-memory Go structure.
type InMemoryAuthenticator struct {
	*keys.X25519KeyPair
	VerifyConfig transport.VerifyConfig
	Leaf         *certs.Certificate
	ServerKEMKey *keys.KEMPublicKey
}

// GetVerifyConfig implements Authenticator.
func (a InMemoryAuthenticator) GetVerifyConfig() transport.VerifyConfig {
	return a.VerifyConfig
}

// GetLeaf implements Authenticator.
func (a InMemoryAuthenticator) GetLeaf() *certs.Certificate {
	return a.Leaf
}

// GetServerKEMKey implements Authenticator.
func (a InMemoryAuthenticator) GetServerKEMKey() *keys.KEMPublicKey {
	return a.ServerKEMKey
}

var _ Authenticator = InMemoryAuthenticator{}

// AgentAuthenticator implements Authenticator with backing from hop-agent
type AgentAuthenticator struct {
	*agent.BoundClient
	VerifyConfig transport.VerifyConfig
	Leaf         *certs.Certificate
	ServerKEMKey *keys.KEMPublicKey
}

// GetVerifyConfig implements Authenticator.
func (a AgentAuthenticator) GetVerifyConfig() transport.VerifyConfig {
	return a.VerifyConfig
}

// GetLeaf implements Authenticator.
func (a AgentAuthenticator) GetLeaf() *certs.Certificate {
	return a.Leaf
}

// GetServerKEMKey implements Authenticator.
func (a AgentAuthenticator) GetServerKEMKey() *keys.KEMPublicKey {
	return a.ServerKEMKey
}

var _ Authenticator = AgentAuthenticator{}
