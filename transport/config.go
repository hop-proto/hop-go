package transport

import (
	"time"

	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
)

// VerifyConfig defines how to verify a remote certificate.
type VerifyConfig struct {
	// Store contains the trusted root certificates
	Store certs.Store

	// When InsecureSkipVerify is true, all chain building and verification is skipped.
	InsecureSkipVerify bool

	// Name is used for SNI and compared to the certificate when non-empty.
	Name certs.Name
}

// IdentityConfig associates a certificate chain with a Name.
type IdentityConfig struct {
	// TODO(dadrian): Wildcards?
	Name         certs.Name
	Leaf         *certs.Certificate
	Intermediate *certs.Certificate
}

// ClientConfig contains client-specific configuration settings.
type ClientConfig struct {
	KeyPair            *keys.X25519KeyPair
	Verify             VerifyConfig
	UseCertificate     bool
	Leaf, Intermediate *certs.Certificate
}

const (

	// DefaultMaxPendingConnections sets the maximum number of handshakes
	// waiting for a call to Accept().
	DefaultMaxPendingConnections = 10

	// DefaultMaxBufferedPacketsPerSession sets the maximum number of packets
	// (not bytes) than can be buffered by the server per accepted session.
	// Packets after this will dropped until the user calls Read.
	DefaultMaxBufferedPacketsPerSession = 100
)

// ServerConfig contains server-specific configuration settings.
type ServerConfig struct {
	MaxPendingConnections           int
	MaxBufferedPacketsPerConnection int

	StartingReadTimeout  time.Duration
	StartingWriteTimeout time.Duration

	KeyPair      *keys.X25519KeyPair
	Certificate  *certs.Certificate
	Intermediate *certs.Certificate

	AutoSelfSign bool

	ClientVerify *VerifyConfig

	// TODO(dadrian): How does this change with Names?
}

func (c *ServerConfig) maxPendingConnections() int {
	if c.MaxPendingConnections == 0 {
		return DefaultMaxPendingConnections
	}
	return c.MaxPendingConnections
}

func (c *ServerConfig) maxBufferedPacketsPerConnection() int {
	if c.MaxBufferedPacketsPerConnection == 0 {
		return DefaultMaxBufferedPacketsPerSession
	}
	return c.MaxBufferedPacketsPerConnection
}
