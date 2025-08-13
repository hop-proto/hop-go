package transport

import (
	"time"

	"hop.computer/hop/authkeys"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// AdditionalVerifyCallback can be called mid handshake to do
// other checks on server certificate
type AdditionalVerifyCallback func(*certs.Certificate) error

// VerifyConfig defines how to verify a remote certificate.
type VerifyConfig struct {
	// Store contains the trusted root certificates
	Store certs.Store

	// AuthKeys contains trusted keys
	AuthKeys *authkeys.SyncAuthKeySet

	// Enable vs. Disable authenticating with authorized keys
	AuthKeysAllowed bool

	// When InsecureSkipVerify is true, all chain building and verification is skipped (authkeys can still happen if enabled)
	InsecureSkipVerify bool

	// Name is used for SNI and compared to the certificate when non-empty.
	Name certs.Name

	// Can do additional verification in a call back.
	AddVerifyCallback AdditionalVerifyCallback
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
	MaxBufferedPackets int
	Exchanger          keys.Exchangable
	Verify             VerifyConfig
	Leaf, Intermediate *certs.Certificate
	AutoSelfSign       bool
	HSTimeout          time.Duration
	HSDeadline         time.Time
	KeepAlive          time.Duration

	// ServerKEMKey is the ML-KEM public static key used in the hidden mode handshake
	ServerKEMKey *keys.KEMPublicKey
}

func (c *ClientConfig) maxBufferedPackets() int {
	if c.MaxBufferedPackets == 0 {
		return ClientDefaultMaxBufferedPacketsPerSession
	}
	return c.MaxBufferedPackets
}

const (

	// ServerDefaultMaxPendingConnections sets the maximum number of handshakes
	// waiting for a call to Accept().
	ServerDefaultMaxPendingConnections = 10

	// ServerDefaultMaxBufferedPacketsPerSession sets the maximum number of packets
	// (not bytes) than can be buffered by the server per accepted session.
	// Packets after this will dropped until the user calls Read.
	// TODO(hosono) fixing the reliable tubes may let us reduce this number
	ServerDefaultMaxBufferedPacketsPerSession = 10000

	// ClientDefaultMaxBufferedPacketsPerSession sets the maximum number of packets
	// (not bytes) that can be buffered for a session. Packets after this will
	// be dropped unless the user calls Read
	// TODO(hosono) fixing the reliable tubes may let us reduce this number
	ClientDefaultMaxBufferedPacketsPerSession = 10000
)

// ClientHandshakeInfo contains information about an attempted handshake. It is
// used as an argument in certificate callbacks.
type ClientHandshakeInfo struct {

	// ServerName indicates the name of the server requested by the client.
	ServerName certs.Name
}

// ServerConfig contains server-specific configuration settings.
type ServerConfig struct {
	MaxPendingConnections           int
	MaxBufferedPacketsPerConnection int

	HandshakeTimeout time.Duration

	KeyPair      *keys.X25519KeyPair
	KEMKeyPair   *keys.KEMKeyPair
	Certificate  *certs.Certificate
	Intermediate *certs.Certificate

	ClientVerify *VerifyConfig

	GetCertificate func(ClientHandshakeInfo) (*Certificate, error)
	GetCertList    func() ([]*Certificate, error)

	HiddenModeVHostNames []string
}

func (c *ServerConfig) maxPendingConnections() int {
	if c.MaxPendingConnections == 0 {
		return ServerDefaultMaxPendingConnections
	}
	return c.MaxPendingConnections
}

func (c *ServerConfig) maxBufferedPacketsPerConnection() int {
	if c.MaxBufferedPacketsPerConnection == 0 {
		return ServerDefaultMaxBufferedPacketsPerSession
	}
	return c.MaxBufferedPacketsPerConnection
}
