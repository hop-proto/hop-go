package transport

import "time"

// ClientConfig contains client-specific configuration settings.
type ClientConfig struct{}

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
