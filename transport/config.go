package transport

import "time"

type ClientConfig struct{}

const (
	DefaultMaxPendingConnections           = 10
	DefaultMaxBufferedPacketsPerConnection = 100
)

type ServerConfig struct {
	MaxPendingConnections           int
	MaxBufferedPacketsPerConnection int

	StartingReadTimeout time.Duration
}

func (c *ServerConfig) maxPendingConnections() int {
	if c.MaxPendingConnections == 0 {
		return DefaultMaxPendingConnections
	}
	return c.MaxPendingConnections
}

func (c *ServerConfig) maxBufferedPacketsPerConnection() int {
	if c.MaxBufferedPacketsPerConnection == 0 {
		return DefaultMaxBufferedPacketsPerConnection
	}
	return c.MaxBufferedPacketsPerConnection
}
