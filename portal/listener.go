package portal

import (
	"errors"
	"net"
)

// ErrUDPOnly is returned when non-UDP connections are attempted or used.
var ErrUDPOnly = errors.New("portal requires UDP transport")

// Dial matches the interface of net.Dial
func Dial(network, address string, config *Config) (*ClientConn, error) {
	if network != "udp" {
		return nil, ErrUDPOnly
	}
	inner, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	return Client(inner.(*net.UDPConn), config), nil
}
