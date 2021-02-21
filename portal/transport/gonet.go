package transport

import (
	"errors"
	"net"
)

// Client directly implements net.Conn
var _ net.Conn = &Client{}

// ErrUDPOnly is returned when non-UDP connections are attempted or used.
var ErrUDPOnly = errors.New("portal requires UDP transport")

// Dial matches the interface of net.Dial
func Dial(network, address string, config *Config) (*Client, error) {
	if network != "udp" && network != "subspace" {
		return nil, ErrUDPOnly
	}

	// Figure out what address we would use to dial
	throwaway, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	localAddr := throwaway.LocalAddr()
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()

	// Recreate as a non-connected socket
	inner, err := net.ListenUDP("udp", localAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	return NewClient(inner, remoteAddr.(*net.UDPAddr), config), nil
}
