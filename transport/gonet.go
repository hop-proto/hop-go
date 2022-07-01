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
func Dial(network, address string, config ClientConfig) (*Client, error) {
	if network != "udp" && network != "subspace" {
		return nil, ErrUDPOnly
	}

	// Open a new UDP socket
	inner, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	// Get the address of the remote host
	dst, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	return NewClient(inner.(UDPLike), dst, config), nil
}

//DialNP is similar to Dial, but using a reliable tube as an underlying conn for the Client
func DialNP(network, address string, tube UDPLike, config ClientConfig) (*Client, error) {
	// Figure out what address we would use to dial
	dst, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return NewClient(tube, dst, config), nil
}
