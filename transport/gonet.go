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
func Dial(network, address string, config *ClientConfig) (*Client, error) {
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

//DialNP is similar to Dial, but using a reliable tube as an underlying conn for the Client
func DialNP(network, address string, tube UDPLike, config *ClientConfig) (*Client, error) {
	// Figure out what address we would use to dial
	throwaway, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	if config == nil { //TODO(baumanl): Why do I have this weird if/else here? necessary?
		return NewClient(tube, remoteAddr.(*net.UDPAddr), nil), nil
	}
	return NewClient(tube, remoteAddr.(*net.UDPAddr), config), nil
}
