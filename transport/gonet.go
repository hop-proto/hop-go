package transport

import (
	"errors"
	"net"
)

const udp = "udp"

// Client directly implements net.Conn
var _ net.Conn = &Client{}

// ErrUDPOnly is returned when non-UDP connections are attempted or used.
var ErrUDPOnly = errors.New("portal requires UDP transport")

// Dial matches the interface of net.Dial
func Dial(network, address string, config ClientConfig) (*Client, error) {
	if network != udp {
		return nil, ErrUDPOnly
	}

	inner, err := net.ListenPacket(udp, ":0")
	if err != nil {
		return nil, err
	}

	raddr, err := net.ResolveUDPAddr(udp, address)
	if err != nil {
		return nil, err
	}

	return NewClient(inner.(*net.UDPConn), raddr, config), nil
}

// DialNP is similar to Dial, but using a reliable tube as an underlying conn for the Client
func DialNP(network, address string, tube UDPLike, config ClientConfig) (*Client, error) {
	// Figure out what address we would use to dial
	dst, err := net.ResolveUDPAddr(udp, address)
	if err != nil {
		return nil, err
	}
	return NewClient(tube, dst, config), nil
}

// DialWithDialer is similar to Dial, but uses options specified in a net.Dialer
// TODO(hosono) Do we need a DialNPWithDialer()??
func DialWithDialer(dialer *net.Dialer, network, address string, config ClientConfig) (*Client, error) {
	if network != udp {
		return nil, ErrUDPOnly
	}

	inner, err := dialer.Dial(udp, address)
	if err != nil {
		return nil, err
	}

	raddr := inner.RemoteAddr()
	if udpListener, err := net.ListenPacket("udp", ":0"); err == nil {
		inner = udpListener.(*net.UDPConn)
	} else {
		return nil, err
	}

	// If dialer has set a timeout, deadline, or keep alive, use those
	// Options set in dialer will override those in config
	if dialer.Timeout != 0 {
		config.HSTimeout = dialer.Timeout
	}

	if !dialer.Deadline.IsZero() {
		config.HSDeadline = dialer.Deadline
	}

	if dialer.KeepAlive != 0 {
		config.KeepAlive = dialer.KeepAlive
	}

	return NewClient(inner.(*net.UDPConn), raddr.(*net.UDPAddr), config), nil
}
