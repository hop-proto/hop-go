package portal

import (
	"errors"
	"io"
	"net"
)

// ErrUDPOnly is returned when non-UDP connections are attempted or used.
var ErrUDPOnly = errors.New("portal requires UDP transport")

// Dial matches the interface of net.Dial
func Dial(network, address string, config *Config) (*Client, error) {
	if network != "udp" && network != "subspace" {
		return nil, ErrUDPOnly
	}
	inner, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	return NewClient(inner.(*net.UDPConn), config), nil
}

// Server implements net.Listener
var _ net.Listener = &Server{}

// Accept implements the net.Listener interface and returns the first connection
// in the pending connection queue. It blocks until a connection is available.
// It return EOF if the server is closed.
func (s *Server) Accept() (net.Conn, error) {
	// TODO(dadrian): #concurrency
	c, ok := <-s.pendingConnections
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

// Addr implements net.Listener. It returns the address of the underlying UDP
// connection.
func (s *Server) Addr() net.Addr {
	// TODO(dadrian): #concurrency
	return s.udpConn.LocalAddr()
}

// LocalAddr returns the UDP address of the Subspace server.
func (s *Server) LocalAddr() net.Addr {
	// TODO(dadrian): #concurrency
	return s.udpConn.LocalAddr()
}

// Close stops the listener, but any active sessions will remain open.
func (s *Server) Close() error {
	// Check to see if we already stopped or are stopping listening
	if !s.closed {
		s.closed = false
		return nil
	}
	return io.EOF
}

// Listen returns a $PROTOCOL_NAME listener configured as specified.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if network != "udp" {
		return nil, ErrUDPOnly
	}
	pktConn, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, err
	}
	inner := pktConn.(*net.UDPConn)
	s := NewServer(inner, config)
	go s.Serve()
	return s, nil
}
