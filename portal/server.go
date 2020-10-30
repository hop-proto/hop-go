package portal

import (
	"net"

	"github.com/sirupsen/logrus"
)

type SessionID []byte

type Server struct {
	handshakeBuf []byte
	handshakePos int
	udpConn      *net.UDPConn
}

// TODO(dadrian): This is mostly a stub to be able to respond to a single
// client. Once I get a hang of what state to track, I'll try to intoduce
// multiple handshakes.
func (s *Server) AcceptHandshake() error {
	// TODO(dadrian): Probably shoudln't initialize this here
	s.handshakeBuf = make([]byte, 1024*1024)
	oob := make([]byte, 1024)
	n, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(s.handshakeBuf, oob)
	if err != nil {
		return err
	}
	logrus.Info(n, oobn, flags, addr)
	return nil
}

func NewServer(conn *net.UDPConn, config *Config) *Server {
	s := Server{
		udpConn: conn,
	}
	return &s
}
