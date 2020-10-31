package portal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/cyclist"
)

// TODO(dadrian): Can we precalculate cookie lengths?
const maxCookieLen = 128

type SessionID []byte

type HandshakeState struct {
	duplex          cyclist.Cyclist
	ephemeral       X25519KeyPair
	clientEphemeral [DHLen]byte
	macBuf          [MacLen]byte
}

type Server struct {
	buf     []byte
	pos     int
	udpConn *net.UDPConn

	cookieKey    []byte
	cookieCipher cipher.Block
}

// TODO(dadrian): This is mostly a stub to be able to respond to a single
// client. Once I get a hang of what state to track, I'll try to intoduce
// multiple handshakes.
func (s *Server) AcceptHandshake() error {
	// TODO(dadrian): Probably shoudln't initialize this here
	s.buf = make([]byte, 1024*1024)
	s.pos = 0
	oob := make([]byte, 1024)
	n, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(s.buf[s.pos:], oob)
	if err != nil {
		return err
	}
	logrus.Info(n, oobn, flags, addr)
	if n < 4 {
		return errors.New("handshake message too short")
	}
	s.pos += n
	mt := MessageType(s.buf[0])
	switch mt {
	case MessageTypeClientHello:
		hs, err := s.handleClientHello(s.buf[0:s.pos])
		if err != nil {
			return err
		}
		// TODO(dadrian): Get rid of this allocation
		out := make([]byte, 1024)
		n, err = s.writeServerHello(out, addr, hs)
		if err != nil {
			return err
		}
		hs.duplex.Squeeze(out[n : n+MacLen])
		_, _, err = s.udpConn.WriteMsgUDP(out[0:n+MacLen], oob, addr)
		// TODO(dadrian): This shouldn't be a return, it needs to be in a loop
		return err
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	default:
		// TODO(dadrian): Make this an explicit error once all handshake message types are handled
		return errors.New("unimplemented")
	}
	return nil
}

func (s *Server) handleClientHello(b []byte) (*HandshakeState, error) {
	m := ClientHello{}
	x := b
	n, err := m.deserialize(x)
	if err != nil {
		return nil, err
	}
	x = x[n:]
	if len(x) != MacLen {
		logrus.Info("bad len", len(b), len(x), MacLen)
		return nil, ErrInvalidMessage
	}
	hs := new(HandshakeState)
	hs.duplex.InitializeEmpty()
	hs.duplex.Absorb([]byte(ProtocolName))
	hs.duplex.Absorb(b[0:n])
	hs.duplex.Squeeze(hs.macBuf[:])
	// TODO(dadrian): Should this be constant time?
	if !bytes.Equal(hs.macBuf[:], x) {
		return nil, ErrInvalidMessage
	}
	hs.ephemeral.Generate()
	return hs, nil
}

func (s *Server) writeCookie(b []byte, clientAddr net.UDPAddr, hs *HandshakeState) (int, error) {
	// TODO(dadrian): This is not amenable to swapping the keys out
	aead, err := cipher.NewGCMWithTagSize(s.cookieCipher, 16)
	if err != nil {
		return 0, err
	}
	// TODO(dadrian): Figure out the nonce?
	if n, err := rand.Read(b[0:12]); err != nil {
		return n, err
	}
	// Until we sort out Deck-SANE, just shove a nonce here
	nonce := b[0:12]
	plaintextCookie := hs.ephemeral.private[:]
	h := sha3.New256()
	h.Write(hs.clientEphemeral[:])
	// TODO(dadrian): Ensure this is always 4 or 12 bytes
	h.Write(clientAddr.IP)
	var port [2]byte
	port[0] = byte(clientAddr.Port >> 8)
	port[1] = byte(clientAddr.Port)
	h.Write(port[:])
	ad := h.Sum(nil)
	enc := aead.Seal(b[12:12], nonce, plaintextCookie, ad)
	return 12 + len(enc), nil
}

func (s *Server) writeServerHello(b []byte, clientAddr *net.UDPAddr, hs *HandshakeState) (n int, err error) {
	cookie := make([]byte, CookieLen)
	cookieLen, err := s.writeCookie(cookie, *clientAddr, hs)
	if err != nil {
		return 0, err
	}
	cookie = cookie[0:cookieLen]
	hello := ServerHello{
		Ephemeral: hs.ephemeral.public[:],
		// TODO(dadrian): This forces an extra allocation, since we can't write the cookie directly to the output buffer
		Cookie: cookie,
	}
	n, err = hello.serialize(b)
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(b[0:n])
	return n, err
}

func NewServer(conn *net.UDPConn, config *Config) *Server {
	s := Server{
		udpConn: conn,
		// TODO(dadrian): Standardize this?
		cookieKey: make([]byte, 16),
	}
	// TODO(dadrian): This probably shouldn't happen in this function
	_, err := rand.Read(s.cookieKey)
	if err != nil {
		panic(err.Error())
	}
	s.cookieCipher, err = aes.NewCipher(s.cookieKey)
	if err != nil {
		panic(err.Error())
	}
	return &s
}
