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
	sharedSecret    []byte
	macBuf          [MacLen]byte
}

type SessionState struct {
	key []byte
}

type Server struct {
	inBuf   []byte
	outBuf  []byte
	encBuf  []byte
	oob     []byte
	udpConn *net.UDPConn

	inShutdown atomicBool

	handshakes map[string]*HandshakeState
	sessions   map[string]*SessionState

	cookieKey    []byte
	cookieCipher cipher.Block
}

func (s *Server) writePacket(pkt []byte, dst *net.UDPAddr) error {
	_, _, err := s.udpConn.WriteMsgUDP(pkt, nil, dst)
	return err
}

func (s *Server) readPacket() error {
	msgLen, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(s.inBuf, s.oob)
	if err != nil {
		return err
	}
	logrus.Info(msgLen, oobn, flags, addr)
	if msgLen < 4 {
		return ErrInvalidMessage
	}
	mt := MessageType(s.inBuf[0])
	switch mt {
	case MessageTypeClientHello:
		hs, err := s.handleClientHello(s.inBuf[:msgLen])
		if err != nil {
			return err
		}
		logrus.Debugf("client ephemeral: %x", hs.clientEphemeral)
		hs.sharedSecret, err = hs.ephemeral.DH(hs.clientEphemeral[:])
		if err != nil {
			logrus.Errorf("server coudln't X25519: %s", err)
			return err
		}
		logrus.Debugf("server shared secret: %x", hs.sharedSecret[:])
		n, err := s.writeServerHello(s.outBuf, addr, hs)
		if err != nil {
			return err
		}
		hs.duplex.Squeeze(s.outBuf[n : n+MacLen])
		if err := s.writePacket(s.outBuf[:n+MacLen], addr); err != nil {
			return err
		}
	case MessageTypeClientAck:
		hs, err := s.handleClientAck(s.inBuf[:msgLen], addr)
		if err != nil {
			return err
		}
		// TODO(dadrian): Don't use .String() for this
		s.handshakes[addr.String()] = hs
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	default:
		// TODO(dadrian): Make this an explicit error once all handshake message types are handled
		return errors.New("unimplemented")
	}
	return nil
}

func (s *Server) handleClientAck(b []byte, addr *net.UDPAddr) (*HandshakeState, error) {
	return nil, errors.New("clientack unimplemented")
}

// TODO(dadrian): Should this provide a Listen()-like API? Once a session is established, should we return something?
func (s *Server) Serve() error {
	// TODO(dadrian): Probably shoudln't initialize this here
	// TODO(dadrian): Do we really need three buffers?
	// TODO(dadrian): Can I make this thread safe?
	s.inBuf = make([]byte, 1024*1024)
	s.outBuf = make([]byte, len(s.inBuf))
	s.encBuf = make([]byte, len(s.inBuf))
	s.oob = make([]byte, 1024)
	for !s.inShutdown.isSet() {
		err := s.readPacket()
		if err != nil {
			logrus.Error(err)
		}
	}
	return nil
}

func (s *Server) ShuttingDown() bool {
	return s.inShutdown.isSet()
}

func (s *Server) Close() error {
	// TODO(dadrian): Make this block until it's actually done
	s.inShutdown.setTrue()
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
	// TODO(dadrian): Get rid of this copy
	n = copy(hs.clientEphemeral[:], m.Ephemeral[:DHLen])
	if n != DHLen {
		return nil, ErrInvalidDH
	}
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
	hs.duplex.Absorb(b[:4])
	hs.duplex.Absorb(hs.ephemeral.public[:])
	hs.duplex.Absorb(hs.sharedSecret[:DHLen])
	hs.duplex.Absorb(cookie)
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
