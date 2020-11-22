package portal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/cyclist"
)

// TODO(dadrian): Can we precalculate cookie lengths?
const maxCookieLen = 128

type SessionID [4]byte

type HandshakeState struct {
	duplex          cyclist.Cyclist
	ephemeral       X25519KeyPair
	clientEphemeral [DHLen]byte
	handshakeKey    [KeyLen]byte
	clientStatic    [DHLen]byte
	sessionID       [SessionIDLen]byte
	// TODO(dadrian): Should these be arrays?
	ee     []byte
	es     []byte
	se     []byte
	macBuf [MacLen]byte
}

type SessionState struct {
	sessionID SessionID
	key       [16]byte
}

type Server struct {
	inBuf   []byte
	outBuf  []byte
	encBuf  []byte
	oob     []byte
	udpConn *net.UDPConn

	inShutdown atomicBool

	handshakes map[string]*HandshakeState
	sessions   map[SessionID]*SessionState

	cookieKey    []byte
	cookieCipher cipher.Block

	// TODO(dadrian): Different keys for different names
	staticKey X25519KeyPair
}

// TODO(dadrian): This is not thread-safe
func (s *Server) newSessionState() (*SessionState, error) {
	ss := new(SessionState)
	for {
		// TODO(dadrian): Remove potential infinite loop
		n, err := rand.Read(ss.sessionID[:])
		if n != 4 || err != nil {
			// TODO(dadrian): Should this be a panic or an error?
			panic("could not read random data")
		}
		if _, ok := s.sessions[ss.sessionID]; !ok {
			s.sessions[ss.sessionID] = ss
			break
		}
	}
	return ss, nil
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
		hs.ee, err = hs.ephemeral.DH(hs.clientEphemeral[:])
		if err != nil {
			logrus.Errorf("server coudln't X25519: %s", err)
			return err
		}
		logrus.Debugf("server shared secret: %x", hs.ee[:])
		n, err := s.writeServerHello(s.outBuf, addr, hs)
		if err != nil {
			return err
		}
		hs.duplex.Squeeze(s.outBuf[n : n+MacLen])
		if err := s.writePacket(s.outBuf[:n+MacLen], addr); err != nil {
			return err
		}
	case MessageTypeClientAck:
		logrus.Debug("about to handle client ack")
		n, hs, err := s.handleClientAck(s.inBuf[:msgLen], addr)
		if err != nil {
			logrus.Debugf("unable to handle client ack: %s", err)
			return err
		}
		if n != msgLen {
			logrus.Debug("client ack had extra data")
			return ErrInvalidMessage
		}
		// TODO(dadrian): Don't use .String() for this
		s.handshakes[addr.String()] = hs
		ss, err := s.newSessionState()
		copy(hs.sessionID[:], ss.sessionID[:])
		if err != nil {
			logrus.Debug("could not make new session state")
			return err
		}
		n, err = s.writeServerAuth(s.outBuf, hs, ss)
		if err != nil {
			return err
		}
		err = s.writePacket(s.outBuf[0:n], addr)
		if err != nil {
			return err
		}
	case MessageTypeClientAuth:
		logrus.Debug("server: received client auth")
		_, err = s.handleClientAuth(s.inBuf[:msgLen], addr)
		if err != nil {
			return err
		}
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	default:
		// TODO(dadrian): Make this an explicit error once all handshake message types are handled
		return errors.New("unimplemented")
	}
	return nil
}

func (s *Server) handleClientAck(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	x := b
	m := ClientAck{}
	n, err := m.deserialize(x)
	if err != nil {
		logrus.Debugf("unable to handleClientAck: %s", err)
		return n, nil, err
	}
	logrus.Debugf("encrypted SNI[%d]: %x", len(m.EncryptedSNI), m.EncryptedSNI)
	x = x[n:]
	hs, err := s.ReplayDuplexFromCookie(m.Cookie, m.Ephemeral, addr)
	hs.duplex.Absorb(b[0:HeaderLen])
	hs.duplex.Absorb(m.Ephemeral)
	hs.duplex.Absorb(m.Cookie)
	decryptedSNI := make([]byte, SNILen)
	hs.duplex.Decrypt(decryptedSNI, m.EncryptedSNI)
	hs.duplex.Squeeze(hs.macBuf[:])
	if len(x) < MacLen {
		return n, nil, ErrBufOverflow
	}
	if !bytes.Equal(hs.macBuf[:], x[:MacLen]) {
		return n + MacLen, nil, ErrInvalidMessage
	}
	return n + MacLen, hs, err
}

func (s *Server) writeServerAuth(b []byte, hs *HandshakeState, ss *SessionState) (int, error) {
	leaf := s.staticKey.public[:]
	var intermediate []byte
	logrus.Debugf("server: leaf, inter: %x, %x", leaf, intermediate)
	encCertLen := EncryptedCertificatesLength(leaf, intermediate)
	if len(b) < HeaderLen+SessionIDLen+encCertLen {
		return 0, ErrBufUnderflow
	}
	x := b
	pos := 0
	x[0] = MessageTypeServerAuth
	x[1] = 0
	x[2] = byte(encCertLen >> 8)
	x[3] = byte(encCertLen)
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	copy(x, ss.sessionID[:])
	hs.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	pos += SessionIDLen
	encCerts, err := EncryptCertificates(&hs.duplex, leaf, intermediate)
	if err != nil {
		return pos, err
	}
	copy(x, encCerts)
	x = x[encCertLen:]
	pos += encCertLen
	if len(x) < 2*MacLen {
		return pos, ErrBufUnderflow
	}
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server: sa tag %x", x[:MacLen])
	x = x[MacLen:]
	pos += MacLen
	hs.es, err = s.staticKey.DH(hs.clientEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(es)")
		return pos, err
	}
	logrus.Debugf("server es: %x", hs.es)
	hs.duplex.Absorb(hs.es)
	hs.duplex.Squeeze(x[:MacLen])
	x = x[MacLen:]
	pos += MacLen
	return pos, nil
}

func (s *Server) handleClientAuth(b []byte, addr *net.UDPAddr) (int, error) {
	x := b
	pos := 0
	if len(b) < HeaderLen+SessionIDLen+MacLen+MacLen {
		logrus.Debug("server: client auth too short")
		return 0, ErrBufUnderflow
	}
	if b[0] != MessageTypeClientAuth {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs, ok := s.handshakes[addr.String()]
	if !ok {
		logrus.Debugf("server: no handshake state for handshake packet from %s", addr)
		return pos, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	sessionID := x[:SessionIDLen]
	if !bytes.Equal(hs.sessionID[:], sessionID) {
		logrus.Debugf("server: mismatched session ID for %s: expected %x, got %x", addr, hs.sessionID, sessionID)
		return pos, ErrUnexpectedMessage
	}
	_, ok = s.sessions[hs.sessionID]
	if !ok {
		logrus.Debugf("server: could not find session ID %x", hs.sessionID)
		return pos, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(sessionID)
	x = x[SessionIDLen:]
	pos += SessionIDLen
	encStatic := x[:DHLen]
	hs.duplex.Decrypt(hs.clientStatic[:], encStatic)
	x = x[DHLen:]
	pos += DHLen
	hs.duplex.Squeeze(hs.macBuf[:])
	clientTag := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientTag) {
		logrus.Debugf("server: mismatched tag in client auth: expected %x, got %x", hs.macBuf, clientTag)
		return pos, ErrInvalidMessage
	}
	x = x[MacLen:]
	pos += MacLen
	var err error
	hs.se, err = hs.ephemeral.DH(hs.clientStatic[:])
	if err != nil {
		logrus.Debugf("server: unable to calculated se: %s", err)
		return pos, err
	}
	logrus.Debugf("server: se %x", hs.se)
	hs.duplex.Absorb(hs.se)
	hs.duplex.Squeeze(hs.macBuf[:]) // mac
	clientMac := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientMac) {
		logrus.Debugf("server: mismatched mac in client auth: expected %x, got %x", hs.macBuf, clientMac)
		return pos, ErrInvalidMessage
	}
	x = x[MacLen:]
	pos += MacLen
	return pos, nil
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
	hs.duplex.Absorb(b[0:HeaderLen])
	hs.duplex.Absorb(m.Ephemeral)
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

func (s *Server) writeCookie(b []byte, clientAddr *net.UDPAddr, hs *HandshakeState) (int, error) {
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
	ad := CookieAD(hs.clientEphemeral[:], clientAddr)
	enc := aead.Seal(b[12:12], nonce, plaintextCookie, ad)

	return 12 + len(enc), nil
}

func (s *Server) decryptCookie(cookie, clientEphemeral []byte, clientAddr *net.UDPAddr) ([]byte, error) {
	if len(cookie) < CookieLen {
		return nil, ErrBufUnderflow
	}
	aead, err := cipher.NewGCMWithTagSize(s.cookieCipher, 16)
	if err != nil {
		return nil, err
	}
	nonce := cookie[0:12]
	encryptedCookie := cookie[12:]
	ad := CookieAD(clientEphemeral, clientAddr)
	// TODO(dadrian): Avoid allocation?
	out := make([]byte, 0, DHLen)
	out, err = aead.Open(out, nonce, encryptedCookie, ad)
	return out, err
}

func (s *Server) writeServerHello(b []byte, clientAddr *net.UDPAddr, hs *HandshakeState) (n int, err error) {
	cookie := make([]byte, CookieLen)
	cookieLen, err := s.writeCookie(cookie, clientAddr, hs)
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
	hs.duplex.Absorb(hs.ee[:DHLen])
	hs.duplex.Absorb(cookie)
	hs.duplex.Squeeze(hs.handshakeKey[:])
	return n, err
}

func NewServer(conn *net.UDPConn, config *Config) *Server {
	s := Server{
		udpConn: conn,
		// TODO(dadrian): Standardize this?
		cookieKey:  make([]byte, 16),
		handshakes: make(map[string]*HandshakeState),
		sessions:   make(map[SessionID]*SessionState),
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
	// TODO(dadrian): This should be on the config object
	s.staticKey.Generate()
	return &s
}
