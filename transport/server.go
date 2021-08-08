package transport

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
)

//AuthGrant contains deadline, user, action
type AuthGrant struct {
	Deadline         time.Time
	User             string
	Action           string
	PrincipalSession *Handle
}

type outgoing struct {
	pkt []byte
	dst *net.UDPAddr
}

// Server implements a Hop server capable of multiplexing roaming Hop
// connections.
//
// To run, call Start.
//
// TODO(dadrian): Figure out how much this should reflect the Listener API.
type Server struct {
	m sync.RWMutex

	rawRead      []byte
	handshakeBuf []byte

	udpConn *net.UDPConn
	config  *ServerConfig

	closed atomicBool

	handshakes map[string]*HandshakeState
	sessions   map[SessionID]*SessionState

	authgrants map[keys.PublicKey]*AuthGrant //static key -> authgrant

	pendingConnections chan *Handle
	outgoing           chan outgoing

	cookieKey    [KeyLen]byte
	cookieCipher cipher.Block

	// TODO(dadrian): Different keys for different names
	staticKey    *keys.X25519KeyPair
	certificate  []byte
	intermediate []byte
}

//AddAuthgrant adds auth grant to server map
func (s *Server) AddAuthgrant(k keys.PublicKey, t time.Time, user string, action string, handle *Handle) {
	ag := &AuthGrant{
		Deadline:         t,
		User:             user,
		Action:           action,
		PrincipalSession: handle,
	}
	s.m.Lock()
	s.authgrants[k] = ag
	s.m.Unlock()
}

func (s *Server) setHandshakeState(remoteAddr *net.UDPAddr, hs *HandshakeState) bool {
	s.m.Lock()
	defer s.m.Unlock()
	key := AddressHashKey(remoteAddr)
	_, exists := s.handshakes[key]
	if exists {
		return false
	}
	s.handshakes[key] = hs
	return true
}

func (s *Server) fetchHandshakeState(remoteAddr *net.UDPAddr) *HandshakeState {
	s.m.RLock()
	defer s.m.RUnlock()
	key := AddressHashKey(remoteAddr)
	return s.handshakes[key]
}

func (s *Server) clearHandshakeStateLocked(remoteAddr *net.UDPAddr) {
	key := AddressHashKey(remoteAddr)
	delete(s.handshakes, key)
}

func (s *Server) newSessionState() (*SessionState, error) {
	ss := new(SessionState)
	for {
		// TODO(dadrian): Remove potential infinite loop
		n, err := rand.Read(ss.sessionID[:])
		if n != 4 || err != nil {
			panic("could not read random data")
		}
		if s.setSessionState(ss) {
			break
		}
	}
	return ss, nil
}

func (s *Server) setSessionState(ss *SessionState) bool {
	s.m.Lock()
	defer s.m.Unlock()
	_, exists := s.sessions[ss.sessionID]
	if exists {
		return false
	}
	s.sessions[ss.sessionID] = ss
	return true
}

func (s *Server) fetchSessionState(sessionID SessionID) *SessionState {
	s.m.RLock()
	defer s.m.RUnlock()
	return s.fetchSessionStateLocked(sessionID)
}

func (s *Server) fetchSessionStateLocked(sessionID SessionID) *SessionState {
	return s.sessions[sessionID]
}

func (s *Server) clearSessionState(sessionID SessionID) {
	s.m.Lock()
	defer s.m.Unlock()
	delete(s.sessions, sessionID)
}

func (s *Server) writePacket(pkt []byte, dst *net.UDPAddr) error {
	_, _, err := s.udpConn.WriteMsgUDP(pkt, nil, dst)
	return err
}

func (s *Server) readPacket() error {
	msgLen, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(s.rawRead, nil)
	if err != nil {
		return err
	}
	logrus.Debug(msgLen, oobn, flags, addr)
	if msgLen < 4 {
		return ErrInvalidMessage
	}
	mt := MessageType(s.rawRead[0])
	switch mt {
	case MessageTypeClientHello:
		hs, err := s.handleClientHello(s.rawRead[:msgLen])
		if err != nil {
			return err
		}
		logrus.Debugf("server: client ephemeral: %x", hs.remoteEphemeral)
		hs.cookieKey = &s.cookieKey
		hs.remoteAddr = addr
		n, err := writeServerHello(hs, s.handshakeBuf)
		if err != nil {
			return err
		}
		logrus.Debugf("server: sh %x", s.handshakeBuf[:n])
		if err := s.writePacket(s.handshakeBuf[:n], addr); err != nil {
			return err
		}
	case MessageTypeClientAck:
		logrus.Debug("server: about to handle client ack")
		n, hs, err := s.handleClientAck(s.rawRead[:msgLen], addr)
		if err != nil {
			logrus.Debugf("server: unable to handle client ack: %s", err)
			return err
		}
		if n != msgLen {
			logrus.Debug("client ack had extra data")
			return ErrInvalidMessage
		}
		// TODO(dadrian): Don't use .String() for this
		if !s.setHandshakeState(addr, hs) {
			logrus.Debugf("server: already have handshake in progress with %s", addr.String())
			return ErrUnexpectedMessage
		}
		ss, err := s.newSessionState()
		copy(hs.sessionID[:], ss.sessionID[:])
		ss.remoteAddr = *addr
		if err != nil {
			logrus.Debug("could not make new session state")
			return err
		}
		n, err = s.writeServerAuth(s.handshakeBuf, hs, ss)
		if err != nil {
			return err
		}
		err = s.writePacket(s.handshakeBuf[0:n], addr)
		if err != nil {
			return err
		}
	case MessageTypeClientAuth:
		logrus.Debug("server: received client auth")
		_, hs, k, err := s.handleClientAuth(s.rawRead[:msgLen], addr)
		if err != nil {
			return err
		}
		logrus.Debug("server: finishHandshakeLocked")
		s.finishHandshake(hs, k)
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	case MessageTypeTransport:
		logrus.Debugf("server: received transport message from %s", addr)
		// TODO(dadrian): Avoid allocation
		plaintext := make([]byte, 65535)
		_, err := s.handleTransport(addr, s.rawRead[:msgLen], plaintext)
		if err != nil {
			return err
		}
		return nil
	default:
		// TODO(dadrian): Make this an explicit error once all handshake message types are handled
		return errors.New("unimplemented")
	}
	return nil
}

func (s *Server) handleClientAck(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	var buf [SNILen]byte
	length := HeaderLen + DHLen + CookieLen + SNILen + MacLen
	if len(b) < length {
		return 0, nil, ErrBufUnderflow
	}
	if mt := MessageType(b[0]); mt != MessageTypeClientAck {
		return 0, nil, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, nil, ErrUnexpectedMessage
	}
	header := b[:HeaderLen]
	b = b[HeaderLen:]
	ephemeral := b[:DHLen]
	b = b[DHLen:]
	logrus.Debugf("server: got client ephemeral again: %x", ephemeral)

	cookie := b[:CookieLen]
	b = b[CookieLen:]

	hs, err := s.ReplayDuplexFromCookie(cookie, ephemeral, addr)
	if err != nil {
		return 0, nil, err
	}
	hs.duplex.Absorb(header)
	hs.duplex.Absorb(ephemeral)
	hs.duplex.Absorb(cookie)
	hs.duplex.Decrypt(buf[:], b[:SNILen])
	decryptedSNI := buf[:SNILen]
	b = b[SNILen:]

	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server got client ack mac: %x, expected %x", b[:MacLen], hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return length, nil, ErrInvalidMessage
	}

	// Only check SNI if MACs match
	logrus.Debugf("server: got raw decrypted SNI %x: ", decryptedSNI[:])
	name := certs.Name{}
	_, err = name.ReadFrom(bytes.NewBuffer(decryptedSNI[:]))
	if err != nil {
		return 0, nil, err
	}
	logrus.Debugf("server: got name %v", name)

	return length, hs, err
}

func (s *Server) writeServerAuth(b []byte, hs *HandshakeState, ss *SessionState) (int, error) {
	logrus.Debugf("server: leaf, inter: %x, %x", s.certificate, s.intermediate)
	logrus.Debugf("server: leaf public: %x", s.staticKey.Public)
	encCertLen := EncryptedCertificatesLength(s.certificate, s.intermediate)
	logrus.Debugf("server: encrypted cert len: %d", encCertLen)
	if len(b) < HeaderLen+SessionIDLen+encCertLen {
		return 0, ErrBufUnderflow
	}
	x := b
	pos := 0
	x[0] = byte(MessageTypeServerAuth)
	x[1] = 0
	x[2] = byte(encCertLen >> 8)
	x[3] = byte(encCertLen)
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	copy(x, ss.sessionID[:])
	logrus.Debugf("server: session ID %x", ss.sessionID[:])
	hs.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	pos += SessionIDLen
	encCerts, err := EncryptCertificates(&hs.duplex, s.certificate, s.intermediate)
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
	hs.es, err = s.staticKey.DH(hs.remoteEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(es)")
		return pos, err
	}
	logrus.Debugf("server es: %x", hs.es)
	hs.duplex.Absorb(hs.es)
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server serverauth mac: %x", x[:MacLen])
	// x = x[MacLen:]
	pos += MacLen
	return pos, nil
}

func (s *Server) handleClientAuth(b []byte, addr *net.UDPAddr) (int, *HandshakeState, keys.PublicKey, error) {
	x := b
	pos := 0
	var k keys.PublicKey
	if len(b) < HeaderLen+SessionIDLen+MacLen+MacLen {
		logrus.Debug("server: client auth too short")
		return 0, nil, k, ErrBufUnderflow
	}

	if mt := MessageType(b[0]); mt != MessageTypeClientAuth {
		return 0, nil, k, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, nil, k, ErrInvalidMessage
	}
	hs := s.fetchHandshakeState(addr)
	if hs == nil {
		logrus.Debugf("server: no handshake state for handshake packet from %s", addr)
		return pos, nil, k, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	sessionID := x[:SessionIDLen]
	if !bytes.Equal(hs.sessionID[:], sessionID) {
		logrus.Debugf("server: mismatched session ID for %s: expected %x, got %x", addr, hs.sessionID, sessionID)
		return pos, nil, k, ErrUnexpectedMessage
	}
	ss := s.fetchSessionState(hs.sessionID)
	if ss == nil {
		logrus.Debugf("server: could not find session ID %x", hs.sessionID)
		return pos, nil, k, ErrUnexpectedMessage
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
		return pos, nil, k, ErrInvalidMessage
	}

	//if the client static key is in authorized keys continue, otherwise abandon all state
	//Check if the client is authorized permanently
	f, e := os.Open("../app/authorized_keys") //TODO: fix to actual address
	if e != nil {
		return pos, nil, k, ErrOpeningAuthKeys
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	authorized := false
	k = keys.PublicKey(hs.clientStatic)
	for scanner.Scan() {
		logrus.Info("COMPARING: ")
		if scanner.Text() == k.String() {
			authorized = true
			logrus.Debugf("USER AUTHORIZED")
			break
		}
	}
	if !authorized {
		//Check for a matching authgrant
		val, ok := s.authgrants[k]
		if !ok {
			//TODO: handle this gracefully (i.e. abandon all state)
			logrus.Info("KEY NOT AUTHORIZED")
		}
		if val.Deadline.Before(time.Now()) {
			delete(s.authgrants, k)
			//TODO: handle this gracefully (i.e. abandon all state)
			logrus.Info("AUTHGRANT DEADLINE EXCEEDED")
		}
		delete(s.authgrants, k)
		logrus.Info("USER AUTHORIZED")
	}
	x = x[MacLen:]
	pos += MacLen
	var err error
	hs.se, err = hs.ephemeral.DH(hs.clientStatic[:])
	if err != nil {
		logrus.Debugf("server: unable to calculated se: %s", err)
		return pos, nil, k, err
	}
	logrus.Debugf("server: se %x", hs.se)
	hs.duplex.Absorb(hs.se)
	hs.duplex.Squeeze(hs.macBuf[:]) // mac
	clientMac := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientMac) {
		logrus.Debugf("server: mismatched mac in client auth: expected %x, got %x", hs.macBuf, clientMac)
		return pos, nil, k, ErrInvalidMessage
	}
	// x = x[MacLen:]
	pos += MacLen
	return pos, hs, k, nil
}

func (s *Server) readPacketFromSession(ss *SessionState, plaintext []byte, pkt []byte, key *[KeyLen]byte) (int, error) {
	return ss.readPacket(plaintext, pkt, &ss.clientToServerKey)
}

func (s *Server) handleTransport(addr *net.UDPAddr, msg []byte, plaintext []byte) (int, error) {
	sessionID, err := PeekSession(msg)
	if err != nil {
		return 0, err
	}
	logrus.Debugf("server: transport message for session %x", sessionID)
	ss := s.fetchSessionState(sessionID)
	if ss == nil {
		return 0, ErrUnknownSession
	}
	ss.handle.m.Lock()
	defer ss.handle.m.Unlock()
	n, err := s.readPacketFromSession(ss, plaintext, msg, &ss.clientToServerKey)
	if err != nil {
		return 0, err
	}
	logrus.Debugf("server: session %x: plaintext: %x from: %s", ss.sessionID, plaintext[:n], addr)
	select {
	case ss.handle.recv <- plaintext[:n]:
		break
	default:
		logrus.Warnf("session %x: recv queue full, dropping packet", sessionID)
	}
	ss.handle.writeLock.Lock()
	defer ss.handle.writeLock.Unlock()
	if !EqualUDPAddress(&ss.remoteAddr, addr) {
		ss.remoteAddr = *addr
	}
	return n, nil
}

// Serve blocks until the server is closed.
func (s *Server) Serve() error {
	// TODO(dadrian): These should be smaller buffers
	s.rawRead = make([]byte, 65535)
	s.handshakeBuf = make([]byte, 65535)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for !s.closed.isSet() {
			err := s.readPacket()
			if err != nil {
				logrus.Errorf("server: %s", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for outgoing := range s.outgoing {
			s.writePacket(outgoing.pkt, outgoing.dst)
		}
		// TODO(dadrian): Write packets
	}()
	wg.Done()
	wg.Wait()
	return nil
}

func (s *Server) handleClientHello(b []byte) (*HandshakeState, error) {
	// TODO(dadrian): Avoid this allocation? It's kind of big to do on an
	// unauthenticated handshake.
	hs := new(HandshakeState)
	hs.duplex.InitializeEmpty()
	hs.duplex.Absorb([]byte(ProtocolName))
	n, err := readClientHello(hs, b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, ErrInvalidMessage
	}
	hs.ephemeral.Generate()
	return hs, nil
}

func (s *Server) finishHandshake(hs *HandshakeState, k keys.PublicKey) error {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.clearHandshakeStateLocked(hs.remoteAddr)
	ss := s.fetchSessionStateLocked(hs.sessionID)
	if ss == nil {
		return ErrUnknownSession
	}
	logrus.Debugf("server: finishing handshake for session %x", ss.sessionID)
	err := hs.deriveFinalKeys(&ss.clientToServerKey, &ss.serverToClientKey)
	if err != nil {
		return err
	}
	// TODO(dadrian): Create this earlier on so that the handshake fails earlier
	// if the queue is full.
	h := s.createHandleLocked(ss, k)
	select {
	case s.pendingConnections <- h:
		break
	default:
		logrus.Warnf("server: session %x: pending connections queue is full, dropping handshake", ss.sessionID)
		s.clearSessionState(ss.sessionID)
		ss.handle.close()
	}
	return nil
}

func (s *Server) createHandleLocked(ss *SessionState, k keys.PublicKey) *Handle {
	val, ok := s.authgrants[k]
	var p atomicBool
	p.setFalse()
	if !ok {
		val = &AuthGrant{}
		p.setTrue()
	}
	handle := &Handle{
		sessionID:    ss.sessionID,
		recv:         make(chan []byte, s.config.maxBufferedPacketsPerConnection()),
		send:         make(chan []byte, s.config.maxBufferedPacketsPerConnection()),
		readTimeout:  atomicTimeout(s.config.StartingReadTimeout),
		writeTimeout: atomicTimeout(s.config.StartingWriteTimeout),

		//TODO(baumanl): Simplify how to add this to handle? right now ag is passed from
		//handleClientAuth() -> finishHandshake() -> createHandleLocked()
		AG:        *val,
		principal: p,
	}
	ss.handle = handle
	return handle
}

func (s *Server) lockHandleAndWriteToSession(ss *SessionState, plaintext []byte) error {
	ss.handle.writeLock.Lock()
	defer ss.handle.writeLock.Unlock()
	err := ss.writePacket(s.udpConn, plaintext, &ss.serverToClientKey)
	return err
}

// AcceptTimeout blocks for up to duration until a new connection is available.
func (s *Server) AcceptTimeout(duration time.Duration) (*Handle, error) {
	timer := time.NewTicker(duration)
	select {
	case handle := <-s.pendingConnections:
		ss := s.fetchSessionState(handle.sessionID)
		if ss.handle != handle {
			// Should never happen
			return nil, ErrUnknownSession
		}
		ss.handle.writeWg.Add(1)
		go func(ss *SessionState) {
			defer ss.handle.writeWg.Done()
			for plaintext := range ss.handle.send {
				err := s.lockHandleAndWriteToSession(ss, plaintext)
				if err != nil {
					logrus.Errorf("server: unable to write packet: %s", err)
					// TODO(dadrian): Should this affect connection state?
				}
			}
		}(ss)
		return handle, nil
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Close stops the server, causing Serve() to return.
//
// TODO(dadrian): What does it do to writes?
func (s *Server) Close() error {
	// TODO(dadrian): #concurrency
	s.closed.setTrue()
	return nil
}

// NewServer returns a Server listening on the provided UDP connection. The
// returned Server object is a valid net.Listener.
func NewServer(conn *net.UDPConn, config *ServerConfig) (*Server, error) {
	if config.KeyPair == nil {
		return nil, errors.New("config.KeyPair must be set")
	}
	if config.Certificate == nil {
		return nil, errors.New("config.Certificate must be set")
	}

	// Pre-serialize the certificates.
	//
	// TODO(dadrian): This should happen on-demand.
	var cert, intermediate bytes.Buffer
	if _, err := config.Certificate.WriteTo(&cert); err != nil {
		return nil, err
	}
	if config.Intermediate != nil {
		if _, err := config.Intermediate.WriteTo(&intermediate); err != nil {
			return nil, err
		}
	}

	s := Server{
		udpConn: conn,
		config:  config,

		handshakes:         make(map[string]*HandshakeState),
		sessions:           make(map[SessionID]*SessionState),
		pendingConnections: make(chan *Handle, config.maxPendingConnections()),
		outgoing:           make(chan outgoing), // TODO(dadrian): Is this the appropriate size?

		staticKey:    config.KeyPair,
		certificate:  cert.Bytes(),
		intermediate: intermediate.Bytes(),
	}
	// TODO(dadrian): This probably shouldn't happen in this function
	_, err := rand.Read(s.cookieKey[:])
	if err != nil {
		panic(err.Error())
	}
	s.cookieCipher, err = aes.NewCipher(s.cookieKey[:])
	if err != nil {
		panic(err.Error())
	}
	return &s, nil
}
