package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
)

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
	config  ServerConfig

	closed atomicBool

	// +checklocks:m
	handshakes map[string]*HandshakeState
	// +checklocks:m
	sessions map[SessionID]*SessionState

	pendingConnections chan *Handle
	outgoing           chan outgoing

	cookieKey [KeyLen]byte
}

//FetchClientLeaf returns the client leaf certificate used in handshake with associated handle's sessionID
func (s *Server) FetchClientLeaf(h *Handle) certs.Certificate {
	s.m.RLock()
	defer s.m.RUnlock()
	ss := s.sessions[h.sessionID]
	return ss.clientLeaf
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

	// Delete handshake if the connection times out
	go func(s *Server, remoteAddr *net.UDPAddr) {
		timer := time.NewTimer(s.config.HandshakeTimeout)
		<-timer.C
		s.m.Lock()
		defer s.m.Unlock()
		hs := s.fetchHandshakeStateLocked(remoteAddr)
		if hs != nil {
			logrus.Errorf("Connection to %s timed out", remoteAddr)
			s.clearHandshakeStateLocked(remoteAddr)
			ss := s.fetchSessionStateLocked(hs.sessionID)
			if ss != nil {
				s.clearSessionState(ss.sessionID)
			}
		} else {
			logrus.Infof("Connection to %s did not time out", remoteAddr)
		}
	}(s, remoteAddr)

	return true
}

func (s *Server) fetchHandshakeState(remoteAddr *net.UDPAddr) *HandshakeState {
	s.m.RLock()
	defer s.m.RUnlock()
	return s.fetchHandshakeStateLocked(remoteAddr)
}

// +checklocksread:s.m
func (s *Server) fetchHandshakeStateLocked(remoteAddr *net.UDPAddr) *HandshakeState {
	key := AddressHashKey(remoteAddr)
	return s.handshakes[key]
}

// +checklocks:s.m
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

// +checklocksread:s.m
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
		hs.certVerify = s.config.ClientVerify
		if !s.setHandshakeState(addr, hs) {
			logrus.Debugf("server: already have handshake in progress with %s", addr.String())
			return ErrUnexpectedMessage
		}
		ss, err := s.newSessionState()
		copy(hs.sessionID[:], ss.sessionID[:])
		ss.remoteAddr = addr
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
		logrus.Debug("server: received client auth with length ", msgLen)
		logrus.Debug(s.rawRead[:msgLen])

		_, hs, err := s.handleClientAuth(s.rawRead[:msgLen], addr)
		if err != nil {
			return err
		}
		logrus.Debug("server: finishHandshakeLocked")
		s.finishHandshake(hs)
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
	hs.sni = name

	return length, hs, err
}

func (s *Server) writeServerAuth(b []byte, hs *HandshakeState, ss *SessionState) (int, error) {
	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: hs.sni,
	})
	if err != nil {
		return 0, err
	}
	encCertLen := EncryptedCertificatesLength(c.RawLeaf, c.RawIntermediate)
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
	encCerts, err := EncryptCertificates(&hs.duplex, c.RawLeaf, c.RawIntermediate)
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
	hs.es, err = c.Exchanger.Agree(hs.remoteEphemeral[:])
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

func (s *Server) handleClientAuth(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	x := b
	pos := 0
	if len(b) < HeaderLen {
		logrus.Debug("server: client auth missing header")
		return 0, nil, ErrBufUnderflow
	}
	encCertsLen := (int(b[2]) << 8) + int(b[3])
	if len(b) < HeaderLen+SessionIDLen+encCertsLen+MacLen {
		logrus.Debug("server: client auth too short")
		return 0, nil, ErrBufUnderflow
	}

	if mt := MessageType(b[0]); mt != MessageTypeClientAuth {
		return 0, nil, ErrUnexpectedMessage
	}
	if b[1] != 0 {
		return 0, nil, ErrInvalidMessage
	}
	hs := s.fetchHandshakeState(addr)
	if hs == nil {
		logrus.Debugf("server: no handshake state for handshake packet from %s", addr)
		return pos, nil, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	sessionID := x[:SessionIDLen]
	if !bytes.Equal(hs.sessionID[:], sessionID) {
		logrus.Debugf("server: mismatched session ID for %s: expected %x, got %x", addr, hs.sessionID, sessionID)
		return pos, nil, ErrUnexpectedMessage
	}
	ss := s.fetchSessionState(hs.sessionID)
	if ss == nil {
		logrus.Debugf("server: could not find session ID %x", hs.sessionID)
		return pos, nil, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(sessionID)
	x = x[SessionIDLen:]
	pos += SessionIDLen
	encCerts := x[:encCertsLen]
	rawLeaf, rawIntermediate, err := DecryptCertificates(&hs.duplex, encCerts)
	if err != nil {
		return pos, nil, err
	}
	x = x[encCertsLen:]
	pos += encCertsLen
	hs.duplex.Squeeze(hs.macBuf[:])
	clientTag := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientTag) {
		logrus.Debugf("server: mismatched tag in client auth: expected %x, got %x", hs.macBuf, clientTag)
		return pos, nil, ErrInvalidMessage
	}
	x = x[MacLen:]
	pos += MacLen
	// Parse certificates
	opts := certs.VerifyOptions{}
	if hs.certVerify != nil {
		logrus.Error("YAY")
		opts.Name = hs.certVerify.Name
	}
	leaf := certs.Certificate{}
	leafLen, err := leaf.ReadFrom(bytes.NewBuffer(rawLeaf))
	if err != nil {
		return pos, nil, err
	}
	if int(leafLen) != len(rawLeaf) {
		return pos, nil, errors.New("extra bytes after leaf certificate")
	}
	hs.clientLeaf = leaf

	intermediate := certs.Certificate{}
	if len(rawIntermediate) > 0 {
		intermediateLen, err := intermediate.ReadFrom(bytes.NewBuffer(rawIntermediate))
		if err != nil {
			return pos, nil, err
		}
		if int(intermediateLen) != len(rawIntermediate) {
			return pos, nil, errors.New("extra bytes after intermediate certificate")
		}
		opts.PresentedIntermediate = &intermediate
	}

	if hs.certVerify != nil && !hs.certVerify.InsecureSkipVerify {
		err := hs.certVerify.Store.VerifyLeaf(&leaf, opts)
		if err != nil {
			logrus.Errorf("server: failed to verify certificate: %s", err)
			return pos, nil, err
		}
	}

	hs.se, err = hs.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("server: unable to calculated se: %s", err)
		return pos, nil, err
	}
	logrus.Debugf("server: se %x", hs.se)
	hs.duplex.Absorb(hs.se)
	hs.duplex.Squeeze(hs.macBuf[:]) // mac
	clientMac := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientMac) {
		logrus.Debugf("server: mismatched mac in client auth: expected %x, got %x", hs.macBuf, clientMac)
		return pos, nil, ErrInvalidMessage
	}
	// x = x[MacLen:]
	pos += MacLen
	return pos, hs, nil
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
	if !EqualUDPAddress(ss.remoteAddr, addr) {
		ss.remoteAddr = addr
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
			logrus.Debug("read a packet")
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

func (s *Server) finishHandshake(hs *HandshakeState) error {
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
	ss.clientLeaf = hs.clientLeaf
	//hs.leaf
	// TODO(dadrian): Create this earlier on so that the handshake fails earlier
	// if the queue is full.
	h := s.createHandleLocked(ss)
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

func (s *Server) createHandleLocked(ss *SessionState) *Handle {
	handle := &Handle{
		sessionID:    ss.sessionID,
		recv:         make(chan []byte, s.config.maxBufferedPacketsPerConnection()),
		send:         make(chan []byte, s.config.maxBufferedPacketsPerConnection()),
		readTimeout:  atomicTimeout(s.config.StartingReadTimeout),
		writeTimeout: atomicTimeout(s.config.StartingWriteTimeout),
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
	logrus.Debug("accept timeout started")
	timer := time.NewTicker(duration)
	select {
	case handle := <-s.pendingConnections:
		logrus.Debug("got a handle")
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

// ListenAddress returns the net.UDPAddr used by the underlying connection.
func (s *Server) ListenAddress() net.Addr {
	return s.udpConn.LocalAddr()
}

// Close stops the server, causing Serve() to return.
//
// TODO(dadrian): What does it do to writes?
func (s *Server) Close() error {
	// TODO(dadrian): #concurrency
	s.closed.setTrue()
	return nil
}

func (s *Server) init() error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.config.KeyPair == nil && s.config.GetCertificate == nil {
		return errors.New("config.KeyPair or config.GetCertificate must be set")
	}
	if s.config.Certificate == nil && s.config.GetCertificate == nil {
		return errors.New("Certificate must be set when GetCertificate is Nil") //nolint:stylecheck
	}

	if s.config.GetCertificate == nil {
		var cert, intermediate bytes.Buffer
		if _, err := s.config.Certificate.WriteTo(&cert); err != nil {
			return err
		}
		if s.config.Intermediate != nil {
			if _, err := s.config.Intermediate.WriteTo(&intermediate); err != nil {
				return err
			}
		}
		c := &Certificate{
			RawLeaf:         cert.Bytes(),
			RawIntermediate: intermediate.Bytes(),
			Exchanger:       s.config.KeyPair,
		}
		s.config.GetCertificate = func(ClientHandshakeInfo) (*Certificate, error) {
			return c, nil
		}
	}

	// TODO(dadrian): Let this be specified or rotated
	_, err := rand.Read(s.cookieKey[:])
	if err != nil {
		panic(err.Error())
	}

	if err != nil {
		panic(err.Error())
	}

	s.handshakes = make(map[string]*HandshakeState)
	s.sessions = make(map[SessionID]*SessionState)

	s.pendingConnections = make(chan *Handle, s.config.maxPendingConnections())
	s.outgoing = make(chan outgoing) // TODO(dadrian): Is this the appropriate size?
	return nil
}

// NewServer returns a Server listening on the provided UDP connection. The
// returned Server object is a valid net.Listener.
func NewServer(conn *net.UDPConn, config ServerConfig) (*Server, error) {
	s := Server{
		udpConn: conn,
		config:  config,
	}
	err := s.init()
	return &s, err
}
