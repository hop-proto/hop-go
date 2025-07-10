package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
)

type serverState uint32

const (
	serverStateReady   serverState = 0
	serverStateServing serverState = 1
	serverStateClosing serverState = 2
	serverStateClosed  serverState = 3
)

// Server implements a Hop server capable of multiplexing roaming Hop
// connections.
//
// To run, call Serve.
type Server struct {
	m sync.RWMutex

	udpConn UDPLike
	config  ServerConfig

	state atomic.Uint32

	// +checklocks:m
	handshakes map[string]*HandshakeState
	// +checklocks:m
	sessions map[SessionID]*SessionState

	pendingConnections chan *Handle

	// +checklocks:cookieLock
	cookieKey        [KeyLen]byte
	cookieLock       sync.Mutex
	stopCookieRotate chan struct{}

	wg        sync.WaitGroup
	closeWait sync.WaitGroup
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
	hs.remoteAddr = remoteAddr

	s.createSessionFromHandshakeLocked(hs)

	// Delete handshake if the connection times out
	// TODO(dadrian)[2023-09-09]: Is there a race condition here? Should we be
	// selecting over two channels---one that gets a message after the handshake
	// finishes, and one after a timeout instead?
	time.AfterFunc(s.config.HandshakeTimeout, func() {
		s.m.Lock()
		defer s.m.Unlock()
		hs := s.fetchHandshakeStateLocked(remoteAddr)
		if hs != nil {
			logrus.Errorf("Connection to %s timed out during handshake", remoteAddr)
			s.stopTrackingHandshakeStateLocked(remoteAddr)
			ss := s.fetchSessionLocked(hs.sessionID)
			if ss != nil {
				s.stopTrackingSessionLocked(ss.sessionID)
			}
		} else {
			logrus.Debugf("Connection to %s did not time out", remoteAddr)
		}
	})
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

// TODO(hosono) fix lint error
// nolint
func (s *Server) stopTrackingHandhshakeState(remoteAddr *net.UDPAddr) {
	s.m.Lock()
	defer s.m.Unlock()
	s.stopTrackingHandshakeStateLocked(remoteAddr)
}

// +checklocks:s.m
func (s *Server) stopTrackingHandshakeStateLocked(remoteAddr *net.UDPAddr) {
	key := AddressHashKey(remoteAddr)
	delete(s.handshakes, key)
}

func (s *Server) fetchSession(sessionID SessionID) *SessionState {
	s.m.RLock()
	defer s.m.RUnlock()
	return s.fetchSessionLocked(sessionID)
}

// +checklocksread:s.m
func (s *Server) fetchSessionLocked(sessionID SessionID) *SessionState {
	return s.sessions[sessionID]
}

func (s *Server) stopTrackingSession(sessionID SessionID) {
	s.m.Lock()
	defer s.m.Unlock()
	s.stopTrackingSessionLocked(sessionID)
}

// +checklocks:s.m
func (s *Server) stopTrackingSessionLocked(sessionID SessionID) {
	delete(s.sessions, sessionID)
}

func (s *Server) writePacket(pkt []byte, dst *net.UDPAddr) error {
	_, _, err := s.udpConn.WriteMsgUDP(pkt, nil, dst)
	return err
}

func (s *Server) readPacket(rawRead []byte, handshakeWriteBuf []byte) error {
	msgLen, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(rawRead, nil)
	if err != nil {
		return err
	}
	if common.Debug {
		logrus.Trace(msgLen, oobn, flags, addr)
	}
	if msgLen < 4 {
		return ErrInvalidMessage
	}
	mt := MessageType(rawRead[0])
	switch mt {
	case MessageTypeClientHello:
		s.cookieLock.Lock()
		defer s.cookieLock.Unlock()
		scratchHS, err := s.handleClientHello(rawRead[:msgLen])
		if err != nil {
			return err
		}
		logrus.Debugf("server: client ephemeral: %x", scratchHS.dh.remoteEphemeral)
		scratchHS.cookieKey = s.cookieKey
		scratchHS.remoteAddr = addr
		n, err := writeServerHello(scratchHS, handshakeWriteBuf)
		if err != nil {
			return err
		}
		logrus.Debugf("server: sh %x", handshakeWriteBuf[:n])
		if err := s.writePacket(handshakeWriteBuf[:n], addr); err != nil {
			return err
		}
	case MessageTypeClientAck:
		logrus.Debug("server: about to handle client ack")
		n, hs, err := s.handleClientAck(rawRead[:msgLen], addr)
		if err != nil {
			logrus.Debugf("server: unable to handle client ack: %s", err)
			return err
		}
		if n != msgLen {
			logrus.Debug("client ack had extra data")
			return ErrInvalidMessage
		}
		hs.certVerify = s.config.ClientVerify
		s.setHandshakeState(addr, hs)
		n, err = s.writeServerAuth(handshakeWriteBuf, hs)
		if err != nil {
			return err
		}
		err = s.writePacket(handshakeWriteBuf[:n], addr)
		if err != nil {
			return err
		}
	case MessageTypeClientAuth:
		if common.Debug {
			logrus.Debug("server: received client auth with length ", msgLen)
			logrus.Tracef("server: raw read: %x", rawRead[:msgLen])
		}

		_, hs, err := s.handleClientAuth(rawRead[:msgLen], addr)
		if err != nil {
			return err
		}
		logrus.Debug("server: finishHandshake")
		if err := s.finishHandshake(hs, false); err != nil {
			return err
		}
		logrus.Debug("server: finished handshake!")
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	case MessageTypeTransport, MessageTypeControl:
		if common.Debug {
			logrus.Tracef("server: received transport/control message from %s", addr)
		}
		err := s.handleSessionMessage(addr, rawRead[:msgLen])
		if err != nil {
			return err
		}
		return nil

	case MessageTypeClientRequestHidden:
		logrus.Debug("server: receiving a hidden client request to handle")
		n, hs, err := s.handleClientRequestHidden(rawRead[:msgLen])
		if err != nil {
			logrus.Debugf("server: unable to handle client hidden request: %s", err)
			return err
		}
		if n != msgLen {
			logrus.Debug("server: client hidden request had extra data")
			return ErrInvalidMessage
		}

		s.setHandshakeState(addr, hs)
		n, err = s.writeServerResponseHidden(hs, handshakeWriteBuf)
		logrus.Debugf("server: sh %x", handshakeWriteBuf[:n])
		if err := s.writePacket(handshakeWriteBuf[:n], addr); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		logrus.Debug("server: finishHandshake hidden mode")
		if err := s.finishHandshake(hs, true); err != nil {
			return err
		}
		logrus.Debug("server: finished handshake!")

	default:
		// If the message is authenticated, this will closed the connection
		// TODO(dadrian)[2023-09-09]: Make this explicit
		s.handleSessionMessage(addr, rawRead[:msgLen])
		return ErrInvalidMessage
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

func (s *Server) writeServerAuth(b []byte, hs *HandshakeState) (int, error) {
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
	copy(x, hs.sessionID[:])
	if common.Debug {
		logrus.Tracef("server: session ID %x", hs.sessionID[:])
	}
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
	hs.dh.es, err = c.Exchanger.Agree(hs.dh.remoteEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(es)")
		return pos, err
	}
	logrus.Debugf("server es: %x", hs.dh.es)
	hs.duplex.Absorb(hs.dh.es)
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
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("server: error parsing client certificates: %s", err)
		return pos, nil, err
	}
	hs.parsedLeaf = &leaf

	hs.dh.se, err = hs.dh.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("server: unable to calculated se: %s", err)
		return pos, nil, err
	}
	logrus.Debugf("server: se %x", hs.dh.se)
	hs.duplex.Absorb(hs.dh.se)
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

func (s *Server) handleSessionMessage(addr *net.UDPAddr, msg []byte) error {
	sessionID, err := PeekSession(msg)
	if err != nil {
		return err
	}
	if common.Debug {
		logrus.Tracef("server: transport/control message for session %x", sessionID)
	}
	ss := s.fetchSession(sessionID)
	if ss == nil {
		return ErrUnknownSession
	}
	ss.m.Lock()
	defer ss.m.Unlock()

	// TODO(dadrian): Can we avoid this allocation?
	plaintext := make([]byte, PlaintextLen(len(msg)))
	_, mt, err := ss.readPacketLocked(plaintext, msg, ss.readKey)
	if err != nil {
		return err
	}
	if common.Debug {
		logrus.Tracef("server: session %x: plaintextLen: %d type: %x from: %s", ss.sessionID, len(plaintext), mt, addr)
	}

	switch mt {
	case MessageTypeTransport:
		select {
		case ss.handle.recv.C <- plaintext:
			break
		default:
			logrus.Warnf("session %x: recv queue full, dropping packet", sessionID)
		}
	case MessageTypeControl:
		if err := ss.handleControlLocked(plaintext); err != nil {
			return err
		}
	default:
		// Close the connection on an unknown message type
		ss.closeLocked()
		return ErrInvalidMessage
	}

	if !EqualUDPAddress(ss.remoteAddr, addr) {
		ss.remoteAddr = addr
	}
	return nil
}

// Serve blocks until the server is closed.
func (s *Server) Serve() error {
	// TODO(dadrian)[2023-09-09]: Handle the case where this function is
	// erroneously called twice.
	if !s.state.CompareAndSwap(uint32(serverStateReady), uint32(serverStateServing)) {
		return errors.New("Serve called on non-ready Server")
	}
	s.wg.Add(3)

	go func() {
		defer s.wg.Done()

		// TODO(dadrian): These should be smaller buffers
		rawRead := make([]byte, 65535)
		handshakeWriteBuf := make([]byte, 65535)

		for s.state.Load() == uint32(serverStateServing) {
			err := s.readPacket(rawRead, handshakeWriteBuf)
			if err != nil {
				state := serverState(s.state.Load())
				if state != serverStateServing {
					continue
				}
				logrus.Errorf("server error: %s", err)
			}
		}
	}()

	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for s.state.Load() == uint32(serverStateServing) {
			select {
			case <-ticker.C:
				s.cookieLock.Lock()
				// TODO(dadrian)[2023-09-10]: Save the previous cookie
				_, err := rand.Read(s.cookieKey[:])
				if err != nil {
					logrus.Panicf("rand.Read failed: %s", err.Error())
				}
				s.cookieLock.Unlock()
			case <-s.stopCookieRotate:
				return
			}
		}
	}()

	s.wg.Done()
	s.wg.Wait()
	return nil
}

func (s *Server) handleClientHello(b []byte) (*HandshakeState, error) {
	scratchHS := &HandshakeState{}
	scratchHS.duplex.InitializeEmpty()
	scratchHS.duplex.Absorb([]byte(ProtocolName))
	n, err := readClientHello(scratchHS, b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, ErrInvalidMessage
	}
	scratchHS.dh.ephemeral.Generate()
	return scratchHS, nil
}

func (s *Server) finishHandshake(hs *HandshakeState, isHidden bool) error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.state.Load() != uint32(serverStateServing) {
		return io.EOF
	}

	defer s.stopTrackingHandshakeStateLocked(hs.remoteAddr)
	ss := s.fetchSessionLocked(hs.sessionID)
	if ss == nil {
		return ErrUnknownSession
	}
	logrus.Debugf("server: finishing handshake for session %x", ss.sessionID)

	// Probably unnecessary
	ss.m.Lock()
	defer ss.m.Unlock()

	err := hs.deriveFinalKeys(&ss.clientToServerKey, &ss.serverToClientKey)
	if err != nil {
		return err
	}
	ss.readKey = &ss.clientToServerKey
	ss.writeKey = &ss.serverToClientKey

	ss.isHiddenHS = isHidden

	ss.handle = newHandleForSession(s.udpConn, ss, hs.parsedLeaf, s.config.maxBufferedPacketsPerConnection())
	ss.handleState = established

	h := ss.handle
	select {
	case s.pendingConnections <- h:
		break
	default:
		logrus.Warnf("server: session %x: pending connections queue is full, dropping handshake", ss.sessionID)
		ss.closeLocked()
	}
	return nil
}

func (s *Server) handleClientRequestHidden(b []byte) (int, *HandshakeState, error) {
	hs := &HandshakeState{}
	hs.duplex.InitializeEmpty()
	hs.dh.ephemeral.Generate()

	hs.duplex.Absorb([]byte(HiddenProtocolName))
	hs.RekeyFromSqueeze(HiddenProtocolName)

	n, err := s.readClientRequestHidden(hs, b)

	if err != nil {
		return n, nil, err
	}
	if n != len(b) {
		return n, nil, ErrInvalidMessage
	}
	return n, hs, nil
}

// +checklocks:s.m
func (s *Server) createSessionFromHandshakeLocked(hs *HandshakeState) *SessionState {
	for i := 0; i < 100; i++ {
		n, err := rand.Read(hs.sessionID[:])
		if n != SessionIDLen || err != nil {
			panic("could not read random data")
		}
		if _, exists := s.sessions[hs.sessionID]; exists {
			continue
		}
		ss := &SessionState{
			sessionID:  hs.sessionID,
			remoteAddr: hs.remoteAddr,
		}
		s.sessions[hs.sessionID] = ss
		return ss
	}
	panic("unable to generate a non-colliding sessionID")
}

// Accept wraps AcceptTimeout with no timeout set. This reflects the net.Listener API
func (s *Server) Accept() (*Handle, error) {
	for {
		h, err := s.AcceptTimeout(5 * time.Second)
		if err != ErrTimeout {
			return h, err
		}
	}
}

// AcceptTimeout blocks for up to duration until a new connection is available.
func (s *Server) AcceptTimeout(duration time.Duration) (*Handle, error) {
	logrus.Debug("accept timeout started")
	timer := time.NewTimer(duration)
	select {
	case handle, ok := <-s.pendingConnections:
		if ok {
			return handle, nil
		}
		return nil, io.EOF
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Addr returns the net.UDPAddr used by the underlying connection.
// It reflects the net.Listener API
func (s *Server) Addr() net.Addr {
	return s.udpConn.LocalAddr()
}

// Close stops the server, causing Serve() to return.
func (s *Server) Close() (err error) {
	s.closeWait.Add(1)
	for !s.state.CompareAndSwap(uint32(serverStateServing), uint32(serverStateClosing)) {
		cur := serverState(s.state.Load())
		switch cur {
		case serverStateReady:
			if s.state.CompareAndSwap(uint32(serverStateReady), uint32(serverStateClosed)) {
				s.closeWait.Done()
				return nil
			}
		case serverStateClosing:
			s.closeWait.Done()
			s.closeWait.Wait()
			return nil
		case serverStateClosed:
			s.closeWait.Done()
			return nil
		}
	}
	defer s.closeWait.Done()

	// Stop reading packets
	s.udpConn.SetReadDeadline(time.Now())
	// Stop rotating cookies inside readPacket
	close(s.stopCookieRotate)
	// Wait for read packet to finish
	s.wg.Wait()

	// Close the channels
	close(s.pendingConnections)

	// Drain everything and close the connections
	wg := sync.WaitGroup{}
	func() {
		s.m.Lock()
		defer s.m.Unlock()
		for h := range s.pendingConnections {
			wg.Add(1)
			go func(h *Handle) {
				defer wg.Done()
				h.Close()
			}(h)
		}
		for _, ss := range s.sessions {
			wg.Add(1)
			go func(ss *SessionState) {
				defer wg.Done()
				if ss.handle != nil {
					ss.handle.Close()
				}
				s.stopTrackingSession(ss.sessionID)
			}(ss)
		}
	}()
	wg.Wait()
	s.udpConn.Close()
	return nil
}

func (s *Server) init() error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.config.KeyPair == nil && s.config.GetCertificate == nil {
		return errors.New("config.KeyPair or config.GetCertificate must be set")
	}
	if s.config.Certificate == nil && s.config.GetCertificate == nil {
		return errors.New("Certificate must be set when GetCertificate is Nil")
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
		s.config.GetCertList = func() ([]*Certificate, error) {
			return []*Certificate{c}, nil
		}
	}

	s.cookieLock.Lock()
	_, err := rand.Read(s.cookieKey[:])
	s.cookieLock.Unlock()
	if err != nil {
		panic(err.Error())
	}

	if err != nil {
		panic(err.Error())
	}

	s.handshakes = make(map[string]*HandshakeState)
	s.sessions = make(map[SessionID]*SessionState)
	s.pendingConnections = make(chan *Handle, s.config.maxPendingConnections())
	return nil
}

// NewServer returns a Server listening on the provided UDP connection. The
// returned Server object is a valid net.Listener.
func NewServer(conn UDPLike, config ServerConfig) (*Server, error) {
	s := Server{
		udpConn:          conn,
		config:           config,
		stopCookieRotate: make(chan struct{}),
	}
	err := s.init()
	return &s, err
}
