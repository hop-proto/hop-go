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

// Server implements a Hop server capable of multiplexing roaming Hop
// connections.
//
// To run, call Serve.
type Server struct {
	m sync.RWMutex

	// +checklocks:serveLock
	rawRead []byte
	// +checklocks:serveLock
	handshakeBuf []byte

	udpConn UDPLike
	config  ServerConfig

	closed common.AtomicBool

	// +checklocks:m
	handshakes map[string]*HandshakeState
	// TODO(hosono) what should the keys of this map be?
	// Currently it's the string representation of the remote address

	// +checklocks:m
	handles map[SessionID]*Handle

	pendingConnections chan *Handle

	// +checklocks:cookieLock
	cookieKey        [KeyLen]byte
	cookieLock       sync.Mutex
	stopCookieRotate chan struct{}

	wg sync.WaitGroup

	// scratch space to decrypt messages into
	// +checklocks:serveLock
	plaintext []byte

	// scratch space for unauthenticated handshakes
	// +checklocks:serveLock
	scratchHS HandshakeState

	// This lock ensures that Serve() is called exactly once on a given server
	// using sync.Once would be more correct, but checklocks cannot verify that Serve()
	// has exclusive access to certain buffers
	// TODO(hosono) confirm that there is not a better way to do this
	serveLock sync.Mutex
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

	// Give the handshake a sessionID
	handshakeSet := false
	for i := 0; i < 100; i++ {
		n, err := rand.Read(hs.sessionID[:])
		if n != SessionIDLen || err != nil {
			panic("could not read random data")
		}
		if _, exists := s.handles[hs.sessionID]; !exists {
			s.handles[hs.sessionID] = s.createHandleLocked(hs)
			handshakeSet = true
			break
		}
	}
	if !handshakeSet {
		return false
	}

	// Delete handshake if the connection times out
	time.AfterFunc(s.config.HandshakeTimeout, func() {
		s.m.Lock()
		defer s.m.Unlock()
		hs := s.fetchHandshakeStateLocked(remoteAddr)
		if hs != nil {
			logrus.Errorf("Connection to %s timed out", remoteAddr)
			s.clearHandshakeStateLocked(remoteAddr)
			h := s.fetchHandleLocked(hs.sessionID)
			if h != nil {
				s.clearHandleLocked(h.ss.sessionID)
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

// +checklocks:s.m
func (s *Server) clearHandshakeStateLocked(remoteAddr *net.UDPAddr) {
	key := AddressHashKey(remoteAddr)
	hs := s.handshakes[key]
	if s.handles[hs.sessionID] == nil {
		delete(s.handles, hs.sessionID)
	}
	delete(s.handshakes, key)
}

func (s *Server) fetchHandle(sessionID SessionID) *Handle {
	s.m.RLock()
	defer s.m.RUnlock()
	return s.fetchHandleLocked(sessionID)
}

// +checklocksread:s.m
func (s *Server) fetchHandleLocked(sessionID SessionID) *Handle {
	return s.handles[sessionID]
}

func (s *Server) clearHandle(sessionID SessionID) {
	s.m.Lock()
	defer s.m.Unlock()
	s.clearHandleLocked(sessionID)
}

// +checklocks:s.m
func (s *Server) clearHandleLocked(sessionID SessionID) {
	delete(s.handles, sessionID)
}

func (s *Server) writePacket(pkt []byte, dst *net.UDPAddr) error {
	_, _, err := s.udpConn.WriteMsgUDP(pkt, nil, dst)
	return err
}

// +checklocks:s.serveLock
func (s *Server) readPacket() error {
	msgLen, oobn, flags, addr, err := s.udpConn.ReadMsgUDP(s.rawRead, nil)
	if err != nil {
		return err
	}
	logrus.Trace(msgLen, oobn, flags, addr)
	if msgLen < 4 {
		return ErrInvalidMessage
	}
	mt := MessageType(s.rawRead[0])
	switch mt {
	case MessageTypeClientHello:
		s.cookieLock.Lock()
		defer s.cookieLock.Unlock()
		err := s.handleClientHello(s.rawRead[:msgLen])
		if err != nil {
			return err
		}
		logrus.Debugf("server: client ephemeral: %x", s.scratchHS.remoteEphemeral)
		s.scratchHS.cookieKey = s.cookieKey
		s.scratchHS.remoteAddr = addr
		n, err := writeServerHello(&s.scratchHS, s.handshakeBuf)
		if err != nil {
			return err
		}
		logrus.Debugf("server: sh %x", s.handshakeBuf[:n])
		if err := s.writePacket(s.handshakeBuf[:n], addr); err != nil {
			return err
		}

		// reset scratch space to avoid lingering data
		s.scratchHS = HandshakeState{}
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
			logrus.Debugf("server: failed to make new handshake with %s", addr.String())
			return ErrUnexpectedMessage
		}
		n, err = s.writeServerAuth(s.handshakeBuf, hs)
		if err != nil {
			return err
		}
		err = s.writePacket(s.handshakeBuf[:n], addr)
		if err != nil {
			return err
		}
	case MessageTypeClientAuth:
		logrus.Debug("server: received client auth with length ", msgLen)
		logrus.Tracef("server: raw read: %x", s.rawRead[:msgLen])

		_, hs, err := s.handleClientAuth(s.rawRead[:msgLen], addr)
		if err != nil {
			return err
		}
		logrus.Debug("server: finishHandshakeLocked")
		s.finishHandshake(hs)
	case MessageTypeServerHello, MessageTypeServerAuth:
		// Server-side should not receive messages only sent by the server
		return ErrUnexpectedMessage
	case MessageTypeTransport, MessageTypeControl:
		logrus.Tracef("server: received transport/control message from %s", addr)
		_, err := s.handleSessionMessage(addr, s.rawRead[:msgLen])
		if err != nil {
			return err
		}
		return nil
	default:
		// If the message is authenticated, this will closed the connection
		s.handleSessionMessage(addr, s.rawRead[:msgLen])
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
	logrus.Tracef("server: session ID %x", hs.sessionID[:])
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
	h := s.fetchHandle(hs.sessionID)
	if h == nil {
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

	h.SetClientLeaf(leaf)

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

// writes decrypted packet into s.plaintext
// +checklocks:s.serveLock
func (s *Server) readPacketFromSession(ss *SessionState, pkt []byte, key *[KeyLen]byte) (int, MessageType, error) {
	return ss.readPacket(s.plaintext, pkt, &ss.clientToServerKey)
}

// +checklocks:s.serveLock
func (s *Server) handleSessionMessage(addr *net.UDPAddr, msg []byte) (int, error) {
	sessionID, err := PeekSession(msg)
	if err != nil {
		return 0, err
	}
	logrus.Tracef("server: transport/control message for session %x", sessionID)
	h := s.fetchHandle(sessionID)
	if h == nil {
		return 0, ErrUnknownSession
	}

	if h.getState() == closed {
		return 0, io.EOF
	}

	n, mt, err := s.readPacketFromSession(h.ss, msg, &h.ss.clientToServerKey)
	if err != nil {
		return 0, err
	}

	logrus.Tracef("server: session %x: plaintextLen: %d type: %x from: %s", h.ss.sessionID, n, mt, addr)

	switch mt {
	case MessageTypeTransport:
		select {
		case h.recv.C <- append([]byte{}, s.plaintext[:n]...):
			break
		default:
			logrus.Warnf("session %x: recv queue full, dropping packet", sessionID)
		}
	case MessageTypeControl:
		h.handleControl(s.plaintext[:n])
	default:
		// Close the connection on an unknown message type
		h.Close()
		return 0, ErrInvalidMessage
	}

	h.writeLock.Lock()
	defer h.writeLock.Unlock()
	if !EqualUDPAddress(h.ss.remoteAddr, addr) {
		h.ss.remoteAddr = addr
	}
	return n, nil
}

// Serve blocks until the server is closed.
func (s *Server) Serve() error {
	s.wg.Add(3)

	go func() {
		defer s.wg.Done()

		s.serveLock.Lock()
		defer s.serveLock.Unlock()

		// TODO(dadrian): These should be smaller buffers
		s.rawRead = make([]byte, 65535)
		s.handshakeBuf = make([]byte, 65535)

		for !s.closed.Load() {
			err := s.readPacket()
			logrus.Tracef("read a packet")
			if err != nil {
				// this prevents logging an error upon closing the server
				if !(errors.Is(err, net.ErrClosed) && s.closed.Load()) {
					logrus.Errorf("server: %s", err)
				}
			}
		}
	}()

	go func() {
		defer s.wg.Done()

		for !s.closed.Load() {
			t := time.NewTicker(2 * time.Minute)
			select {
			case <-t.C:
				s.cookieLock.Lock()
				_, err := rand.Read(s.cookieKey[:])
				if err != nil {
					logrus.Panicf("rand.Read failed: %s", err.Error())
				}
				s.cookieLock.Unlock()
			case <-s.stopCookieRotate:
			}
		}
	}()

	s.wg.Done()
	s.wg.Wait()
	return nil
}

// +checklocks:s.serveLock
func (s *Server) handleClientHello(b []byte) error {
	s.scratchHS.duplex.InitializeEmpty()
	s.scratchHS.duplex.Absorb([]byte(ProtocolName))
	n, err := readClientHello(&s.scratchHS, b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return ErrInvalidMessage
	}
	s.scratchHS.ephemeral.Generate()
	return nil
}

func (s *Server) finishHandshake(hs *HandshakeState) error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.closed.Load() {
		return io.EOF
	}

	defer s.clearHandshakeStateLocked(hs.remoteAddr)
	h, exists := s.handles[hs.sessionID]
	if !exists {
		return ErrUnknownSession
	}

	// This allows the handshake to be dropped early if pendingoConnections if full
	if len(s.pendingConnections) == cap(s.pendingConnections) {
		logrus.Warnf("server: session %x: pending connections queue is full, dropping handshake", h.ss.sessionID)
		s.clearHandle(h.ss.sessionID)
		h.Close()
		return nil
	}

	logrus.Debugf("server: finishing handshake for session %x", h.ss.sessionID)

	err := hs.deriveFinalKeys(&h.ss.clientToServerKey, &h.ss.serverToClientKey)
	if err != nil {
		return err
	}

	h.m.Lock()
	h.state = established
	h.m.Unlock()

	select {
	case s.pendingConnections <- h:
		break
	default:
		logrus.Warnf("server: session %x: pending connections queue is full, dropping handshake", h.ss.sessionID)
		s.clearHandle(h.ss.sessionID)
		h.Close()
	}
	return nil
}

// +checklocks:s.m
func (s *Server) createHandleLocked(hs *HandshakeState) *Handle {
	handle := &Handle{
		recv:   common.NewDeadlineChan[[]byte](s.config.maxBufferedPacketsPerConnection()),
		send:   common.NewDeadlineChan[message](s.config.maxBufferedPacketsPerConnection()),
		ss:     &SessionState{},
		server: s,
	}

	s.handles[hs.sessionID] = handle
	handle.ss.sessionID = hs.sessionID
	handle.ss.remoteAddr = hs.remoteAddr
	return handle
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
	case handle := <-s.pendingConnections:
		logrus.Debug("got a handle")
		h := s.fetchHandle(handle.ss.sessionID)
		if h != handle {
			// Should never happen
			return nil, ErrUnknownSession
		}
		h.Start()
		return handle, nil
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Addr returns the net.UDPAddr used by the underlying connection.
// It reflects the net.Listener API
func (s *Server) Addr() net.Addr {
	return s.udpConn.LocalAddr()
}

// CloseSession gracefully closes one hop session
func (s *Server) CloseSession(sessionID SessionID) error {
	h := s.fetchHandle(sessionID)
	if h != nil {
		return h.Close()
	}
	return nil
}

// Close stops the server, causing Serve() to return.
func (s *Server) Close() (err error) {
	// This will end the reading goroutine and wait for it to exit
	if s.closed.Load() {
		return io.EOF
	}

	s.m.Lock()
	s.closed.Store(true)

	close(s.stopCookieRotate)

	wg := sync.WaitGroup{}

	for _, h := range s.handles {
		if h != nil {
			wg.Add(1)
			go func(h *Handle) {
				defer wg.Done()
				h.Close()
			}(h)
		}
	}

	close(s.pendingConnections)
	for h := range s.pendingConnections {
		if h != nil {
			wg.Add(1)
			go func(h *Handle) {
				defer wg.Done()
				h.Close()
			}(h)
		} else {
			logrus.Error("server: nil handle in pending connections")
		}
	}
	s.m.Unlock()

	// wait for all handles to close
	wg.Wait()

	s.udpConn.Close()
	s.wg.Wait()

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
	s.handles = make(map[SessionID]*Handle)

	s.pendingConnections = make(chan *Handle, s.config.maxPendingConnections())
	return nil
}

// NewServer returns a Server listening on the provided UDP connection. The
// returned Server object is a valid net.Listener.
func NewServer(conn UDPLike, config ServerConfig) (*Server, error) {
	s := Server{
		udpConn:          conn,
		config:           config,
		plaintext:        make([]byte, 65535),
		stopCookieRotate: make(chan struct{}),
	}
	err := s.init()
	return &s, err
}
