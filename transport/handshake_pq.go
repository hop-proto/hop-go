package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/kravatte"
	"net"
)

var (
	errTruncatedEkem = errors.New("nyquist/HandshakeState/ReadMessage/ekem: truncated message")
	errTruncatedSkem = errors.New("nyquist/HandshakeState/ReadMessage/skem: truncated message")

	errMissingRe = errors.New("nyquist/HandshakeState/WriteMessage/ekem: re not set")
	errMissingRs = errors.New("nyquist/HandshakeState/WriteMessage/skem: rs not set")
)

// TODO paul: there are many many duplications, needs to refactor these with if statements, whenever the PQ would work

func writePQClientHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < PQHelloLen {
		return 0, ErrBufOverflow
	}
	x := b
	// Header
	x[0] = byte(MessageTypePQClientHello) // Type = ClientHello (0x01)
	x[1] = Version                        // Version
	x[2] = 0                              // Reserved
	x[3] = 0                              // Reserved
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]

	// Ephemeral
	ephemeralBytes := hs.kem.ephemeral.Public().Bytes()
	copy(x, ephemeralBytes[:])
	//hs.duplexAbsorbKem(x[:KemKeyLen])
	x = x[KemKeyLen:]

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("client: client hello mac: %x", x[:MacLen])
	return PQHelloLen, nil
}

func readPQClientHello(hs *HandshakeState, b []byte) (int, error) {

	var err error

	logrus.Debug("read PQ client hello")
	if len(b) < PQHelloLen {
		return 0, ErrBufUnderflow
	}
	if MessageType(b[0]) != MessageTypePQClientHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != Version {
		return 0, ErrUnsupportedVersion
	}
	if b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	hs.kem.remoteEphemeral, err = hs.kem.impl.ParsePublicKey(b[:KemKeyLen])
	if err != nil {
		return 0, err
	}

	//hs.duplexAbsorbKem(b[:KemKeyLen])
	b = b[KemKeyLen:]
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server: calculated client hello mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}
	return PQHelloLen, nil
}

func writePQServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+PQCookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	b[0] = byte(MessageTypePQServerHello)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Cookie
	n, err := hs.writePQCookie(b)
	logrus.Debugf("server: generated cookie %x", b[:n])
	if err != nil {
		return 0, err
	}
	if n != PQCookieLen {
		return 0, ErrBufOverflow
	}
	hs.duplex.Absorb(b[:PQCookieLen])
	b = b[PQCookieLen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server: sh mac %x", b[:MacLen])

	return HeaderLen + PQCookieLen + MacLen, nil
}

// the cyclist implementation has been thought to have absorption of max rKout 136 bytes
// TODO be sure that this split ensure the duplex security
// TODO we should not absorb Ct as non deterministic
func (hs *HandshakeState) duplexAbsorbKem(key []byte) {
	keyLen := len(key)
	chunk := keyLen / 8

	if chunk > 136 {
		panic(errTruncatedEkem)
	}

	for i := 0; i < 8; i++ {
		hs.duplex.Absorb(key[chunk*i : chunk*(i+1)])
	}
}

func readPQServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+PQCookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	if MessageType(b[0]) != MessageTypePQServerHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Cookie
	hs.cookie = make([]byte, PQCookieLen)
	copy(hs.cookie, b[:PQCookieLen])
	hs.duplex.Absorb(hs.cookie)
	logrus.Debugf("client: read PQCookie %x", hs.cookie)
	b = b[PQCookieLen:]

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: sh mac %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}

	return HeaderLen + PQCookieLen + MacLen, nil
}

func (hs *HandshakeState) writePQClientAck(b []byte) (int, error) {
	length := HeaderLen + KemKeyLen + PQCookieLen + SNILen + MacLen
	if len(b) < length {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypePQClientAck)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Ephemeral
	ephemeralBytes := hs.kem.ephemeral.Public().Bytes()
	copy(b, ephemeralBytes[:])
	//hs.duplexAbsorbKem(b[:KemKeyLen])
	b = b[KemKeyLen:]

	// Cookie
	n := copy(b, hs.cookie)
	if n != PQCookieLen {
		logrus.Debugf("unexpected PQ cookie length: %d (expected %d)", n, PQCookieLen)
		return HeaderLen + KemKeyLen + n, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:PQCookieLen])
	b = b[PQCookieLen:]

	// Encrypted SNI
	err := hs.EncryptSNI(b, hs.certVerify.Name)
	if err != nil {
		return HeaderLen + KemKeyLen + PQCookieLen, ErrInvalidMessage
	}
	b = b[SNILen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: PQ client ack mac: %x", b[:MacLen])

	return length, nil
}

func (s *Server) readPQClientAck(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	var buf [SNILen]byte
	length := HeaderLen + KemKeyLen + PQCookieLen + SNILen + MacLen
	if len(b) < length {
		return 0, nil, ErrBufUnderflow
	}
	if mt := MessageType(b[0]); mt != MessageTypePQClientAck {
		return 0, nil, ErrUnexpectedMessage
	}

	// Header
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, nil, ErrUnexpectedMessage
	}
	header := b[:HeaderLen]
	b = b[HeaderLen:]

	// Ephemeral
	ephemeral := b[:KemKeyLen]
	b = b[KemKeyLen:]
	logrus.Debugf("server: got client ephemeral again: %x", ephemeral)

	// Cookie
	cookie := b[:PQCookieLen]
	b = b[PQCookieLen:]

	hs, err := s.ReplayPQDuplexFromCookie(cookie, ephemeral, addr)
	if err != nil {
		return 0, nil, err
	}

	hs.duplex.Absorb(header)
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

func (s *Server) writePQServerAuth(b []byte, hs *HandshakeState) (int, error) {

	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: hs.sni,
	})

	if err != nil {
		return 0, err
	}
	encCertLen := EncryptedCertificatesLength(c.RawLeaf, c.RawIntermediate)
	if len(b) < HeaderLen+SessionIDLen+KemCtLen+encCertLen {
		return 0, ErrBufUnderflow
	}
	x := b
	pos := 0
	x[0] = byte(MessageTypePQServerAuth)
	x[1] = 0
	x[2] = byte(encCertLen >> 8)
	x[3] = byte(encCertLen)

	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen
	copy(x, hs.sessionID[:])

	logrus.Debugf("server: session ID %x", hs.sessionID[:])

	hs.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	pos += SessionIDLen

	// Certs
	encCerts, err := EncryptCertificates(&hs.duplex, c.RawLeaf, c.RawIntermediate)
	if err != nil {
		return pos, err
	}
	copy(x, encCerts)
	x = x[encCertLen:]
	pos += encCertLen

	// Certs MAC
	if len(x) < 2*MacLen {
		return pos, ErrBufUnderflow
	}
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server: sa tag %x", x[:MacLen])
	x = x[MacLen:]
	pos += MacLen

	// KEM CipherText -> ekem
	ct, k, err := hs.kem.impl.Enc(rand.Reader, hs.kem.remoteEphemeral)
	if err != nil {
		return 0, err
	}

	if len(ct) != KemCtLen {
		return 0, ErrBufOverflow
	}

	copy(x, ct[:])
	x = x[KemCtLen:]
	hs.duplex.Absorb(k) // shared secret
	pos += KemCtLen

	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server serverauth mac: %x", x[:MacLen])
	// x = x[MacLen:]
	pos += MacLen
	return pos, nil
}

func (hs *HandshakeState) readPQServerAuth(b []byte) (int, error) {
	minLength := HeaderLen + SessionIDLen + 2*MacLen + KemCtLen
	if len(b) < minLength {
		return 0, ErrBufUnderflow
	}

	// Header
	if mt := MessageType(b[0]); mt != MessageTypePQServerAuth {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 {
		return 0, ErrInvalidMessage
	}
	encryptedCertLen := (int(b[2]) << 8) + int(b[3])
	logrus.Debugf("client: got encrypted cert length %d", encryptedCertLen)
	fullLength := minLength + encryptedCertLen
	if len(b) < fullLength {
		return 0, ErrBufOverflow
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// SessionID
	copy(hs.sessionID[:], b[:SessionIDLen])
	hs.duplex.Absorb(hs.sessionID[:])
	logrus.Debugf("client: got session ID %x", hs.sessionID)
	b = b[SessionIDLen:]

	// Certs
	encryptedCertificates := b[:encryptedCertLen]
	b = b[encryptedCertLen:]

	// Decrypt the certificates, but don't read them yet
	rawLeaf, rawIntermediate, err := DecryptCertificates(&hs.duplex, encryptedCertificates)
	if err != nil {
		logrus.Debugf("client: error decrypting certificates: %s", err)
		return 0, err
	}
	logrus.Debugf("client: leaf, intermediate: %x, %x", rawLeaf, rawIntermediate)

	// Tag (Encrypted Certs)
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa tag: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: sa tag mismatch, got %x, wanted %x", b[:MacLen], hs.macBuf)
		return 0, ErrInvalidMessage
	}
	b = b[MacLen:]

	// eKEM CipherText
	k, err := hs.kem.ephemeral.Dec(b[:KemCtLen])
	if err != nil {
		return 0, err
	}

	b = b[KemCtLen:]
	hs.duplex.Absorb(k)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	// Parse the certificate
	// We are parsing the certificate here as there is no need before while reading the server Auth
	hs.certVerify.InsecureSkipVerify = true // TODO fix the certificates
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("client: error parsing server certificates: %s", err)
		return 0, err
	}

	remoteStaticBytes := leaf.PublicKey
	hs.kem.remoteStatic, err = hs.kem.impl.ParsePublicKey(remoteStaticBytes[:])
	if err != nil {
		return 0, err
	}

	logrus.Debugf("Client: kem remote static: %v", leaf.PublicKey[:])
	logrus.Debugf("Client: kem static: %v", hs.kem.static.Public().Bytes())

	return fullLength, nil
}

func (hs *HandshakeState) writePQClientAuth(b []byte) (int, error) {
	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)
	// TODO this has a length of 1905 -> too large
	length := HeaderLen + SessionIDLen + encCertLen + MacLen + MacLen + KemCtLen
	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	x := b
	pos := 0

	// Header
	x[0] = byte(MessageTypePQClientAuth)
	x[1] = 0
	x[2] = byte(encCertLen >> 8)
	x[3] = byte(encCertLen)
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen

	// SessionID
	copy(x, hs.sessionID[:])
	hs.duplex.Absorb(hs.sessionID[:])
	x = x[SessionIDLen:]
	pos += SessionIDLen

	// Encrypted Certificates
	if len(hs.leaf) == 0 {
		return pos, errors.New("client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.duplex, hs.leaf, hs.intermediate)
	if err != nil {
		return pos, err
	}
	if len(encCerts) != encCertLen {
		return pos, fmt.Errorf("certificates encrypted to unexpected length %d, expected %d", len(encCerts), encCertLen)
	}
	copy(x, encCerts)
	x = x[encCertLen:]
	pos += encCertLen

	// Tag
	hs.duplex.Squeeze(x[:MacLen])
	x = x[MacLen:]
	pos += MacLen

	// KEM CipherText -> skem
	ct, k, err := hs.kem.impl.Enc(rand.Reader, hs.kem.remoteStatic)
	if err != nil {
		return pos, err
	}

	if len(ct) != KemCtLen {
		return pos, ErrBufOverflow
	}

	copy(x, ct[:])
	//hs.duplexAbsorbKem(b[:KemCtLen]) // public artifact encapsulating the shared secret
	x = x[KemCtLen:]
	pos += KemCtLen

	hs.duplex.Absorb(k) // shared secret

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	// b = b[MacLen:]
	pos += MacLen

	return pos, nil
}

// TODO fix read client auth from the test
func (s *Server) readPQClientAuth(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	x := b
	pos := 0
	if len(b) < HeaderLen {
		logrus.Debug("server: client auth missing header")
		return 0, nil, ErrBufUnderflow
	}

	logrus.Debugf("buf %v", b)

	encCertsLen := (int(b[2]) << 8) + int(b[3])
	if len(b) < HeaderLen+SessionIDLen+encCertsLen+MacLen+KemCtLen {
		logrus.Debug("server: client auth too short")
		return 0, nil, ErrBufUnderflow
	}

	if mt := MessageType(b[0]); mt != MessageTypePQClientAuth {
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

	hs.kem.remoteStatic, err = hs.kem.impl.ParsePublicKey(leaf.PublicKey[:])
	if err != nil {
		return 0, nil, err
	}
	logrus.Debugf("Server: kem remote static: %v", leaf.PublicKey[:])
	logrus.Debugf("Server: kem static: %v", hs.kem.static.Public().Bytes())

	// KEM CipherText
	//hs.duplexAbsorbKem(b[:KemCtLen])

	k, err := hs.kem.static.Dec(x[:KemCtLen]) // skem
	if err != nil {
		return 0, nil, err
	}
	hs.duplex.Absorb(k)

	x = x[KemCtLen:]

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

func (s *Server) writePQServerConf(b []byte, hs *HandshakeState) (int, error) {

	length := HeaderLen + KemCtLen + MacLen

	if len(b) < length {
		return 0, ErrBufOverflow
	}

	x := b
	pos := 0
	x[0] = byte(MessageTypePQServerConf)
	x[1] = 0
	x[2] = 0
	x[3] = 0
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	pos += HeaderLen

	// KEM CipherText -> skem
	ct, k, err := hs.kem.impl.Enc(rand.Reader, hs.kem.remoteStatic)
	if err != nil {
		return 0, err
	}
	if len(ct) != KemCtLen {
		return 0, ErrBufOverflow
	}
	copy(x, ct[:])
	//hs.duplexAbsorbKem(x[:KemCtLen]) // public artifact encapsulating the shared secret
	x = x[KemCtLen:]
	pos += KemCtLen

	hs.duplex.Absorb(k) // shared secret

	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server serverauth mac: %x", x[:MacLen])
	// x = x[MacLen:]
	pos += MacLen

	if pos != length {
		return 0, ErrInvalidMessage
	}

	return pos, nil
}

func (hs *HandshakeState) readPQServerConf(b []byte) (int, error) {
	length := HeaderLen + KemCtLen + MacLen
	if len(b) < length {
		return 0, ErrBufUnderflow
	}
	if mt := MessageType(b[0]); mt != MessageTypePQServerConf {
		return 0, ErrUnexpectedMessage
	}

	// Header
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrUnexpectedMessage
	}
	header := b[:HeaderLen]
	b = b[HeaderLen:]
	hs.duplex.Absorb(header)

	// KEM CipherText
	//hs.duplexAbsorbKem(b[:KemCtLen])

	k, err := hs.kem.static.Dec(b[:KemCtLen]) // skem
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(k)

	b = b[KemCtLen:]

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	return length, nil
}

// TODO write a if statement in the original function
func (hs *HandshakeState) writePQCookie(b []byte) (int, error) {
	// TODO(dadrian): Avoid allocating memory.
	aead, err := kravatte.NewSANSE(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	seed := hs.kem.ephemeral.Seed()
	if seed == nil {
		return 0, err
	}

	plaintextCookie := seed[:]
	ad := CookieAD(hs.kem.remoteEphemeral.Bytes(), hs.remoteAddr) // TODO why does it return only 32 bytes
	enc := aead.Seal(b[:0], nil, plaintextCookie, ad)
	if len(enc) != PQCookieLen {
		logrus.Panicf("len(enc) != PQCookieLen: %d != %d. Not possible", len(enc), PQCookieLen)
	}
	return len(enc), nil // PQCookieLen
}
func (hs *HandshakeState) decryptPQCookie(b []byte) (int, error) {
	if len(b) < PQCookieLen {
		return 0, ErrBufUnderflow
	}
	aead, err := kravatte.NewSANSE(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	encryptedCookie := b[:PQCookieLen]
	remoteEphemeralBytes := hs.kem.remoteEphemeral.Bytes()
	ad := CookieAD(remoteEphemeralBytes[:], hs.remoteAddr)

	seed := make([]byte, PQSeedLen)
	out, err := aead.Open(seed[:0], nil, encryptedCookie, ad)
	if err != nil {
		return 0, ErrInvalidMessage
	}
	if len(out) != PQSeedLen {
		return 0, ErrInvalidMessage
	}

	hs.kem.ephemeral, err = hs.kem.impl.GenerateKeypairFromSeed(seed)

	if err != nil {
		return 0, ErrInvalidMessage
	}
	return PQCookieLen, nil
}

// ReplayPQDuplexFromCookie does exactly like ReplayDuplexFromCookie with KEM
// TODO write the description or refactor
func (s *Server) ReplayPQDuplexFromCookie(cookie, clientEphemeralBytes []byte, clientAddr *net.UDPAddr) (*HandshakeState, error) {
	s.cookieLock.Lock()
	defer s.cookieLock.Unlock()

	out := new(HandshakeState)
	out.kem = new(kemState)
	out.kem.impl = keys.MlKem512

	clientEphemeral, err := out.kem.impl.ParsePublicKey(clientEphemeralBytes)
	if err != nil {
		return nil, err
	}

	out.kem.remoteEphemeral = clientEphemeral
	out.remoteAddr = clientAddr
	out.cookieKey = s.cookieKey
	out.kem.static = *s.config.KEMKeyPair

	// Pull the private key out of the cookie
	n, err := out.decryptPQCookie(cookie)
	if err != nil {
		logrus.Errorf("unable to decrypt cookie: %s", err)
		return nil, err
	}
	if n != PQCookieLen {
		return nil, ErrInvalidMessage
	}

	// Replay the duplex
	out.duplex.InitializeEmpty()

	// Replay Client Hello
	out.duplex.Absorb([]byte(PostQuantumProtocolName))
	out.duplex.Absorb([]byte{byte(MessageTypePQClientHello), Version, 0, 0})
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen ch mac: %x", out.macBuf[:])

	// Replay Server Hello
	out.duplex.Absorb([]byte{byte(MessageTypePQServerHello), 0, 0, 0})
	out.duplex.Absorb(cookie)
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen sh mac: %x", out.macBuf[:])

	out.RekeyFromSqueeze(PostQuantumProtocolName)
	return out, nil
}
