package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// Hop Noise XX pattern
// --------------------
// -> e
// <- ekem, cookie
// -> e, cookie, Encaps(ekem), Encrypt(SNI)
// <- e, Encrypt(certs (s))  // compute DH(es)
// -> Encrypt(certs (s))     // compute DH(se)

func writePQClientHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < DHLen+HeaderLen+MacLen {
		return 0, ErrBufOverflow
	}
	x := b
	// Header
	x[0] = byte(MessageTypeClientHello) // Type = ClientHello (0x01)
	x[1] = Version                      // Version
	x[2] = 0                            // Reserved
	x[3] = 0                            // Reserved
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]

	// Ephemeral DH
	copy(x, hs.dh.ephemeral.Public[:])
	hs.duplex.Absorb(x[:DHLen])
	x = x[DHLen:]

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("client: client hello mac: %x", x[:MacLen])
	return DHLen + HeaderLen + MacLen, nil
}

func readPQClientHello(hs *HandshakeState, b []byte) (int, error) {
	logrus.Debug("read client hello")
	if len(b) < DHLen+HeaderLen+MacLen {
		return 0, ErrBufUnderflow
	}

	// Header
	if MessageType(b[0]) != MessageTypeClientHello {
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

	// Remote DH Ephemeral
	copy(hs.dh.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server: calculated client hello mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}
	return DHLen + HeaderLen + MacLen, nil
}

func writePQServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+KemKeyLen+PQCookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypeServerHello)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// PQ Ephemeral
	ephemeralBytes := hs.kem.ephemeral.Public.Bytes()
	copy(b, ephemeralBytes[:])
	hs.duplex.Absorb(b[:KemKeyLen])
	b = b[KemKeyLen:]

	// Cookie
	n, err := hs.writeCookie(b)
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

	return HeaderLen + KemKeyLen + PQCookieLen + MacLen, nil
}

func readPQServerHello(hs *HandshakeState, b []byte) (int, error) {
	var err error
	if len(b) < HeaderLen+KemKeyLen+PQCookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	if MessageType(b[0]) != MessageTypeServerHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// PQ Ephemeral
	hs.kem.remoteEphemeral, err = keys.ParseKEMPublicKeyFromBytes(b[:KemKeyLen])
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(b[:KemKeyLen])
	b = b[KemKeyLen:]

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

	return HeaderLen + KemKeyLen + PQCookieLen + MacLen, nil
}

func (hs *HandshakeState) writePQClientAck(b []byte) (int, error) {
	length := HeaderLen + DHLen + PQCookieLen + KemCtLen + SNILen + MacLen
	if len(b) < length {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypeClientAck)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Ephemeral DH
	copy(b, hs.dh.ephemeral.Public[:])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// Cookie
	n := copy(b, hs.cookie)
	if n != PQCookieLen {
		logrus.Debugf("unexpected PQ cookie length: %d (expected %d)", n, PQCookieLen)
		return HeaderLen + KemKeyLen + n, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:PQCookieLen])
	b = b[PQCookieLen:]

	// KEM Ephemeral CipherText
	ct, k, err := keys.Encapsulate(rand.Reader, hs.kem.remoteEphemeral)
	if err != nil {
		return 0, err
	}
	if len(ct) != KemCtLen {
		return 0, ErrBufOverflow
	}
	copy(b, ct[:])
	b = b[KemCtLen:]
	hs.duplex.Absorb(k) // shared secret

	// Encrypted SNI
	err = hs.EncryptSNI(b, hs.certVerify.Name)
	if err != nil {
		return HeaderLen + KemKeyLen + PQCookieLen + DHLen, ErrInvalidMessage
	}
	b = b[SNILen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: PQ client ack mac: %x", b[:MacLen])

	return length, nil
}

func (s *Server) readPQClientAck(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	var bufSNI [SNILen]byte
	length := HeaderLen + DHLen + PQCookieLen + KemCtLen + SNILen + MacLen
	if len(b) < length {
		return 0, nil, ErrBufUnderflow
	}
	if mt := MessageType(b[0]); mt != MessageTypeClientAck {
		return 0, nil, ErrUnexpectedMessage
	}

	// Header
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, nil, ErrUnexpectedMessage
	}
	header := b[:HeaderLen]
	b = b[HeaderLen:]

	// Ephemeral
	ephemeral := b[:DHLen]
	b = b[DHLen:]
	logrus.Debugf("server: got client ephemeral again: %x", ephemeral)

	// Cookie
	cookie := b[:PQCookieLen]
	b = b[PQCookieLen:]

	hs, err := s.ReplayPQDuplexFromCookie(cookie, ephemeral, addr)
	if err != nil {
		return 0, nil, err
	}

	logrus.Debugf("eph %v", ephemeral[:])

	hs.duplex.Absorb(header)
	hs.duplex.Absorb(ephemeral)
	hs.duplex.Absorb(cookie)

	// KEM Ephemeral CipherText
	k, err := hs.kem.ephemeral.Decapsulate(b[:KemCtLen])
	if err != nil {
		return 0, nil, err
	}
	b = b[KemCtLen:]
	hs.duplex.Absorb(k) // shared secret

	// SNI
	hs.duplex.Decrypt(bufSNI[:], b[:SNILen])
	decryptedSNI := bufSNI[:SNILen]
	b = b[SNILen:]

	// MAC
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server got client ack mac: %x, expected %x", b[:MacLen], hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return length, nil, ErrInvalidMessage
	}

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
	if len(b) < HeaderLen+SessionIDLen+DHLen+encCertLen {
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

	logrus.Debugf("server: session ID %x", hs.sessionID[:])

	hs.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	pos += SessionIDLen

	// Ephemeral DH
	copy(x, hs.dh.ephemeral.Public[:])
	hs.duplex.Absorb(x[:DHLen])
	x = x[DHLen:]
	pos += DHLen

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

	// DH (es)
	dhEs, err := c.Exchanger.Agree(hs.dh.remoteEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(es)")
		return pos, err
	}
	logrus.Debugf("server es: %x", dhEs)
	hs.duplex.Absorb(dhEs)

	// MAC
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("server serverauth mac: %x", x[:MacLen])
	// x = x[MacLen:]
	pos += MacLen
	return pos, nil
}

func (hs *HandshakeState) readPQServerAuth(b []byte) (int, error) {
	minLength := HeaderLen + SessionIDLen + 2*MacLen + DHLen
	if len(b) < minLength {
		return 0, ErrBufUnderflow
	}

	// Header
	if mt := MessageType(b[0]); mt != MessageTypeServerAuth {
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

	// Remote DH Ephemeral
	copy(hs.dh.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

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

	// Parse the certificate
	// We are parsing the certificate here as there is no need before while reading the server Auth
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("client: error parsing server certificates: %s", err)
		return 0, err
	}

	// DH (es)
	dhEs, err := hs.dh.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", dhEs)
	hs.duplex.Absorb(dhEs)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	return fullLength, nil
}

func (hs *HandshakeState) writePQClientAuth(b []byte) (int, error) {
	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)
	length := HeaderLen + SessionIDLen + encCertLen + MacLen + MacLen
	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	x := b
	pos := 0

	// Header
	x[0] = byte(MessageTypeClientAuth)
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

	// DH (se)
	dhSe, err := hs.dh.static.Agree(hs.dh.remoteEphemeral[:])
	if err != nil {
		logrus.Debugf("client: unable to calculate se: %s", err)
		return HeaderLen + SessionIDLen + encCertLen + MacLen, err
	}
	logrus.Debugf("client: se: %x", dhSe)
	hs.duplex.Absorb(dhSe)

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	// b = b[MacLen:]
	pos += MacLen

	return pos, nil
}

func (s *Server) readPQClientAuth(b []byte, addr *net.UDPAddr) (int, *HandshakeState, error) {
	x := b
	pos := 0
	if len(b) < HeaderLen {
		logrus.Debug("server: client auth missing header")
		return 0, nil, ErrBufUnderflow
	}

	logrus.Debugf("buf %v", b)

	encCertsLen := (int(b[2]) << 8) + int(b[3])
	if len(b) < HeaderLen+SessionIDLen+encCertsLen+MacLen {
		logrus.Debug("server: client auth too short")
		return 0, nil, ErrBufUnderflow
	}

	// Header
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

	// Session ID
	sessionID := x[:SessionIDLen]
	if !bytes.Equal(hs.sessionID[:], sessionID) {
		logrus.Debugf("server: mismatched session ID for %s: expected %x, got %x", addr, hs.sessionID, sessionID)
		return pos, nil, ErrUnexpectedMessage
	}
	hs.duplex.Absorb(sessionID)
	x = x[SessionIDLen:]
	pos += SessionIDLen

	// Certificates
	encCerts := x[:encCertsLen]
	rawLeaf, rawIntermediate, err := DecryptCertificates(&hs.duplex, encCerts)
	if err != nil {
		return pos, nil, err
	}
	x = x[encCertsLen:]
	pos += encCertsLen

	// Tag
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

	// DH (se)
	dhSe, err := hs.dh.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("server: unable to calculated se: %s", err)
		return pos, nil, err
	}
	logrus.Debugf("server: se %x", dhSe)
	hs.duplex.Absorb(dhSe)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	clientMac := x[:MacLen]
	if !bytes.Equal(hs.macBuf[:], clientMac) {
		logrus.Debugf("server: mismatched mac in client auth: expected %x, got %x", hs.macBuf, clientMac)
		return pos, nil, ErrInvalidMessage
	}
	// x = x[MacLen:]
	pos += MacLen
	return pos, hs, nil
}

// ReplayPQDuplexFromCookie reads a cookie containing an encrypted KEM private key
// seed, and returns a HandshakeState with the duplex replayed to a state
// equivalent after the server sent the Server Hello message. The returned
// duplex has not yet processed the Client Ack as in ReplayDuplexFromCookie.
func (s *Server) ReplayPQDuplexFromCookie(cookie, clientEphemeralBytes []byte, clientAddr *net.UDPAddr) (*HandshakeState, error) {
	s.cookieLock.Lock()
	defer s.cookieLock.Unlock()

	out := new(HandshakeState)
	out.dh = new(dhState)
	out.dh.ephemeral.Generate()
	out.kem = new(kemState)

	// TODO (paul) this notation with DHLen hard coded sounds weird, we might have a better way to do it
	out.dh.remoteEphemeral = [DHLen]byte(clientEphemeralBytes)
	out.remoteAddr = clientAddr
	out.cookieKey = s.cookieKey
	//out.kem.static = s.config.KEMKeyPair

	// Pull the private key out of the cookie
	n, err := out.decryptCookie(cookie)
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
	out.duplex.Absorb([]byte{byte(MessageTypeClientHello), Version, 0, 0})
	out.duplex.Absorb(clientEphemeralBytes)
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen ch mac: %x", out.macBuf[:])

	// Replay Server Hello
	out.duplex.Absorb([]byte{byte(MessageTypeServerHello), 0, 0, 0})
	out.duplex.Absorb(out.kem.ephemeral.Public.Bytes())
	out.duplex.Absorb(cookie)
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen sh mac: %x", out.macBuf[:])

	out.RekeyFromSqueeze(PostQuantumProtocolName)
	return out, nil
}

// Hop Noise IK pattern
// --------------------
// <- skem
// …
// -> ekem, Encaps(skem), Encrypt(certs (s))
// <- Encaps(ekem), Encrypt(certs (s)) // DH (ss)

func (hs *HandshakeState) writePQClientRequestHidden(b []byte, serverKEMPublicKey *keys.KEMPublicKey) (int, error) {

	logrus.Debug("client: sending client request (hidden mode)")

	encCertsLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)

	length := HeaderLen + KemCtLen + KemKeyLen + encCertsLen + MacLen + TimestampLen + MacLen

	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	pos := 0

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	b[2] = byte(encCertsLen >> 8)
	b[3] = byte(encCertsLen)

	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	pos += HeaderLen

	// PQ Ephemeral -> ekem
	ephemeralBytes := hs.kem.ephemeral.Public.Bytes()
	copy(b, ephemeralBytes[:])
	hs.duplex.Absorb(b[:KemKeyLen])
	b = b[KemKeyLen:]
	pos += KemKeyLen

	// skem CipherText
	ct, k, err := keys.Encapsulate(rand.Reader, *serverKEMPublicKey)
	if err != nil {
		return pos, err
	}
	if len(ct) != KemCtLen {
		return pos, ErrBufOverflow
	}
	copy(b, ct[:])
	b = b[KemCtLen:]
	pos += KemCtLen
	hs.duplex.Absorb(k) // shared secret

	// Encrypted Certificates (s)
	if len(hs.leaf) == 0 {
		return pos, errors.New("client: client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.duplex, hs.leaf, hs.intermediate)
	if err != nil {
		return pos, err
	}
	if len(encCerts) != encCertsLen {
		return pos, fmt.Errorf("client: certificates encrypted to unexpected length %d, expected %d", len(encCerts), encCertsLen)
	}
	copy(b, encCerts)
	b = b[encCertsLen:]
	pos += encCertsLen

	// Client Static Authentication Tag
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: hidden handshake tag %x", b[:MacLen])
	b = b[MacLen:]
	pos += MacLen

	// Timestamp
	now := time.Now().Unix()
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(now))
	hs.duplex.Encrypt(b, timeBytes[:])
	b = b[TimestampLen:]
	pos += TimestampLen

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: calculated hidden client request mac: %x", b[:MacLen])
	// b = b[MacLen:]
	pos += MacLen

	return pos, err
}

func (s *Server) readPQClientRequestHidden(hs *HandshakeState, b []byte) (int, error) {

	logrus.Debug("server: read client request hidden")

	var err error
	encCertsLen := (int(b[2]) << 8) + int(b[3])
	length := HeaderLen + KemCtLen + encCertsLen + MacLen + KemKeyLen + TimestampLen + MacLen

	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	var timestampBuf [TimestampLen]byte

	if MessageType(b[0]) != MessageTypeClientRequestHidden {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != Version {
		return 0, ErrUnsupportedVersion
	}

	certList, err := s.config.GetCertList()

	if err != nil {
		logrus.Debugf("server: unable to get cert list hidden mode, %s", err)
		return 0, ErrInvalidMessage
	}

	var (
		rawLeaf, rawIntermediate, remoteEphemeralBytes []byte
		c                                              *Certificate
	)
	bufCopy := make([]byte, len(b))

	for _, cert := range certList {
		// Copy buffer for processing
		copy(bufCopy, b)

		// Recreate duplex at each VM loop
		hs.duplex.InitializeEmpty()
		hs.duplex.Absorb([]byte(PostQuantumHiddenProtocolName))
		hs.RekeyFromSqueeze(PostQuantumHiddenProtocolName)

		// Absorb Header
		hs.duplex.Absorb(bufCopy[:HeaderLen])
		bufCopy = bufCopy[HeaderLen:]

		// Handle PQ client Ephemeral Key -> ekem
		remoteEphemeralBytes = bufCopy[:KemKeyLen]
		hs.duplex.Absorb(bufCopy[:KemKeyLen])
		bufCopy = bufCopy[KemKeyLen:]

		if cert.KEMKeyPair == nil {
			logrus.Debug("server: Hidden mode unable to find a kem key in the hop transport cert")
			continue // Tag mismatch, move to the next certificate
		}

		k, err := cert.KEMKeyPair.Decapsulate(bufCopy[:KemCtLen]) // skem CipherText
		if err != nil {
			logrus.Debugf("server: unable to calculate skem: %s", err)
			continue // Proceed to the next certificate on error
		}
		hs.duplex.Absorb(k)
		bufCopy = bufCopy[KemCtLen:]

		// Decrypt Client Encrypted Certificates
		encCerts := bufCopy[:encCertsLen]
		rawLeaf, rawIntermediate, err = DecryptCertificates(&hs.duplex, encCerts)
		if err != nil {
			logrus.Debugf("server: unable to decrypt certificates: %s", err)
			continue // Skip to the next certificate on error
		}
		bufCopy = bufCopy[encCertsLen:]

		// Validate Tag (Client Static Auth Tag)
		hs.duplex.Squeeze(hs.macBuf[:])
		logrus.Debugf("server: calculated hidden client request tag: %x", hs.macBuf)
		if !bytes.Equal(hs.macBuf[:], bufCopy[:MacLen]) {
			logrus.Debugf("server: hidden client request tag mismatch, got %x, wanted %x", bufCopy[:MacLen], hs.macBuf)
			continue // Tag mismatch, move to the next certificate
		}
		bufCopy = bufCopy[MacLen:]

		vhostNames := cert.HostNames

		if len(vhostNames) == 0 {
			logrus.Debugf("server: unable to retrieve any sni")
			continue // Skip to the next certificate on error
		}

		c = cert
		hs.sni = certs.RawStringName(vhostNames[0]) // get the first vhost liked to the cert

		break
	}

	if c == nil {
		logrus.Debugf("server: No valid certificate found")
		return 0, ErrInvalidMessage
	}

	copy(b, bufCopy)

	// save remote in the hs object
	hs.kem.remoteEphemeral, err = keys.ParseKEMPublicKeyFromBytes(remoteEphemeralBytes)
	if err != nil {
		return 0, err
	}

	// Parse certificates
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("server: error parsing client certificates: %s", err)
		return 0, err
	}
	hs.parsedLeaf = &leaf

	hs.dh.remoteStatic = [32]byte(leaf.PublicKey)
	if err != nil {
		return 0, err
	}

	// Timestamp
	hs.duplex.Decrypt(timestampBuf[:], b[:TimestampLen])
	decryptedTimestamp := timestampBuf[:TimestampLen]
	if len(decryptedTimestamp) < TimestampLen {
		logrus.Debugf("server: decrypted timestamp too short")
		return 0, ErrInvalidMessage
	}

	timeBytes := binary.BigEndian.Uint64(decryptedTimestamp[:TimestampLen])
	now := time.Now().Unix()

	if timeBytes > uint64(now) || now-int64(timeBytes) > HiddenModeTimestampExpiration {
		logrus.Debugf("server: hidden client request timestamp doen't match")
		return 0, ErrInvalidMessage
	}
	logrus.Debugf("The time is %v and we got %v", now, timeBytes)

	b = b[TimestampLen:]

	// MAC
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server: calculated hidden client request mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("server: hidden client request mac mismatch, got %x, wanted %x", b[:MacLen], hs.macBuf)
		return 0, ErrInvalidMessage
	}

	return length, err
}

func (s *Server) writePQServerResponseHidden(hs *HandshakeState, b []byte) (int, error) {

	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: hs.sni,
	})

	if err != nil {
		logrus.Debugf("server: hidden mode no cert found in hs")
		return 0, ErrInvalidMessage
	}

	encCertLen := EncryptedCertificatesLength(c.RawLeaf, c.RawIntermediate)

	length := HeaderLen + SessionIDLen + KemCtLen + encCertLen + 2*MacLen

	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	pos := 0

	// Header
	b[0] = byte(MessageTypeServerResponseHidden)
	b[1] = 0
	b[2] = byte(encCertLen >> 8)
	b[3] = byte(encCertLen)
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	pos += HeaderLen

	copy(b, hs.sessionID[:])
	logrus.Debugf("server: session ID %x", hs.sessionID[:])
	hs.duplex.Absorb(b[:SessionIDLen])
	b = b[SessionIDLen:]
	pos += SessionIDLen

	// KEM CipherText -> ekem
	eCt, ek, err := keys.Encapsulate(rand.Reader, hs.kem.remoteEphemeral)
	if err != nil {
		return 0, err
	}
	if len(eCt) != KemCtLen {
		return 0, ErrBufOverflow
	}
	copy(b, eCt[:])
	b = b[KemCtLen:]
	hs.duplex.Absorb(ek) // shared secret
	pos += KemCtLen

	// Server Certificates (s)
	encCerts, err := EncryptCertificates(&hs.duplex, c.RawLeaf, c.RawIntermediate)
	if err != nil {
		return pos, err
	}
	copy(b, encCerts)
	b = b[encCertLen:]
	pos += encCertLen

	if len(b) < 2*MacLen {
		return pos, ErrBufUnderflow
	}

	// Certificate Authentication Tag
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server: sa tag %x", b[:MacLen])
	b = b[MacLen:]
	pos += MacLen

	// DH (ss)
	dhSs, err := c.Exchanger.Agree(hs.dh.remoteStatic[:])
	if err != nil {
		logrus.Debugf("server: unable to calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("server: ss: %x", dhSs)
	hs.duplex.Absorb(dhSs)

	// MAC
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server hidden mac: %x", b[:MacLen])
	// b = b[MacLen:]
	pos += MacLen
	return pos, nil
}

func (hs *HandshakeState) readPQServerResponseHidden(b []byte) (int, error) {

	minLength := HeaderLen + SessionIDLen + KemCtLen + 2*MacLen

	if len(b) < minLength {
		return 0, ErrBufUnderflow
	}

	// Header
	if mt := MessageType(b[0]); mt != MessageTypeServerResponseHidden {
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

	// eKEM CipherText
	ek, err := hs.kem.ephemeral.Decapsulate(b[:KemCtLen])
	if err != nil {
		return 0, err
	}

	b = b[KemCtLen:]
	hs.duplex.Absorb(ek)

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

	// Parse certificates
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("client: error parsing server certificates: %s", err)
		return 0, err
	}
	hs.parsedLeaf = &leaf

	// DH (ss)
	dhSs, err := hs.dh.static.Agree(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("client: ss: %x", dhSs)
	hs.duplex.Absorb(dhSs)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
		return 0, ErrInvalidMessage
	}
	// b = b[MacLen:]

	return fullLength, nil
}
