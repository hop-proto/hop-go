package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/vektra/tai64n"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// TODO(hosono) In the paper, the hidden mode client hello is called "Client Request"
// which seems like an ambiguous name. I've changed it to ClientRequestHidden
func (hs *HandshakeState) writeClientRequestHidden(b []byte, serverPublicKey *keys.PublicKey) (int, error) {

	logrus.Debug("client: sending client request (hidden mode)")

	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)

	length := HeaderLen + DHLen + encCertLen + MacLen + TimestampLen + MacLen

	if len(b) < length {
		return 0, ErrBufOverflow
	}

	pos := 0

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	b[2] = byte(encCertLen >> 8)
	b[3] = byte(encCertLen)

	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	pos += HeaderLen

	// Client Ephemeral key for Diffie-Hellman (e)
	copy(b, hs.ephemeral.Public[:])
	logrus.Debugf("client: client ephemeral: %x", b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	pos += DHLen

	// DH (es)
	secret, err := hs.ephemeral.DH(serverPublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", secret)
	hs.duplex.Absorb(secret)

	// Encrypted Certificates
	if len(hs.leaf) == 0 {
		return pos, errors.New("client: client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.duplex, hs.leaf, hs.intermediate)
	if err != nil {
		return pos, err
	}
	if len(encCerts) != encCertLen {
		return pos, fmt.Errorf("client: certificates encrypted to unexpected length %d, expected %d", len(encCerts), encCertLen)
	}
	copy(b, encCerts)
	b = b[encCertLen:]
	pos += encCertLen

	// Client Static Authentication Tag
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: hidden handshake tag %x", b[:MacLen])
	b = b[MacLen:]
	pos += MacLen

	// DH (ss)
	hs.ss, err = hs.static.Agree(serverPublicKey[:])
	if err != nil {
		logrus.Debugf("client: unable to calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("client: ss: %x", hs.ss)
	hs.duplex.Absorb(hs.ss)

	// Tai64N is necessary to prevent replay of Client Hello to trigger server response
	now := tai64n.Now()
	timeBytes := make([]byte, 12)
	binary.BigEndian.PutUint64(timeBytes[0:], now.Seconds)
	binary.BigEndian.PutUint32(timeBytes[8:], now.Nanoseconds)
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

func (s *Server) readClientRequestHidden(hs *HandshakeState, b []byte) (int, error) {

	logrus.Debug("server: read client request hidden")

	var err error
	encCertsLen := (int(b[2]) << 8) + int(b[3])
	length := HeaderLen + DHLen + encCertsLen + MacLen + TimestampLen + MacLen

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

	// Header
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Client Ephemeral
	copy(hs.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: certs.HiddenName("hidden-handshake"),
	})

	if err != nil {
		return 0, err
	}

	// DH (es)
	hs.es, err = c.Exchanger.Agree(hs.remoteEphemeral[:])
	if err != nil {
		logrus.Debugf("server: unable to calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("server: es: %x", hs.es)
	hs.duplex.Absorb(hs.es)

	// Client Encrypted Certificates
	encCerts := b[:encCertsLen]
	rawLeaf, _, err := DecryptCertificates(&hs.duplex, encCerts)
	if err != nil {
		logrus.Debugf("server: unable to decrypt certificates: %s", err)
		return 0, err
	}
	b = b[encCertsLen:]

	// Tag (Client Static Auth Tag)
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server: calculated hidden client request tag: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("server: hidden client request tag mismatch, got %x, wanted %x", b[:MacLen], hs.macBuf)
		return 0, ErrInvalidMessage
	}
	b = b[MacLen:]

	// TODO add the parsing verification
	// Parse certificates
	leaf := certs.Certificate{}

	leafLen, err := leaf.ReadFrom(bytes.NewBuffer(rawLeaf))
	if err != nil {
		return 0, err
	}
	if int(leafLen) != len(rawLeaf) {
		return 0, errors.New("extra bytes after leaf certificate")
	}

	// DH (ss)
	hs.ss, err = c.Exchanger.Agree(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("server: could not calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("server: ss: %x", hs.ss)
	hs.duplex.Absorb(hs.ss)

	// Timestamp
	hs.duplex.Decrypt(timestampBuf[:], b[:TimestampLen])
	decryptedTimestamp := timestampBuf[:TimestampLen]
	b = b[TimestampLen:]

	taiTime := tai64n.TAI64N{
		Seconds:     binary.BigEndian.Uint64(decryptedTimestamp[0:8]),  // First 8 bytes are the Seconds
		Nanoseconds: binary.BigEndian.Uint32(decryptedTimestamp[8:12]), // Last 4 bytes are the Nanoseconds
	}

	// TODO (paul) 5 sec is a way too long, evaluate the time need for a connection
	// TODO (paul) what is considered a reasonable time range for a timestamp to prevent replay attack?
	// Time comparison to prevent replay attacks
	if tai64n.Now().Seconds-taiTime.Seconds > 5 {
		logrus.Debugf("server: hidden client request timestamp too long")
		return 0, ErrInvalidMessage
	}

	// MAC (Client Static)
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("server: calculated hidden client request mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("server: hidden client request mac mismatch, got %x, wanted %x", b[:MacLen], hs.macBuf)
		return 0, ErrInvalidMessage
	}

	return length, err
}

func (s *Server) writeServerRequestHidden(hs *HandshakeState, b []byte) (int, error) {
	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: certs.HiddenName("hidden-handshake"),
	})

	if err != nil {
		return 0, err
	}

	encCertLen := EncryptedCertificatesLength(c.RawLeaf, c.RawIntermediate)

	length := HeaderLen + SessionIDLen + DHLen + encCertLen + 2*MacLen

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

	// TODO (paul): check if there is any session ID at this point of the handshake
	copy(b, hs.sessionID[:])
	logrus.Debugf("server: session ID %x", hs.sessionID[:])
	hs.duplex.Absorb(b[:SessionIDLen])
	b = b[SessionIDLen:]
	pos += SessionIDLen

	// Server Ephemeral key
	copy(b, hs.ephemeral.Public[:])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	pos += DHLen

	// DH (ee)
	secret, err := hs.ephemeral.DH(hs.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	logrus.Debugf("server: ee: %x", secret)
	hs.duplex.Absorb(secret)

	// Server Certificates
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

	// DH (se)
	hs.se, err = c.Exchanger.Agree(hs.remoteEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(se)")
		return pos, err
	}
	logrus.Debugf("server se: %x", hs.se)
	hs.duplex.Absorb(hs.se)

	// MAC
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server hidden mac: %x", b[:MacLen])
	// b = b[MacLen:]
	pos += MacLen
	return pos, nil
}

func (hs *HandshakeState) readServerRequestHidden(b []byte) (int, error) {

	minLength := HeaderLen + SessionIDLen + DHLen + 2*MacLen

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

	// Server Ephemeral
	copy(hs.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// DH (ee)
	secret, err := hs.ephemeral.DH(hs.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(secret)

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

	// TODO add the parsing verification
	// Parse certificates
	leaf := certs.Certificate{}

	leafLen, err := leaf.ReadFrom(bytes.NewBuffer(rawLeaf))
	if err != nil {
		return 0, err
	}
	if int(leafLen) != len(rawLeaf) {
		return 0, errors.New("extra bytes after leaf certificate")
	}

	// DH (se)
	hs.se, err = hs.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate se: %s", err)
		return 0, err
	}
	logrus.Debugf("client: se: %x", hs.se)
	hs.duplex.Absorb(hs.se)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	return fullLength, nil
}
