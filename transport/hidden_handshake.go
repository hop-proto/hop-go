package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// TODO(hosono) In the paper, the hidden mode client hello is called "Client Request"
// which seems like an ambiguous name. I've changed it to ClientRequestHidden
func (hs *HandshakeState) writeClientRequestHidden(b []byte, serverPublicKey *keys.DHPublicKey) (int, error) {

	logrus.Debug("client: sending client request (hidden mode)")

	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)

	length := HeaderLen + DHLen + encCertLen + MacLen + TimestampLen + MacLen

	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	pos := 0

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	b[2] = byte(encCertLen >> 8)
	b[3] = byte(encCertLen)

	hs.dh.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	pos += HeaderLen

	// Client Ephemeral key for Diffie-Hellman (e)
	copy(b, hs.dh.ephemeral.Public[:])
	logrus.Debugf("client: client ephemeral: %x", b[:DHLen])
	hs.dh.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	pos += DHLen

	// DH (es)
	secret, err := hs.dh.ephemeral.DH(serverPublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", secret)
	hs.dh.duplex.Absorb(secret)

	// Encrypted Certificates (s)
	if len(hs.leaf) == 0 {
		return pos, errors.New("client: client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.dh.duplex, hs.leaf, hs.intermediate)
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
	hs.dh.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: hidden handshake tag %x", b[:MacLen])
	b = b[MacLen:]
	pos += MacLen

	// DH (ss)
	hs.dh.ss, err = hs.dh.static.Agree(serverPublicKey[:])
	if err != nil {
		logrus.Debugf("client: unable to calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("client: ss: %x", hs.dh.ss)
	hs.dh.duplex.Absorb(hs.dh.ss)

	now := time.Now().Unix()
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(now))
	hs.dh.duplex.Encrypt(b, timeBytes[:])
	b = b[TimestampLen:]
	pos += TimestampLen

	// Mac
	hs.dh.duplex.Squeeze(b[:MacLen])
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

	certList, err := s.config.GetCertList()

	if err != nil {
		logrus.Debugf("server: unable to get cert list hidden mode, %s", err)
		return 0, ErrInvalidMessage
	}

	var (
		rawLeaf, rawIntermediate []byte
		c                        *Certificate
	)
	bufCopy := make([]byte, len(b))

	for _, cert := range certList {
		// Copy buffer for processing
		copy(bufCopy, b)

		// Absorb Header
		hs.dh.duplex.Absorb(bufCopy[:HeaderLen])
		bufCopy = bufCopy[HeaderLen:]

		// Handle Client Ephemeral Key
		copy(hs.dh.remoteEphemeral[:], bufCopy[:DHLen])
		hs.dh.duplex.Absorb(bufCopy[:DHLen])
		bufCopy = bufCopy[DHLen:]

		// Derive DH (es)
		hs.dh.es, err = cert.Exchanger.Agree(hs.dh.remoteEphemeral[:])
		if err != nil {
			logrus.Debugf("server: unable to calculate es: %s", err)
			continue // Proceed to the next certificate on error
		}
		logrus.Debugf("server: es: %x", hs.dh.es)
		hs.dh.duplex.Absorb(hs.dh.es)

		// Decrypt Client Encrypted Certificates
		encCerts := bufCopy[:encCertsLen]
		rawLeaf, rawIntermediate, err = DecryptCertificates(&hs.dh.duplex, encCerts)
		if err != nil {
			logrus.Debugf("server: unable to decrypt certificates: %s", err)
			continue // Skip to the next certificate on error
		}
		bufCopy = bufCopy[encCertsLen:]

		// Validate Tag (Client Static Auth Tag)
		hs.dh.duplex.Squeeze(hs.dh.macBuf[:])
		logrus.Debugf("server: calculated hidden client request tag: %x", hs.dh.macBuf)
		if !bytes.Equal(hs.dh.macBuf[:], bufCopy[:MacLen]) {
			logrus.Debugf("server: hidden client request tag mismatch, got %x, wanted %x", bufCopy[:MacLen], hs.dh.macBuf)
			continue // Tag mismatch, move to the next certificate
		}
		bufCopy = bufCopy[MacLen:]

		c = cert
		vhostName := cert.HostName
		if vhostName == "" {
			logrus.Debugf("server: unable to retrieve sni: %s", err)
			continue // Skip to the next certificate on error
		}
		hs.sni = certs.RawStringName(vhostName)

		break
	}

	if c == nil {
		logrus.Debugf("server: No valid certificate found")
		return 0, ErrInvalidMessage
	}

	copy(b, bufCopy)

	// Parse certificates
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("server: error parsing client certificates: %s", err)
		return 0, err
	}
	hs.parsedLeaf = &leaf

	// DH (ss)
	hs.dh.ss, err = c.Exchanger.Agree(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("server: could not calculate ss: %s", err)
		return 0, err
	}
	logrus.Debugf("server: ss: %x", hs.dh.ss)
	hs.dh.duplex.Absorb(hs.dh.ss)

	// Timestamp
	hs.dh.duplex.Decrypt(timestampBuf[:], b[:TimestampLen])
	decryptedTimestamp := timestampBuf[:TimestampLen]
	if len(decryptedTimestamp) < TimestampLen {
		logrus.Debugf("server: decrypted timestamp too short")
		return 0, ErrInvalidMessage
	}

	timeBytes := binary.BigEndian.Uint64(decryptedTimestamp[:TimestampLen])
	now := time.Now().Unix()

	// TODO (paul) 5 sec is a way too long, evaluate the time need for a connection
	// TODO (paul) what is considered a reasonable time range for a timestamp to prevent replay attack?
	// Time comparison to prevent replay attacks
	if timeBytes > uint64(now) || now-int64(timeBytes) > 5 {
		logrus.Debugf("server: hidden client request timestamp doen't match")
		return 0, ErrInvalidMessage
	}

	b = b[TimestampLen:]

	// MAC (Client Static)
	hs.dh.duplex.Squeeze(hs.dh.macBuf[:])
	logrus.Debugf("server: calculated hidden client request mac: %x", hs.dh.macBuf)
	if !bytes.Equal(hs.dh.macBuf[:], b[:MacLen]) {
		logrus.Debugf("server: hidden client request mac mismatch, got %x, wanted %x", b[:MacLen], hs.dh.macBuf)
		return 0, ErrInvalidMessage
	}

	return length, err
}

func (s *Server) writeServerResponseHidden(hs *HandshakeState, b []byte) (int, error) {

	c, err := s.config.GetCertificate(ClientHandshakeInfo{
		ServerName: hs.sni,
	})

	if err != nil {
		logrus.Debugf("server: hidden mode no cert found in hs")
		return 0, ErrInvalidMessage
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
	hs.dh.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	pos += HeaderLen

	copy(b, hs.sessionID[:])
	logrus.Debugf("server: session ID %x", hs.sessionID[:])
	hs.dh.duplex.Absorb(b[:SessionIDLen])
	b = b[SessionIDLen:]
	pos += SessionIDLen

	// Server Ephemeral key
	copy(b, hs.dh.ephemeral.Public[:])
	hs.dh.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	pos += DHLen

	// DH (ee)
	secret, err := hs.dh.ephemeral.DH(hs.dh.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	logrus.Debugf("server: ee: %x", secret)
	hs.dh.duplex.Absorb(secret)

	// Server Certificates (s)
	encCerts, err := EncryptCertificates(&hs.dh.duplex, c.RawLeaf, c.RawIntermediate)
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
	hs.dh.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server: sa tag %x", b[:MacLen])
	b = b[MacLen:]
	pos += MacLen

	// DH (se)
	hs.dh.se, err = c.Exchanger.Agree(hs.dh.remoteEphemeral[:])
	if err != nil {
		logrus.Debug("could not calculate DH(se)")
		return pos, err
	}
	logrus.Debugf("server se: %x", hs.dh.se)
	hs.dh.duplex.Absorb(hs.dh.se)

	// MAC
	hs.dh.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server hidden mac: %x", b[:MacLen])
	// b = b[MacLen:]
	pos += MacLen
	return pos, nil
}

func (hs *HandshakeState) readServerResponseHidden(b []byte) (int, error) {

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
	hs.dh.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// SessionID
	copy(hs.sessionID[:], b[:SessionIDLen])
	hs.dh.duplex.Absorb(hs.sessionID[:])
	logrus.Debugf("client: got session ID %x", hs.sessionID)
	b = b[SessionIDLen:]

	// Server Ephemeral
	copy(hs.dh.remoteEphemeral[:], b[:DHLen])
	hs.dh.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// DH (ee)
	secret, err := hs.dh.ephemeral.DH(hs.dh.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	hs.dh.duplex.Absorb(secret)

	// Certs
	encryptedCertificates := b[:encryptedCertLen]
	b = b[encryptedCertLen:]

	// Decrypt the certificates, but don't read them yet
	rawLeaf, rawIntermediate, err := DecryptCertificates(&hs.dh.duplex, encryptedCertificates)
	if err != nil {
		logrus.Debugf("client: error decrypting certificates: %s", err)
		return 0, err
	}
	logrus.Debugf("client: leaf, intermediate: %x, %x", rawLeaf, rawIntermediate)

	// Tag (Encrypted Certs)
	hs.dh.duplex.Squeeze(hs.dh.macBuf[:])
	logrus.Debugf("client: calculated sa tag: %x", hs.dh.macBuf)
	if !bytes.Equal(hs.dh.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: sa tag mismatch, got %x, wanted %x", b[:MacLen], hs.dh.macBuf)
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

	// DH (se)
	hs.dh.se, err = hs.dh.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate se: %s", err)
		return 0, err
	}
	logrus.Debugf("client: se: %x", hs.dh.se)
	hs.dh.duplex.Absorb(hs.dh.se)

	// Mac
	hs.dh.duplex.Squeeze(hs.dh.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.dh.macBuf)
	if !bytes.Equal(hs.dh.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.dh.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	return fullLength, nil
}
