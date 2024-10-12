package transport

import (
	"encoding/binary"
	"errors"
	"github.com/vektra/tai64n"
	"hop.computer/hop/certs"
	"time"

	"github.com/sirupsen/logrus"
)

// TODO(hosono) In the paper, the hidden mode client hello is called "Client Request"
// which seems like an ambiguous name. I've changed it to ClientRequestHidden
func (hs *HandshakeState) writeClientRequestHiddenOld(b []byte) (int, error) {
	logrus.Debug("Sending client request (hidden mode)")
	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)

	// TODO(hosono) calculate length correctly
	length := HeaderLen + DHLen + encCertLen + MacLen + TimestampLen + MacLen
	if len(b) > length {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	binary.BigEndian.PutUint16(b[2:], uint16(encCertLen))
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Client Ephemeral key for Diffie-Hellman
	copy(b, hs.ephemeral.Public[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// Encrypted Certificates
	if (len(hs.leaf)) == 0 {
		// TODO(hosono) this error can also happen in writeClientAuth
		// either consolidate or eliminate them
		return HeaderLen + DHLen, errors.New("client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.duplex, hs.leaf, hs.intermediate)
	if err != nil {
		return HeaderLen + DHLen, err
	}
	if len(encCerts) != encCertLen {
		// TODO(hosono) same with the error above. Consolidate or eliminate
		return HeaderLen + DHLen, errors.New("certificates encrypted to unexpected length")
	}
	copy(b, encCerts)
	b = b[encCertLen:]

	// Client Static Auth Tag
	// TODO(hosono) Is this correct? I don't know what this means
	hs.duplex.Squeeze(b[:MacLen])
	b = b[MacLen:]

	// Timestamp
	now := time.Now().Unix()
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(now))
	hs.duplex.Encrypt(b, timeBytes)
	b = b[TimestampLen:]

	// MAC Tag
	hs.duplex.Squeeze(b[:MacLen])
	b = b[MacLen:]

	return length, nil
}

func (hs *HandshakeState) writeClientRequestHidden(b []byte, leaf *certs.Certificate) (int, error) {

	logrus.Debug("client: sending client request (hidden mode)")

	length := HeaderLen + DHLen + DHLen + MacLen + TimestampLen + MacLen

	if len(b) < length {
		return 0, ErrBufOverflow
	}

	pos := 0

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	b[2] = 0
	b[3] = 0

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
	serverStatic := leaf.PublicKey[:]
	secret, err := hs.ephemeral.DH(serverStatic)
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", secret)
	hs.duplex.Absorb(secret)

	// Client Static key for Diffie-Hellman (s)
	clientStatic := hs.static.Share()
	logrus.Debugf("client: static %x", clientStatic)
	hs.duplex.Encrypt(b, clientStatic[:])
	b = b[DHLen:]

	pos += DHLen

	// Tag
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("client: hidden handshake tag %x", b[:MacLen])
	b = b[MacLen:]

	pos += MacLen

	// DH (ss)
	hs.ss, err = hs.static.Agree(serverStatic)
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
	// b = b[MacLen:]
	pos += MacLen

	return pos, err
}
