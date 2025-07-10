package transport

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/kravatte"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/cyclist"
)

// AddressHashKey returns a string suitable for use as a key in Golang map (e.g.
// of handshakes) that identifies the remote address.
func AddressHashKey(addr *net.UDPAddr) string {
	// TODO(dadrian): Figure out if this is stable, and possible replace with
	// the same format as our cookie AD?
	key := addr.String()
	return key
}

// HandshakeState tracks state across the lifetime of a handshake, starting with
// the ClientHello. A HandshakeState may be allocated on ClientHello, it does
// not need to be stored until after the ClientAck since enough state is
// contained within the cookie to reconstruct the HandshakeState.
type HandshakeState struct {
	sni certs.Name

	sessionID [SessionIDLen]byte

	dh  *dhState
	kem *kemState

	// Certificate Stuff
	certVerify         *VerifyConfig
	leaf, intermediate []byte

	// Parsed certs
	parsedLeaf *certs.Certificate

	remoteAddr *net.UDPAddr

	duplex cyclist.Cyclist
	macBuf [MacLen]byte

	handshakeKey [KeyLen]byte

	cookieKey [KeyLen]byte // server only

	cookie []byte // client only
}

type dhState struct {
	ephemeral keys.X25519KeyPair
	static    keys.Exchangable

	remoteEphemeral [DHLen]byte

	// TODO(dadrian): Rework APIs to make these arrays and avoid copies with the curve25519 API.
	ee []byte
	es []byte
	se []byte
	ss []byte
}

type kemState struct {
	impl keys.KEM

	ephemeral keys.KEMKeypair
	// TODO paul: here the interface Exchangable is not a key pair, thus figure out what to do
	static keys.KEMKeypair

	remoteEphemeral keys.PublicKey
	remoteStatic    keys.PublicKey

	// TODO, we actually maybe never need these
	ee []byte
	es []byte
	se []byte
	ss []byte
}

func (hs *HandshakeState) writeCookie(b []byte) (int, error) {
	// TODO(dadrian): Avoid allocating memory.
	aead, err := kravatte.NewSANSE(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	plaintextCookie := hs.dh.ephemeral.Private[:]
	ad := CookieAD(hs.dh.remoteEphemeral[:], hs.remoteAddr)
	enc := aead.Seal(b[:0], nil, plaintextCookie, ad)
	if len(enc) != CookieLen {
		logrus.Panicf("len(enc) != CookieLen: %d != %d. Not possible", len(enc), CookieLen)
	}
	return len(enc), nil // CookieLen
}

func (hs *HandshakeState) decryptCookie(b []byte) (int, error) {
	if len(b) < CookieLen {
		return 0, ErrBufUnderflow
	}
	aead, err := kravatte.NewSANSE(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	encryptedCookie := b[:CookieLen]
	ad := CookieAD(hs.dh.remoteEphemeral[:], hs.remoteAddr)
	out, err := aead.Open(hs.dh.ephemeral.Private[:0], nil, encryptedCookie, ad)
	if err != nil {
		return 0, ErrInvalidMessage
	}
	if len(out) != DHLen {
		return 0, ErrInvalidMessage
	}
	hs.dh.ephemeral.PublicFromPrivate()
	return CookieLen, nil
}

func writeClientHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HelloLen {
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

	// Ephemeral
	copy(x, hs.dh.ephemeral.Public[:])
	hs.duplex.Absorb(hs.dh.ephemeral.Public[:])
	x = x[DHLen:]

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("client: client hello mac: %x", x[:MacLen])
	return HelloLen, nil
}

func readClientHello(hs *HandshakeState, b []byte) (int, error) {
	logrus.Debug("read client hello")
	if len(b) < HelloLen {
		return 0, ErrBufUnderflow
	}
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
	copy(hs.dh.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	hs.duplex.Squeeze(hs.macBuf[:])
	// TODO(dadrian): #constanttime
	logrus.Debugf("server: calculated client hello mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}
	return HelloLen, nil
}

func writeServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypeServerHello)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Ephemeral
	copy(b, hs.dh.ephemeral.Public[:])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	secret, err := hs.dh.ephemeral.DH(hs.dh.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	logrus.Debugf("server: ee: %x", secret)
	hs.duplex.Absorb(secret)

	// Cookie
	n, err := hs.writeCookie(b)
	logrus.Debugf("server: generated cookie %x", b[:n])
	if err != nil {
		return 0, err
	}
	if n != CookieLen {
		return 0, ErrBufOverflow
	}
	hs.duplex.Absorb(b[:CookieLen])
	b = b[CookieLen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	logrus.Debugf("server: sh mac %x", b[:MacLen])

	return HeaderLen + DHLen + CookieLen + MacLen, nil
}

func readServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen+MacLen {
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

	// Server Ephemeral
	copy(hs.dh.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	secret, err := hs.dh.ephemeral.DH(hs.dh.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(secret)

	// Cookie
	hs.cookie = make([]byte, CookieLen)
	copy(hs.cookie, b[:CookieLen])
	hs.duplex.Absorb(hs.cookie)
	logrus.Debugf("client: read cookie %x", hs.cookie)
	b = b[CookieLen:]

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: sh mac %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}

	return HeaderLen + DHLen + CookieLen + MacLen, nil
}

// RekeyFromSqueeze squeezes out KeyLen bytes and then re-initializes the duplex
// using the new key.
func (hs *HandshakeState) RekeyFromSqueeze(protocolName string) {
	hs.duplex.Squeeze(hs.handshakeKey[:])
	hs.duplex.Initialize(hs.handshakeKey[:], []byte(protocolName), nil)
}

// EncryptSNI encrypts the name to a buffer. The encrypted length is always
// SNILen.
func (hs *HandshakeState) EncryptSNI(dst []byte, name certs.Name) error {
	// TODO(dadrian): Avoid this memory allocation
	buf := &bytes.Buffer{}
	_, err := name.WriteTo(buf)
	logrus.Debugf("client: pre-encrypted SNI buf: %x", buf.Bytes())
	if err != nil {
		return err
	}
	// SNI is padded to SNILen
	var b [SNILen]byte
	copy(b[:], buf.Bytes())
	logrus.Debugf("client: pre-encrypted SNI: %x", b)
	hs.duplex.Encrypt(dst, b[:])
	return nil
}

func (hs *HandshakeState) writeClientAck(b []byte) (int, error) {
	length := HeaderLen + DHLen + CookieLen + SNILen + MacLen
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

	// DH
	copy(b, hs.dh.ephemeral.Public[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// Cookie
	n := copy(b, hs.cookie)
	if n != CookieLen {
		logrus.Debugf("unexpected cookie length: %d (expected %d)", n, CookieLen)
		return HeaderLen + DHLen + n, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:CookieLen])
	b = b[CookieLen:]

	// Encrypted SNI
	err := hs.EncryptSNI(b, hs.certVerify.Name)
	if err != nil {
		return HeaderLen + DHLen + CookieLen, ErrInvalidMessage
	}
	b = b[SNILen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	// b = b[MacLen:]

	return length, nil
}

func (hs *HandshakeState) readServerAuth(b []byte) (int, error) {
	minLength := HeaderLen + SessionIDLen + 2*MacLen
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
	// TODO(dadrian): Should we just get this out of UDP packet length?
	// TODO (paul): This goes wrong if the value stored is over 65535 behave like a modulo
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

	// Parse the certificate
	leaf, _, err := hs.certificateParserAndVerifier(rawLeaf, rawIntermediate)
	if err != nil {
		logrus.Debugf("client: error parsing server certificates: %s", err)
		return 0, err
	}

	// DH
	hs.dh.es, err = hs.dh.ephemeral.DH(leaf.PublicKey[:])
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", hs.dh.es)
	hs.duplex.Absorb(hs.dh.es)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	// b = b[MacLen:]

	return fullLength, nil
}

func (hs *HandshakeState) writeClientAuth(b []byte) (int, error) {
	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)
	length := HeaderLen + SessionIDLen + encCertLen + MacLen + MacLen
	if len(b) < length {
		return 0, ErrBufUnderflow
	}

	// Header
	b[0] = byte(MessageTypeClientAuth)
	b[1] = 0
	b[2] = byte(encCertLen >> 8)
	b[3] = byte(encCertLen)
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// SessionID
	copy(b, hs.sessionID[:])
	hs.duplex.Absorb(hs.sessionID[:])
	b = b[SessionIDLen:]

	// Encrypted Certificates
	if len(hs.leaf) == 0 {
		return HeaderLen + SessionIDLen, errors.New("client did not set leaf certificate")
	}
	encCerts, err := EncryptCertificates(&hs.duplex, hs.leaf, hs.intermediate)
	if err != nil {
		return HeaderLen + SessionIDLen, err
	}
	if len(encCerts) != encCertLen {
		return HeaderLen + SessionIDLen, fmt.Errorf("certificates encrypted to unexpected length %d, expected %d", len(encCerts), encCertLen)
	}
	copy(b, encCerts)
	b = b[encCertLen:]

	// Tag
	hs.duplex.Squeeze(b[:MacLen])
	b = b[MacLen:]

	// DH (se)
	hs.dh.se, err = hs.dh.static.Agree(hs.dh.remoteEphemeral[:])
	if err != nil {
		logrus.Debugf("client: unable to calculate se: %s", err)
		return HeaderLen + SessionIDLen + encCertLen + MacLen, err
	}
	logrus.Debugf("client: se: %x", hs.dh.se)
	hs.duplex.Absorb(hs.dh.se)

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	// b = b[MacLen:]

	return length, nil
}

func (hs *HandshakeState) deriveFinalKeys(clientToServerKey, serverToClientKey *[KeyLen]byte) error {
	hs.duplex.Ratchet()
	hs.duplex.Absorb([]byte("client_to_server_key"))
	hs.duplex.Squeeze(clientToServerKey[:])
	hs.duplex.Ratchet()
	hs.duplex.Absorb([]byte("server_to_client_key"))
	hs.duplex.Squeeze(serverToClientKey[:])
	logrus.Debugf("client_to_server_key: %x", *clientToServerKey)
	logrus.Debugf("server_to_client_key: %x", *serverToClientKey)
	return nil
}

func writeVector(dst []byte, src []byte) (int, error) {
	srcLen := len(src)
	if srcLen > 65535 {
		return 0, errors.New("input too long for vector")
	}
	if len(dst) < 2+srcLen {
		return 0, errors.New("dst too short")
	}
	dst[0] = byte(srcLen >> 8)
	dst[1] = byte(srcLen)
	copy(dst[2:], src)
	return 2 + srcLen, nil
}

func readVector(src []byte) (int, []byte, error) {
	srcLen := len(src)
	if srcLen < 2 {
		return 0, nil, ErrBufUnderflow
	}
	vecLen := (int(src[0]) << 8) + int(src[1])
	end := 2 + vecLen
	if srcLen < end {
		return 0, nil, ErrBufUnderflow
	}
	return vecLen, src[2:end], nil
}

func (hs *HandshakeState) certificateParserAndVerifier(rawLeaf []byte, rawIntermediate []byte) (certs.Certificate, certs.Certificate, error) {
	// Parse the certificate
	opts := certs.VerifyOptions{}
	if hs.certVerify != nil {
		opts.Name = hs.certVerify.Name
	}
	leaf := certs.Certificate{}
	intermediate := certs.Certificate{}

	leafLen, err := leaf.ReadFrom(bytes.NewBuffer(rawLeaf))
	if err != nil {
		return leaf, intermediate, err
	}
	if int(leafLen) != len(rawLeaf) {
		return leaf, intermediate, errors.New("extra bytes after leaf certificate")
	}

	if len(rawIntermediate) > 0 {
		intermediateLen, err := intermediate.ReadFrom(bytes.NewBuffer(rawIntermediate))
		if err != nil {
			return leaf, intermediate, err
		}
		if int(intermediateLen) != len(rawIntermediate) {
			return leaf, intermediate, errors.New("extra bytes after intermediate certificate")
		}
		opts.PresentedIntermediate = &intermediate
	}

	// TODO(baumanl): enable more general cert verify callback?
	// TODO(baumanl): if certVerify is nil then no verification happens --> okay default?

	if hs.certVerify != nil && !hs.certVerify.InsecureSkipVerify {
		// try authkeys first if enabled
		logrus.Debug("Beginning authentication")
		var errAuthkeys error
		if hs.certVerify.AuthKeysAllowed {
			logrus.Debug("Authkeys are allowed. attempting to validate self-signed cert")
			errAuthkeys = hs.certVerify.AuthKeys.VerifyLeaf(&leaf, opts)
		}
		if !hs.certVerify.AuthKeysAllowed || errAuthkeys != nil {
			logrus.Debug("performing certificate validation")
			err := hs.certVerify.Store.VerifyLeaf(&leaf, opts)
			if err != nil {
				logrus.Errorf("failed to verify certificate: %s", err)
				return leaf, intermediate, err
			}
			logrus.Debug("Leaf verification successful")
			logrus.Infof("Used certificate verification to authenticate")
		} else {
			logrus.Info("Used an authorized key to authenticate")
		}
	} else {
		logrus.Debug("InsecureSkipVerify set. Not verifying server certificate")
	}

	if hs.certVerify != nil && hs.certVerify.AddVerifyCallback != nil {
		logrus.Debug("additional verify callback check enabled. running...")
		if err := hs.certVerify.AddVerifyCallback(&leaf); err != nil {
			logrus.Debugf("additional verify callback returned an error: %v", err.Error())
			return leaf, intermediate, err
		}
		logrus.Debug("additional verify callback successful")
	}

	return leaf, intermediate, err
}
