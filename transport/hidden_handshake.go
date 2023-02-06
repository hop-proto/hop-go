package transport

import (
	"errors"
)

// TODO(hosono) In the paper, the hidden mode client hello is called "Client Request"
// which seems like an ambiguous name. I've changed it to ClientRequestHidden
func (hs *HandshakeState) writeClientRequestHidden(b []byte) (int, error) {
	encCertLen := EncryptedCertificatesLength(hs.leaf, hs.intermediate)

	// TODO(hosono) calculate length correctly
	length := HeaderLen + encCertLen
	if len(b) > length {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = byte(MessageTypeClientRequestHidden)
	b[1] = Version
	b[2] = byte(encCertLen >> 8)
	b[3] = byte(encCertLen)
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

	timestamp := hs.duplex.Encrypt(TAI64())
}
