package transport

import (
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/cyclist"
)

func (s *Server) ReplayDuplexFromCookie(cookie, clientEphemeral []byte, clientAddr *net.UDPAddr) (*HandshakeState, error) {
	out := new(HandshakeState)
	copy(out.remoteEphemeral[:], clientEphemeral)
	out.remoteAddr = clientAddr
	out.cookieKey = &s.cookieKey

	// Pull the private key out of the cookie
	n, err := out.decryptCookie(cookie)
	if err != nil {
		return nil, err
	}
	if n != CookieLen {
		return nil, ErrInvalidMessage
	}

	// Replay the duplex
	out.duplex.InitializeEmpty()
	out.duplex.Absorb([]byte(ProtocolName))
	// TODO(dadrian): The type conversion of MessageType are a little silly,
	// maybe the constants should just be bytes?
	out.duplex.Absorb([]byte{byte(MessageTypeClientHello), Version, 0, 0})
	out.duplex.Absorb(clientEphemeral)
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen ch mac: %x", out.macBuf[:])
	out.duplex.Absorb([]byte{byte(MessageTypeServerHello), 0, 0, 0})
	out.duplex.Absorb(out.ephemeral.public[:])
	out.ee, err = out.ephemeral.DH(out.remoteEphemeral[:])
	logrus.Debugf("replay server ee: %x", out.ee)
	if err != nil {
		return nil, err
	}
	out.duplex.Absorb(out.ee)
	out.duplex.Absorb(cookie)
	out.duplex.Squeeze(out.macBuf[:])
	logrus.Debugf("server: regen sh mac: %x", out.macBuf[:])
	out.RekeyFromSqueeze()
	return out, nil
}

func CookieAD(ephemeral *[DHLen]byte, clientAddr *net.UDPAddr) []byte {
	// TODO(dadrian): Remove the memory allocation
	h := sha3.New256()
	h.Write(ephemeral[:])
	// TODO(dadrian): Ensure this is always 4 or 12 bytes
	h.Write(clientAddr.IP)
	var port [2]byte
	port[0] = byte(clientAddr.Port >> 8)
	port[1] = byte(clientAddr.Port)
	h.Write(port[:])
	return h.Sum(nil)
}

// TODO(dadrian): Remove memory allocation
// TODO(dadrian): Don't reveal length
func EncryptCertificates(duplex *cyclist.Cyclist, leaf, intermediate []byte) ([]byte, error) {
	b := make([]byte, len(leaf)+len(intermediate)+4)
	x := b
	n, err := writeVector(x, leaf)
	if err != nil {
		return nil, err
	}
	x = b[n:]
	n, err = writeVector(x, intermediate)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(b))
	duplex.Encrypt(out, b)
	return out, nil
}

// TODO(dadrian): Handle padding
func EncryptedCertificatesLength(leaf, intermediate []byte) int {
	return 4 + len(leaf) + len(intermediate)
}

func DecryptCertificates(duplex *cyclist.Cyclist, ciphertext []byte) ([]byte, []byte, error) {
	out := make([]byte, len(ciphertext))
	duplex.Decrypt(out, ciphertext)
	x := out
	leafLen, leaf, err := readVector(x)
	if err != nil {
		return nil, nil, err
	}
	x = x[2+leafLen:]
	_, intermediate, err := readVector(x)
	if err != nil {
		return nil, nil, err
	}
	return leaf, intermediate, nil
}
