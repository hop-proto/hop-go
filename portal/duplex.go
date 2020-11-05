package portal

import (
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func (s *Server) ReplayDuplexFromCookie(cookie, clientEphemeral []byte, clientAddr *net.UDPAddr) (*HandshakeState, error) {
	var macBuf [MacLen]byte

	// Pull the private key out of the cookie
	serverPrivate, err := s.decryptCookie(cookie, clientEphemeral, clientAddr)
	if err != nil {
		return nil, err
	}

	// Fill in the ephemerals
	out := new(HandshakeState)
	copy(out.clientEphemeral[:], clientEphemeral)
	copy(out.ephemeral.private[:], serverPrivate)
	out.ephemeral.PublicFromPrivate()

	// Replay the duplex
	out.duplex.InitializeEmpty()
	out.duplex.Absorb([]byte(ProtocolName))
	// TODO(dadrian): The type conversion of MessageType are a little silly,
	// maybe the constants should just be bytes?
	out.duplex.Absorb([]byte{byte(MessageTypeClientHello), Version, 0, 0})
	out.duplex.Absorb(clientEphemeral)
	out.duplex.Squeeze(macBuf[:])
	out.duplex.Absorb([]byte{byte(MessageTypeServerHello), 0, 0, 0})
	out.duplex.Absorb(out.ephemeral.public[:])
	out.ee, err = out.ephemeral.DH(out.clientEphemeral[:])
	logrus.Debugf("replay server ee: %x", out.ee)
	if err != nil {
		return nil, err
	}
	out.duplex.Absorb(out.ee)
	out.duplex.Absorb(cookie)
	out.duplex.Squeeze(out.handshakeKey[:])
	out.duplex.Squeeze(macBuf[:])
	logrus.Debugf("server: regen sh mac: %x", macBuf[:])
	out.duplex.Initialize(out.handshakeKey[:], []byte(ProtocolName), nil)
	return out, nil
}

func CookieAD(clientEphemeral []byte, clientAddr *net.UDPAddr) []byte {
	h := sha3.New256()
	h.Write(clientEphemeral)
	// TODO(dadrian): Ensure this is always 4 or 12 bytes
	h.Write(clientAddr.IP)
	var port [2]byte
	port[0] = byte(clientAddr.Port >> 8)
	port[1] = byte(clientAddr.Port)
	h.Write(port[:])
	return h.Sum(nil)
}
