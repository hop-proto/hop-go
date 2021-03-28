package transport

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func TestClientServerCompatibilityHandshake(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	udpC := pc.(*net.UDPConn)
	s, err := NewServer(udpC, newTestServerConfig(t))
	assert.NilError(t, err)
	go s.Serve()
	c, err := Dial("udp", pc.LocalAddr().String(), &ClientConfig{})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.Check(t, err)
	time.Sleep(time.Second)
	ss := s.sessions[c.ss.sessionID]
	assert.Assert(t, ss != nil)
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)
}

func TestBufferSizes(t *testing.T) {
	short := make([]byte, HeaderLen+4)
	hs := new(HandshakeState)
	hs.duplex.InitializeEmpty()
	hs.ephemeral.Generate()
	n, err := writeClientHello(hs, short)
	assert.Check(t, cmp.Equal(ErrBufOverflow, err))
	assert.Check(t, cmp.Equal(0, n))
}

func TestCookie(t *testing.T) {
	var cookieKey [KeyLen]byte
	_, err := rand.Read(cookieKey[:])
	assert.NilError(t, err)
	hs := HandshakeState{}
	hs.duplex.InitializeEmpty()
	hs.duplex.Absorb([]byte("some data that is longish"))
	hs.ephemeral.Generate()
	_, err = rand.Read(hs.remoteEphemeral[:])
	assert.NilError(t, err)

	oldPrivate := hs.ephemeral.Private

	hs.remoteAddr = &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8675,
	}
	hs.cookieKey = &cookieKey
	cookie := make([]byte, 2*CookieLen)
	n, err := hs.writeCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, n))
	assert.NilError(t, err)

	bytesRead, err := hs.decryptCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, bytesRead))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(oldPrivate, hs.ephemeral.Private))
}
