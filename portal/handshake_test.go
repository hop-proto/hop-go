package portal

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

// TODO(dadrian): Actually specify transcripts?
var clientServerTranscripts = []int{0}

func TestClientServerCompatibilityHandshake(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatalf("unable to listen for packets: %s", err)
	}
	udpC := pc.(*net.UDPConn)
	s := NewServer(udpC, nil)
	go s.Serve()
	c, err := Dial("udp", pc.LocalAddr().String(), &Config{})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.Check(t, err)
	ss := s.sessions[c.sessionID]
	assert.Assert(t, ss != nil)
	assert.DeepEqual(t, c.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Equal(t, c.sessionKey, ss.key)
	assert.Check(t, c.sessionKey != zero)
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

	oldPrivate := hs.ephemeral.private

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
	assert.Check(t, cmp.Equal(oldPrivate, hs.ephemeral.private))
}
