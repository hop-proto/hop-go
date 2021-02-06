package portal

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"zmap.io/portal/cyclist"
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
	assert.Equal(t, c.sessionKey, ss.key)
}

func TestBufferSizes(t *testing.T) {
	short := make([]byte, HeaderLen+4)
	key := GenerateNewX25519Keypair()
	duplex := cyclist.Cyclist{}
	duplex.InitializeEmpty()
	n, err := serializeToHello(&duplex, short, key)
	assert.Check(t, cmp.Equal(ErrBufOverflow, err))
	assert.Check(t, cmp.Equal(0, n))
}
