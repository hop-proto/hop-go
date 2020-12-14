package portal

import (
	"net"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
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
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		c, err := Dial("udp", pc.LocalAddr().String(), &Config{})
		assert.NilError(t, err)
		err = c.Handshake()
		assert.Check(t, err)
		ss := s.sessions[c.sessionID]
		assert.Assert(t, ss)
		assert.Equal(t, c.sessionID, ss.sessionID)
		assert.Equal(t, c.sessionKey, ss.key)
		s.Close()
		wg.Done()
	}()
	go func() {
		s.Serve()
	}()
	// TODO(dadrian): Remove the wait group once Server.Close works
	wg.Wait()
}
