package portal

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

// TODO(dadrian): Actually specify transcripts?
var clientServerTranscripts = []int{0}

func TestClientServerCompatibility(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatalf("unable to listen for packets: %s", err)
	}
	udpC := pc.(*net.UDPConn)
	s := NewServer(udpC, nil)
	testChan := make(chan int)
	go func() {
		for i := range clientServerTranscripts {
			t.Logf("sending %d", i)
			testChan <- i
			c, err := Dial("udp", pc.LocalAddr().String(), nil)
			if err != nil {
				t.Errorf("could not connect on transcript %d: %s", i, err)
				continue
			}
			if err := c.Handshake(); err != nil {
				t.Errorf("error in handshake index %d: %s", i, err)
			}
			c.Close()
		}
		close(testChan)
	}()
	go s.Serve()
	for transcriptIdx := range testChan {
		t.Logf("received %d", transcriptIdx)
	}
	s.Close()
	t.Fail()
}
