package portal

import (
	"net"
	"testing"
)

// TODO(dadrian): Actually specify transcripts?
var clientServerTranscripts = []int{0, 1, 2, 3, 4, 5}

func TestClientServerCompatibility(t *testing.T) {
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
	for transcriptIdx := range testChan {
		t.Logf("received %d", transcriptIdx)
		err := s.AcceptHandshake()
		t.Error(err)
	}
}
