package portal

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func TestMultipleHandshakes(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	s := NewServer(pc.(*net.UDPConn), nil)
	wg := sync.WaitGroup{}
	go func() {
		s.Serve()
	}()
	clientConfig := Config{}
	wg.Add(3)
	for i := int64(0); i < 3; i++ {
		go func(i int64) {
			defer wg.Done()
			delay := (time.Second * 3) - (time.Second * time.Duration(i))
			time.Sleep(delay)
			c, err := Dial("udp", pc.LocalAddr().String(), &clientConfig)
			assert.NilError(t, err)
			err = c.Handshake()
			assert.NilError(t, err, "error in client %d", i)
		}(i)
	}
	wg.Wait()
}
