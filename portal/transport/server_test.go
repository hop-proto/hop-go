package transport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
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
	clientConfig := ClientConfig{}
	wg.Add(3)
	var zero [KeyLen]byte
	now := time.Now()
	start := now.Add(time.Second)
	for i := int64(0); i < 3; i++ {
		go func(i int64) {
			defer wg.Done()
			delay := start.Sub(time.Now())
			if delay > 0 {
				time.Sleep(delay)
			}
			c, err := Dial("udp", pc.LocalAddr().String(), &clientConfig)
			assert.NilError(t, err)
			err = c.Handshake()

			// Server needs to finish processing the handshake
			time.Sleep(time.Second)
			assert.NilError(t, err, "error in client %d", i)

			ss := s.fetchSessionState(c.ss.sessionID)
			assert.Assert(t, ss != nil)
			assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
			assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
			assert.Check(t, c.ss.clientToServerKey != zero)
			assert.Check(t, c.ss.serverToClientKey != zero)
		}(i)
	}
	wg.Wait()
}

func ExpectData(t *testing.T, expected string, wg *sync.WaitGroup) PacketCallback {
	return func(_ SessionID, msg []byte) {
		assert.Check(t, cmp.Equal(expected, string(msg)))
		wg.Done()
	}
}

func ExpectRead(t *testing.T, expected string, r io.Reader) {
	buf := make([]byte, len(expected))
	n, err := r.Read(buf)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(len(expected), n))
}

func TestReadWrite(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	config := &ServerConfig{}
	s := NewServer(pc.(*net.UDPConn), config)
	go func() {
		s.Serve()
	}()

	t.Run("test client write", func(t *testing.T) {
		c, err := Dial("udp", pc.LocalAddr().String(), nil)
		assert.NilError(t, err)
		err = c.Handshake()
		assert.NilError(t, err)
		h, err := s.AcceptTimeout(10 * time.Second)
		assert.NilError(t, err)
		s := "It's time to ignite. I'm making a fire!"
		n, err := c.Write([]byte(s))
		assert.NilError(t, err)
		assert.Check(t, cmp.Equal(len(s), n))
		ExpectRead(t, s, h)
	})

	t.Run("test client write triggers handshake", func(t *testing.T) {
		c, err := Dial("udp", pc.LocalAddr().String(), nil)
		assert.NilError(t, err)
		s := "Another splinter under the skin. Another season of loneliness."
		n, err := c.Write([]byte(s))
		assert.NilError(t, err)
		assert.Check(t, cmp.Equal(len(s), n))
	})
}
