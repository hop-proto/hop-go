package transport

import (
	"bytes"
	"crypto/rand"
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

func ExpectRead(t *testing.T, expected string, r io.Reader) {
	buf := make([]byte, len(expected))
	n, err := r.Read(buf)
	logrus.Debugf("read %d bytes, err?: %s", n, err)
	assert.Check(t, err)
	assert.Check(t, cmp.Equal(len(expected), n))
}

func TestReadWrite(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	config := &ServerConfig{
		StartingReadTimeout:             10 * time.Second,
		MaxPendingConnections:           1,
		MaxBufferedPacketsPerConnection: 5,
	}
	server := NewServer(pc.(*net.UDPConn), config)
	go func() {
		server.Serve()
	}()

	t.Run("test client write", func(t *testing.T) {
		c, err := Dial("udp", pc.LocalAddr().String(), nil)
		assert.NilError(t, err)
		err = c.Handshake()
		assert.NilError(t, err)
		h, err := server.AcceptTimeout(10 * time.Second)
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
		h, err := server.AcceptTimeout(10 * time.Second)
		assert.NilError(t, err)
		assert.Check(t, cmp.Equal(len(s), n))
		ExpectRead(t, s, h)
	})

	t.Run("test big client writes", func(t *testing.T) {
		c, err := Dial("udp", pc.LocalAddr().String(), nil)
		assert.NilError(t, err)
		data := make([]byte, 3100)
		n, err := rand.Read(data)
		assert.NilError(t, err)
		assert.Assert(t, cmp.Equal(n, len(data)))
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := server.AcceptTimeout(5 * time.Second)
			assert.NilError(t, err)
			buf := make([]byte, 1000)
			for i := 0; i < 5; i++ {
				soFar := 0
				for soFar < len(data) {
					n, err := h.Read(buf)
					assert.NilError(t, err)
					assert.DeepEqual(t, data[soFar:soFar+n], buf[:n])
					soFar += n
				}
				assert.Check(t, cmp.Equal(len(data), soFar))
			}
		}()
		for i := 0; i < 5; i++ {
			n, err := c.Write(data)
			assert.NilError(t, err)
			assert.Check(t, cmp.Equal(len(data), n))
		}
		wg.Wait()
	})
}

func TestBufferBehavior(t *testing.T) {
	data := []byte("hi this is some data!")
	buf := bytes.Buffer{}
	assert.Equal(t, 0, buf.Len())
	n, err := buf.Write(data)
	assert.NilError(t, err)
	assert.Equal(t, len(data), n)
	readBuf := make([]byte, 100)
	n, err = buf.Read(readBuf)
	assert.NilError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, 0, buf.Len())
	buf.Reset()
	assert.Equal(t, 0, buf.Len())
	assert.Assert(t, buf.Cap() != 0)
}
