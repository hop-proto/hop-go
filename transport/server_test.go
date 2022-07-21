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

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

func newClientAuth(t *testing.T) (*keys.X25519KeyPair, *certs.Certificate) {
	k := keys.GenerateNewX25519KeyPair()
	c, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: k.Public,
	})
	assert.NilError(t, err)
	return k, c
}

func newTestServerConfig(t *testing.T) (*ServerConfig, *VerifyConfig) {
	keyPair, err := keys.ReadDHKeyFromPEMFile("testdata/leaf-key.pem")
	assert.NilError(t, err)
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	root, err := certs.ReadCertificatePEMFile("testdata/root.pem")
	assert.NilError(t, err)
	server := ServerConfig{
		KeyPair:          keyPair,
		Certificate:      certificate,
		Intermediate:     intermediate,
		HandshakeTimeout: 5 * time.Second,
	}
	verify := VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)
	return &server, &verify
}

func TestMultipleHandshakes(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverConfig, verifyConfig := newTestServerConfig(t)
	s, err := NewServer(pc.(*net.UDPConn), *serverConfig)
	defer s.Close()
	assert.NilError(t, err)
	wg := sync.WaitGroup{}
	go func() {
		s.Serve()
	}()
	kp, leaf := newClientAuth(t)
	clientConfig := ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: kp,
		Leaf:      leaf,
	}
	wg.Add(3)
	var zero [KeyLen]byte
	now := time.Now()
	start := now.Add(time.Second)
	for i := int64(0); i < 3; i++ {
		go func(i int64) {
			defer wg.Done()
			delay := time.Until(start)
			if delay > 0 {
				time.Sleep(delay)
			}
			c, err := Dial("udp", pc.LocalAddr().String(), clientConfig)
			assert.NilError(t, err)
			err = c.Handshake()

			// Server needs to finish processing the handshake
			time.Sleep(time.Second)
			assert.NilError(t, err, "error in client %d", i)

			ss := s.fetchSessionState(c.ss.sessionID)
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

func TestServerRead(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	config, verify := newTestServerConfig(t)
	config.StartingReadTimeout = 10 * time.Second
	config.MaxPendingConnections = 1
	config.MaxBufferedPacketsPerConnection = 5
	server, err := NewServer(pc.(*net.UDPConn), *config)
	defer server.Close()
	assert.NilError(t, err)
	go func() {
		server.Serve()
	}()

	t.Run("test client write", func(t *testing.T) {
		kp, cert := newClientAuth(t)
		c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{Verify: *verify, Exchanger: kp, Leaf: cert})
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
		kp, cert := newClientAuth(t)
		c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{Verify: *verify, Exchanger: kp, Leaf: cert})
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
		kp, cert := newClientAuth(t)
		c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{Verify: *verify, Exchanger: kp, Leaf: cert})
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

func TestServerWrite(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	config, verify := newTestServerConfig(t)
	config.StartingReadTimeout = 10 * time.Second
	config.MaxPendingConnections = 1
	config.MaxBufferedPacketsPerConnection = 5
	server, err := NewServer(pc.(*net.UDPConn), *config)
	defer server.Close()
	assert.NilError(t, err)
	go func() {
		server.Serve()
	}()

	t.Run("server echo", func(t *testing.T) {
		kp, leaf := newClientAuth(t)
		c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{Verify: *verify, Exchanger: kp, Leaf: leaf})
		assert.NilError(t, err)
		c.Handshake()
		h, err := server.AcceptTimeout(5 * time.Second)
		assert.NilError(t, err)

		data := make([]byte, 10)
		buf := make([]byte, 30)
		for i := 0; i < 5; i++ {
			rand.Read(data)
			n, err := c.Write(data)
			assert.Check(t, err)
			assert.Check(t, cmp.Equal(len(data), n))
			n, err = h.Read(buf)
			assert.Check(t, err)
			assert.Check(t, cmp.Equal(len(data), n))
			assert.DeepEqual(t, data, buf[:n])
			n, err = h.Write(buf[:n])
			assert.Check(t, err)
			assert.Check(t, cmp.Equal(len(data), n))
			n, err = c.Read(buf)
			assert.Check(t, err)
			assert.Check(t, cmp.Equal(len(data), n))
			assert.DeepEqual(t, data, buf[:n])
		}
	})

	t.Run("server call and response", func(t *testing.T) {
		lines := [...]string{
			"I've been waiting on a war since I was young",
			"Since I was a little boy with a toy gun",
			"Never really wanted to be number one",
			"Just wanted to love everyone",
		}

		kp, leaf := newClientAuth(t)
		c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{Verify: *verify, Exchanger: kp, Leaf: leaf})
		assert.NilError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := server.AcceptTimeout(5 * time.Second)
			assert.NilError(t, err)
			h.Write([]byte(lines[0]))
			h.Write([]byte(lines[1]))
			buf := make([]byte, len(lines[2]+lines[3]))
			pos := 0
			for pos < len(buf) {
				n, err := h.Read(buf[pos:])
				assert.NilError(t, err)
				pos += n
			}
			assert.Check(t, cmp.Equal(lines[2]+lines[3], string(buf)))
		}()
		buf := make([]byte, len(lines[0]+lines[1]))
		pos := 0
		for pos < len(buf) {
			n, err := c.Read(buf[pos:])
			assert.NilError(t, err)
			pos += n
		}
		assert.Check(t, cmp.Equal(lines[0]+lines[1], string(buf)))
		c.Write([]byte(lines[2]))
		c.Write([]byte(lines[3]))
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
