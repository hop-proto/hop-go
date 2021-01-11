package portal

import (
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func TestClient(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	listener, err := Listen("udp", "127.0.0.1:0", &Config{})
	assert.NilError(t, err)

	message := "Until we dance into the fire, that fatal kiss is all we need."
	response := "Dance into the fire to the sound of broken dreams."

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		assert.NilError(t, err)
		logrus.Debug("connection accepted")
		b := make([]byte, len(message))
		n, err := conn.Read(b)
		assert.NilError(t, err)
		assert.Check(t, cmp.Equal(n, len(message)))
		assert.Check(t, cmp.Equal(message, string(b)))
		n, err = conn.Write([]byte(response))
		assert.NilError(t, err)
		logrus.Debug("server: wrote response")
		assert.Equal(t, n, len(response))
	}()

	conn, err := Dial("subspace", listener.Addr().String(), &Config{})
	assert.NilError(t, err)
	err = conn.Handshake()
	logrus.Debug("client: handshake completed")
	n, err := conn.Write([]byte(message))
	assert.NilError(t, err)
	logrus.Debug("client: message sent")
	assert.Check(t, cmp.Equal(len(message), n))
	b := make([]byte, len(response))
	n, err = conn.Read(b)
	assert.NilError(t, err)
	logrus.Debugf("client: read response: %s", string(b))
	assert.Check(t, cmp.Equal(n, len(response)))
	assert.Check(t, cmp.Equal(response, string(b)))
	listener.Close()
	wg.Wait()
}
