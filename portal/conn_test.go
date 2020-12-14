package portal

import (
	"sync"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func TestClient(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", &Config{})
	assert.NilError(t, err)

	message := "Until we dance into the fire, that fatal kiss is all we need."

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		conn, err := listener.Accept()
		assert.NilError(t, err)
		b := make([]byte, len(message))
		n, err := conn.Read(b)
		assert.NilError(t, err)
		assert.Check(t, cmp.Equal(len(message), n))
		assert.Check(t, cmp.Equal(message, string(b)))
		wg.Done()
	}()

	conn, err := Dial("subspace", listener.Addr().String(), &Config{})
	assert.NilError(t, err)
	n, err := conn.Write([]byte(message))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(len(message), n))
	listener.Close()
	wg.Wait()
}
