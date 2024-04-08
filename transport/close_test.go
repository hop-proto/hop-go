package transport

import (
	"io"
	"net"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestClientClose(t *testing.T) {
	pcs, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)

	sc, vc := newTestServerConfig(t)
	s, err := NewServer(pcs.(*net.UDPConn), *sc)
	assert.NilError(t, err)
	go s.Serve()
	defer func() {
		// TODO(dadrian)[2024-04-07]: This test fails when ran in bulk because
		// the server runs forever because server close is not implemented.
		s.Close()
	}()

	t.Run("close after handshake, no write", func(t *testing.T) {
		_, _, cc := newClientAuthAndConfig(t, vc)
		c, err := Dial("udp", s.Addr().String(), *cc)
		assert.NilError(t, err)
		err = c.Handshake()
		assert.NilError(t, err)
		err = c.Close()
		assert.NilError(t, err)

		assert.Equal(t, c.state.Load(), clientStateClosed)

		// Closing a closed connection should succeed
		err = c.Close()
		assert.NilError(t, err)

		// Writing to a closed connection should io.EOF
		n, err := c.Write([]byte("ex post facto"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)

		// Accept the connection on the server
		h, err := s.AcceptTimeout(100 * time.Millisecond)
		assert.NilError(t, err)

		err = h.Close()
		assert.NilError(t, err)
	})

	t.Run("close with pending reads", func(t *testing.T) {
		_, _, cc := newClientAuthAndConfig(t, vc)
		c, err := Dial("udp", s.Addr().String(), *cc)
		assert.NilError(t, err)
		err = c.Handshake()
		assert.NilError(t, err)

		h, err := s.AcceptTimeout(100 * time.Millisecond)
		assert.NilError(t, err)

		assert.NilError(t, h.WriteMsg([]byte("one")))
		assert.NilError(t, h.WriteMsg([]byte("two")))

		// Hack to block until the messages have actually made it to the client,
		// even if they haven't been Read() yet.
		loop := true
		for loop {
			c.ss.handle.ss.m.Lock()
			loop = c.ss.handle.ss.window.Check(1)
			c.ss.handle.ss.m.Unlock()
		}

		err = c.Close()
		assert.NilError(t, err)

		assert.Equal(t, c.state.Load(), clientStateClosed)

		// Closing a closed connection should succeed
		err = c.Close()
		assert.NilError(t, err)

		// Writing to a closed connection should io.EOF
		n, err := c.Write([]byte("ex post facto"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)

		// We should still get two successful reads
		var buf [3]byte
		{
			n, err := c.ReadMsg(buf[:])
			assert.NilError(t, err)
			assert.Equal(t, 3, n)
			assert.Equal(t, "one", string(buf[:]))
		}
		{
			n, err := c.ReadMsg(buf[:])
			assert.NilError(t, err)
			assert.Equal(t, 3, n)
			assert.Equal(t, "two", string(buf[:]))
		}
		_, err = c.ReadMsg(buf[:])
		assert.Equal(t, err, io.EOF)

	})
}
