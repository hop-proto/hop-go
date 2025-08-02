package transport

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"
	"gotest.tools/assert"
)

// TestConcurrentReadWrite verifies that ReadMsg and WriteMsg can be
// called concurrently on the same MsgConn without data races or deadlocks.
func TestConcurrentReadWrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.TraceLevel)

	// Set up server and client with a completed handshake over UDP.
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverCfg, verifyCfg := newTestServerConfig(t)
	srv, err := NewServer(pc.(*net.UDPConn), *serverCfg)
	assert.NilError(t, err)
	defer func() { assert.NilError(t, srv.Close()) }()
	go srv.Serve()

	kp, leaf := newClientAuth(t)
	clientCfg := ClientConfig{Verify: *verifyCfg, Exchanger: kp, Leaf: leaf}
	cli, err := Dial("udp", pc.LocalAddr().String(), clientCfg)
	assert.NilError(t, err)
	defer func() { assert.NilError(t, cli.Close()) }()
	assert.NilError(t, cli.Handshake())

	// Accept the connection on the server side.
	srvConn, err := srv.AcceptTimeout(5 * time.Second)
	assert.NilError(t, err)
	defer func() { assert.NilError(t, srvConn.Close()) }()

	// Echo handler: read messages into a buffer and write them back.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := srvConn.ReadMsg(buf)
			if err != nil {
				return
			}
			_ = srvConn.WriteMsg(buf[:n])
		}
	}()

	const msgCount = 100
	// Writer: send sequentially numbered messages.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < msgCount; i++ {
			data := []byte(fmt.Sprintf("message-%d", i))
			err := cli.WriteMsg(data)
			assert.NilError(t, err)
		}
	}()

	// Reader: receive and verify echoed messages.
	recvErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for i := 0; i < msgCount; i++ {
			n, err := cli.ReadMsg(buf)
			if err != nil {
				recvErr <- err
				return
			}
			got := buf[:n]
			want := []byte(fmt.Sprintf("message-%d", i))
			if !bytes.Equal(got, want) {
				recvErr <- fmt.Errorf("message mismatch: got %q, want %q", got, want)
				return
			}
		}
		recvErr <- nil
	}()

	// Wait for send to complete or timeout.
	select {
	case <-sendDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout writing messages")
	}

	// Wait for receive to complete or timeout.
	select {
	case err := <-recvErr:
		assert.NilError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout reading messages")
	}
}
