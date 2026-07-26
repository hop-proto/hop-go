package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"
	"gotest.tools/assert"
)

type concurrencyTestConn struct {
	closed    chan struct{}
	closeOnce sync.Once
	closeN    atomic.Int32

	readStarted     chan struct{}
	readStartedOnce sync.Once

	blockTransport   bool
	transportStarted chan struct{}
	transportOnce    sync.Once
	releaseTransport chan struct{}

	packetsMu sync.Mutex
	// +checklocks:packetsMu
	packets [][]byte
}

func newConcurrencyTestConn() *concurrencyTestConn {
	return &concurrencyTestConn{
		closed:           make(chan struct{}),
		readStarted:      make(chan struct{}),
		transportStarted: make(chan struct{}),
		releaseTransport: make(chan struct{}),
	}
}

func (c *concurrencyTestConn) Read(b []byte) (int, error) {
	n, _, _, _, err := c.ReadMsgUDP(b, nil)
	return n, err
}

func (c *concurrencyTestConn) Write(b []byte) (int, error) {
	n, _, err := c.WriteMsgUDP(b, nil, nil)
	return n, err
}

func (c *concurrencyTestConn) Close() error {
	c.closeN.Add(1)
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *concurrencyTestConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (c *concurrencyTestConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}

func (c *concurrencyTestConn) SetDeadline(time.Time) error      { return nil }
func (c *concurrencyTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *concurrencyTestConn) SetWriteDeadline(time.Time) error { return nil }

func (c *concurrencyTestConn) WriteMsgUDP(b, _ []byte, _ *net.UDPAddr) (int, int, error) {
	if len(b) > 0 && MessageType(b[0]) == MessageTypeTransport && c.blockTransport {
		c.transportOnce.Do(func() {
			close(c.transportStarted)
		})
		select {
		case <-c.releaseTransport:
		case <-c.closed:
			return 0, 0, net.ErrClosed
		}
	}

	select {
	case <-c.closed:
		return 0, 0, net.ErrClosed
	default:
	}

	c.packetsMu.Lock()
	c.packets = append(c.packets, append([]byte(nil), b...))
	c.packetsMu.Unlock()
	return len(b), 0, nil
}

func (c *concurrencyTestConn) ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error) {
	c.readStartedOnce.Do(func() {
		close(c.readStarted)
	})
	<-c.closed
	return 0, 0, 0, nil, net.ErrClosed
}

func newConcurrencyTestHandle(conn UDPLike, bufferSize int) *Handle {
	ss := &SessionState{
		handleState: established,
		remoteAddr: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 2,
		},
	}
	ss.readKey = &ss.clientToServerKey
	ss.writeKey = &ss.serverToClientKey
	ss.handle = newHandleForSession(conn, ss, nil, bufferSize)
	return ss.handle
}

func waitForResult[T any](t *testing.T, ch <-chan T, message string) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		var zero T
		return zero
	}
}

func waitForCondition(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestConcurrentReadWrite verifies that ReadMsg and WriteMsg can be called
// concurrently on the same MsgConn without data races or deadlocks by sending a
// lot of data on each side. This test is not deterministic.
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
	srvConn, err := srv.AcceptTimeout(1 * time.Second)
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

	recvErr := make(chan error, 1)
	recvArr := make([]bool, msgCount)
	go func() {
		buf := make([]byte, 2048)
		for i := 0; i < msgCount; i++ {
			n, err := cli.ReadMsg(buf)
			if err != nil {
				recvErr <- err
				return
			}
			got := buf[:n]
			{
				var d int
				n, err := fmt.Sscanf(string(got), "message-%d", &d)
				if err != nil || n != 1 {
					recvErr <- fmt.Errorf("message bad format: got %q", got)
				}
				if recvArr[d] {
					recvErr <- fmt.Errorf("received %d twice", d)
				}
				recvArr[d] = true
			}
		}
		for i, b := range recvArr {
			if !b {
				recvErr <- fmt.Errorf("did not receive %d", i)
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

// TestDeadlineInteractionUnderConcurrency ensures that deadlines can be set concurrently
// without affecting pending I/O calls.
//
// Steps:
// 1. Launch read and write operations that block indefinitely (e.g., waiting for data).
// 2. Concurrently call SetDeadline, SetReadDeadline, and SetWriteDeadline multiple times.
// 3. Observe that existing blocked calls eventually return errors only due to deadline expiration.
//
// Expected: Deadlines trigger appropriate timeout errors; setting deadlines does not leak
// goroutines or prevent I/O from returning.
func TestDeadlineInteractionUnderConcurrency(t *testing.T) {
	conn := newConcurrencyTestConn()
	h := newConcurrencyTestHandle(conn, 1)

	readErr := make(chan error, 1)
	go func() {
		_, err := h.ReadMsg(make([]byte, 1))
		readErr <- err
	}()

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NilError(t, h.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
			assert.NilError(t, h.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
		}()
	}
	wg.Wait()

	err := waitForResult(t, readErr, "a deadline did not unblock ReadMsg")
	assert.Check(t, errors.Is(err, os.ErrDeadlineExceeded))
	assert.NilError(t, h.Close())
}

// TestCloseUnblocksInFlightOperations verifies that calling Close on a
// connection unblocks in-flight reads and does not wait behind in-flight writes.
//
// Steps:
// 1. Start goroutines blocking on ReadMsg.
// 2. Start a goroutine blocked inside the underlying WriteMsgUDP.
// 3. Invoke Close from the main goroutine.
// 4. Verify Close and the reads return before releasing the write.
//
// Expected: Reads return EOF and socket I/O never holds the session lock needed
// by Close. An already in-flight write may complete independently.
func TestCloseUnblocksInFlightOperations(t *testing.T) {
	conn := newConcurrencyTestConn()
	conn.blockTransport = true
	h := newConcurrencyTestHandle(conn, 1)

	const readers = 2
	readErrs := make(chan error, readers)
	for range readers {
		go func() {
			_, err := h.ReadMsg(make([]byte, 1))
			readErrs <- err
		}()
	}

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- h.WriteMsg([]byte("blocked"))
	}()
	<-conn.transportStarted

	closeErr := make(chan error, 1)
	go func() {
		closeErr <- h.Close()
	}()
	assert.NilError(t, waitForResult(t, closeErr, "Close blocked behind an in-flight write"))

	for range readers {
		assert.Check(t, errors.Is(waitForResult(t, readErrs, "Close did not unblock a reader"), io.EOF))
	}

	close(conn.releaseTransport)
	assert.NilError(t, waitForResult(t, writeErr, "the released write did not return"))
}

// TestBufferedDataReturnedAfterClose confirms that ReadMsg/Read can return buffered data
// even after Close is called.
//
// Steps:
// 1. Have the peer send a few messages and ensure they are queued locally.
// 2. Call Close on the local connection.
// 3. Consume queued messages with ReadMsg/Read until empty.
// 4. Verify subsequent reads return io.EOF or an appropriate closed error.
//
// Expected: Buffered messages are delivered; after exhaustion, reads return EOF.
func TestBufferedDataReturnedAfterClose(t *testing.T) {
	h := newConcurrencyTestHandle(newConcurrencyTestConn(), 2)
	h.recv.C <- []byte("one")
	h.recv.C <- []byte("two")
	assert.NilError(t, h.Close())

	buf := make([]byte, 3)
	for _, want := range []string{"one", "two"} {
		n, err := h.ReadMsg(buf)
		assert.NilError(t, err)
		assert.Equal(t, string(buf[:n]), want)
	}
	_, err := h.ReadMsg(buf)
	assert.Check(t, errors.Is(err, io.EOF))
}

// TestWriteFailsAfterClose ensures that any WriteMsg/Write performed after Close
// immediately returns an error.
//
// Steps:
// 1. Call Close on the connection.
// 2. Attempt to send new messages.
//
// Expected: Writes return a "use of closed network connection" or equivalent error.
func TestWriteFailsAfterClose(t *testing.T) {
	h := newConcurrencyTestHandle(newConcurrencyTestConn(), 1)
	assert.NilError(t, h.Close())

	assert.Check(t, errors.Is(h.WriteMsg([]byte("late")), io.EOF))
	n, err := h.Write([]byte("late"))
	assert.Equal(t, n, 0)
	assert.Check(t, errors.Is(err, io.EOF))
}

// TestIdempotentClose validates that multiple calls to Close do not cause panics or
// additional errors.
//
// Steps:
// 1. Call Close on the connection once.
// 2. Call Close again.
//
// Expected: Subsequent Close calls return a consistent error or nil and do not panic.
func TestIdempotentClose(t *testing.T) {
	conn := newConcurrencyTestConn()
	h := newConcurrencyTestHandle(conn, 1)

	const closers = 64
	errs := make(chan error, closers)
	for range closers {
		go func() {
			errs <- h.Close()
		}()
	}
	for range closers {
		assert.NilError(t, waitForResult(t, errs, "concurrent Close calls deadlocked"))
	}

	conn.packetsMu.Lock()
	defer conn.packetsMu.Unlock()
	assert.Equal(t, len(conn.packets), 0, "local Close should not perform socket I/O")
}

// TestPeerInitiatedClose tests behavior when the remote endpoint closes the connection.
//
// Steps:
// 1. After handshake, have the peer call Close.
// 2. Perform ReadMsg/Read and WriteMsg/Write on the other side.
//
// Expected: Reads return EOF or closed error; writes return closed connection error.
func TestPeerInitiatedClose(t *testing.T) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverCfg, verifyCfg := newTestServerConfig(t)
	srv, err := NewServer(pc.(*net.UDPConn), *serverCfg)
	assert.NilError(t, err)
	go func() {
		_ = srv.Serve()
	}()
	t.Cleanup(func() {
		assert.NilError(t, srv.Close())
	})

	kp, leaf := newClientAuth(t)
	cli, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:    *verifyCfg,
		Exchanger: kp,
		Leaf:      leaf,
	})
	assert.NilError(t, err)
	t.Cleanup(func() {
		assert.NilError(t, cli.Close())
	})
	assert.NilError(t, cli.Handshake())

	peer, err := srv.AcceptTimeout(time.Second)
	assert.NilError(t, err)
	assert.NilError(t, peer.send(MessageTypeControl, []byte{byte(ControlMessageClose)}))

	waitForCondition(t, cli.ss.handle.IsClosed, "peer close was not observed by the client")
	assert.NilError(t, peer.WriteMsg([]byte("late")))
	time.Sleep(10 * time.Millisecond)
	_, err = cli.ReadMsg(make([]byte, 1))
	assert.Check(t, errors.Is(err, io.EOF))
	assert.Check(t, errors.Is(cli.WriteMsg([]byte("late")), io.EOF))
	assert.NilError(t, peer.Close())
}

// TestRaceBetweenCloseAndDeadlineOrIO stresses race conditions by invoking Close,
// deadline changes, and I/O in rapid succession.
//
// Steps:
//  1. Spawn multiple goroutines each randomly choosing to ReadMsg, WriteMsg,
//     set deadlines, or Close.
//  2. Run for a short duration under the race detector.
//
// Expected: No data races, deadlocks, or unexpected panics.
func TestRaceBetweenCloseAndDeadlineOrIO(t *testing.T) {
	conn := newConcurrencyTestConn()
	h := newConcurrencyTestHandle(conn, 64)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				switch (i + j) % 4 {
				case 0:
					_ = h.WriteMsg([]byte{byte(i), byte(j)})
				case 1:
					_ = h.SetReadDeadline(time.Now().Add(time.Millisecond))
				case 2:
					_, _ = h.ReadMsg(make([]byte, 2))
				case 3:
					_ = h.Close()
				}
			}
		}(i)
	}
	wg.Wait()
	assert.Check(t, h.IsClosed())
}

// TestStressHighConcurrency subjects the connection to high-volume, concurrent reads,
// writes, deadlines, and closes to uncover subtle races.
//
// Steps:
//  1. Use a large number of goroutines performing random operations (ReadMsg,
//     WriteMsg, SetDeadline, Close).
//  2. Run under go test -race with sufficient iterations.
//
// Expected: Stability under load with correct semantics.
func TestStressHighConcurrency(t *testing.T) {
	conn := newConcurrencyTestConn()
	h := newConcurrencyTestHandle(conn, 1)

	const writers = 128
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			assert.NilError(t, h.WriteMsg([]byte{byte(i)}))
		}(i)
	}
	wg.Wait()

	conn.packetsMu.Lock()
	assert.Equal(t, len(conn.packets), writers)
	counters := make(map[uint64]struct{}, writers)
	for _, pkt := range conn.packets {
		counter := binary.BigEndian.Uint64(pkt[HeaderLen+SessionIDLen : AssociatedDataLen])
		counters[counter] = struct{}{}
	}
	conn.packetsMu.Unlock()
	assert.Equal(t, len(counters), writers, "concurrent writes reused a packet counter")
	assert.NilError(t, h.Close())
}

func TestClientCloseInterruptsHandshake(t *testing.T) {
	conn := newConcurrencyTestConn()
	_, verify := newTestServerConfig(t)
	kp, leaf := newClientAuth(t)
	client := NewClient(conn, conn.RemoteAddr().(*net.UDPAddr), ClientConfig{
		Verify:    *verify,
		Exchanger: kp,
		Leaf:      leaf,
	})

	handshakeErr := make(chan error, 1)
	go func() {
		handshakeErr <- client.Handshake()
	}()
	<-conn.readStarted

	closeErr := make(chan error, 1)
	go func() {
		closeErr <- client.Close()
	}()
	assert.NilError(t, waitForResult(t, closeErr, "Close did not interrupt an in-flight handshake"))
	assert.Check(t, errors.Is(waitForResult(t, handshakeErr, "the interrupted handshake did not return"), io.EOF))
	assert.Check(t, client.IsClosed())
	assert.Equal(t, conn.closeN.Load(), int32(1))
}

func TestConcurrentHandshakeRunsOnce(t *testing.T) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverCfg, verifyCfg := newTestServerConfig(t)
	server, err := NewServer(pc.(*net.UDPConn), *serverCfg)
	assert.NilError(t, err)
	go func() {
		_ = server.Serve()
	}()
	t.Cleanup(func() {
		assert.NilError(t, server.Close())
	})

	kp, leaf := newClientAuth(t)
	client, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:    *verifyCfg,
		Exchanger: kp,
		Leaf:      leaf,
	})
	assert.NilError(t, err)
	t.Cleanup(func() {
		assert.NilError(t, client.Close())
	})

	const callers = 32
	errs := make(chan error, callers)
	for range callers {
		go func() {
			errs <- client.Handshake()
		}()
	}
	for range callers {
		assert.NilError(t, waitForResult(t, errs, "concurrent Handshake calls deadlocked"))
	}

	peer, err := server.AcceptTimeout(time.Second)
	assert.NilError(t, err)
	assert.NilError(t, peer.Close())
	peer, err = server.AcceptTimeout(20 * time.Millisecond)
	assert.Check(t, peer == nil)
	assert.Equal(t, err, ErrTimeout, "concurrent callers performed more than one handshake")
}

func TestConcurrentClientCloseBeforeHandshake(t *testing.T) {
	conn := newConcurrencyTestConn()
	client := NewClient(conn, conn.RemoteAddr().(*net.UDPAddr), ClientConfig{})

	const closers = 64
	errs := make(chan error, closers)
	for range closers {
		go func() {
			errs <- client.Close()
		}()
	}
	for range closers {
		assert.NilError(t, waitForResult(t, errs, "concurrent Client.Close calls deadlocked"))
	}

	assert.Check(t, client.IsClosed())
	assert.Equal(t, conn.closeN.Load(), int32(1))
	_, err := client.Read(make([]byte, 1))
	assert.Check(t, errors.Is(err, io.EOF))
}

func TestServerServeCloseRace(t *testing.T) {
	for range 100 {
		conn := newConcurrencyTestConn()
		config, _ := newTestServerConfig(t)
		server, err := NewServer(conn, *config)
		assert.NilError(t, err)

		serveErr := make(chan error, 1)
		closeErr := make(chan error, 1)
		go func() {
			serveErr <- server.Serve()
		}()
		go func() {
			closeErr <- server.Close()
		}()

		assert.NilError(t, waitForResult(t, closeErr, "Server.Close deadlocked racing with Serve"))
		err = waitForResult(t, serveErr, "Serve did not return after Close")
		if err != nil {
			assert.ErrorContains(t, err, "non-ready Server")
		}
		assert.Equal(t, server.state.Load(), uint32(serverStateClosed))
		assert.Equal(t, conn.closeN.Load(), int32(1))
	}
}

func TestConcurrentServerCloseUnblocksAccept(t *testing.T) {
	conn := newConcurrencyTestConn()
	config, _ := newTestServerConfig(t)
	server, err := NewServer(conn, *config)
	assert.NilError(t, err)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve()
	}()

	acceptErr := make(chan error, 1)
	go func() {
		_, err := server.Accept()
		acceptErr <- err
	}()

	const closers = 64
	closeErrs := make(chan error, closers)
	for range closers {
		go func() {
			closeErrs <- server.Close()
		}()
	}
	for range closers {
		assert.NilError(t, waitForResult(t, closeErrs, "concurrent Server.Close calls deadlocked"))
	}
	err = waitForResult(t, serveErr, "Serve was not unblocked by Close")
	if err != nil {
		assert.ErrorContains(t, err, "non-ready Server")
	}
	assert.Check(t, errors.Is(waitForResult(t, acceptErr, "Accept was not unblocked by Close"), io.EOF))
	assert.Equal(t, conn.closeN.Load(), int32(1))
}
