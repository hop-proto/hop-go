package transport

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"
	"gotest.tools/assert"
)

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

// newConnPair sets up a Server, a Client, and the server-side Handle for a
// single connection that has completed its handshake. The caller is responsible
// for closing the returned Server (which tears down the Handle) and Client.
func newConnPair(t *testing.T) (*Server, *Client, *Handle) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverCfg, verifyCfg := newTestServerConfig(t)
	srv, err := NewServer(pc.(*net.UDPConn), *serverCfg)
	assert.NilError(t, err)
	go srv.Serve()

	kp, leaf := newClientAuth(t)
	clientCfg := ClientConfig{Verify: *verifyCfg, Exchanger: kp, Leaf: leaf}
	cli, err := Dial("udp", srv.Addr().String(), clientCfg)
	assert.NilError(t, err)
	assert.NilError(t, cli.Handshake())

	h, err := srv.AcceptTimeout(2 * time.Second)
	assert.NilError(t, err)
	return srv, cli, h
}

// waitForReceived blocks until the SessionState has received (and decrypted) a
// packet with the given counter, indicating that all packets up to and
// including highestCount have been delivered to the local receive queue. It
// fails the test if that does not happen within a couple of seconds.
func waitForReceived(t *testing.T, ss *SessionState, highestCount uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ss.m.Lock()
		// Check returns false once the counter has been marked as seen.
		seen := !ss.window.Check(highestCount)
		ss.m.Unlock()
		if seen {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for messages to arrive")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestDeadlineInteractionUnderConcurrency ensures that deadlines can be set
// concurrently without corrupting deadline state, and that a read blocked with
// no data returns a timeout error once its deadline is exceeded.
func TestDeadlineInteractionUnderConcurrency(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.ErrorLevel)

	srv, cli, h := newConnPair(t)
	defer srv.Close()
	defer cli.Close()
	_ = h

	// Invariant: a read that blocks with no data available returns a timeout
	// error wrapping os.ErrDeadlineExceeded once the read deadline passes.
	t.Run("blocked read times out", func(t *testing.T) {
		assert.NilError(t, cli.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
		buf := make([]byte, 32)
		_, err := cli.ReadMsg(buf)
		assert.Assert(t, errors.Is(err, os.ErrDeadlineExceeded), "expected deadline error, got %v", err)
		// Unexpire the deadline so later operations aren't immediately timed out.
		assert.NilError(t, cli.SetReadDeadline(time.Time{}))
	})

	// Invariant: SetDeadline, SetReadDeadline, and SetWriteDeadline may be called
	// from many goroutines simultaneously without data races, panics, or
	// deadlocks, and the connection remains usable afterwards.
	t.Run("concurrent deadline setters are safe", func(t *testing.T) {
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(seed int) {
				defer wg.Done()
				d := time.Duration(seed) * time.Millisecond
				for {
					select {
					case <-stop:
						return
					default:
					}
					cli.SetDeadline(time.Now().Add(d))
					cli.SetReadDeadline(time.Time{})
					cli.SetWriteDeadline(time.Now().Add(d))
				}
			}(i)
		}
		time.Sleep(200 * time.Millisecond)
		close(stop)
		wg.Wait()

		// The connection should still be usable: clearing deadlines succeeds and a
		// message written by the peer is still readable.
		assert.NilError(t, cli.SetDeadline(time.Time{}))
		assert.NilError(t, h.WriteMsg([]byte("still alive")))
		buf := make([]byte, 32)
		assert.NilError(t, cli.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err := cli.ReadMsg(buf)
		assert.NilError(t, err)
		assert.Equal(t, "still alive", string(buf[:n]))
	})
}

// TestCloseUnblocksInFlightOperations verifies that calling Close on a
// connection promptly unblocks any in-flight ReadMsg/Read call with io.EOF.
//
// Note: Write/WriteMsg do not block in this transport (packets are handed to the
// underlying socket immediately), so there is no in-flight write to unblock.
func TestCloseUnblocksInFlightOperations(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	t.Run("client", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		_ = h

		readReturned := make(chan error, 1)
		go func() {
			_, err := cli.ReadMsg(make([]byte, 32))
			readReturned <- err
		}()
		// Give the read a chance to reach its blocking state.
		time.Sleep(100 * time.Millisecond)

		start := time.Now()
		assert.NilError(t, cli.Close())
		select {
		case err := <-readReturned:
			assert.Equal(t, io.EOF, err)
			assert.Assert(t, time.Since(start) < time.Second, "Close was slow to unblock read")
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not unblock pending read")
		}
	})

	t.Run("handle", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		defer cli.Close()

		readReturned := make(chan error, 1)
		go func() {
			_, err := h.ReadMsg(make([]byte, 32))
			readReturned <- err
		}()
		time.Sleep(100 * time.Millisecond)

		start := time.Now()
		assert.NilError(t, h.Close())
		select {
		case err := <-readReturned:
			assert.Equal(t, io.EOF, err)
			assert.Assert(t, time.Since(start) < time.Second, "Close was slow to unblock read")
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not unblock pending read on Handle")
		}
	})
}

// TestBufferedDataReturnedAfterClose confirms that ReadMsg can return data that
// was queued locally before Close was called, and that reads return io.EOF only
// once the buffered data is exhausted.
func TestBufferedDataReturnedAfterClose(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	t.Run("client reads buffered data", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()

		msgs := []string{"alpha", "bravo", "charlie"}
		for _, m := range msgs {
			assert.NilError(t, h.WriteMsg([]byte(m)))
		}
		// Ensure all messages have been received by the client before closing.
		waitForReceived(t, cli.ss, uint64(len(msgs)-1))

		assert.NilError(t, cli.Close())

		buf := make([]byte, 64)
		for _, want := range msgs {
			n, err := cli.ReadMsg(buf)
			assert.NilError(t, err)
			assert.Equal(t, want, string(buf[:n]))
		}
		_, err := cli.ReadMsg(buf)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("handle reads buffered data", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		defer cli.Close()

		msgs := []string{"one", "two", "three"}
		for _, m := range msgs {
			assert.NilError(t, cli.WriteMsg([]byte(m)))
		}
		waitForReceived(t, h.ss, uint64(len(msgs)-1))

		assert.NilError(t, h.Close())

		buf := make([]byte, 64)
		for _, want := range msgs {
			n, err := h.ReadMsg(buf)
			assert.NilError(t, err)
			assert.Equal(t, want, string(buf[:n]))
		}
		_, err := h.ReadMsg(buf)
		assert.Equal(t, io.EOF, err)
	})
}

// TestWriteFailsAfterClose ensures that any WriteMsg/Write performed after Close
// immediately returns io.EOF, for both the Client and the server-side Handle.
func TestWriteFailsAfterClose(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	t.Run("client", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		_ = h

		assert.NilError(t, cli.Close())

		assert.Equal(t, io.EOF, cli.WriteMsg([]byte("x")))
		n, err := cli.Write([]byte("y"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("handle", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		defer cli.Close()

		assert.NilError(t, h.Close())

		// Before the closeLocked fix, the Handle never transitioned to the closed
		// state and these writes silently succeeded on the wire.
		assert.Assert(t, h.IsClosed())
		assert.Equal(t, io.EOF, h.WriteMsg([]byte("x")))
		n, err := h.Write([]byte("y"))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})
}

// TestIdempotentClose validates that multiple calls to Close, whether sequential
// or concurrent, do not panic and return consistently.
func TestIdempotentClose(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	t.Run("client sequential", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		_ = h
		for i := 0; i < 3; i++ {
			assert.NilError(t, cli.Close())
		}
	})

	t.Run("client concurrent", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		_ = h
		var wg sync.WaitGroup
		errs := make([]error, 20)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = cli.Close()
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			assert.NilError(t, err)
		}
		assert.Equal(t, cli.state.Load(), clientStateClosed)
	})

	t.Run("handle concurrent", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer srv.Close()
		defer cli.Close()
		var wg sync.WaitGroup
		errs := make([]error, 20)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = h.Close()
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			assert.NilError(t, err)
		}
		assert.Assert(t, h.IsClosed())
	})

	// Concurrent Server.Close calls must not panic (the previous WaitGroup-based
	// barrier could panic with "WaitGroup is reused before previous Wait has
	// returned") and every caller must return nil.
	t.Run("server concurrent", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		srv, cli, h := newConnPair(t)
		defer cli.Close()
		_ = h
		var wg sync.WaitGroup
		errs := make([]error, 20)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = srv.Close()
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			assert.NilError(t, err)
		}
	})
}

// TestPeerInitiatedClose tests that when the remote endpoint sends a Close
// control message, the receiving side transitions into the closed state and
// subsequent writes fail with io.EOF.
func TestPeerInitiatedClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.ErrorLevel)

	srv, cli, h := newConnPair(t)
	defer srv.Close()
	defer cli.Close()

	// The server sends a Close control message to the client.
	h.ss.m.Lock()
	err := h.writeControlLocked(ControlMessageClose)
	h.ss.m.Unlock()
	assert.NilError(t, err)

	// The client's listen loop should process the control message and mark the
	// session closed.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cli.ss.m.Lock()
		st := cli.ss.handleState
		cli.ss.m.Unlock()
		if st == closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not observe peer-initiated close")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Writes after the peer-initiated close fail.
	assert.Equal(t, io.EOF, cli.WriteMsg([]byte("after peer close")))
}

// TestRaceBetweenCloseAndDeadlineOrIO stresses race conditions by invoking
// Close, deadline changes, and I/O in rapid succession on a single connection.
// Its correctness check is the absence of data races (under -race), panics, and
// deadlocks: the test fails if the workers do not all return.
func TestRaceBetweenCloseAndDeadlineOrIO(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.ErrorLevel)

	srv, cli, h := newConnPair(t)
	defer srv.Close()
	defer h.Close()

	const workers = 16
	stopAt := time.Now().Add(300 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(seed)))
			buf := make([]byte, 64)
			for time.Now().Before(stopAt) {
				switch r.Intn(6) {
				case 0:
					cli.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					cli.ReadMsg(buf)
				case 1:
					cli.WriteMsg([]byte("data"))
				case 2:
					cli.SetDeadline(time.Now().Add(time.Duration(r.Intn(30)) * time.Millisecond))
				case 3:
					h.WriteMsg([]byte("echo"))
				case 4:
					h.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					h.ReadMsg(buf)
				case 5:
					// Only one worker ever closes, roughly halfway through.
					if seed == workers-1 && time.Now().After(stopAt.Add(-150*time.Millisecond)) {
						cli.Close()
					}
				}
			}
		}(i)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("possible deadlock: workers did not finish")
	}

	// Ensure the client is fully closed for goleak.
	cli.Close()
}

// TestStressHighConcurrency subjects the server to many concurrent connections
// that each perform concurrent reads, writes, deadline changes, and a close.
// Like the race test, it passes if it completes without deadlock, panic, or
// (under -race) data races.
func TestStressHighConcurrency(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.ErrorLevel)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverCfg, verifyCfg := newTestServerConfig(t)
	srv, err := NewServer(pc.(*net.UDPConn), *serverCfg)
	assert.NilError(t, err)
	defer srv.Close()
	go srv.Serve()

	// Accept connections and echo everything back until the server is closed.
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		for {
			h, err := srv.AcceptTimeout(500 * time.Millisecond)
			if err == io.EOF {
				return // server closed
			}
			if err != nil {
				continue // timeout, keep waiting
			}
			serverWg.Add(1)
			go func(h *Handle) {
				defer serverWg.Done()
				buf := make([]byte, 2048)
				for {
					n, err := h.ReadMsg(buf)
					if err != nil {
						return
					}
					if err := h.WriteMsg(buf[:n]); err != nil {
						return
					}
				}
			}(h)
		}
	}()

	const clients = 12
	var clientWg sync.WaitGroup
	for i := 0; i < clients; i++ {
		clientWg.Add(1)
		go func(seed int) {
			defer clientWg.Done()
			kp, leaf := newClientAuth(t)
			clientCfg := ClientConfig{Verify: *verifyCfg, Exchanger: kp, Leaf: leaf}
			cli, err := Dial("udp", srv.Addr().String(), clientCfg)
			if err != nil {
				return
			}
			defer cli.Close()

			stopAt := time.Now().Add(200 * time.Millisecond)
			var ops sync.WaitGroup
			// Writer.
			ops.Add(1)
			go func() {
				defer ops.Done()
				for time.Now().Before(stopAt) {
					cli.WriteMsg([]byte(fmt.Sprintf("c%d", seed)))
				}
			}()
			// Reader.
			ops.Add(1)
			go func() {
				defer ops.Done()
				buf := make([]byte, 64)
				for time.Now().Before(stopAt) {
					cli.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					cli.ReadMsg(buf)
				}
			}()
			// Deadline churn.
			ops.Add(1)
			go func() {
				defer ops.Done()
				for time.Now().Before(stopAt) {
					cli.SetDeadline(time.Now().Add(15 * time.Millisecond))
				}
			}()
			ops.Wait()
		}(i)
	}

	done := make(chan struct{})
	go func() { clientWg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("possible deadlock: clients did not finish")
	}

	// Shut down the server and wait for the accept/echo goroutines to exit so
	// goleak sees a clean slate.
	srv.Close()
	serverWg.Wait()
}
