package tubes

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/pkg/must"
	"hop.computer/hop/transport"
)

type blockingWriteMsgConn struct {
	writeStarted   chan struct{}
	releaseWrite   chan struct{}
	writeCompleted chan struct{}
	closed         chan struct{}

	startOnce    sync.Once
	completeOnce sync.Once
	closeOnce    sync.Once
}

type stopResult struct {
	sendErr error
	recvErr error
}

func newBlockingWriteMsgConn() *blockingWriteMsgConn {
	return &blockingWriteMsgConn{
		writeStarted:   make(chan struct{}),
		releaseWrite:   make(chan struct{}),
		writeCompleted: make(chan struct{}),
		closed:         make(chan struct{}),
	}
}

func (c *blockingWriteMsgConn) Read(p []byte) (int, error) {
	return c.ReadMsg(p)
}

func (c *blockingWriteMsgConn) Write(p []byte) (int, error) {
	if err := c.WriteMsg(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *blockingWriteMsgConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *blockingWriteMsgConn) LocalAddr() net.Addr {
	return &net.IPAddr{}
}

func (c *blockingWriteMsgConn) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}

func (c *blockingWriteMsgConn) SetDeadline(time.Time) error {
	return nil
}

func (c *blockingWriteMsgConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *blockingWriteMsgConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *blockingWriteMsgConn) ReadMsg([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingWriteMsgConn) WriteMsg([]byte) error {
	c.startOnce.Do(func() {
		close(c.writeStarted)
	})

	select {
	case <-c.releaseWrite:
		c.completeOnce.Do(func() {
			close(c.writeCompleted)
		})
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

// TestMuxerStopDrainsSenderBeforeClosingUnderlying verifies that shutdown
// writes every frame accepted from a tube before closing the transport.
func TestMuxerStopDrainsSenderBeforeClosingUnderlying(t *testing.T) {
	conn := newBlockingWriteMsgConn()
	muxer := newMuxer(conn, time.Second, false, logrus.WithField("test", t.Name()))

	muxer.sendQueue <- []byte("final reliable acknowledgement")
	<-conn.writeStarted

	stopDone := make(chan stopResult, 1)
	go func() {
		sendErr, recvErr := muxer.Stop()
		stopDone <- stopResult{sendErr: sendErr, recvErr: recvErr}
	}()

	select {
	case <-conn.closed:
		close(conn.releaseWrite)
		<-stopDone
		t.Fatal("underlying connection closed while the muxer sender was writing")
	case <-stopDone:
		close(conn.releaseWrite)
		t.Fatal("Muxer.Stop returned while the muxer sender was writing")
	case <-time.After(50 * time.Millisecond):
	}

	close(conn.releaseWrite)
	select {
	case result := <-stopDone:
		assert.NilError(t, result.sendErr)
		assert.NilError(t, result.recvErr)
	case <-time.After(time.Second):
		t.Fatal("Muxer.Stop did not finish after the pending write completed")
	}

	select {
	case <-conn.writeCompleted:
	default:
		t.Fatal("pending write did not complete")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("underlying connection was not closed")
	}
}

// TestMuxerStopInterruptsBlockedSender verifies that a stuck transport write
// cannot deadlock shutdown after the graceful drain period expires.
func TestMuxerStopInterruptsBlockedSender(t *testing.T) {
	conn := newBlockingWriteMsgConn()
	muxer := newMuxer(conn, time.Second, false, logrus.WithField("test", t.Name()))

	muxer.sendQueue <- []byte("blocked write")
	<-conn.writeStarted

	stopDone := make(chan stopResult, 1)
	go func() {
		sendErr, recvErr := muxer.Stop()
		stopDone <- stopResult{sendErr: sendErr, recvErr: recvErr}
	}()

	select {
	case result := <-stopDone:
		assert.NilError(t, result.sendErr)
		assert.NilError(t, result.recvErr)
	case <-time.After(2 * muxerTimeout):
		t.Fatal("Muxer.Stop deadlocked on a blocked transport write")
	}

	select {
	case <-conn.closed:
	default:
		t.Fatal("blocked transport was not closed")
	}
	select {
	case <-conn.writeCompleted:
		t.Fatal("blocked write unexpectedly completed")
	default:
	}
}

// makeMuxers creates two connected muxers running over UDP. Packet delivery is
// controlled by a deterministic coin flipper with the provided bit bias.
//
//nolint:unused // used in commented out test
func makeMuxers(bits int, t *testing.T) (m1, m2 *Muxer, stop func()) {

	responderPacketConn := must.Do(net.ListenPacket("udp", "127.0.0.1:0"))
	responderUDPConn := responderPacketConn.(*net.UDPConn)

	var initiator, responder transport.MsgConn

	initiatorConn := must.Do(net.Dial("udp", responderUDPConn.LocalAddr().String()))
	initiator = MakeTestUDPMsgConn(bits, 1, initiatorConn.(*net.UDPConn))

	responder = MakeTestUDPMsgConn(bits, 2, responderUDPConn)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		m1 = newMuxer(initiator, time.Second, false, logrus.WithFields(logrus.Fields{
			"muxer": "m1",
			"test":  t.Name(),
		}))
		m1.log.WithField("addr", initiator.LocalAddr()).Info("Created")
	}()
	go func() {
		defer wg.Done()
		m2 = newMuxer(responder, time.Second, true, logrus.WithFields(logrus.Fields{
			"muxer": "m2",
			"test":  t.Name(),
		}))
		m2.log.WithField("addr", responder.LocalAddr()).Info("Created")
	}()

	wg.Wait()

	stop = func() {
		stopWg := sync.WaitGroup{}
		stopWg.Add(1)
		go func() {
			sendErr, recvErr := m1.Stop()
			assert.NilError(t, sendErr)
			assert.NilError(t, recvErr)
			stopWg.Done()
		}()

		sendErr, recvErr := m2.Stop()
		assert.NilError(t, sendErr)
		assert.NilError(t, recvErr)

		stopWg.Wait()

		initiatorConn.Close()
		responderPacketConn.Close()

		// This makes sure that lingering goroutines do not panic
		// time.Sleep(muxerTimeout + time.Second)
	}

	return m1, m2, stop
}

//nolint:unused // used in commented out test
func manyTubes(bits int, rel bool, waitForOpen bool, t *testing.T) {
	// Each muxer can create exactly 128 Unreliable tubes and 128 Reliable tubes
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(bits, t)

	var m1CreateTube func() (Tube, error)
	var m2CreateTube func() (Tube, error)

	if rel {
		m1CreateTube = func() (Tube, error) {
			t, err := m1.CreateReliableTube(common.ExecTube)
			return Tube(t), err
		}
		m2CreateTube = func() (Tube, error) {
			t, err := m2.CreateReliableTube(common.ExecTube)
			return Tube(t), err
		}
	} else {
		m1CreateTube = func() (Tube, error) {
			t, err := m1.CreateUnreliableTube(common.ExecTube)
			return Tube(t), err
		}
		m2CreateTube = func() (Tube, error) {
			t, err := m2.CreateUnreliableTube(common.ExecTube)
			return Tube(t), err
		}
	}

	wg := sync.WaitGroup{}

	prevID := -1
	for i := 0; i < 128; i++ {
		tube, err := m1CreateTube()
		assert.NilError(t, err)
		assert.Assert(t, int(tube.GetID()) > prevID)
		prevID = int(tube.GetID())
		if waitForOpen {
			wg.Add(1)
			go func() {
				tube.SetDeadline(time.Time{})
				wg.Done()
			}()
		}
	}

	numTubes := 128

	prevID = -1
	for i := 0; i < numTubes; i++ {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m2CreateTube()
		assert.NilError(t, err)
		assert.Assert(t, int(tube.GetID()) > prevID)
		prevID = int(tube.GetID())
		if waitForOpen {
			wg.Add(1)
			go func() {
				tube.SetDeadline(time.Time{})
				wg.Done()
			}()
		}
	}

	tube, err := m1CreateTube()
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == (*Unreliable)(nil) || tube == (*Reliable)(nil))

	tube, err = m2CreateTube()
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == (*Unreliable)(nil) || tube == (*Reliable)(nil))

	if waitForOpen {
		wg.Wait()
	}

	stop()
}

// TODO(hosono) write a test to check that when the remote host
// has a tube waiting in lastAck, we don't reuse that tube ID.
//
// TODO(dadrian)[2025-07-07]: Uncomment out this test once I understand the
// concurrency in the muxer. The problem right now is that in the test code, all
// of these end up starting a tube on a stopped muxer. In the normal course of
// an application, this won't happen, because you don't usually immediately tear
// down a Muxer. So for the purposes of CI and the AI agent overlords, leaving
// this test disabled.
/*
 func TestMuxer(t *testing.T) {

 	//defer goleak.VerifyNone(t)
 	logrus.SetLevel(logrus.TraceLevel)

 	t.Run("ImmediateStop", func(t *testing.T) {
 		_, _, stop := makeMuxers(0, t)
 		stop()
 	})
 	t.Run("UnreliableTubes/ImmediateStop", func(t *testing.T) {
 		manyTubes(0, false, false, t)
 	})
 	t.Run("UnreliableTubes/Wait", func(t *testing.T) {
 		manyTubes(2, false, true, t)
 	})

 	t.Run("ReliableTubes/ImmediateStop", func(t *testing.T) {
 		manyTubes(0, true, false, t)
 	})
 	t.Run("ReliableTubes/Wait", func(t *testing.T) {
 		manyTubes(1, true, true, t)
 	})
 }
*/
