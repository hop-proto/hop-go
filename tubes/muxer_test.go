package tubes

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

// makeMuxers creates two connected muxers running over UDP
// odds is the probability that a given packet is sent.
// Set odds to 1.0 to send all packet and 0.0 to send no packets
func makeMuxers(odds float64, t *testing.T) (m1, m2 *Muxer, stop func()) {
	var c1, c2 transport.MsgConn
	c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
	assert.NilError(t, err)

	c1UDP, err := net.Dial("udp", c2Addr.String())
	assert.NilError(t, err)
	c1 = MakeUDPMsgConn(odds, c1UDP.(*net.UDPConn))

	c2UDP, err := net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(t, err)
	c2 = MakeUDPMsgConn(odds, c2UDP)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		m1 = NewMuxer(c1, 0, false, logrus.WithFields(logrus.Fields{
			"muxer": "m1",
			"test":  t.Name(),
		}))
		m1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	}()
	go func() {
		defer wg.Done()
		m2 = NewMuxer(c2, 0, true, logrus.WithFields(logrus.Fields{
			"muxer": "m2",
			"test":  t.Name(),
		}))
		m2.log.WithField("addr", c2.LocalAddr()).Info("Created")
	}()

	wg.Wait()

	stop = func() {
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			err := m1.Stop()
			assert.NilError(t, err)
			wg.Done()
		}()
		go func() {
			err := m2.Stop()
			assert.NilError(t, err)
			wg.Done()
		}()

		err = m1.WaitForStop()
		assert.NilError(t, err)

		err = m2.WaitForStop()
		assert.NilError(t, err)

		c1UDP.Close()
		c2UDP.Close()

		// This makes sure that lingering goroutines do not panic
		time.Sleep(timeWaitTime + time.Second)
	}

	return m1, m2, stop
}

func manyTubes(odds float64, rel bool, waitForOpen bool, t *testing.T) {
	// Each muxer can create exactly 127 Unreliable tubes and 128 Reliable tubes
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(odds, t)

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

	var numTubes int
	if rel {
		numTubes = 128
	} else {
		numTubes = 127
	}

	prevID := -1
	for i := 0; i < numTubes; i++ {
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

	// Create a reliable tube
	t1, err := m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.DeepEqual(t, t1.GetID(), byte(1))
	t2, ok := <-m2.TubeQueue
	assert.Assert(t, ok)
	t2Rel := t2.(*Reliable)

	// Create a reliable tube
	t1, err := m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.DeepEqual(t, t1.GetID(), byte(1))
	t2, err := m2.Accept()
	assert.NilError(t, err)
	t2Rel := t2.(*Reliable)

	// Close it on both ends
	t2.Close()
	time.Sleep(100 * time.Millisecond)
	t1.Close()
	time.Sleep(100 * time.Millisecond)

	t2Rel.l.Lock()
	t2State := t2Rel.tubeState
	t2Rel.l.Unlock()

	// Attempt to open another tube with the same ID
	t1, err = m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.DeepEqual(t, t1.GetID(), byte(1))
	t2, ok = <-m2.TubeQueue
	assert.Assert(t, ok)
	t2Rel = t2.(*Reliable)

	// Attempt to open another tube with the same ID
	t1, err = m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.DeepEqual(t, t1.GetID(), byte(1))
	t2, err = m2.Accept()
	assert.NilError(t, err)
	t2Rel = t2.(*Reliable)

	// Attempt to send data on that tube
	data := []byte("hello")
	n, err := t1.Write(data)
	assert.DeepEqual(t, n, len(data))
	assert.NilError(t, err)
	err = t1.Close()
	assert.NilError(t, err)

	buf, err := io.ReadAll(t2Rel)
	assert.NilError(t, err)

	assert.DeepEqual(t, buf, data)

	err = t2Rel.Close()
	assert.NilError(t, err)

	stop()
}

	defer goleak.VerifyNone(t)

	logrus.SetLevel(logrus.TraceLevel)
	t.Run("UnreliableTubes/ImmediateStop", func(t *testing.T) {
		manyTubes(1.0, false, false, t)
	})
	t.Run("UnreliableTubes/Wait", func(t *testing.T) {
		manyTubes(0.9, false, true, t)
	})

	defer goleak.VerifyNone(t)

	logrus.SetLevel(logrus.TraceLevel)
	t.Run("UnreliableTubes/ImmediateStop", func(t *testing.T) {
		manyTubes(1.0, false, false, t)
	})
	t.Run("UnreliableTubes/Wait", func(t *testing.T) {
		manyTubes(0.9, false, true, t)
	})

	t.Run("ReliableTubes/ImmediateStop", func(t *testing.T) {
		manyTubes(1.0, true, false, t)
	})
	t.Run("ReliableTubes/Wait", func(t *testing.T) {
		manyTubes(0.9, true, true, t)
	})
	t.Run("ReuseTubes", reusingTubes)
}
