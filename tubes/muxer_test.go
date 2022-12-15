package tubes

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

func makeMuxers(t *testing.T) (m1, m2 *Muxer, stop func()) {
	var c1, c2 transport.MsgConn
	c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
	assert.NilError(t, err)

	c1UDP, err := net.Dial("udp", c2Addr.String())
	assert.NilError(t, err)
	c1 = transport.MakeUDPMsgConn(c1UDP.(*net.UDPConn))

	c2UDP, err := net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(t, err)
	c2 = transport.MakeUDPMsgConn(c2UDP)

	m1 = NewMuxer(c1, 0, false, logrus.WithField("muxer", "m1"))
	m1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	m2 = NewMuxer(c2, 0, true, logrus.WithField("muxer", "m2"))
	m2.log.WithField("addr", c2.LocalAddr()).Info("Created")

	go func() {
		e := m1.Start()
		if e != nil {
			logrus.Fatalf("muxer1 error: %v", e)
		}
	}()
	go func() {
		e := m2.Start()
		if e != nil {
			logrus.Fatalf("muxer2 error: %v", e)
		}
	}()

	stop = func() {
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			m1.Stop()
			wg.Done()
		}()
		go func() {
			m2.Stop()
			wg.Done()
		}()

		wg.Wait()

		c1UDP.Close()
		c2UDP.Close()
	}

	return m1, m2, stop
}

// These two tests are flagged as duplicates by the linter,
// but making them one generic test is much less readable
//
//nolint:dupl
func manyReliableTubes(t *testing.T) {
	// Each muxer can create exactly 128 tubes.
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(t)
	for i := 1; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m1.CreateReliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}
	for i := 0; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m2.CreateReliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}

	tube, err := m1.CreateReliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	tube, err = m2.CreateReliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	stop()
}

//nolint:dupl
func manyUnreliableTubes(t *testing.T) {
	// Each muxer can create exactly 128 tubes.
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(t)
	for i := 1; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m1.CreateUnreliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}
	for i := 0; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m2.CreateUnreliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}

	tube, err := m1.CreateUnreliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	tube, err = m2.CreateUnreliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	stop()
}

// this ensures that tubes can still be opened even if the remote host is in the timeWait state
func reusingTubes(t *testing.T) {
	m1, m2, stop := makeMuxers(t)

	// Create a reliable tube
	t1, err := m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
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

	assert.DeepEqual(t, t2State, timeWait)

	// Attempt to open another tube with the same ID
	t1, err = m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
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

func TestMuxer(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	t.Run("ManyUnreliableTubes", manyUnreliableTubes)
	t.Run("ManyReliableTubes", manyReliableTubes)
	t.Run("ReuseTubes", reusingTubes)
}
