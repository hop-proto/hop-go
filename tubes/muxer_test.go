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
)

// makeMuxers creates two connected muxers running over UDP
// odds is the probability that a given packet is sent.
// Set odds to 1.0 to send all packet and 0.0 to send no packets
func makeMuxers(odds float64, t *testing.T) (m1, m2 *Muxer, stop func()) {

	c1Packet, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	c1UDP := c1Packet.(*net.UDPConn)

	c2Packet, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	c2UDP := c2Packet.(*net.UDPConn)

	c1 := MakeUDPMsgConn(odds, c1UDP, c2UDP.LocalAddr().(*net.UDPAddr))
	c2 := MakeUDPMsgConn(odds, c2UDP, c1UDP.LocalAddr().(*net.UDPAddr))

	wg := sync.WaitGroup{}
	wg.Add(2)

	m1 = NewMuxer(c1, 0, false, logrus.WithFields(logrus.Fields{
		"muxer": "m1",
		"test":  t.Name(),
	}))
	m1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	m2 = NewMuxer(c2, 0, true, logrus.WithFields(logrus.Fields{
		"muxer": "m2",
		"test":  t.Name(),
	}))
	m2.log.WithField("addr", c2.LocalAddr()).Info("Created")

	go func() {
		defer wg.Done()
		m1 = NewMuxer(c1, 30*retransmitOffset, false, logrus.WithFields(logrus.Fields{
			"muxer": "m1",
			"test":  t.Name(),
		}))
		m1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	}()
	go func() {
		defer wg.Done()
		m2 = NewMuxer(c2, 30*retransmitOffset, true, logrus.WithFields(logrus.Fields{
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
			defer wg.Done()
			sendErr, recvErr := m1.Stop()
			assert.NilError(t, sendErr)
			assert.NilError(t, recvErr)
		}()
		go func() {
			defer wg.Done()
			sendErr, recvErr := m2.Stop()
			assert.NilError(t, sendErr)
			assert.NilError(t, recvErr)
		}()

		wg.Wait()

		c1UDP.Close()
		c2UDP.Close()

		// This makes sure that lingering goroutines do not panic
		// TODO(dadrian): WHY ARE THEY PANICING IN THE FIRST PLACE?
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
			tube, err := m1.CreateReliableTube(common.ExecTube)
			if err != nil {
				return nil, err
			}
			return Tube(tube), nil
		}
		m2CreateTube = func() (Tube, error) {
			tube, err := m2.CreateReliableTube(common.ExecTube)
			if err != nil {
				return nil, err
			}
			return Tube(tube), nil
		}
	} else {
		m1CreateTube = func() (Tube, error) {
			tube, err := m1.CreateUnreliableTube(common.ExecTube)
			if err != nil {
				return nil, err
			}
			return Tube(tube), nil
		}
		m2CreateTube = func() (Tube, error) {
			tube, err := m2.CreateUnreliableTube(common.ExecTube)
			if err != nil {
				return nil, err
			}
			return Tube(tube), nil
		}
	}

	wg := sync.WaitGroup{}

	for i := 1; i < 256; i += 2 {
		tube, err := m1CreateTube()
		assert.NilError(t, err)
		assert.Equal(t, tube.GetID(), byte(i))
		if waitForOpen {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tube.SetDeadline(time.Time{})
			}()
		}
	}

	// Since muxer2 handles keep alives, it can only create 127 unreliable tubes
	// Tube 0 is reserved for keep alives
	var numTubes int
	if rel {
		numTubes = 128
	} else {
		numTubes = 127
	}

	prevID := -1
	for i := 0; i < numTubes; i++ {
		tube, err := m2CreateTube()
		assert.NilError(t, err)
		assert.Assert(t, int(tube.GetID()) > prevID)
		prevID = int(tube.GetID())
		if waitForOpen {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tube.SetDeadline(time.Time{})
			}()
		}
	}

	_, err := m1CreateTube()
	assert.ErrorType(t, err, ErrOutOfTubes)

	_, err = m2CreateTube()
	assert.ErrorType(t, err, ErrOutOfTubes)

	if waitForOpen {
		wg.Wait()
	}

	stop()
}

// this ensures that tubes can still be opened even if the remote host is in the timeWait state
func reusingTubes(t *testing.T) {
	m1, m2, stop := makeMuxers(1.0, t)

	// Create a reliable tube
	t1, err := m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.Equal(t, t1.GetID(), byte(1))
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
	time.Sleep(timeWaitTime + time.Second)

	// Attempt to open another tube with the same ID
	t1, err = m1.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	assert.Equal(t, t1.GetID(), byte(1))
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

func TestOneMuxer(t *testing.T) {
	clientLogger := logrus.NewEntry(logrus.StandardLogger()).WithField("muxer", "client")
	serverLogger := logrus.NewEntry(logrus.StandardLogger()).WithField("muxer", "server")

	serverPacket, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverUDP := serverPacket.(*net.UDPConn)
	serverAddr := serverUDP.LocalAddr().(*net.UDPAddr)

	clientPacket, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	clientUDP := clientPacket.(*net.UDPConn)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	serverMsg := MakeUDPMsgConn(1.0, serverUDP, clientAddr)
	clientMsg := MakeUDPMsgConn(1.0, clientUDP, serverAddr)
	serverMuxer := NewMuxer(serverMsg, 100*time.Second, true, serverLogger)
	clientMuxer := NewMuxer(clientMsg, time.Second*100, false, clientLogger)

	wg := sync.WaitGroup{}
	wg.Add(1)
	s := "hello from server"
	go func() {
		defer wg.Done()
		tube, err := serverMuxer.Accept()
		assert.NilError(t, err)
		n, err := tube.Write([]byte(s))
		assert.Equal(t, len(s), n)
		assert.NilError(t, err)
		sendErr, recvErr := serverMuxer.Stop()
		assert.NilError(t, sendErr)
		assert.NilError(t, recvErr)
	}()
	tube, err := clientMuxer.CreateReliableTube(common.ExecTube)
	assert.NilError(t, err)
	buf := make([]byte, len(s))
	n, err := tube.Read(buf)
	assert.NilError(t, err)
	assert.Equal(t, len(buf), n)
	wg.Wait()
	n, err = tube.Write([]byte("ope"))
	assert.Equal(t, net.ErrClosed, err)
	assert.Equal(t, 0, n)
	sendErr, recvErr := clientMuxer.Stop()
	assert.NilError(t, sendErr)
	assert.NilError(t, recvErr)
}

func TestMuxer(t *testing.T) {

	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.WarnLevel)

	t.Run("ImmediateStop", func(t *testing.T) {
		_, _, stop := makeMuxers(1.0, t)
		stop()
	})
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
