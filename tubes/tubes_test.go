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
	"hop.computer/hop/nettest"
	"hop.computer/hop/transport"
)

// odds indicates the probability that a packet will be sent. 1.0 sends all packets, and 0.0 sends no packets
// rel is true for reliable tubes and false for unreliable ones
func makeConn(odds float64, rel bool, t *testing.T) (t1, t2 net.Conn, stop func(), r bool, err error) {
	r = rel
	var c1, c2 transport.MsgConn
	c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
	assert.NilError(t, err)

	c1UDP, err := net.Dial("udp", c2Addr.String())
	assert.NilError(t, err)
	c1 = transport.MakeUDPMsgConn(odds, c1UDP.(*net.UDPConn))

	c2UDP, err := net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(t, err)
	c2 = transport.MakeUDPMsgConn(odds, c2UDP)

	muxer1 := NewMuxer(c1, 0, false, logrus.WithFields(logrus.Fields{
		"muxer": "m1",
		"test":  t.Name(),
	}))
	muxer1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	muxer2 := NewMuxer(c2, 0, true, logrus.WithFields(logrus.Fields{
		"muxer": "m2",
		"test":  t.Name(),
	}))
	muxer2.log.WithField("addr", c2.LocalAddr()).Info("Created")

	go func() {
		e := muxer1.Start()
		if e != nil {
			logrus.Errorf("muxer1 error: %v", e)
			t.Fail()
		}
	}()
	go func() {
		e := muxer2.Start()
		if e != nil {
			logrus.Errorf("muxer2 error: %v", e)
			t.Fail()
		}
	}()

	if rel {
		t1, err = muxer1.CreateReliableTube(common.ExecTube)
	} else {
		t1, err = muxer1.CreateUnreliableTube(common.ExecTube)
	}
	if err != nil {
		return
	}

	t2, err = muxer2.Accept()
	if err != nil {
		return
	}

	if rel {
		_, ok := t1.(*Reliable)
		assert.Assert(t, ok)

		_, ok = t2.(*Reliable)
		assert.Assert(t, ok)
	} else {
		_, ok := t1.(*Unreliable)
		assert.Assert(t, ok)

		_, ok = t2.(*Unreliable)
		assert.Assert(t, ok)
	}

	stop = func() {

		wg := sync.WaitGroup{}
		wg.Add(2)

		go func() {
			defer wg.Done()
			t1.Close()
			t1.(Tube).WaitForClose()
			muxer1.Stop()
			assert.DeepEqual(t, muxer1.state.Load(), muxerStopped)
		}()
		go func() {
			defer wg.Done()
			t2.Close()
			t2.(Tube).WaitForClose()
			muxer2.Stop()
			assert.DeepEqual(t, muxer2.state.Load(), muxerStopped)
		}()

		wg.Wait()

		c1.Close()
		c2.Close()

	}

	return t1, t2, stop, rel, err
}

// CloseTest tests the closing behavior of tubes
func CloseTest(odds float64, rel bool, wait bool, t *testing.T) {
	c1, c2, stop, _, err := makeConn(odds, rel, t)
	assert.NilError(t, err)
	defer stop()

	if c1Rel, ok := c1.(*Reliable); ok {
		c1Rel.WaitForInit()
	}
	if c2Rel, ok := c2.(*Reliable); ok {
		c2Rel.WaitForInit()
	}

	c1.Close()
	if wait {
		time.Sleep(100 * time.Millisecond)
	}
	c2.Close()

	if c1Rel, ok := c1.(*Reliable); ok {
		c1Rel.WaitForClose()
		c1Rel.l.Lock()
		assert.DeepEqual(t, c1Rel.tubeState, closed)
		c1Rel.l.Unlock()
	}

	if c2Rel, ok := c1.(*Reliable); ok {
		c2Rel.WaitForClose()
		c2Rel.l.Lock()
		assert.DeepEqual(t, c2Rel.tubeState, closed)
		c2Rel.l.Unlock()
	}

	n, err := c1.Write([]byte("hello world"))
	assert.ErrorType(t, err, io.EOF)
	assert.DeepEqual(t, n, 0)
}

func reliable(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	t.Run("Close", func(t *testing.T) {
		t.Run("Wait", func(t *testing.T) {
			CloseTest(1.0, true, true, t)
		})
		t.Run("NoWait", func(t *testing.T) {
			CloseTest(1.0, true, false, t)
		})
		t.Run("BadConnection", func(t *testing.T) {
			CloseTest(0.2, true, true, t)
		})
	})

	f := func(t *testing.T) (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(1.0, true, t)
	}

	mp := nettest.MakePipe(f)
	t.Run("Nettest", func(t *testing.T) {
		nettest.TestConn(t, mp)
	})
}

func unreliable(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	t.Run("Close", func(t *testing.T) {
		CloseTest(1.0, false, true, t)
		CloseTest(1.0, false, false, t)
	})

	f := func(t *testing.T) (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(1.0, false, t)
	}
	mp := nettest.MakePipe(f)
	t.Run("Nettest", func(t *testing.T) {
		nettest.TestConn(t, mp)
	})
}

func TestTubes(t *testing.T) {
	t.Run("Reliable", reliable)
	t.Run("Unreliable", unreliable)
}
