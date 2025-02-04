package tubes

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/nettest"
	"hop.computer/hop/transport"
)

// ProbabalisticUDPMsgConn is a wrapper around net.UDPConn that implements MsgConn
type ProbabalisticUDPMsgConn struct {
	odds float64
	net.UDPConn
}

var _ transport.MsgConn = &ProbabalisticUDPMsgConn{}

// MakeUDPMsgConn converts a *net.UDPConn into a *UDPMsgConn
func MakeUDPMsgConn(odds float64, underlying *net.UDPConn) *ProbabalisticUDPMsgConn {
	return &ProbabalisticUDPMsgConn{
		odds,
		*underlying,
	}
}

// ReadMsg implements the MsgConn interface
func (c *ProbabalisticUDPMsgConn) ReadMsg(b []byte) (n int, err error) {
	n, _, _, _, err = c.ReadMsgUDP(b, nil)
	return
}

// WriteMsg implement the MsgConn interface
func (c *ProbabalisticUDPMsgConn) WriteMsg(b []byte) (err error) {
	var x float64 // defaults to 0.0
	if c.odds != 1.0 {
		size := big.NewInt(100000)
		i, err := rand.Int(rand.Reader, size)
		if err != nil {
			return err
		}
		x = float64(i.Int64()) / float64(size.Int64())
	}
	if x < c.odds {
		_, _, err = c.WriteMsgUDP(b, nil, nil)
	}
	return
}

// odds indicates the probability that a packet will be sent. 1.0 sends all packets, and 0.0 sends no packets
// rel is true for reliable tubes and false for unreliable ones
func makeConn(odds float64, rel bool, t testing.TB) (t1, t2 net.Conn, stop func(), r bool, err error) {
	r = rel
	var c1, c2 transport.MsgConn
	c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
	assert.NilError(t, err)

	c1UDP, err := net.Dial("udp", c2Addr.String())
	assert.NilError(t, err)
	c1 = MakeUDPMsgConn(odds, c1UDP.(*net.UDPConn))

	c2UDP, err := net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(t, err)
	c2 = MakeUDPMsgConn(odds, c2UDP)

	var muxer1 *Muxer
	var muxer2 *Muxer
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		muxer1 = newMuxer(c1, time.Second, false, logrus.WithFields(logrus.Fields{
			"muxer": "m1",
			"test":  t.Name(),
		}))
		muxer1.log.WithField("addr", c1.LocalAddr()).Info("Created")
	}()
	go func() {
		defer wg.Done()
		muxer2 = newMuxer(c2, time.Second, true, logrus.WithFields(logrus.Fields{
			"muxer": "m2",
			"test":  t.Name(),
		}))
		muxer2.log.WithField("addr", c2.LocalAddr()).Info("Created")
	}()
	wg.Wait()

	if rel {
		t1, err = muxer1.CreateReliableTube(common.ExecTube)
	} else {
		t1, err = muxer1.CreateUnreliableTube(common.ExecTube)
	}
	if err != nil {
		return t1, t2, stop, r, err
	}

	t2, err = muxer2.Accept()
	if err != nil {
		err = ErrMuxerStopping
		return t1, t2, stop, r, err
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

// This is heavily based on the BasicIO test from the nettests
func lossyBasicIO(t *testing.T) {
	c1, c2, stop, _, err := makeConn(0.8, true, t)
	assert.NilError(t, err)

	want := make([]byte, 1<<20)
	n, err := rand.Read(want)
	assert.NilError(t, err)
	assert.Equal(t, n, len(want))

	go func() {
		rd := bytes.NewReader(want)
		_, err := io.Copy(c1, rd)
		assert.NilError(t, err)
		// TODO(hosono) for some reason, this assert never returns
		//assert.Equal(t, n, len(want))
		err = c1.Close()
		assert.NilError(t, err)
	}()

	got, err := io.ReadAll(c2)
	assert.NilError(t, err)
	assert.Equal(t, len(got), len(want))

	err = c2.Close()
	assert.NilError(t, err)

	assert.DeepEqual(t, got, want)

	stop()
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
			t.Skip()
			CloseTest(0.8, true, true, t)
		})
	})

	f := func(t *testing.T) (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(1.0, true, t)
	}

	mp := nettest.MakePipe(f)
	t.Run("Nettest", func(t *testing.T) {
		nettest.TestConn(t, mp)
	})

	// Reliable Tubes should pass the nettests even with packet loss
	f = func(t *testing.T) (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(0.90, true, t)
	}
	mp = nettest.MakePipe(f)
	t.Run("LossyBasicIO", lossyBasicIO)
}

func unreliable(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	t.Run("Close", func(t *testing.T) {
		t.Run("Wait", func(t *testing.T) {
			CloseTest(1.0, false, true, t)
		})
		t.Run("NoWait", func(t *testing.T) {
			CloseTest(1.0, false, false, t)
		})
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
	defer goleak.VerifyNone(t)
	t.Run("Reliable", reliable)
	t.Run("Unreliable", unreliable)
}
