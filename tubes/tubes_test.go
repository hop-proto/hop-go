package tubes

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/nettest"
	"hop.computer/hop/transport"
)

type MsgConnUDP struct {
	net.UDPConn
}

var _ transport.MsgConn = &MsgConnUDP{}

func (c *MsgConnUDP) ReadMsg(b []byte) (n int, err error) {
	n, _, _, _, err = c.ReadMsgUDP(b, nil)
	return
}

func (c *MsgConnUDP) WriteMsg(b []byte) (err error) {
	_, _,  err = c.WriteMsgUDP(b, nil, nil)
	return
}

// rel is true for reliable tubes and false for unreliable ones
// fake is true for in memory reliable udp and false otherwise
func makeConn(t *testing.T, rel bool, fake bool) (t1, t2 net.Conn, stop func(), r bool, err error) {
	r = rel
	var c1UDP, c2UDP net.Conn
	var c1, c2 transport.MsgConn
	if fake {
		c1, c2 = transport.MakeReliableUDPConn(false)
	} else {
		c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
		assert.NilError(t, err)

		c1UDP, err = net.Dial("udp", "localhost:7777")
		assert.NilError(t, err)
		c1 = &MsgConnUDP{
			*c1UDP.(*net.UDPConn),
		}

		c2UDP, err = net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
		assert.NilError(t, err)
		c2 = &MsgConnUDP{
			*c2UDP.(*net.UDPConn),
		}
	}

	muxer1 := NewMuxer(c1, c1, 0, logrus.WithField("muxer", "m1"))
	muxer2 := NewMuxer(c2, c2, 0, logrus.WithField("muxer", "m2"))

	go func() {
		e := muxer1.Start()
		if e != nil {
			logrus.Fatalf("muxer1 error: %v", e)
		}
	}()
	go func() {
		e := muxer2.Start()
		if e != nil {
			logrus.Fatalf("muxer2 error: %v", e)
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
		t1.Close()
		t2.Close()

		muxer1.Stop()
		assert.Assert(t, muxer1.stopped.Load())

		muxer2.Stop()
		assert.Assert(t, muxer2.stopped.Load())

		// TODO(hosono) closing these connections causes a panic
		if c1UDP != nil {
			//c1UDP.Close()
		}
		if c2UDP != nil {
			//c2UDP.Close()
		}
	}

	return t1, t2, stop, rel, err
}

func ReliableClose(t *testing.T, rel bool) {
	c1Conn, c2Conn, stop, _, err := makeConn(t, rel, false)
	c1 := c1Conn.(*Reliable)
	c2 := c2Conn.(*Reliable)

	assert.NilError(t,err)

	s := "hello"

	n, err := c1.Write([]byte(s))
	assert.NilError(t,err)
	assert.DeepEqual(t, n, len(s))

	b := make([]byte, len(s))
	n, err = c2.Read(b)
	assert.DeepEqual(t, n, len(s))
	assert.DeepEqual(t, string(b), s)

	c1.Close()
	c2.Close()

	assert.DeepEqual(t, c1.tubeState, closed)
	assert.DeepEqual(t, c2.tubeState, closed)

	stop()
}

// TODO(hosono) make reliable tubes pass these tests
func TestReliable(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	t.Run("Close", func (t *testing.T) {
		ReliableClose(t, true)
	})

	f := func() (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(t, true, false)
	}

	mp := nettest.MakePipe(f)
	nettest.TestConn(t, mp)
}

func TestUnreliable(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	f := func() (c1, c2 net.Conn, stop func(), rel bool, err error) {
		return makeConn(t, false, true)
	}
	mp := nettest.MakePipe(f)
	nettest.TestConn(t, mp)
}
