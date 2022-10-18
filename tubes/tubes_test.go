package tubes

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"gotest.tools/assert"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"

	"golang.org/x/net/nettest"
)

// rel is true for reliable tubes and false for unreliable ones
func makeConn(t *testing.T, rel bool) (t1, t2 net.Conn, stop func(), err error) {
	c1, c2 := transport.MakeReliableUDPConn()

	muxer1 := NewMuxer(c1, c1, 0, logrus.WithField("muxer", "m1"))
	muxer2 := NewMuxer(c2, c2, 0, logrus.WithField("muxer", "m2"))

	go func() {
		e := muxer1.Start()
		if e != nil {
			logrus.Fatalf("muxer1 error: %v", err)
		}
	}()
	go func() {
		e := muxer2.Start()
		if e != nil {
			logrus.Fatalf("muxer2 error: %v", err)
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
		muxer2.Stop()
	}

	return t1, t2, stop, err
}

// TODO(hosono) make reliable tubes pass these tests
func DontTestReliable(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	f := func() (c1, c2 net.Conn, stop func(), err error) {
		return makeConn(t, true)
	}

	mp := nettest.MakePipe(f)
	nettest.TestConn(t, mp)
}

func CheckUnreliable(t *testing.T) {
	c1, c2, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	c1.Write([]byte("hello"))

	buf := make([]byte, 5)
	_, err = c2.Read(buf)
	assert.NilError(t, err)

	assert.DeepEqual(t, buf, []byte("hello"))

	stop()
}

func UnreliableCount(t *testing.T) {
	c1, c2, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	for i := 0; i < 8; i++ {
		c1.Write([]byte{byte(i)})
	}

	buf := make([]byte, 16)
	for i := 0; i < 8; i++ {
		n, err := c2.Read(buf)
		assert.NilError(t, err)
		assert.DeepEqual(t, n, 1)
		assert.DeepEqual(t, buf[:n], []byte{byte(i)})
	}

	stop()
}

func TestUnreliable(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	t.Run("CheckUnreliable", CheckUnreliable)
	t.Run("Count", UnreliableCount)

	f := func() (c1, c2 net.Conn, stop func(), err error) {
		return makeConn(t, false)
	}
	mp := nettest.MakePipe(f)
	nettest.TestConn(t, mp)
}
