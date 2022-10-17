package tubes

import (
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"hop.computer/hop/common"
	"hop.computer/hop/transport"

	"golang.org/x/net/nettest"
)

func makeReliableConn() (t1, t2 net.Conn, stop func(), err error) {
	c1, c2 := transport.MakeReliableUDPConn()
	muxer1 := NewMuxer(c1, c1, time.Second)
	muxer2 := NewMuxer(c2, c2, time.Second)

	go muxer1.Start()
	go muxer2.Start()

	t1, err = muxer1.CreateReliableTube(common.ExecTube)
	if err != nil {
		return
	}

	t2, err  = muxer2.Accept()
	if err != nil {
		return
	}

	stop = func() {
		t1.Close()
		t2.Close()
		muxer1.Stop()
		muxer2.Stop()
	}
	return
}

func TestReliable(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	mp := nettest.MakePipe(makeReliableConn)
	nettest.TestConn(t, mp)
}

func makeUnreliableConn(t *testing.T) (t1, t2 net.Conn, stop func(), err error) {
	c1, c2 := transport.MakeReliableUDPConn()

	muxer1 := NewMuxer(c1, c1, 5 * time.Second)
	muxer2 := NewMuxer(c2, c2, 5 * time.Second)

	go func() {
		err = muxer1.Start()
		if err != nil {
			logrus.Fatalf("muxer1 error: %v", err)
		}
	}()
	go func() {
		err = muxer2.Start()
		if err != nil {
			logrus.Fatalf("muxer2 error: %v", err)
		}
	}()

	t1, err = muxer1.CreateUnreliableTube(common.ExecTube)
	if err != nil {
		return
	}

	t2, err  = muxer2.Accept()
	if err != nil {
		return
	}

	_, ok := t1.(*Unreliable)
	assert.Assert(t, ok)

	_, ok = t2.(*Unreliable)
	assert.Assert(t, ok)

	stop = func() {
		t1.Close()
		t2.Close()
		muxer1.Stop()
		muxer2.Stop()
	}

	return
}

func CheckUnreliable(t *testing.T) {
	c1, c2, stop, err := makeUnreliableConn(t)
	assert.NilError(t, err)

	c1.Write([]byte("hello"))

	buf := make([]byte, 5)
	_, err = c2.Read(buf)
	assert.NilError(t, err)

	assert.DeepEqual(t, buf, []byte("hello"))

	stop()
}


func TestUnreliable(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	t.Run("CheckUnreliable", CheckUnreliable)

	f := func() (c1, c2 net.Conn, stop func(), err error){
		return makeUnreliableConn(t)
	}
	mp := nettest.MakePipe(f)
	nettest.TestConn(t, mp)
}
