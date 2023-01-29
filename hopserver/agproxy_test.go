package hopserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/proxy"
)

func TestProxySimpleDenial(t *testing.T) {
	c, cproxy := net.Pipe() // simulates client process -> agproxy
	p, pproxy := net.Pipe() // simulates agproxy -> principal tube
	var wg sync.WaitGroup
	wg.Add(2)

	msg := authgrants.AgMessage{
		MsgType: authgrants.IntentDenied,
		Data:    authgrants.MessageData{Denial: "I say so"},
	}

	go func() {
		// principal
		_, err := msg.WriteTo(p)
		assert.NilError(t, err)
		recMsg := new(authgrants.AgMessage)
		_, err = recMsg.ReadFrom(p)
		assert.Error(t, err, "EOF")
		err = p.Close()
		logrus.Info("p closed")
		assert.NilError(t, err)
		wg.Done()
	}()

	go func() {
		// delegate client
		recMsg := new(authgrants.AgMessage)
		_, err := recMsg.ReadFrom(c)
		assert.NilError(t, err)
		err = c.Close()
		logrus.Info("c closed")
		assert.NilError(t, err)
		assert.Equal(t, msg.MsgType, recMsg.MsgType)
		assert.Equal(t, msg.Data.Denial, recMsg.Data.Denial)
		wg.Done()
	}()

	proxywg := proxy.ReliableProxy(pproxy, cproxy)

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		proxywg.Wait()
	}()

	close := func() {
		err := pproxy.Close()
		assert.NilError(t, err)
		err = cproxy.Close()
		assert.NilError(t, err)
	}

	select {
	case <-ch:
		logrus.Info("Wait group finished normally")
		close()
	case <-time.After(time.Second):
		logrus.Info("Timed out waiting for wait group")
		close()
		<-ch
	}
	wg.Wait()
}
