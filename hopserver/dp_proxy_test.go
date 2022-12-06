package hopserver

import (
	"net"
	"sync"
	"testing"

	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
)

func TestProxySimpleDenial(t *testing.T) {
	c, cproxy := net.Pipe() // simulates client process -> agproxy
	p, pproxy := net.Pipe() // simulates agproxy -> principal tube
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// principal
		msg := authgrants.AgMessage{
			MsgType: authgrants.IntentDenied,
			Data:    authgrants.MessageData{Denial: "I say so"},
		}
		_, err := msg.WriteTo(p)
		assert.NilError(t, err)
		recMsg := new(authgrants.AgMessage)
		_, err = recMsg.ReadFrom(p)
		assert.Error(t, err, "EOF")
		wg.Done()
	}()

	go func() {
		// delegate client
		recMsg := new(authgrants.AgMessage)
		_, err := recMsg.ReadFrom(c)
		assert.NilError(t, err)
		err = c.Close()
		assert.NilError(t, err)
		wg.Done()
	}()

	proxyHelper(pproxy, cproxy)
	wg.Wait()
}
