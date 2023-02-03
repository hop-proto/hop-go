package proxy

import (
	"sync"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

func unreliableProxyOneSide(a transport.UDPLike, b transport.UDPLike, wg *sync.WaitGroup) {
	buf := make([]byte, tubes.MaxFrameDataLength)
	defer func() {
		a.Close()
		b.Close()
		wg.Done()
	}()
	// Upon a call to Close, pending reads and write are canceled
	for {
		n, _, _, _, err := a.ReadMsgUDP(buf, nil)
		if err != nil {
			return
		}
		_, _, err = b.WriteMsgUDP(buf[:n], nil, nil)
		if err != nil {
			return
		}
	}
}

// UnreliableProxy starts proxying two unreliable connections. Will stop on
// error. Caller is responsible for closing proxied connections.
func UnreliableProxy(a transport.UDPLike, b transport.UDPLike) *sync.WaitGroup {
	logrus.Infof("unreliable proxy: starting proxy between %v and %v.", a.LocalAddr().String(), b.LocalAddr().String())
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go unreliableProxyOneSide(a, b, wg)
	go unreliableProxyOneSide(b, a, wg)
	return wg
}
