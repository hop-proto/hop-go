package proxy

import (
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

func reliableProxyOneSide(a net.Conn, b net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	w, err := io.Copy(a, b)
	a.Close()
	b.Close()
	logrus.Infof("reliable proxy: wrote %v bytes from %v to %v. Ended with err: %v", w, b.LocalAddr().String(), a.LocalAddr().String(), err)
}

// ReliableProxy starts proxying two reliable connections. Will stop on
// error.
func ReliableProxy(a net.Conn, b net.Conn) *sync.WaitGroup {
	logrus.Infof("reliable proxy: starting proxy between %v and %v.", a.LocalAddr().String(), b.LocalAddr().String())
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go reliableProxyOneSide(a, b, wg)
	go reliableProxyOneSide(b, a, wg)
	return wg
}
