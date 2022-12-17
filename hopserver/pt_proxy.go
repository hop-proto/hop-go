package hopserver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

// PT Proxy: Server acts as a proxy between the Principal client
// and Target server.

// Delegate proxy server: a hop server that has an active hop session with
// a (remote) Principal hop client and a (local) Delegate hop client that was
// started from a process spawned from that active hop session. Two "proxying"
// actions actually occur:
// 1. Delegate hop client <--> Principal hop client (dp_proxy.go)
// 2. Principal hop client <--> Target hop server (pt_proxy.go) (*)

// Responsibilities [status] (2: Principal <--> Target proxy):
// - run a "UDP proxy" between the Principal (unreliable tube) and Target
// 	(udp "conn") (roughly implemented)
// - only create a proxy if it is expected and allowed (partially implemented)
// - close down the proxy/associated resources neatly if either side fails (TODO)

// allows server to keep track of unreliable principal proxy
// tubes before the reliable has received the tube id
type ptProxyTubeQueue struct {
	tubes map[byte]*tubes.Unreliable
	lock  *sync.Mutex
	cv    sync.Cond
}

// newPTProxyTubeQueue creates a synchronized set of unreliable principal proxy tubes
func newPTProxyTubeQueue() *ptProxyTubeQueue {
	proxyLock := sync.Mutex{}
	proxyQueue := &ptProxyTubeQueue{
		tubes: make(map[byte]*tubes.Unreliable), // tube ID --> tube
		lock:  &proxyLock,
		cv:    *sync.NewCond(&proxyLock),
	}
	return proxyQueue
}

func unreliableProxyOneSide(a transport.UDPLike, b transport.UDPLike) {
	// TODO(baumanl): way to eliminate buffer? At least make it smaller?
	buf := make([]byte, 65535)
	for {
		// TODO(baumanl): calibrate timeouts
		a.SetReadDeadline(time.Now().Add(time.Second))
		n, _, _, _, err := a.ReadMsgUDP(buf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				logrus.Errorf("pt proxy: read deadline exceeded: %s", err)
				return
			}
			logrus.Error(err)
			continue
		}
		b.SetWriteDeadline(time.Now().Add(time.Second))
		_, _, err = b.WriteMsgUDP(buf[:n], nil, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				logrus.Errorf("pt proxy: write deadline exceeded: %s", err)
				return
			}
			logrus.Error(err)
			continue
			// TODO(baumanl): what should we do
		}
	}
}

// TODO(baumanl): make sure this closes down cleanly/consistently
// unreliableProxyHelper proxies msgs from two udplike connections
func unreliableProxyHelper(a transport.UDPLike, b transport.UDPLike) {
	go unreliableProxyOneSide(a, b)
	unreliableProxyOneSide(b, a)
}

// manage principal to target proxying (t is a reliable tube)
func (sess *hopSession) startPTProxy(t net.Conn, pq *ptProxyTubeQueue) {
	defer t.Close()

	// TODO(baumanl): add check for authgrant?

	// make sure this is currently expected
	if sess.numActiveReqDelegates.Load() == 0 {
		logrus.Info("Server: received unexpected request to start net proxy")
		return
	}

	// receive target message
	var targetInfo authgrants.TargetInfo
	_, err := targetInfo.ReadFrom(t)
	if err != nil {
		authgrants.WriteFailure(t, "Server: unable to read target info")
		return
	}

	// connect to target
	targetConn, err := targetInfo.ConnectToTarget()
	if err != nil {
		authgrants.WriteFailure(t, fmt.Sprint(err))
		return
	}
	authgrants.WriteConfirmation(t)
	defer targetConn.Close()

	// receive unreliable principal proxy tube id
	tubeID, err := authgrants.ReadUnreliableProxyID(t)
	if err != nil {
		logrus.Errorf("Server: error reading unreliable proxy id: %s", err)
	}

	// check (and keep checking on signal) for the unreliable tube with the id
	pq.lock.Lock()
	for _, ok := pq.tubes[tubeID]; !ok; {
		pq.cv.Wait()
	}

	principalTube := pq.tubes[tubeID]
	delete(pq.tubes, tubeID)
	pq.lock.Unlock()

	// proxy
	unreliableProxyHelper(principalTube, targetConn)
}
