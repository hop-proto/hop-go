package hopserver

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

/* PT Proxy: Server acts as a proxy between the Principal client
 * and Target server. */

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

// unreliableProxyHelper proxies msgs from two udplike connections
func unreliableProxyHelper(a transport.UDPLike, b transport.UDPLike) {
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, _, _, err := a.ReadMsgUDP(buf, nil)
			if err != nil {
				logrus.Error(err)
				continue
				// TODO(baumanl): what should actually be done here
			}
			_, _, err = b.WriteMsgUDP(buf[:n], nil, nil)
			if err != nil {
				logrus.Error(err)
				continue
				// TODO(baumanl): what should we do
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, _, _, _, err := b.ReadMsgUDP(buf, nil)
		if err != nil {
			logrus.Error(err)
			continue
			// TODO(baumanl): what should actually be done here
		}
		_, _, err = a.WriteMsgUDP(buf[:n], nil, nil)
		if err != nil {
			logrus.Error(err)
			continue
			// TODO(baumanl): what should we do
		}
	}
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
