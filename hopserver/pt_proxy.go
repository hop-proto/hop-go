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
	// +checklocks:lock
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

func unreliableProxyOneSide(a transport.UDPLike, b transport.UDPLike, wg *sync.WaitGroup) {
	buf := make([]byte, tubes.MaxFrameDataLength)
	defer wg.Done()
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

// manage principal to target proxying (t is a reliable tube)
func (sess *hopSession) startPTProxy(t net.Conn, pq *ptProxyTubeQueue) {

	// TODO(baumanl): add check for authgrant?

	// make sure this is currently expected
	if sess.numActiveReqDelegates.Load() == 0 {
		logrus.Info("Server: received unexpected request to start net proxy")
		return
	}

	// receive target message
	var targetInfo authgrants.TargetInfo
	url, err := authgrants.ReadTargetInfo(t)
	if err != nil {
		logrus.Errorf("pt_proxy: error reading target info: %s", err)
		authgrants.WriteFailure(t, "Server: unable to read target info")
		return
	}
	targetInfo.TargetURL = *url
	logrus.Info("pt_proxy: read targetinfo")

	// connect to target
	targetConn, err := targetInfo.ConnectToTarget()
	if err != nil {
		logrus.Errorf("pt_proxy: error connecting to target: %s", err)
		authgrants.WriteFailure(t, fmt.Sprint(err))
		return
	}
	logrus.Info("pt_proxy: connected to target")
	defer targetConn.Close()
	err = authgrants.WriteConfirmation(t)
	if err != nil {
		logrus.Error("pt_proxy: error writing confirmation of target conn")
		return
	}
	logrus.Info("pt_proxy: wrote confirmation of target conn")

	// receive unreliable principal proxy tube id
	tubeID, err := authgrants.ReadUnreliableProxyID(t)
	if err != nil {
		logrus.Errorf("Server: error reading unreliable proxy id: %s", err)
	}
	logrus.Infof("pt_proxy: got unreliable proxy ID: %v", tubeID)

	test := func(m map[byte]*tubes.Unreliable, b byte) bool {
		_, ok := m[b]
		return ok
	}
	// check (and keep checking on signal) for the unreliable tube with the id
	pq.lock.Lock()
	logrus.Info("pt_proxy: acquired pq.lock for the first time")
	for !test(pq.tubes, tubeID) {
		logrus.Info("tube not here yet. waiting...")
		pq.cv.Wait()
	}

	principalTube := pq.tubes[tubeID]
	logrus.Info("pt_proxy: got the unreliable tube")
	delete(pq.tubes, tubeID)
	pq.lock.Unlock()

	// send confirmation to principal
	err = authgrants.WriteConfirmation(t)
	if err != nil {
		logrus.Errorf("pt_proxy: error writing confirmation to principal: %s", err)
		return
	}

	logrus.Info("pt_proxy: wrote conf to principal; starting unreliable proxy")

	wg := &sync.WaitGroup{}
	wg.Add(2)

	// proxy
	go unreliableProxyOneSide(principalTube, targetConn, wg)
	go unreliableProxyOneSide(targetConn, principalTube, wg)

	t.Read(make([]byte, 1)) // block until this tube is closed by principal
	logrus.Info("pt_proxy: reliable tube with principal closed. shutting down pt proxy...")

	err = targetConn.Close()
	if err != nil {
		logrus.Error("pt_proxy: error closing target conn udp conn: ", err)
	}
	logrus.Info("pt_proxy: closed udp conn to target")

	err = principalTube.Close()
	if err != nil {
		logrus.Error("pt_proxy: error closing unreliable principal tube: ", err)
	}
	logrus.Infof("pt_proxy: closed unreliable principal tube with id %v", principalTube.GetID())

	err = t.Close()
	if err != nil {
		logrus.Error("pt_proxy: error closing reliable principal conn: ", err)
	}
	logrus.Info("pt_proxy: closed reliable principal tube")
	wg.Wait()
}
