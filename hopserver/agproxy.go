package hopserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/common"
	"hop.computer/hop/proxy"
	"hop.computer/hop/tubes"

	"golang.org/x/exp/maps"
)

// Proxy: a hop server that has an active hop session with
//   a (remote) Principal hop client and a (local) Delegate hop client that was
//   started from a process spawned from that active hop session. Two "proxying"
//   actions actually occur:
//   1. Delegate hop client <--> Principal hop client (dp_proxy.go) (*)
//   2. Principal hop client <--> Target hop server (pt_proxy.go)

//   Responsibilities [status] (1: Delegate <--> Principal proxy):
//   - listen on a unix socket for Delegate hop clients
//   - maintain a mapping of Delegate hop clients to Principal hop client sessions
//   - proxy all authgrant messages between the Delegate and Principal
//   - ensure that processes connecting to unix socket are legitimate descendants
//     of the hop server [implemented for linux, TODO others]

// 	Responsibilities [status] (2: Principal <--> Target proxy):
// 	- run a proxy between the Principal (unreliable tube) and Target
// 		(udp "conn") (roughly implemented)
// 	- only create a proxy if it is expected and allowed (partially implemented)
// 	- close down the proxy/associated resources neatly if either side fails (TODO)

// GetPrincipal is a callback to return principal of sessID
type GetPrincipal func(sessID) (*hopSession, bool)

// agProxy holds state used by server to proxy delegate requests to principals
type agProxy struct {
	address string // unix socket to listen on.

	// +checklocks:principalLock
	principals    map[int32]sessID
	principalLock sync.Mutex

	// +checklocks:runningCV.L
	listener net.Listener
	running  bool
	// +checklocks::runningCV.L
	runningCV sync.Cond

	proxyWG      sync.WaitGroup
	getPrincipal GetPrincipal
}

type agpInstance struct {
	dconn net.Conn        // connection to delegate (IPC)
	pconn *tubes.Reliable // connection to target (reliable tube)

	targetUDP *net.UDPConn      // udp socket with target
	pproxy    *tubes.Unreliable // tube for principal to proxy to target over
}

// start starts authgrant proxy server
func (p *agProxy) start() error {
	if p.running {
		return fmt.Errorf("AG Proxy: start called when already running")
	}

	logrus.Debug("AG Proxy: trying to acquire proxyLock")
	p.runningCV.L.Lock()
	defer p.runningCV.L.Unlock()

	fileInfo, err := os.Stat(p.address)
	if err == nil { // file exists
		// IsDir is short for fileInfo.Mode().IsDir()
		if fileInfo.IsDir() {
			return fmt.Errorf("AG Proxy: unable to start AG Proxy at address %s: is a directory", p.address)
		}
		// make sure the socket does not already exist. remove if it does.
		if err := os.RemoveAll(p.address); err != nil {
			return fmt.Errorf("AG Proxy: error removing %s: %s", p.address, err)
		}
	}

	// set socket options and start listening to socket
	sockconfig := &net.ListenConfig{Control: setListenerOptions}
	authgrantServer, err := sockconfig.Listen(context.Background(), "unix", p.address)
	if err != nil {
		return fmt.Errorf("AG Proxy: unix socket listen error: %s", err)
	}

	p.listener = authgrantServer
	p.running = true
	go p.serve()

	return nil
}

// serve accepts connections and starts proxying
func (p *agProxy) serve() {
	logrus.Info("AG Proxy: listening on unix socket: ", p.listener.Addr().String())
	for {
		c, err := p.listener.Accept()
		// If the listener was closed, it's ok to return
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			logrus.Error("AG Proxy: accept error:", err)
			continue
		}
		p.proxyWG.Add(1)
		go p.checkAndProxy(c)
	}
}

func (p *agProxy) stop() error {
	p.runningCV.L.Lock()
	if p.listener != nil {
		l := p.listener.(*net.UnixListener)
		l.Close()
	}
	p.runningCV.L.Unlock()
	p.runningCV.Broadcast()
	p.proxyWG.Wait()
	return nil
}

// checks that the connecting process is a hop session descendent and then proxies
func (p *agProxy) checkAndProxy(c net.Conn) {
	defer p.proxyWG.Done()
	defer c.Close()
	logrus.Debug("AG Proxy: just accepted a new connection")
	// Verify that the client is a legit descendent and get principal sess
	principalID, e := p.checkCredentials(c)
	if e != nil {
		logrus.Errorf("AG Proxy: error checking credentials: %v", e)
		return
	}
	principalSess, ok := p.getPrincipal(principalID)
	if !ok {
		logrus.Error("AG Proxy: principal session not found.")
		return
	}
	logrus.Debug("AG Proxy: found the principal session")

	if principalSess.transportConn.IsClosed() {
		logrus.Error("AG Proxy: connection with principal is closed or closing")
		return
	}
	// connect to principal (reliable)
	principalConn, err := principalSess.newAuthGrantTube()
	if err != nil {
		logrus.Errorf("AG Proxy: error connecting to principal: %v", err)
		return
	}
	logrus.Infof("AG Proxy: connected to principal")
	defer principalConn.Close()

	// connect to principal (unreliable)
	unreliableProxyTube, err := principalSess.newUnreliablePrincipalProxyTube()
	if err != nil {
		logrus.Errorf("AG Proxy: error making unreliable proxy tube with principal: %v", err)
		return
	}
	logrus.Infof("AG Proxy: got unreliable proxy tube to principal")
	defer unreliableProxyTube.Close()

	// read Target Info and get udp conn to target
	targetURL, err := authgrants.ReadTargetInfo(c)
	if err != nil {
		return
	}

	ti := authgrants.TargetInfo{
		TargetURL: *targetURL,
	}

	tconn, err := ti.ConnectToTarget()
	if err != nil {
		logrus.Error("AG Proxy: error connecting to target")
		return
	}
	logrus.Infof("AG Proxy: successfully connected to target")
	defer tconn.Close()

	conns := &agpInstance{
		dconn:     c,
		pconn:     principalConn,
		targetUDP: tconn,
		pproxy:    unreliableProxyTube,
	}

	p.proxy(conns)
}

// proxy is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
// Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func (p *agProxy) proxy(conns *agpInstance) {
	// send unreliable pproxy tube id to principal over pconn
	err := authgrants.WriteUnreliableProxyID(conns.pconn, conns.pproxy.GetID())
	if err != nil {
		logrus.Error("AG Proxy: error writing unreliable proxy id")
		return
	}
	logrus.Info("AG Proxy: wrote unreliable proxy id", conns.pproxy.GetID())
	logrus.Info("AG Proxy: starting PT and DP proxies")

	ptWG := proxy.UnreliableProxy(conns.pproxy, conns.targetUDP) // started proxy from principal to target
	dpWG := proxy.ReliableProxy(conns.pconn, conns.dconn)        // started proxy from delegate to principal

	dpCh := make(chan struct{})
	go func() {
		defer close(dpCh)
		dpWG.Wait()
	}()

	ptCh := make(chan struct{})
	go func() {
		defer close(ptCh)
		ptWG.Wait()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)

		isRunning := func() bool {
			return p.running
		}

		p.runningCV.L.Lock()
		for isRunning() {
			p.runningCV.Wait()
		}
		p.runningCV.L.Unlock()
	}()

	select {
	case <-dpCh: // dp_proxy closed normally
		logrus.Info("AG Proxy: closed normally")
		// TODO(baumanl): give principal time to close hop sess with target
		// before ripping out proxy?
		conns.pconn.WaitForClose() // TODO(baumanl): ask george if this does what I want
		conns.pproxy.Close()
		conns.targetUDP.Close()
		<-ptCh
	case <-ptCh:
		logrus.Info("AG Proxy: pt proxy closed before dp")
		conns.pconn.Close()
		conns.dconn.Close()
		<-dpCh
	case <-done:
		logrus.Info("AG Proxy: proxy being force closed")
		conns.pconn.Close()
		conns.dconn.Close()
		<-dpCh
		conns.pconn.WaitForClose() // TODO(baumanl): ask george if this does what I want
		conns.pproxy.Close()
		conns.targetUDP.Close()
		<-ptCh
	}
}

// verifies that client is a descendent of a process started by the principal
// and returns its corresponding principal session
func (p *agProxy) checkCredentials(c net.Conn) (sessID, error) {
	// cPID is PID of client process that connected to socket
	cPID, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	p.principalLock.Lock()
	defer p.principalLock.Unlock()
	aPID, err := getAncestor(maps.Keys(p.principals), cPID)
	if err != nil {
		return 0, err
	}

	return p.principals[aPID], nil
}

func (sess *hopSession) newUnreliablePrincipalProxyTube() (*tubes.Unreliable, error) {
	return sess.tubeMuxer.CreateUnreliableTube(common.PrincipalProxyTube)
}
