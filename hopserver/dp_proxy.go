package hopserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
)

/* DP Proxy: Server acts as a proxy between the Delegate client
 * and Principal client. */

/* Delegate proxy server: a hop server that has an active hop session with
 * a (remote) Principal hop client and a (local) Delegate hop client that was
 * started from a process spawned from that active hop session. Two "proxying"
 * actions actually occur:
 * 1. Delegate hop client <--> Principal hop client (dp_proxy.go) (*)
 * 2. Principal hop client <--> Target hop server (pt_proxy.go)
 *
 * Responsibilities [status] (1: Delegate <--> Principal proxy):
 * - listen on a unix socket for Delegate hop clients [implemented]
 * - maintain a mapping of Delegate hop clients to Principal hop client sessions [implemented]
 * - proxy all authgrant messages between the Delegate and Principal [implemented]
 * - ensure that processes connecting to unix socket are legitimate descendants
 *   of the hop server [implemented for linux, TODO others]
 */

// GetPrincipal is a callback to return principal of sessID
type GetPrincipal func(sessID) (*hopSession, bool)

// dpproxy holds state used by server to proxy delegate requests to principals
type dpproxy struct {
	address      string
	principals   map[int32]sessID
	running      bool
	listener     net.Listener
	proxyLock    sync.Mutex
	getPrincipal GetPrincipal
}

// start starts DP Proxy server
func (p *dpproxy) start() error {
	p.proxyLock.Lock()
	defer p.proxyLock.Unlock()

	if p.running {
		return fmt.Errorf("DP Proxy: start called when already running")
	}

	fileInfo, err := os.Stat(p.address)
	if err == nil { // file exists
		// IsDir is short for fileInfo.Mode().IsDir()
		if fileInfo.IsDir() {
			return fmt.Errorf("DP Proxy: unable to start DP Proxy at address %s: is a directory", p.address)
		}
		//make sure the socket does not already exist.
		if err := os.RemoveAll(p.address); err != nil {
			return fmt.Errorf("DP Proxy: error removing %s: %s", p.address, err)
		}
	}

	//set socket options and start listening to socket
	sockconfig := &net.ListenConfig{Control: setListenerOptions}
	authgrantServer, err := sockconfig.Listen(context.Background(), "unix", p.address)
	if err != nil {
		return fmt.Errorf("DP Proxy: unix socket listen error: %s", err)
	}

	p.listener = authgrantServer
	p.running = true
	go p.serve()

	return nil
}

// serve accepts connections and starts proxying
func (p *dpproxy) serve() {
	logrus.Info("DP Proxy: listening on unix socket: ", p.listener.Addr().String())
	for {
		c, err := p.listener.Accept()
		if err != nil {
			logrus.Error("DP Proxy: accept error:", err)
			continue
		}
		go p.checkAndProxy(c)
	}
}

// checks that the connecting process is a hop session descendent and then proxies
func (p *dpproxy) checkAndProxy(c net.Conn) {
	// Verify that the client is a legit descendent and get principal sess
	principalID, e := p.checkCredentials(c)
	if e != nil {
		logrus.Errorf("DP Proxy: error checking credentials: %v", e)
		return
	}
	principalSess, ok := p.getPrincipal(principalID)
	if !ok {
		logrus.Error("DP Proxy: principal session not found.")
		return
	}
	p.proxyAuthGrantRequest(principalSess, c)
}

// verifies that client is a descendent of a process started by the principal
// and returns its corresponding principal session
func (p *dpproxy) checkCredentials(c net.Conn) (sessID, error) {
	// cPID is PID of client process that connected to socket
	cPID, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	// aPID is the ancestor of cPID spawned by a hop session
	var aPID int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	if err != nil {
		return 0, err
	}

	p.proxyLock.Lock()
	defer p.proxyLock.Unlock()
	// check all of the PIDs of processes that the server started
	for k := range p.principals {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			aPID = k
			break
		}
	}
	if aPID == -1 {
		return 0, errors.New("not a descendent process")
	}
	return p.principals[aPID], nil
}

// checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

// proxyAuthGrantRequest is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
// Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func (p *dpproxy) proxyAuthGrantRequest(principalSess *hopSession, c net.Conn) {
	defer c.Close()
	if principalSess.transportConn.IsClosed() {
		logrus.Error("DP Proxy: connection with principal is closed or closing")
		return
	}
	// connect to principal
	principalConn, err := principalSess.newAuthGrantTube()
	if err != nil {
		logrus.Errorf("DP Proxy: error connecting to principal: %v", err)
		return
	}
	defer principalConn.Close()
	logrus.Infof("DP Proxy: connected to principal")

	// enable principal to proxy a connection through the server
	principalSess.numActiveReqDelegates.Add(1)

	proxyHelper(principalConn, c)

	// disable principal's ability to proxy a connection through the server
	principalSess.numActiveReqDelegates.Add(-1)
}

func proxyHelper(p net.Conn, c net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	// proxy the bytes
	go func() {
		w, err := io.Copy(c, p)
		logrus.Infof("DP Proxy: wrote %v bytes to client from principal. err: %v", w, err)
		err = c.Close()
		logrus.Debugf("c close: %v", err)
		wg.Done()
	}()
	w, err := io.Copy(p, c)
	logrus.Infof("DP Proxy: wrote %v bytes to principal from client. err: %v", w, err)
	err = p.Close()
	logrus.Debugf("p close: %v", err)
	wg.Wait()
}
