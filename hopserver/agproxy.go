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

// Agproxy holds state used by server to proxy delegate requests to principals
type Agproxy struct {
	address    string
	principals map[int32]*hopSession // TODO(baumanl): pointer to hopSession may not work how I want...
	running    bool
	listener   net.Listener
	proxyLock  sync.Mutex
}

// Running returns whether agproxy is currently accepting connections
func (p *Agproxy) Running() bool {
	p.proxyLock.Lock()
	defer p.proxyLock.Unlock()
	return p.running
}

// Start starts agproxy server
func (p *Agproxy) Start() error {
	p.proxyLock.Lock()
	defer p.proxyLock.Unlock()

	fileInfo, err := os.Stat(p.address)
	if err == nil { // file exists
		// IsDir is short for fileInfo.Mode().IsDir()
		if fileInfo.IsDir() {
			return fmt.Errorf("Agproxy: unable to start agproxy at address %s: is a directory", p.address)
		}
		//make sure the socket does not already exist.
		if err := os.RemoveAll(p.address); err != nil {
			return fmt.Errorf("Agproxy: error removing %s: %s", p.address, err)
		}
	}

	//set socket options and start listening to socket
	sockconfig := &net.ListenConfig{Control: setListenerOptions}
	authgrantServer, err := sockconfig.Listen(context.Background(), "unix", p.address)
	if err != nil {
		return fmt.Errorf("Agproxy: unix socket listen error: %s", err)
	}

	p.listener = authgrantServer
	p.running = true
	go p.serve()

	return nil
}

// serve accepts connections and starts proxying
func (p *Agproxy) serve() {
	logrus.Info("Agproxy: listening on unix socket: ", p.listener.Addr().String())
	for {
		c, err := p.listener.Accept()
		if err != nil {
			logrus.Error("Agproxy: accept error:", err)
			continue
		}
		go p.checkAndProxy(c)
	}
}

// checks that the connecting process is a hop session descendent and then proxies
func (p *Agproxy) checkAndProxy(c net.Conn) {
	// Verify that the client is a legit descendent and get principal sess
	principalSess, e := p.checkCredentials(c)
	if e != nil {
		logrus.Errorf("Agproxy: error checking credentials: %v", e)
		return
	}
	p.proxyAuthGrantRequest(principalSess, c)
}

// verifies that client is a descendent of a process started by the principal
// and returns its corresponding principal session
func (p *Agproxy) checkCredentials(c net.Conn) (*hopSession, error) {
	// cPID is PID of client process that connected to socket
	cPID, err := readCreds(c)
	if err != nil {
		return nil, err
	}
	// aPID is the ancestor of cPID spawned by a hop session
	var aPID int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	if err != nil {
		return nil, err
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
		return nil, errors.New("not a descendent process")
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
func (p *Agproxy) proxyAuthGrantRequest(principalSess *hopSession, c net.Conn) {
	defer c.Close()
	if principalSess.transportConn.IsClosed() {
		logrus.Error("Agproxy: connection with principal is closed or closing")
		return
	}
	// connect to principal
	principalConn, err := principalSess.newAuthGrantTube()
	if err != nil {
		logrus.Errorf("Agproxy: error connecting to principal: %v", err)
		return
	}
	defer principalConn.Close()
	logrus.Infof("Agproxy: connected to principal")

	proxyHelper(principalConn, c)

}

func proxyHelper(p net.Conn, c net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	// proxy the bytes
	go func() {
		w, err := io.Copy(c, p)
		logrus.Infof("Agproxy: wrote %v bytes to client from principal. err: %v", w, err)
		err = c.Close()
		logrus.Debugf("c close: %v", err)
		wg.Done()
	}()
	w, err := io.Copy(p, c)
	logrus.Infof("Agproxy: wrote %v bytes to principal from client. err: %v", w, err)
	err = p.Close()
	logrus.Debugf("p close: %v", err)
	wg.Wait()
}
