package app

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

type hopServer struct {
	m                     sync.Mutex
	principals            map[int32]*hopSession
	authgrants            map[keys.PublicKey]*authGrant //static key -> authgrant associated with that key
	outstandingAuthgrants int

	server   *transport.Server
	authsock net.Listener
}

//Starts a new hop session
func (s *hopServer) newSession(serverConn *transport.Handle) {
	sess := &hopSession{
		transportConn: serverConn,
		tubeMuxer:     tubes.NewMuxer(serverConn, serverConn),
		tubeQueue:     make(chan *tubes.Reliable),
		done:          make(chan int),
		server:        s,
	}
	sess.start()
}

//handles connections to the hop server UDS to allow hop client processes to get authorization grants from their principal
func (s *hopServer) authGrantServer() {
	defer s.authsock.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", s.authsock.Addr().String())

	for {
		c, err := s.authsock.Accept()
		if err != nil {
			logrus.Error("accept error:", err)
			continue
		}

		go s.proxyAuthGrantRequest(c)
	}
}

//proxyAuthGrantRequest is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
//Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func (s *hopServer) proxyAuthGrantRequest(c net.Conn) {
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()
	//Verify that the client is a legit descendent
	ancestor, e := s.checkCredentials(c)
	if e != nil {
		logrus.Errorf("S: ISSUE CHECKING CREDENTIALS: %v", e)
		return
	}
	s.m.Lock()
	// find corresponding session
	principalSess := s.principals[ancestor]
	s.m.Unlock()
	if principalSess.transportConn.IsClosed() {
		logrus.Error("S: Connection with Principal is closed")
		return
	}
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())
	agc := authgrants.NewAuthGrantConn(c)
	principalAgc, err := authgrants.NewAuthGrantConnFromMux(principalSess.tubeMuxer)
	if err != nil {
		logrus.Errorf("S: ERROR MAKING AGT WITH PRINCIPAL: %v", err)
		return
	}
	defer principalAgc.Close()
	logrus.Infof("S: CREATED AGC")
	for {
		req, e := agc.ReadIntentRequest()
		if e != nil { //if client closes agc this will error out and the loop will end
			logrus.Info("Delegate client closed IPC AGC with delegate server.")
			return
		}
		err = principalAgc.WriteRawBytes(req)
		if err != nil {
			logrus.Errorf("S: ERROR WRITING TO CHANNEL: %v", err)
			return
		}
		logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")
		_, response, err := principalAgc.ReadResponse()
		if err != nil {
			logrus.Errorf("S: ERROR GETTING RESPONSE: %v, %v", err, response)
			return
		}
		err = agc.WriteRawBytes(response)
		if err != nil {
			logrus.Errorf("S: ERROR WRITING TO CHANNEL: %v", err)
			return
		}
	}
}

//verifies that client is a descendent of a process started by the principal and returns its ancestor process PID if found
func (s *hopServer) checkCredentials(c net.Conn) (int32, error) {
	creds, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	//PID of client process that connected to socket
	cPID := creds.Pid
	//ancestor represents the PID of the ancestor of the client and child of server daemon
	var ancestor int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	if err != nil {
		return 0, err
	}
	//check all of the PIDs of processes that the server started
	s.m.Lock()
	for k := range s.principals {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			ancestor = k
			break
		}
	}
	s.m.Unlock()
	if ancestor == -1 {
		return 0, errors.New("not a descendent process")
	}
	logrus.Info("S: CREDENTIALS VERIFIED")
	return ancestor, nil
}

//checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

//Callback function that sets the appropriate socket options
func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PASSCRED,
			1)
	})
}

//Src: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/src/peercred/cred.go
//Parses the credentials sent by the client when it connects to the socket
func readCreds(c net.Conn) (*unix.Ucred, error) {
	var cred *unix.Ucred

	//should only have *net.UnixConn types
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error opening raw connection: %s", err)
	}

	// The raw.Control() callback does not return an error directly.
	// In order to capture errors, we wrap already defined variable
	// 'err' within the closure. 'err2' is then the error returned
	// by Control() itself.
	err2 := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED)
	})

	if err != nil {
		return nil, fmt.Errorf(" GetsockoptUcred() error: %s", err)
	}

	if err2 != nil {
		return nil, fmt.Errorf(" Control() error: %s", err2)
	}

	return cred, nil
}
