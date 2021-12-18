package app

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

//HopServer represents state/conns needed for a hop server
type HopServer struct {
	m                     sync.Mutex
	principals            map[int32]*hopSession
	authgrants            map[keys.PublicKey]*authGrant //static key -> authgrant associated with that key
	outstandingAuthgrants int
	config                *HopServerConfig

	server   *transport.Server
	authsock net.Listener
}

//HopServerConfig contains hop server specific configuration settings
type HopServerConfig struct {
	Port string
	Host string

	SockAddr                 string
	TransportConfig          *transport.ServerConfig
	MaxOutstandingAuthgrants int
}

//NewHopServer returns a Hop Server containing a transport server running on the host/port
//sepcified in the config file and an authgrant server listening on the provided socket.
func NewHopServer(hconfig *HopServerConfig) (*HopServer, error) {
	//set up transportServer
	//*****TRANSPORT LAYER SET UP*****
	pktConn, err := net.ListenPacket("udp", net.JoinHostPort(hconfig.Host, hconfig.Port))
	if err != nil {
		logrus.Errorf("S: ERROR STARTING UDP CONN: %v", err)
		return nil, err
	}
	logrus.Infof("listening on %v:%v", hconfig.Host, hconfig.Port)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	transportServer, err := transport.NewServer(udpConn, *hconfig.TransportConfig)
	if err != nil {
		logrus.Errorf("S: ERROR STARTING TRANSPORT CONN: %v", err)
		return nil, err
	}
	//set up authgrantServer (UDS socket)
	//make sure the socket does not already exist.
	if err := os.RemoveAll(hconfig.SockAddr); err != nil {
		logrus.Error(err)
		return nil, err
	}

	//set socket options and start listening to socket
	sockconfig := &net.ListenConfig{Control: setListenerOptions}
	authgrantServer, err := sockconfig.Listen(context.Background(), "unix", hconfig.SockAddr)
	logrus.Infof("address: %v", authgrantServer.Addr())
	if err != nil {
		logrus.Error("S: UDS LISTEN ERROR:", err)
		return nil, err
	}

	principals := make(map[int32]*hopSession)         //PID -> principal hop session
	authgrants := make(map[keys.PublicKey]*authGrant) //static key -> authgrant

	server := &HopServer{
		m:                     sync.Mutex{},
		principals:            principals,
		authgrants:            authgrants,
		outstandingAuthgrants: 0,
		config:                hconfig,

		server:   transportServer,
		authsock: authgrantServer,
	}

	return server, nil
}

//Serve listens for incoming hop connection requests and start corresponding authGrantServer on a Unix Domain socket
func (s *HopServer) Serve() {
	logrus.SetLevel(logrus.InfoLevel)

	go s.server.Serve()    //start transport layer server
	go s.authGrantServer() //start authgrant server

	//*****ACCEPT CONNS AND START SESSIONS*****
	logrus.Info("hop server starting")
	for {
		serverConn, err := s.server.AcceptTimeout(30 * time.Minute)
		if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Debugf("S: ACCEPTED NEW CONNECTION with authgrant")
		go s.newSession(serverConn)
	}
}

//Starts a new hop session
func (s *HopServer) newSession(serverConn *transport.Handle) {
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
func (s *HopServer) authGrantServer() {
	defer s.authsock.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", s.authsock.Addr().String())

	for {
		c, err := s.authsock.Accept()
		if err != nil {
			logrus.Error("accept error:", err)
			continue
		}
		go func() {
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
			s.proxyAuthGrantRequest(principalSess, c)
		}()
	}

}

//proxyAuthGrantRequest is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
//Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func (s *HopServer) proxyAuthGrantRequest(principalSess *hopSession, c net.Conn) {
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()

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
func (s *HopServer) checkCredentials(c net.Conn) (int32, error) {
	pid, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	//PID of client process that connected to socket
	cPID := pid
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
