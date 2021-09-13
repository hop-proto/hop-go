//Package app provides functions to run hop client and hop server
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/creack/pty"
	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/netproxy"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

const maxOutstandingAuthgrants = 50 //TODO(baumanl): calibrate/allow being set from config file

//AuthGrant contains deadline, user, action
type authGrant struct {
	deadline         time.Time
	user             string
	action           string
	principalSession *hopSession
	used             bool
}

type hopServer struct {
	m                     sync.Mutex
	principals            map[int32]*hopSession
	authgrants            map[keys.PublicKey]*authGrant //static key -> authgrant
	outstandingAuthgrants int

	server   *transport.Server
	authsock net.Listener
}

type hopSession struct {
	transportConn *transport.Handle
	tubeMuxer     *tubes.Muxer
	tubeQueue     chan *tubes.Reliable
	done          chan int

	server *hopServer
	user   string

	isPrincipal bool
	authgrant   *authGrant
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
			logrus.Errorf("ERROR READING INTENT REQUEST: %v", e)
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

//Serve listens for incoming hop connection requests and start corresponding authGrantServer on a Unix Domain socket
func Serve(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//logrus.SetOutput(io.Discard)
	//TEMPORARY: Should take address from argument and socket should be abstract/same place or dependent on session?
	hostname, _ := os.Hostname()
	port := defaultHopPort
	sockAddr := defaultHopAuthSocket
	if len(args) > 1 && args[1] == "local" {
		hostname = "localhost"
		if len(args) > 2 {
			port = args[2]
		}
	} else if len(args) > 1 {
		port = args[1]
	}
	addr := hostname + ":" + port

	//*****TRANSPORT LAYER SET UP*****
	pktConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING UDP CONN: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	serverConfig, _ := newTestServerConfig()
	transportServer, err := transport.NewServer(udpConn, serverConfig)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING TRANSPORT CONN: %v", err)
	}
	go transportServer.Serve()

	//*****AUTHGRANT SERVER ON UNIX DOMAIN SOCKET SET UP*****
	//Start UDS socket
	//make sure the socket does not already exist.
	if err := os.RemoveAll(sockAddr); err != nil {
		log.Fatal(err)
	}
	//set socket options and start listening to socket
	config := &net.ListenConfig{Control: setListenerOptions}
	l, err := config.Listen(context.Background(), "unix", sockAddr)
	logrus.Infof("address: %v", l.Addr())
	if err != nil {
		log.Fatal("S: UDS LISTEN ERROR:", err)
	}

	principals := make(map[int32]*hopSession)         //PID -> principal hop session
	authgrants := make(map[keys.PublicKey]*authGrant) //static key -> authgrant

	server := &hopServer{
		m:                     sync.Mutex{},
		principals:            principals,
		authgrants:            authgrants,
		outstandingAuthgrants: 0,

		server:   transportServer,
		authsock: l,
	}

	go server.authGrantServer()

	//*****ACCEPT CONNS AND START SESSIONS*****
	for {
		logrus.Infof("S: SERVER LISTENING ON %v", addr)
		serverConn, err := transportServer.AcceptTimeout(30 * time.Minute)
		if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Debugf("S: ACCEPTED NEW CONNECTION with authgrant")
		go server.newSession(serverConn)
	}
}

func (sess *hopSession) checkAuthorization() bool {
	uaTube, _ := sess.tubeMuxer.Accept()
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	user := userauth.GetInitMsg(uaTube) //client sends desired username
	//TODO(baumanl): verify that this is the best way to get client static key.
	/*I originally had the client just send the key over along with the username, but it
	seemed strange to rely on the client to send the same key that it used during the handshake.
	Instead I modified the transport layer code so that the client static is stored in the session state.
	This way the server directly grabs the key that was used in the handshake.*/
	k := sess.server.server.FetchClientStatic(sess.transportConn) //server fetches client static key that was used in handshake
	logrus.Info("got userauth init message: ", k.String())
	sess.user = user
	//check /user/.hop/authorized_keys first
	path := "/home/" + user + "/.hop/authorized_keys"
	f, e := os.Open(path)
	if e != nil {
		logrus.Error("Could not open file at path: ", path)
	} else {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if scanner.Text() == k.String() {
				logrus.Info("USER AUTHORIZED")
				sess.isPrincipal = true
				uaTube.Write([]byte{userauth.UserAuthConf})
				return true
			}
		}
	}

	//Check for a matching authgrant
	sess.server.m.Lock()
	defer sess.server.m.Unlock()
	val, ok := sess.server.authgrants[k]
	if !ok {
		logrus.Info("USER NOT AUTHORIZED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if val.deadline.Before(time.Now()) {
		delete(sess.server.authgrants, k)
		logrus.Info("AUTHGRANT DEADLINE EXCEEDED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if sess.user != val.user {
		logrus.Info("AUTHGRANT USER DOES NOT MATCH")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	sess.authgrant = val
	sess.isPrincipal = false
	delete(sess.server.authgrants, k)
	logrus.Info("USER AUTHORIZED")
	uaTube.Write([]byte{userauth.UserAuthConf})
	return true
}

//Starts a session muxer and manages incoming tube requests
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

func (sess *hopSession) start() {
	go sess.tubeMuxer.Start()
	logrus.Info("S: STARTED CHANNEL MUXER")

	//User Authorization Step
	if !sess.checkAuthorization() {
		return
		//TODO(baumanl): Check closing behavior. how to end session completely
	}

	logrus.Info("STARTING CHANNEL LOOP")
	go func() {
		for {
			serverChan, err := sess.tubeMuxer.Accept()
			if err != nil {
				logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
			}
			sess.tubeQueue <- serverChan
		}
	}()

	for {
		select {
		case <-sess.done:
			logrus.Info("Closing everything")
			sess.tubeMuxer.Stop()
			return
			//TODO: serverside transport layer Close() not implemented yet
			// e := sess.transportConn.Close()
			// if e != nil {
			// 	logrus.Error("stopped transport conn error: ", e)
			// }
		case serverChan := <-sess.tubeQueue:
			logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", serverChan.Type())
			switch serverChan.Type() {
			case tubes.ExecTube:
				go sess.startCodex(serverChan)
			case tubes.AuthGrantTube:
				go sess.handleAgc(serverChan)
			case tubes.NetProxyTube:
				go netproxy.Server(serverChan)
			default:
				serverChan.Close()
			}
		}

	}
}

func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	agc := authgrants.NewAuthGrantConn(tube)
	k, t, user, action, e := agc.HandleIntentComm()
	logrus.Info("got intent comm")
	if e != nil {
		logrus.Info("Server denied authgrant")
		agc.SendIntentDenied("Server denied")
		return
	}
	sess.server.m.Lock()
	if sess.server.outstandingAuthgrants >= maxOutstandingAuthgrants {
		sess.server.m.Unlock()
		logrus.Info("Server exceeded max number of authgrants")
		agc.SendIntentDenied("Server denied. Too many outstanding authgrants.")
		return
	}
	sess.server.outstandingAuthgrants++
	sess.server.authgrants[k] = &authGrant{
		deadline:         t,
		user:             user,
		action:           action,
		principalSession: sess,
		used:             false,
	}
	sess.server.m.Unlock()
	agc.SendIntentConf(t)
	logrus.Info("Sent intent conf")
	tube.Close()
}

//TODO(baumanl): Add in better privilege separation? Right now hopd(root) directly starts commands through go routines. sshd uses like 3 levels of separation.
func (sess *hopSession) startCodex(ch *tubes.Reliable) {
	cmd, shell, _ := codex.GetCmd(ch)
	logrus.Info("CMD: ", cmd)
	if !sess.isPrincipal {
		if sess.authgrant.used {
			err := errors.New("already performed approved action")
			logrus.Error(err)
			codex.SendFailure(ch, err)
			return
		}
		sess.authgrant.used = true
		if cmd != sess.authgrant.action {
			err := errors.New("CMD does not match Authgrant approved action")
			logrus.Error(err)
			codex.SendFailure(ch, err)
			return
		}
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache() //Best way to do this? should I load this only once and then just reload on misses? What if /etc/passwd modified between accesses?
	if err != nil {
		err := errors.New("issue loading /etc/passwd")
		logrus.Error(err)
		codex.SendFailure(ch, err)
		return
	}
	if user, ok := cache.LookupUserByName(sess.user); ok {
		//Default behavior is for command.Env to inherit parents environment unless given and explicit alternative.
		//TODO(baumanl): These are minimal environment variables. SSH allows for more inheritance from client, but it gets complicated.
		env := []string{
			"USER=" + sess.user,
			"SHELL=" + user.Shell(),
			"LOGNAME=" + user.Username(),
			"HOME=" + user.Homedir(),
			"TERM=" + os.Getenv("TERM"),
		}
		var args []string
		var c *exec.Cmd
		if shell {
			cmd = "login -f " + sess.user //login(1) starts default shell for user and changes all privileges and environment variables
			args = strings.Split(cmd, " ")
			c = exec.Command(args[0], args[1:]...)
		} else {
			args = []string{user.Shell(), "-c", cmd}
			c = exec.Command(args[0], args[1], args[2])
		}
		if !shell {
			c.Dir = user.Homedir()
			c.SysProcAttr = &syscall.SysProcAttr{}
			c.SysProcAttr.Credential = &syscall.Credential{
				Uid:    uint32(user.Uid()),
				Gid:    uint32(user.Gid()),
				Groups: []uint32{uint32(user.Gid())},
			}
		}
		c.Env = env
		logrus.Infof("Executing: %v", cmd)
		f, err := pty.Start(c)
		if err != nil {
			logrus.Errorf("S: error starting pty %v", err)
			codex.SendFailure(ch, err)
			return
		}
		codex.SendSuccess(ch)
		go func() {
			c.Wait()
			ch.Close()
			logrus.Info("closed chan")
		}()

		sess.server.m.Lock()
		if !sess.isPrincipal {
			sess.server.principals[int32(c.Process.Pid)] = sess.authgrant.principalSession
		} else {
			logrus.Infof("S: using standard muxer")
			sess.server.principals[int32(c.Process.Pid)] = sess
		}
		sess.server.m.Unlock()
		go func() {
			codex.Server(ch, f)
			logrus.Info("signaling done")
			sess.done <- 1
		}()
	} else {
		err := errors.New("could not find entry for user " + sess.user)
		logrus.Error(err)
		codex.SendFailure(ch, err)
		return
	}
}
