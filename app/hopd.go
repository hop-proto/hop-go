package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/npc"
	"zmap.io/portal/transport"
)

func newTestServerConfig() *transport.ServerConfig {
	keyPair, err := keys.ReadDHKeyFromPEMFile("./testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: WRROR WITH CERTS %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
	}
	return &transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
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

func checkCredentials(c net.Conn, principals *map[int32]*channels.Muxer) (int32, error) {
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
	//display(os.Getppid(), tree, 1) //displays all pstree for ipcserver
	if err != nil {
		return 0, err
	}
	//check all of the PIDs of processes that the server started
	for k := range *principals {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			ancestor = k
			break
		}
	}
	if ancestor == -1 {
		return 0, errors.New("not a descendent process")
	}
	logrus.Info("S: CREDENTIALS VERIFIED")
	return ancestor, nil
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

func authGrantServer(l net.Listener, principals *map[int32]*channels.Muxer) {
	defer l.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", l.Addr().String())

	for {
		c, err := l.Accept()
		if err != nil {
			logrus.Fatal("accept error:", err)
		}

		go handleAuthGrantRequest(c, principals)
	}
}

//TODO: check threadsafety
func handleAuthGrantRequest(c net.Conn, principals *map[int32]*channels.Muxer) {
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()
	//Verify that the client is a legit descendent
	ancestor, e := checkCredentials(c, principals)
	if e != nil {
		log.Fatalf("S: ISSUE CHECKING CREDENTIALS: %v", e)
	}
	// find corresponding session muxer
	principal := (*principals)[ancestor]
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())
	intent, e := authgrants.ReadIntentRequest(c)
	if e != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", e)
	}
	agc, err := principal.CreateChannel(channels.AGC_CHANNEL)
	if err != nil {
		logrus.Fatalf("S: ERROR MAKING CHANNEL: %v", err)
	}
	logrus.Infof("S: CREATED CHANNEL (AGC)")
	_, err = agc.Write(intent)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}
	logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")
	response, err := authgrants.GetResponse(agc)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v, %v", err, response)
	}
	_, err = c.Write(response)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}

	if response[0] == authgrants.INTENT_DENIED {
		//ASK USER IF THEY WANT TO TRY AGAIN BEFORE CLOSING AGC
	}
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

func serve(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//TEMPORARY: Should take address from argument and socket should be abstract/same place or dependent on session?
	addr := "localhost:7777"
	sockAddr := "/tmp/auth.sock"
	if args[2] == "2" {
		addr = "localhost:8888"
		sockAddr = "/tmp/auth2.sock" //because we are on the same host => figure out how to use abstract sockets and naming
	} else if args[2] == "3" {
		addr = "localhost:9999"
		sockAddr = "/tmp/auth3.sock"
	}

	//*****TRANSPORT LAYER SET UP*****
	pktConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING UDP CONN: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig())
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING TRANSPORT CONN: %v", err)
	}
	go server.Serve()

	//*****AUTHGRANT SERVER ON UNIX DOMAIN SOCKET SET UP*****
	//Start IPC socket TODO: need 1 for every session? MAKE ABSTRACT?
	//make sure the socket does not already exist.
	if err := os.RemoveAll(sockAddr); err != nil {
		log.Fatal(err)
	}
	//set socket options and start listening to socket
	config := &net.ListenConfig{Control: setListenerOptions}
	l, err := config.Listen(context.Background(), "unix", sockAddr)
	if err != nil {
		log.Fatal("S: UDS LISTEN ERROR:", err)
	}
	//TODO: Make thread safe?
	principals := make(map[int32]*channels.Muxer) //PID -> principal hop session
	agToMux := make(map[string]*channels.Muxer)   //AuthGrant -> session muxer (added by server when it issues an authgrant)

	go authGrantServer(l, &principals)

	//*****ACCEPT CONNS AND START SESSIONS*****
	for {
		logrus.Infof("S: SERVER LISTENING ON %v", addr)
		serverConn, err := server.AcceptTimeout(30 * time.Minute) //won't be a minute in reality
		//From serverConn (handle on connection) get authgrant
		if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CONNECTION with authgrant: %v", serverConn.Authgrant)
		logrus.Infof("agToMux[authgrant] -> %v", agToMux[serverConn.Authgrant])
		go session(serverConn, principals, l, agToMux)
	}
}

func session(serverConn *transport.Handle, principals map[int32]*channels.Muxer, l net.Listener, agToMux map[string]*channels.Muxer) {
	ms := channels.NewMuxer(serverConn, serverConn)
	go ms.Start()
	defer ms.Stop()
	logrus.Info("S: STARTED CHANNEL MUXER")

	for {
		serverChan, err := ms.Accept()
		if err != nil {
			logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", serverChan.Type())
		if serverChan.Type() == channels.EXEC_CHANNEL {

			l := make([]byte, 1)
			serverChan.Read(l)
			cmd := make([]byte, int(l[0]))
			serverChan.Read(cmd)
			logrus.Infof("Executing: %v", string(cmd))

			args := strings.Split(string(cmd), " ")
			c := exec.Command(args[0], args[1:]...)

			f, err := pty.Start(c)

			//If session is using an authorization grant then the muxer in this goroutine
			//should be replaced by the muxer that the server has with the principal that authorized the grant
			//use the muxers map above (authgrant --> muxer)
			if mux, ok := agToMux[serverConn.Authgrant]; ok {
				principals[int32(c.Process.Pid)] = mux
				logrus.Infof("S: using muxer from auth grant: %v", serverConn.Authgrant)
			} else {
				logrus.Infof("S: using standard muxer")
				principals[int32(c.Process.Pid)] = ms
			}
			if err != nil {
				logrus.Fatalf("S: error starting pty %v", err)
			}
			go codex.Serve(serverChan, f)
		} else if serverChan.Type() == channels.NPC_CHANNEL {
			go npc.Server(serverChan)
		} else if serverChan.Type() == channels.AGC_CHANNEL {
			go authgrants.Server(serverChan, ms, agToMux)
		}
	}
}
