package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
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

type hopServer struct {
	m          sync.Mutex
	principals map[int32]*transport.Handle
	sessions   map[*transport.Handle]*channels.Muxer

	server   *transport.Server
	authsock net.Listener
}

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

//handles connections to the hop server UDS to allow hop client processes to get authorization grants from their principal
func (server *hopServer) authGrantServer() {
	defer server.authsock.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", server.authsock.Addr().String())

	for {
		c, err := server.authsock.Accept()
		if err != nil {
			logrus.Fatal("accept error:", err)
		}

		go authgrants.ProxyAuthGrantRequest(c, server.principals, server.sessions)
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

//listen for incoming hop connection requests and start corresponding authGrantServer on a Unix Domain socket
func serve(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//logrus.SetOutput(io.Discard)
	//TEMPORARY: Should take address from argument and socket should be abstract/same place or dependent on session?
	addr := "localhost:7777"
	sockAddr := "@auth1"
	if args[2] == "2" {
		addr = "localhost:8888"
		sockAddr = "@auth2" //because we are on the same host => figure out how to use abstract sockets and naming
	} else if args[2] == "3" {
		addr = "localhost:9999"
		sockAddr = "@auth3"
	}

	//*****TRANSPORT LAYER SET UP*****
	pktConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING UDP CONN: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	transportServer, err := transport.NewServer(udpConn, newTestServerConfig())
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

	//TODO(baumanl): Make thread safe?
	//principal hop sessions are represented by the appropriate channel muxer for that session
	principals := make(map[int32]*transport.Handle) //PID -> principal hop session
	//agToMux := make(map[string]*channels.Muxer)   //AuthGrant -> principal hop session (added by server when it issues an authgrant)
	sessions := make(map[*transport.Handle]*channels.Muxer) //all hop sessions -> their channel muxers

	server := &hopServer{
		m:          sync.Mutex{},
		principals: principals,
		sessions:   sessions,

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
		go session(transportServer, serverConn, principals, l, sessions)
	}
}

//Starts a session muxer and manages incoming channel requests
func session(server *transport.Server, serverConn *transport.Handle, principals map[int32]*transport.Handle, l net.Listener, sessions map[*transport.Handle]*channels.Muxer) {
	ms := channels.NewMuxer(serverConn, serverConn)
	go ms.Start()
	defer ms.Stop()
	logrus.Info("S: STARTED CHANNEL MUXER")
	sessions[serverConn] = ms
	for {
		serverChan, err := ms.Accept()
		if err != nil {
			logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", serverChan.Type())

		switch serverChan.Type() {
		case channels.EXEC_CHANNEL:
			cmd, _ := codex.GetCmd(serverChan)
			if _, p := serverConn.GetPrincipalSession(); p {
				if cmd != serverConn.AG.Action {
					logrus.Error("CMD does not match Authgrant approved action")
					continue
				}
				if serverConn.Used() { //Probably not necessary to check because the client can't create another code execution channel with the current framework anyway
					logrus.Error("Already performed Authgrant approved action")
					continue
				}
				serverConn.SetUsed()
			}
			logrus.Infof("Executing: %v", cmd)

			args := strings.Split(cmd, " ")
			c := exec.Command(args[0], args[1:]...)
			// c.SysProcAttr = &syscall.SysProcAttr{}
			// c.SysProcAttr.Credential = &syscall.Credential{Uid: uid}

			f, err := pty.Start(c)
			if err != nil {
				logrus.Fatalf("S: error starting pty %v", err)
			}
			go func() {
				c.Wait()
				serverChan.Close()
				logrus.Info("closed chan")
			}()

			if handle, ok := serverConn.GetPrincipalSession(); ok {
				principals[int32(c.Process.Pid)] = handle
			} else {
				logrus.Infof("S: using standard muxer")
				principals[int32(c.Process.Pid)] = serverConn
			}
			go codex.Server(serverChan, f)
		case channels.AGC_CHANNEL:
			k, t, user, action, e := authgrants.HandleIntentComm(serverChan)
			if e != nil {
				logrus.Info("Server denied authgrant")
				authgrants.SendIntentDenied(serverChan, "Server denied")
				continue
			}
			server.AddAuthgrant(k, t, user, action, serverConn)
			authgrants.SendIntentConf(serverChan, t)
			logrus.Info("Sent intent conf")
			serverChan.Close()
		case channels.NPC_CHANNEL:
			go npc.Server(serverChan)
		default:
			serverChan.Close()
		}
	}
}
