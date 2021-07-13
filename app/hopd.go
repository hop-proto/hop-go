package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/keys"
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

func checkCredentials(c net.Conn, principals *map[int32]string) (int32, error) {
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
		return nil, fmt.Errorf("S: unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("S: error opening raw connection: %s", err)
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
		return nil, fmt.Errorf("S: GetsockoptUcred() error: %s", err)
	}

	if err2 != nil {
		return nil, fmt.Errorf("S: Control() error: %s", err2)
	}

	return cred, nil
}

func authGrantServer(l net.Listener, principals *map[int32]string, ms *channels.Muxer) {
	defer l.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", l.Addr().String())

	for {
		c, err := l.Accept()
		if err != nil {
			logrus.Fatal("accept error:", err)
		}

		go handleAuthGrantRequest(c, principals, ms)
	}
}

//TODO: check threadsafety
func handleAuthGrantRequest(c net.Conn, principals *map[int32]string, ms *channels.Muxer) {
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()
	//Verify that the client is a legit descendent
	ancestor, e := checkCredentials(c, principals)
	if e != nil {
		log.Fatalf("S: ISSUE CHECKING CREDENTIALS: %v", e)
	}
	// + find corresponding principal
	principal, _ := (*principals)[ancestor]
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())

	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == authgrants.INTENT_REQUEST {
		irh := make([]byte, authgrants.IR_HEADER_LENGTH)
		_, err := c.Read(irh)
		actionLen := int8(irh[authgrants.IR_HEADER_LENGTH-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)

		logrus.Infof("S: INITIATING AGC W/ %v", principal)
		agc, err := ms.CreateChannel(channels.AGC_CHANNEL)
		if err != nil {
			logrus.Fatalf("S: ERROR MAKING CHANNEL: %v", err)
		}
		logrus.Infof("S: CREATED CHANNEL (AGC)")
		agc.Write(append(msgType, append(irh, action...)...))
		if err != nil {
			logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
		}
		logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")

		responseType := make([]byte, 1)
		_, err = agc.Read(responseType)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Infof("Got response type: %v", responseType)
		//TODO: SET TIMEOUT STUFF + BETTER ERROR CHECKING
		if responseType[0] == authgrants.INTENT_CONFIRMATION {
			conf := make([]byte, authgrants.INTENT_CONF_SIZE)
			_, err := agc.Read(conf)
			if err != nil {
				logrus.Fatal(err)
			}
			c.Write(append(responseType, conf...))
		} else if responseType[0] == authgrants.INTENT_DENIED {
			reason_length := make([]byte, 1)
			_, err := agc.Read(reason_length)
			if err != nil {
				logrus.Fatal(err)
			}
			logrus.Infof("C: EXPECTING %v BYTES OF REASON", reason_length)
			reason := make([]byte, int(reason_length[0]))
			_, err = agc.Read(reason)
			if err != nil {
				logrus.Fatal(err)
			}
			c.Write(append(append(responseType, reason_length...), reason...))
		} else {
			logrus.Fatal("S: UNRECOGNIZED MESSAGE TYPE")
		}
	} else {
		logrus.Fatal("S: UNRECOGNIZED MESSAGE TYPE")
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
	addr := "localhost:8888"
	sockAddr := "/tmp/echo1.sock"
	if args[2] == "2" {
		addr = "localhost:9999"
		sockAddr = "/tmp/echo2.sock" //because we are on the same host => figure out how to use abstract sockets and naming
	}
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

	//Start IPC socket
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

	principals := make(map[int32]string) //PID -> "principal" (what should actually rep principal?)

	go server.Serve()

	//TODO: make this a loop so it can handle multiple client conns
	logrus.Infof("S: SERVER LISTENING ON %v", addr)
	serverConn, err := server.AcceptTimeout(5 * time.Minute) //won't be a minute in reality
	if err != nil {
		logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
	}
	logrus.Info("S: ACCEPTED NEW CONNECTION")
	ms := channels.NewMuxer(serverConn, serverConn)
	go ms.Start()
	defer ms.Stop()
	logrus.Info("S: STARTED CHANNEL MUXER")

	go authGrantServer(l, &principals, ms)

	serverChan, err := ms.Accept()
	if err != nil {
		logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
	}
	logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", serverChan.Type())
	exec_channels.Serve(serverChan, &principals)
	logrus.Infof("S: finished command")

	// buf := make([]byte, 14)
	// bytesRead := 0
	// n, err := serverChan.Read(buf[bytesRead:])
	// if err != nil {
	// 	logrus.Fatalf("S: ERROR READING FROM CHANNEL %v", err)
	// }
	// if string(buf[0:n]) == "INTENT_REQUEST" {
	// 	logrus.Info("S: TESTING AGC PROCEDURE")
	// 	//Spawn a child hop client
	// 	cmd := exec.Command("go", "run", "main.go", "hopclient.go", "hopd.go", "hop", "user@127.0.0.1:9999", "-a", "shell", "second param") //need to pass a secret when it is spawned?
	// 	cmd.Stdout = os.Stdout
	// 	cmd.Stderr = os.Stderr
	// 	err = cmd.Start()
	// 	if err != nil {
	// 		logrus.Errorf("S: PROCESS START ERROR: %v", err)
	// 	} else {
	// 		principals[int32(cmd.Process.Pid)] = "principal1" //temporary placeholder for real principal identifier
	// 		logrus.Infof("S: STARTED PROCESS WITH PID: %v", cmd.Process.Pid)
	// 	}
	// } else {
	// 	logrus.Info("S: RECEIVED NOT AN INTENT_REQEST")
	// }

	for {
	}

	//TODO: close channels or muxer appropriately
}
