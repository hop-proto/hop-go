package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

func newTestServerConfig() *transport.ServerConfig {
	keyPair, err := keys.ReadDHKeyFromPEMFile("./testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: error with keypair: %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: error with certs: %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: error with intermediate certs: %v", err)
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
		logrus.Printf("S: Checking [%v]", child)
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

func checkCredentials(c net.Conn, principals *map[int32]string) (int32, error) {
	creds, err := readCreds(c)
	if err != nil {
		logrus.Errorf("S: Error reading credentials: %s", err)
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
		logrus.Errorf("S: Error making pstree: %s", err)
		return 0, err
	}
	//check all of the PIDs of processes that the server started
	for k := range *principals {
		logrus.Printf("S: Checking [%v]", k)
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			logrus.Infof("S: Legit descendent!")
			ancestor = k
			break
		}
	}
	if ancestor == -1 {
		logrus.Infof("S: Not a legitimate descendent. [%v]", ancestor)
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
		log.Fatalf("Issue checking credentials: %v", e)
	}
	// + find corresponding principal
	principal, _ := (*principals)[ancestor]
	logrus.Infof("S: Client connected [%s]", c.RemoteAddr().Network())

	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == authgrants.INTENT_REQUEST {
		irh := make([]byte, authgrants.IR_HEADER_LENGTH)
		_, err := c.Read(irh)
		actionLen := int8(irh[authgrants.IR_HEADER_LENGTH-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)

		logrus.Infof("S: Initiating AGC w/ %v", principal)
		agc, err := ms.CreateChannel(1 << 8)
		if err != nil {
			logrus.Fatalf("S: error making channel: %v", err)
		}
		logrus.Infof("S: CREATED CHANNEL (AGC)")
		agc.Write(append(irh, action...))
		if err != nil {
			logrus.Fatalf("S: error writing to channel: %v", err)
		}
		logrus.Infof("S: WROTE INTENT")

		responseType := make([]byte, 1)
		_, err = agc.Read(responseType)
		if err != nil {

		}
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
			_, err := c.Read(reason_length)
			if err != nil {
				logrus.Fatal(err)
			}
			reason := make([]byte, int(reason_length[0]))
			_, err = c.Read(reason)
			if err != nil {
				logrus.Fatal(err)
			}
			c.Write(append(append(responseType, reason_length...), reason...))
		} else {
			logrus.Fatal("Received unrecognized message type")
		}
	} else {
		logrus.Fatal("Received unrecognized message type")
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
	sockAddr := "echo1.sock"
	if args[2] == "2" {
		addr = "localhost:9999"
		sockAddr = "echo2.sock" //because we are on the same host => figure out how to use abstract sockets and naming
	}
	pktConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logrus.Fatalf("S: error starting udp conn: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig())
	if err != nil {
		logrus.Fatalf("S: error starting transport conn: %v", err)
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
		log.Fatal("S: listen error:", err)
	}

	principals := make(map[int32]string) //PID -> "principal" (what should actually rep principal?)

	go server.Serve()

	//TODO: make this a loop so it can handle multiple client conns
	logrus.Infof("S: SERVER LISTENING ON %v", addr)
	serverConn, err := server.AcceptTimeout(time.Minute) //won't be a minute in reality
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
		logrus.Fatalf("S: issue accepting channel: %v", err)
	}
	logrus.Info("S: ACCEPTED NEW CHANNEL (CODE EXEC)")

	buf := make([]byte, 14)
	bytesRead := 0
	n, err := serverChan.Read(buf[bytesRead:])
	if err != nil {
		logrus.Fatalf("S: issue reading from channel: %v", err)
	}
	if string(buf[0:n]) == "INTENT_REQUEST" {
		logrus.Info("S: REC: INTENT_REQUEST")
		//Spawn some children processes that will act as clients
		cmd := exec.Command("go", "run", "main.go", "hopclient.go", "hopd.go", "hop", "user@127.0.0.1:9999", "-a", "shell") //need to pass a secret when it is spawned?
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			logrus.Errorf("S: Started w/ err: %v", err)
		} else {
			principals[int32(cmd.Process.Pid)] = "principal1" //temporary placeholder for real principal identifier
			logrus.Infof("S: Started process at PID: %v", cmd.Process.Pid)
		}
	} else {
		logrus.Info("S: RECEIVED NOT AN INTENT_REQEST")
	}

	for {
	}

	err = serverChan.Close()
	if err != nil {
		logrus.Errorf("error closing channel: %v", err)
	}

	//infinite loop so the client program doesn't quit
	//otherwise client quits before server can read data
	//TODO: Figure out how to check if the other side closed channel

}
