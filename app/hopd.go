//Package app provides functions to run hop client and hop server
package app

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

const maxOutstandingAuthgrants = 50 //TODO(baumanl): calibrate/allow being set from config file

//AuthGrant contains deadline, user, action
type authGrant struct {
	deadline         time.Time
	user             string
	arg              string
	principalSession *hopSession
	used             bool
	grantType        byte
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
	serverConfig, _ := newTestServerConfig() //TEMPORARY
	transportServer, err := transport.NewServer(udpConn, serverConfig)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING TRANSPORT CONN: %v", err)
	}
	go transportServer.Serve()

	//*****AUTHGRANT SERVER ON UNIX DOMAIN SOCKET SET UP*****
	principals := make(map[int32]*hopSession)           //PID -> principal hop session
	authgrants := make(map[keys.PublicKey][]*authGrant) //static key -> authgrant

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
