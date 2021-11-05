//Package app provides functions to run hop client and hop server
package app

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

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
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	transportServer, err := transport.NewServer(udpConn, hconfig.TransportConfig)
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
