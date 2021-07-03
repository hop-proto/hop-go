package main

import (
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

func newTestServerConfig() *transport.ServerConfig {
	keyPair, err := keys.ReadDHKeyFromPEMFile("./testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("error with keypair: %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("error with certs: %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("error with intermediate certs: %v", err)
	}
	return &transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
}

func serve() {
	logrus.SetLevel(logrus.InfoLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8888")
	if err != nil {
		logrus.Fatalf("error starting udp conn: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig())
	if err != nil {
		logrus.Fatalf("error starting transport conn: %v", err)
	}
	go server.Serve()

	//TODO: make this a loop so it can handle multiple client conns
	logrus.Info("SERVER LISTENING ON PORT 8888")
	serverConn, err := server.AcceptTimeout(time.Minute) //won't be a minute in reality
	if err != nil {
		logrus.Fatalf("SERVER TIMEOUT: %v", err)
	}
	logrus.Info("ACCEPTED NEW CONNECTION")
	ms := channels.NewMuxer(serverConn, serverConn)
	go ms.Start()
	defer ms.Stop()
	logrus.Info("STARTED CHANNEL MUXER")

	serverChan, err := ms.Accept()
	if err != nil {
		logrus.Fatalf("issue accepting channel: %v", err)
	}

	testData := "hi i am some data"
	buf := make([]byte, len(testData))

	bytesRead := 0
	n, err := serverChan.Read(buf[bytesRead:])
	if err != nil {
		logrus.Fatalf("issue reading from channel: %v", err)
	}
	bytesRead += n
	println("Read: %v", bytesRead)
	if bytesRead == len(testData) {
		fmt.Println("Bytes match")
	}
	err = serverChan.Close()
	if err != nil {
		fmt.Printf("error closing channel: %v", err)
	}
}
