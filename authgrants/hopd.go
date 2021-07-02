package main

import (
	"fmt"
	"log"
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
		log.Fatalf("error with keypair: %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	if err != nil {
		log.Fatalf("error with certs: %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	if err != nil {
		log.Fatalf("error with intermediate certs: %v", err)
	}
	return &transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
}

func serve() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("STARTING SERVER AT localhost:8888")
	pktConn, err := net.ListenPacket("udp", "localhost:8888")
	if err != nil {
		logrus.Fatalf("error starting udp conn: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig())
	if err != nil {
		log.Fatalf("error starting transport conn: %v", err)
	}
	go server.Serve()

	serverConn, err := server.AcceptTimeout(time.Minute)
	if err != nil {
		log.Fatalf("error starting server conn: %v", err)
	}

	ms := channels.NewMuxer(serverConn, serverConn)
	go ms.Start()

	serverChan, err := ms.Accept()
	if err != nil {
		log.Fatalf("issue accepting channel: %v", err)
	}
	println("started channel")

	testData := "hi i am some data"
	buf := make([]byte, len(testData))

	bytesRead := 0
	n, err := serverChan.Read(buf[bytesRead:])
	if err != nil {
		log.Fatalf("issue reading from channel: %v", err)
	}
	serverChan.Close()
	bytesRead += n
	ms.Stop()
	println("Read: %v", bytesRead)
	if bytesRead == len(testData) {
		fmt.Println("Bytes match")
	}
}
