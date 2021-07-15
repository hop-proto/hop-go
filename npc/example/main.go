package main

import (
	"encoding/binary"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/keys"
	"zmap.io/portal/npc"
	"zmap.io/portal/transport"
)

func main() {
	if os.Args[1] == "client" {
		startClient(os.Args[2])
	} else if os.Args[1] == "server" {
		startServer(os.Args[2])
	}
}

func principalProxy(ch *channels.Reliable) {
	addr := "127.0.0.1:9999"
	pktConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logrus.Fatalf("S: ERROR STARTING UDP CONN: %v", err)
	}
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	logrus.Info("principal proxy got a connection")
	b := make([]byte, 11)
	udpConn.ReadMsgUDP(b, nil)
	logrus.Info("b: ", string(b))
	udpConn.Close()
	// go func() {
	// 	io.Copy(os.Stdout, udpConn)
	// }()
	// io.Copy(udpConn, ch)

}

func startClient(port string) {
	addr := "127.0.0.1:" + port

	//******ESTABLISH HOP SESSION******
	//TODO: figure out addr format requirements + check for them above
	transportConn, err := transport.Dial("udp", addr, nil) //There seem to be limits on Dial() and addr format
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("C: Issue with handshake: %v", err)
	}
	//TODO: should these functions + things from Channels layer have errors?
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()

	//start NPC channel
	ch, e := mc.CreateChannel(channels.NPC_CHANEL)
	if e != nil {
		logrus.Fatalf("C: error making channel: %v", e)
	}
	if port == "1111" {
		logrus.Info("Starting NPC with Server 1 on port 1111")
		npcinit := npc.NewNPCInitMsg("127.0.0.1:2222")
		logrus.Infof("len: %v and addr: %v", npcinit.MsgLen, npcinit.Addr)
		ch.Write(npc.NewNPCInitMsg("127.0.0.1:2222").ToBytes())
		ch.Read(make([]byte, 1))
		logrus.Info("Receieved NPC Conf. Starting principal proxy...")
		go principalProxy(ch)
		transportConn2, err := net.Dial("udp", "127.0.0.1:9999")
		if err != nil {
			logrus.Fatalf("C: error dialing server: %v", err)
		}
		logrus.Info("Dialed Principal proxy")
		transportConn2.Write([]byte("HELLO WORLD"))
		time.Sleep(5 * time.Second)
		transportConn2.Close()
		logrus.Info("Wrote and closed conn to pproxy")
		// err = transportConn2.Handshake() //hanging
		// if err != nil {
		// 	logrus.Fatalf("C: Issue with handshake: %v", err)
		// }
		// logrus.Info("conducted handshake")
		// //TODO: should these functions + things from Channels layer have errors?
		// mc := channels.NewMuxer(transportConn2, transportConn2)
		// go mc.Start()
		// defer mc.Stop()

		// mc.CreateChannel(channels.AGC_CHANNEL)
		// logrus.Info("CREATED AGC")
	}
	for {
	}
}

func startServer(port string) {
	addr := "127.0.0.1:" + port
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

	if port == "1111" {
		logrus.Info("Server 1: Accepting NPC and setting up Proxy to Server 2")
		ch, _ := ms.Accept()

		b := make([]byte, 4)
		ch.Read(b)
		l := binary.BigEndian.Uint32(b[0:4])
		logrus.Infof("Expecting %v bytes", l)
		init := make([]byte, l)
		ch.Read(init)
		dest := npc.FromBytes(init)
		logrus.Infof("trying to dial dest: %v", dest.Addr)
		_, err := net.Dial("udp", dest.Addr)
		if err != nil {
			logrus.Fatalf("C: error dialing server: %v", err)
		}
		logrus.Info("connected to: ", dest.Addr)
		// go func() {
		// 	io.Copy(udpConn, ch)
		// }()
		ch.Write([]byte{npc.NPC_CONF})
		// go func() {
		// 	io.Copy(ch, udpConn)
		// }()

		for {
		}
	}
}

func newTestServerConfig() *transport.ServerConfig {
	keyPair, err := keys.ReadDHKeyFromPEMFile("../../app/testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile("../../app/testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: WRROR WITH CERTS %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile("../../app/testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
	}
	return &transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
}
