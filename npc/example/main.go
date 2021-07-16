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
	//logrus.SetLevel(logrus.DebugLevel)
	if os.Args[1] == "client" {
		startClient(os.Args[2])
	} else if os.Args[1] == "server" {
		startServer(os.Args[2])
	}
}

func startClient(port string) {
	//logrus.SetLevel(logrus.DebugLevel)
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
	// ch.Write([]byte("Hello World"))
	// ch.Close()
	if port == "1111" {
		logrus.Info("Starting NPC with Server 1 on port 1111")
		npcinit := npc.NewNPCInitMsg("127.0.0.1:2222")
		logrus.Infof("len: %v and addr: %v", npcinit.MsgLen, npcinit.Addr)
		ch.Write(npc.NewNPCInitMsg("127.0.0.1:2222").ToBytes())
		ch.Read(make([]byte, 1))
		logrus.Info("Receieved NPC Conf")
		tclient, _ := transport.DialNPC("npc", "127.0.0.1:2222", ch)
		//logrus.SetLevel(logrus.DebugLevel)
		e := tclient.Handshake()
		if e != nil {
			logrus.Fatal("Handshake failed: ", e)
		}
		logrus.Info("handshake successful")
		// //TODO: should these functions + things from Channels layer have errors?
		// mc := channels.NewMuxer(transportConn2, transportConn2)
		// go mc.Start()
		// defer mc.Stop()

		// mc.CreateChannel(channels.AGC_CHANNEL)
		// logrus.Info("CREATED AGC")
	}
	for {
	}
	ch.Close()
}

func startServer(port string) {
	//logrus.SetLevel(logrus.DebugLevel)
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
	// ch, _ := ms.Accept()
	// b := make([]byte, 11)
	// ch.Read(b)
	// logrus.Infof("GOT: %v", string(b))
	// ch.Close()

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
		logrus.Infof("actually dialing dest: %v", dest.Addr)
		//tconn, err := transport.Dial("udp", dest.Addr, nil)
		throwaway, _ := net.Dial("udp", dest.Addr)
		localAddr := throwaway.LocalAddr()
		remoteAddr := throwaway.RemoteAddr()
		throwaway.Close()
		tconn, err := net.DialUDP("udp", localAddr.(*net.UDPAddr), remoteAddr.(*net.UDPAddr))
		if err != nil {
			logrus.Fatalf("C: error dialing server: %v", err)
		}
		logrus.Info("connected to: ", dest.Addr)
		ch.Write([]byte{npc.NPC_CONF})
		logrus.Infof("wrote confirmation that NPC ready")
		go func() {
			for {
				buf := make([]byte, 65500)
				n, _, _, _, _ := ch.ReadMsgUDP(buf, nil)
				logrus.Info("Read: ", n, " bytes from channel")
				n, _, e := tconn.WriteMsgUDP(buf[:n], nil, nil)
				if e != nil {
					logrus.Fatal("Error sending packet: ", e)
				}
				logrus.Infof("Wrote %v bytes to UDP", n)
			}
		}()
		for {
			buf := make([]byte, 65500)
			n, _, _, _, e := tconn.ReadMsgUDP(buf, nil)
			if e != nil {
				logrus.Fatal("Err reading from UDP: ", e)
			}
			logrus.Info("Read: ", n, " bytes from UDP Conn")
			n, _, e = ch.WriteMsgUDP(buf[:n], nil, nil)
			if e != nil {
				logrus.Fatal("Error writing to channel, ", e)
			}
			logrus.Infof("Wrote %v bytes to channel.", n)
		}

		for {
		}
	}
	for {
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
