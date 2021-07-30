package main

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

//Intuition and some code adopted from:
//https://dev.to/napicella/linux-terminals-tty-pty-and-shell-part-2-2cb2
//https://gist.github.com/napicella/777e83c0ef5b77bf72c0a5d5da9a4b4e

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

func startServer(p string) {
	addr := "localhost:" + p
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

	ch, err := ms.Accept()
	if err != nil {
		logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
	}
	//exec_channels.Serve(ch)
	defer ch.Close()
	logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", ch.Type())

	cmd, _ := codex.GetCmd(ch)
	logrus.Infof("Executing: %v", string(cmd))

	args := strings.Split(string(cmd), " ")
	c := exec.Command(args[0], args[1:]...)

	f, err := pty.Start(c)
	if err != nil {
		logrus.Fatalf("S: error starting pty %v", err)
	}

	defer func() { _ = f.Close() }() // Best effort.

	// Handle pty size.
	ch2 := make(chan os.Signal, 1)
	signal.Notify(ch2, syscall.SIGWINCH)
	go func() {
		for range ch2 {
			if err := pty.InheritSize(os.Stdin, f); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch2 <- syscall.SIGWINCH                         // Initial resize.
	defer func() { signal.Stop(ch2); close(ch2) }() // Cleanup signals when done.

	go func() {
		io.Copy(f, ch)
		logrus.Info("Stopped io.Copy(f, ch)")
	}()

	io.Copy(ch, f)
	logrus.Info("Stopped io.Copy(ch, f)")
}
