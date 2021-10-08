package netproxy

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

//StartRemote sends an NPCInitMsg and waits for confirmation that the proxy connection is ready
func StartRemote(npTube *tubes.Reliable, addr string) error {
	npTube.Write(newNPCInitMsg(addr, Remote).toBytes()) //tell server to prepare to proxy to addr (start a UDP conn)
	//TODO(baumanl): Make better conf/denial messages for NPC
	//wait until server says it has a UDP conn to desired address
	npTube.Read(make([]byte, 1))
	logrus.Info("Receieved NPC Conf")
	return nil
}

//RemoteServer starts listening on given port and pipes the traffic back over the tube
func RemoteServer(npTube *tubes.Reliable) {
	b := make([]byte, 4)
	npTube.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	init := make([]byte, l)
	npTube.Read(init)
	remotePort := fromBytes(init).info
	tcpListener, e := net.Listen("tcp", ":"+remotePort)
	if e != nil {
		logrus.Error("Issue listening on requested port")
		return
	}
	tconn, e := tcpListener.Accept()
	if e != nil {
		logrus.Error("Issue accepting conn on remote port")
		return
	}
	npTube.Write([]byte{npcConf})
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		io.Copy(tconn, npTube)
	}()
	//handles all traffic from server 2 back to principal
	io.Copy(npTube, tconn)
}
