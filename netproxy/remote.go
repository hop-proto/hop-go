package netproxy

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

//RemoteServer starts listening on given port and pipes the traffic back over the tube
func RemoteServer(npTube *tubes.Reliable) {
	b := make([]byte, 4)
	npTube.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	init := make([]byte, l)
	npTube.Read(init)
	remotePort := fromBytes(init).info
	tcpListener, e := net.Listen("tcp", ":"+remotePort) //TODO(baumanl): this runs with root privileges which is bad because unprivileged users can forward privileged ports on the server
	if e != nil {
		logrus.Error("Issue listening on requested port")
		npTube.Write([]byte{npcDen})
		return
	}
	tconn, e := tcpListener.Accept() //TODO(baumanl): should this be in a loop? how does SSH do it?
	if e != nil {
		logrus.Error("Issue accepting conn on remote port")
		npTube.Write([]byte{npcDen})
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
