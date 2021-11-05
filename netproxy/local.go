package netproxy

import (
	"io"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

//LocalServer starts a TCP Conn with remote addr and proxies traffic from ch -> tcp and tcp -> ch
func LocalServer(npTube *tubes.Reliable, arg string) {
	//dest := fromBytes(init)
	//TODO: more flexible parsing of arg
	parts := strings.Split(arg, ":") //assuming port:host:hostport
	addr := net.JoinHostPort(parts[1], parts[2])
	if _, err := net.LookupAddr(addr); err != nil {
		//Couldn't resolve address with local resolver
		h, p, e := net.SplitHostPort(addr)
		if e != nil {
			logrus.Error(e)
			npTube.Write([]byte{NpcDen})
			return
		}
		if ip, ok := hostToIPAddr[h]; ok {
			addr = ip + ":" + p
		}
	}
	logrus.Infof("dialing dest: %v", addr)
	tconn, err := net.Dial("tcp", addr)
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		npTube.Write([]byte{NpcDen})
		return
	}
	defer tconn.Close()
	logrus.Info("connected to: ", arg)
	npTube.Write([]byte{NpcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		io.Copy(tconn, npTube)
	}()
	//handles all traffic from server 2 back to principal
	io.Copy(npTube, tconn)
}
