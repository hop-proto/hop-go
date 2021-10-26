package netproxy

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

//LocalServer starts a TCP Conn with remote addr and proxies traffic from ch -> tcp and tcp -> ch
func LocalServer(npTube *tubes.Reliable, dest string) {
	//dest := fromBytes(init)
	if _, err := net.LookupAddr(dest); err != nil {
		//Couldn't resolve address with local resolver
		h, p, e := net.SplitHostPort(dest)
		if e != nil {
			logrus.Error(e)
			npTube.Write([]byte{NpcDen})
			return
		}
		if ip, ok := hostToIPAddr[h]; ok {
			dest = ip + ":" + p
		}
	}
	logrus.Infof("dialing dest: %v", dest)
	tconn, err := net.Dial("tcp", dest)
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		npTube.Write([]byte{NpcDen})
		return
	}
	defer tconn.Close()
	logrus.Info("connected to: ", dest)
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
