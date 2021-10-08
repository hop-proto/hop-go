package netproxy

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

//StartLocal sends an NPCInitMsg and waits for confirmation that the proxy connection is ready
func StartLocal(npTube *tubes.Reliable, addr string) error {
	npTube.Write(newNPCInitMsg(addr, Local).toBytes()) //tell server to prepare to proxy to addr (start a UDP conn)
	//TODO(baumanl): Make better conf/denial messages for NPC
	//wait until server says it has a UDP conn to desired address
	npTube.Read(make([]byte, 1))
	logrus.Info("Receieved NPC Conf")
	return nil
}

//LocalServer starts a TCP Conn with remote addr and proxies traffic from ch -> tcp and tcp -> ch
func LocalServer(npTube *tubes.Reliable) {
	b := make([]byte, 4)
	npTube.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	npTube.Read(init)
	dest := fromBytes(init)
	if _, err := net.LookupAddr(dest.info); err != nil {
		//Couldn't resolve address with local resolver
		h, p, e := net.SplitHostPort(dest.info)
		if e != nil {
			logrus.Error(e)
			return
		}
		if ip, ok := hostToIPAddr[h]; ok {
			dest.info = ip + ":" + p
		}
	}
	logrus.Infof("dialing dest: %v", dest.info)
	tconn, err := net.Dial("tcp", dest.info)
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	defer tconn.Close()
	logrus.Info("connected to: ", dest.info)
	npTube.Write([]byte{npcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		io.Copy(tconn, npTube)
	}()
	//handles all traffic from server 2 back to principal
	io.Copy(npTube, tconn)
}
