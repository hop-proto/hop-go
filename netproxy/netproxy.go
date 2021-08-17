//Package npc provides utilities for network proxy tubes
package netproxy

import (
	"encoding/binary"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

const npcConf = byte(1)

type npcInitMsg struct {
	msgLen uint32
	addr   string
}

func newNPCInitMsg(address string) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(address)),
		addr:   address,
	}
}

func (n *npcInitMsg) Addr() string {
	return n.addr
}

func (n *npcInitMsg) toBytes() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r, n.msgLen)
	return append(r, []byte(n.addr)...)
}

func fromBytes(b []byte) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(b)),
		addr:   string(b),
	}
}

//Start sends an NPCInitMsg and waits for confirmation that the proxy connection is ready
func Start(npTube *tubes.Reliable, addr string) error {
	npTube.Write(newNPCInitMsg(addr).toBytes()) //tell server to prepare to proxy to addr (start a UDP conn)
	//TODO(baumanl): Make better conf/denial messages for NPC
	//wait until server says it has a UDP conn to desired address
	npTube.Read(make([]byte, 1))
	logrus.Info("Receieved NPC Conf")
	return nil
}

//Server starts a UDP Conn with remote addr and proxies traffic from ch -> udp and upd -> ch
func Server(npTube *tubes.Reliable) {
	b := make([]byte, 4)
	npTube.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	npTube.Read(init)
	dest := fromBytes(init)
	logrus.Infof("dialing dest: %v", dest.addr)
	throwaway, _ := net.Dial("udp", dest.addr)
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	tconn, err := net.DialUDP("udp", nil, remoteAddr.(*net.UDPAddr))
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	defer tconn.Close()
	logrus.Info("connected to: ", dest.addr)
	npTube.Write([]byte{npcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		for {
			buf := make([]byte, 65500)
			n, _, _, _, e := npTube.ReadMsgUDP(buf, nil)
			if e != nil {
				logrus.Info("Error Reading from tube: ", e)
				npTube.Close()
				break
			}
			//logrus.Infof("Read: %v bytes from tube", n)
			//logrus.Infof("buf[:n] -> %v", buf[:n])
			_, _, e = tconn.WriteMsgUDP(buf[:n], nil, nil)
			if e != nil {
				logrus.Fatal("Error sending packet: ", e)
			}
			//logrus.Infof("Wrote %v bytes to UDP", n)
		}
	}()
	//handles all traffic from server 2 back to principal
	for {
		buf := make([]byte, 65500)
		n, _, _, _, e := tconn.ReadMsgUDP(buf, nil)
		if e != nil {
			logrus.Errorf("Err reading from UDP: %v", e)
			continue

		}
		//logrus.Infof("Read: %v bytes from UDP Conn", n)
		//logrus.Infof("buf[:n] -> %v", buf[:n])
		_, _, e = npTube.WriteMsgUDP(buf[:n], nil, nil)
		if e != nil {
			logrus.Fatal("Error writing to tube, ", e)
		}
		//logrus.Infof("Wrote %v bytes to tube.", n)
	}
}
