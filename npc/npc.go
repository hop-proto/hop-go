//Package npc provides utilities for network proxy channels
package npc

import (
	"encoding/binary"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
)

const NPC_CONF = byte(1)

type npcInitMsg struct {
	msgLen uint32
	addr   string
}

func NewNPCInitMsg(address string) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(address)),
		addr:   address,
	}
}

func (n *npcInitMsg) ToBytes() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r, n.msgLen)
	return append(r, []byte(n.addr)...)
}

func FromBytes(b []byte) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(b)),
		addr:   string(b),
	}
}

//Starts UDP Conn with remote addr and proxies traffic from ch -> udp and upd -> ch
func Server(npch *channels.Reliable) {
	b := make([]byte, 4)
	npch.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	npch.Read(init)
	dest := FromBytes(init)
	logrus.Infof("dialing dest: %v", dest.addr)
	throwaway, _ := net.Dial("udp", dest.addr)
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	tconn, err := net.DialUDP("udp", nil, remoteAddr.(*net.UDPAddr))
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	logrus.Info("connected to: ", dest.addr)
	npch.Write([]byte{NPC_CONF})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		for {
			buf := make([]byte, 65500)
			n, _, _, _, e := npch.ReadMsgUDP(buf, nil)
			if e != nil {
				logrus.Fatal("Error Reading from Channel: ", e)
			}
			//logrus.Infof("Read: %v bytes from channel", n)
			//logrus.Infof("buf[:n] -> %v", buf[:n])
			n, _, e = tconn.WriteMsgUDP(buf[:n], nil, nil)
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
			logrus.Errorf("Err reading from UDP: ", e)
			continue

		}
		//logrus.Infof("Read: %v bytes from UDP Conn", n)
		//logrus.Infof("buf[:n] -> %v", buf[:n])
		n, _, e = npch.WriteMsgUDP(buf[:n], nil, nil)
		if e != nil {
			logrus.Fatal("Error writing to channel, ", e)
		}
		//logrus.Infof("Wrote %v bytes to channel.", n)
	}
}
