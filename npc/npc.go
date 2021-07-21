package npc

import (
	"encoding/binary"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
)

const NPC_CONF = byte(1)

type npcInitMsg struct {
	MsgLen uint32
	Addr   string
}

func NewNPCInitMsg(address string) *npcInitMsg {
	return &npcInitMsg{
		MsgLen: uint32(len(address)),
		Addr:   address,
	}
}

func (n *npcInitMsg) ToBytes() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r, n.MsgLen)
	return append(r, []byte(n.Addr)...)
}

func FromBytes(b []byte) *npcInitMsg {
	return &npcInitMsg{
		MsgLen: uint32(len(b)),
		Addr:   string(b),
	}
}

func Server(npch *channels.Reliable) {
	b := make([]byte, 4)
	npch.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	npch.Read(init)
	dest := FromBytes(init)
	logrus.Infof("dialing dest: %v", dest.Addr)
	throwaway, _ := net.Dial("udp", dest.Addr)
	localAddr := throwaway.LocalAddr()
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	tconn, err := net.DialUDP("udp", localAddr.(*net.UDPAddr), remoteAddr.(*net.UDPAddr))
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	logrus.Info("connected to: ", dest.Addr)
	npch.Write([]byte{NPC_CONF})
	logrus.Infof("wrote confirmation that NPC ready")
	go func() {
		for {
			buf := make([]byte, 65500)
			n, _, _, _, e := npch.ReadMsgUDP(buf, nil)
			if e != nil {
				logrus.Fatal("Error Reading from Channel: ", e)
			}
			logrus.Debugf("Read: ", n, " bytes from channel")
			n, _, e = tconn.WriteMsgUDP(buf[:n], nil, nil)
			if e != nil {
				logrus.Fatal("Error sending packet: ", e)
			}
			logrus.Debugf("Wrote %v bytes to UDP", n)
		}
	}()
	for {
		buf := make([]byte, 65500)
		n, _, _, _, e := tconn.ReadMsgUDP(buf, nil)
		if e != nil {
			logrus.Fatal("Err reading from UDP: ", e)
		}
		logrus.Debugf("Read: ", n, " bytes from UDP Conn")
		n, _, e = npch.WriteMsgUDP(buf[:n], nil, nil)
		if e != nil {
			logrus.Fatal("Error writing to channel, ", e)
		}
		logrus.Debugf("Wrote %v bytes to channel.", n)
	}
}
