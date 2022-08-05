package netproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/tubes"
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

// Constants related to netproxy channels
const (
	NpcConf = byte(1)
	NpcDen  = byte(2)
	Local   = byte(2)
	Remote  = byte(3)
	AG      = byte(4)
)

type npcInitMsg struct {
	msgLen uint32
	info   string
}

func newNPCInitMsg(arg string, t byte) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(arg)),
		info:   arg,
	}
}

func (n *npcInitMsg) Addr() string {
	return n.info
}

func (n *npcInitMsg) toBytes() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r[0:], n.msgLen)
	return append(r, []byte(n.info)...)
}

func fromBytes(b []byte) *npcInitMsg {
	return &npcInitMsg{
		msgLen: uint32(len(b)),
		info:   string(b),
	}
}

// Start sends an NPCInitMsg and waits for confirmation that the proxy connection is ready
func Start(npTube *tubes.Reliable, arg string, t byte) error {
	npTube.Write(newNPCInitMsg(arg, t).toBytes()) //tell server to prepare to proxy to addr (start a UDP conn)
	//TODO(baumanl): Make better conf/denial messages for NPC
	//wait until server says it has a UDP conn to desired address
	res := make([]byte, 1)
	_, err := io.ReadFull(npTube, res)
	if err != nil {
		return err
	}
	if res[0] != NpcConf {
		return errors.New("denied")
	}
	logrus.Info("Receieved NPC Conf")
	// exit := make([]byte, 1) //TODO(baumanl): replace this with a better soln that doesn't block
	// _, err = npTube.Read(exit) //wait for server to say if there is a problem
	// if err != nil {
	// 	return err
	// }
	return nil
}

// Server starts a UDP Conn with remote addr and proxies traffic from ch -> udp and upd -> ch
func Server(npTube *tubes.Reliable) {
	b := make([]byte, 4)
	io.ReadFull(npTube, b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	io.ReadFull(npTube, init)
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
	throwaway, _ := net.Dial("udp", dest.info)
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	tconn, err := net.DialUDP("udp", nil, remoteAddr.(*net.UDPAddr))
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	defer tconn.Close()
	logrus.Info("connected to: ", dest.info)
	npTube.Write([]byte{NpcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		buf := make([]byte, 65535)
		for {
			n, _, _, _, e := npTube.ReadMsgUDP(buf, nil)
			if e != nil {
				logrus.Info("Error Reading from tube: ", e)
				npTube.Close()
				break
			}
			_, _, e = tconn.WriteMsgUDP(buf[:n], nil, nil)
			if e != nil {
				logrus.Fatal("Error sending packet: ", e)
			}
		}
	}()
	//handles all traffic from server 2 back to principal
	buf := make([]byte, 65535)
	for {
		n, _, _, _, e := tconn.ReadMsgUDP(buf, nil)
		if e != nil {
			logrus.Errorf("Err reading from UDP: %v", e)
			continue
		}
		_, _, e = npTube.WriteMsgUDP(buf[:n], nil, nil)
		if e != nil {
			logrus.Fatal("Error writing to tube, ", e)
		}
	}
}
