package npc

import "encoding/binary"

const NPC_INIT = byte(1)

type npcMsg struct {
	msgType byte
	msgLen  uint32
	d       Data
}

type Data interface {
	toBytes() []byte
}

type npcInitMsg struct {
	server string
	port   string
}

func NewNPCInitMsg(s string, p string) *npcMsg {
	return &npcMsg{
		msgType: NPC_INIT,
		msgLen:  1 + uint32(len(s)+len(p)),
		d: &npcInitMsg{
			server: s,
			port:   p,
		},
	}
}

func (n *npcInitMsg) toBytes() []byte {
	return append([]byte(n.server), append([]byte(" "), []byte(n.port)...)...)
}

func (n *npcMsg) ToBytes() []byte {
	r := make([]byte, 5+n.msgLen)
	r[0] = n.msgType
	binary.BigEndian.PutUint32(r[1:5], n.msgLen)
	copy(r[5:], n.d.toBytes())
	return r
}
