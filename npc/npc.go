package npc

import "encoding/binary"

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
