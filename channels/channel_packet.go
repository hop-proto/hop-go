package channels

import "encoding/binary"

type Frame struct {
	ackNo      uint32
	channelID  byte
	data       []byte
	dataLength uint16
	flags      PacketFlags
	frameNo    uint32
}

type InitiatePacket struct {
	channelID   byte
	channelType byte
	data        []byte
	dataLength  uint16
	flags       PacketFlags
	frameNo     uint32
	windowSize  uint16
}

type PacketFlags struct {
	// Flag to update the acknowledgement number from the sender of the packet for the receiver of the packet.
	ACK bool
	// Flag to teardown channel.
	FIN bool
	// Flag to initiate a channel.
	REQ bool
	// Flag to accept channel initiation.
	RESP bool
}

// The bit index for each of these flags.
const (
	ACKIdx  = 0
	FINIdx  = 1
	REQIdx  = 2
	RESPIdx = 3
)

func flagsToMetaByte(p *PacketFlags) byte {
	meta := byte(0)
	if p.ACK {
		meta = meta | (1 << ACKIdx)
	}
	if p.FIN {
		meta = meta | (1 << FINIdx)
	}
	if p.REQ {
		meta = meta | (1 << REQIdx)
	}
	if p.RESP {
		meta = meta | (1 << RESPIdx)
	}
	return meta
}

func metaToFlags(b byte) PacketFlags {
	flags := PacketFlags{
		ACK:  b&(1<<ACKIdx) != 0,
		FIN:  b&(1<<FINIdx) != 0,
		REQ:  b&(1<<REQIdx) != 0,
		RESP: b&(1<<RESPIdx) != 0,
	}
	return flags
}

func (p *InitiatePacket) toBytes() []byte {
	frameNumBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNumBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	windowSize := []byte{0, 0}
	binary.BigEndian.PutUint16(windowSize, p.windowSize)
	return append(
		[]byte{
			p.channelID, flagsToMetaByte(&p.flags),
			dataLength[0], dataLength[1],
			windowSize[0], windowSize[1],
			p.channelType, byte(0),
			frameNumBytes[0], frameNumBytes[1], frameNumBytes[2], frameNumBytes[3],
		},
		p.data...,
	)
}

func (p *Frame) toBytes() []byte {
	frameNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNoBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	ackNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ackNoBytes, p.ackNo)
	return append(
		[]byte{
			p.channelID, flagsToMetaByte(&p.flags), dataLength[0], dataLength[1],
			ackNoBytes[0], ackNoBytes[1], ackNoBytes[2], ackNoBytes[3],
			frameNoBytes[0], frameNoBytes[1], frameNoBytes[2], frameNoBytes[3],
		},
		p.data...,
	)
}

func FromBytes(b []byte) (*Frame, error) {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &Frame{
		channelID:  b[0],
		flags:      metaToFlags(b[1]),
		dataLength: dataLength,
		data:       b[12 : 12+dataLength],
		ackNo:      binary.BigEndian.Uint32(b[4:8]),
		frameNo:    binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

func FromInitiateBytes(b []byte) (*InitiatePacket, error) {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &InitiatePacket{
		channelID:   b[0],
		flags:       metaToFlags(b[1]),
		dataLength:  dataLength,
		windowSize:  binary.BigEndian.Uint16(b[4:6]),
		channelType: b[6],
		frameNo:     binary.BigEndian.Uint32(b[8:12]),
		data:        b[12 : 12+dataLength],
	}, nil
}
