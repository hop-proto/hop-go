package channels

import "encoding/binary"

type Packet struct {
	channelID  byte
	meta       byte
	dataLength uint16
	ackNo      uint32
	frameNo    uint32
	data       []byte
}

type InitiatePacket struct {
	channelID   byte
	meta        byte
	dataLength  uint16
	windowSize  uint16
	channelType byte
	frameNo     uint32
	data        []byte
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
			p.channelID, p.meta,
			dataLength[0], dataLength[1],
			windowSize[0], windowSize[1],
			p.channelType, byte(0),
			frameNumBytes[0], frameNumBytes[1], frameNumBytes[2], frameNumBytes[3],
		},
		p.data...,
	)
}

func (p *Packet) toBytes() []byte {
	frameNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNoBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	ackNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ackNoBytes, p.ackNo)
	return append(
		[]byte{
			p.channelID, p.meta, dataLength[0], dataLength[1],
			ackNoBytes[0], ackNoBytes[1], ackNoBytes[2], ackNoBytes[3],
			frameNoBytes[0], frameNoBytes[1], frameNoBytes[2], frameNoBytes[3],
		},
		p.data...,
	)
}

func FromBytes(b []byte) (*Packet, error) {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &Packet{
		b[0], b[1],
		dataLength,
		binary.BigEndian.Uint32(b[4:8]),
		binary.BigEndian.Uint32(b[8:12]),
		b[12 : 12+dataLength],
	}, nil
}

func FromInitiateBytes(b []byte) (*InitiatePacket, error) {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &InitiatePacket{
		b[0], b[1],
		dataLength,
		binary.BigEndian.Uint16(b[4:6]),
		b[7],
		binary.BigEndian.Uint32(b[8:12]),
		b[12 : 12+dataLength],
	}, nil
}
