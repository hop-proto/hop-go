package tubes

import "encoding/binary"

type frame struct {
	ackNo      uint32
	frameNo    uint32
	dataLength uint16
	flags      frameFlags
	tubeID     byte
	data       []byte
}

type initiateFrame struct {
	frameNo    uint32
	tubeID     byte
	tubeType   TubeType
	data       []byte
	dataLength uint16
	flags      frameFlags
	// The actual window size is this number bitshifted up by 4
	windowSize uint16
}

type frameFlags struct {
	// Flag to initiate a tube.
	REQ bool
	// Flag to accept tube initiation.
	RESP bool
	// Flag is indicate a reliable tube
	REL bool
	// Flag to update the acknowledgement number from the sender of the packet for the receiver of the packet.
	ACK bool
	// Flag to teardown tube.
	FIN bool
}

// The bit index for each of these flags.
const (
	REQIdx  = 0
	RESPIdx = 1
	RELIdx  = 2
	ACKIdx  = 3
	FINIdx  = 4
)

func flagsToMetaByte(p *frameFlags) byte {
	meta := byte(0)
	if p.REQ {
		meta = meta | (1 << REQIdx)
	}
	if p.RESP {
		meta = meta | (1 << RESPIdx)
	}
	if p.REL {
		meta = meta | (1 << RELIdx)
	}
	if p.ACK {
		meta = meta | (1 << ACKIdx)
	}
	if p.FIN {
		meta = meta | (1 << FINIdx)
	}
	return meta
}

func metaToFlags(b byte) frameFlags {
	flags := frameFlags{
		REQ:  b&(1<<REQIdx) != 0,
		RESP: b&(1<<RESPIdx) != 0,
		REL:  b&(1<<RELIdx) != 0,
		ACK:  b&(1<<ACKIdx) != 0,
		FIN:  b&(1<<FINIdx) != 0,
	}
	return flags
}

func (p *initiateFrame) toBytes() []byte {
	frameNumBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNumBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	windowSize := []byte{0, 0}
	binary.BigEndian.PutUint16(windowSize, p.windowSize)
	return append(
		[]byte{
			p.tubeID, flagsToMetaByte(&p.flags),
			dataLength[0], dataLength[1],
			windowSize[0], windowSize[1],
			byte(p.tubeType), byte(0),
			frameNumBytes[0], frameNumBytes[1], frameNumBytes[2], frameNumBytes[3],
		},
		p.data...,
	)
}

func (p *frame) toBytes() []byte {
	frameNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNoBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	ackNoBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ackNoBytes, p.ackNo)
	return append(
		[]byte{
			p.tubeID, flagsToMetaByte(&p.flags), dataLength[0], dataLength[1],
			ackNoBytes[0], ackNoBytes[1], ackNoBytes[2], ackNoBytes[3],
			frameNoBytes[0], frameNoBytes[1], frameNoBytes[2], frameNoBytes[3],
		},
		p.data...,
	)
}

func fromBytes(b []byte) (*frame, error) {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &frame{
		tubeID:     b[0],
		flags:      metaToFlags(b[1]),
		dataLength: dataLength,
		data:       append([]byte(nil), b[12:12+dataLength]...),
		ackNo:      binary.BigEndian.Uint32(b[4:8]),
		frameNo:    binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

func fromInitiateBytes(b []byte) *initiateFrame {
	dataLength := binary.BigEndian.Uint16(b[2:4])
	return &initiateFrame{
		tubeID:     b[0],
		flags:      metaToFlags(b[1]),
		dataLength: dataLength,
		windowSize: binary.BigEndian.Uint16(b[4:6]),
		tubeType:   TubeType(b[6]),
		frameNo:    binary.BigEndian.Uint32(b[8:12]),
		data:       b[12 : 12+dataLength],
	}
}
