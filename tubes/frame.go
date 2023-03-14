package tubes

import "encoding/binary"

type frame struct {
	ackNo      uint32
	frameNo    uint32
	dataLength uint16
	flags      byte
	tubeID     byte
	data       []byte
}

type initiateFrame struct {
	frameNo    uint32
	tubeID     byte
	tubeType   TubeType
	data       []byte
	dataLength uint16
	flags      byte
	windowSize uint16
}

// Optional bit flags set on each frame. Set flags by OR'ing them together.
const (
	FlagREQ  = 1
	FlagRESP = 1 << 1
	FlagREL  = 1 << 2
	FlagACK  = 1 << 3
	FlagFIN  = 1 << 4
)

func (p *initiateFrame) toBytes() []byte {
	frameNumBytes := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(frameNumBytes, p.frameNo)
	dataLength := []byte{0, 0}
	binary.BigEndian.PutUint16(dataLength, p.dataLength)
	windowSize := []byte{0, 0}
	binary.BigEndian.PutUint16(windowSize, p.windowSize)
	return append(
		[]byte{
			p.tubeID, p.flags,
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
			p.tubeID, p.flags,
			dataLength[0], dataLength[1],
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
		flags:      b[1],
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
		flags:      b[1],
		dataLength: dataLength,
		windowSize: binary.BigEndian.Uint16(b[4:6]),
		tubeType:   TubeType(b[6]),
		frameNo:    binary.BigEndian.Uint32(b[8:12]),
		data:       b[12 : 12+dataLength],
	}
}

func (p *initiateFrame) hasFlags(flags byte) bool {
	return p.flags&flags == flags
}

func (p *frame) hasFlags(flags byte) bool {
	return p.flags&flags == flags
}
