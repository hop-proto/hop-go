package main

import (
	"encoding/binary"
	"sync/atomic"
)

func updateAck(ack *uint32, newack uint32) {
	atomic.StoreUint32(ack, newack)
}

func readAck(ack *uint32) uint32 {
	return atomic.LoadUint32(ack)
}

func getCID(frame []byte) int {
	return int(frame[0])
}

func getCtr(frame []byte) uint32 {
	return binary.BigEndian.Uint32([]byte{frame[8],frame[9],frame[10], frame[11]})
}

func getData(frame []byte) []byte {
	datasz := int(binary.BigEndian.Uint32([]byte{0,0,frame[2], frame[3]}))
	return frame[12:12+datasz]
}

func getByte(number uint32, n) {
	return (number >> (8*n)) & 0xff;
}

func toBytes(number uint32) []byte {
	temp := make([]byte, 4)
	binary.BigEndian.PutUint32(temp, number)
	return temp
}

func buildFrame(cid int, flags uint8, cdack uint32, ctr uint32, data []byte) []byte {
	buf := []byte{}
	buf = append(buf, []byte{cid, flags})
	datasz = uint16(len(data))
	buf = append(buf, []byte{getByte(datasz, 1), getByte(datasz, 0)})
	buf = append(buf, toBytes(cdack))
	buf = append(buf, toBytes(ctr))
	buf = append(buf, data)
	return buf
}

func isData(frame []byte) bool {
	return (frame[1] & 0xC0 == 0)
}

func isRep(frame []byte) bool {
	return (frame[1] & 0x40 != 0)
}

func isReq(frame []byte) bool {
	return (frame[1] & 0x80 != 0)
}
