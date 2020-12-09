package main

import (
	"encoding/binary"
	"sync/atomic"
)

func updateCtr(ctr *uint32, newctr uint32) {
	atomic.StoreUint32(ctr, newctr)
}

func readCtr(ctr *uint32) uint32 {
	return atomic.LoadUint32(ctr)
}

func getCID(frame []byte) int {
	return int(frame[0])
}

func getCtr(frame []byte) uint32 {
	return binary.BigEndian.Uint32([]byte{frame[8],frame[9],frame[10], frame[11]})
}

func getAck(frame []byte) uint32 {
	return binary.BigEndian.Uint32([]byte{frame[4],frame[5],frame[6], frame[7]})
}

func getData(frame []byte) []byte {
	datasz := int(binary.BigEndian.Uint32([]byte{0,0,frame[2], frame[3]}))
	return frame[12:12+datasz]
}

func getDataSz(frame []byte) int {
	return int(binary.BigEndian.Uint32([]byte{0,0,frame[2], frame[3]}))
}

func getByte(number uint32, n int) byte {
	return byte((number >> (8*n)) & 0xff);
}

func toBytes(number uint32) []byte {
	temp := make([]byte, 4)
	binary.BigEndian.PutUint32(temp, number)
	return temp
}

func buildFrame(cid int, flags uint8, cdack uint32, ctr uint32, data []byte) []byte {
	buf := make([]byte, 0)
	buf = append(buf, []byte{byte(cid), byte(flags)}...)
	datasz := uint32(len(data))
	buf = append(buf, []byte{getByte(datasz, 1), getByte(datasz, 0)}...)
	buf = append(buf, toBytes(cdack)...)
	buf = append(buf, toBytes(ctr)...)
	buf = append(buf, data...)
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
