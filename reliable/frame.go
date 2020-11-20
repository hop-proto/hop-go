package main

func getCID(frame []byte) int {
	return int(frame[0])
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
