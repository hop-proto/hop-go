package ports

import (
	"net"
	"strconv"
	"sync"
)

var Mutex = sync.Mutex{}
var PortMutex = sync.Mutex{}

//go tests run in parallel so each one needs to be on different ports
//var LastPort = 17000

//true --> port open, false --> port closed
func checkPort(port string) bool {
	conn, err := net.Listen("tcp", net.JoinHostPort("localhost", port))
	if conn != nil {
		conn.Close()
	}
	return err == nil
}

//GetPortNumber finds the next local port number that is free to be listened on
func GetPortNumber(start int) (string, int) {
	for !checkPort(strconv.Itoa(start)) {
		start++
	}
	return strconv.Itoa(start), start + 1
}
