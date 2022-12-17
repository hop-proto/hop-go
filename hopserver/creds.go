//go:build !linux && !darwin

package hopserver

import (
	"errors"
	"net"
	"syscall"
)

func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return nil
}

func readCreds(c net.Conn) (int32, error) {
	return -1, errors.New("readCreds is unimplemented on this platform")
}

func getAncestor(pids []int32, cPID int32) (int32, error) {
	return -1, errors.New("getAncestor is unimplemented on this platform")
}
