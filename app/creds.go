//go:build !linux

package app

import (
	"errors"
	"net"
	"syscall"
)

func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return nil
}

func readCreds(c net.Conn) (int32, error) {
	// TODO(dadrian): Implement on Darwin
	return -1, errors.New("readCreds is unimplemented on non-linux platforms")
}
