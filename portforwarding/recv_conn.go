package portforwarding

// modified lightly from https://github.com/ftrvxmtrx/fd

import (
	"net"
	"os"
	"syscall"
)

// Get receives file descriptors from a Unix domain socket.
//
// Num specifies the expected number of file descriptors in one message.
// Internal files' names to be assigned are specified via optional filenames
// argument.
//
// You need to close all files in the returned slice. The slice can be
// non-empty even if this function returns an error.
//
// Use net.FileConn() if you're receiving a network connection.
func Get(via *net.UnixConn, num int, filenames []string) ([]*os.File, error) {
	if num < 1 {
		return nil, nil
	}

	// get the underlying socket
	viaf, err := via.File()
	if err != nil {
		return nil, err
	}
	socket := int(viaf.Fd())
	defer viaf.Close()

	// recvmsg
	buf := make([]byte, syscall.CmsgSpace(num*4))
	_, _, _, _, err = syscall.Recvmsg(socket, nil, buf, 0)
	if err != nil {
		return nil, err
	}

	// parse control msgs
	var msgs []syscall.SocketControlMessage
	msgs, err = syscall.ParseSocketControlMessage(buf)

	// convert fds to files
	res := make([]*os.File, 0, len(msgs))
	for i := 0; i < len(msgs) && err == nil; i++ {
		var fds []int
		fds, err = syscall.ParseUnixRights(&msgs[i])

		for fi, fd := range fds {
			var filename string
			if fi < len(filenames) {
				filename = filenames[fi]
			}

			res = append(res, os.NewFile(uintptr(fd), filename))
		}
	}

	return res, err
}
