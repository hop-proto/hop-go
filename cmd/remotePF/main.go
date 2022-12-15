package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"syscall"
)

// modified lightly from https://github.com/ftrvxmtrx/fd
// Put sends file descriptors to Unix domain socket.
//
// Please note that the number of descriptors in one message is limited
// and is rather small.
// Use conn.File() to get a file if you want to put a network connection.
func Put(via *net.UnixConn, files ...*os.File) error {
	if len(files) == 0 {
		return nil
	}

	viaf, err := via.File()
	if err != nil {
		return err
	}
	socket := int(viaf.Fd())
	// defer viaf.Close()

	fds := make([]int, len(files))
	for i := range files {
		fds[i] = int(files[i].Fd())
	}

	rights := syscall.UnixRights(fds...)
	return syscall.Sendmsg(socket, nil, rights, nil, 0)
}

func PutFD(via *net.UnixConn, fds []int) error {
	if len(fds) == 0 {
		return nil
	}

	viaf, err := via.File()
	if err != nil {
		return err
	}
	socket := int(viaf.Fd())
	defer viaf.Close()

	rights := syscall.UnixRights(fds...)
	return syscall.Sendmsg(socket, nil, rights, nil, 0)
}

func main() {
	// TODO(drebelsky): better error handling
	conno, err := net.Dial("unix", "/tmp/sock")
	if err != nil {
		panic(err)
	}
	conn := conno.(*net.UnixConn)
	for {
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			panic(err)
		}
		b := make([]byte, length)
		_, err = io.ReadFull(conn, b)
		if err != nil {
			panic(err)
		}
		netType := string(b)
		err = binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			panic(err)
		}
		b2 := make([]byte, length)
		_, err = io.ReadFull(conn, b2)
		if err != nil {
			panic(err)
		}
		addr := string(b2)
		ln, err := net.Listen(netType, addr)
		if err != nil {
			panic(err)
		}
		switch server := ln.(type) {
		case *net.TCPListener:
			file, err := server.File()
			if err != nil {
				panic(err)
			}
			Put(conn, file)
			file.Close()
		case *net.UnixListener:
			file, err := server.File()
			if err != nil {
				panic(err)
			}
			Put(conn, file)
			file.Close()
		default:
			panic("Bad type")
		}
		ln.Close()
	}
}
