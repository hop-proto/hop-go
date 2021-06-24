// Simple client that connects to a server via a Unix socket and sends
// a message.
//
// Eli Bendersky [http://eli.thegreenplace.net]
// This code is in the public domain.
package main

import (
	"log"
	"net"
	"os"
)

func reader(r net.Conn, finished chan bool, intent string) {
	defer func() {
		finished <- true
	}()
	log.Printf("Connected to server [%s]", r.RemoteAddr().Network())

	//send intent
	r.Write([]byte(intent))

	buf := make([]byte, 1024)
	n, err := r.Read(buf[:])
	if err != nil {
		return
	}
	println("Client got:", string(buf[0:n]))
}

func main() {

	c, err := net.Dial("unix", "../echo.sock")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	ppid := os.Getppid()
	println(ppid)
	finished := make(chan bool)
	go reader(c, finished, "user@server1, action, server2")

	<-finished
}
