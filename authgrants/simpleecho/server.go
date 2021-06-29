//Taken from: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/
//Shows simplest use of UDS
package main

import (
	"log"
	"net"
	"os"
)

const sockAddr = "/tmp/echo.sock"

func main() {
	// Make sure no stale sockets present
	os.Remove(sockAddr)

	// Create new Unix domain socket
	server, err := net.Listen("unix", sockAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	// Loop to process client connections
	for {
		client, err := server.Accept()
		if err != nil {
			log.Printf("Accept() failed: %s", err)
			continue
		}

		go handleConn(client)
	}
}
