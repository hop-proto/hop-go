//Simple example to work with code execution channels and trying to work with redirecting user input appropriately
package main

import "os"

//Start server: go run *.go server <port>
//Start client: go run *.go client <port>

func main() {
	if os.Args[1] == "client" {
		startClient(os.Args[2])
	} else {
		startServer(os.Args[2])
	}
}
