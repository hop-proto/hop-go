package main

import "os"

func main() {
	if os.Args[1] == "client" {
		startClient(os.Args[2])
	} else {
		startServer(os.Args[2])
	}
}
