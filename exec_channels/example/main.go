package main

import "os"

func main() {
	if os.Args[1] == "client" {
		startClient()
	} else {
		startServer()
	}
}
