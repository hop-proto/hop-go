package main

import (
	"fmt"
	"os"
)

//go run *.go => run hopclient.go
//go run *.go -hopd => start hop server

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Starting hop client")
		startClient()
	} else if os.Args[1] == "-hopd" {
		fmt.Println("Hosting hop server daemon")
		serve() //start "hop server daemon process"
	}
}
