package main

import (
	"fmt"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Starting hop client")
		startClient()
	} else if os.Args[1] == "-hopd" {
		fmt.Println("Hosting hop server daemon")
		serve() //start "hop server daemon process"
	}
}
