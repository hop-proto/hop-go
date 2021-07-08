package main

import (
	"fmt"
	"os"
)

func main() {
	/*
		TODO (drew): parse args to include:
			- host, user, and port
			- identity file
			- tunneling
	*/

	fmt.Println("This is where the SSH replacement CLI will be implemented")
	if os.Args[1] == "sshd" {
		fmt.Println("Hosting ssh server")
		sshd()
	}

	if os.Args[1] == "ssh" {
		fmt.Println("Attempting to connect to client")
		sshClient()
	}

}
