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

	if os.Args[1] == "sshd" {
		fmt.Println("Hosting ssh server")
		sshd()
	}

	if os.Args[1] == "ssh" {
		fmt.Println("Attempting to connect to client")
		sshClient(os.Args[2])
	}

	if os.Args[1] == "scp" {
		fmt.Println("Copying file over SSH.")
		scp(os.Args[2], os.Args[3])
	}

}
