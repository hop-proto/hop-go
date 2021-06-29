//Taken from: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/
//Shows simplest use of UDS

package main

import (
	"bufio"
	"net"
)

func handleConn(c net.Conn) {
	b := bufio.NewReader(c)
	for {
		line, err := b.ReadBytes('\n')
		if err != nil {
			break
		}
		c.Write([]byte("> "))
		c.Write(line)
	}

	c.Close()
}
