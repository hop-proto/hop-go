package main

import (
	"log"
	"net"
	"os"
	"os/exec"
)

const SockAddr = "echo.sock"

func authGrantServer(c net.Conn) {
	log.Printf("Client connected [%s]", c.RemoteAddr().Network())

	buf := make([]byte, 1024)
	n, err := c.Read(buf[:])
	if err != nil {
		return
	}
	println("Server got:", string(buf[0:n]))

	//initiate NPC w/ principal and get user response
	approved := true
	if !approved {
		c.Write([]byte("denied"))
	} else {
		c.Write([]byte("approved"))
	}

	//c.Write([]byte("testing"))
	// io.Copy(c, c)
	// //time.Sleep(100 * time.Millisecond)

	c.Close()
}

func main() {

	//cmd := exec.Command("cmd", "/C", "bash") //specific to windows
	//cmd := exec.Command("sleep", "10") //wsl compat
	cmd := exec.Command("go", "run", "./client/ipcclient.go")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	state, es := cmd.Process.Wait()
	if es != nil {
		log.Fatal(es)
	}
	log.Printf("Pid: %v", state.Pid())
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)

	// args := []string{"cmd", "/C", "go", "run", "ipcclient.go"}
	// var attr *os.ProcAttr

	// p, e := os.StartProcess("go", args, attr)
	// if e != nil {
	// 	log.Fatal(e)
	// }
	// p.Release()

	if err := os.RemoveAll(SockAddr); err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("unix", SockAddr)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()

	for {
		// Accept new connections, dispatching them to echoServer
		// in a goroutine.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go authGrantServer(conn)
	}
}
