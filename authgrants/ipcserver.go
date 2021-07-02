/*ipcserver replicates the hop server daemon.
It waits for connections from hop client,
and pretends to do auth grant with principal*/

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/sbinet/pstree"
	"golang.org/x/sys/unix"
)

//prints out information of a pstree
func display(pid int, tree *pstree.Tree, indent int) {
	str := strings.Repeat("  ", indent)
	for _, cid := range tree.Procs[pid].Children {
		proc := tree.Procs[cid]
		fmt.Printf("%s%#v\n", str, proc)
		display(cid, tree, indent+1)
	}
}

//checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		log.Printf("Checking [%v]", child)
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

func authGrantServer(c net.Conn, principals *map[int32]string) {
	defer c.Close()
	//Verify that the client is a legit descendent
	creds, err := readCreds(c)
	if err != nil {
		log.Printf("Error reading credentials: %s", err)
		return
	}

	//PID of client process that connected to socket
	cPID := creds.Pid

	//ancestor represents the PID of the ancestor of the client and child of server daemon
	var ancestor int32 = -1

	//get a picture of the entire system process tree
	tree, err := pstree.New()
	//display(os.Getppid(), tree, 1) //displays all pstree for ipcserver
	if err != nil {
		log.Printf("Error making pstree: %s", err)
		return
	}

	//check all of the PIDs of processes that the server started
	for k := range *principals {
		log.Printf("Checking [%v]", k)
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			log.Printf("Legit descendent!")
			ancestor = k
			break
		}
	}
	if ancestor == -1 {
		log.Printf("Not a legitimate descendent. [%v]", ancestor)
		return
	}
	//Right now only checks for direct descendents
	// + find corresponding principal
	principal, _ := (*principals)[ancestor]

	log.Printf("Client connected [%s]", c.RemoteAddr().Network())

	buf := make([]byte, 1024)
	n, err := c.Read(buf[:])
	if err != nil {
		return
	}
	log.Printf("Server got: %v", string(buf[0:n]))

	//initiate NPC w/ principal and get user response
	//TODO: make this actually work
	log.Printf("Initiating AGC w/ %v", principal)
	approved := true
	if !approved {
		c.Write([]byte("denied"))
	} else {
		c.Write([]byte("approved"))
	}
}

//SockAddr := net.UnixAddr{"unix", "echo.sock"}
const SockAddr = "echo.sock"

//Callback function that sets the appropriate socket options
func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PASSCRED,
			1)
	})
}

//Src: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/src/peercred/cred.go
//Parses the credentials sent by the client when it connects to the socket
func readCreds(c net.Conn) (*unix.Ucred, error) {
	var cred *unix.Ucred

	//should only have *net.UnixConn types
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error opening raw connection: %s", err)
	}

	// The raw.Control() callback does not return an error directly.
	// In order to capture errors, we wrap already defined variable
	// 'err' within the closure. 'err2' is then the error returned
	// by Control() itself.
	err2 := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED)
	})

	if err != nil {
		return nil, fmt.Errorf("GetsockoptUcred() error: %s", err)
	}

	if err2 != nil {
		return nil, fmt.Errorf("Control() error: %s", err2)
	}

	return cred, nil
}

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

func serve() {
	//set up UDS for principal (temp soln) would actually be over a network conn
	// Make sure no stale sockets present
	const server1 = "/tmp/server1.sock"
	os.Remove(server1)

	// Create new Unix domain socket
	server, err := net.Listen("unix", server1)
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
		//break
	}

	// //make sure the socket does not already exist.
	// if err := os.RemoveAll(SockAddr); err != nil {
	// 	log.Fatal(err)
	// }

	// //set socket options and start listening to socket
	// config := &net.ListenConfig{Control: setListenerOptions}
	// l, err := config.Listen(context.Background(), "unix", SockAddr)
	// if err != nil {
	// 	log.Fatal("listen error:", err)
	// }
	// defer l.Close()

	// principals := make(map[int32]string) //PID -> "principal" (what should actually rep principal?)

	// // //Spawn some children processes that will act as clients
	// // cmd := exec.Command("go", "run", "client/ipcclient.go") //need to pass a secret when it is spawned?
	// // err = cmd.Start()
	// // if err != nil {
	// // 	log.Printf("Started w/ err: %v", err)
	// // } else {
	// // 	principals[int32(cmd.Process.Pid)] = "principal1" //temporary placeholder for real principal identifier
	// // 	log.Printf("Started process at PID: %v", cmd.Process.Pid)
	// // }

	// log.Printf("Listening at [%v]", SockAddr)
	// for {
	// 	// Accept new connections, dispatching them to echoServer
	// 	// in a goroutine.
	// 	conn, err := l.Accept()
	// 	if err != nil {
	// 		log.Fatal("accept error:", err)
	// 		continue
	// 	}

	// 	go authGrantServer(conn, &principals)
	// }
}
