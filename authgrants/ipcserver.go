/*ipcserver replicates the hop server daemon.
It waits for connections from hop client,
and pretends to do auth grant with principal*/

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sbinet/pstree"
	"golang.org/x/sys/unix"
)

func display(pid int, tree *pstree.Tree, indent int) {
	str := strings.Repeat("  ", indent)
	for _, cid := range tree.Procs[pid].Children {
		proc := tree.Procs[cid]
		fmt.Printf("%s%#v\n", str, proc)
		display(cid, tree, indent+1)
	}
}

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

	cPID := creds.Pid
	var ancestor int32 = -1
	tree, err := pstree.New()
	display(os.Getppid(), tree, 1)
	if err != nil {
		log.Printf("Error making pstree: %s", err)
		return
	}
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
	println("Server got:", string(buf[0:n]))

	//initiate NPC w/ principal and get user response
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

func main() {

	//make sure the socket does not already exist.
	if err := os.RemoveAll(SockAddr); err != nil {
		log.Fatal(err)
	}

	//set socket options and start listening to socket
	config := &net.ListenConfig{Control: setListenerOptions}
	l, err := config.Listen(context.Background(), "unix", SockAddr)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()

	principals := make(map[int32]string) //PID -> "principal" (what should actually rep principal?)

	//Spawn some children processes that will act as clients
	cmd := exec.Command("go", "run", "client/ipcclient.go") //need to pass a secret when it is spawned?
	err = cmd.Start()
	if err != nil {
		log.Printf("Started w/ err: %v", err)
	} else {
		principals[int32(cmd.Process.Pid)] = "principal1"
		log.Printf("Started process at PID: %v", cmd.Process.Pid)
	}

	log.Printf("Listening at [%v]", SockAddr)
	for {
		// Accept new connections, dispatching them to echoServer
		// in a goroutine.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
			continue
		}

		go authGrantServer(conn, &principals)
	}
	//first way to wait
	// state, es := cmd.Process.Wait()
	// if es != nil {
	// 	log.Printf("Waited w/ err: %v", err)
	// }
	// log.Printf("Pid: %v", state.Pid())

	//other way to wait
	// err = cmd.Wait()
	// log.Printf("Command finished with error: %v", err)
}
