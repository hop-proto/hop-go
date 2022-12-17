package hopserver

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/sbinet/pstree"
	"golang.org/x/sys/unix"
)

// Callback function that sets the appropriate socket options
func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PASSCRED,
			1)
	})
}

// Src: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/src/peercred/cred.go
// Parses the credentials sent by the client when it connects to the socket
func readCreds(c net.Conn) (int32, error) { //nolint TODO(hosono) add linting back
	var cred *unix.Ucred

	//should only have *net.UnixConn types
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("error opening raw connection: %s", err)
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
		return -1, fmt.Errorf(" GetsockoptUcred() error: %s", err)
	}

	if err2 != nil {
		return -1, fmt.Errorf(" Control() error: %s", err2)
	}

	return cred.Pid, nil
}

func getAncestor(pids []int32, cPID int32) (int32, error) {
	// aPID is the ancestor of cPID spawned by a hop session
	var aPID int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	if err != nil {
		return 0, err
	}

	// check all of the PIDs of processes that the server started
	for _, k := range pids {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			aPID = k
			break
		}
	}
	if aPID == -1 {
		return -1, errors.New("not a descendent process")
	}
	return aPID, nil
}

// checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}
