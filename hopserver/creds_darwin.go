package hopserver

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/mitchellh/go-ps"
)

func setListenerOptions(proto, addr string, c syscall.RawConn) error {
	return nil
}

func readCreds(c net.Conn) (int32, error) {
	// TODO(dadrian): Implement on Darwin
	return -1, errors.New("readCreds is unimplemented on non-linux platforms")
}

func getAncestor(pids []int32, cPID int32) (int32, error) {
	tree := make(map[int32][]int32) // parent --> children
	procs, err := ps.Processes()
	if err != nil {
		return -1, err
	}
	if len(procs) == 0 {
		return -1, fmt.Errorf("no processes found")
	}
	_, ok := procs[0].(*ps.DarwinProcess)
	if !ok {
		return -1, fmt.Errorf("unable to cast ps.Process to ps.DarwinProcess")
	}
	for _, p := range procs {
		dp, _ := p.(*ps.DarwinProcess)
		tree[int32(dp.PPid())] = append(tree[int32(dp.PPid())], int32(dp.Pid()))
	}

	var aPID int32 = -1
	for _, pid := range pids {
		if pid == cPID || checkDescendents(tree, tree[pid], cPID) {
			aPID = pid
			break
		}
	}
	if aPID == -1 {
		return -1, fmt.Errorf("not a descendent process")
	}
	return aPID, nil
}

// checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree map[int32][]int32, children []int32, cPID int32) bool {
	for _, child := range children {
		if child == cPID || checkDescendents(tree, tree[child], cPID) {
			return true
		}
	}
	return false
}
