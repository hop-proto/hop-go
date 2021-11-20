package main

import (
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"syscall"
	"testing"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/netproxy"
)

func TestRemote(t *testing.T) {
	curUser, err := user.Current()
	assert.NilError(t, err)
	logrus.Infof("Currently running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	assert.NilError(t, err)
	args := []string{"./remotePF", "7779"}
	c := exec.Command(args[0], args[1:]...)
	if curUser.Uid == "0" {
		logrus.Info("running as root, configuring to run as 'baumanl'")
		user, ok := cache.LookupUserByName("baumanl")
		assert.Equal(t, ok, true)
		c.SysProcAttr = &syscall.SysProcAttr{}
		c.SysProcAttr.Credential = &syscall.Credential{
			Uid:    uint32(user.Uid()),
			Gid:    uint32(user.Gid()),
			Groups: []uint32{uint32(user.Gid())},
		}
	}
	//set up authgrantServer (UDS socket)
	//make sure the socket does not already exist.
	err = os.RemoveAll(sock)
	assert.NilError(t, err)

	//set socket options and start listening to socket
	//sockconfig := &net.ListenConfig{Control: setListenerOptions}
	uds, err := net.Listen("unix", sock)
	assert.NilError(t, err)
	defer uds.Close()
	logrus.Infof("address: %v", uds.Addr())

	// r, err := c.StdoutPipe()
	// assert.NilError(t, err)

	// w, err := c.StdinPipe()
	// assert.NilError(t, err)
	// _, err = c.StderrPipe()
	// assert.NilError(t, err)

	err = c.Start()
	assert.NilError(t, err)

	udsconn, err := uds.Accept()
	assert.NilError(t, err)

	go func() {
		//start TCP connections to the other process
		ctconn, err := net.Dial("tcp", ":7779")
		assert.NilError(t, err)
		_, err = ctconn.Write([]byte("Hi there! this is the first tcp conn.\n"))
		assert.NilError(t, err)
		err = ctconn.Close()
		assert.NilError(t, err)

		ctconn, err = net.Dial("tcp", ":7779")
		assert.NilError(t, err)
		_, err = ctconn.Write([]byte("Howdy! this is the second tcp conn.\n"))
		assert.NilError(t, err)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	logrus.Info("got first conn")
	buf := make([]byte, 1)
	_, err = udsconn.Read(buf)
	assert.NilError(t, err)
	if buf[0] == netproxy.NpcConf {
		logrus.Info("got conf")
		go func() {
			io.Copy(os.Stdout, udsconn)
			udsconn.Close()
			logrus.Info("closed first conn")
		}()
	}

	udsconn2, err := uds.Accept()
	assert.NilError(t, err)
	logrus.Info("got second conn")
	buf = make([]byte, 1)
	_, err = udsconn2.Read(buf)
	assert.NilError(t, err)
	if buf[0] == netproxy.NpcConf {
		logrus.Info("got conf")
		go func() {
			io.Copy(os.Stdout, udsconn2)
			udsconn2.Close()
		}()
	}
	// assert.NilError(t, err)
	// buf := make([]byte, 10)
	// n, _ := udsconn.Read(buf)
	// assert.Equal(t, n, 10)
	// assert.Equal(t, string(buf), "Hi there!!")
	// logrus.Infof("received: %v bytes : %v", n, string(buf))
	// err = udsconn.Close()
	// assert.NilError(t, err)

	err = c.Wait()
	assert.NilError(t, err)
}
