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
)

func TestRemote(t *testing.T) {
	remotePort := "7779"
	arg := remotePort + ":connect_host:connect_port"
	curUser, err := user.Current()
	assert.NilError(t, err)
	logrus.Infof("Currently running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	assert.NilError(t, err)
	args := []string{"remotePF", arg}
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
	//set up UDS socket
	//make sure the socket does not already exist.
	contentSockAddr := "@content" + remotePort
	err = os.RemoveAll(contentSockAddr)
	assert.NilError(t, err)

	//set socket options and start listening to socket
	//sockconfig := &net.ListenConfig{Control: setListenerOptions}
	uds, err := net.Listen("unix", contentSockAddr)
	assert.NilError(t, err)
	defer uds.Close()
	logrus.Infof("address: %v", uds.Addr())

	//control socket
	controlSockAddr := "@control" + remotePort
	control, err := net.Listen("unix", controlSockAddr)
	assert.NilError(t, err)
	defer uds.Close()
	logrus.Infof("control address: %v", control.Addr())

	err = c.Start()
	assert.NilError(t, err)

	controlChan, _ := control.Accept() //wait for the child process to start listening for TCP conns and connect to control

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

	go func() {
		udsconn, err := uds.Accept()
		assert.NilError(t, err)

		logrus.Info("got first conn")
		go func() {
			io.Copy(os.Stdout, udsconn)
			udsconn.Close()
			logrus.Info("closed first conn")
		}()
	}()

	udsconn2, err := uds.Accept()
	assert.NilError(t, err)
	logrus.Info("got second conn")
	go func() {
		io.Copy(os.Stdout, udsconn2)
		udsconn2.Close()
		logrus.Info("closed second conn")
		controlChan.Write([]byte{1})
	}()

	err = c.Wait()
	assert.NilError(t, err)
}
