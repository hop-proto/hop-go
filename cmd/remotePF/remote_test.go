package main

import (
	"os/exec"
	"os/user"
	"syscall"
	"testing"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/app"
)

func TestRemote(t *testing.T) {
	curUser, err := user.Current()
	assert.NilError(t, err)
	logrus.Infof("Currently running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	assert.NilError(t, err)
	args := []string{"./remotePF", app.DefaultHopPort}
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
	// r, err := c.StdoutPipe()
	// assert.NilError(t, err)
	// w, err := c.StdinPipe()
	// assert.NilError(t, err)
	// _, err = c.StderrPipe()
	// assert.NilError(t, err)

	err = c.Run()
	assert.NilError(t, err)
}
