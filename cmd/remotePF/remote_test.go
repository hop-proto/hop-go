package main

import (
	"os/exec"
	"os/user"
	"syscall"
	"testing"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func TestRemote(t *testing.T) {
	curUser, err := user.Current()
	assert.NilError(t, err)
	logrus.Infof("Currently running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)
	username := curUser.Username
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	assert.NilError(t, err)
	user, ok := cache.LookupUserByName(username)
	assert.Equal(t, ok, true)
	args := []string{"./remotePF"}
	c := exec.Command(args[0])
	if curUser.Uid == "0" {
		c.SysProcAttr = &syscall.SysProcAttr{}
		c.SysProcAttr.Credential = &syscall.Credential{
			Uid:    uint32(user.Uid()),
			Gid:    uint32(user.Gid()),
			Groups: []uint32{uint32(user.Gid())},
		}
	}
	err = c.Run()
	assert.NilError(t, err)
}
