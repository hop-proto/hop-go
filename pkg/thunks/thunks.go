// Package thunks contains pointers to functions that might be replaced in
// tests.
package thunks

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/AstromechZA/etcpwdparse"
	"hop.computer/hop/acme"
)

// UserHomeDir is an alias for os.UserHomeDir
var UserHomeDir = os.UserHomeDir

// TimeNow is an alias for time.Now
var TimeNow = time.Now

var ErrUserNotFound = errors.New("user not found")

// LookupUser parses /etc/passwd to find information on a given user
var LookupUser = lookupUser

// StartCmd is an alias for the Start method on os.Cmd
var StartCmd = func(c *exec.Cmd) error {
	return c.Start()
}

func lookupUser(username string) (*etcpwdparse.EtcPasswdEntry, error) {
	if username == acme.AcmeUser {
		passwdLine := fmt.Sprintf("%s:x:1000:1000:Test User:/home/%s:/sbin/nologin", username, username)
		ent, err := etcpwdparse.ParsePasswdLine(passwdLine)
		return &ent, err
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		return nil, err
	}
	user, ok := cache.LookupUserByName(username)
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// SetUpTest replaces thunks with stable test versions.
func SetUpTest() {
	TimeNow = func() time.Time {
		return time.Date(1992, 12, 31, 1, 2, 3, 4, time.UTC)
	}
	StartCmd = func(c *exec.Cmd) error {
		c.SysProcAttr = nil
		c.Dir = ""
		return c.Start()
	}
	LookupUser = func(username string) (*etcpwdparse.EtcPasswdEntry, error) {
		// If the user really exists, return their entry
		entry, err := lookupUser(username)
		if err == nil {
			return entry, err
		}

		// Otherwise, make up an entry
		passwdLine := fmt.Sprintf("%s:x:1000:1000:Test User:/home/%s:/bin/sh", username, username)
		ent, err := etcpwdparse.ParsePasswdLine(passwdLine)
		return &ent, err
	}
}
