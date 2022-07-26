// Package thunks contains pointers to functions that might be replaced in
// tests.
package thunks

import (
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
)

// UserHomeDir is an alias for os.UserHomeDir
var UserHomeDir = os.UserHomeDir

// TimeNow is an alias for time.Now
var TimeNow = time.Now

// LookupUser is an alias for user.Lookup.
var LookupUser = user.Lookup

// Setuid is an alias for syscall.Setuid
var Setuid = syscall.Setuid

// Setgid is an alias for syscall.Setuid
var Setgid = syscall.Setgid

// Setgroups is an alias for syscall.Setgroups
var Setgroups = syscall.Setgroups

// SetUpTest replaces thunks with stable test versions.
// and overrides the authentication methods to be able to be run as an unpriveleged user
func SetUpTest() {
	TimeNow = func() time.Time {
		return time.Date(1992, 12, 31, 1, 2, 3, 4, time.UTC)
	}
	LookupUser = func(username string) (*user.User, error) {
		cur, err := user.Current()
		if err != nil {
			return nil, err
		}
		cur.HomeDir = filepath.Join("/home", username)
		return cur, nil
	}
	Setuid = func(uid int) (err error) { return }
	Setgid = func(gid int) (err error) { return }
	Setgroups = func(gids []int) (err error) { return }
}
