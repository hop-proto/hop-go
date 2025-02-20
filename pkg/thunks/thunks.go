// Package thunks contains pointers to functions that might be replaced in
// tests.
package thunks

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AstromechZA/etcpwdparse"
)

// UserHomeDir is an alias for os.UserHomeDir
var UserHomeDir = os.UserHomeDir

// TimeNow is an alias for time.Now
var TimeNow = time.Now

var ErrUserNotFound = errors.New("user not found")

// LookupUser is an alias for user.Lookup.
var LookupUser = func(username string) (*etcpwdparse.EtcPasswdEntry, error) {
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		return nil, err
	}
	user, ok := cache.LookupUserByName("username")
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
	LookupUser = func(username string) (*etcpwdparse.EtcPasswdEntry, error) {
		passwdLine := fmt.Sprintf("%s:x:1000:1000:Test User:/home/%s:/bin/sh", username, username)
		entry, err := etcpwdparse.ParsePasswdLine(passwdLine)
		return &entry, err
	}
}
