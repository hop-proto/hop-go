// Package thunks contains pointers to functions that might be replaced in
// tests.
package thunks

import (
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// UserHomeDir is an alias for os.UserHomeDir
var UserHomeDir = os.UserHomeDir

// TimeNow is an alias for time.Now
var TimeNow = time.Now

// LookupUser is an alias for user.Lookup.
var LookupUser = user.Lookup

// SetUpTest replaces thunks with stable test versions.
func SetUpTest() {
	TimeNow = func() time.Time {
		return time.Date(1992, 12, 31, 1, 2, 3, 4, time.UTC)
	}
	LookupUser = func(username string) (*user.User, error) {
		return &user.User{
			HomeDir: filepath.Join("/home", username),
		}, nil
	}
}
