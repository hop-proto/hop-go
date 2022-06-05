// Package data implements a basic dependency system for test artifacts.
//
// It is not yet complete.
package data

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
)

var workspaceOnce sync.Once
var workspaceDir string

// Workspace returns the root of the workspace, as located by finding a
// WORKSPACE file.
func Workspace() string {
	workspaceOnce.Do(func() {
		d, _ := os.Getwd()
		for d != "." && d != "" {
			path := filepath.Join(d, "WORKSPACE")
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				d = filepath.Dir(d)
				continue
			}
			workspaceDir = d
			break
		}
		if workspaceDir == "" {
			logrus.Fatalf("unable to find workspace root")
		}
	})
	return workspaceDir
}
