// Package data implements a basic dependency system for test artifacts.
//
// It is not yet complete.
package data

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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

// Data is not-quite a content addressable store
type Data struct {
	m       sync.Mutex
	root    string
	fsystem fs.FS
}

var instance *Data
var initOnce sync.Once

// Instance returns the default global instance for the workspace
func Instance() *Data {
	initOnce.Do(func() {
		root := filepath.Join(Workspace(), ".local")
		instance = &Data{
			root:    root,
			fsystem: os.DirFS(root),
		}
	})
	return instance
}

// Hash is a byte array representing a SHA-256
type Hash [sha256.Size]byte

// State is a map of names to hashes
type State map[string]Hash

// State returns the current data state.
func (d *Data) State() (State, error) {
	var s State
	d.m.Lock()
	defer d.m.Unlock()
	f, err := os.Open(filepath.Join(d.root, "db.json"))
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(f).Decode(&s)
	return s, err
}

// Get retrieves the named object as bytes
func (d *Data) Get(name string) ([]byte, error) {
	f, err := d.fsystem.Open(name)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// NewResource writes out a new resource for during calls to Gen.
type NewResource struct {
	Name      string
	Generator func(w io.Writer) error
}

// Gen overwrites a resource
func (d *Data) Gen(res NewResource) error {
	p := filepath.Join(d.root, res.Name)
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	return res.Generator(f)
}
