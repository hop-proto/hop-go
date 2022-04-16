// Package data implements a basic dependency system for test artifacts.
//
// It is not yet complete.
package data

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

type Checksum [32]byte

func (ck Checksum) String() string {
	return fmt.Sprintf("%x", ck[:])
}

// ChecksumHexString decodes s as hex and returns it as a checksum. Invalid data
// or extra data is ignored.
func ChecksumHexString(s string) (ck Checksum) {
	b, _ := hex.DecodeString(s)
	copy(ck[:], b)
	return ck
}

type Hasher interface {
	hash.Hash
	Checksum() Checksum
}

type s256 struct {
	hash.Hash
}

func (s s256) Checksum() (ck Checksum) {
	_ = s.Sum(ck[:0])
	return ck
}

func NewHasher() Hasher {
	return s256{
		Hash: sha256.New(),
	}
}

// Data is not-quite a content addressable store
type Data struct {
	m       sync.Mutex
	root    string
	cache   string
	fsystem fs.FS
	state   State
}

var instance *Data
var initOnce sync.Once

// Instance returns the default global instance for the workspace
func Instance() *Data {
	initOnce.Do(func() {
		root := Workspace()
		cache := filepath.Join(Workspace(), ".local")
		instance = &Data{
			root:    root,
			cache:   cache,
			fsystem: os.DirFS(root),
			state:   State{},
		}
	})
	return instance
}

// State is a map of checksums to data
type State map[Checksum][]byte

func (d *Data) Set(ck Checksum, b []byte) {
	d.m.Lock()
	defer d.m.Unlock()
	d.state[ck] = b
}

func (d *Data) PackageSourceFS(path string) (fs.FS, error) {
	if strings.HasPrefix(path, "//") {
		path = path[2:]
		path = filepath.Join(d.root, path)
		return os.DirFS(path), nil
	}
	return nil, errors.New("only abs workspace paths supported")
}
