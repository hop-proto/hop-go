// Package loader contains utilties for caching the read and parse of a file by
// path.
package loader

import (
	"fmt"
	"os"
)

// Contents is the raw bytes of a file, and an optional parsed object associated with the raw bytes.
type Contents struct {
	Raw    []byte
	Parsed interface{}
}

// Loader contains cached file contents.
type Loader map[string]*Contents

// LoadFn defines how to turn bytes into an object when loading a file.
type LoadFn func(b []byte) (interface{}, error)

// LoadPath reads the file at path, using the provided load function to create a
// parsed object. It will overwrite any existing file stored at that path in the
// loader.
func (l Loader) LoadPath(path string, f LoadFn) (*Contents, error) {
	var err error
	contents := Contents{}
	if contents.Raw, err = os.ReadFile(path); err != nil {
		return nil, err
	}
	if contents.Parsed, err = f(contents.Raw); err != nil {
		return nil, fmt.Errorf("error in LoadFn for %q: %w", path, err)
	}
	return &contents, nil
}

// LoadOrGet loads the file at path if it is not already read.
func (l Loader) LoadOrGet(path string, f LoadFn) (contents *Contents, created bool, err error) {
	existing, ok := l[path]
	if ok {
		return existing, false, nil
	}
	c, err := l.LoadPath(path, f)
	return c, false, err
}
