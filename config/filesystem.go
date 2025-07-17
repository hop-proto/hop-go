package config

import (
	"io/fs"
	"os"
)

// overwriting fileSystem lets us use a mock filesystem for tests
var fileSystem fs.FS = osFS{}

type osFS struct{}

// osFS implements fs.FS.
func (o osFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}
