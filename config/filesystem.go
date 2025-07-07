package config

import (
	"github.com/spf13/afero"
)

// overwriting fileSystem lets us use a mock filesystem for tests
var fileSystem afero.Fs = afero.NewOsFs()
