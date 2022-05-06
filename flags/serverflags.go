package flags

import (
	"errors"
	"flag"
)

var ErrExcessArgs = errors.New("excess arguments provided")

// ServerFlags holds CLI args for Hop server.
type ServerFlags struct {
	ConfigPath string
	// TODO(baumanl): is it even worth allowing flags for servers? Or should they
	// always be started from a config file?
}

// ParseServerArgs defines and parses the flags from the cmd line for hop server
func ParseServerArgs(args []string) (*ServerFlags, error) {
	var f *ServerFlags
	var fs *flag.FlagSet
	defineServerFlags(fs, f)

	err := fs.Parse(args[1:])
	if err != nil {
		return nil, err
	}
	if fs.NArg() > 0 { // there were unparsed args
		return nil, ErrExcessArgs
	}
	return f, nil
}

func defineServerFlags(fs *flag.FlagSet, f *ServerFlags) {
	// var sockAddr string
	// fs.StringVar(&sockAddr, "s", hopserver.DefaultHopAuthSocket, "indicates custom sockaddr to use for auth grant")
	fs.StringVar(&f.ConfigPath, "C", "", "path to server config file")
}
