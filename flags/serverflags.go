package flags

import (
	"errors"
	"flag"

	"hop.computer/hop/config"
)

// ErrExcessArgs is called when unparsed arguments remain
var ErrExcessArgs = errors.New("excess arguments provided")

// ServerFlags holds CLI args for Hop server.
type ServerFlags struct {
	ConfigPath       string
	Verbose          bool
	EnableAuthgrants bool
}

// ParseServerArgs defines and parses the flags from the cmd line for hop server
func ParseServerArgs(args []string) (*ServerFlags, error) {
	f := new(ServerFlags)
	fs := new(flag.FlagSet)
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
	//var sockAddr string
	// fs.StringVar(&sockAddr, "s", hopserver.DefaultHopAuthSocket, "indicates custom sockaddr to use for auth grant")
	fs.StringVar(&f.ConfigPath, "C", "", "path to server config file")
	fs.BoolVar(&f.Verbose, "V", false, "verbose logging")
	fs.BoolVar(&f.EnableAuthgrants, "A", true, "enable authgrants")
}

func mergeServerFlagsAndConfig(f *ServerFlags, sc *config.ServerConfig) error {
	// TODO(baumanl): implement this if actually needed. Potentially find a way to share
	// functionality with client stuff.
	return nil
}

// LoadServerConfigFromFlags follows the configpath provided in flags (or default)
// also updates config with info from flags.
func LoadServerConfigFromFlags(f *ServerFlags) (*config.ServerConfig, error) {
	sc, err := config.GetServer(f.ConfigPath)
	if err != nil {
		// TODO(baumanl): currently fails if no config file found at provided path or default path
		// Do we want to support case where file literally doesn't exist?
		return nil, err
	}
	err = mergeServerFlagsAndConfig(f, sc)
	return sc, err
}
