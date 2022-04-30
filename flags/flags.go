// Package flags provides support for hop CLI args
package flags

import (
	"errors"
	"flag"
	"fmt"
	"os/user"
	"strconv"

	"zmap.io/portal/config"
	"zmap.io/portal/core"
)

// ErrMissingInputURL is returned when hoststring is missing
var ErrMissingInputURL = errors.New("missing [hop://][user@]host[:port]")

// Flags holds CLI arguments for the Hop client.
//
// TODO(dadrian): This structure probably needs to get moved to another package.
type Flags struct {
	ConfigPath string

	Cmd     string
	Address *core.URL

	// TODO(dadrian): What are these args?
	RemoteArgs []string // CLI arguments related to remote port forwarding
	LocalArgs  []string // CLI arguments related to local port forwarding
	Headless   bool     // if no cmd/shell desired (just port forwarding)
}

func mergeAddresses(f *Flags, hc *config.HostConfig) error {
	address := core.MergeURLs(hc.HostURL(), *f.Address)

	if address.User == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("user not specified and unable to determine current user: %s", err)
		}
		address.User = u.Username
	}

	// Update host config address
	hc.Hostname = address.Host
	hc.Port, _ = strconv.Atoi(address.Port)
	hc.User = address.User
	return nil
}

func mergeFlagsAndConfig(f *Flags, cc *config.ClientConfig) error {
	//
	// TODO(baumanl): any need to preserve the original inputURL?
	hc := cc.MatchHost(f.Address.Host)
	err := mergeAddresses(f, hc)
	if err != nil {
		return err
	}
	// TODO(baumanl): add merge support for all other flags/config options
	return nil
}

// LoadConfigFromFlags follows the configpath provided in flags (or default)
// also updates the flags.Address to be the correct override (currently)
func LoadConfigFromFlags(f *Flags) (*config.ClientConfig, error) {
	// Make client config
	// Load the config file
	err := config.InitClient(f.ConfigPath)
	if err != nil {
		// TODO(baumanl): currently fails if no config file found at provided path or default path
		// Do we want to support case where file literally doesn't exist? Just use default
		// host config and CLI flags?
		return nil, fmt.Errorf("no config file found: %s", err)
	}
	cc := config.GetClientCopy(f.Address.Host)
	err = mergeFlagsAndConfig(f, cc)
	return cc, err
}

// defineFlags calls fs.StringVar
func defineFlags(fs *flag.FlagSet, f *Flags) {
	fs.Func("R", "perform remote port forwarding", func(s string) error {
		f.RemoteArgs = append(f.RemoteArgs, s)
		return nil
	})

	fs.Func("L", "perform local port forwarding", func(s string) error {
		f.LocalArgs = append(f.LocalArgs, s)
		return nil
	})

	fs.StringVar(&f.ConfigPath, "C", "", "path to client config (uses ~/.hop/config when unspecified)")

	fs.StringVar(&f.Cmd, "c", "", "specific command to execute on remote server")
	fs.BoolVar(&f.Headless, "N", false, "don't execute a remote command. Useful for just port forwarding.")

	// TODO(baumanl): Right now all explicit commands are run within the context
	// of a shell using "$SHELL -c <cmd>" (this allows for expanding env
	// variables, piping, etc.) However, there may be instances where this is
	// undesirable. Add an option to resort to running the command without this
	// feature. Decide which is the better default. Add config/enforcement on
	// what clients/auth grants are allowed to do. How should this be
	// communicated within Intent and in Authgrant?

	// var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")
}

// ParseArgs defines and parses the flags from the command line
func ParseArgs(args []string) (*Flags, error) {
	var f *Flags
	var fs *flag.FlagSet
	defineFlags(fs, f)

	err := fs.Parse(args[1:])
	if err != nil {
		return nil, err
	}
	if fs.NArg() < 1 { // there needs to be an argument that is not a flag of the form [user@]host[:port]
		return nil, ErrMissingInputURL
	}
	hoststring := fs.Arg(0)
	inputURL, err := core.ParseURL(hoststring)
	if err != nil {
		return nil, fmt.Errorf("invalid input %s: %s", hoststring, err)
	}
	f.Address = inputURL
	return f, nil
}

// ClientSetup creates a hopclient config with the appropriate ovveride rules with information from Flags and config file
// func ClientSetup(f *Flags) (*hopclient.Config, string) {
// 	// potentially other stuff??? Or not necessary at all???
// 	return &hopclient.Config{User: f.Address.User}, f.Address.Address()
// }
