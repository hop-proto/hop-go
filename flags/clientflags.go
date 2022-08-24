// Package flags provides support for hop CLI args
package flags

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	istty "github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/config"
	"hop.computer/hop/core"
)

// ErrMissingInputURL is returned when hoststring is missing
var ErrMissingInputURL = errors.New("missing [hop://][user@]host[:port]")

// ClientFlags holds CLI arguments for the Hop client.
type ClientFlags struct {
	ConfigPath string

	Cmd     string
	Address *core.URL

	// TODO(dadrian): What are these args?
	RemoteArgs []string // CLI arguments related to remote port forwarding
	LocalArgs  []string // CLI arguments related to local port forwarding
	Headless   bool     // if no cmd desired (just port forwarding)
	UsePty     bool     // whether or not to request a remote PTY be allocated
	Verbose    bool     // show verbose error messages
}

func mergeAddresses(f *ClientFlags, hc *config.HostConfigOptional) error {
	address := core.MergeURLs(hc.HostURL(), *f.Address)

	if address.User == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("user not specified and unable to determine current user: %s", err)
		}
		address.User = u.Username
	}

	// Update host config address
	hc.Hostname = &address.Host
	hc.Port, _ = strconv.Atoi(address.Port)
	hc.User = &address.User
	return nil
}

func mergeClientFlagsAndConfig(f *ClientFlags, cc *config.ClientConfig, dc *config.ClientConfig) (*config.HostConfig, error) {
	// TODO(baumanl): any need to preserve the original inputURL?
	var hc *config.HostConfigOptional
	if dc == nil {
		hc = cc.MatchHost(f.Address.Host)
	} else {
		hc = dc.MatchHost(f.Address.Host)
		hc.MergeWith(cc.MatchHost(f.Address.Host))
	}
	err := mergeAddresses(f, hc)
	if err != nil {
		return nil, err
	}

	if f.Cmd != "" {
		hc.Cmd = &f.Cmd
	}

	hc.UsePty = &f.UsePty

	// TODO(baumanl): add merge support for all other flags/config options
	return hc.Unwrap(), nil
}

// LoadClientConfigFromFlags follows the configpath provided in flags (or default)
// also updates the flags.Address to be the correct override (currently)
func LoadClientConfigFromFlags(f *ClientFlags) (*config.HostConfig, error) {
	// Get default client config if it exists
	var dc *config.ClientConfig
	if f.ConfigPath != "" {
		var err error
		dc, err = config.GetClient("")
		if err != nil {
			logrus.Warnf("Problem with loading config in default location: %v", err)
			dc = nil
		}
	}
	// Load the config file
	cc, err := config.GetClient(f.ConfigPath)
	if err != nil {
		// TODO(baumanl): currently fails if no config file found at provided path or default path
		// Do we want to support case where file literally doesn't exist? Just use default
		// host config and CLI flags?
		return nil, err
	}
	return mergeClientFlagsAndConfig(f, cc, dc)
}

// defineClientFlags calls fs.StringVar for Client
func defineClientFlags(fs *flag.FlagSet, f *ClientFlags) {
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
	fs.BoolVar(&f.Verbose, "V", false, "display verbose error messages")

	// TODO(baumanl): Right now all explicit commands are run within the context
	// of a shell using "$SHELL -c <cmd>" (this allows for expanding env
	// variables, piping, etc.) However, there may be instances where this is
	// undesirable. Add an option to resort to running the command without this
	// feature. Decide which is the better default. Add config/enforcement on
	// what clients/auth grants are allowed to do. How should this be
	// communicated within Intent and in Authgrant?

	// var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")

	// TODO(drebelsky): SSH compat options all ignored for now
	_ = fs.Bool("x", true, "")
	_ = fs.String("oForwardAgent", "", "")
	_ = fs.String("oPermitLocalCommand", "", "")
	_ = fs.String("oClearAllForwardings", "", "")
	_ = fs.String("oRemoteCommand", "", "")
	_ = fs.String("oRequestTTY", "", "")
}

// ParseClientArgs defines and parses the flags from the command line for Client
func ParseClientArgs(args []string) (*ClientFlags, error) {
	f := new(ClientFlags)
	fs := new(flag.FlagSet)
	defineClientFlags(fs, f)

	// For SSH compatibility
	var port, username string
	fs.StringVar(&port, "p", "", "port")
	fs.StringVar(&username, "l", "", "username")
	var reqPty, forcePty, noPty bool
	fs.BoolVar(&reqPty, "t", false, "Request a pseudo-terminal allocation (defaults to true if no command is specified and there is a local tty unless -N is specified)")
	fs.BoolVar(&forcePty, "tt", false, "Force request a pseudo-terminal allocation, even if the local side is not a tty")
	fs.BoolVar(&noPty, "T", false, "Don't request a pseudo-terminal allocation (overrides default)")

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
	if port != "" {
		inputURL.Port = port
	}
	if username != "" {
		inputURL.User = username
	}

	// Support putting the command after the hostname
	if f.Cmd == "" {
		f.Cmd = strings.Join(fs.Args()[1:], " ")
	}
	f.Address = inputURL

	// Handle pty allocation
	switch {
	case forcePty:
		f.UsePty = true
	case reqPty:
		f.UsePty = istty.IsTerminal(os.Stdin.Fd())
	case noPty:
		f.UsePty = false
	default:
		f.UsePty = f.Cmd == "" && istty.IsTerminal(os.Stdin.Fd()) && !f.Headless
	}
	return f, nil
}
