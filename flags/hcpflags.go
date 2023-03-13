package flags

import (
	"errors"
	"flag"
)

// ErrMissingSrcFile indicates that no files were provided in the hcp command line arguments
var ErrMissingSrcFile = errors.New("missing source file")

// HcpFlags holds CLI arguments for the hcp program.
type HcpFlags struct {
	IsRemote bool   // indicates that this is the server the user is connecting to
	IsSource bool   // indicates that this is the source of the file to copy
	SrcFile  string // the source file to be copied from
	DstFile  string // the destination to copy to

	Flags *ClientFlags // flags for the underlying hop instance
}

// defineHcpFlags calls fs.StringVar for hcp
func defineHcpFlags(fs *flag.FlagSet, f *HcpFlags) {
	defineClientFlags(fs, f.Flags)
	fs.BoolVar(&f.IsRemote, "t", false, "run hcp in remote mode")
	fs.BoolVar(&f.IsRemote, "s", false, "if running in remote mode, read from file and write to stdout")
}

// ParseHcpArgs defines and parses the flags from the command line for hcp
func ParseHcpArgs(args []string) (*HcpFlags, error) {
	f := &HcpFlags{}
	fs := &flag.FlagSet{}
	f.Flags = &ClientFlags{}

	defineHcpFlags(fs, f)

	err := fs.Parse(args[1:])
	if err != nil {
		return nil, err
	}

	if fs.NArg() < 1 {
		return nil, ErrMissingSrcFile
	}
	f.SrcFile = fs.Arg(0)

	// Add destination if specified
	if fs.NArg() > 1 {
		f.DstFile = fs.Arg(1)
	}

	if err != nil {
		return nil, err
	}

	// hcp should never use a pty
	f.Flags.UsePty = false

	return f, nil
}
