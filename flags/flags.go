// Package flags provides support for hop CLI args
package flags

// Flags holds CLI arguments for the Hop client.
//
// TODO(dadrian): This structure probably needs to get moved to another package.
type Flags struct {
	ConfigPath string
	Cmd        string

	// TODO(dadrian): What are these args?
	RemoteArgs []string // CLI arguments related to remote port forwarding
	LocalArgs  []string // CLI arguments related to local port forwarding
	Headless   bool     // if no cmd/shell desired (just port forwarding)
}
