// Package common contains shared constants across all of Hop.
package common

const (
	// UserConfigDirtory is the dirname of the directory holding the user
	// configuration for the Hop client.
	UserConfigDirtory = ".hop"

	// AuthorizedKeysFile is the name of the file that holds authorized public
	// keys for a user. It is stored inside the ConfigDirectory.
	AuthorizedKeysFile = "authorized_keys"

	// DefaultKeyFile is the name of the key file used by the client when none
	// are specified the config file.
	DefaultKeyFile = "id_hop.pem"

	// DefaultAgentPortString is the string version of the default port the key
	// agent listens on.
	DefaultAgentPortString = "26735"

	// DefaultListenPortString is the string version of the hop default listen
	// port.
	DefaultListenPortString = "77"
)
