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

	// DefaultAgentURL is the string version of the default URL the agent
	// listens on, including the port number.
	DefaultAgentURL = "http://localhost:26735"

	// DefaultListenPortString is the string version of the hop default listen
	// port.
	DefaultListenPortString = "77"
)

//Tube Type constants
const (
	ExecTube      = byte(1)
	AuthGrantTube = byte(2)
	NetProxyTube  = byte(3) // Net Proxy should maybe be unreliable tube?
	UserAuthTube  = byte(4)
	LocalPFTube   = byte(5)
	RemotePFTube  = byte(6)
)

// HostToIPAddr is a hacky DNS alt. Should probs be deleted as transition to
// using docker for testing
var HostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}
