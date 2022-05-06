// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"zmap.io/portal/common"
	"zmap.io/portal/config/ast"
	"zmap.io/portal/core"
	"zmap.io/portal/pkg/glob"
	"zmap.io/portal/pkg/thunks"
)

// BoolSetting is True, False, or Unset. The zero value is unset.
type BoolSetting int

// Valid values for BoolSetting
const (
	Unset BoolSetting = 0
	True  BoolSetting = 1
	False BoolSetting = -1
)

// ClientConfig represents a parsed client configuration.
type ClientConfig struct {
	CAFiles      []string
	Key          string
	Certificate  string
	AutoSelfSign BoolSetting
	AgentURL     string
	Hosts        []HostConfig
}

// ServerConfig represents a parsed server configuration.
type ServerConfig struct {
	Key          string
	Certificate  string
	Intermediate string

	AutoSelfSign  BoolSetting
	ListenAddress string

	Names []NameConfig
}

// HostConfig contains a definition of a host pattern in a client configuration.
type HostConfig struct {
	Pattern      string
	Hostname     string
	User         string // TODO(dadrian): Implement this setting in the grammar
	Port         int
	AutoSelfSign BoolSetting
	Key          string
	Certificate  string
	Intermediate string

	DisableAgent BoolSetting // TODO(baumanl): figure out a better way to get a running agent to not interfere with other tests

	// TODO(baumanl): Add application layer hop config options to grammar
	Cmd      string // what command to run on connect
	Headless bool   // run without shell
	// something for principal vs. delegate
	// something for remote port forward
	// something for local port forward
}

// NameConfig defines the keys and certificates presented by the server for a
// given name.
type NameConfig struct {
	Pattern      string
	Key          string
	Certificate  string
	Intermediate string
	AutoSelfSign BoolSetting

	// TODO(dadrian): User mapping
}

//go:generate go run ./gen config_gen.go

// LoadClientConfig converts an AST into an actual configuration object.
func LoadClientConfig(root *ast.Node) (*ClientConfig, error) {
	var c ClientConfig
	return loadClientConfig_Gen(&c, root)
}

func tokenizeAndParseFile(path string) (*ast.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tokens, err := ast.Tokenize(b)
	if err != nil {
		return nil, err
	}
	p := ast.NewParser(b, tokens)
	if err := p.Parse(); err != nil {
		return nil, err
	}
	return p.AST, nil
}

// LoadClientConfigFromFile tokenizes and parses the file at path, then loads it into
// a Config object.
func LoadClientConfigFromFile(path string) (*ClientConfig, error) {
	var c ClientConfig
	return loadClientConfigFromFile(&c, path)
}

func loadClientConfigFromFile(c *ClientConfig, path string) (*ClientConfig, error) {
	root, err := tokenizeAndParseFile(path)
	if err != nil {
		return nil, err
	}
	return loadClientConfig_Gen(c, root)
}

// LoadServerConfig parses an AST into a ServerConfig.
func LoadServerConfig(root *ast.Node) (*ServerConfig, error) {
	var c ServerConfig
	return loadServerConfig_Gen(&c, root)
}

// LoadServerConfigFromFile tokenizes and parse the file at path, and then loads
// it as a ServerConfig.
func LoadServerConfigFromFile(path string) (*ServerConfig, error) {
	var c ServerConfig
	return loadServerConfigFromFile(&c, path)
}

func loadServerConfigFromFile(c *ServerConfig, path string) (*ServerConfig, error) {
	root, err := tokenizeAndParseFile(path)
	if err != nil {
		return nil, err
	}
	return loadServerConfig_Gen(c, root)
}

var clientDirectory string
var clientDirectoryOnce sync.Once

func locateHopClientConfigDirectory() {
	// TODO(dadrian): Actually decide where this is on different platforms.
	// Using the ".hop" folder on Windows doesn't make sense.
	home, err := thunks.UserHomeDir()
	if err != nil {
		clientDirectory = ""
		return
	}
	clientDirectory = filepath.Join(home, common.UserConfigDirtory)
}

// UserDirectory returns the path to Hop configuration directory for the current user.
func UserDirectory() string {
	clientDirectoryOnce.Do(locateHopClientConfigDirectory)
	return clientDirectory
}

// UserDirectoryFor returns the path to the Hop configuration directory for a specific user.
func UserDirectoryFor(username string) (string, error) {
	u, err := thunks.LookupUser(username)
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, common.UserConfigDirtory), nil
}

var serverDirectory string
var serverDirectoryOnce sync.Once

func locateServerConfigDirectory() {
	serverDirectory = "/etc/hopd" // TODO(dadrian): Windows? Compile-time override?
}

// ServerDirectory returns the directory used for server configuration.
func ServerDirectory() string {
	serverDirectoryOnce.Do(locateServerConfigDirectory)
	return serverDirectory
}

// DefaultKeyPath returns UserDirectory()/id_hop.pem.
func DefaultKeyPath() string {
	d := UserDirectory()
	return filepath.Join(d, common.DefaultKeyFile)
}

// DefaultServerKeyPath returns Serverdirectory()/id_hop.pem.
func DefaultServerKeyPath() string {
	d := ServerDirectory()
	return filepath.Join(d, common.DefaultKeyFile)
}

// GetClient reads and parses the ClientConfig, either from the override path
// or a default location and returns a parsed ClientConfig.
func GetClient(path string) (*ClientConfig, error) {
	var userConfig ClientConfig
	var userConfigErr error
	if path == "" {
		path = filepath.Join(UserDirectory(), "config")
	}
	_, userConfigErr = loadClientConfigFromFile(&userConfig, path)
	return &userConfig, userConfigErr
}

// TODO(baumanl): get rid of server config caching
var serverConfig ServerConfig
var serverConfigErr error
var serverConfigOnce sync.Once

// InitServer reads and parses the ServerConfig, either from the default
// location (/etc), or from the provided location if the path is non-empty. The
// result is cached.
func InitServer(path string) error {
	if path == "" {
		path = filepath.Join(ServerDirectory(), "config")
	}
	serverConfigOnce.Do(func() {
		_, serverConfigErr = loadServerConfigFromFile(&serverConfig, path)
	})
	return serverConfigErr
}

// GetServer returns a parsed ServerConfig. It is only non-nil after InitServer
// finishes executing. It is not atomic with InitServer.
func GetServer() *ServerConfig {
	return &serverConfig
}

// MatchHostPattern returns true if the input string matches the provided
// pattern. It is used to match user input to Host blocks in their
// configuration.
func MatchHostPattern(pattern string, input string) bool {
	return glob.Glob(pattern, input)
}

// MatchHost returns the host block that matches the input host.
func (c *ClientConfig) MatchHost(inputHost string) *HostConfig {
	for i := range c.Hosts {
		if MatchHostPattern(c.Hosts[i].Pattern, inputHost) {
			return &c.Hosts[i]
		}
	}
	// TODO(dadrian): Should this return a default host config? Yes.
	return &HostConfig{}
}

// ApplyConfigToInputAddress updates the input address with the Host, Port, and
// User from the HostConfig. It only replaces Port and User if they are empty in
// the input address.
func (hc *HostConfig) ApplyConfigToInputAddress(address core.URL) core.URL {
	if hc.Hostname != "" {
		address.Host = hc.Hostname
	}
	if address.Port == "" {
		address.Port = strconv.Itoa(hc.Port)
	}
	if address.User == "" {
		address.User = hc.User
	}
	return address
}

// HostURL extracts the Hostname, Port, and User from the HostConfig into an
// core.URL.
func (hc HostConfig) HostURL() core.URL {
	u := core.URL{
		Host: hc.Hostname,
		User: hc.User,
	}
	if hc.Port != 0 {
		u.Port = strconv.Itoa(hc.Port)
	} else {
		u.Port = common.DefaultListenPortString
	}
	return u
}
