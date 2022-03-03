// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"fmt"
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

// ClientConfig represents a parsed client configuration.
type ClientConfig struct {
	CAFiles []string
	Hosts   []HostConfig
}

// ServerConfig represents a parsed server configuration.
type ServerConfig struct {
	Key          string
	Certificate  string
	Intermediate string

	ListenAddress string

	Names []NameConfig
}

// HostConfig contains a definition of a host pattern in a client configuration.
type HostConfig struct {
	Pattern      string
	Hostname     string
	User         string // TODO(dadrian): Implement this setting in the grammar
	Port         int
	AutoSelfSign bool
	Key          string
	Certificate  string
	Intermediate string
}

// NameConfig defines the keys and certificates presented by the server for a
// given name.
type NameConfig struct {
	Pattern      string
	Key          string
	Certificate  string
	Intermediate string
	// AutoSelfSign bool

	// TODO(dadrian): User mapping
}

// LoadClientConfig converts an AST into an actual configuration object.
func LoadClientConfig(root *ast.Node) (*ClientConfig, error) {
	var c ClientConfig
	return loadClientConfig(&c, root)
}

func loadClientConfig(c *ClientConfig, root *ast.Node) (*ClientConfig, error) {
	var global bool
	var hc *HostConfig
	err := root.Walk(func(n ast.Node) error {
		fmt.Println(n.Type)
		switch n.Type {
		case ast.NodeTypeFile:
			global = true
		case ast.NodeTypeBlock:
			switch n.BlockType {
			case "Include":
				// TODO(dadrian): Includes
			case "Host":
				c.Hosts = append(c.Hosts, HostConfig{})
				hc = &c.Hosts[len(c.Hosts)-1]
				global = false
				hc.Pattern = n.BlockName
			}
		case ast.NodeTypeSetting:
			if global {
				switch n.SettingKey {
				case ast.Setting.CAFile.Value:
					c.CAFiles = append(c.CAFiles, n.SettingValue)
				default:
					return fmt.Errorf("invalid global setting %q", n.SettingKey)
				}
			} else {
				switch n.SettingKey {
				case ast.Setting.Address.Value:
					hc.Hostname = n.SettingValue
				case ast.Setting.Port.Value:
					port, err := strconv.Atoi(n.SettingValue)
					if err != nil {
						return err
					}
					hc.Port = port
				case ast.Setting.AutoSelfSign.Value:
					b, err := strconv.ParseBool(n.SettingValue)
					if err != nil {
						return err
					}
					hc.AutoSelfSign = b
				case ast.Setting.Key.Value:
					hc.Key = n.SettingValue
				case ast.Setting.Certificate.Value:
					hc.Certificate = n.SettingValue
				}
			}
		default:
			return fmt.Errorf("unknown node type %s", n.Type)
		}
		return nil
	})
	return c, err
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
	return loadClientConfig(c, root)
}

// LoadServerConfig parses an AST into a ServerConfig.
func LoadServerConfig(root *ast.Node) (*ServerConfig, error) {
	var c ServerConfig
	return loadServerConfig(&c, root)
}

func loadServerConfig(c *ServerConfig, root *ast.Node) (*ServerConfig, error) {
	// TODO(dadrian): This is duplicated a lot between client and server types.
	var global bool
	var nc *NameConfig
	err := root.Walk(func(n ast.Node) error {
		fmt.Println(n.Type)
		switch n.Type {
		case ast.NodeTypeFile:
			global = true
		case ast.NodeTypeBlock:
			switch n.BlockType {
			case "Include":
				// TODO(dadrian): Includes
			case "Name":
				c.Names = append(c.Names, NameConfig{})
				nc = &c.Names[len(c.Names)-1]
				global = false
				nc.Pattern = n.BlockName
			}
		case ast.NodeTypeSetting:
			if global {
				switch n.SettingKey {
				case ast.Setting.Key.Value:
					c.Key = n.SettingValue
				case ast.Setting.Certificate.Value:
					c.Certificate = n.SettingValue
				case ast.Setting.Intermediate.Value:
					c.Intermediate = n.SettingValue
				case ast.Setting.ListenAddress.Value:
					c.ListenAddress = n.SettingValue
				default:
					return fmt.Errorf("invalid global setting %q", n.SettingKey)
				}
			} else {
				switch n.SettingKey {
				case ast.Setting.Key.Value:
					nc.Key = n.SettingValue
				case ast.Setting.Certificate.Value:
					nc.Certificate = n.SettingValue
				case ast.Setting.Intermediate.Value:
					nc.Intermediate = n.SettingValue
				default:
					return fmt.Errorf("invalid host block setting %q", n.SettingKey)
				}
			}
		default:
			return fmt.Errorf("unknown node type %s", n.Type)
		}
		return nil
	})
	return c, err
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
	return loadServerConfig(c, root)
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

var userConfig ClientConfig
var userConfigErr error
var userConfigOnce sync.Once

// InitClient reads and parses the ClientConfig, either from the override path
// or a default location. This function caches its result and only parses the
// config once.
func InitClient(path string) error {
	if path == "" {
		path = filepath.Join(UserDirectory(), "config")
	}
	userConfigOnce.Do(func() {
		_, userConfigErr = loadClientConfigFromFile(&userConfig, path)
	})
	return userConfigErr
}

// GetClient returns a parsed ClientConfig. This will return nil until
// InitClient is called.
func GetClient() *ClientConfig {
	return &userConfig
}

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
	//TODO(dadrian): Should this return a default host config? Yes.
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
