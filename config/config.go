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

// HostConfig contains a definition of a host pattern.
type HostConfig struct {
	Pattern      string
	Hostname     string
	User         string // TODO(dadrian): Implement this setting in the grammar
	Port         int
	AutoSelfSign bool
	Key          string
	Certificate  string
}

// LoadConfig converts an AST into an actual configuration object.
func LoadConfig(root *ast.Node) (*ClientConfig, error) {
	var c ClientConfig
	return loadConfig(&c, root)
}

func loadConfig(c *ClientConfig, root *ast.Node) (*ClientConfig, error) {
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

// LoadConfigFromFile tokenizes and parses the file at path, then loads it into
// a Config object.
func LoadConfigFromFile(path string) (*ClientConfig, error) {
	var c ClientConfig
	return loadConfigFromFile(&c, path)
}

func loadConfigFromFile(c *ClientConfig, path string) (*ClientConfig, error) {
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
	return loadConfig(c, p.AST)
}

var configDirectory string
var configOnce sync.Once

func locateHopConfigDirectory() {
	// TODO(dadrian): Actually decide where this is on different platforms.
	// Using the ".hop" folder on Windows doesn't make sense.
	home, err := thunks.UserHomeDir()
	if err != nil {
		configDirectory = ""
		return
	}
	configDirectory = filepath.Join(home, common.UserConfigDirtory)
}

// UserDirectory returns the path to Hop configuration directory for the current user.
func UserDirectory() string {
	configOnce.Do(locateHopConfigDirectory)
	return configDirectory
}

// UserDirectoryFor returns the path to the Hop configuration directory for a specific user.
func UserDirectoryFor(username string) (string, error) {
	u, err := thunks.LookupUser(username)
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, common.UserConfigDirtory), nil
}

// DefaultKeyPath returns UserDirectory()/id_hop.pem.
func DefaultKeyPath() string {
	d := UserDirectory()
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
		_, userConfigErr = loadConfigFromFile(&userConfig, path)
	})
	return userConfigErr
}

// GetClient returns a parsed ClientConfig. This will return nil until
// InitClient is called.
func GetClient() *ClientConfig {
	return &userConfig
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
	return nil
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

// Address extracts the Hostname, Port, and User from the HostConfig into an
// Address.
func (hc HostConfig) Address() core.URL {
	return core.URL{
		Host: hc.Hostname,
		Port: strconv.Itoa(hc.Port),
		User: hc.User,
	}
}
