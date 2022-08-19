// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"hop.computer/hop/common"
	"hop.computer/hop/core"
	"hop.computer/hop/pkg/glob"
	"hop.computer/hop/pkg/thunks"

	"github.com/BurntSushi/toml"
)

// BoolSetting is True, False, or Unset. The zero value is unset.
type BoolSetting int

// Valid values for BoolSetting
const (
	Unset BoolSetting = 0
	True  BoolSetting = 1
	False BoolSetting = -1
)

// Bool converts the BoolSetting into true if it is true, false if it is false,
// and defaultVal if it is Unset
func (bs BoolSetting) Bool(defaultVal bool) bool {
	switch bs {
	case True:
		return true
	case False:
		return false
	default:
		return defaultVal
	}
}

// UnmarshalText converts a byte slice (where []byte("true") = True and
// []byte("false") = False) to a BoolSetting
func (bs *BoolSetting) UnmarshalText(text []byte) error {
	switch string(text) {
	case "true":
		*bs = True
	case "false":
		*bs = False
	default:
		return fmt.Errorf("expected value but found \"%v\" instead", string(text))
	}
	return nil
}

// ClientConfig represents a parsed client configuration.
type ClientConfig struct {
	Global HostConfig
	Hosts  []HostConfig
}

// ServerConfig represents a parsed server configuration.
type ServerConfig struct {
	Key          string
	Certificate  string
	Intermediate string

	AutoSelfSign  BoolSetting
	ListenAddress string

	Names []NameConfig

	HandshakeTimeout time.Duration
	DataTimeout      time.Duration
}

// HostConfig contains a definition of a host pattern in a client configuration.
type HostConfig struct {
	AgentURL     string
	AutoSelfSign BoolSetting
	CAFiles      []string
	Certificate  string
	Cmd          string      // what command to run on connect
	DisableAgent BoolSetting // TODO(baumanl): figure out a better way to get a running agent to not interfere with other tests
	Headless     BoolSetting // run without command
	Hostname     string
	Intermediate string
	Key          string
	Patterns     []string
	Port         int
	User         string
	// something for principal vs. delegate
	// something for remote port forward
	// something for local port forward

	UsePty           BoolSetting
	HandshakeTimeout time.Duration
	DataTimeout      time.Duration
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

func (hc *HostConfig) mergeWith(other *HostConfig) {
	//TODO(drebelsky): consider whether these default values could be valid values
	if other.AgentURL != "" {
		hc.AgentURL = other.AgentURL
	}
	if other.AutoSelfSign != Unset {
		hc.AutoSelfSign = other.AutoSelfSign
	}
	hc.CAFiles = append(hc.CAFiles, other.CAFiles...)
	if other.Certificate != "" {
		hc.Certificate = other.Certificate
	}
	if other.Cmd != "" {
		hc.Cmd = other.Cmd
	}
	if other.DisableAgent != Unset {
		hc.DisableAgent = other.DisableAgent
	}
	if other.Headless != Unset {
		hc.Headless = other.Headless
	}
	if other.Hostname != "" {
		hc.Hostname = other.Hostname
	}
	if other.Intermediate != "" {
		hc.Intermediate = other.Intermediate
	}
	if other.Key != "" {
		hc.Key = other.Key
	}
	// don't need to merge hc.Patterns
	if other.Port != 0 {
		hc.Port = other.Port
	}
	if other.User != "" {
		hc.User = other.User
	}
	if other.UsePty != Unset {
		hc.UsePty = other.UsePty
	}
	if other.HandshakeTimeout != 0 {
		hc.HandshakeTimeout = other.HandshakeTimeout
	}
	if other.DataTimeout != 0 {
		hc.DataTimeout = other.DataTimeout
	}
}

// LoadClientConfigFromFile tokenizes and parses the file at path, then loads it into
// a Config object.
func LoadClientConfigFromFile(path string) (*ClientConfig, error) {
	var c ClientConfig
	return loadClientConfigFromFile(&c, path)
}

func loadClientConfigFromFile(c *ClientConfig, path string) (*ClientConfig, error) {
	_, err := toml.DecodeFile(path, c)
	return c, err
}

// LoadServerConfigFromFile tokenizes and parse the file at path, and then loads
// it as a ServerConfig.
func LoadServerConfigFromFile(path string) (*ServerConfig, error) {
	var c ServerConfig
	return loadServerConfigFromFile(&c, path)
}

func loadServerConfigFromFile(c *ServerConfig, path string) (*ServerConfig, error) {
	_, err := toml.DecodeFile(path, c)
	return c, err
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

// GetServer reads and parses the ServerConfig, either from the default
// location (/etc), or from the provided location if the path is non-empty. It
// returns a parsed ServerConfig.
func GetServer(path string) (*ServerConfig, error) {
	var serverConfig ServerConfig
	var serverConfigErr error
	if path == "" {
		path = filepath.Join(ServerDirectory(), "config")
	}
	_, serverConfigErr = loadServerConfigFromFile(&serverConfig, path)
	return &serverConfig, serverConfigErr
}

// MatchHostPattern returns true if the input string matches the provided
// pattern. It is used to match user input to Host blocks in their
// configuration.
func MatchHostPattern(pattern string, input string) bool {
	return glob.Glob(pattern, input)
}

// MatchHost returns the host block that matches the input host.
func (c *ClientConfig) MatchHost(inputHost string) *HostConfig {
	host := c.Global
	for i := range c.Hosts {
		for _, pattern := range c.Hosts[i].Patterns {
			if MatchHostPattern(pattern, inputHost) {
				host.mergeWith(&c.Hosts[i])
				break
			}
		}
	}
	return &host
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
