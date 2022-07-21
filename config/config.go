// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
	"hop.computer/hop/core"
	"hop.computer/hop/pkg/glob"
	"hop.computer/hop/pkg/thunks"
	"hop.computer/hop/portforwarding"
)

// ClientConfig represents a parsed client configuration.
type ClientConfig struct {
	Global HostConfigOptional
	Hosts  []HostConfigOptional
}

// TODO(baumanl): do the below boolean fields need to be *bool instead of bool?

// ServerConfig represents a parsed server configuration.
type ServerConfig struct {
	Key          string
	Certificate  string
	Intermediate string

	AutoSelfSign  *bool
	ListenAddress string

	Names []NameConfig

	HandshakeTimeout time.Duration
	DataTimeout      time.Duration

	// transport layer client validation options
	InsecureSkipVerify          *bool
	EnableCertificateValidation *bool
	EnableAuthorizedKeys        *bool
	Users                       []string

	AllowAuthgrants     *bool // as an authgrant Target this server will approve authgrants and as an authgrant Delegate server will proxy ag intent requests
	AgProxyListenSocket *string
}

// HostConfigOptional contains a definition of a host pattern in a client
// configuration; strings and bools are represented as pointers so that a
// default value can be distinguished from a set zero-value; users should
// convert to a `HostConfig` (via .Unwrap) before reading the values
type HostConfigOptional struct {
	AgentURL     *string
	AutoSelfSign *bool
	CAFiles      []string
	Certificate  *string
	Cmd          *string // what command to run on connect
	DisableAgent *bool   // TODO(baumanl): figure out a better way to get a running agent to not interfere with other tests
	Headless     *bool   // run without command
	Hostname     *string
	Intermediate *string
	Key          *string
	Patterns     []string
	Port         int
	RemoteFwds   []*portforwarding.Forward
	LocalFwds    []*portforwarding.Forward
	User         *string
	// something for principal vs. delegate
	IsPrincipal *bool
	// something for remote port forward
	// something for local port forward

	UsePty           *bool
	HandshakeTimeout int
	DataTimeout      int
}

// HostConfig contains a definition of a host pattern in a client configuration
type HostConfig struct {
	AgentURL     string
	AutoSelfSign bool
	CAFiles      []string
	Certificate  string
	Cmd          string // what command to run on connect
	DisableAgent bool   // TODO(baumanl): figure out a better way to get a running agent to not interfere with other tests
	Headless     bool   // run without command
	Hostname     string
	Intermediate string
	Key          string
	Port         int
	User         string
	// something for principal vs. delegate
	IsPrincipal bool
	// something for remote port forward
	// something for local port forward

	UsePty           bool
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
	AutoSelfSign *bool

	// TODO(dadrian): User mapping
}

// MergeWith takes non-default values in another HostConfigOptional and overwrites them
// on/merges them with the values in the receiver
func (hc *HostConfigOptional) MergeWith(other *HostConfigOptional) {
	//TODO(drebelsky): consider using reflection
	if other.AgentURL != nil {
		hc.AgentURL = other.AgentURL
	}
	if other.AutoSelfSign != nil {
		hc.AutoSelfSign = other.AutoSelfSign
	}
	hc.CAFiles = append(hc.CAFiles, other.CAFiles...)
	if other.Certificate != nil {
		hc.Certificate = other.Certificate
	}
	if other.Cmd != nil {
		hc.Cmd = other.Cmd
	}
	if other.DisableAgent != nil {
		hc.DisableAgent = other.DisableAgent
	}
	if other.Headless != nil {
		hc.Headless = other.Headless
	}
	if other.Hostname != nil {
		hc.Hostname = other.Hostname
	}
	if other.Intermediate != nil {
		hc.Intermediate = other.Intermediate
	}
	if other.Key != nil {
		hc.Key = other.Key
	}
	// don't need to merge Patterns
	if other.Port != 0 {
		hc.Port = other.Port
	}
	if other.User != nil {
		hc.User = other.User
	}
	if other.IsPrincipal != nil {
		hc.IsPrincipal = other.IsPrincipal
	}
	if other.UsePty != nil {
		hc.UsePty = other.UsePty
	}
	if other.HandshakeTimeout != 0 {
		hc.HandshakeTimeout = other.HandshakeTimeout
	}
	if other.DataTimeout != 0 {
		hc.DataTimeout = other.DataTimeout
	}
}

func (hc *HostConfigOptional) Unwrap() *HostConfig {
	//TODO(drebelsky): consider using reflection
	newHC := HostConfig{
		HandshakeTimeout: 15 * time.Second,
		DataTimeout:      15 * time.Second,
	}
	if hc.AgentURL != nil {
		newHC.AgentURL = *hc.AgentURL
	}
	if hc.AutoSelfSign != nil {
		newHC.AutoSelfSign = *hc.AutoSelfSign
	}
	newHC.CAFiles = hc.CAFiles
	if hc.Certificate != nil {
		newHC.Certificate = *hc.Certificate
	}
	if hc.Cmd != nil {
		newHC.Cmd = *hc.Cmd
	}
	if hc.DisableAgent != nil {
		newHC.DisableAgent = *hc.DisableAgent
	}
	if hc.Headless != nil {
		newHC.Headless = *hc.Headless
	}
	if hc.Hostname != nil {
		newHC.Hostname = *hc.Hostname
	}
	if hc.Intermediate != nil {
		newHC.Intermediate = *hc.Intermediate
	}
	if hc.Key != nil {
		newHC.Key = *hc.Key
	}
	// don't need to include patterns
	if hc.Port != 0 {
		newHC.Port = hc.Port
	}
	if hc.User != nil {
		newHC.User = *hc.User
	}
	if hc.IsPrincipal != nil {
		newHC.IsPrincipal = *hc.IsPrincipal
	}
	if hc.UsePty != nil {
		newHC.UsePty = *hc.UsePty
	}
	if hc.HandshakeTimeout != 0 {
		newHC.HandshakeTimeout = time.Duration(hc.HandshakeTimeout) * time.Second
	}
	if hc.DataTimeout != 0 {
		newHC.DataTimeout = time.Duration(hc.DataTimeout) * time.Second
	}
	return &newHC
}

// LoadClientConfigFromFile tokenizes and parses the file at path, then loads it into
// a Config object.
func LoadClientConfigFromFile(path string) (*ClientConfig, error) {
	var c ClientConfig
	return loadClientConfigFromFile(&c, path)
}

func loadClientConfigFromFile(c *ClientConfig, path string) (*ClientConfig, error) {
	meta, err := toml.DecodeFile(path, c)
	keys, lines := meta.UndecodedWithLines()
	for i, key := range keys {
		logrus.Warnf("While parsing config, encountered unknown key `%v` at %v:%v", key, path, lines[i])
	}
	return c, err
}

// LoadServerConfigFromFile tokenizes and parse the file at path, and then loads
// it as a ServerConfig.
func LoadServerConfigFromFile(path string) (*ServerConfig, error) {
	var c ServerConfig
	return loadServerConfigFromFile(&c, path)
}

func loadServerConfigFromFile(c *ServerConfig, path string) (*ServerConfig, error) {
	meta, err := toml.DecodeFile(path, c)
	keys, lines := meta.UndecodedWithLines()
	for i, key := range keys {
		logrus.Warnf("While parsing config, encountered unknown key `%v` at %v:%v", key, path, lines[i])
	}
	c.HandshakeTimeout *= time.Second
	c.DataTimeout *= time.Second
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
	clientDirectory = filepath.Join(home, common.UserConfigDirectory)
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
	return filepath.Join(u.HomeDir, common.UserConfigDirectory), nil
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
func (c *ClientConfig) MatchHost(inputHost string) *HostConfigOptional {
	host := c.Global
	for i := range c.Hosts {
		for _, pattern := range c.Hosts[i].Patterns {
			if MatchHostPattern(pattern, inputHost) {
				host.MergeWith(&c.Hosts[i])
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
func (hc *HostConfig) HostURL() core.URL {
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

// HostURL extracts the Hostname, Port, and User from the HostConfig into an
// core.URL.
func (hc *HostConfigOptional) HostURL() core.URL {
	u := core.URL{}
	if hc.Hostname != nil {
		u.Host = *hc.Hostname
	}
	if hc.User != nil {
		u.User = *hc.User
	}
	if hc.Port != 0 {
		u.Port = strconv.Itoa(hc.Port)
	} else {
		u.Port = common.DefaultListenPortString
	}
	return u
}
