// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"zmap.io/portal/common"
	"zmap.io/portal/config/ast"
	"zmap.io/portal/pkg/glob"
)

// ClientConfig represents a parsed client configuration.
type ClientConfig struct {
	CAFiles []string
	Hosts   []HostConfig
}

// HostConfig contains a definition of a host pattern.
type HostConfig struct {
	Pattern      string
	Address      string
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
					hc.Address = n.SettingValue
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
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	configDirectory = filepath.Join(home, ".hop")
}

// UserDirectory returns the path to Hop configuration directory for the current user.
func UserDirectory() string {
	configOnce.Do(locateHopConfigDirectory)
	return configDirectory
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

// MatchURL takes a user-specified url, and turns it into a connectable URL in
// the hop:// protocol by matching the host against Host blocks in the
// configuration. Anything user-specified in the input will override any setting
// from the Host block itself (e.g. username, port).
func (c *ClientConfig) MatchURL(in *url.URL) (*url.URL, error) {
	if in.Path != "" || in.RawPath != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a path: %q", in.String())
	}
	if in.RawQuery != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a query: %q", in.String())
	}
	if in.Fragment != "" || in.RawFragment != "" {
		return nil, fmt.Errorf("hop URLs cannot contain a query: %q", in.String())
	}

	var hc *HostConfig
	for i := range c.Hosts {
		if MatchHostPattern(c.Hosts[i].Pattern, in.Host) {
			hc = &c.Hosts[i]
			break
		}
	}

	inHost, inPort, portErr := net.SplitHostPort(in.Host)
	if portErr != nil {
		inHost = in.Host
		inPort = ""
	}

	var host string
	if hc != nil && hc.Address != "" {
		host = hc.Address
	} else {
		host = inHost
	}

	var port string
	if inPort != "" {
		port = inPort
	} else if hc != nil && hc.Port != 0 {
		port = fmt.Sprintf("%d", hc.Port)
	} else {
		port = common.DefaultListenPortString
	}

	var username string
	if in.User != nil {
		if _, ok := in.User.Password(); ok {
			return nil, fmt.Errorf("input URL %s contains a password, only usernames are allowed", in.String())
		}
		username = in.User.Username()
	} else if hc != nil {
		username = hc.User
	}

	out := &url.URL{
		Scheme: "hop",
		Host:   net.JoinHostPort(host, port),
	}
	if username != "" {
		out.User = url.User(username)
	}
	return out, nil
}
