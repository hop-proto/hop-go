// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/config/ast"
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
var userConfigOnce sync.Once

// UserConfig returns a parsed ClientConfig
func UserConfig() *ClientConfig {
	userConfigOnce.Do(func() {
		d := UserDirectory()
		_, err := loadConfigFromFile(&userConfig, filepath.Join(d, "config"))
		if err != nil {
			logrus.Fatalf("unable to parse config: %s", err)
		}
	})
	return &userConfig
}
