// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

import (
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
	Hostname     string
	Port         int
	AutoSelfSign bool
	Key          string
	Certificate  string
}

func Parse(toks []ast.Token) {
}
