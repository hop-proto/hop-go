// Package config contains structures for parsing Hop client, agent, and server configurations.
package config

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

type TokenFlag uint64

const (
	TokenFlagCaseInsensitive = iota
)

type Token struct {
	Value string
	Flags TokenFlag
}

//go:generate go run ./gen tokens_gen.go

func Tokenize(b []byte) []Token {
	return nil
}
