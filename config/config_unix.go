//go:build unix

package config

// ServerDirectory returns the directory used for server configuration.
func ServerDirectory() string {
	return "/etc/hopd"
}
