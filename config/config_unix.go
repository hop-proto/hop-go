//go:build unix

package config

func locateServerConfigDirectory() {
	serverDirectory = "/etc/hopd"
}
