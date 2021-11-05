package app

import (
	"testing"

	"gotest.tools/assert"
)

func TestServerStart(t *testing.T) {
	tconf, _ := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     DefaultHopPort,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket,
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	go s.Serve() //starts transport layer server, authgrant server, and listens for hop conns
}
