package app

import (
	"os"
	"os/user"
	"testing"

	"gotest.tools/assert"
)

func SetupClientServer(t *testing.T) (*HopServer, *HopClient) {
	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
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

	keypath, _ := os.UserHomeDir()
	keypath += DefaultKeyPath

	u, e := user.Current()
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket,
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          DefaultHopPort,
		Username:      u.Username,
		Principal:     true,
		RemoteForward: false,
		LocalForward:  false,
		Cmd:           "echo hello world",
		Quiet:         false,
		Headless:      false,
	}
	client, err := NewHopClient(clientConfig)
	assert.NilError(t, err)

	err = client.Connect()
	assert.NilError(t, err)
	return s, client
}

func TestClientServerSetup(t *testing.T) {
	SetupClientServer(t)
}

func TestClientServerCodex(t *testing.T) {
	_, c := SetupClientServer(t)
	err := c.startExecTube()
	assert.NilError(t, err)
}
