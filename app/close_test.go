package app

import (
	"sync"
	"testing"

	"gotest.tools/assert"
	"zmap.io/portal/transport"
)

func TestTransportServerClose(t *testing.T) {
	port := getPort()
	tconf, _ := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "10",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.server.Serve() //starts transport layer server
		assert.NilError(t, err)
	}()
	err = s.server.Close()
	assert.NilError(t, err)
	wg.Wait()
}

func TestTransportClientClose(t *testing.T) {
	port := getPort()
	tconf, verifyConfig := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "9",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.server.Serve() //starts transport layer server
		assert.NilError(t, err)
	}()

	//client connects and closes
	c, err := transport.Dial("udp", "127.0.0.1:"+serverConfig.Port, transport.ClientConfig{Verify: *verifyConfig})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.NilError(t, err)
	err = c.Close()
	assert.NilError(t, err)

	//client connects and server closes before it
	c, err = transport.Dial("udp", "127.0.0.1:"+serverConfig.Port, transport.ClientConfig{Verify: *verifyConfig})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.NilError(t, err)

	err = s.server.Close()
	assert.NilError(t, err)
	wg.Wait()

	err = c.Close()
	assert.NilError(t, err)

	//client tries to connect after server closes
	// c, err = transport.Dial("udp", "127.0.0.1:"+serverConfig.Port, transport.ClientConfig{Verify: *verifyConfig})
	// assert.NilError(t, err)
	// err = c.Handshake()
	// assert.NilError(t, err)

}
