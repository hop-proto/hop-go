package app

import (
	"io"
	"net"
	"os"
	"os/user"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

func TestClientServer(t *testing.T) {
	logrus.SetOutput(io.Discard)
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	KeyGen(DefaultKeyPath, true)

	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     DefaultHopPort,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "1",
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
		SockAddr:      DefaultHopAuthSocket + "1",
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
}

func TestAuthgrantOneHop(t *testing.T) {
	logrus.SetOutput(io.Discard)
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	KeyGen(DefaultKeyPath, true)

	//start hop server 1
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     "7778",
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "2",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)

	//start principal
	keypath, _ := os.UserHomeDir()
	keypath += DefaultKeyPath

	u, e := user.Current()
	assert.NilError(t, e)
	principalConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      "",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          "7778",
		Username:      u.Username,
		Principal:     true,
		RemoteForward: false,
		LocalForward:  false,
		Cmd:           "",
		Quiet:         false,
		Headless:      false,
	}
	principal, err := NewHopClient(principalConfig)
	assert.NilError(t, err)

	go s.server.Serve()

	go func() {
		//principal starts session with server 1
		err = principal.Connect()
		assert.NilError(t, err)

		//principal handles intent request from delegate
		agreqtube, err := principal.TubeMuxer.Accept()
		assert.NilError(t, err)

		agt := authgrants.NewAuthGrantConn(agreqtube)
		intent, err := agt.GetIntentRequest()
		assert.NilError(t, err)
		logrus.Info("assuming user approves prompt")

		//ask remote
		remoteSession, err := principal.setupRemoteSession(intent)
		assert.NilError(t, err)
		targetAgt, err := authgrants.NewAuthGrantConnFromMux(remoteSession.TubeMuxer)
		assert.NilError(t, err)
		response, err := remoteSession.confirmWithRemote(intent, targetAgt, agt)
		assert.NilError(t, err)
		err = agt.WriteRawBytes(response)
		assert.NilError(t, err)
		agt.Close()
		targetAgt.Close()
	}()

	//server 1 accepts principal connection and starts hopsession
	psconn, err := s.server.AcceptTimeout(1 * time.Minute)
	assert.NilError(t, err)
	psess := &hopSession{
		transportConn: psconn,
		tubeMuxer:     tubes.NewMuxer(psconn, psconn),
		tubeQueue:     make(chan *tubes.Reliable),
		done:          make(chan int),
		server:        s,
	}
	go psess.start()

	// server 1 listens on authsock for Intent requests
	// proxies them to the principal
	go func() {
		c, err := s.authsock.Accept()
		assert.NilError(t, err)
		s.proxyAuthGrantRequest(psess, c)
	}()

	//start hop server 2
	serverConfig2 := &HopServerConfig{
		Port:                     "8888",
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "3",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s2, err := NewHopServer(serverConfig2)
	assert.NilError(t, err)
	go s2.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	//set up delegate client
	delegateConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "2",
		Keypath:       "",
		Hostname:      "127.0.0.1",
		Port:          "8888",
		Username:      u.Username,
		Principal:     false,
		RemoteForward: false,
		LocalForward:  false,
		Cmd:           "echo hello world",
		Quiet:         false,
		Headless:      false,
	}

	delegate := &HopClient{
		TransportConfig: transport.ClientConfig{Verify: delegateConfig.Verify},
		Config:          delegateConfig,
		Primarywg:       sync.WaitGroup{},
	}

	//delegate gets authorization
	delegate.TransportConfig.KeyPair = new(keys.X25519KeyPair)
	delegate.TransportConfig.KeyPair.Generate()

	logrus.Infof("Client generated: %v", delegate.TransportConfig.KeyPair.Public.String())
	logrus.Infof("C: Initiating AGC Protocol.")

	udsconn, err := net.Dial("unix", delegate.Config.SockAddr)
	assert.NilError(t, err)
	logrus.Infof("C: CONNECTED TO UDS: [%v]", udsconn.RemoteAddr().String())
	agc := authgrants.NewAuthGrantConn(udsconn)
	_, err = agc.GetAuthGrant(delegate.TransportConfig.KeyPair.Public, delegate.Config.Username, delegate.Config.Hostname,
		delegate.Config.Port, authgrants.ShellAction, "")
	assert.NilError(t, err)

	//delegate connects to server2
	err = delegate.Connect()
	assert.NilError(t, err)
}

func TestClientNotAuthorized(t *testing.T) {
	logrus.SetOutput(io.Discard)
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	KeyGen(DefaultKeyPath, true)
	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     "7779",
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "4",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	go s.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/mykey" //mykey is not in authorized keys file

	u, e := user.Current()
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "4",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          "7779",
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
	assert.Error(t, err, ErrClientUnauthorized.Error())
}

func TestAuthgrantTimeOut(t *testing.T) {
	logrus.SetOutput(io.Discard)
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	KeyGen(DefaultKeyPath, true)
	//start hop server 1
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     "7780",
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "5",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)

	//start principal
	keypath, _ := os.UserHomeDir()
	keypath += DefaultKeyPath

	u, e := user.Current()
	assert.NilError(t, e)
	principalConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      "",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          "7780",
		Username:      u.Username,
		Principal:     true,
		RemoteForward: false,
		LocalForward:  false,
		Cmd:           "",
		Quiet:         false,
		Headless:      false,
	}
	principal, err := NewHopClient(principalConfig)
	assert.NilError(t, err)

	go s.server.Serve()

	go func() {
		//principal starts session with server 1
		err = principal.Connect()
		assert.NilError(t, err)

		//principal handles intent request from delegate
		agreqtube, err := principal.TubeMuxer.Accept()
		assert.NilError(t, err)

		agt := authgrants.NewAuthGrantConn(agreqtube)
		intent, err := agt.GetIntentRequest()
		assert.NilError(t, err)
		logrus.Info("assuming user approves prompt")

		//ask remote
		remoteSession, err := principal.setupRemoteSession(intent)
		assert.NilError(t, err)
		targetAgt, err := authgrants.NewAuthGrantConnFromMux(remoteSession.TubeMuxer)
		assert.NilError(t, err)
		response, err := remoteSession.confirmWithRemote(intent, targetAgt, agt)
		assert.NilError(t, err)
		err = agt.WriteRawBytes(response)
		assert.NilError(t, err)
		agt.Close()
		targetAgt.Close()
	}()

	//server 1 accepts principal connection and starts hopsession
	psconn, err := s.server.AcceptTimeout(1 * time.Minute)
	assert.NilError(t, err)
	psess := &hopSession{
		transportConn: psconn,
		tubeMuxer:     tubes.NewMuxer(psconn, psconn),
		tubeQueue:     make(chan *tubes.Reliable),
		done:          make(chan int),
		server:        s,
	}
	go psess.start()

	// server 1 listens on authsock for Intent requests
	// proxies them to the principal
	go func() {
		c, err := s.authsock.Accept()
		assert.NilError(t, err)
		s.proxyAuthGrantRequest(psess, c)
	}()

	//start hop server 2
	serverConfig2 := &HopServerConfig{
		Port:                     "8889",
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "6",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s2, err := NewHopServer(serverConfig2)
	assert.NilError(t, err)
	go s2.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	//set up delegate client
	delegateConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "5",
		Keypath:       "",
		Hostname:      "127.0.0.1",
		Port:          "8889",
		Username:      u.Username,
		Principal:     false,
		RemoteForward: false,
		LocalForward:  false,
		Cmd:           "echo hello world",
		Quiet:         false,
		Headless:      false,
	}

	delegate := &HopClient{
		TransportConfig: transport.ClientConfig{Verify: delegateConfig.Verify},
		Config:          delegateConfig,
		Primarywg:       sync.WaitGroup{},
	}

	//delegate gets authorization
	delegate.TransportConfig.KeyPair = new(keys.X25519KeyPair)
	delegate.TransportConfig.KeyPair.Generate()

	logrus.Infof("Client generated: %v", delegate.TransportConfig.KeyPair.Public.String())
	logrus.Infof("C: Initiating AGC Protocol.")

	udsconn, err := net.Dial("unix", delegate.Config.SockAddr)
	assert.NilError(t, err)
	logrus.Infof("C: CONNECTED TO UDS: [%v]", udsconn.RemoteAddr().String())
	agc := authgrants.NewAuthGrantConn(udsconn)
	_, err = agc.GetAuthGrant(delegate.TransportConfig.KeyPair.Public, delegate.Config.Username, delegate.Config.Hostname,
		delegate.Config.Port, authgrants.ShellAction, "")
	assert.NilError(t, err)

	time.Sleep(6 * time.Second) //max is set to 5 seconds

	//delegate connects to server2
	err = delegate.Connect()
	assert.Error(t, err, ErrClientUnauthorized.Error())
}
