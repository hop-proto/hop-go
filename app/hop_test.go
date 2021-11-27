package app

import (
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/keys"
	"zmap.io/portal/ports"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

var start = 18000

var portMutex = sync.Mutex{}

func getPort() string {
	portMutex.Lock()
	port, next := ports.GetPortNumber(start)
	start = next
	portMutex.Unlock()
	return port
}
func TestPortNumbers(t *testing.T) {
	logrus.Info("starting. Init Port number: ", strconv.Itoa(start))
	port1 := getPort()
	logrus.Info("port1: ", port1)
	logrus.Info("ended. Last Port number: ", strconv.Itoa(start))
}

func TestClientServer(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	keyname := "key1"
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	portMutex.Lock()
	KeyGen("/.hop", keyname, true)
	portMutex.Unlock()
	port := getPort()
	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "1",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	go s.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/" + keyname

	u, e := user.Current()
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "1",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          port,
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
	logrus.SetLevel(logrus.ErrorLevel)
	keyname := "key2"
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	portMutex.Lock()
	KeyGen("/.hop", keyname, true)
	portMutex.Unlock()
	port1 := getPort()
	//start hop server 1
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port1,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "2",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)

	//start principal
	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/" + keyname

	u, e := user.Current()
	assert.NilError(t, e)
	principalConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      "",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          port1,
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

	port2 := getPort()
	//start hop server 2
	serverConfig2 := &HopServerConfig{
		Port:                     port2,
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
		Port:          port2,
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
	logrus.SetLevel(logrus.ErrorLevel)
	keyname := "key3"
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//DON'T put public key in /home/user/.hop/authorized_keys
	portMutex.Lock()
	KeyGen("/.hop", keyname, false)
	portMutex.Unlock()
	port1 := getPort()
	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port1,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "4",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	go s.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/" + keyname

	u, e := user.Current()
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "4",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          port1,
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
	logrus.SetLevel(logrus.ErrorLevel)
	keyname := "key4"
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	portMutex.Lock()
	KeyGen("/.hop", keyname, true)
	portMutex.Unlock()
	port1 := getPort()
	//start hop server 1
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port1,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "5",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)

	//start principal
	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/" + keyname

	u, e := user.Current()
	assert.NilError(t, e)
	principalConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      "",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          port1,
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
	port2 := getPort()
	//start hop server 2
	serverConfig2 := &HopServerConfig{
		Port:                     port2,
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
		Port:          port2,
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

func TestRemotePF(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	keyname := "key7"
	//put keys in /home/user/.hop/key + /home/user/.hop/key.pub
	//put public key in /home/user/.hop/authorized_keys
	portMutex.Lock()
	KeyGen("/.hop", keyname, true)
	portMutex.Unlock()
	port := getPort()
	//start hop server
	tconf, verify := NewTestServerConfig("../certs/")
	serverConfig := &HopServerConfig{
		Port:                     port,
		Host:                     "localhost",
		SockAddr:                 DefaultHopAuthSocket + "7",
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	go s.Serve() //starts transport layer server, authgrant server, and listens for hop conns

	keypath, _ := os.UserHomeDir()
	keypath += "/.hop/" + keyname

	remoteport1 := getPort()
	remoteport2 := getPort()

	u, e := user.Current()
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		Verify:        *verify,
		SockAddr:      DefaultHopAuthSocket + "7",
		Keypath:       keypath,
		Hostname:      "127.0.0.1",
		Port:          port,
		Username:      u.Username,
		Principal:     true,
		RemoteForward: true,
		RemoteArgs:    []string{remoteport1 + ":localhost:" + remoteport2},
		LocalForward:  false,
		Cmd:           "",
		Quiet:         false,
		Headless:      false,
	}
	client, err := NewHopClient(clientConfig)
	assert.NilError(t, err)

	err = client.Connect()
	assert.NilError(t, err)

	err = client.remoteForward(client.Config.RemoteArgs[0])
	assert.NilError(t, err)

	logrus.Info("simulating a tcp conn")

	parts := strings.Split(client.Config.RemoteArgs[0], ":") //assuming port:host:hostport

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		//simulate program listening on local (target port)
		li, err := net.Listen("tcp", ":"+parts[2])
		logrus.Info("simulating listening program on target: port ", parts[2])
		wg.Done()
		assert.NilError(t, err)
		liconn, err := li.Accept()
		assert.NilError(t, err)
		buf := make([]byte, 39)
		n := 0
		for n < 39 {
			x, err := liconn.Read(buf[n:])
			logrus.Infof("listening program read %v bytes", x)
			assert.NilError(t, err)
			n += x
		}
		logrus.Info("program listening on target got: ", string(buf[:]))
		if string(buf) == "Howdy! This is connection number two./n" {
			logrus.Info("writing Hello")
			liconn.Write([]byte("Hello/n"))
		}
		liconn.Close()

		logrus.Info("expecting second conn")
		liconn, err = li.Accept()
		assert.NilError(t, err)
		n = 0
		for n < 39 {
			x, err := liconn.Read(buf[n:])
			logrus.Infof("listening program read %v bytes", x)
			assert.NilError(t, err)
			n += x
		}
		logrus.Info("program listening on target got: ", string(buf[:]))
		if string(buf) == "Howdy! This is connection number two./n" {
			logrus.Info("writing Hello")
			liconn.Write([]byte("Hello/n"))
		}
		liconn.Close()
	}()

	wg.Wait()
	go func() {
		//simulate a TCP conn to remote port
		logrus.Info("attempting to dial port ", parts[0])
		ctconn, err := net.Dial("tcp", ":"+parts[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("Howdy! This is connection number two./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn. Waiting for response...", n)
		buf := make([]byte, 7)
		n = 0
		for n < 7 {
			x, err := ctconn.Read(buf[n:])
			logrus.Infof("response read %v bytes", x)
			assert.NilError(t, err)
			n += x
		}
		logrus.Info("2nd tcp initiator got: ", string(buf))
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	go func() {
		//simulate another TCP conn to remote port
		logrus.Info("attempting to dial port ", parts[0])
		ctconn, err := net.Dial("tcp", ":"+parts[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("Hi there! this is the first tcp conn./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	crft, err := client.TubeMuxer.Accept()
	assert.NilError(t, err)
	assert.Equal(t, crft.Type(), RemotePFTube)

	err = client.handleRemote(crft)
	assert.NilError(t, err)
	logrus.Info("First tube done")

	crft, err = client.TubeMuxer.Accept()
	assert.NilError(t, err)
	assert.Equal(t, crft.Type(), RemotePFTube)

	err = client.handleRemote(crft)
	assert.NilError(t, err)

}
