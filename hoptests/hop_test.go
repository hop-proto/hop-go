package hoptests

import (
	"net"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"zmap.io/portal/certs"
	"zmap.io/portal/common"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/hopserver"

	"zmap.io/portal/hopclient"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/thunks"
	"zmap.io/portal/transport"
)

// //Defaults and constants for starting a hop session
// const (
// 	DefaultHopPort        = "7777"
// 	DefaultKeyPath        = "/.hop/key"
//
// 	TestDataPathPrefixDef = "../../certs/"

// )
// //NewTestServerConfig populates server config and verify config with sample cert data
// func NewTestServerConfig(testDataPathPrefix string) (*transport.ServerConfig, *transport.VerifyConfig) {
// 	keyPair, err := keys.ReadDHKeyFromPEMFile(testDataPathPrefix + "testdata/leaf-key.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
// 	}
// 	certificate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/leaf.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH CERTS %v", err)
// 	}
// 	intermediate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/intermediate.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
// 	}
// 	root, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/root.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH ROOT CERT %v", err)
// 	}
// 	err = certs.VerifyParent(certificate, intermediate)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}
// 	err = certs.VerifyParent(intermediate, root)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}
// 	err = certs.VerifyParent(root, root)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}

// 	server := transport.ServerConfig{
// 		KeyPair:      keyPair,
// 		Certificate:  certificate,
// 		Intermediate: intermediate,
// 	}
// 	verify := transport.VerifyConfig{
// 		Store: certs.Store{},
// 	}
// 	verify.Store.AddCertificate(root)
// 	return &server, &verify
// }

/*
const howdy = "Howdy! This is connection numero two./n"

func serverSetup(t *testing.T, p string) *HopServer {
	baseConfig, _ := NewTestServerConfig("../certs/")
	transportConfig := *baseConfig
	transportConfig.ClientVerify = nil //no certificate verification at all
	serverConfig := &HopServerConfig{
		SockAddr:                 DefaultHopAuthSocket + p,
		MaxOutstandingAuthgrants: 50,
		AuthorizedKeysLocation:   "/.hop_test/authorized_keys",
	}
	s, err := NewHopServer(serverConfig)
	assert.NilError(t, err)
	return s
}

func principalSetup(t *testing.T, p string, auth bool) *HopClient {
	_, verify := NewTestServerConfig("../certs/")
	keyname := "key" + p
	u, e := user.Current()
	assert.NilError(t, e)
	clientKey, e := KeyGen("/.hop_test", keyname, auth)
	assert.NilError(t, e)
	clientLeafIdentity := certs.Identity{
		PublicKey: clientKey.Public,
		Names:     []certs.Name{certs.RawStringName(u.Username)},
	}
	clientLeaf, err := certs.SelfSignLeaf(&clientLeafIdentity)
	assert.NilError(t, err)

	transportClientConfig := &transport.ClientConfig{
		KeyPair:        clientKey,
		Leaf:           clientLeaf,
		UseCertificate: true,
		Intermediate:   nil,
		Verify:         *verify,
	}
	//set up Hop client
	keypath, _ := os.UserHomeDir()
	keypath += "/.hop_test/" + keyname
	assert.NilError(t, e)
	clientConfig := &HopClientConfig{
		TransportConfig: transportClientConfig,
		Keypath:         keypath,
		Hostname:        "127.0.0.1",
		Port:            p,
		Username:        u.Username,
		Principal:       true,
	}
	client, err := NewHopClient(clientConfig)
	assert.NilError(t, err)
	return client
}

func delegateSetup(t *testing.T, p string, authSockID string) *HopClient {
	_, verify := NewTestServerConfig("../certs/")
	u, e := user.Current()
	assert.NilError(t, e)

	transportClientConfig := &transport.ClientConfig{
		KeyPair:        nil,
		Leaf:           nil,
		UseCertificate: true,
		Intermediate:   nil,
		Verify:         *verify,
	}
	//set up Hop client
	clientConfig := &HopClientConfig{
		TransportConfig: transportClientConfig,
		SockAddr:        DefaultHopAuthSocket + authSockID,
		Hostname:        "127.0.0.1",
		Port:            p,
		Username:        u.Username,
	}
	client, err := NewHopClient(clientConfig)
	assert.NilError(t, err)
	return client
}

//simple client server connect
func TestSimpleClientServer(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()
	client := principalSetup(t, port, true)

	//handshake + user authorization
	err := client.Connect()
	assert.NilError(t, err)
}

//connect fail when key not in authorized_keys
func TestUnauthorizedFail(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()
	client := principalSetup(t, port, false)

	//handshake + user authorization
	err := client.Connect()
	assert.Error(t, err, "client not authorized")
}

func TestAuthgrantOneHop(t *testing.T) {
	port1 := getPort()               //port server 1 (delegate) will listen on
	port2 := getPort()               //port server 2 (target) will listen on
	server1 := serverSetup(t, port1) //server 1 (delegate)
	server2 := serverSetup(t, port2) //server 2 (target)
	principal := principalSetup(t, port1, true)

	//start hop server 2
	go server2.Serve()        //starts transport layer server, authgrant server, and listens for hop conns
	go server1.server.Serve() //start delgate transport layer server (manually handle incoming connection because I can't simulate the delegate client actually being a child process)

	go func() {
		//principal starts session with server 1
		err := principal.Connect()
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
	psconn, err := server1.server.AcceptTimeout(1 * time.Minute)
	assert.NilError(t, err)
	psess := &hopSession{
		transportConn:          psconn,
		tubeMuxer:              tubes.NewMuxer(psconn, psconn),
		tubeQueue:              make(chan *tubes.Reliable),
		done:                   make(chan int),
		server:                 server1,
		authorizedKeysLocation: server1.config.AuthorizedKeysLocation,
	}
	go psess.start()

	// server 1 listens on authsock for Intent requests
	// proxies them to the principal
	go func() {
		c, err := server1.authsock.Accept()
		assert.NilError(t, err)
		server1.proxyAuthGrantRequest(psess, c)
	}()

	delegate := delegateSetup(t, port2, port1)
	err = delegate.Connect()
	assert.NilError(t, err)
}

func TestAuthgrantTimeout(t *testing.T) {
	port1 := getPort()               //port server 1 (delegate) will listen on
	port2 := getPort()               //port server 2 (target) will listen on
	server1 := serverSetup(t, port1) //server 1 (delegate)
	server2 := serverSetup(t, port2) //server 2 (target)
	principal := principalSetup(t, port1, true)

	//start hop server 2
	go server2.Serve()        //starts transport layer server, authgrant server, and listens for hop conns
	go server1.server.Serve() //start delgate transport layer server (manually handle incoming connection because I can't simulate the delegate client actually being a child process)

	go func() {
		//principal starts session with server 1
		err := principal.Connect()
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
		//pause to add delay
		time.Sleep(6 * time.Second) //max set to 5 seconds
		err = agt.WriteRawBytes(response)
		assert.NilError(t, err)
		agt.Close()
		targetAgt.Close()
	}()

	//server 1 accepts principal connection and starts hopsession
	psconn, err := server1.server.AcceptTimeout(1 * time.Minute)
	assert.NilError(t, err)
	psess := &hopSession{
		transportConn:          psconn,
		tubeMuxer:              tubes.NewMuxer(psconn, psconn),
		tubeQueue:              make(chan *tubes.Reliable),
		done:                   make(chan int),
		server:                 server1,
		authorizedKeysLocation: server1.config.AuthorizedKeysLocation,
	}
	go psess.start()

	// server 1 listens on authsock for Intent requests
	// proxies them to the principal
	go func() {
		c, err := server1.authsock.Accept()
		assert.NilError(t, err)
		server1.proxyAuthGrantRequest(psess, c)
	}()

	delegate := delegateSetup(t, port2, port1)
	err = delegate.Connect()
	assert.Error(t, err, ErrClientUnauthorized.Error())
}

func TestRemotePF(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()

	remoteport1 := getPort()
	remoteport2 := getPort()

	client := principalSetup(t, port, true)
	client.config.RemoteArgs = []string{remoteport1 + ":localhost:" + remoteport2}

	err := client.Connect()
	assert.NilError(t, err)

	err = client.remoteForward(client.config.RemoteArgs[0])
	assert.NilError(t, err)

	logrus.Info("simulating a tcp conn")

	parts := strings.Split(client.config.RemoteArgs[0], ":") //assuming port:host:hostport

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
		if string(buf) == howdy {
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
		if string(buf) == howdy {
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
		n, err := ctconn.Write([]byte(howdy))
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

func TestTwoRemotePF(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()

	remoteport1 := getPort()
	remoteport2 := getPort()

	remoteport3 := getPort()
	remoteport4 := getPort()

	client := principalSetup(t, port, true)
	client.config.RemoteArgs = []string{remoteport1 + ":localhost:" + remoteport2, remoteport3 + ":localhost:" + remoteport4}

	err := client.Connect()
	assert.NilError(t, err)

	err = client.remoteForward(client.config.RemoteArgs[0])
	assert.NilError(t, err)

	err = client.remoteForward(client.config.RemoteArgs[1])
	assert.NilError(t, err)

	logrus.Info("simulating a tcp conn")

	parts := strings.Split(client.config.RemoteArgs[0], ":")    //assuming port:host:hostport
	partsTwo := strings.Split(client.config.RemoteArgs[1], ":") //assuming port:host:hostport

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		//simulate program listening on local (target port)
		li, err := net.Listen("tcp", ":"+parts[2])
		logrus.Info("simulating listening program on target: port ", parts[2])
		assert.NilError(t, err)
		wg.Done()
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
		liconn.Close()
	}()

	go func() {
		//simulate program listening on local (target port) (for second arg)
		li, err := net.Listen("tcp", ":"+partsTwo[2])
		logrus.Info("simulating listening program on target: port ", partsTwo[2])
		assert.NilError(t, err)
		wg.Done()
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
		liconn.Close()
	}()

	wg.Wait()

	go func() {
		//simulate a TCP conn to remote port
		logrus.Info("attempting to dial port ", parts[0])
		ctconn, err := net.Dial("tcp", ":"+parts[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("Hi there! this is the first tcp conn./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	go func() {
		//simulate a TCP conn to remote port (2)
		logrus.Info("attempting to dial port ", partsTwo[0])
		ctconn, err := net.Dial("tcp", ":"+partsTwo[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("HI THERE! THIS IS THE FIRST TCP CONN./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	wg.Add(1)
	go func() {

		crft, err := client.TubeMuxer.Accept()
		assert.NilError(t, err)
		assert.Equal(t, crft.Type(), RemotePFTube)

		err = client.handleRemote(crft)
		assert.NilError(t, err)
		logrus.Info("First tube done")
		wg.Done()
	}()

	crft, err := client.TubeMuxer.Accept()
	assert.NilError(t, err)
	assert.Equal(t, crft.Type(), RemotePFTube)

	err = client.handleRemote(crft)
	assert.NilError(t, err)
	wg.Wait()

}

func TestRemotePFListenSocket(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()

	remoteport1 := getPort()
	listensocket := "/tmp/sock" + remoteport1 //just using remoteport1 as a unique id to avoid conflicts in testing
	remoteport2 := getPort()

	client := principalSetup(t, port, true)
	client.config.RemoteArgs = []string{listensocket + ":localhost:" + remoteport2}

	err := client.Connect()
	assert.NilError(t, err)

	err = client.remoteForward(client.config.RemoteArgs[0])
	assert.NilError(t, err)

	logrus.Info("simulating a tcp conn")

	fwdStruct := Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	err = ParseForward(client.config.RemoteArgs[0], &fwdStruct)
	assert.NilError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		//simulate program listening on Connecthost:Connectport
		addr := net.JoinHostPort(fwdStruct.Connecthost, fwdStruct.Connectportorpath)
		li, err := net.Listen("tcp", addr)
		logrus.Info("simulating listening program on target: ", addr)
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
		if string(buf) == howdy {
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
		if string(buf) == howdy {
			logrus.Info("writing Hello")
			liconn.Write([]byte("Hello/n"))
		}
		liconn.Close()
	}()

	wg.Wait()
	go func() {
		//simulate a conn to listening socket
		logrus.Info("attempting to dial socket ", listensocket)
		ctconn, err := net.Dial("unix", listensocket)
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte(howdy))
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
		//simulate another conn to listening socket
		logrus.Info("attempting to dial port ", listensocket)
		ctconn, err := net.Dial("unix", listensocket)
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

func TestLocalPF(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()
	localport1 := getPort()
	localport2 := getPort()

	client := principalSetup(t, port, true)
	client.config.LocalArgs = []string{localport1 + ":127.0.0.1:" + localport2}

	err := client.Connect()
	assert.NilError(t, err)

	err = client.localForward(client.config.LocalArgs[0]) //client listening on localport1
	assert.NilError(t, err)

	parts := strings.Split(client.config.LocalArgs[0], ":") //assuming port:host:hostport

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		//simulate program listening on end dest (host:hostport)
		li, err := net.Listen("tcp", parts[1]+":"+parts[2])
		logrus.Infof("simulating listening program on end dest: addr %v & port %v", parts[1], parts[2])
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
		logrus.Info("program listening on end dest got: ", string(buf[:]))
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
		logrus.Info("program listening on end dest got: ", string(buf[:]))
		if string(buf) == "Howdy! This is connection number two./n" {
			logrus.Info("writing Hello")
			liconn.Write([]byte("Hello/n"))
		}
		liconn.Close()
	}()

	wg.Wait()
	wg.Add(2)

	go func() {
		defer wg.Done()
		//simulate another TCP conn to localport1
		logrus.Info("attempting to dial port ", parts[0])
		ctconn, err := net.Dial("tcp", ":"+parts[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("Hi there! this is the first tcp conn./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	go func() {
		defer wg.Done()
		//simulate a TCP conn to localport
		logrus.Info("simulating a tcp conn to localport1, ", parts[0])
		ctconn, err := net.Dial("tcp", "127.0.0.1:"+parts[0])
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

	wg.Wait()
}

func TestTwoLocalPF(t *testing.T) {
	port := getPort()
	server := serverSetup(t, port)
	go server.Serve()

	localport1 := getPort()
	localport2 := getPort()

	localport3 := getPort()
	localport4 := getPort()

	client := principalSetup(t, port, true)
	client.config.LocalArgs = []string{localport1 + ":localhost:" + localport2, localport3 + ":localhost:" + localport4}

	err := client.Connect()
	assert.NilError(t, err)

	err = client.localForward(client.config.LocalArgs[0])
	assert.NilError(t, err)

	err = client.localForward(client.config.LocalArgs[1])
	assert.NilError(t, err)

	parts := strings.Split(client.config.LocalArgs[0], ":")    //assuming port:host:hostport
	partsTwo := strings.Split(client.config.LocalArgs[1], ":") //assuming port:host:hostport

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		//simulate program listening on end dest (target port)
		li, err := net.Listen("tcp", parts[1]+":"+parts[2])
		logrus.Info("simulating listening program on target: port ", parts[2])
		assert.NilError(t, err)
		wg.Done()
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
		logrus.Info("program listening on end dest got: ", string(buf[:]))
		liconn.Close()
	}()

	go func() {
		//simulate program listening on end dest (target port) (for second arg)
		li, err := net.Listen("tcp", partsTwo[1]+":"+partsTwo[2])
		logrus.Info("simulating listening program on target: port ", partsTwo[2])
		assert.NilError(t, err)
		wg.Done()
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
		logrus.Info("program listening on end dest got: ", string(buf[:]))
		liconn.Close()
	}()

	wg.Wait()
	wg.Add(2)

	go func() {
		defer wg.Done()
		//simulate a TCP conn to localport1
		logrus.Info("attempting to dial port ", parts[0])
		ctconn, err := net.Dial("tcp", ":"+parts[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("Hi there! this is the first tcp conn./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()

	go func() {
		defer wg.Done()
		//simulate a TCP conn to localport3
		logrus.Info("attempting to dial port ", partsTwo[0])
		ctconn, err := net.Dial("tcp", ":"+partsTwo[0])
		assert.NilError(t, err)
		n, err := ctconn.Write([]byte("HI THERE! THIS IS THE FIRST TCP CONN./n"))
		assert.NilError(t, err)
		logrus.Infof("sent %v bytes over tcpconn", n)
		err = ctconn.Close()
		assert.NilError(t, err)
	}()
	wg.Wait()
}
*/

// Suite is a helper type for writing tests
type Suite struct {
	ServerSockPath           string
	LeafKeyPair              *keys.X25519KeyPair
	IntermediateKeyPair      *keys.SigningKeyPair
	RootKeyPair              *keys.SigningKeyPair
	Leaf, Intermediate, Root *certs.Certificate
	Store                    certs.Store

	UDPConn   *net.UDPConn
	Transport *transport.Server
	Server    *hopserver.HopServer
}

func NewSuite(t *testing.T) *Suite {
	s := new(Suite)
	var err error
	s.UDPConn, err = net.ListenUDP("udp", nil)
	assert.NilError(t, err)

	s.LeafKeyPair = keys.GenerateNewX25519KeyPair()
	s.IntermediateKeyPair = keys.GenerateNewSigningKeyPair()
	s.RootKeyPair = keys.GenerateNewSigningKeyPair()

	s.Root, err = certs.SelfSignRoot(certs.SigningIdentity(s.RootKeyPair), s.RootKeyPair)
	s.Root.ProvideKey((*[32]byte)(&s.RootKeyPair.Private))
	assert.NilError(t, err)

	s.Intermediate, err = certs.IssueIntermediate(s.Root, certs.SigningIdentity(s.IntermediateKeyPair))
	s.Intermediate.ProvideKey((*[32]byte)(&s.IntermediateKeyPair.Private))
	assert.NilError(t, err)

	s.Leaf, err = certs.IssueLeaf(s.Intermediate, certs.LeafIdentity(s.LeafKeyPair, certs.DNSName("example.local")))
	assert.NilError(t, err)

	s.Store = certs.Store{}
	s.Store.AddCertificate(s.Root)

	s.Transport, err = transport.NewServer(s.UDPConn, transport.ServerConfig{
		Certificate:  s.Leaf,
		Intermediate: s.Intermediate,
		KeyPair:      s.LeafKeyPair,
	})
	assert.NilError(t, err)

	sc := config.ServerConfig{}

	s.Server, err = hopserver.NewHopServerExt(s.Transport, &sc)
	assert.NilError(t, err)
	return s
}

func (s *Suite) MockServerFS(t *testing.T, fsystem fstest.MapFS) {
	assert.Assert(t, s.Server != nil)
	s.Server.SetFSystem(fsystem) // TODO(baumanl): not sure if a setter is the way to go here
}

func (s *Suite) MockClientFS(t *testing.T, client *hopclient.HopClient, fsystem fstest.MapFS) {
	client.Fsystem = fsystem
}

func (s *Suite) NewClient(t *testing.T, config *config.ClientConfig, hostname string) *hopclient.HopClient {
	c, err := hopclient.NewHopClient(config, hostname)
	assert.NilError(t, err)
	return c
}

func (s *Suite) ChainAuthenticator(t *testing.T, clientKey *keys.X25519KeyPair) core.Authenticator {
	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: clientKey.Public,
	})
	assert.NilError(t, err)
	return core.InMemoryAuthenticator{
		X25519KeyPair: clientKey,
		Leaf:          leaf,
		VerifyConfig: transport.VerifyConfig{
			Store: s.Store,
		},
	}
}

func TestHopClientExtAuthenticator(t *testing.T) {
	thunks.SetUpTest()
	t.Run("connect", func(t *testing.T) {
		s := NewSuite(t)

		h, _, err := net.SplitHostPort(s.Server.ListenAddress().String())
		assert.NilError(t, err)

		cc := config.ClientConfig{
			Hosts: []config.HostConfig{{
				Pattern:  h,
				Hostname: h,
				User:     "username",
			}},
		}
		c := s.NewClient(t, &cc, h)
		clientKey := keys.GenerateNewX25519KeyPair()
		mock := fstest.MapFS{
			"home/username/.hop/authorized_keys": &fstest.MapFile{
				Data: []byte(clientKey.Public.String() + "\n"),
				Mode: 0600,
			},
			"home/username/.hop/hopauth": &fstest.MapFile{},
		}
		s.MockServerFS(t, mock)
		go s.Server.Serve()
		err = c.DialExternalAuthenticator(s.Server.ListenAddress().String(), s.ChainAuthenticator(t, clientKey))
		assert.NilError(t, err)
	})

}

/* The hopclient automatically generates a cert and authenticator from key file */
func TestHopClient(t *testing.T) {
	thunks.SetUpTest()
	t.Run("connect", func(t *testing.T) {
		s := NewSuite(t)

		h, p, err := net.SplitHostPort(s.Server.ListenAddress().String())
		assert.NilError(t, err)
		port, err := strconv.Atoi(p)
		assert.NilError(t, err)
		logrus.Info("Test: ", s.Server.ListenAddress().String())

		cc := config.ClientConfig{
			Hosts: []config.HostConfig{{
				Pattern:      h,
				Hostname:     h,
				Port:         port,
				User:         "username",
				AutoSelfSign: config.True,
				Key:          "home/username/.hop/id_hop.pem",
				DisableAgent: config.True,
			}},
		}
		c := s.NewClient(t, &cc, h)
		clientKey := keys.GenerateNewX25519KeyPair()
		mock := fstest.MapFS{
			"home/username/.hop/authorized_keys": &fstest.MapFile{
				Data: []byte(clientKey.Public.String() + "\n"),
				Mode: 0600,
			},
		}
		s.MockServerFS(t, mock)
		mockClient := fstest.MapFS{
			"home/username/.hop/" + common.DefaultKeyFile: &fstest.MapFile{
				Data: []byte(clientKey.Private.String() + "\n"),
				Mode: 0600,
			},
		}

		c.Fsystem = mockClient
		go s.Server.Serve()
		err = c.Dial()
		assert.NilError(t, err)
	})
}
