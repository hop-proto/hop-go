//Package app provides functions to run hop client and hop server
package app

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/certs"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/netproxy"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

//HopClient holds state for client's perspective of session
type HopClient struct {
	TransportConn *transport.Client
	ProxyConn     *tubes.Reliable
	TubeMuxer     *tubes.Muxer
	ExecTube      *codex.ExecTube
	Config        *HopClientConfig
	Proxied       bool
	Primarywg     sync.WaitGroup
}

//HopClientConfig holds configuration options for hop client
type HopClientConfig struct {
	Principal       bool
	Quiet           bool
	Headless        bool
	TransportConfig *transport.ClientConfig
	SockAddr        string
	Keypath         string
	Username        string
	Hostname        string
	Port            string
	LocalArgs       []string
	RemoteArgs      []string
	Cmd             string
}

//NewHopClient creates a new client object and loads keys from file or auth grant protocol
func NewHopClient(cConfig *HopClientConfig) (*HopClient, error) {
	client := &HopClient{
		Config:    cConfig,
		Primarywg: sync.WaitGroup{},
		Proxied:   false,
	}
	if cConfig.Principal {
		err := client.LoadKeys(cConfig.Keypath) //read keys and generate a self signed cert
		if err != nil {
			return nil, err
		}
	} else {
		err := client.getAuthorization()
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

//Connect starts hop transport, tube muxer, conducts user authorization
func (c *HopClient) Connect() error {
	err := c.startUnderlying()
	if err != nil {
		return err
	}
	c.TubeMuxer = tubes.NewMuxer(c.TransportConn, c.TransportConn)
	go c.TubeMuxer.Start()
	err = c.userAuthorization()
	if err != nil {
		return err
	}
	return nil
}

//Start starts any port forwarding/cmds/shells from the client
func (c *HopClient) Start() error {
	//TODO(baumanl): fix how session duration tied to cmd duration or port forwarding duration depending on options
	if len(c.Config.RemoteArgs) > 0 {
		for _, v := range c.Config.RemoteArgs {
			if c.Config.Headless {
				c.Primarywg.Add(1)
			}
			go func(arg string) {
				if c.Config.Headless {
					defer c.Primarywg.Done()
				}
				logrus.Info("Calling remote forward with arg: ", arg)
				e := c.remoteForward(arg)
				if e != nil {
					logrus.Error(e)
				}

			}(v)
		}
	}
	if len(c.Config.LocalArgs) > 0 {
		for _, v := range c.Config.LocalArgs {
			if c.Config.Headless {
				c.Primarywg.Add(1)
			}
			go func(arg string) {
				if c.Config.Headless {
					defer c.Primarywg.Done()
				}
				e := c.localForward(arg)
				if e != nil {
					logrus.Error(e)
				}
			}(v)
		}
	}
	if !c.Config.Headless {
		err := c.startExecTube()
		if err != nil {
			logrus.Error(err)
			return ErrClientStartingExecTube
		}
	}
	return nil
}

//Wait blocks until the client has finished (usually used when waiting for a session tied to cmd/shell to finish)
func (c *HopClient) Wait() {
	c.Primarywg.Wait()
}

//Close explicitly closes down hop session (usually used after PF is down and can be terminated)
func (c *HopClient) Close() error {
	panic("not implemented")
	//close all remote and local port forwarding relationships
}

//LoadKeys reads keys from provided file location and stores them in sess.Config.KeyPair
func (c *HopClient) LoadKeys(keypath string) error {
	logrus.Infof("C: Using key-file at %v for auth.", keypath)
	pair, e := keys.ReadDHKeyFromPEMFile(keypath)
	if e != nil {
		return e
	}
	names := []certs.Name{certs.RawStringName(c.Config.Username)}
	clientLeafIdentity := certs.Identity{
		PublicKey: pair.Public,
		Names:     names,
	}
	clientLeaf, err := certs.SelfSignLeaf(&clientLeafIdentity)
	if err != nil {
		return err
	}
	c.Config.TransportConfig.KeyPair = pair
	c.Config.TransportConfig.Leaf = clientLeaf
	c.Config.TransportConfig.Intermediate = nil
	return nil
}

func (c *HopClient) getAuthorization() error {
	clientKey := keys.GenerateNewX25519KeyPair()
	c.Config.TransportConfig.KeyPair = clientKey
	clientLeafIdentity := certs.Identity{
		PublicKey: clientKey.Public,
		Names:     []certs.Name{certs.RawStringName(c.Config.Username)},
	}
	clientLeaf, err := certs.SelfSignLeaf(&clientLeafIdentity)
	c.Config.TransportConfig.Leaf = clientLeaf
	if err != nil {
		return nil
	}

	logrus.Infof("Client generated: %v", c.Config.TransportConfig.KeyPair.Public.String())
	logrus.Infof("C: Initiating AGC Protocol.")

	udsconn, err := net.Dial("unix", c.Config.SockAddr)
	if err != nil {
		return err
	}
	logrus.Infof("C: CONNECTED TO UDS: [%v]", udsconn.RemoteAddr().String())
	agc := authgrants.NewAuthGrantConn(udsconn)
	defer agc.Close()
	if !c.Config.Headless && c.Config.Cmd == "" { //shell
		t, e := agc.GetAuthGrant(c.Config.TransportConfig.KeyPair.Public, c.Config.Username, c.Config.Hostname,
			c.Config.Port, authgrants.ShellAction, "")
		if e == nil {
			logrus.Infof("C: Principal approved request to open a shell. Deadline: %v", t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	if !c.Config.Headless && c.Config.Cmd != "" { //cmd
		t, e := agc.GetAuthGrant(c.Config.TransportConfig.KeyPair.Public, c.Config.Username, c.Config.Hostname,
			c.Config.Port, authgrants.CommandAction, c.Config.Cmd)
		if e == nil {
			logrus.Infof("C: Principal approved request to run cmd: %v. Deadline: %v", c.Config.Cmd, t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	if len(c.Config.LocalArgs) > 0 { //local forwarding
		for _, v := range c.Config.LocalArgs {
			t, e := agc.GetAuthGrant(c.Config.TransportConfig.KeyPair.Public, c.Config.Username, c.Config.Hostname,
				c.Config.Port, authgrants.LocalPFAction, v)
			if e == nil {
				logrus.Infof("C: Principal approved request to do local forwarding for %v. Deadline: %v", v, t)
			} else if e != authgrants.ErrIntentDenied {
				return e
			}
		}
	}
	if len(c.Config.RemoteArgs) > 0 { //remote forwarding
		for _, v := range c.Config.RemoteArgs {
			t, e := agc.GetAuthGrant(c.Config.TransportConfig.KeyPair.Public, c.Config.Username, c.Config.Hostname,
				c.Config.Port, authgrants.RemotePFAction, v)
			if e == nil {
				logrus.Infof("C: Principal approved request to do remote forwarding for %v. Deadline: %v", v, t)
			} else if e != authgrants.ErrIntentDenied {
				return e
			}
		}
	}
	return nil
}

func (c *HopClient) startUnderlying() error {
	//logrus.SetLevel(logrus.DebugLevel)
	//******ESTABLISH HOP SESSION******
	//TODO(baumanl): figure out addr format requirements + check for them above
	addr := c.Config.Hostname + ":" + c.Config.Port
	if _, err := net.LookupAddr(addr); err != nil {
		//Couldn't resolve address with local resolver
		if ip, ok := hostToIPAddr[c.Config.Hostname]; ok {
			addr = ip + ":" + c.Config.Port
		}
	}
	var err error
	if !c.Proxied {
		c.TransportConn, err = transport.Dial("udp", addr, *c.Config.TransportConfig) //There seem to be limits on Dial() and addr format
	} else {
		c.TransportConn, err = transport.DialNP("netproxy", addr, c.ProxyConn, *c.Config.TransportConfig)
	}
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		return err
	}
	err = c.TransportConn.Handshake() //This hangs if the server is not available when it starts. Add retry or timeout?
	if err != nil {
		logrus.Errorf("C: Issue with handshake: %v", err)
		return err
	}
	return nil
}

func (c *HopClient) userAuthorization() error {
	//*****PERFORM USER AUTHORIZATION******
	uaCh, _ := c.TubeMuxer.CreateTube(UserAuthTube)
	defer uaCh.Close()
	if ok := userauth.RequestAuthorization(uaCh, c.Config.Username); !ok {
		return ErrClientUnauthorized
	}
	logrus.Info("User authorization complete")
	return nil
}

// reroutes remote port forwarding connections to the appropriate destination
// TODO(baumanl): add ability to handle multiple PF relationships
func (c *HopClient) handleRemote(tube *tubes.Reliable) error {
	defer tube.Close()
	//if multiple remote pf relationships, figure out which one this corresponds to
	b := make([]byte, 4)
	tube.Read(b)
	l := binary.BigEndian.Uint32(b[0:4])
	logrus.Infof("Expecting %v bytes", l)
	init := make([]byte, l)
	tube.Read(init)
	arg := string(init)
	found := false
	for _, v := range c.Config.RemoteArgs {
		if v == arg {
			found = true
		}
	}
	if !found {
		logrus.Error()
	}
	tube.Write([]byte{netproxy.NpcConf})

	//handle another remote pf conn (rewire to dest)
	logrus.Info("Doing remote with: ", arg)

	fwdStruct := Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	err := ParseForward(arg, &fwdStruct)
	if err != nil {
		return err
	}

	var tconn net.Conn
	if !fwdStruct.Connectsock {
		addr := net.JoinHostPort(fwdStruct.Connecthost, fwdStruct.Connectportorpath)
		if _, err := net.LookupAddr(addr); err != nil {
			//Couldn't resolve address with local resolver
			h, p, e := net.SplitHostPort(addr)
			if e != nil {
				logrus.Error(e)
				return e
			}
			if ip, ok := hostToIPAddr[h]; ok {
				addr = ip + ":" + p
			}
		}
		logrus.Infof("dialing dest: %v", addr)
		tconn, err = net.Dial("tcp", addr)
	} else {
		logrus.Infof("dialing dest: %v", fwdStruct.Connectportorpath)
		tconn, err = net.Dial("unix", fwdStruct.Connectportorpath)
	}
	if err != nil {
		logrus.Error(err)
		return err
	}

	wg := sync.WaitGroup{}
	//do remote port forwarding
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(tube, tconn)
		logrus.Infof("Copied %v bytes from tconn to tube", n)
	}()

	n, _ := io.Copy(tconn, tube)
	tconn.Close()
	logrus.Infof("Copied %v bytes from tube to tconn", n)
	wg.Wait()
	return nil
}

// client initiates remote port forwarding and sends the server the info it needs
func (c *HopClient) remoteForward(arg string) error {
	logrus.Info("Setting up remote with: ", arg)
	npt, e := c.TubeMuxer.CreateTube(RemotePFTube)
	if e != nil {
		return e
	}
	e = netproxy.Start(npt, arg, netproxy.Remote)
	return e
}

func (c *HopClient) localForward(arg string) error {
	logrus.Info("Doing local with: ", arg)
	fwdStruct := Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	err := ParseForward(arg, &fwdStruct)
	if err != nil {
		return err
	}
	var local net.Listener
	if !fwdStruct.Listensock { //bind to local address
		localAddr := net.JoinHostPort(fwdStruct.Listenhost, fwdStruct.Listenportorpath)
		local, err = net.Listen("tcp", localAddr)
		if err != nil {
			logrus.Error("host:port listen error: ", err)
			return err
		}
	} else {
		local, err = net.Listen("unix", fwdStruct.Listenportorpath)
		if err != nil {
			logrus.Error("socket listen error: ", err)
			return err
		}
	}

	go func() {
		//do local port forwarding
		if c.Config.Headless {
			defer c.Primarywg.Done()
		}
		//accept incoming connections
		regchan := make(chan net.Conn)
		go func() {
			for {
				localConn, e := local.Accept()
				if e != nil {
					logrus.Error(e)
					break
				}
				logrus.Info("Accepted TCPConn...")
				regchan <- localConn
			}
		}()

		for {
			lconn := <-regchan
			go func() { //start tube with server for new connection
				npt, e := c.TubeMuxer.CreateTube(LocalPFTube)
				if e != nil {
					return
				}
				defer npt.Close()
				e = netproxy.Start(npt, arg, netproxy.Local)
				if e != nil {
					return
				}
				if c.Config.Headless {
					c.Primarywg.Add(1)
				}
				go func() {
					n, _ := io.Copy(npt, lconn)
					npt.Close()
					logrus.Debugf("Copied %v bytes from lconn to npt", n)
					logrus.Info("tconn ended")
				}()
				n, _ := io.Copy(lconn, npt)
				lconn.Close()
				logrus.Debugf("Copied %v bytes from npt to lconn", n)
			}()
		}
	}()
	return nil
}

func (c *HopClient) startExecTube() error {
	//*****RUN COMMAND (BASH OR AG ACTION)*****
	//Hop Session is tied to the life of this code execution tube.
	logrus.Infof("Performing action: %v", c.Config.Cmd)
	ch, err := c.TubeMuxer.CreateTube(ExecTube)
	if err != nil {
		logrus.Error(err)
		return err
	}
	c.Primarywg.Add(1)
	c.ExecTube, err = codex.NewExecTube(c.Config.Cmd, ch, &c.Primarywg)
	return err
}

//HandleTubes handles incoming tube requests to the client
func (c *HopClient) HandleTubes() {
	//TODO(baumanl): figure out responses to different tube types/what all should be allowed
	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	for {
		t, e := c.TubeMuxer.Accept()
		if e != nil {
			logrus.Errorf("Error accepting tube: %v", e)
			continue
		}
		logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", t.Type())
		if t.Type() == AuthGrantTube && c.Config.Headless {
			go c.principal(t)
		} else if t.Type() == RemotePFTube {
			go c.handleRemote(t)
		} else {
			//Client only expects to receive AuthGrantTubes. All other tube requests are ignored.
			e := t.Close()
			if e != nil {
				logrus.Errorf("Error closing tube: %v", e)
			}
			continue
		}
	}
	/*
		switch {
		case <- mux.Stop()
		case <- mux.Accept()
		}
	*/
}

func (c *HopClient) principal(tube *tubes.Reliable) {
	defer tube.Close()
	logrus.SetOutput(io.Discard)
	agt := authgrants.NewAuthGrantConn(tube)
	var remoteSession *HopClient = nil
	var targetAgt *authgrants.AuthGrantConn = nil

	for { //allows for user to retry sending intent request if denied
		intent, err := agt.GetIntentRequest()
		if err != nil { //when the agt is closed this will error out
			logrus.Error("error getting intent request")
			return
		}
		//logrus.SetOutput(os.Stdout)
		c.ExecTube.Restore()
		r := c.ExecTube.Redirect()

		allow := intent.Prompt(r)

		c.ExecTube.Raw()
		c.ExecTube.Resume()
		//logrus.SetOutput(io.Discard)
		if !allow {
			agt.SendIntentDenied("User denied")
			continue
		}
		if remoteSession == nil {
			remoteSession, err = c.setupRemoteSession(intent)
			if err != nil {
				logrus.Errorf("error getting remote session from principal: %v", err)
				agt.SendIntentDenied("Unable to connect to remote server")
				break
			}
			targetAgt, err = authgrants.NewAuthGrantConnFromMux(remoteSession.TubeMuxer)
			if err != nil {
				logrus.Fatal("Error creating AGC: ", err)
			}
			defer targetAgt.Close()
			logrus.Info("CREATED AGC")
		}
		response, err := remoteSession.confirmWithRemote(intent, targetAgt, agt)
		if err != nil {
			logrus.Error("error getting confirmation from remote server")
			agt.SendIntentDenied("Unable to connect to remote server")
			break
		}
		//write response back to server asking for Authorization Grant
		err = agt.WriteRawBytes(response)
		if err != nil {
			logrus.Errorf("C: error writing to agt: %v", err)
			break
		}
	}
}

//start session between principal and target proxied through the delegate
func (c *HopClient) setupRemoteSession(req *authgrants.Intent) (*HopClient, error) {
	logrus.Info("C: USER CONFIRMED FIRST INTENT_REQUEST. CONTACTING S2...")

	//create netproxy with server
	npt, e := c.TubeMuxer.CreateTube(NetProxyTube)
	logrus.Info("started netproxy tube from principal")
	if e != nil {
		logrus.Fatal("C: Error starting netproxy tube")
	}

	hostname, port := req.Address()
	addr := hostname + ":" + port
	e = netproxy.Start(npt, addr, netproxy.AG)
	if e != nil {
		logrus.Error("Issue proxying connection")
		return nil, e
	}

	subConfig := c.Config
	subConfig.Hostname = hostname
	subConfig.Port = port
	subConfig.Username = req.Username()
	subsess, err := NewHopClient(subConfig)
	if err != nil {
		logrus.Error("Issue creating client")
		return nil, err
	}
	subsess.Proxied = true
	subsess.ProxyConn = npt

	e = subsess.startUnderlying()
	if e != nil {
		logrus.Error("Issue starting underlying connection")
		return nil, e
	}
	subsess.TubeMuxer = tubes.NewMuxer(subsess.TransportConn, subsess.TransportConn)
	go subsess.TubeMuxer.Start()

	e = subsess.userAuthorization()
	if e != nil {
		logrus.Error("Failed user authorization")
		return nil, e
	}
	// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
	// TODO(baumanl): Simplify this. Should only get authorization grant tubes?
	go subsess.HandleTubes()

	return subsess, nil
}

//start an authorization grant connection with the remote server and send intent request. return response.
func (c *HopClient) confirmWithRemote(req *authgrants.Intent, npAgc *authgrants.AuthGrantConn, agt *authgrants.AuthGrantConn) ([]byte, error) {
	//send INTENT_COMMUNICATION
	e := npAgc.SendIntentCommunication(req)
	if e != nil {
		logrus.Info("Issue writing intent comm to netproxyAgc")
	}
	logrus.Info("sent intent comm")
	_, response, e := npAgc.ReadResponse()
	if e != nil {
		logrus.Errorf("C: error reading from agc: %v", e)
		return nil, e
	}
	logrus.Info("got response")
	return response, nil
}
