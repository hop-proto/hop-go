// Package hopclient provides functions to run hop client
package hopclient

import (
	"errors"
	"io"
	"sync"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/common"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

// HopClient holds state for client's perspective of session. It is not safe to
// copy a HopClient.
type HopClient struct { // nolint:maligned
	m  sync.Mutex     // must be held whenever changing state (connecting)
	wg sync.WaitGroup // incremented while a connection opens, decremented when it ends

	connected     bool // true if connected to address
	authenticator core.Authenticator

	TransportConn *transport.Client
	ProxyConn     *tubes.Reliable

	TubeMuxer *tubes.Muxer
	ExecTube  *codex.ExecTube

	// Proxied bool   // TODO(baumanl): put in config probably
	// address string // TODO(baumanl): what exactly is this? address string or real address or hop url??? does it need to be here or could it be in the config

	// TODO(baumanl): does the hop client actually need all of the Hosts slice if
	// it is just connecting to one? In general I think they won't be used, but
	// could be useful for creating a config during authorization grant protocol
	config     config.ClientConfig
	hostconfig config.HostConfig // TODO(baumanl): better to have a single representation with just the ClientConfig information & the host specific information
}

// TODO (baumanl): this whole struct feels very redundant
// it is basically just a copy of some of the config.ClientConfig
// However, if we want hopclient to be a stand alone library then
// we shouldn't depend on having a config file. Maybe some decomp though???

// Config holds configuration options for hop client
// type Config struct {
// 	// TODO (baumanl): delete/refine this
// 	User string //necessary?
// 	// Leaf *certs.Certificate

// 	SockAddr   string
// 	LocalArgs  []string
// 	RemoteArgs []string
// 	Cmd        string

// 	NonPricipal bool // TODO(dadrian): Rename. What's the name for a non-principal connection? IsAuthGranted?
// 	Headless    bool
// }

// NewHopClient creates a new client object and loads keys from file or auth grant protocol
func NewHopClient(config *config.ClientConfig, hostname string) (*HopClient, error) {
	client := &HopClient{
		config:     *config,
		hostconfig: *config.MatchHost(hostname), // TODO(baumanl): don't love this
		wg:         sync.WaitGroup{},
		// Proxied:    false,
	}
	// if !config.NonPricipal {
	// 	// Do nothing, keys are passed at Dial time
	// } else {
	// 	err := client.getAuthorization()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	return client, nil
}

// Dial connects to an address with the provided authentication.
func (c *HopClient) Dial(address string, authenticator core.Authenticator) error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.connectLocked(address, authenticator)
}

func (c *HopClient) connectLocked(address string, authenticator core.Authenticator) error {
	if c.connected {
		return errors.New("already connected")
	}
	err := c.startUnderlying(address, authenticator)
	if err != nil {
		return err
	}
	// TODO(baumanl): Is there something wrong with doing this?
	// This would allow for the same authenticator to be used again during the
	// authgrant procedure.
	// c.address = address
	c.authenticator = authenticator
	c.TubeMuxer = tubes.NewMuxer(c.TransportConn, c.TransportConn)
	go c.TubeMuxer.Start()
	err = c.userAuthorization()
	if err != nil {
		return err
	}
	c.connected = true
	return nil
}

//Start starts any port forwarding/cmds/shells from the client
func (c *HopClient) Start() error {
	//TODO(baumanl): fix how session duration tied to cmd duration or port
	//forwarding duration depending on options

	// if len(c.config.RemoteArgs) > 0 {
	// 	for _, v := range c.config.RemoteArgs {
	// 		if c.config.Headless {
	// 			c.wg.Add(1)
	// 		}
	// 		go func(arg string) {
	// 			if c.config.Headless {
	// 				defer c.wg.Done()
	// 			}
	// 			logrus.Info("Calling remote forward with arg: ", arg)
	// 			e := c.remoteForward(arg)
	// 			if e != nil {
	// 				logrus.Error(e)
	// 			}

	// 		}(v)
	// 	}
	// }
	// if len(c.config.LocalArgs) > 0 {
	// 	for _, v := range c.config.LocalArgs {
	// 		if c.config.Headless {
	// 			c.wg.Add(1)
	// 		}
	// 		go func(arg string) {
	// 			if c.config.Headless {
	// 				defer c.wg.Done()
	// 			}
	// 			e := c.localForward(arg)
	// 			if e != nil {
	// 				logrus.Error(e)
	// 			}
	// 		}(v)
	// 	}
	// }
	// if !c.config.Headless {
	err := c.startExecTube()
	if err != nil {
		logrus.Error(err)
		return ErrClientStartingExecTube
	}
	// }

	// handle incoming tubes
	go c.HandleTubes()
	c.Wait() //client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
	return nil
}

//Wait blocks until the client has finished (usually used when waiting for a session tied to cmd/shell to finish)
func (c *HopClient) Wait() {
	c.wg.Wait()
}

//Close explicitly closes down hop session (usually used after PF is down and can be terminated)
func (c *HopClient) Close() error {
	panic("not implemented")
	//close all remote and local port forwarding relationships
}

func (c *HopClient) getAuthorization() error {
	/*
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
	*/
	panic("unimplemented")
}

func (c *HopClient) startUnderlying(address string, authenticator core.Authenticator) error {
	// TODO(dadrian): Update this once the authenticator interface is set.
	transportConfig := transport.ClientConfig{
		Exchanger: authenticator,
		Verify:    authenticator.GetVerifyConfig(),
		Leaf:      authenticator.GetLeaf(),
	}
	var err error
	// if !c.Proxied {
	c.TransportConn, err = transport.Dial("udp", address, transportConfig)
	// } else {
	// 	c.TransportConn, err = transport.DialNP("netproxy", address, c.ProxyConn, transportConfig)
	// }
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		return err
	}

	// TODO(dadrian): This hangs if the server is not available when it starts.
	// Transport needs to be set with a timeout.
	err = c.TransportConn.Handshake()
	if err != nil {
		logrus.Errorf("C: Issue with handshake: %v", err)
		return err
	}
	return nil
}

func (c *HopClient) userAuthorization() error {
	//*****PERFORM USER AUTHORIZATION******
	uaCh, _ := c.TubeMuxer.CreateTube(common.UserAuthTube)
	defer uaCh.Close()
	if ok := userauth.RequestAuthorization(uaCh, c.hostconfig.User); !ok {
		return ErrClientUnauthorized
	}
	logrus.Info("User authorization complete")
	return nil
}

func (c *HopClient) startExecTube() error {
	//*****RUN COMMAND (BASH OR AG ACTION)*****
	//Hop Session is tied to the life of this code execution tube.
	// TODO(baumanl): provide support for Cmd in ClientConfig

	logrus.Infof("Performing action: %v", c.hostconfig.Cmd)
	ch, err := c.TubeMuxer.CreateTube(common.ExecTube)
	if err != nil {
		logrus.Error(err)
		return err
	}
	c.wg.Add(1)
	c.ExecTube, err = codex.NewExecTube(c.hostconfig.Cmd, ch, &c.wg)
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
		logrus.Infof("ACCEPTED NEW TUBE OF TYPE: %v", t.Type())
		if t.Type() == common.AuthGrantTube && c.hostconfig.Headless {
			go c.principal(t)
		} else if t.Type() == common.RemotePFTube {
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
	var remoteSession *HopClient
	var targetAgt *authgrants.AuthGrantConn

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
