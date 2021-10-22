package app

import (
	"io"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/netproxy"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

type session struct {
	transportConn *transport.Client
	proxyConn     *tubes.Reliable
	tubeMuxer     *tubes.Muxer
	execTube      *codex.ExecTube
	isPrincipal   bool
	headless      bool
	proxied       bool

	primarywg sync.WaitGroup
	config    transport.ClientConfig
}

func (sess *session) loadKeys(keypath string) error {
	logrus.Infof("C: Using key-file at %v for auth.", keypath)
	pair, e := keys.ReadDHKeyFromPEMFile(keypath)
	if e != nil {
		return e
	}
	sess.config.KeyPair = pair
	return nil
}

func (sess *session) getAuthorization(username string, hostname string, port string,
	headless bool, cmd string, local bool, localArg string, remote bool, remoteArg string) error {
	sess.config.KeyPair = new(keys.X25519KeyPair)
	sess.config.KeyPair.Generate()

	logrus.Infof("Client generated: %v", sess.config.KeyPair.Public.String())
	logrus.Infof("C: Initiating AGC Protocol.")

	c, err := net.Dial("unix", defaultHopAuthSocket)
	if err != nil {
		return err
	}
	logrus.Infof("C: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	agc := authgrants.NewAuthGrantConn(c)
	defer agc.Close()
	if !headless && cmd == "" { //shell
		t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, authgrants.ShellGrant, "")
		if e == nil {
			logrus.Infof("C: Principal approved request to open a shell. Deadline: %v", t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	if !headless && cmd != "" { //cmd
		t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, authgrants.CommandGrant, cmd)
		if e == nil {
			logrus.Infof("C: Principal approved request to run cmd: %v. Deadline: %v", cmd, t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	if local { //local forwarding
		t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, authgrants.LocalGrant, localArg)
		if e == nil {
			logrus.Infof("C: Principal approved request to do local forwarding. Deadline: %v", t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	if remote { //remote forwarding
		t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, authgrants.RemoteGrant, remoteArg)
		if e == nil {
			logrus.Infof("C: Principal approved request to do remote forwarding. Deadline: %v", t)
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
	}
	return nil
}

func (sess *session) startUnderlying(hostname string, port string) error {
	//******ESTABLISH HOP SESSION******
	//TODO(baumanl): figure out addr format requirements + check for them above
	addr := hostname + ":" + port
	if _, err := net.LookupAddr(addr); err != nil {
		//Couldn't resolve address with local resolver
		if ip, ok := hostToIPAddr[hostname]; ok {
			addr = ip + ":" + port
		}
	}
	var err error
	if !sess.proxied {
		sess.transportConn, err = transport.Dial("udp", addr, sess.config) //There seem to be limits on Dial() and addr format
	} else {
		sess.transportConn, err = transport.DialNP("netproxy", addr, sess.proxyConn, sess.config)
	}
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		return err
	}
	err = sess.transportConn.Handshake() //This hangs if the server is not available when it starts. Add retry or timeout?
	if err != nil {
		logrus.Errorf("C: Issue with handshake: %v", err)
		return err
	}
	return nil
}

func (sess *session) userAuthorization(username string) error {
	//*****PERFORM USER AUTHORIZATION******
	uaCh, _ := sess.tubeMuxer.CreateTube(tubes.UserAuthTube)
	defer uaCh.Close()
	if ok := userauth.RequestAuthorization(uaCh, username); !ok {
		return ErrClientUnauthorized
	}
	logrus.Info("User authorization complete")
	return nil
}

func (sess *session) remoteForward(parts []string) error {
	localPort := parts[2]
	remotePort := parts[0]
	npt, e := sess.tubeMuxer.CreateTube(tubes.NetProxyTube)
	if e != nil {
		return e
	}
	e = netproxy.Start(npt, remotePort, netproxy.Remote)
	if e != nil {
		return e
	}

	//TODO: fix address (not just local host)
	//TODO: add bind address options
	tconn, e := net.Dial("tcp", "localhost:"+localPort)
	if e != nil {
		logrus.Error(e)
		return e
	}
	//do remote port forwarding
	go func() {
		io.Copy(tconn, npt)
	}()
	io.Copy(npt, tconn)
	return nil
}

func (sess *session) localForward(parts []string) error {
	remoteAddr := net.JoinHostPort(parts[1], parts[2])
	npt, e := sess.tubeMuxer.CreateTube(tubes.NetProxyTube)
	if e != nil {
		return e
	}
	e = netproxy.Start(npt, remoteAddr, netproxy.Local)
	if e != nil {
		return e
	}
	if sess.headless {
		sess.primarywg.Add(1)
	}
	//do local port forwarding
	go func() {
		if sess.headless {
			defer sess.primarywg.Done()
		}

		local, e := net.Listen("tcp", ":"+strings.Trim(parts[0], ":"))
		if e != nil {
			logrus.Error(e)
			return
		}
		for {
			localConn, e := local.Accept()
			if e != nil {
				logrus.Error(e)
				break
			}
			go io.Copy(npt, localConn)
		}
	}()
	return nil
}

func (sess *session) startExecTube(cmd string) error {
	//*****RUN COMMAND (BASH OR AG ACTION)*****
	//Hop Session is tied to the life of this code execution tube.
	logrus.Infof("Performing action: %v", cmd)
	ch, err := sess.tubeMuxer.CreateTube(tubes.ExecTube)
	if err != nil {
		logrus.Error(err)
		return err
	}
	sess.primarywg.Add(1)
	sess.execTube, err = codex.NewExecTube(cmd, ch, &sess.primarywg)
	return err
}

func (sess *session) handleTubes() {
	//TODO(baumanl): figure out responses to different tube types/what all should be allowed
	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	for {
		c, e := sess.tubeMuxer.Accept()
		if e != nil {
			logrus.Errorf("Error accepting tube: %v", e)
			continue
		}
		logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", c.Type())
		if c.Type() == tubes.AuthGrantTube && sess.isPrincipal {
			go sess.principal(c)
		} else {
			//Client only expects to receive AuthGrantTubes. All other tube requests are ignored.
			e := c.Close()
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

func (sess *session) principal(tube *tubes.Reliable) {
	defer tube.Close()
	logrus.SetOutput(io.Discard)
	agt := authgrants.NewAuthGrantConn(tube)
	var remoteSession *session = nil

	for { //allows for user to retry sending intent request if denied
		intent, err := agt.GetIntentRequest()
		if err != nil { //when the agt is closed this will error out
			logrus.Error("error getting intent request")
			return
		}
		//logrus.SetOutput(os.Stdout)
		sess.execTube.Restore()
		r := sess.execTube.Redirect()

		allow := intent.Prompt(r)

		sess.execTube.Raw()
		sess.execTube.Resume()
		//logrus.SetOutput(io.Discard)
		if !allow {
			agt.SendIntentDenied("User denied")
			continue
		}
		if remoteSession == nil {
			remoteSession, err = sess.setupRemoteSession(intent)
			if err != nil {
				logrus.Errorf("error getting remote session from principal: %v", err)
				agt.SendIntentDenied("Unable to connect to remote server")
				break
			}
		}
		response, err := remoteSession.confirmWithRemote(intent, agt)
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
func (sess *session) setupRemoteSession(req *authgrants.Intent) (*session, error) {
	logrus.Debug("C: USER CONFIRMED FIRST INTENT_REQUEST. CONTACTING S2...")

	//create netproxy with server
	npt, e := sess.tubeMuxer.CreateTube(tubes.NetProxyTube)
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
	subsess := &session{
		isPrincipal: true,
		config:      sess.config,
		proxyConn:   npt,
	}

	e = subsess.startUnderlying(hostname, port)
	if e != nil {
		logrus.Error("Issue starting underlying connection")
		return nil, e
	}
	subsess.tubeMuxer = tubes.NewMuxer(subsess.transportConn, subsess.transportConn)
	go subsess.tubeMuxer.Start()

	e = subsess.userAuthorization(req.Username())
	if e != nil {
		logrus.Error("Failed user authorization")
		return nil, e
	}
	// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
	// TODO(baumanl): Simplify this. Should only get authorization grant tubes?
	go subsess.handleTubes()

	return subsess, nil
}

//start an authorization grant connection with the remote server and send intent request. return response.
func (sess *session) confirmWithRemote(req *authgrants.Intent, agt *authgrants.AuthGrantConn) ([]byte, error) {
	//start AGC and send INTENT_COMMUNICATION
	npAgc, e := authgrants.NewAuthGrantConnFromMux(sess.tubeMuxer)
	if e != nil {
		logrus.Fatal("Error creating AGC: ", e)
	}
	defer npAgc.Close()
	logrus.Info("CREATED AGC")
	e = npAgc.SendIntentCommunication(req)
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
