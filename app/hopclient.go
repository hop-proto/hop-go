package app

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
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

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

type session struct {
	transportConn *transport.Client
	proxyConn     *tubes.Reliable
	tubeMuxer     *tubes.Muxer
	execTube      *codex.ExecTube
	isPrincipal   bool
	proxied       bool

	wg     sync.WaitGroup
	config transport.ClientConfig
}

//Client parses cmd line arguments and establishes hop session with remote hop server
func Client(args []string) error {
	logrus.SetLevel(logrus.InfoLevel)

	//TODO(baumanl): add .hop_config support
	//******PROCESS CMD LINE ARGUMENTS******
	var fs flag.FlagSet
	keypath, _ := os.UserHomeDir()
	keypath += defaultKeyPath

	sess := &session{isPrincipal: false}

	fs.Func("k", "indicates principal with specific key location", func(s string) error {
		sess.isPrincipal = true
		keypath = s
		return nil
	})

	fs.BoolVar(&sess.isPrincipal, "K", sess.isPrincipal, "indicates principal with default key location: $HOME/.hop/key")

	remoteForward := false
	remoteArg := ""
	fs.Func("R", "perform remote port forwarding", func(s string) error {
		remoteForward = true
		remoteArg = s
		return nil
	})

	localForward := false
	localArg := ""
	fs.Func("L", "perform local port forwarding", func(s string) error {
		localForward = true
		localArg = s
		return nil
	})

	/*TODO(baumanl): Right now all explicit commands are run within the context of a shell using "$SHELL -c <cmd>"
	(this allows for expanding env variables, piping, etc.) However, there may be instances where this is undesirable.
	Add an option to resort to running the command without this feature.
	Decide which is the better default.
	Add config/enforcement on what clients/auth grants are allowed to do.
	How should this be communicated within Intent and in Authgrant?*/
	//var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")

	var cmd string
	fs.StringVar(&cmd, "c", "", "specific command to execute on remote server")

	var quiet bool
	fs.BoolVar(&quiet, "q", false, "turn off logging")

	var noCmd bool
	fs.BoolVar(&noCmd, "N", false, "don't execute a remote command. Useful for just port forwarding.")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return ErrClientInvalidUsage
	}
	if fs.NArg() < 1 { //the only argument that is not a flag is of the form [user@]host[:port]
		return ErrClientInvalidUsage
	}
	hoststring := fs.Arg(0)
	if fs.NArg() > 1 { //still flags after the hoststring that need to be parsed
		err = fs.Parse(fs.Args()[1:])
		if err != nil || fs.NArg() > 0 {
			if err == flag.ErrHelp {
				return nil
			}
			return ErrClientInvalidUsage
		}
	}

	if quiet {
		logrus.SetOutput(io.Discard)
	}

	url, err := url.Parse("//" + hoststring) //double slashes necessary since there is never a scheme
	if err != nil {
		logrus.Error(err)
		return ErrClientInvalidUsage
	}

	hostname := url.Hostname()
	port := url.Port()
	if port == "" {
		port = defaultHopPort
	}

	username := url.User.Username()
	if username == "" { //if no username is entered use local client username
		u, e := user.Current()
		if e != nil {
			return e
		}
		username = u.Username
	}

	_, verify := newTestServerConfig()
	sess.config = transport.ClientConfig{Verify: *verify}
	if sess.isPrincipal {
		err = sess.loadKeys(keypath)
		if err != nil {
			logrus.Error(err)
			return ErrClientLoadingKeys
		}
	} else {
		err = sess.getAuthorization(username, hostname, port, cmd)
		if err != nil {
			logrus.Error(err)
			return ErrClientGettingAuthorization
		}
	}
	err = sess.startUnderlying(hostname, port)
	if err != nil {
		return ErrClientStartingUnderlying
	}
	sess.tubeMuxer = tubes.NewMuxer(sess.transportConn, sess.transportConn)
	go sess.tubeMuxer.Start()
	defer func() {
		sess.tubeMuxer.Stop()
		logrus.Info("muxer stopped")
		//TODO: finish closing behavior
		// e := transportConn.Close()
		// logrus.Error("closing transport: ", e)
	}()

	err = sess.userAuthorization(username)
	if err != nil {
		return err
	}
	if remoteForward {
		logrus.Info("Doing remote with: ", remoteArg)
		//do remote port forwarding
		parts := strings.Split(remoteArg, ":")
		if len(parts) != 3 {
			logrus.Error("remote port forwarding currently only supported with port:host:hostport format")
		} else {
			sess.wg.Add(1)
			go sess.remoteForward(parts)
		}
	}
	if localForward {
		logrus.Info("Doing local with: ", localArg)
		//parse string
		parts := strings.Split(localArg, ":")
		if len(parts) != 3 {
			logrus.Error("local port forwarding currently only supported with port:host:hostport format")
		} else {
			sess.wg.Add(1)
			go sess.localForward(parts)
		}
	}

	if !noCmd {
		err = sess.startExecTube(cmd)
		if err != nil {
			logrus.Error(err)
			return ErrClientStartingExecTube
		}
	}
	go sess.handleTubes()
	sess.wg.Wait() //client program ends when the code execution tube ends.
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec tubes?
	return nil
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

func (sess *session) getAuthorization(username string, hostname string, port string, cmd string) error {
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
	for {
		t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, cmd == "", cmd)
		if e == nil {
			logrus.Infof("C: Principal approved request. Deadline: %v", t)
			break
		} else if e != authgrants.ErrIntentDenied {
			return e
		}
		var ans string
		for ans != "y" && ans != "n" {
			fmt.Println("Send intent request again? [y/n]: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			ans = scanner.Text()
		}
		if ans == "n" {
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
	if ok := userauth.RequestAuthorization(uaCh, sess.config.KeyPair.Public, username); !ok {
		return ErrClientUnauthorized
	}
	logrus.Info("User authorization complete")
	return nil
}

func (sess *session) remoteForward(parts []string) error {
	defer sess.wg.Done()
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
	sess.wg.Add(1)
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
	defer sess.wg.Done()
	remoteAddr := net.JoinHostPort(parts[1], parts[2])
	npt, e := sess.tubeMuxer.CreateTube(tubes.NetProxyTube)
	if e != nil {
		return e
	}
	e = netproxy.Start(npt, remoteAddr, netproxy.Local)
	if e != nil {
		return e
	}
	sess.wg.Add(1)
	//do local port forwarding
	go func() {
		defer sess.wg.Done()
		local, e := net.Listen("tcp", ":"+strings.Trim(parts[0], ":"))
		if e != nil {

			logrus.Error(e)
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
	sess.wg = sync.WaitGroup{}
	sess.wg.Add(1)
	sess.execTube, err = codex.NewExecTube(cmd, ch, &sess.wg)
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
		sess.confirmWithRemote(intent, agt)
	}
}

func (sess *session) confirmWithRemote(req *authgrants.Intent, agt *authgrants.AuthGrantConn) {
	logrus.Debug("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...")

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
		logrus.Fatal("Issue proxying connection")
	}
	subsess := &session{
		isPrincipal: true,
		config:      sess.config,
		proxyConn:   npt,
	}

	subsess.startUnderlying(hostname, port)
	subsess.tubeMuxer = tubes.NewMuxer(subsess.transportConn, subsess.transportConn)
	go subsess.tubeMuxer.Start()

	subsess.userAuthorization(req.Username()) //TODO: what if this fails?

	//start AGC and send INTENT_COMMUNICATION
	npAgc, e := authgrants.NewAuthGrantConnFromMux(subsess.tubeMuxer)
	if e != nil {
		logrus.Fatal("Error creating AGC: ", e)
	}
	logrus.Info("CREATED AGC")
	e = npAgc.SendIntentCommunication(req)
	if e != nil {
		logrus.Info("Issue writing intent comm to netproxyAgc")
	}
	logrus.Info("sent intent comm")
	responseType, response, e := npAgc.ReadResponse()
	logrus.Info("got response")
	if e != nil {
		logrus.Fatalf("C: error reading from agc: %v", e)
	}
	npAgc.Close()

	//write response back to server asking for Authorization Grant
	err := agt.WriteRawBytes(response)
	if err != nil {
		logrus.Fatalf("C: error writing to agt: %v", err)
	}

	switch responseType {
	case authgrants.IntentDenied:
		logrus.Infof("C: WROTE IntentDenied")
		return
	case authgrants.IntentConfirmation:
		logrus.Infof("C: WROTE IntentConfirmation")
	}
	// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
	// TODO(baumanl): Simplify this. Should only get authorization grant tubes?
	go subsess.handleTubes()
}
