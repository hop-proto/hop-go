package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
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
func Client(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//TODO(baumanl): add .hop_config support
	//******PROCESS CMD LINE ARGUMENTS******
	if len(args) < 2 {
		logrus.Fatal("C: Invalid arguments. Usage: ", clientUsage)
	}

	url, err := url.Parse("//" + args[1]) //double slashes necessary since there is never a scheme
	if err != nil {
		logrus.Fatal("C: Destination should be of form: [user@]host[:port]", err)
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
			logrus.Error(e)
		}
		username = u.Username
	}

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

	//TODO(baumanl): implement this option to allow for piping and expansion
	//var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command within a shell")

	var cmd string
	fs.StringVar(&cmd, "c", "", "specific command to execute on remote server")

	err = fs.Parse(os.Args[2:])
	if err != nil {
		logrus.Fatal(err)
	}
	if fs.NArg() > 0 {
		logrus.Fatal("Unknown arguments provided. Usage: ", clientUsage)
	}

	_, verify := newTestServerConfig()
	sess.config = transport.ClientConfig{Verify: *verify}
	err = sess.getAuthorization(keypath, username, hostname, port, cmd)
	if err != nil {
		logrus.Fatalf("C: Error getting authorization: %v", err)
	}

	sess.startUnderlying(hostname, port)
	sess.tubeMuxer = tubes.NewMuxer(sess.transportConn, sess.transportConn)
	go sess.tubeMuxer.Start()
	defer func() {
		sess.tubeMuxer.Stop()
		logrus.Info("muxer stopped")
		//TODO: finish closing behavior
		// e := transportConn.Close()
		// logrus.Error("closing transport: ", e)
	}()

	sess.userAuthorization(username)
	sess.startExecTube(cmd)
	go sess.handleTubes()
	sess.wg.Wait() //client program ends when the code execution tube ends.
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec tubes?
}

func (sess *session) getAuthorization(keypath string, username string, hostname string, port string, cmd string) error {
	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	if sess.isPrincipal {
		logrus.Infof("C: Using key-file at %v for auth.", keypath)
		var e error
		sess.config.KeyPair, e = keys.ReadDHKeyFromPEMFile(keypath)
		if e != nil {
			return e
		}
	} else {
		shell := false
		if cmd == "" {
			shell = true
		}
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
			t, e := agc.GetAuthGrant(sess.config.KeyPair.Public, username, hostname, port, shell, cmd)
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
				return errors.New("not authorized")
			}
		}
	}
	return nil
}

func (sess *session) startUnderlying(hostname string, port string) {
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
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = sess.transportConn.Handshake() //This hangs if the server is not available when it starts. Add retry or timeout?
	if err != nil {
		logrus.Fatalf("C: Issue with handshake: %v", err)
	}
}

func (sess *session) userAuthorization(username string) {
	//*****PERFORM USER AUTHORIZATION******
	uaCh, _ := sess.tubeMuxer.CreateTube(tubes.UserAuthTube)
	if ok := userauth.RequestAuthorization(uaCh, sess.config.KeyPair.Public, username); !ok {
		logrus.Fatal("Not authorized.")
	}
	logrus.Info("User authorization complete")
	uaCh.Close()
}

func (sess *session) startExecTube(cmd string) {
	//*****RUN COMMAND (BASH OR AG ACTION)*****
	//Hop Session is tied to the life of this code execution tube.
	logrus.Infof("Performing action: %v", cmd)
	ch, _ := sess.tubeMuxer.CreateTube(tubes.ExecTube)
	sess.wg = sync.WaitGroup{}
	sess.wg.Add(1)
	sess.execTube = codex.NewExecTube(cmd, ch, &sess.wg)
}

func (sess *session) handleTubes() {
	//TODO(baumanl): figure out responses to different tube types/what all should be allowed
	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	for {
		c, e := sess.tubeMuxer.Accept()
		if e != nil {
			logrus.Fatalf("Error accepting tube: %v", e)
		}
		logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", c.Type())
		if c.Type() == tubes.AuthGrantTube && sess.isPrincipal {
			go sess.principal(c)
		} else {
			//Client only expects to receive AuthGrantTubes. All other tube requests are ignored.
			c.Close()
			continue
		}
	}
}

func (sess *session) principal(tube *tubes.Reliable) {
	defer tube.Close()
	logrus.SetOutput(io.Discard)
	agt := authgrants.NewAuthGrantConn(tube)
	for {
		intent, err := agt.GetIntentRequest()
		if err != nil { //when the agt is closed this will error out
			logrus.Error("error getting intent request")
			return
		}
		logrus.SetOutput(os.Stdout)
		sess.execTube.Restore()
		r := sess.execTube.Redirect()

		allow := intent.Prompt(r)

		sess.execTube.Raw()
		sess.execTube.Resume()
		logrus.SetOutput(io.Discard)
		if !allow {
			agt.SendIntentDenied("User denied")
			return
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
	e = netproxy.Start(npt, addr)
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

	subsess.userAuthorization(req.Username())

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
