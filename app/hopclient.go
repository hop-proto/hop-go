package app

import (
	"flag"
	"io"
	"net/url"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//Client parses cmd line arguments and establishes hop session with remote hop server
func Client(args []string) error {
	logrus.SetLevel(logrus.InfoLevel)

	//TODO(baumanl): add .hop_config support
	//******PROCESS CMD LINE ARGUMENTS******
	var fs flag.FlagSet
	keypath, _ := os.UserHomeDir()
	keypath += DefaultKeyPath

	sess := &session{isPrincipal: false, primarywg: sync.WaitGroup{}}

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

	fs.BoolVar(&sess.headless, "N", false, "don't execute a remote command. Useful for just port forwarding.")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return ErrClientInvalidUsage
	}
	if fs.NArg() < 1 { //there needs to be an argument that is not a flag of the form [user@]host[:port]
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
		port = DefaultHopPort
	}

	username := url.User.Username()
	if username == "" { //if no username is entered use local client username
		u, e := user.Current()
		if e != nil {
			return e
		}
		username = u.Username
	}

	_, verify := NewTestServerConfig(TestDataPathPrefixDef)
	sess.config = transport.ClientConfig{Verify: *verify}
	if sess.isPrincipal {
		err = sess.loadKeys(keypath)
		if err != nil {
			logrus.Error(err)
			return ErrClientLoadingKeys
		}
	} else {
		err = sess.getAuthorization(username, hostname, port, sess.headless, cmd, localForward, localArg, remoteForward, remoteArg)
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

	//TODO(baumanl): fix how session duration tied to cmd duration or port forwarding duration depending on options
	if remoteForward {
		logrus.Info("Doing remote with: ", remoteArg)
		parts := strings.Split(remoteArg, ":")
		if len(parts) != 3 {
			logrus.Error("remote port forwarding currently only supported with port:host:hostport format")
			return ErrInvalidPortForwardingArgs
		}
		logrus.Info("Forwarding traffic from remote port ", parts[0], " to localhost port ", parts[2])
		if sess.headless {
			sess.primarywg.Add(1)
		}
		go func() {
			if sess.headless {
				defer sess.primarywg.Done()
			}
			e := sess.remoteForward(remoteArg)
			logrus.Error(e)
		}()
	}
	if localForward {
		logrus.Info("Doing local with: ", localArg)
		parts := strings.Split(localArg, ":")
		if len(parts) != 3 {
			logrus.Error("local port forwarding currently only supported with port:host:hostport format")
			return ErrInvalidPortForwardingArgs
		}
		logrus.Info("Forwarding traffic from local port ", parts[0], " to remote port ", parts[2], " on host ", parts[1])
		if sess.headless {
			sess.primarywg.Add(1)
		}
		go func() {
			if sess.headless {
				defer sess.primarywg.Done()
			}
			e := sess.localForward(localArg)
			logrus.Error(e)
		}()

	}
	if !sess.headless {
		err = sess.startExecTube(cmd)
		if err != nil {
			logrus.Error(err)
			return ErrClientStartingExecTube
		}
	}
	go sess.handleTubes()

	sess.primarywg.Wait() //client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec tubes?
	return nil
}
