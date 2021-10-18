package app

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/netproxy"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

type hopSession struct {
	transportConn *transport.Handle
	tubeMuxer     *tubes.Muxer
	tubeQueue     chan *tubes.Reliable
	done          chan int

	server *hopServer
	user   string

	isPrincipal bool
	authgrants  []*authGrant
}

func (sess *hopSession) checkAuthorization() bool {
	uaTube, _ := sess.tubeMuxer.Accept()
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	username := userauth.GetInitMsg(uaTube) //client sends desired username
	//TODO(baumanl): verify that this is the best way to get client static key.
	/*I originally had the client just send the key over along with the username, but it
	seemed strange to rely on the client to send the same key that it used during the handshake.
	Instead I modified the transport layer code so that the client static is stored in the session state.
	This way the server directly grabs the key that was used in the handshake.*/
	k := sess.server.server.FetchClientStatic(sess.transportConn) //server fetches client static key that was used in handshake
	logrus.Info("got userauth init message: ", k.String())
	sess.user = username

	cache, err := etcpwdparse.NewLoadedEtcPasswdCache() //Best way to do this? should I load this only once and then just reload on misses? What if /etc/passwd modified between accesses?
	if err != nil {
		err := errors.New("issue loading /etc/passwd")
		logrus.Error(err)
	}
	path := "/home/" + username + "/.hop/authorized_keys"
	if user, ok := cache.LookupUserByName(sess.user); ok {
		path = user.Homedir() + "/.hop/authorized_keys"
	}
	f, e := os.Open(path)
	if e != nil {
		logrus.Error("Could not open file at path: ", path)
	} else {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if scanner.Text() == k.String() {
				logrus.Info("USER AUTHORIZED")
				sess.isPrincipal = true
				uaTube.Write([]byte{userauth.UserAuthConf})
				return true
			}
		}
	}

	//Check for a matching authgrant
	sess.server.m.Lock()
	defer sess.server.m.Unlock()
	authgrants, ok := sess.server.authgrants[k]
	if !ok {
		logrus.Info("USER NOT AUTHORIZED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if authgrants[0].deadline.Before(time.Now()) {
		delete(sess.server.authgrants, k)
		logrus.Info("AUTHGRANT DEADLINE EXCEEDED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if sess.user != authgrants[0].user {
		logrus.Info("AUTHGRANT USER DOES NOT MATCH")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	sess.authgrants = authgrants
	sess.isPrincipal = false
	delete(sess.server.authgrants, k)
	logrus.Info("USER AUTHORIZED")
	uaTube.Write([]byte{userauth.UserAuthConf})
	return true
}

func (sess *hopSession) start() {
	go sess.tubeMuxer.Start()
	logrus.Info("S: STARTED CHANNEL MUXER")

	//User Authorization Step
	if !sess.checkAuthorization() {
		return
		//TODO(baumanl): Check closing behavior. how to end session completely
	}

	logrus.Info("STARTING CHANNEL LOOP")
	go func() {
		for {
			serverChan, err := sess.tubeMuxer.Accept()
			if err != nil {
				logrus.Fatalf("S: ERROR ACCEPTING CHANNEL: %v", err)
			}
			sess.tubeQueue <- serverChan
		}
	}()

	for {
		select {
		case <-sess.done:
			logrus.Info("Closing everything")
			sess.close()
			return
		case serverChan := <-sess.tubeQueue:
			logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", serverChan.Type())
			switch serverChan.Type() {
			case tubes.ExecTube:
				go sess.startCodex(serverChan)
			case tubes.AuthGrantTube:
				go sess.handleAgc(serverChan)
			case tubes.NetProxyTube:
				go netproxy.Handle(serverChan) //TODO(baumanl): different tube types for local/remote/ag forwarding?
			default:
				serverChan.Close()
			}
		}

	}
}

func (sess *hopSession) close() error {
	var err, err2 error
	if !sess.isPrincipal {
		err = sess.authgrants[0].principalSession.close() //TODO: move where principalSession stored?
	}
	sess.tubeMuxer.Stop()
	//err2 = sess.transportConn.Close() (not implemented yet)
	if err != nil {
		return err
	}
	return err2
}

func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	agc := authgrants.NewAuthGrantConn(tube)
	k, t, user, arg, e := agc.HandleIntentComm()
	logrus.Info("got intent comm")
	if e != nil {
		logrus.Info("Server denied authgrant")
		agc.SendIntentDenied("Server denied")
		return
	}
	sess.server.m.Lock()
	if sess.server.outstandingAuthgrants >= maxOutstandingAuthgrants {
		sess.server.m.Unlock()
		logrus.Info("Server exceeded max number of authgrants")
		agc.SendIntentDenied("Server denied. Too many outstanding authgrants.")
		return
	}
	sess.server.outstandingAuthgrants++
	sess.server.authgrants[k] = append(sess.server.authgrants[k], &authGrant{
		deadline:         t,
		user:             user,
		arg:              arg,
		principalSession: sess,
		used:             false,
	})

	sess.server.m.Unlock()
	agc.SendIntentConf(t)
	logrus.Info("Sent intent conf")
	tube.Close()
}

//TODO(baumanl): Add in better privilege separation?
//Right now hopd(root) directly starts commands through go routines.
//sshd uses like 3 levels of separation.
func (sess *hopSession) startCodex(ch *tubes.Reliable) {
	cmd, shell, _ := codex.GetCmd(ch)
	logrus.Info("CMD: ", cmd)
	if !sess.isPrincipal {
		var ag *authGrant = nil
		for _, v := range sess.authgrants {
			if v.grantType == authgrants.CommandGrant || v.grantType == authgrants.ShellGrant {
				ag = v
			}
		}
		if ag == nil {
			err := errors.New("no CommandGrant or ShellGrant authgrant found")
			logrus.Error(err)
			codex.SendFailure(ch, err)
			return
		}
		if ag.used {
			err := errors.New("already performed approved action")
			logrus.Error(err)
			codex.SendFailure(ch, err)
			return
		}
		ag.used = true
		if cmd != ag.arg {
			err := errors.New("CMD does not match Authgrant approved action")
			logrus.Error(err)
			codex.SendFailure(ch, err)
			return
		}
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache() //Best way to do this? should I load this only once and then just reload on misses? What if /etc/passwd modified between accesses?
	if err != nil {
		err := errors.New("issue loading /etc/passwd")
		logrus.Error(err)
		codex.SendFailure(ch, err)
		return
	}
	if user, ok := cache.LookupUserByName(sess.user); ok {
		//Default behavior is for command.Env to inherit parents environment unless given and explicit alternative.
		//TODO(baumanl): These are minimal environment variables. SSH allows for more inheritance from client, but it gets complicated.
		env := []string{
			"USER=" + sess.user,
			"SHELL=" + user.Shell(),
			"LOGNAME=" + user.Username(),
			"HOME=" + user.Homedir(),
			"TERM=" + os.Getenv("TERM"),
		}
		var args []string
		var c *exec.Cmd
		if shell {
			cmd = "login -f " + sess.user //login(1) starts default shell for user and changes all privileges and environment variables
			args = strings.Split(cmd, " ")
			c = exec.Command(args[0], args[1:]...)
		} else {
			args = []string{user.Shell(), "-c", cmd}
			c = exec.Command(args[0], args[1], args[2])
		}
		if !shell {
			c.Dir = user.Homedir()
			c.SysProcAttr = &syscall.SysProcAttr{}
			c.SysProcAttr.Credential = &syscall.Credential{
				Uid:    uint32(user.Uid()),
				Gid:    uint32(user.Gid()),
				Groups: []uint32{uint32(user.Gid())},
			}
		}
		c.Env = env
		logrus.Infof("Executing: %v", cmd)
		f, err := pty.Start(c)
		if err != nil {
			logrus.Errorf("S: error starting pty %v", err)
			codex.SendFailure(ch, err)
			return
		}
		codex.SendSuccess(ch)
		go func() {
			c.Wait()
			ch.Close()
			logrus.Info("closed chan")
		}()

		sess.server.m.Lock()
		if !sess.isPrincipal {
			sess.server.principals[int32(c.Process.Pid)] = sess.authgrants[0].principalSession
		} else {
			logrus.Infof("S: using standard muxer")
			sess.server.principals[int32(c.Process.Pid)] = sess
		}
		sess.server.m.Unlock()
		go func() {
			codex.Server(ch, f)
			logrus.Info("signaling done")
			sess.done <- 1
		}()
	} else {
		err := errors.New("could not find entry for user " + sess.user)
		logrus.Error(err)
		codex.SendFailure(ch, err)
		return
	}
}
