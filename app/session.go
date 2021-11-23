package app

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
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

//AuthGrant contains deadline, user, data
type data struct {
	actionType     byte
	associatedData string
}

type authGrant struct {
	deadline         time.Time
	actions          map[*data]bool //apparently golang doesn't have sets...? Found this on StackOverflow. too hacky???
	user             string
	principalSession *hopSession
}

type hopSession struct {
	transportConn   *transport.Handle
	tubeMuxer       *tubes.Muxer
	tubeQueue       chan *tubes.Reliable
	done            chan int
	controlChannels []net.Conn

	server *HopServer
	user   string

	isPrincipal bool
	authgrant   *authGrant
}

func (sess *hopSession) checkAuthorization() bool {
	uaTube, _ := sess.tubeMuxer.Accept()
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	username := userauth.GetInitMsg(uaTube) //client sends desired username
	logrus.Info("S: client req to access as: ", username)
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
		logrus.Info("opened keys file")
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
	authgrant, ok := sess.server.authgrants[k]
	if !ok {
		logrus.Info("USER NOT AUTHORIZED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if authgrant.deadline.Before(time.Now()) {
		delete(sess.server.authgrants, k)
		logrus.Info("AUTHGRANT DEADLINE EXCEEDED")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	if sess.user != authgrant.user {
		logrus.Info("AUTHGRANT USER DOES NOT MATCH")
		uaTube.Write([]byte{userauth.UserAuthDen})
		return false
	}
	sess.authgrant = authgrant
	sess.isPrincipal = false
	delete(sess.server.authgrants, k)
	sess.server.outstandingAuthgrants--
	logrus.Info("USER AUTHORIZED")
	uaTube.Write([]byte{userauth.UserAuthConf})
	return true
}

//start() sets up a session's muxer and handles incoming tube requests.
//calls close when it receives a signal from the code execution tube that it is finished
//TODO(baumanl): change closing behavior for sessions without cmd/shell --> integrate port forwarding duration
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
			case ExecTube:
				go sess.startCodex(serverChan)
			case AuthGrantTube:
				go sess.handleAgc(serverChan)
			case NetProxyTube:
				//TODO(baumanl): different tube types for local/remote/ag forwarding?
				go sess.startNetProxy(serverChan)
			case RemotePFTube:
				go sess.startRemote(serverChan)
			case LocalPFTube:
				go sess.startLocal(serverChan)
			default:
				serverChan.Close()
			}
		}

	}
}

func (sess *hopSession) close() error {
	var err, err2 error
	if !sess.isPrincipal {
		err = sess.authgrant.principalSession.close() //TODO: move where principalSession stored?
	}

	sess.tubeMuxer.Stop()
	//err2 = sess.transportConn.Close() (not implemented yet)
	if err != nil {
		return err
	}
	return err2
}

//handleAgc handles Intent Communications from principals and updates the outstanding authgrants maps appropriately
func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	agc := authgrants.NewAuthGrantConn(tube)
	defer agc.Close()
	for {
		k, t, user, arg, grantType, e := agc.HandleIntentComm()
		if e != nil {
			//better error handling
			logrus.Infof("agc closed: %v", e)
			return
		}
		logrus.Info("got intent comm")
		sess.server.m.Lock()
		if sess.server.outstandingAuthgrants >= sess.server.config.MaxOutstandingAuthgrants {
			sess.server.m.Unlock()
			logrus.Info("Server exceeded max number of authgrants")
			agc.SendIntentDenied("Server denied. Too many outstanding authgrants.")
			return
		}
		if _, ok := sess.server.authgrants[k]; !ok {
			sess.server.outstandingAuthgrants++
			sess.server.authgrants[k] = &authGrant{
				deadline:         t,
				user:             user,
				principalSession: sess,
				actions:          make(map[*data]bool),
			}
		}
		sess.server.authgrants[k].actions[&data{
			actionType:     grantType,
			associatedData: arg,
		}] = true
		logrus.Infof("Added AG: action %v, type %v", arg, grantType)
		sess.server.m.Unlock()
		agc.SendIntentConf(t)
		logrus.Info("Sent intent conf")
	}
}

//server enforces that delegates only execute approved actions
func (sess *hopSession) checkAction(action string, actionType byte) error {
	logrus.Info("CHECKING ACTION IS AUTHORIZED")
	for elem := range sess.authgrant.actions {
		if elem.actionType == actionType && elem.associatedData == action {
			delete(sess.authgrant.actions, elem)
			return nil
		}
	}
	err := fmt.Errorf("no authgrant of action: %v and type: %v, found", action, actionType)
	return err

}

func (sess *hopSession) startCodex(ch *tubes.Reliable) {
	cmd, shell, _ := codex.GetCmd(ch)
	logrus.Info("CMD: ", cmd)
	if !sess.isPrincipal {
		err := sess.checkAction(cmd, authgrants.CommandAction)
		if err != nil {
			err = sess.checkAction(cmd, authgrants.ShellAction)
		}
		if err != nil {
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
			sess.server.principals[int32(c.Process.Pid)] = sess.authgrant.principalSession
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

func (sess *hopSession) startLocal(ch *tubes.Reliable) {
	buf := make([]byte, 4)
	ch.Read(buf)
	l := binary.BigEndian.Uint32(buf[0:4])
	arg := make([]byte, l)
	ch.Read(arg)
	//Check authorization
	if !sess.isPrincipal {
		err := sess.checkAction(string(arg), authgrants.LocalPFAction)
		if err != nil {
			logrus.Error(err)
			ch.Write([]byte{netproxy.NpcDen})
			return
		}
	}
	sess.LocalServer(ch, string(arg))
}

func (sess *hopSession) startRemote(ch *tubes.Reliable) {
	buf := make([]byte, 4)
	ch.Read(buf)
	l := binary.BigEndian.Uint32(buf[0:4])
	arg := make([]byte, l)
	ch.Read(arg)
	//Check authorization
	if !sess.isPrincipal {
		err := sess.checkAction(string(arg), authgrants.RemotePFAction)
		if err != nil {
			logrus.Error(err)
			ch.Write([]byte{netproxy.NpcDen})
			return
		}
	}
	sess.RemoteServer(ch, string(arg))
}

func (sess *hopSession) startNetProxy(ch *tubes.Reliable) {
	netproxy.Server(ch)
}

func (sess *hopSession) RemoteServer(ch *tubes.Reliable, arg string) {
	sock := "@remotesock"
	//RemoteServer starts listening on given port and pipes the traffic back over the tube
	parts := strings.Split(arg, ":") //assuming port:host:hostport

	curUser, err := user.Current()
	if err != nil {
		logrus.Error("couldn't find current user")
		ch.Write([]byte{netproxy.NpcDen})
	}
	logrus.Infof("Currently running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		logrus.Error("couln't load passwd cache")
		ch.Write([]byte{netproxy.NpcDen})
	}
	args := []string{"remotePF", parts[0]}
	c := exec.Command(args[0], args[1:]...)
	logrus.Infof("running as %v, configuring to run as %v", curUser.Username, sess.user)
	user, ok := cache.LookupUserByName(sess.user)
	if !ok {
		logrus.Error("couldn't find session user")
		ch.Write([]byte{netproxy.NpcDen})
	}
	if curUser.Uid == "0" { //remove check (for testing purposes)
		c.SysProcAttr = &syscall.SysProcAttr{}
		c.SysProcAttr.Credential = &syscall.Credential{
			Uid:    uint32(user.Uid()),
			Gid:    uint32(user.Gid()),
			Groups: []uint32{uint32(user.Gid())},
		}
	}

	//TODO: dynamically generate sock address and put it as an argument to child process
	//set up authgrantServer (UDS socket)
	//make sure the socket does not already exist.
	err = os.RemoveAll(sock)
	if err != nil {
		logrus.Error("couln't remove other process listening on UDS socket")
		ch.Write([]byte{netproxy.NpcDen})
	}

	//set socket options and start listening to socket
	//sockconfig := &net.ListenConfig{Control: setListenerOptions}
	uds, err := net.Listen("unix", sock)
	if err != nil {
		logrus.Error("error listening on socket")
		ch.Write([]byte{netproxy.NpcDen})
	}
	defer uds.Close()
	logrus.Infof("address: %v", uds.Addr())

	//control socket
	control, err := net.Listen("unix", "@control")
	if err != nil {
		logrus.Error("error listening on control socket")
		ch.Write([]byte{netproxy.NpcDen})
	}
	defer uds.Close()
	logrus.Infof("control address: %v", control.Addr())

	err = c.Start()
	if err != nil {
		logrus.Error("error starting child process: ", err)
		ch.Write([]byte{netproxy.NpcDen})
	}

	controlChan, _ := control.Accept()
	sess.controlChannels = append(sess.controlChannels, controlChan)
	logrus.Info("S: accepted Control channel")

	logrus.Info("started child process")
	ch.Write([]byte{netproxy.NpcConf})
	ch.Close()

	for {
		udsconn, err := uds.Accept() //TODO: add some timer so if child can't connect for some reason it doesn't hang forever
		wg := sync.WaitGroup{}
		if err != nil {
			logrus.Error("error accepting uds conn")
			return
		}
		t, err := sess.tubeMuxer.CreateTube(RemotePFTube)
		if err != nil {
			logrus.Error("error creating tube", err)
			return
		}
		logrus.Info("S: started new RPF tube")
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(udsconn, t)
			logrus.Infof("Copied %v bytes from t to udsconn", n)
			udsconn.Close()
		}()
		n, _ := io.Copy(t, udsconn)
		logrus.Infof("Copied %v bytes from udsconn to t", n)
		t.Close()
		wg.Wait()

	}

}

func (sess *hopSession) LocalServer(ch *tubes.Reliable, arg string) {

}
