package hopserver

import (
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
	"zmap.io/portal/common"
	"zmap.io/portal/keys"
	"zmap.io/portal/netproxy"
	"zmap.io/portal/portforwarding"
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

	authorizedKeysLocation string

	isPrincipal bool
	authgrant   *authGrant
}

func (sess *hopSession) checkAuthorization() bool {
	uaTube, _ := sess.tubeMuxer.Accept()
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	username := userauth.GetInitMsg(uaTube) //client sends desired username
	logrus.Info("S: client req to access as: ", username)
	// TODO(baumanl): verify that this is the best way to get client static key.
	/*I originally had the client just send the key over along with the username, but it
	seemed strange to rely on the client to send the same key that it used during the handshake.
	Instead I modified the transport layer code so that the client static is stored in the session state.
	This way the server directly grabs the key that was used in the handshake.*/
	leaf := sess.server.server.FetchClientLeaf(sess.transportConn) //server fetches client static key that was used in handshake
	k := keys.PublicKey(leaf.PublicKey)
	logrus.Info("got userauth init message: ", k.String())

	if err := sess.server.authorizeKey(username, k); err != nil {
		logrus.Errorf("rejecting key for %q: %s", username, err)
		return false
	}

	sess.user = username

	logrus.Info("USER AUTHORIZED")
	sess.isPrincipal = true
	uaTube.Write([]byte{userauth.UserAuthConf})
	return true

	// TODO(dadrian): re-enable authgrants
	/*
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
		logrus.Info("USER AUTHORIZED VIA AUTHGRANT")
		uaTube.Write([]byte{userauth.UserAuthConf})
		return true
	*/
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

	logrus.Info("STARTING TUBE LOOP")
	go func() {
		for {
			tube, err := sess.tubeMuxer.Accept()
			if err != nil {
				logrus.Fatalf("S: ERROR ACCEPTING TUBE: %v", err)
			}
			sess.tubeQueue <- tube
		}
	}()

	for {
		select {
		case <-sess.done:
			logrus.Info("Closing everything")
			sess.close()
			return
		case tube := <-sess.tubeQueue:
			logrus.Infof("S: ACCEPTED NEW TUBE (%v)", tube.Type())
			switch tube.Type() {
			case common.ExecTube:
				go sess.startCodex(tube)
			case common.AuthGrantTube:
				go sess.handleAgc(tube)
			case common.NetProxyTube:
				go sess.startNetProxy(tube)
			case common.RemotePFTube:
				go sess.startRemote(tube)
			case common.LocalPFTube:
				go sess.startLocal(tube)
			default:
				tube.Close() //Close unrecognized tube types
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
	//err2 = sess.transportConn.Close() //(not implemented yet)
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

func (sess *hopSession) startCodex(tube *tubes.Reliable) {
	cmd, shell, _ := codex.GetCmd(tube)
	logrus.Info("CMD: ", cmd)
	if !sess.isPrincipal {
		err := sess.checkAction(cmd, authgrants.CommandAction)
		if err != nil {
			err = sess.checkAction(cmd, authgrants.ShellAction)
		}
		if err != nil {
			logrus.Error(err)
			codex.SendFailure(tube, err)
			return
		}
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache() //Best way to do this? should I load this only once and then just reload on misses? What if /etc/passwd modified between accesses?
	if err != nil {
		err := errors.New("issue loading /etc/passwd")
		logrus.Error(err)
		codex.SendFailure(tube, err)
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
		// TODO (baumanl): something is wrong with pty (backspace no longer works
		// and getting "error resizing pty: inappropriate ioctl for device" in
		// docker)
		if err != nil {
			logrus.Errorf("S: error starting pty %v", err)
			codex.SendFailure(tube, err)
			return
		}
		codex.SendSuccess(tube)
		go func() {
			c.Wait()
			tube.Close()
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
			codex.Server(tube, f)
			logrus.Info("signaling done")
			sess.done <- 1
		}()
	} else {
		err := errors.New("could not find entry for user " + sess.user)
		logrus.Error(err)
		codex.SendFailure(tube, err)
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

func (sess *hopSession) startRemote(tube *tubes.Reliable) {
	buf := make([]byte, 4)
	tube.Read(buf)
	l := binary.BigEndian.Uint32(buf[0:4])
	arg := make([]byte, l)
	tube.Read(arg)
	//Check authorization
	if !sess.isPrincipal {
		err := sess.checkAction(string(arg), authgrants.RemotePFAction)
		if err != nil {
			logrus.Error(err)
			tube.Write([]byte{netproxy.NpcDen})
			return
		}
	}
	sess.RemoteServer(tube, string(arg))
}

func (sess *hopSession) startNetProxy(ch *tubes.Reliable) {
	netproxy.Server(ch)
}

//RemoteServer starts listening on given port and pipes the traffic back over the tube
func (sess *hopSession) RemoteServer(tube *tubes.Reliable, arg string) {
	//parts := strings.Split(arg, ":") //assuming port:host:hostport
	fwdStruct := portforwarding.Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	err := portforwarding.ParseForward(arg, &fwdStruct)
	if err != nil {
		logrus.Error(err)
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		logrus.Error("couln't load passwd cache")
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	args := []string{"remotePF", arg}
	c := exec.Command(args[0], args[1:]...)
	logrus.Infof("configuring child to run as %v", sess.user)
	userEntry, ok := cache.LookupUserByName(sess.user)
	if !ok {
		logrus.Error("couldn't find session user")
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	curUser, _ := user.Current()
	if curUser.Username != sess.user || curUser.Uid == "0" { //TODO: necessary because in tests it doesn't run as root so trying to do this causes an error
		c.SysProcAttr = &syscall.SysProcAttr{}
		c.SysProcAttr.Credential = &syscall.Credential{
			Uid:    uint32(userEntry.Uid()),
			Gid:    uint32(userEntry.Gid()),
			Groups: []uint32{uint32(userEntry.Gid())},
		}
	}

	//set up content socket (UDS socket)
	contentSockAddr := "@content" + fwdStruct.Listenportorpath //TODO: improve robustness of abstract socket address names
	uds, err := net.Listen("unix", contentSockAddr)
	if err != nil {
		logrus.Error("error listening on content socket")
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	defer uds.Close()
	logrus.Infof("address: %v", uds.Addr())

	//control socket
	controlSockAddr := "@control" + fwdStruct.Listenportorpath
	control, err := net.Listen("unix", controlSockAddr)
	if err != nil {
		logrus.Error("error listening on control socket")
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	defer control.Close()
	logrus.Infof("control address: %v", control.Addr())

	err = c.Start()
	if err != nil {
		logrus.Error("error starting child process: ", err)
		tube.Write([]byte{netproxy.NpcDen})
		return
	}

	//TODO: add timeout so this doesn't hang forever if something goes wrong
	controlChan, _ := control.Accept()
	buf := make([]byte, 1)
	controlChan.Read(buf)
	if buf[0] != netproxy.NpcConf {
		logrus.Error("error binding to remote port")
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	sess.controlChannels = append(sess.controlChannels, controlChan)
	logrus.Info("S: accepted Control channel")

	logrus.Info("started child process")
	tube.Write([]byte{netproxy.NpcConf})
	defer func() {
		tube.Write([]byte{netproxy.NpcDen}) //tell it something went wrong
		tube.Close()
	}()

	for {
		udsconn, err := uds.Accept() //TODO: add some timer so if child can't connect for some reason it doesn't hang forever
		wg := sync.WaitGroup{}
		if err != nil {
			logrus.Error("error accepting uds conn")
			return
		}
		logrus.Info("server got a uds conn from child")
		t, err := sess.tubeMuxer.CreateTube(common.RemotePFTube)
		if err != nil {
			logrus.Error("error creating tube", err)
			return
		}
		//send arg across tube
		err = netproxy.Start(t, arg, netproxy.Remote)
		if err != nil {
			logrus.Error("Local refused forwarded connection: ", arg)
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

//LocalServer starts a TCP Conn with remote addr and proxies traffic from ch -> tcp and tcp -> ch
func (sess *hopSession) LocalServer(tube *tubes.Reliable, arg string) {
	defer tube.Close()

	fwdStruct := portforwarding.Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	err := portforwarding.ParseForward(arg, &fwdStruct)
	if err != nil {
		logrus.Error(err)
		tube.Write([]byte{netproxy.NpcDen})
		return
	}

	var tconn net.Conn
	if !fwdStruct.Connectsock {
		addr := net.JoinHostPort(fwdStruct.Connecthost, fwdStruct.Connectportorpath)
		if _, err := net.LookupAddr(addr); err != nil {
			//Couldn't resolve address with local resolver
			h, p, e := net.SplitHostPort(addr)
			if e != nil {
				logrus.Error(e)
				tube.Write([]byte{netproxy.NpcDen})
				return
			}
			if ip, ok := common.HostToIPAddr[h]; ok {
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
		logrus.Errorf("C: error dialing server: %v", err)
		tube.Write([]byte{netproxy.NpcDen})
		return
	}
	defer tconn.Close()
	logrus.Info("connected to: ", arg)
	tube.Write([]byte{netproxy.NpcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	go func() {
		//Handles all traffic from local port to end dest
		io.Copy(tconn, tube)
	}()
	//handles all traffic from end dest back to local port
	io.Copy(tube, tconn)
}
