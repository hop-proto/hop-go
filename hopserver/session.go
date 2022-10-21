package hopserver

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/creack/pty"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/codex"
	"hop.computer/hop/common"
	"hop.computer/hop/keys"
	"hop.computer/hop/netproxy"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
	"hop.computer/hop/userauth"
)

type hopSession struct {
	transportConn   *transport.Handle
	tubeMuxer       *tubes.Muxer
	tubeQueue       chan tubes.Tube
	done            chan int
	controlChannels []net.Conn

	server *HopServer
	user   string

	// authorizedKeysLocation string

	isPrincipal bool

	// We use a channel (with size 1) to avoid reading window sizes before we've created the pty
	pty chan *os.File
}

func (sess *hopSession) checkAuthorization() bool {
	t, _ := sess.tubeMuxer.Accept()
	uaTube, ok := t.(*tubes.Reliable)
	if !ok || uaTube.Type() != common.UserAuthTube {
		return false
	}
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	username := userauth.GetInitMsg(uaTube) //client sends desired username
	logrus.Info("S: client req to access as: ", username)

	leaf := sess.transportConn.FetchClientLeaf()
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
}

// start() sets up a session's muxer and handles incoming tube requests.
// calls close when it receives a signal from the code execution tube that it is finished
// TODO(baumanl): change closing behavior for sessions without cmd/shell --> integrate port forwarding duration
func (sess *hopSession) start() {
	go func() {
		err := sess.tubeMuxer.Start()
		sess.done <- 1
		if err != nil {
			logrus.Error(err)
		}
	}()
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
			r, ok := tube.(*tubes.Reliable)
			if !ok {
				// TODO(hosono) handle unreliable tubes
				continue
			}
			switch tube.Type() {
			case common.ExecTube:
				go sess.startCodex(r)
			case common.AuthGrantTube:
				go sess.handleAgc(r)
			case common.NetProxyTube:
				go sess.startNetProxy(r)
			case common.RemotePFTube:
				panic("unimplemented: remote pf")
			case common.LocalPFTube:
				panic("unimplmented: local pf")
			case common.WinSizeTube:
				go sess.startSizeTube(r)
			default:
				tube.Close() //Close unrecognized tube types
			}
		}

	}
}

func (sess *hopSession) close() error {
	var err, err2 error

	sess.tubeMuxer.Stop()
	//err2 = sess.transportConn.Close() //(not implemented yet)
	if err != nil {
		return err
	}
	return err2
}

// handleAgc handles Intent Communications from principals and updates the outstanding authgrants maps appropriately
func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	panic("unimplemented")
}

func getGroups(uid int) (groups []uint32) {
	groups = append(groups, uint32(uid))
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return
	}
	groupIds, err := u.GroupIds()
	if err != nil {
		logrus.Infof("Failed to fully get group ids for user with uid %v", err)
	}
	for _, gid := range groupIds {
		parsed, err := strconv.ParseUint(gid, 10, 32)
		if err == nil {
			groups = append(groups, uint32(parsed))
		} else {
			logrus.Infof("Failed to parse gid %v (error: %v)", gid, err)
		}
	}
	return
}

func (sess *hopSession) startCodex(tube *tubes.Reliable) {
	cmd, termEnv, shell, size, _ := codex.GetCmd(tube)
	logrus.Info("CMD: ", cmd)
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
			"TERM=" + termEnv,
		}
		var c *exec.Cmd
		if cmd == "" {
			//login(1) starts default shell for user and changes all privileges and environment variables
			c = exec.Command("login", "-f", sess.user)
		} else {
			c = exec.Command(user.Shell(), "-c", cmd)
			c.Dir = user.Homedir()
			c.SysProcAttr = &syscall.SysProcAttr{}
			c.SysProcAttr.Credential = &syscall.Credential{
				Uid:    uint32(user.Uid()),
				Gid:    uint32(user.Gid()),
				Groups: getGroups(user.Uid()),
			}
		}
		c.Env = env
		logrus.Infof("Executing: %v", cmd)
		var f *os.File
		var err error
		if shell {
			if size != nil {
				f, err = pty.StartWithSize(c, size)
			} else {
				f, err = pty.Start(c)
			}
			sess.pty <- f
			if err != nil {
				logrus.Errorf("S: error starting pty %v", err)
				codex.SendFailure(tube, err)
				return
			}
		} else {
			// Signal nil to sess.pty so that window sizes don't indefinitely buffer
			sess.pty <- nil
			c.Stdin = tube
			c.Stdout = tube
			c.Stderr = tube
			c.Start()
		}

		codex.SendSuccess(tube)
		go func() {
			c.Wait()
			tube.Close()
			logrus.Info("closed chan")
		}()

		if shell {
			go func() {
				codex.Server(tube, f)
				logrus.Info("signaling done")
				sess.done <- 1
			}()
		}
	} else {
		err := errors.New("could not find entry for user " + sess.user)
		logrus.Error(err)
		codex.SendFailure(tube, err)
		return
	}
}

func (sess *hopSession) startNetProxy(ch *tubes.Reliable) {
	netproxy.Server(ch)
}

func (sess *hopSession) startSizeTube(ch *tubes.Reliable) {
	codex.HandleSize(ch, <-sess.pty)
}
