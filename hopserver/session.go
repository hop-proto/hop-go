package hopserver

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AstromechZA/etcpwdparse"
	"github.com/creack/pty"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/codex"
	"hop.computer/hop/common"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
	"hop.computer/hop/userauth"
)

type sessID uint32

type hopSession struct {
	transportConn   *transport.Handle
	tubeMuxer       *tubes.Muxer
	tubeQueue       chan tubes.Tube
	done            chan int
	controlChannels []net.Conn

	ID sessID

	// TODO(baumanl): better solution than pointer to server?
	server *HopServer
	user   string

	// We use a channel (with size 1) to avoid reading window sizes before we've created the pty
	pty chan *os.File

	usingAuthGrant        bool // true if client authenticated with authgrant
	authorizedActions     []authgrants.Authgrant
	numActiveReqDelegates atomic.Int32
}

func (sess *hopSession) checkAuthorization() bool {
	t, _ := sess.tubeMuxer.Accept()
	uaTube, ok := t.(*tubes.Reliable)
	if !ok || uaTube.Type() != common.UserAuthTube {
		return false
	}
	logrus.Info("S: Accepted USER AUTH tube")
	defer uaTube.Close()
	username := userauth.GetInitMsg(uaTube) // client sends desired username
	logrus.Info("S: client req to access as: ", username)

	leaf := sess.transportConn.FetchClientLeaf()
	k := keys.PublicKey(leaf.PublicKey)
	logrus.Info("got userauth init message: ", k.String())

	sess.usingAuthGrant = false
	err := sess.server.authorizeKey(username, k)
	if err != nil {
		if sess.server.config.AllowAuthgrants != nil && *sess.server.config.AllowAuthgrants {
			actions, err := sess.server.authorizeKeyAuthGrant(username, k)
			if err != nil {
				logrus.Errorf("rejecting key for %q: %s", username, err)
				return false
			}
			sess.usingAuthGrant = true
			sess.authorizedActions = actions
		} else {
			logrus.Errorf("rejecting key for %q: %s", username, err)
			return false
		}
	}
	sess.user = username

	logrus.Info("USER AUTHORIZED")
	uaTube.Write([]byte{userauth.UserAuthConf})
	return true
}

// start() sets up a session's muxer and handles incoming tube requests.
// calls close when it receives a signal from the code execution tube that it is finished
// TODO(baumanl): change closing behavior for sessions without cmd/shell --> integrate port forwarding duration
func (sess *hopSession) start() {
	// starting tube muxer, but not yet accepting incoming tubes
	go func() {
		err := sess.tubeMuxer.Start()
		sess.done <- 1
		if err != nil {
			logrus.Error(err)
		}
	}()
	logrus.Info("S: STARTED CHANNEL MUXER")
	time.Sleep(time.Second)

	// User Authorization
	if !sess.checkAuthorization() {
		return
		//TODO(baumanl): Check closing behavior. how to end session completely
	}

	// start accepting incoming tubes
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

	proxyQueue := newPTProxyTubeQueue()

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
				// TODO(hosono) handle unreliable tubes (general case)
				r, ok := tube.(*tubes.Unreliable)
				if ok && r.Type() == common.PrincipalProxyTube {
					// add to map and signal waiting processes
					proxyQueue.lock.Lock()
					proxyQueue.tubes[r.GetID()] = r
					proxyQueue.lock.Unlock()
					proxyQueue.cv.Broadcast()
					logrus.Infof("session muxer broadcasted that unreliable tube is here: %x", r.GetID())
				}
				continue
			}
			switch tube.Type() {
			case common.ExecTube:
				go sess.startCodex(r)
			case common.AuthGrantTube:
				go sess.handleAgc(r)
			case common.PrincipalProxyTube:
				go sess.startPTProxy(r, proxyQueue)
			case common.RemotePFTube:
				panic("unimplemented: remote pf")
			case common.LocalPFTube:
				panic("unimplmented: local pf")
			case common.WinSizeTube:
				go sess.startSizeTube(r)
			default:
				tube.Close() // Close unrecognized tube types
			}
		}

	}
}

// TODO(baumanl): look closely at closing behavior
func (sess *hopSession) close() error {
	var err, err2 error

	sess.tubeMuxer.Stop()

	// remove from server session map
	sess.server.sessionLock.Lock()
	defer sess.server.sessionLock.Unlock()
	delete(sess.server.sessions, sess.ID)

	err2 = sess.transportConn.Close()
	if err != nil {
		return err
	}
	return err2
}

// handleAgc handles Intent Communications from principals and updates the outstanding authgrants maps appropriately
func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	defer tube.Close()
	// TODO(baumanl): add check for authgrant?

	// Check server config (coarse grained enable/disable)
	if sess.server.config.AllowAuthgrants == nil || !*sess.server.config.AllowAuthgrants { // AuthGrants not enabled
		authgrants.WriteIntentDenied(tube, authgrants.TargetDenial)
	} else {
		authgrants.StartTargetInstance(tube, sess.checkIntent, sess.addAuthGrant)
	}
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
	principalSess := sess.ID
	// if using an authgrant, check that the cmd is authorized
	if sess.usingAuthGrant {
		principalID, err := sess.checkCmd(cmd, shell)
		if err != nil {
			codex.SendFailure(tube, err)
			return
		}
		principalSess = principalID
	}

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

		// lock principals map so can be updated with pid after starting process
		sess.server.dpProxy.proxyLock.Lock()
		defer sess.server.dpProxy.proxyLock.Unlock()

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
			codex.SendSuccess(tube)
		} else {
			// Signal nil to sess.pty so that window sizes don't indefinitely buffer
			sess.pty <- nil
			c.Stdin = tube
			c.Stdout = codex.NewStdoutWriter(tube)
			c.Stderr = codex.NewStderrWriter(tube)
			err = c.Start()
			if err != nil {
				logrus.Errorf("S: error running command %v", err)
				codex.SendFailure(tube, err)
				return
			}
			codex.SendSuccessSplit(tube)
		}

		// update principals map.
		pid := c.Process.Pid
		sess.server.dpProxy.principals[int32(pid)] = principalSess

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

func (sess *hopSession) startSizeTube(ch *tubes.Reliable) {
	codex.HandleSize(ch, <-sess.pty)
}

func (sess *hopSession) newAuthGrantTube() (*tubes.Reliable, error) {
	return sess.tubeMuxer.CreateReliableTube(common.AuthGrantTube)
}
