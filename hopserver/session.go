package hopserver

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/codex"
	"hop.computer/hop/common"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
	"hop.computer/hop/portforwarding"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
	"hop.computer/hop/userauth"
)

type sessID uint32

type hopSession struct {
	transportConn   *transport.Handle
	tubeMuxer       *tubes.Muxer
	controlChannels []net.Conn

	ID sessID

	// TODO(baumanl): better solution than pointer to server?
	server *HopServer
	user   string

	// We use a channel (with size 1) to avoid reading window sizes before we've created the pty
	pty chan *os.File

	usingAuthGrant    bool // true if client authenticated with authgrant
	authorizedActions []authgrants.Authgrant

	forward portforwarding.Forward
}

func (sess *hopSession) checkAuthorization() bool {
	t, err := sess.tubeMuxer.Accept()
	if err != nil {
		// If we can't accept a tube here, it means the session is closing
		logrus.Info("muxer stopping dufing check authorization")
		return false
	}
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
	err = sess.server.authorizeKey(username, k)
	if err != nil {
		if sess.server.config.EnableAuthgrants != nil && *sess.server.config.EnableAuthgrants {
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
	// Tube Muxer is started when NewMuxer is called in hopserver.go
	// User Authorization
	if !sess.checkAuthorization() {
		return
		//TODO(baumanl): Check closing behavior. how to end session completely
	}

	// start accepting incoming tubes
	logrus.Info("STARTING TUBE LOOP")

	for {
		tube, err := sess.tubeMuxer.Accept()
		if err != nil {
			sess.close()
			break
		}
		logrus.Infof("S: ACCEPTED NEW TUBE Type: %v, ID: %v, Reliable? %v)", tube.Type(), tube.GetID(), tube.IsReliable())

		if r, ok := tube.(*tubes.Reliable); ok {
			switch tube.Type() {
			case common.ExecTube:
				t2, err := sess.tubeMuxer.Accept()
				r2, ok := t2.(*tubes.Reliable)
				if err != nil || !ok {
					sess.close()
					return
				}
				go sess.startCodex(r, r2)
			case common.AuthGrantTube:
				go sess.handleAgc(r)
			case common.PFControlTube:
				go sess.startPF(r)
			case common.PFTube:
				go sess.handlePFReliable(r)
			case common.WinSizeTube:
				go sess.startSizeTube(r)
			default:
				tube.Close() // Close unrecognized tube types
			}

		} else if u, ok := tube.(*tubes.Unreliable); ok {
			switch tube.Type() {
			case common.PFTube:
				go sess.handlePFUnreliable(u)
			default:
				tube.Close() // Close unrecognized tube types
			}

		} else {
			e := tube.Close()
			if e != nil {
				logrus.Errorf("Error closing tube: %v", e)
			}
		}

	}
}

// TODO(baumanl): look closely at closing behavior
func (sess *hopSession) close() error {
	sess.tubeMuxer.Stop()

	// remove from server session map
	sess.server.sessionLock.Lock()
	defer sess.server.sessionLock.Unlock()
	delete(sess.server.sessions, sess.ID)

	return sess.transportConn.Close()
}

// handleAgc handles Intent Communications from principals and updates the outstanding authgrants maps appropriately
func (sess *hopSession) handleAgc(tube *tubes.Reliable) {
	defer tube.Close()
	// TODO(baumanl): add check for authgrant?
	logrus.Info("target: received authgrant tube")

	// Check server config (coarse grained enable/disable)
	if sess.server.config.EnableAuthgrants == nil || !*sess.server.config.EnableAuthgrants { // AuthGrants not enabled
		authgrants.WriteIntentDenied(tube, authgrants.TargetDenial)
	} else {
		logrus.Info("target: starting target instance")
		cert := sess.transportConn.FetchClientLeaf()
		authgrants.StartTargetInstance(tube, cert, sess.checkIntent, sess.addAuthGrant)
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

func (sess *hopSession) startCodex(t1, t2 *tubes.Reliable) {
	var stdinTube *tubes.Reliable
	var stdoutTube *tubes.Reliable
	// We may have accepted the tubes in any order, so we need to check which one was created first
	if t1.GetID() < t2.GetID() {
		stdinTube = t1
		stdoutTube = t2
	} else {
		stdinTube = t2
		stdoutTube = t1
	}
	cmd, termEnv, shell, size, _ := codex.GetCmd(stdinTube)
	principalSess := sess.ID
	// if using an authgrant, check that the cmd is authorized
	if sess.usingAuthGrant {
		principalID, err := sess.checkCmd(cmd, shell)
		if err != nil {
			codex.SendFailure(stdoutTube, err)
			return
		}
		principalSess = principalID
	}

	logrus.WithFields(logrus.Fields{
		"command": cmd,
		"shell":   shell,
	}).Info("starting code execution")
	var err error
	user, err := thunks.LookupUser(sess.user)
	if err != nil {
		err := errors.New("could not find entry for user " + sess.user)
		logrus.Error(err)
		codex.SendFailure(stdoutTube, err)
		return
	}
	//Default behavior is for command.Env to inherit parents environment unless given and explicit alternative.
	//TODO(baumanl): These are minimal environment variables. SSH allows for more inheritance from client, but it gets complicated.
	env := []string{
		"USER=" + user.Username(),
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

	// lock principals map so can be updated with pid after starting process
	sess.server.dpProxy.principalLock.Lock()
	defer sess.server.dpProxy.principalLock.Unlock()

	if shell {
		if size != nil {
			f, err = pty.StartWithSize(c, size)
		} else {
			f, err = pty.Start(c)
		}
		sess.pty <- f
		if err != nil {
			logrus.Errorf("S: error starting pty %v", err)
			codex.SendFailure(stdoutTube, err)
			return
		}
	} else {
		// Signal nil to sess.pty so that window sizes don't indefinitely buffer
		sess.pty <- nil
		c.Stdin = stdinTube
		c.Stdout = stdoutTube
		c.Stderr = stdoutTube
		err = thunks.StartCmd(c)
		if err != nil {
			logrus.Errorf("S: error running command: %v", err)
			codex.SendFailure(stdoutTube, err)
			return
		}
	}

	// update principals map.
	pid := c.Process.Pid
	sess.server.dpProxy.principals[int32(pid)] = principalSess

	codex.SendSuccess(stdoutTube)
	go func() {
		c.Process.Wait()
		logrus.Info("command done. closing tubes")
		stdoutTube.Close()
		stdinTube.Close()
		logrus.Info("closed chan")
	}()

	if shell {
		go func() {
			codex.Server(stdinTube, stdoutTube, f)
			logrus.Info("signaling done")
			sess.close()
		}()
	}
}

func (sess *hopSession) startSizeTube(ch *tubes.Reliable) {
	codex.HandleSize(ch, <-sess.pty)
}

func (sess *hopSession) newAuthGrantTube() (*tubes.Reliable, error) {
	return sess.tubeMuxer.CreateReliableTube(common.AuthGrantTube)
}

func (sess *hopSession) startPF(ch *tubes.Reliable) {
	// TODO find a way of selecting a remote forwarding
	// or a local forwarding
	portforwarding.StartPFServer(ch, &sess.forward, sess.tubeMuxer)
}

func (sess *hopSession) handlePFReliable(ch *tubes.Reliable) {
	portforwarding.HandlePF(ch, &sess.forward, portforwarding.PfLocal)
}

func (sess *hopSession) handlePFUnreliable(ch *tubes.Unreliable) {
	portforwarding.HandlePF(ch, &sess.forward, portforwarding.PfLocal)
}
