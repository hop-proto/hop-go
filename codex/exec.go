//Package codex provides functions specific to code execution tubes
package codex

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"

	"zmap.io/portal/tubes"
)

//ExecTube wraps a code execution tube with additional terminal state
type ExecTube struct {
	tube  *tubes.Reliable
	state *term.State
	redir bool
	r     *io.PipeReader
	w     *io.PipeWriter
}

const (
	defaultShell = byte(1)
	specificCmd  = byte(2)
)

const (
	execConf = byte(1)
	execFail = byte(2)
)

//SendFailure lets the client know that executing the command failed and the error
func SendFailure(t *tubes.Reliable, err error) {
	msg := make([]byte, 5+len(err.Error()))
	msg[0] = execFail
	binary.BigEndian.PutUint16(msg[1:], uint16(len(err.Error())))
	copy(msg[5:], []byte(err.Error()))
	t.Write(msg)
}

//SendSuccess lets the client know that the server successful started the command
func SendSuccess(t *tubes.Reliable) {
	t.Write([]byte{execConf})
}

//GetStatus lets client waits for confirmation that cmd started or error if it failed
func getStatus(t *tubes.Reliable) error {
	resp := make([]byte, 1)
	t.Read(resp)
	if resp[0] == execConf {
		return nil
	}
	elen := make([]byte, 4)
	t.Read(elen)
	buf := make([]byte, binary.BigEndian.Uint16(elen))
	t.Read(buf)
	return errors.New(string(buf))
}

//NewExecTube sets terminal to raw and makes ch -> os.Stdout and pipes stdin to the ch.
//Stores state in an ExecChan struct so stdin can be manipulated during authgrant process
func NewExecTube(cmd string, tube *tubes.Reliable, wg *sync.WaitGroup) (*ExecTube, error) {
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Errorf("C: error with terminal state: %v", e)
		return nil, e
	}
	msg := newExecInitMsg(specificCmd, cmd)
	if cmd == "" {
		msg = newExecInitMsg(defaultShell, cmd)
	}
	_, e = tube.Write(msg.ToBytes())
	if e != nil {
		logrus.Error(e)
		return nil, e
	}

	//get confirmation that cmd started successfully before piping IO
	err := getStatus(tube)
	if err != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
		logrus.Error("C: server failed to start cmd with error: ", err)
		return nil, err
	}

	r, w := io.Pipe()
	ex := ExecTube{
		tube:  tube,
		state: oldState,
		redir: false,
		r:     r,
		w:     w,
	}

	go func(ex *ExecTube) {
		defer wg.Done()
		io.Copy(os.Stdout, ex.tube) //read bytes from tube to os.Stdout
		term.Restore(int(os.Stdin.Fd()), ex.state)
		logrus.Info("Stopped io.Copy(os.Stdout, tube)")
		ex.tube.Close()
		logrus.Info("closed tube")

	}(&ex)

	go func(ex *ExecTube) {
		p := make([]byte, 1)
		for {
			_, _ = os.Stdin.Read(p)
			if ex.redir {
				ex.w.Write(p)
			} else {
				ex.tube.Write(p)
			}
		}
	}(&ex)

	return &ex, nil
}

type execInitMsg struct {
	cmdType byte
	cmdLen  uint32
	cmd     string
}

func newExecInitMsg(t byte, c string) *execInitMsg {
	return &execInitMsg{
		cmdType: t,
		cmdLen:  uint32(len(c)),
		cmd:     c,
	}
}

func (m *execInitMsg) ToBytes() []byte {
	r := make([]byte, 5+m.cmdLen)
	r[0] = m.cmdType
	binary.BigEndian.PutUint32(r[1:], m.cmdLen)
	if m.cmdLen > 0 {
		copy(r[5:], []byte(m.cmd))
	}
	return r
}

//GetCmd reads execInitMsg from an EXEC_CHANNEL and returns the cmd to run
func GetCmd(c net.Conn) (string, bool, error) {
	t := make([]byte, 1)
	c.Read(t)
	l := make([]byte, 4)
	c.Read(l)
	buf := make([]byte, binary.BigEndian.Uint32(l))
	c.Read(buf)
	if t[0] == defaultShell {
		return "", true, nil
	}
	return string(buf), false, nil
}

//Server deals with serverside code exec channe details like pty size, copies ch -> pty and pty -> ch
func Server(tube *tubes.Reliable, f *os.File) {
	defer tube.Close()
	defer func() { _ = f.Close() }() // Best effort.
	// Handle pty size.
	//TODO(baumanl): Check that this is working properly
	ch2 := make(chan os.Signal, 1)
	signal.Notify(ch2, syscall.SIGWINCH)
	go func() {
		for range ch2 {
			if err := pty.InheritSize(os.Stdin, f); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch2 <- syscall.SIGWINCH                         // Initial resize.
	defer func() { signal.Stop(ch2); close(ch2) }() // Cleanup signals when done.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		_, e := io.Copy(f, tube)
		logrus.Info("io.Copy(f, tube) stopped with error: ", e)
		wg.Done()
	}()
	_, e := io.Copy(tube, f)
	logrus.Info("io.Copy(tube, f) stopped with error: ", e)
	wg.Wait()
}

//Resume makes sure the input is piped to the exec tube
func (e *ExecTube) Resume() {
	e.redir = false
}

//Redirect redirects os.Stdin to a pipe and returns the read end
func (e *ExecTube) Redirect() *io.PipeReader {
	e.redir = true
	return e.r
}

//Restore returns the terminal to regular state
func (e *ExecTube) Restore() {
	term.Restore(int(os.Stdin.Fd()), e.state)
}

//Raw switches the terminal to raw mode
func (e *ExecTube) Raw() {
	term.MakeRaw(int(os.Stdin.Fd()))
}
