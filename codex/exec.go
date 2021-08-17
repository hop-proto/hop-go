//Package codex provides functions specific to code execution channels
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
	"zmap.io/portal/channels"
)

//ExecChan wraps a code execution channel with additional terminal state
type ExecChan struct {
	ch    *channels.Reliable
	state *term.State
	redir bool
	r     *io.PipeReader
	w     *io.PipeWriter
}

const (
	defaultShell = byte(1)
	specificCmd  = byte(2)
)

//NewExecChan sets terminal to raw and makes ch -> os.Stdout and pipes stdin to the ch.
//Stores state in an ExecChan struct so stdin can be manipulated during authgrant process
func NewExecChan(cmd string, ch *channels.Reliable, wg *sync.WaitGroup) *ExecChan {
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	// defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	msg := newExecInitMsg(specificCmd, cmd)
	if cmd == "" {
		msg = newExecInitMsg(defaultShell, cmd)
	}
	ch.Write(msg.ToBytes())

	r, w := io.Pipe()
	ex := ExecChan{
		ch:    ch,
		state: oldState,
		redir: false,
		r:     r,
		w:     w,
	}

	go func(ex ExecChan) {
		defer wg.Done()
		io.Copy(os.Stdout, ex.ch) //read bytes from ch to os.Stdout
		term.Restore(int(os.Stdin.Fd()), ex.state)
		logrus.Info("Stopped io.Copy(os.Stdout, ch)")
		ex.ch.Close()
		logrus.Info("closed chan")

	}(ex)

	go func(ex *ExecChan) {
		p := make([]byte, 1)
		for {
			_, _ = os.Stdin.Read(p)
			if ex.redir {
				ex.w.Write(p)
			} else {
				ex.ch.Write(p)
			}
		}
	}(&ex)

	return &ex
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

//Parses raw bytes (not including length) of an execInitMsg
// func fromBytes(b []byte) *execInitMsg {
// 	m := execInitMsg{
// 		cmdType: b[0],
// 		cmdLen:  uint32(len(b) - 1),
// 	}
// 	m.cmd = ""
// 	if m.cmdLen > 0 {
// 		m.cmd = string(b[1:])
// 	}
// 	return &m
// }

//GetCmd reads execInitMsg from an EXEC_CHANNEL and returns the cmd to run
func GetCmd(c net.Conn) (string, error) {
	t := make([]byte, 1)
	c.Read(t)
	l := make([]byte, 4)
	c.Read(l)
	cmd := ""
	if t[0] == defaultShell {
		if c, ok := os.LookupEnv("SHELL"); ok {
			cmd = c + " --login"
			//" --login" forces bash to start as a login shell so it evaluates stuff in .bashrc,
			//but this probably isn't generalizeable to all possible default shells
			logrus.Infof("SHELL: %v", cmd)
		} else {
			logrus.Error("SHELL not set and no cmd specified")
			return "", errors.New("no command or shell")
		}

	} else {
		buf := make([]byte, binary.BigEndian.Uint32(l))
		c.Read(buf)
		cmd = string(buf)
	}
	cmd = os.ExpandEnv(cmd)
	return cmd, nil
}

//Server deals with serverside code exec channe details like pty size, copies ch -> pty and pty -> ch
func Server(ch *channels.Reliable, f *os.File) {
	defer ch.Close()
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
		_, e := io.Copy(f, ch)
		logrus.Info("io.Copy(f, ch) stopped with error: ", e)
		wg.Done()
	}()
	_, e := io.Copy(ch, f)
	logrus.Info("io.Copy(ch, f) stopped with error: ", e)
	wg.Wait()
}

//Resume makes sure the input is piped to the exec channel
func (e *ExecChan) Resume() {
	e.redir = false
}

//Redirect moves input to a pipe and returns the read end of the pipe
func (e *ExecChan) Redirect() *io.PipeReader {
	e.redir = true
	return e.r
}

//Restore returns the terminal to regular state
func (e *ExecChan) Restore() {
	term.Restore(int(os.Stdin.Fd()), e.state)
}

//Raw switches the terminal to raw mode
func (e *ExecChan) Raw() {
	term.MakeRaw(int(os.Stdin.Fd()))
}
