package codex

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"

	"hop.computer/hop/tubes"
)

// ExecTube wraps a code execution tube with additional terminal state
type ExecTube struct {
	tube  *tubes.Reliable
	state *term.State
	redir bool
	r     *io.PipeReader
	w     *io.PipeWriter
}

const (
	usePtyFlag  = 0x1
	hasSizeFlag = 0x2
)

const (
	execConf = byte(1)
	execFail = byte(2)
)

// SendFailure lets the client know that executing the command failed and the error
func SendFailure(t *tubes.Reliable, err error) {
	msg := make([]byte, 5+len(err.Error()))
	msg[0] = execFail
	binary.BigEndian.PutUint16(msg[1:], uint16(len(err.Error())))
	copy(msg[5:], []byte(err.Error()))
	t.Write(msg)
}

// SendSuccess lets the client know that the server successful started the command
func SendSuccess(t *tubes.Reliable) {
	t.Write([]byte{execConf})
}

// GetStatus lets client waits for confirmation that cmd started or error if it failed
func getStatus(t *tubes.Reliable) error {
	// TODO(drebelsky): consider how to handle erros in io.ReadFull
	resp := make([]byte, 1)
	io.ReadFull(t, resp)
	if resp[0] == execConf {
		return nil
	}
	elen := make([]byte, 4)
	io.ReadFull(t, elen)
	buf := make([]byte, binary.BigEndian.Uint16(elen))
	io.ReadFull(t, buf)
	return errors.New(string(buf))
}

// NewExecTube sets terminal to raw and makes ch -> os.Stdout and pipes stdin to the ch.
// Stores state in an ExecChan struct so stdin can be manipulated during authgrant process
func NewExecTube(cmd string, usePty bool, tube *tubes.Reliable, winTube *tubes.Reliable, wg *sync.WaitGroup) (*ExecTube, error) {
	var oldState *term.State
	var e error
	var termEnv string
	var size *pty.Winsize
	if usePty {
		termEnv = os.Getenv("TERM")
		size, _ = pty.GetsizeFull(os.Stdin) // ignoring the error is okay here becaus then size is set to nil
		oldState, e = term.MakeRaw(int(os.Stdin.Fd()))
		if e != nil {
			logrus.Infof("C: error with terminal state: %v", e)
		}
	} else {
		oldState = nil
	}
	msg := newExecInitMsg(usePty, cmd, termEnv, size)
	_, e = tube.Write(msg.ToBytes())
	if e != nil {
		logrus.Error(e)
		return nil, e
	}

	//get confirmation that cmd started successfully before piping IO
	err := getStatus(tube)
	if err != nil {
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		logrus.Error("C: server failed to start cmd with error: ", err)
		return nil, err
	}

	if usePty {
		// Send window size updates to window channel
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGWINCH)
			b := make([]byte, 8)
			for range ch {
				if size, err := pty.GetsizeFull(os.Stdin); err == nil {
					serializeSize(b, size)
					if _, err = winTube.Write(b); err != nil {
						break
					}
				}
			}
		}()
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
		io.Copy(os.Stdout, ex.tube) // read bytes from tube to os.Stdout
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		logrus.Info("Stopped io.Copy(os.Stdout, tube)")
		ex.tube.Close()
		logrus.Info("closed tube")

	}(&ex)

	go func(ex *ExecTube) {
		io.Copy(tube, os.Stdin)
		tube.Close()
	}(&ex)

	return &ex, nil
}

type execInitMsg struct {
	usePty  bool
	cmdLen  uint32
	cmd     string
	termLen uint32
	term    string
	size    *pty.Winsize
}

func newExecInitMsg(usePty bool, c, term string, size *pty.Winsize) *execInitMsg {
	return &execInitMsg{
		usePty:  usePty,
		cmdLen:  uint32(len(c)),
		cmd:     c,
		termLen: uint32(len(term)),
		term:    term,
		size:    size,
	}
}

func (m *execInitMsg) ToBytes() []byte {
	length := 9 + m.cmdLen + m.termLen
	if m.size != nil {
		length += 8
	}
	r := make([]byte, length)
	if m.usePty {
		r[0] |= usePtyFlag
	}
	if m.size != nil {
		r[0] |= hasSizeFlag
	}
	binary.BigEndian.PutUint32(r[1:], m.cmdLen)
	if m.cmdLen > 0 {
		copy(r[5:], []byte(m.cmd))
	}
	binary.BigEndian.PutUint32(r[5+m.cmdLen:], m.termLen)
	if m.termLen > 0 {
		copy(r[9+m.cmdLen:], []byte(m.term))
	}
	if m.size != nil {
		sizeStart := int(9+m.cmdLen) + len(m.term)
		serializeSize(r[sizeStart:], m.size)
	}
	return r
}

// GetCmd reads execInitMsg from an EXEC_CHANNEL and returns the cmd to run
func GetCmd(c net.Conn) (string, string, bool, *pty.Winsize, error) {
	//TODO (drebelsky): consider handling io errors
	t := make([]byte, 1)
	io.ReadFull(c, t)
	usePty := (t[0] & usePtyFlag) != 0
	hasSize := (t[0] & hasSizeFlag) != 0
	l := make([]byte, 4)
	io.ReadFull(c, l)
	buf := make([]byte, binary.BigEndian.Uint32(l))
	io.ReadFull(c, buf)
	io.ReadFull(c, l)
	term := make([]byte, binary.BigEndian.Uint32(l))
	io.ReadFull(c, term)
	var size *pty.Winsize
	if hasSize {
		size, _ = readSize(c)
	}
	return string(buf), string(term), usePty, size, nil
}

func readSize(r io.Reader) (*pty.Winsize, error) {
	b := make([]byte, 8)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return &pty.Winsize{
		Rows: binary.BigEndian.Uint16(b),
		Cols: binary.BigEndian.Uint16(b[2:]),
		X:    binary.BigEndian.Uint16(b[4:]),
		Y:    binary.BigEndian.Uint16(b[6:]),
	}, nil
}

// serializeSize serializes a *pty.Winsize, into the start of b; it assumes b
// has space for (at least) 8 bytes
func serializeSize(b []byte, size *pty.Winsize) {
	binary.BigEndian.PutUint16(b, size.Rows)
	binary.BigEndian.PutUint16(b[2:], size.Cols)
	binary.BigEndian.PutUint16(b[4:], size.X)
	binary.BigEndian.PutUint16(b[6:], size.Y)
}

// HandleSize deals with resizing the pty according to messages from a WinSize tube
func HandleSize(tube *tubes.Reliable, ptyFile *os.File) {
	for {
		if size, err := readSize(tube); err == nil {
			pty.Setsize(ptyFile, size)
		}
	}
}

// Server deals with serverside code exec channe details like pty size, copies ch -> pty and pty -> ch
func Server(tube *tubes.Reliable, f *os.File) {
	defer tube.Close()
	defer func() { _ = f.Close() }() // Best effort.
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

// Resume makes sure the input is piped to the exec tube
func (e *ExecTube) Resume() {
	e.redir = false
}

// Redirect redirects os.Stdin to a pipe and returns the read end
func (e *ExecTube) Redirect() *io.PipeReader {
	e.redir = true
	return e.r
}

// Restore returns the terminal to regular state
func (e *ExecTube) Restore() {
	if e.state != nil {
		term.Restore(int(os.Stdin.Fd()), e.state)
	}
}

// Raw switches the terminal to raw mode
func (e *ExecTube) Raw() {
	if e.state != nil {
		term.MakeRaw(int(os.Stdin.Fd()))
	}
}
