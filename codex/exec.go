// Package codex provides functions specific to code execution tubes
package codex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/muesli/cancelreader"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"

	"hop.computer/hop/tubes"
)

// ExecTube wraps a code execution tube with additional terminal state
type ExecTube struct {
	tube  *tubes.Reliable
	state *term.State

	// lock is used to pause copy operations
	lock *sync.RWMutex
}

// Config is the options required to start an ExecTube
type Config struct {
	Cmd        string
	UsePty     bool
	StdinTube  *tubes.Reliable
	StdoutTube *tubes.Reliable
	WinTube    *tubes.Reliable
	WaitGroup  *sync.WaitGroup

	InPipe  io.Reader
	OutPipe io.Writer
}

const (
	usePtyFlag  = 0x1
	hasSizeFlag = 0x2
)

const (
	execConf = byte(1)
	execFail = byte(2)
)

// CanAcceptFunc is a callback that reports whether the sender window
// is currently able to accept more data. It should return true if
// s.frames has room for more entries.
type CanAcceptFunc func() bool

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
func NewExecTube(c Config) (*ExecTube, error) {
	var oldState *term.State
	var e error
	var termEnv string
	var size *pty.Winsize
	if c.UsePty {
		logrus.Info("starting codex with pty")
		termEnv = os.Getenv("TERM")
		size, _ = pty.GetsizeFull(os.Stdin) // ignoring the error is okay here because then size is set to nil
		oldState, e = term.MakeRaw(int(os.Stdin.Fd()))
		if e != nil {
			logrus.Infof("C: error with terminal state: %v", e)
		}
	} else {
		logrus.Info("starting codex with no pty")
		oldState = nil
	}
	msg := newExecInitMsg(c.UsePty, c.Cmd, termEnv, size)
	_, e = c.StdinTube.Write(msg.ToBytes())
	if e != nil {
		logrus.Error(e)
		return nil, e
	}

	//get confirmation that cmd started successfully before piping IO
	err := getStatus(c.StdoutTube)
	if err != nil {
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		logrus.Error("C: server failed to start cmd with error: ", err)
		return nil, err
	}

	if c.UsePty {
		logrus.WithField("winTubeID", c.WinTube.GetID()).Debug("Starting winTube")
		// Send window size updates to window channel
		go func() {
			defer c.WinTube.Close()
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGWINCH)
			b := make([]byte, 8)
			for range ch {
				if size, err := pty.GetsizeFull(os.Stdin); err == nil {
					serializeSize(b, size)
					if _, err = c.WinTube.Write(b); err != nil {
						break
					}
				}
			}
		}()
	}

	var inPipe io.Reader
	inPipe, err = cancelreader.NewReader(c.InPipe)
	if err != nil {
		logrus.Infof("could not create cancel reader %v", err)
		inPipe = c.InPipe
	}

	ex := ExecTube{
		tube:  c.StdoutTube,
		state: oldState,
		lock:  &sync.RWMutex{},
	}

	c.WaitGroup.Add(2)
	go func(ex *ExecTube) {
		defer c.WaitGroup.Done()
		n, err := pausableCopy(c.OutPipe, c.StdoutTube, ex.lock, nil)
		if err != nil {
			logrus.Errorf("codex: error copying from tube to stdout: %s", err)
		}
		logrus.WithField("bytes", n).Info("Stopped io.Copy(OutPipe, StdoutTube)")
		ex.tube.Close()
		logrus.Info("closed stdout tube")
		if inp, ok := inPipe.(cancelreader.CancelReader); ok {
			inp.Cancel()
		}
		logrus.Info("closed stdin tube")

	}(&ex)

	go func(ex *ExecTube) {
		defer c.WaitGroup.Done()
		n, err := pausableCopy(c.StdinTube, inPipe, ex.lock, c.StdinTube.CanAcceptBytes)
		if err != nil {
			logrus.Errorf("codex: error copying from stdin to tube: %s", err)
		}
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		logrus.WithField("bytes", n).Info("Stopped io.Copy(StdinTube, InPipe)")
		c.StdinTube.Close()
		logrus.Info("closed stdin tube")
	}(&ex)

	return &ex, nil
}

// pausableCopy copies everything from src to dst.
// When lock.Lock() is called in another goroutine, pausableCopy temoporarily
// stops copying data until lock.Unlock() is called.
// This method is based on the code from io.Copy
func pausableCopy(dst io.Writer, src io.Reader, lock *sync.RWMutex, canAccept CanAcceptFunc) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64 = 0
	var err error
	for {
		if nil != canAccept && !canAccept() {
			time.Sleep(10 * time.Millisecond) // avoid busy waiting = tubes.minRTT
			continue
		}
		lock.RLock()
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		lock.RUnlock()
	}
	lock.RUnlock()
	return written, err
}

// +checklocksignore
func (e *ExecTube) SuspendPipes() {
	e.lock.Lock()
}

// +checklocksignore
func (e *ExecTube) ResumePipes() {
	e.lock.Unlock()
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
	defer tube.Close()
	for {
		if size, err := readSize(tube); err == nil {
			pty.Setsize(ptyFile, size)
		} else {
			if !errors.Is(err, io.EOF) {
				logrus.Warnf("Handle size exited with unexpected error: %s", err)
			}
			return
		}
	}
}

// Server deals with serverside code exec channel details like pty size, copies ch -> pty and pty -> ch
func Server(stdinTube, stdoutTube *tubes.Reliable, f *os.File) {
	defer stdinTube.Close()
	defer stdoutTube.Close()
	defer func() { _ = f.Close() }() // Best effort.

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		_, e := io.Copy(f, stdinTube)
		logrus.Info("io.Copy(f, tube) stopped with error: ", e)
		wg.Done()
	}()

	// TODO(hosono) This solves a race condition that intermittently causes login shells to fail.
	// We should find a real solution
	time.Sleep(5 * time.Millisecond)

	_, e := io.Copy(stdoutTube, f)
	logrus.Info("io.Copy(tube, f) stopped with error: ", e)
	wg.Wait()
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
