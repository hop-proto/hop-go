/*
Package provides functions specific to code execution channels
*/
package codex

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	ctxio "github.com/jbenet/go-context/io"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"
	"zmap.io/portal/channels"
)

type ExecChan struct {
	ch *channels.Reliable

	cancel context.CancelFunc //TODO(baumanl): make sure this is safe/reliable. Context doesn't even solve the user input glitch like I hoped it would.
	state  *term.State
	closed bool
}

//Sets terminal to raw and makes ch -> os.Stdout and pipes stdin to the ch.
//Stores state in an ExecChan struct so stdin can be manipulated during authgrant process
func NewExecChan(cmd []string, ch *channels.Reliable, wg *sync.WaitGroup) *ExecChan {
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	// defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	ch.Write(NewexecInitMsg(strings.Join(cmd, " ")).ToBytes())

	go func() {
		defer wg.Done()
		io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
		logrus.Info("Stopped io.Copy(os.Stdout, ch)")
	}()

	ctx, cancel := context.WithCancel(context.Background())
	in := ctxio.NewReader(ctx, os.Stdin)
	go io.Copy(ch, in)

	return &ExecChan{
		ch:     ch,
		cancel: cancel,
		state:  oldState,
		closed: false,
	}
}

type execInitMsg struct {
	msgLen uint32
	cmd    string
}

func NewexecInitMsg(c string) *execInitMsg {
	return &execInitMsg{
		msgLen: uint32(len(c)),
		cmd:    c,
	}
}

func (m *execInitMsg) ToBytes() []byte {
	r := make([]byte, 4)
	binary.BigEndian.PutUint32(r, m.msgLen)
	return append(r, []byte(m.cmd)...)
}

//Parses raw bytes (not including length) of an execInitMsg
func FromBytes(b []byte) *execInitMsg {
	return &execInitMsg{
		msgLen: uint32(len(b)),
		cmd:    string(b),
	}
}

//Reads execInitMsg from an EXEC_CHANNEL and returns the cmd to run
func GetCmd(c net.Conn) (string, error) {
	l := make([]byte, 4)
	c.Read(l)
	buf := make([]byte, binary.BigEndian.Uint32(l))
	c.Read(buf)
	msg := FromBytes(buf)
	return msg.cmd, nil
}

//deals with pty size, copies ch -> pty and pty -> ch
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
	go func() {
		_, e := io.Copy(f, ch)
		logrus.Info("io.Copy(f, ch) stopped with error: ", e)
	}()
	_, e := io.Copy(ch, f)
	logrus.Info("io.Copy(ch, f) stopped with error: ", e)
}

//Pipe stdin -> ch
func (e *ExecChan) Pipe() {
	if !e.closed {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	in := ctxio.NewReader(ctx, os.Stdin)

	go io.Copy(e.ch, in)
	e.cancel = cancel
	e.closed = false
}

//Stop stdin -> ch
func (e *ExecChan) ClosePipe() {
	e.cancel()
	e.closed = true
}

//Restores terminal to regular state
func (e *ExecChan) Restore() {
	term.Restore(int(os.Stdin.Fd()), e.state)
}

//Switches terminal to raw mode
func (e *ExecChan) Raw() {
	term.MakeRaw(int(os.Stdin.Fd()))
}
