/*
Package provides functions specific to code execution channels
*/
package codex

import (
	"context"
	"io"
	"log"
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

	w *io.PipeWriter
	r *io.PipeReader

	cancel context.CancelFunc
	state  *term.State
	closed bool
}

func NewExecChan(cmd []string, ch *channels.Reliable) *ExecChan {
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	// defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	ch.Write(NewExecInitMsg(strings.Join(cmd, " ")).ToBytes())

	go func() {
		io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
		logrus.Info("Stopped io.Copy(os.Stdout, ch)")
	}()

	r, w := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	cr := ctxio.NewReader(ctx, os.Stdin)

	go func() {
		io.Copy(w, cr)
		logrus.Info("Stopped io.Copy(w, os.Stdin)")
	}()

	go func() {
		io.Copy(ch, r)
		logrus.Info("Stopped io.Copy(ch, r)")
	}()
	return &ExecChan{
		ch:     ch,
		w:      w,
		r:      r,
		cancel: cancel,
		state:  oldState,
		closed: false,
	}
}

type ExecInitMsg struct {
	msgLen byte
	msg    string
}

func NewExecInitMsg(c string) *ExecInitMsg {
	return &ExecInitMsg{
		msgLen: byte(len(c)),
		msg:    c,
	}
}

func (m *ExecInitMsg) ToBytes() []byte {
	return append([]byte{m.msgLen}, []byte(m.msg)...)
}

//deals with pty size, copies ch -> pty and pty -> ch
func Serve(ch *channels.Reliable, f *os.File) {
	defer ch.Close()
	defer func() { _ = f.Close() }() // Best effort.
	// Handle pty size.
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

//Sends cmd to server, makes terminal raw, copies ch -> stdout
func Client(ch *channels.Reliable, cmd []string, w *sync.WaitGroup) {
	defer w.Done()

	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}

	ch.Write(NewExecInitMsg(strings.Join(cmd, " ")).ToBytes())

	io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
	logrus.Info("Stopped io.Copy(os.Stdout, ch)")
}

func (e *ExecChan) Pipe() {
	if !e.closed {
		return
	}
	r, w := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	cr := ctxio.NewReader(ctx, os.Stdin)

	go func() {
		io.Copy(w, cr)
		logrus.Debug("Stopped io.Copy(w, os.Stdin)")
	}()

	go func() {
		io.Copy(e.ch, r)
		logrus.Debug("Stopped io.Copy(ch, r)")
	}()
	e.w = w
	e.r = r
	e.cancel = cancel
	e.closed = false
}

func (e *ExecChan) ClosePipe() {
	e.w.Close()
	e.r.Close()
	e.cancel()
	e.closed = true
}

func (e *ExecChan) Restore() {
	term.Restore(int(os.Stdin.Fd()), e.state)
}

func (e *ExecChan) Raw() {
	term.MakeRaw(int(os.Stdin.Fd()))
}
