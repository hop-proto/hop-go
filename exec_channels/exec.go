package exec_channels

import (
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"
	"zmap.io/portal/channels"
)

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
		io.Copy(f, ch)
	}()
	io.Copy(ch, f)
}

//Sends cmd to server, makes terminal raw, copies ch -> stdout and stdin -> ch
func Client(ch *channels.Reliable, cmd []string, w *sync.WaitGroup, r io.Reader) {
	defer w.Done()
	ch.Write(NewExecInitMsg(strings.Join(cmd, " ")).ToBytes())
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	//TODO: check exit behavior esp. with noninteractive (oneshot) cmds
	//r, wr := io.Pipe() //Pipe seems to help with closing behavior? not positive if necessary
	go func() {
		io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
		//wr.Close()
	}()
	// go func() {
	// 	io.Copy(wr, os.Stdin)
	// }()
	//io.Copy(ch, r)
	io.Copy(ch, os.Stdin)
	//io.Copy(ch, r)
}
