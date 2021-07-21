package exec_channels

import (
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
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

func Serve(ch *channels.Reliable, principals *map[int32]*channels.Muxer, muxer *channels.Muxer) {
	defer ch.Close()
	l := make([]byte, 1)
	ch.Read(l)
	logrus.Infof("S: CMD LEN %v", int(l[0]))
	cmd := make([]byte, int(l[0]))
	ch.Read(cmd)
	logrus.Infof("Executing: %v", string(cmd))

	args := strings.Split(string(cmd), " ")
	c := exec.Command(args[0], args[1:]...)

	f, err := pty.Start(c)
	(*principals)[int32(c.Process.Pid)] = muxer
	//change c.Stdin and c.Stdout???
	if err != nil {
		logrus.Fatalf("S: error starting pty %v", err)
	}

	defer func() { _ = f.Close() }() // Best effort.

	if args[0] == "bash" {
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
			logrus.Infof("done 1: %v", e)
		}()

		_, e := io.Copy(ch, f)
		logrus.Infof("done 2: %v", e)
	} else {
		go func() {
			io.Copy(ch, f)
		}()
		c.Process.Wait()
	}
}

func RestoreTerm(state *terminal.State) {
	terminal.Restore(int(os.Stdin.Fd()), state)
}

func MakeRawTerm() *terminal.State {
	// MakeRaw put the terminal connected to the given file
	// descriptor into raw mode and returns the previous state
	// of the terminal so that it can be restored.
	oldState, e := terminal.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	return oldState
}

func Client(ch *channels.Reliable, cmd []string, w *sync.WaitGroup) {
	defer w.Done()
	ch.Write(NewExecInitMsg(strings.Join(cmd, " ")).ToBytes())

	if cmd[0] == "bash" { //start an interactive session
		go func() {
			_, e := io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
			logrus.Infof("done 3: %v", e)
		}()
		_, e := io.Copy(ch, os.Stdin)
		logrus.Infof("done 4: %v", e)
	} else { //run a one-shot command
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			io.Copy(os.Stdout, ch)
			wg.Done()
		}()
		go func() {
			ch.Close()
			wg.Done()
		}()
		wg.Wait()
	}
	//TODO: add support for interactive comands not bash (i.e. grep)

}
