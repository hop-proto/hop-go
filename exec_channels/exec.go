package exec_channels

import (
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
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

func Serve(ch *channels.Reliable) {
	defer ch.Close()
	logrus.Infof("S: ACCEPTED NEW CHANNEL (%v)", ch.Type())

	l := make([]byte, 1)
	ch.Read(l)
	logrus.Infof("S: CMD LEN %v", int(l[0]))
	cmd := make([]byte, int(l[0]))
	ch.Read(cmd)
	logrus.Infof("Executing: %v", string(cmd))

	args := strings.Split(string(cmd), " ")
	c := exec.Command(args[0], args[1:]...)

	f, err := pty.Start(c)
	if err != nil {
		logrus.Fatalf("S: error starting pty %v", err)
	}

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

func Client(ch *channels.Reliable, cmd []string) {
	// MakeRaw put the terminal connected to the given file
	// descriptor into raw mode and returns the previous state
	// of the terminal so that it can be restored.
	oldState, e := terminal.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", e)
	}
	defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldState) }()

	ch.Write(NewExecInitMsg(strings.Join(cmd, " ")).ToBytes())

	go func() {
		io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
	}()

	io.Copy(ch, os.Stdin)
}
