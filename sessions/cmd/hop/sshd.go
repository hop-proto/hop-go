package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Modified from https://gist.github.com/jpillora/b480fde82bff51a06238

func sshd() {
	log.Println("starting sshd")

	// create server config, use username/password for client authentication
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "foo" && string(pass) == "bar" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	// Add host key to server
	// can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(".ssh/id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (id_rsa)")
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	config.AddHostKey(private)

	// will need to swap out net.Listen for our own custom Listener.
	// Listen(network, address) only takes tcp, tcp4, tcp6, unix, or unixpacket as the network
	// pick some port to listen on
	listener, err := net.Listen("tcp", "0.0.0.0:2234")
	if err != nil {
		log.Printf("failed to listen for connection: (%s)", err)
	}

	log.Println("listening on 2234...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: (%s)", err)
			continue
		}

		// start a new SSH server with tcpConn as the underlying transport
		// why does this return multiple channels?
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("failed to handshake: (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// discard all global out-of-band Requests
		// TODO: what does this mean?
		go ssh.DiscardRequests(reqs)
		// accept all channels
		go handleChannels(chans)

	}

}

func handleChannels(chans <-chan ssh.NewChannel) {
	// service incoming channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	t := newChannel.ChannelType()

	if t != "session" {
		log.Printf("Unknown channel type: %s", t)
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// start bash for this session
	bashCmd := exec.Command("bash")

	// prepare teardown function
	closeConnection := func() {
		connection.Close()
		_, err := bashCmd.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}

	// Allocate a PTY for this channel
	log.Println("Creating pty...")
	bashf, err := pty.Start(bashCmd) // bashf is an open file descriptor
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		closeConnection()
		return
	}

	// pipe session to bash and vice-versa
	// seems to print after client closes session?
	var once sync.Once
	go func() {
		nbCopied, _ := io.Copy(connection, bashf)
		log.Printf("Num copied bashf -> connection: (%d)", nbCopied)
		once.Do(closeConnection)
	}()
	go func() {
		nbCopied, _ := io.Copy(bashf, connection)
		log.Printf("Num copied connection -> bashf: (%d)", nbCopied)
		once.Do(closeConnection)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				log.Printf("PTY req: w: %d, h: %d", w, h)
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				log.Printf("Window size change: w: %d, h: %d", w, h)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
