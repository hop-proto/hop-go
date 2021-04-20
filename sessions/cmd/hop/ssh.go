package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func parseHost(userHost string) (string, string, error) {
	split := strings.Split(userHost, "@")
	if len(split) != 2 || strings.Contains(userHost, ":") {
		return "", "", errors.New("Invalid user host format")
	}
	return split[0], split[1], nil
}

func getClient(userHost string) (*ssh.Client, error) {

	user, host, err := parseHost(userHost)
	if err != nil {
		return nil, err
	}
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password("bar"),
		},
		// TODO (drew): consider fixed host key
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// TODO: support custom ports
	port := 2234

	// TODO: When the channel layer is completed, this code will look somewhat like:
	// conn := transport.Dial("udp", "localhost:1234")
	// reliableChannel = reliable.NewChannel(transportConn)
	// client, err := ssh.NewClientConn(reliableChannel, otherargs....)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)

	if err != nil {
		return nil, err
	}

	return client, nil
}

func setupTerminal(session *ssh.Session) (*term.State, error) {
	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
		return nil, err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	go io.Copy(stdin, os.Stdin)

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	go io.Copy(os.Stdout, stdout)

	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, err
	}
	go io.Copy(os.Stderr, stderr)

	// Set stdin in raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	return oldState, nil
}

/**
* Inspired by https://gist.github.com/svett/b7f56afc966a6b6ac2fc and
* https://pkg.go.dev/golang.org/x/crypto/ssh#example-Session.RequestPty.
 */
func sshClient(userHost string) error {
	client, err := getClient(userHost)
	if err != nil {
		return err
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	oldState, err := setupTerminal(session)
	if err != nil {
		return err
	}
	defer func() { term.Restore(int(os.Stdin.Fd()), oldState) }()

	if err = session.Shell(); err != nil {
		return err
	}

	if err = session.Wait(); err != nil {
		return err
	}

	return nil
}
