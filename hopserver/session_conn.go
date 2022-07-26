package hopserver

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

// Functions used for serializing packets to/from stdin/stdout of the subprocess
func writePacket(w io.Writer, pkt []byte) error {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(pkt)))
	_, err := w.Write(length)
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// If buf is nil, an appropriately sized buffer will be allocated. Otherwise,
// the returned slice will use the same memory as the initial buffer. The
// returned slice has length equal to the number of bytes read from the packet
// (assuming no error is returned)
func readPacket(r io.Reader, buf []byte) ([]byte, error) {
	length := make([]byte, 4)
	_, err := io.ReadFull(r, length)
	if err != nil {
		return buf, err
	}
	n := int(binary.BigEndian.Uint32(length))
	if buf == nil {
		buf = make([]byte, n)
	}
	// We can ignore the number that io.ReadFull returns because "On return, n ==
	// len(buf) if and only if err == nil"
	_, err = io.ReadFull(r, buf[:n])
	return buf[:n], err
}

// sessionConn implements the transport.MsgConn interface, it handles
// communication between the session-specific child process and the parent hopd
// process
type sessionConn struct {
	buffered []byte
	in       *bufio.Reader
	out      *bufio.Writer
}

func (c *sessionConn) ReadMsg(b []byte) (int, error) {
	if c.buffered != nil {
		if len(c.buffered) > len(b) {
			return 0, transport.ErrBufOverflow
		}
		n := copy(b, c.buffered)
		c.buffered = nil
		return n, nil
	}
	buf, err := readPacket(c.in, nil)
	if err != nil {
		// 0 is not technically the number of bytes read, but this is sufficient
		// for our purposes
		return 0, err
	}
	copy(b, buf)
	return len(buf), nil
}

func (c *sessionConn) WriteMsg(b []byte) error {
	err := writePacket(c.out, b)
	if err != nil {
		return err
	}
	return c.out.Flush()
}

func (c *sessionConn) SetReadDeadline(time.Time) error {
	// TODO
	return nil
}

// Handles creating and communicating between serverConn and a session-specific subprocess
func launchSubprocessSession(serverConn *transport.Handle, key keys.PublicKey) error {
	// TODO(drebelsky): do we have a better mechanism to launch the subprocess
	session := exec.Command(os.Args[0], "-s")
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	err = session.Start()
	if err != nil {
		return err
	}

	// TODO(drebelsky): If this fails, we shuold figure out how to kill the subprocess
	if err = writePacket(stdin, []byte(key.String())); err != nil {
		return err
	}

	go func() {
		b := make([]byte, 65535)
		for {
			n, err := serverConn.ReadMsg(b)
			if err != nil {
				if !errors.Is(err, transport.ErrTimeout) {
					break
				}
			} else if n != 0 {
				err = writePacket(stdin, b[:n])
				if err != nil {
					break
				}
			}
		}
	}()

	go func() {
		b := make([]byte, 65535)
		for {
			buf, err := readPacket(stdout, b)
			if err != nil {
				break
			}
			err = serverConn.WriteMsg(append([]byte(nil), buf...))
			if err != nil {
				break
			}
		}
	}()

	go session.Wait()

	return nil
}
