package authgrants

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
)

// TargetInfo is sent from principal indicating target
type TargetInfo struct {
	TargetPort uint16
	TargetSNI  certs.Name
}

const confirmation = byte(1)
const denial = byte(0)

// WriteTo serializes an InitInfo message
func (m *TargetInfo) WriteTo(w io.Writer) (int64, error) {
	var written int64
	// write port number
	err := binary.Write(w, binary.BigEndian, m.TargetPort)
	if err != nil {
		return written, err
	}
	written += 2

	// write targetSNI
	n, err := m.TargetSNI.WriteTo(w)
	written += n
	return written, err
}

// ReadFrom reads a serialized InitInfo message
func (m *TargetInfo) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	// read target port
	err := binary.Read(r, binary.BigEndian, &m.TargetPort)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += 2

	// read targetSNI
	n, err := m.TargetSNI.ReadFrom(r)
	bytesRead += n
	return bytesRead, err
}

// ConnectToTarget initiates a udp conn to target
func (m *TargetInfo) ConnectToTarget() (*net.UDPConn, error) {
	// TODO(baumanl): make this work for all possible cert.Name.Types
	hostname := string(m.TargetSNI.Label)
	port := fmt.Sprint(m.TargetPort)
	addr := net.JoinHostPort(hostname, port)

	throwaway, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()
	return net.DialUDP("udp", nil, remoteAddr.(*net.UDPAddr))
}

// WriteConfirmation used by proxy to tell principal it successfully connected
// to target.
func WriteConfirmation(w io.Writer) error {
	_, err := w.Write([]byte{confirmation})
	return err
}

// WriteFailure used by proxy to tell principal it did not connect to target
func WriteFailure(w io.Writer, errString string) error {
	_, err := w.Write([]byte{denial})
	if err != nil {
		return err
	}

	_, err = writeString(errString, w)
	return err
}

// ReadResponse reads either confirmation or Failure message
func ReadResponse(r io.Reader) (bool, string, error) {
	var resp byte
	_, err := r.Read([]byte{resp})
	if err != nil {
		return false, "", err
	}

	if resp == confirmation {
		return true, "", nil
	}

	reason, _, err := readString(r)
	return false, reason, err
}

// WriteUnreliableProxyID writes tube id of unreliable tube to proxy
func WriteUnreliableProxyID(w io.Writer, id byte) error {
	_, err := w.Write([]byte{id})
	return err
}

// ReadUnreliableProxyID reads tube id of unreliable tube to proxy
func ReadUnreliableProxyID(r io.Reader) (byte, error) {
	var id byte
	_, err := r.Read([]byte{id})
	return id, err
}

// UDPLike interface standardizes Reliable channels and UDPConn.
// Reliable channels implement this interface so they can be used as the underlying conn for Clients
// TODO(baumanl): this is also defined in transport/client.go --> figure out
// best organization
type UDPLike interface {
	net.Conn
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// UnreliableProxyHelper proxies msgs from two udplike connections
func UnreliableProxyHelper(a UDPLike, b UDPLike) {
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, _, _, err := a.ReadMsgUDP(buf, nil)
			if err != nil {
				logrus.Error(err)
				continue
				// TODO(baumanl): what should actually be done here
			}
			_, _, err = b.WriteMsgUDP(buf[:n], nil, nil)
			if err != nil {
				logrus.Error(err)
				continue
				// TODO(baumanl): what should we do
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, _, _, _, err := b.ReadMsgUDP(buf, nil)
		if err != nil {
			logrus.Error(err)
			continue
			// TODO(baumanl): what should actually be done here
		}
		_, _, err = a.WriteMsgUDP(buf[:n], nil, nil)
		if err != nil {
			logrus.Error(err)
			continue
			// TODO(baumanl): what should we do
		}
	}

}
