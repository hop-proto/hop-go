package authgrants

import (
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/core"
)

// TargetInfo is sent from principal indicating target
type TargetInfo struct {
	TargetPort string
	TargetSNI  certs.Name
	TargetURL  core.URL
}

const confirmation = byte(1)
const denial = byte(0)

// WriteTargetInfo writes the relevant target info from given intent
func WriteTargetInfo(targURL core.URL, w io.Writer) error {
	_, err := common.WriteString(targURL.String(), w)
	return err
}

// ReadTargetInfo reads target info
func ReadTargetInfo(r io.Reader) (*core.URL, error) {
	url, _, err := common.ReadString(r)
	if err != nil {
		return nil, err
	}
	return core.ParseURL(url)
}

// ConnectToTarget initiates a udp conn to target
func (m *TargetInfo) ConnectToTarget() (*net.UDPConn, error) {
	// TODO(baumanl): make this work for all possible cert.Name.Types
	// hostname := string(m.TargetSNI.Label)
	// port := fmt.Sprint(m.TargetPort)
	// addr := net.JoinHostPort(hostname, port)
	addr := m.TargetURL.Address()

	throwaway, err := net.Dial("udp", addr)
	if err != nil {
		logrus.Error("couldn't connect to target: ", err)
		return nil, err
	}
	logrus.Info("connected to target")
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

	_, err = common.WriteString(errString, w)
	return err
}

// ReadResponse reads either confirmation or Failure message
func ReadResponse(r io.Reader) error {
	resp := make([]byte, 1)
	_, err := io.ReadFull(r, resp)
	if err != nil {
		return err
	}

	if resp[0] == confirmation {
		return nil
	}

	reason, _, err := common.ReadString(r)
	if err != nil {
		return err
	}
	return fmt.Errorf("%s", reason)
}

// WriteUnreliableProxyID writes tube id of unreliable tube to proxy
func WriteUnreliableProxyID(w io.Writer, id byte) error {
	_, err := w.Write([]byte{id})
	return err
}

// ReadUnreliableProxyID reads tube id of unreliable tube to proxy
func ReadUnreliableProxyID(r io.Reader) (byte, error) {
	id := make([]byte, 1)
	_, err := io.ReadFull(r, id)
	return id[0], err
}
