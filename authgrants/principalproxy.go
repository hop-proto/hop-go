package authgrants

import (
	"encoding/binary"
	"io"

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

func (m *TargetInfo) ConnectToTarget() error {
	hostname :=
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
