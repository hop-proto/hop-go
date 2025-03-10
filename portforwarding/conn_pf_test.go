package portforwarding

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestReadPacket(t *testing.T) {
	tests := []struct {
		name            string
		input           []byte
		expectedAddr    net.Addr
		expectedFwdType byte
		expectErr       bool
	}{
		{
			name: "Valid TCP address",
			input: func() []byte {
				ipPort := "192.168.0.1:80"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(ipPort)))
				return append([]byte{byte(PfTCP), PfLocal}, append(addrLen, []byte(ipPort)...)...)
			}(),
			expectedAddr:    &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 80},
			expectedFwdType: PfLocal,
			expectErr:       false,
		},
		{
			name: "Valid UDP address",
			input: func() []byte {
				ipPort := "127.0.0.1:53"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(ipPort)))
				return append([]byte{byte(PfUDP), PfLocal}, append(addrLen, []byte(ipPort)...)...)
			}(),
			expectedAddr:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
			expectedFwdType: PfLocal,
			expectErr:       false,
		},
		{
			name: "Valid UNIX address",
			input: func() []byte {
				unixAddr := "/tmp/unix.sock"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(unixAddr)))
				return append([]byte{byte(PfUNIX), PfRemote}, append(addrLen, []byte(unixAddr)...)...)
			}(),
			expectedAddr:    &net.UnixAddr{Name: "/tmp/unix.sock", Net: "unix"},
			expectedFwdType: PfRemote,
			expectErr:       false,
		},
		{
			name: "Error: Invalid address length",
			input: func() []byte {
				ipPort := "127.01:53"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(14))
				return append([]byte{byte(PfUNIX), PfRemote}, append(addrLen, []byte(ipPort)...)...)
			}(),
			expectedAddr:    nil,
			expectedFwdType: 0,
			expectErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			addr, fwdType, err := readPacket(r)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check the address
			if addr.String() != tt.expectedAddr.String() {
				t.Errorf("expected address %v, got %v", tt.expectedAddr, addr)
			}

			// Check the forward type
			if *fwdType != tt.expectedFwdType {
				t.Errorf("expected forward type %v, got %v", tt.expectedFwdType, *fwdType)
			}
		})
	}
}

func TestToBytes(t *testing.T) {
	tests := []struct {
		name      string
		inputAddr net.Addr
		fwdType   int
		expected  []byte
	}{
		{
			name:      "TCP Address",
			inputAddr: &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 80},
			fwdType:   PfLocal,
			expected: func() []byte {
				ipPort := "192.168.0.1:80"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(ipPort)))
				return append([]byte{byte(PfTCP), PfLocal}, append(addrLen, []byte(ipPort)...)...)
			}(),
		},
		{
			name:      "UDP Address",
			inputAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
			fwdType:   PfLocal,
			expected: func() []byte {
				ipPort := "127.0.0.1:53"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(ipPort)))
				return append([]byte{byte(PfUDP), PfLocal}, append(addrLen, []byte(ipPort)...)...)
			}(),
		},
		{
			name:      "UNIX Address",
			inputAddr: &net.UnixAddr{Name: "/tmp/unix.sock", Net: "unix"},
			fwdType:   PfRemote,
			expected: func() []byte {
				unixAddr := "/tmp/unix.sock"
				addrLen := make([]byte, 2)
				binary.BigEndian.PutUint16(addrLen, uint16(len(unixAddr)))
				return append([]byte{byte(PfUNIX), PfRemote}, append(addrLen, []byte(unixAddr)...)...)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toBytes(tt.inputAddr, tt.fwdType)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
