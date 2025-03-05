package portforwarding

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gotest.tools/assert"
)

func assertEqual(t *testing.T, fwdStruct, correctStruct Forward) {
	assert.DeepEqual(t, fwdStruct, correctStruct, cmp.Comparer(func(a, b Forward) bool {
		return a.listen.String() == b.listen.String() && a.connect.String() == b.connect.String()
	}))
}

func TestParse(t *testing.T) {
	// Valid formats
	A := "listen_port:connect_host:connect_port"
	correctStruct := Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: parsePort("listen_port"),
		},
		connect: &net.TCPAddr{
			IP:   net.ParseIP("connect_host"),
			Port: parsePort("connect_port"),
		},
	}
	fwdStruct, err := ParseForward(A)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	B := "listen_port:/connect_socket"
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: parsePort("listen_port"),
		},
		connect: &net.UnixAddr{
			Name: "/connect_socket",
			Net:  "unix",
		},
	}
	fwdStruct, err = ParseForward(B)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	C := "listen_address:listen_port:connect_host:connect_port"
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("listen_address"),
			Port: parsePort("listen_port"),
		},
		connect: &net.TCPAddr{
			IP:   net.ParseIP("connect_host"),
			Port: parsePort("connect_port"),
		},
	}
	fwdStruct, err = ParseForward(C)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	D := "listen_address:listen_port:/connect_socket"
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("listen_address"),
			Port: parsePort("listen_port"),
		},
		connect: &net.UnixAddr{
			Name: "/connect_socket",
			Net:  "unix",
		},
	}
	fwdStruct, err = ParseForward(D)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	E := "/listen_socket:connect_host:connect_port"
	correctStruct = Forward{
		listen: &net.UnixAddr{
			Name: "/listen_socket",
			Net:  "unix",
		},
		connect: &net.TCPAddr{
			IP:   net.ParseIP("connect_host"),
			Port: parsePort("connect_port"),
		},
	}
	fwdStruct, err = ParseForward(E)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	F := "/listen_socket:/connect_socket"
	correctStruct = Forward{
		listen: &net.UnixAddr{
			Name: "/listen_socket",
			Net:  "unix",
		},
		connect: &net.UnixAddr{
			Name: "/connect_socket",
			Net:  "unix",
		},
	}
	fwdStruct, err = ParseForward(F)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	G := "[2001:db8::1]:listen_port:/connect_socket" // leading IPv6 address
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("[2001:db8::1]"),
			Port: parsePort("listen_port"),
		},
		connect: &net.UnixAddr{
			Name: "/connect_socket",
			Net:  "unix",
		},
	}
	fwdStruct, err = ParseForward(G)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	H := "listen_port:[2001:db8::1]:connect_port" // connect IPv6 address
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: parsePort("listen_port"),
		},
		connect: &net.TCPAddr{
			IP:   net.ParseIP("[2001:db8::1]"),
			Port: parsePort("connect_port"),
		},
	}
	fwdStruct, err = ParseForward(H)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	I := "[2001:db8:3333:4444:5555:6666:7777:8888]:listen_port:[2001:db8::1]:connect_port" // listen and connect IPv6 address
	correctStruct = Forward{
		listen: &net.TCPAddr{
			IP:   net.ParseIP("[2001:db8:3333:4444:5555:6666:7777:8888]"),
			Port: parsePort("listen_port"),
		},
		connect: &net.TCPAddr{
			IP:   net.ParseIP("[2001:db8::1]"),
			Port: parsePort("connect_port"),
		},
	}
	fwdStruct, err = ParseForward(I)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	// Invalid formats
	errOne := "arg1" // too few args
	_, err = ParseForward(errOne)
	assert.Error(t, err, ErrInvalidPFArgs.Error())

	errTwo := "arg1:arg2:arg3:arg4:arg5" // too many args
	_, err = ParseForward(errTwo)
	assert.Error(t, err, ErrInvalidPFArgs.Error())
}
