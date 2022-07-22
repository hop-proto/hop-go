package portforwarding

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"gotest.tools/assert"
)

func assertEqual(t *testing.T, fwdStruct, correctStruct Forward) {
	assert.DeepEqual(t, fwdStruct, correctStruct, cmp.AllowUnexported(Forward{}, Addr{}))
}

func TestParse(t *testing.T) {
	//valid formats
	A := "listen_port:connect_host:connect_port"
	correctStruct := Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "127.0.0.1:listen_port", //TODO: consider loopback expected
		},
		connect: Addr{
			netType: pfTCP,
			addr:    "connect_host:connect_port",
		},
	}
	fwdStruct, err := ParseForward(A)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	B := "listen_port:/connect_socket"
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "127.0.0.1:listen_port", //TODO: consider loopback expected
		},
		connect: Addr{
			netType: pfUNIX,
			addr:    "/connect_socket",
		},
	}
	fwdStruct, err = ParseForward(B)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	C := "listen_address:listen_port:connect_host:connect_port"
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "listen_address:listen_port",
		},
		connect: Addr{
			netType: pfTCP,
			addr:    "connect_host:connect_port",
		},
	}
	fwdStruct, err = ParseForward(C)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	D := "listen_address:listen_port:/connect_socket"
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "listen_address:listen_port",
		},
		connect: Addr{
			netType: pfUNIX,
			addr:    "/connect_socket",
		},
	}
	fwdStruct, err = ParseForward(D)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	E := "/listen_socket:connect_host:connect_port"
	correctStruct = Forward{
		listen: Addr{
			netType: pfUNIX,
			addr:    "/listen_socket",
		},
		connect: Addr{
			netType: pfTCP,
			addr:    "connect_host:connect_port",
		},
	}
	fwdStruct, err = ParseForward(E)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	F := "/listen_socket:/connect_socket"
	correctStruct = Forward{
		listen: Addr{
			netType: pfUNIX,
			addr:    "/listen_socket",
		},
		connect: Addr{
			netType: pfUNIX,
			addr:    "/connect_socket",
		},
	}
	fwdStruct, err = ParseForward(F)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	G := "[2001:db8::1]:listen_port:/connect_socket" //leading IPv6 address
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "[2001:db8::1]:listen_port",
		},
		connect: Addr{
			netType: pfUNIX,
			addr:    "/connect_socket",
		},
	}
	fwdStruct, err = ParseForward(G)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	H := "listen_port:[2001:db8::1]:connect_port" //connect IPv6 address
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "127.0.0.1:listen_port", //TODO: consider loopback expected
		},
		connect: Addr{
			netType: pfTCP,
			addr:    "[2001:db8::1]:connect_port",
		},
	}
	fwdStruct, err = ParseForward(H)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	I := "[2001:db8:3333:4444:5555:6666:7777:8888]:listen_port:[2001:db8::1]:connect_port" //listen and connect IPv6 address
	correctStruct = Forward{
		listen: Addr{
			netType: pfTCP,
			addr:    "[2001:db8:3333:4444:5555:6666:7777:8888]:listen_port",
		},
		connect: Addr{
			netType: pfTCP,
			addr:    "[2001:db8::1]:connect_port",
		},
	}
	fwdStruct, err = ParseForward(I)
	assert.NilError(t, err)
	assertEqual(t, *fwdStruct, correctStruct)

	//invalidFormats
	errOne := "arg1" // too few args
	fwdStruct, err = ParseForward(errOne)
	assert.Error(t, err, ErrInvalidPFArgs.Error())

	errTwo := "arg1:arg2:arg3:arg4:arg5" // too many args
	fwdStruct, err = ParseForward(errTwo)
	assert.Error(t, err, ErrInvalidPFArgs.Error())

}
