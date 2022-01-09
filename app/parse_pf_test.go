package app

import (
	"testing"

	"gotest.tools/assert"
)

func TestParse(t *testing.T) {
	//valid formats
	A := "listen_port:connect_host:connect_port"
	fwdStruct := Fwd{}
	correctStruct := Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "listen_port",
		Connecthost:       "connect_host",
		Connectportorpath: "connect_port",
	}
	err := parseForward(A, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	B := "listen_port:/connect_socket"
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       true,
		Listenhost:        "",
		Listenportorpath:  "listen_port",
		Connecthost:       "",
		Connectportorpath: "/connect_socket",
	}
	err = parseForward(B, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	C := "listen_address:listen_port:connect_host:connect_port"
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "listen_address",
		Listenportorpath:  "listen_port",
		Connecthost:       "connect_host",
		Connectportorpath: "connect_port",
	}
	err = parseForward(C, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	D := "listen_address:listen_port:/connect_socket"
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       true,
		Listenhost:        "listen_address",
		Listenportorpath:  "listen_port",
		Connecthost:       "",
		Connectportorpath: "/connect_socket",
	}
	err = parseForward(D, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	E := "/listen_socket:connect_host:connect_port"
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        true,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "/listen_socket",
		Connecthost:       "connect_host",
		Connectportorpath: "connect_port",
	}
	err = parseForward(E, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	F := "/listen_socket:/connect_socket"
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        true,
		Connectsock:       true,
		Listenhost:        "",
		Listenportorpath:  "/listen_socket",
		Connecthost:       "",
		Connectportorpath: "/connect_socket",
	}
	err = parseForward(F, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	G := "[2001:db8::1]:listen_port:/connect_socket" //leading IPv6 address
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       true,
		Listenhost:        "2001:db8::1",
		Listenportorpath:  "listen_port",
		Connecthost:       "",
		Connectportorpath: "/connect_socket",
	}
	err = parseForward(G, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	H := "listen_port:[2001:db8::1]:connect_port" //connect IPv6 address
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "listen_port",
		Connecthost:       "2001:db8::1",
		Connectportorpath: "connect_port",
	}
	err = parseForward(H, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	I := "[2001:db8:3333:4444:5555:6666:7777:8888]:listen_port:[2001:db8::1]:connect_port" //listen and connect IPv6 address
	fwdStruct = Fwd{}
	correctStruct = Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "2001:db8:3333:4444:5555:6666:7777:8888",
		Listenportorpath:  "listen_port",
		Connecthost:       "2001:db8::1",
		Connectportorpath: "connect_port",
	}
	err = parseForward(I, &fwdStruct)
	assert.NilError(t, err)
	assert.DeepEqual(t, fwdStruct, correctStruct)

	//invalidFormats
	errOne := "arg1" // too few args
	fwdStruct = Fwd{}
	err = parseForward(errOne, &fwdStruct)
	assert.Error(t, err, ErrInvalidPFArgs.Error())

	errTwo := "arg1:arg2:arg3:arg4:arg5" // too many args
	fwdStruct = Fwd{}
	err = parseForward(errTwo, &fwdStruct)
	assert.Error(t, err, ErrInvalidPFArgs.Error())

}
