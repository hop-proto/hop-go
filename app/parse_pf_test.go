package app

import (
	"testing"

	"gotest.tools/assert"
)

func TestParse(t *testing.T) {
	//-R 10.10.2.3:5555:example.com:8888
	s := "10.10.2.3:5555:example.com:8888"
	fwdStruct := Fwd{}
	correctStruct := Fwd{
		Listensock:        true,
		Connectsock:       false,
		Listenhost:        "10.10.2.3",
		Listenportorpath:  "5555",
		Connecthost:       "example.com",
		Connectportorpath: "8888",
	}
	parseForward(s, &fwdStruct)
	assert.DeepEqual(t, fwdStruct, correctStruct)
}
