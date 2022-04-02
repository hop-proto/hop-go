package core

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

type urlTestInput struct {
	raw     string
	address string
	s       string
	e       string
}

var inputs = []urlTestInput{
	{
		raw:     "hop://user@host:1234",
		address: "host:1234",
		s:       "hop://user@host:1234",
	},
	{
		raw:     "hop://user@host",
		address: "host",
		s:       "hop://user@host",
	},
}

func TestURL(t *testing.T) {
	for i, in := range inputs {
		in := in
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			u, err := ParseURL(in.raw)
			if in.e != "" {
				assert.Assert(t, err != nil)
				return

			}
			assert.NilError(t, err)
			assert.Check(t, cmp.Equal(in.address, u.Address()))
			assert.Check(t, cmp.Equal(in.s, u.String()))
		})
	}
}
