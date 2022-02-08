package glob

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

type globTest struct {
	pattern string
	in      string
	out     bool
}

var globTests = []globTest{
	{pattern: "*.example.com", in: "sub.example.com", out: true},
	{pattern: "example.com", in: "sub.example.com", out: false},
	{pattern: "example.com", in: "example.com", out: true},
	{pattern: "example.*", in: "example.com", out: true},
	{pattern: "example.*", in: "ope.example", out: false},
	{pattern: "example.*", in: "example.domain.local", out: true},
	{pattern: "d*d", in: "david", out: true},
	{pattern: "d*d", in: "davidadrian", out: false},
	{pattern: "d*d", in: "dave", out: false},
	{pattern: "d*", in: "dave", out: true},
	{pattern: "d*", in: "dd", out: true},
	{pattern: "d*v*", in: "dave", out: true},
	{pattern: "d*v*", in: "david", out: true},
	{pattern: "d*v*d", in: "david", out: true},
	{pattern: "d*v*d", in: "dave", out: false},
}

func TestGlob(t *testing.T) {
	for i, input := range globTests {
		d := input
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			out := Glob(d.pattern, d.in)
			assert.Check(t, cmp.Equal(d.out, out), "%s against %s", d.in, d.pattern)
		})
	}
}
