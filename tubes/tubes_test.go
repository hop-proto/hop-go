//nolint
package tubes

import (
	"net"
	"testing"

	"golang.org/x/net/nettest"
	"gotest.tools/assert"

	"hop.computer/hop/hoptests"
)

func makeConn(t *testing.T) (c1, c2 net.Conn, stop func(), err error){
		s := hoptests.NewTestServer(t)
		c := hoptests.NewTestClient(t, s, "username")

		s.AddClientToAuthorizedKeys(t, c)

		s.StartTransport(t)
		s.StartHopServer(t)

		c.StartClient(t)

		c1, err = c.TubeMuxer.CreateTube(Reliable)
		assert.NilError(t, err)
		// TODO(hosono) accept tube on other end

		return
}

func TestTubes(t *testing.T) {
	mk := nettest.MakePipe(
		func() (c1, c2 net.Conn, stop func(), err error) {
			return makeConn(t)
	})
	nettest.TestConn(t, mk)
}
