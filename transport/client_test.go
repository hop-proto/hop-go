package transport

import (
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
)

func TestClientCertificates(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	baseConfig, verify := newTestServerConfig(t)
	baseConfig.StartingReadTimeout = 10 * time.Second
	baseConfig.MaxPendingConnections = 1
	baseConfig.MaxBufferedPacketsPerConnection = 5

	clientRootKey := keys.GenerateNewSigningKeyPair()
	clientIntermediateKey := keys.GenerateNewSigningKeyPair()
	clientKey := keys.GenerateNewX25519KeyPair()

	clientRootIdentity := certs.Identity{
		PublicKey: clientRootKey.Public,
		Names:     []certs.Name{certs.RawStringName("Client Root")},
	}

	clientRoot, err := certs.SelfSignRoot(&clientRootIdentity, clientRootKey)
	clientRoot.ProvideKey((*[32]byte)(&clientRootKey.Private))
	assert.NilError(t, err)

	clientIntermediateIdentity := certs.Identity{
		PublicKey: clientIntermediateKey.Public,
		Names:     []certs.Name{certs.RawStringName("Client Intermediate")},
	}
	clientIntermediate, err := certs.IssueIntermediate(clientRoot, &clientIntermediateIdentity)
	clientIntermediate.ProvideKey((*[32]byte)(&clientIntermediateKey.Private))
	assert.NilError(t, err)

	clientRootStore := certs.Store{}
	clientRootStore.AddCertificate(clientRoot)

	startServer := func(t *testing.T, verify *VerifyConfig) *Server {
		pc, err := net.ListenPacket("udp", "localhost:0")
		assert.NilError(t, err)
		config := *baseConfig
		config.ClientVerify = verify
		server, err := NewServer(pc.(*net.UDPConn), config)
		assert.NilError(t, err)
		go func() {
			server.Serve()
		}()
		return server
	}

	issueClientLeaf := func(t *testing.T, names ...certs.Name) ClientConfig {
		clientLeafIdentity := certs.Identity{
			PublicKey: clientKey.Public,
			Names:     names,
		}
		clientLeaf, err := certs.IssueLeaf(clientIntermediate, &clientLeafIdentity)
		assert.NilError(t, err)

		return ClientConfig{
			KeyPair:      clientKey,
			Leaf:         clientLeaf,
			Intermediate: clientIntermediate,
			Verify:       *verify,
		}
	}

	selfSignClientLeaf := func(t *testing.T, names ...certs.Name) ClientConfig {
		clientLeafIdentity := certs.Identity{
			PublicKey: clientKey.Public,
			Names:     names,
		}
		clientLeaf, err := certs.SelfSignLeaf(&clientLeafIdentity)
		assert.NilError(t, err)

		return ClientConfig{
			KeyPair:      clientKey,
			Leaf:         clientLeaf,
			Intermediate: nil,
			Verify:       *verify,
		}
	}

	assertHandshake := func(t *testing.T, clientConfig ClientConfig, server *Server) {
		client, err := Dial("udp", server.ListenAddress().String(), clientConfig)
		assert.NilError(t, err)

		err = client.Handshake()
		assert.NilError(t, err)
		err = client.Close()
		assert.NilError(t, err)
		err = server.Close()
		assert.NilError(t, err)
	}

	assertNoHandshake := func(t *testing.T, clientConfig ClientConfig, server *Server) {
		client, err := Dial("udp", server.ListenAddress().String(), clientConfig)
		assert.NilError(t, err)

		go func() {
			_, err := server.AcceptTimeout(time.Second * 1)
			assert.Check(t, err != nil)
		}()

		// TODO(dadrian): We should have a better way of detecting handshake failure.
		err = client.Handshake()
		assert.Check(t, err)
		err = client.Close()
		assert.Check(t, err)
	}

	t.Run("username with no auth", func(t *testing.T) {
		clientConfig := issueClientLeaf(t, certs.RawStringName("dadrian"))
		server := startServer(t, nil)
		assertHandshake(t, clientConfig, server)

	})

	t.Run("username with chain auth", func(t *testing.T) {
		clientConfig := issueClientLeaf(t, certs.RawStringName("dadrian"))
		verify := &VerifyConfig{
			Store: clientRootStore,
		}
		server := startServer(t, verify)
		assertHandshake(t, clientConfig, server)
	})

	t.Run("name with no auth", func(t *testing.T) {
		clientConfig := issueClientLeaf(t, certs.DNSName("hop.computer"))
		server := startServer(t, nil)
		assertHandshake(t, clientConfig, server)
	})

	t.Run("name with chain auth", func(t *testing.T) {
		clientConfig := issueClientLeaf(t, certs.DNSName("hop.computer"))
		verify := &VerifyConfig{
			Store: clientRootStore,
		}
		server := startServer(t, verify)
		assertHandshake(t, clientConfig, server)
	})

	t.Run("username with bad signature", func(t *testing.T) {
		clientConfig := issueClientLeaf(t, certs.RawStringName("username"))
		clientConfig.Leaf.Signature[8] ^= 0xFF
		verify := &VerifyConfig{
			Store: clientRootStore,
		}
		server := startServer(t, verify)
		assertNoHandshake(t, clientConfig, server)
	})

	t.Run("self-signed with username when expecting chain", func(t *testing.T) {
		clientConfig := selfSignClientLeaf(t, certs.RawStringName("username"))
		server := startServer(t, verify)
		assertNoHandshake(t, clientConfig, server)
	})

	t.Run("self-signed with no name when expecting chain", func(t *testing.T) {
		var names []certs.Name
		clientConfig := selfSignClientLeaf(t, names...)
		server := startServer(t, verify)
		assertNoHandshake(t, clientConfig, server)
	})

	t.Run("self-signed with username when expecting self-signed", func(t *testing.T) {
		clientConfig := selfSignClientLeaf(t, certs.RawStringName("username"))
		server := startServer(t, nil)
		assertHandshake(t, clientConfig, server)
	})

}
