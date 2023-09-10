package transport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"gotest.tools/assert"

	"hop.computer/hop/authkeys"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

func TestClientCertificates(t *testing.T) {
	defer goleak.VerifyNone(t)

	baseConfig, verify := newTestServerConfig(t)
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
		go server.Serve()
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
			Exchanger:    clientKey,
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
			Exchanger:    clientKey,
			Leaf:         clientLeaf,
			Intermediate: nil,
			Verify:       *verify,
		}
	}

	assertHandshake := func(t *testing.T, clientConfig ClientConfig, server *Server) {
		client, err := Dial("udp", server.Addr().String(), clientConfig)
		assert.NilError(t, err)

		err = client.Handshake()
		assert.NilError(t, err)
		err = client.Close()
		assert.NilError(t, err)
		err = server.Close()
		assert.NilError(t, err)
	}

	assertNoHandshake := func(t *testing.T, clientConfig ClientConfig, server *Server) {
		client, err := Dial("udp", server.Addr().String(), clientConfig)
		assert.NilError(t, err)

		clientWg := sync.WaitGroup{}
		clientWg.Add(1)

		serverWg := sync.WaitGroup{}
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()

			// Don't Accept until after the client has "finished" a handshake.
			clientWg.Wait()
			h, err := server.AcceptTimeout(time.Millisecond * 100)

			// The AcceptTimeout should return with an ErrTimeout on a failed
			// handshake because there will be nothing to Accept.
			assert.Check(t, h == nil)
			assert.Equal(t, io.EOF, err)
		}()

		func() {
			// TODO(dadrian): We should have a better way of detecting handshake failure.
			defer clientWg.Done()
			err = client.Handshake()
			assert.NilError(t, err)
			err = client.Close()
			assert.NilError(t, err)
			err = server.Close()
			assert.NilError(t, err)
		}()
		serverWg.Wait()

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

	t.Run("self-signed expecting self-signed (authkeys)", func(t *testing.T) {
		var names []certs.Name
		clientConfig := selfSignClientLeaf(t, names...)
		set := authkeys.NewSyncAuthKeySet()
		set.AddKey(clientConfig.Leaf.PublicKey)
		verify := &VerifyConfig{
			AuthKeys:           set,
			AuthKeysAllowed:    true,
			InsecureSkipVerify: false,
		}
		server := startServer(t, verify)
		assertHandshake(t, clientConfig, server)
	})

	t.Run("self-signed with nonauthorized key", func(t *testing.T) {
		var names []certs.Name
		clientConfig := selfSignClientLeaf(t, names...)
		set := authkeys.NewSyncAuthKeySet()
		verify := &VerifyConfig{
			AuthKeys:           set,
			AuthKeysAllowed:    true,
			InsecureSkipVerify: false,
		}
		server := startServer(t, verify)
		assertNoHandshake(t, clientConfig, server)
	})

}
