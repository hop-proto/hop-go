package main

import (
	"fmt"
	"io"
	"os"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/transport"

	// "hop.computer/hop/certs"
	"hop.computer/hop/hopserver"
	"hop.computer/hop/keys"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

// Generates a fully self-signed chain for the given key pair
func genCerts(domainName string, ourKeys *keys.X25519KeyPair) (root, intermediate, leaf *certs.Certificate) {
	rootKeys := keys.GenerateNewSigningKeyPair()
	rootCert, err := certs.SelfSignRoot(certs.SigningIdentity(rootKeys), rootKeys)
	checkErr(err)
	err = rootCert.ProvideKey((*[32]byte)(&rootKeys.Private))
	checkErr(err)

	intermediateKeys := keys.GenerateNewSigningKeyPair()
	intermediateCert, err := certs.IssueIntermediate(rootCert, certs.SigningIdentity(intermediateKeys))
	checkErr(err)
	err = intermediateCert.ProvideKey((*[32]byte)(&intermediateKeys.Private))
	checkErr(err)

	leafCert, err := certs.IssueLeaf(intermediateCert, certs.LeafIdentity(ourKeys, certs.DNSName(domainName)))
	checkErr(err)

	return rootCert, intermediateCert, leafCert
}

func startChallengeServer(domainName string, challenge [32]byte, ourKeys *keys.X25519KeyPair, caPubKey keys.PublicKey) *hopserver.HopServer {
	_, intermediate, leaf := genCerts(domainName, ourKeys)
	leafBytes, err := leaf.Marshal()
	checkErr(err)
	intermediateBytes, err := intermediate.Marshal()
	checkErr(err)

	sc := &config.ServerConfig{}
	b := true
	sc.EnableAuthorizedKeys = &b
	sc.TransportCert = &transport.Certificate{
		RawLeaf:         leafBytes,
		RawIntermediate: intermediateBytes,
		Exchanger:       ourKeys,
		Leaf:            leaf,
		HostName:        domainName,
	}

	server, err := hopserver.NewHopServer(sc)
	checkErr(err)

	go func() {
		server.Serve()
	}()

	return server
}

func main() {
	domainName := "request.com"

	// Step 1: Send domain name and public key to CA
	fmt.Fprintln(os.Stderr, "Step 1")
	keyPair := keys.GenerateNewX25519KeyPair()
	domainAndKey := acme.DomainNameAndKey{
		DomainName: domainName,
		PublicKey:  keyPair.Public,
	}
	_, err := domainAndKey.Write(os.Stdout)
	checkErr(err)

	// Step 2: Receive public key and challenge from server
	fmt.Fprintln(os.Stderr, "Step 2")
	challenge := make([]byte, acme.ChallengeLen)
	_, err = io.ReadFull(os.Stdin, challenge)
	checkErr(err)

	caPubKey := keys.PublicKey{}
	_, err = io.ReadFull(os.Stdin, caPubKey[:])
	checkErr(err)

	// Step 3: Requester informs CA that challenge is complete
	fmt.Fprintln(os.Stderr, "Step 3")
	server := startChallengeServer(domainName, [32]byte(challenge), keyPair, caPubKey)
	_, err = os.Stdout.Write([]byte{1})

	// Step 4: CA checks that client controls identifier
	fmt.Fprintln(os.Stderr, "Step 4")

	server.Close()

	// Step 5: Make certificate request
	fmt.Fprintln(os.Stderr, "Step 5")

	// Step 6: Receive certificate
	fmt.Fprintln(os.Stderr, "Step 6")
}
