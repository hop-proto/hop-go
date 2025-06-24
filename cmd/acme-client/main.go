package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/hopserver"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
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

func startChallengeServer(domainName string, challengeString string, ourKeys *keys.X25519KeyPair, caPubKey keys.PublicKey) *hopserver.HopServer {
	_, intermediate, leaf := genCerts(domainName, ourKeys)
	leafBytes, err := leaf.Marshal()
	checkErr(err)
	intermediateBytes, err := intermediate.Marshal()
	checkErr(err)

	t := true
	sc := &config.ServerConfig{
		ListenAddress:        ":7777",
		HiddenModeVHostNames: []string{domainName},
		InsecureSkipVerify:   &t,
		HandshakeTimeout:     time.Minute,
		Challenge:            challengeString,
	}
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
	reqKeyPair := keys.GenerateNewX25519KeyPair()

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
	caPubKey := keys.PublicKey{}
	_, err = io.ReadFull(os.Stdin, caPubKey[:])
	checkErr(err)

	challenge := make([]byte, base64.StdEncoding.EncodedLen(acme.ChallengeLen))
	_, err = io.ReadFull(os.Stdin, challenge)
	checkErr(err)
	challengeString := string(challenge)
	fmt.Fprintf(os.Stderr, "client got challenge string: %s\n", challengeString)

	// Step 3: Requester informs CA that challenge is complete
	fmt.Fprintln(os.Stderr, "Step 3")
	server := startChallengeServer(domainName, challengeString, keyPair, caPubKey)
	_, err = os.Stdout.Write([]byte{1})
	checkErr(err)

	// Step 4: CA checks that client controls identifier
	fmt.Fprintln(os.Stderr, "Step 4")

	var ok byte
	err = binary.Read(os.Stdin, binary.BigEndian, &ok)
	checkErr(err)
	if ok != 1 {
		err = fmt.Errorf("confirmation was %d instead of 1", ok)
		checkErr(err)
	}
	server.Close()

	// Step 5: Make certificate request
	fmt.Fprintln(os.Stderr, "Step 5")
	request := acme.CertificateRequest{
		Name:   certs.DNSName(domainName),
		PubKey: reqKeyPair.Public,
	}
	_, err = request.WriteTo(os.Stdout)
	checkErr(err)

	// Step 6: Receive certificate
	fmt.Fprintln(os.Stderr, "Step 6")
	cert := certs.Certificate{}
	_, err = cert.ReadFrom(os.Stdin)
	checkErr(err)

	certBuf, err := certs.EncodeCertificateToPEM(&cert)
	checkErr(err)

	fmt.Fprintln(os.Stderr, string(certBuf))
}
