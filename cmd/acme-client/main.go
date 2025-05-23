package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	// Step 1: Send domain name and public key to CA
	domainAndKey := acme.DomainNameAndKey{
		DomainName: "request.com",
		PublicKey:  [certs.KeyLen]byte{},
	}
	rand.Read(domainAndKey.PublicKey[:])

	_, err := domainAndKey.Write(os.Stdout)
	checkErr(err)

	// Step 2: Receive public key and challenge from server
	challenge := make([]byte, acme.ChallengeLen)
	_, err = io.ReadFull(os.Stdin, challenge)
	checkErr(err)

	caPubKey := keys.PublicKey{}
	_, err = io.ReadFull(os.Stdin, caPubKey[:])
	checkErr(err)

	// Step 3: Requester informs CA that challenge is complete
	// TODO acutally complete challenge
	_, err = os.Stdout.Write([]byte{1})

	// Step 4: CA checks that client controls identifier

	// Step 5: Make certificate request

	// Step 6: Receive certificate
}
