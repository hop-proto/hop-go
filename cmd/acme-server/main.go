package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"hop.computer/hop/acme"
	"hop.computer/hop/keys"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	// Step 1: Read domain to be requested and the public key that it will be advertized with
	domainAndKey := acme.DomainNameAndKey{}
	err := domainAndKey.Read(os.Stdin)
	checkErr(err)
	// domain := domainAndKey.DomainName
	// pubKey := domainAndKey.PublicKey

	// Step 2: CA sends deployment key and a random challenge token
	challenge := make([]byte, acme.ChallengeLen)
	rand.Read(challenge)

	keyPair := keys.GenerateNewX25519KeyPair()

	_, err = os.Stdout.Write(keyPair.Public[:])
	checkErr(err)
	_, err = os.Stdout.Write(challenge)
	checkErr(err)

	// Step 3: Wait for confirmation that challenge is ready
	var ok byte
	err = binary.Read(os.Stdin, binary.BigEndian, &ok)
	checkErr(err)
	if ok != 1 {
		err = fmt.Errorf("confirmation was %d instead of 1", ok)
		checkErr(err)
	}

	// Step 4: CA checks that client controls identifier
	// TODO do this

	// Step 5: Requester makes certificate request

	// Step 6: CA issues certificate
}
