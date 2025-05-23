package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"hop.computer/hop/acme"
)

func exit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func main() {
	// Step 1: Read domain to be requested and the public key that it will be advertized with
	domainAndKey := acme.DomainNameAndKey{}
	err := domainAndKey.Read(os.Stdin)
	if err != nil {
		exit(err.Error())
	}
	// domain := domainAndKey.DomainName
	// pubKey := domainAndKey.PublicKey

	// Step 2: CA sends deployment key and a random challenge token
	challenge := make([]byte, 32)
	rand.Read(challenge)

	fmt.Println("request validated!")
}
