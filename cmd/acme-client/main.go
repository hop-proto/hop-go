package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
)

func main() {
	domainAndKey := acme.DomainNameAndKey{
		DomainName: "request.com",
		PublicKey:  [certs.KeyLen]byte{},
	}
	rand.Read(domainAndKey.PublicKey[:])

	_, err := domainAndKey.Write(os.Stdout)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(1)
	}
}
