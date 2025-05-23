package main

import (
	"fmt"
	"io"
	"os"
	"time"
	"crypto/rand"

	"hop.computer/hop/certs"
)

func exit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func isEmptySlice(s []byte) bool {
	for b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

// validateRequest takes in a certificate request and ensures that the correct data is present
// and that no fields are filled in that should not be filled in.
// On an error, it exits the process with an error message
func validateRequest(cert *certs.Certificate) {
	if err != nil {
		exit(fmt.Sprintf("failed to read cert request: %v", err))
	}
	if !isEmptySlice(cert.Signature[:]) {
		exit("signature is already filled")
	}
	if cert.CertificateType != certs.Leaf {
		exit("request is not a leaf certificate")
	}
	if cert.IssuedAt != time.Time{} {
		exit("request has nonempty IssuedAt")
	}
	if cert.ExpiresAt != time.Time{} {
		exit("request has nonempty ExpiresAt")
	}
	if len(cert.IDChunk.Blocks) != 0 {
		// TODO(hosono) support additional names
		exit("certificate request can only include one name")
	}
	if name.Type != certs.TypeDNSName {
		// TODO(hosono) handle other types of names
		exit("can only request certificates for dns names")
	}
	if isEmptySlice(cert.PublicKey) {
		exit("certificate request has empty public key")
	}
	if !isEmptySlice(cert.Parent[:]) {
		exit("certificate has nonempty parent")
	}
	if !isEmptySlice(cert.Signature[:]) {
		exit("certificate has nonempty signature")
	}
	if !isEmptySlice(cert.Fingerprint[:]) {
		exit("certificate has nonempty fingerprint")
	}
}

func main() {
	// Step 1: Read certificate to be requested
	// The certificate should include a single DNSLabel and a public key
	cert := &certs.Certificate{}
	_, err := cert.ReadFrom(os.Stdin)
	validateRequest(cert)

	// Step 2: CA sends deployment key and a random challenge token
	domain:= cert.IDChunk.Blocks[0].String()
	pubKey := cert.PublicKey
	challenge := make([]byte, 32)
	rand.Read(challenge)

	fmt.Println("request validated!")
}
