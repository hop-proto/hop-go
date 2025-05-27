package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/acme"
	"hop.computer/hop/config"
	"hop.computer/hop/hopclient"
	"hop.computer/hop/keys"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	// Step 1: Read domain to be requested and the public key that it will be advertized with
	fmt.Fprintln(os.Stderr, "Server: Step 1")
	domainAndKey := acme.DomainNameAndKey{}
	err := domainAndKey.Read(os.Stdin)
	checkErr(err)
	domain := domainAndKey.DomainName
	pubKey := domainAndKey.PublicKey

	// Step 2: CA sends deployment key and a random challenge token
	fmt.Fprintln(os.Stderr, "Server: Step 2")
	challenge := make([]byte, acme.ChallengeLen)
	rand.Read(challenge)
	challengeString := base64.StdEncoding.EncodeToString(challenge)

	keyPair := keys.GenerateNewX25519KeyPair()

	_, err = os.Stdout.Write(keyPair.Public[:])
	checkErr(err)
	_, err = os.Stdout.Write([]byte(challengeString))
	checkErr(err)

	fmt.Fprintf(os.Stderr, "challenge: %s\npubkey: %s\n", challengeString, base64.StdEncoding.EncodeToString(keyPair.Public[:]))

	// Step 3: Wait for confirmation that challenge is ready
	fmt.Fprintln(os.Stderr, "Server: Step 3")
	var ok byte
	err = binary.Read(os.Stdin, binary.BigEndian, &ok)
	checkErr(err)
	if ok != 1 {
		err = fmt.Errorf("confirmation was %d instead of 1", ok)
		checkErr(err)
	}

	// Step 4: CA checks that client controls identifier
	fmt.Fprintln(os.Stderr, "Server: Step 4")
	pipeReader, pipeWriter := io.Pipe()
	fakeReader, _ := io.Pipe()
	clientKeys := keys.GenerateNewX25519KeyPair()
	var t = true
	var username = acme.AcmeUser
	hc := &config.HostConfigOptional{
		AutoSelfSign:   &t,
		KeyPair:        clientKeys,
		ServerName:     &domain,
		Port:           7777,
		ServerKeyBytes: pubKey,
		User:           &username,
		Input:          fakeReader,
		Output:         pipeWriter,
	}
	clientConfig := hc.Unwrap()
	// prevent logging from messing up communication
	client, err := hopclient.NewHopClient(clientConfig)
	checkErr(err)
	err = client.Dial()
	checkErr(err)

	go func() {
		err = client.Start()
		checkErr(err)
	}()

	challengeResponse := make([]byte, base64.StdEncoding.EncodedLen(acme.ChallengeLen))
	fmt.Fprintln(os.Stderr, "waiting for client response")
	_, err = io.ReadFull(pipeReader, challengeResponse)
	fmt.Fprintf(os.Stderr, "expected challenge: %s\n", challengeString)
	fmt.Fprintf(os.Stderr, "finished pipe read: %s\n", string(challengeResponse))
	checkErr(err)

	if challengeString != string(challengeResponse) {
		fmt.Fprintf(os.Stderr, "CHALLENGE RESPONSE DID NOT MATCH")
		os.Exit(2)
	} else {
		fmt.Fprintf(os.Stderr, "CHALLENGE MATCHED RESPONSE")
	}

	// Send confimation back to requester
	_, err = os.Stdout.Write([]byte{1})
	checkErr(err)
	client.Close()

	// Step 5: Requester makes certificate request
	fmt.Fprintln(os.Stderr, "Serer: Step 5")

	// Step 6: CA issues certificate
	fmt.Fprintln(os.Stderr, "Serer: Step 6")
}
