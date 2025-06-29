package acme

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/config"
	"hop.computer/hop/hopclient"
	"hop.computer/hop/keys"
)

type AcmeClientConfig struct {
	*config.HostConfig
	Key        keys.X25519KeyPair
	DomainName string
}

type AcmeClient struct {
	*hopclient.HopClient
	Config *AcmeClientConfig
	log    *logrus.Entry
}

func NewAcmeClient(hc *AcmeClientConfig) (*AcmeClient, error) {
	client, err := hopclient.NewHopClient(hc.HostConfig)
	if err != nil {
		return nil, err
	}

	return &AcmeClient{
		HopClient: client,
		Config:    hc,
		log:       logrus.WithField("client", ""),
	}, nil
}

func (c *AcmeClient) Dial() error {
	return c.HopClient.Dial()
}

func (c *AcmeClient) startChallengeServer(challengeString string, ourKeys *keys.X25519KeyPair, caPubKey keys.PublicKey) (*AcmeServer, error) {
	root, intermediate, leaf, err := createCertChain(c.Config.DomainName, ourKeys)
	if err != nil {
		return nil, err
	}

	config := &AcmeServerConfig{
		ServerConfig: &config.ServerConfig{
			Key:                ourKeys,
			Certificate:        leaf,
			Intermediate:       intermediate,
			ListenAddress:      "localhost:8888",
			HandshakeTimeout:   5 * time.Minute,
			DataTimeout:        5 * time.Minute,
			CACerts:            []*certs.Certificate{root, intermediate},
			InsecureSkipVerify: true, // TODO(hosono) only allow the CA to see the challenge
		},
		SigningCertificate: nil,
		IsChallengeServer:  true,
		ChallengeString:    challengeString,
		log:                c.log.WithField("challengeServer", ""),
	}

	server, err := NewAcmeServer(config)
	if err != nil {
		return nil, err
	}

	go server.Serve()

	return server, err
}

func (c *AcmeClient) Run() (*certs.Certificate, error) {
	tube, err := c.TubeMuxer.CreateReliableTube(common.ExecTube)
	if err != nil {
		return nil, err
	}

	reqKeyPair := keys.GenerateNewX25519KeyPair()

	// Step 1: Send domain name and public key to CA
	c.log.Info("Step 1: Send domain name and public key to CA")
	domainAndKey := DomainNameAndKey{
		DomainName: c.Config.DomainName,
		PublicKey:  reqKeyPair.Public,
	}
	_, err = domainAndKey.Write(tube)
	if err != nil {
		return nil, err
	}

	// Step 2: Receive public key and challenge from server
	c.log.Info("Step 2: Receive public key and challenge from server")
	caPubKey := keys.PublicKey{}
	_, err = tube.Read(caPubKey[:])
	if err != nil {
		return nil, err
	}

	challenge := make([]byte, base64.StdEncoding.EncodedLen(ChallengeLen))
	_, err = io.ReadFull(tube, challenge)
	if err != nil {
		return nil, err
	}
	challengeString := string(challenge)
	c.log.Infof("client got challenge string: %s\n", challengeString)

	// Step 3: Requester informs CA that challenge is complete
	c.log.Info("Step 3: Requester informs CA that challenge is complete")
	server, err := c.startChallengeServer(challengeString, reqKeyPair, caPubKey)
	if err != nil {
		return nil, err
	}
	_, err = tube.Write([]byte{1})
	if err != nil {
		return nil, err
	}

	// Step 4: CA checks that client controls identifier
	c.log.Info("Step 4: CA checks that client controls identifier")

	var ok byte
	err = binary.Read(tube, binary.BigEndian, &ok)
	if err != nil {
		return nil, err
	}
	server.Close()
	if ok != 1 {
		return nil, fmt.Errorf("confirmation was %d instead of 1", ok)
	}

	// Step 5: Make certificate request
	c.log.Info("Step 5: Make certificate request")
	request := CertificateRequest{
		Name:   certs.DNSName(c.Config.DomainName),
		PubKey: c.Config.Key.Public,
	}
	_, err = request.WriteTo(tube)
	if err != nil {
		return nil, err
	}

	// Step 6: Receive certificate
	c.log.Info("Step 6: Receive certificate")
	cert := &certs.Certificate{}
	_, err = cert.ReadFrom(tube)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
