package acme

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/config"
	"hop.computer/hop/hopclient"
	"hop.computer/hop/keys"
)

type AcmeClientConfig struct {
	*config.HostConfig
	Key           *keys.X25519KeyPair
	DomainName    string
	ChallengePort uint16
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

func (c *AcmeClient) startChallengeServer(listenAddr string, challenge []byte, ourKeys *keys.X25519KeyPair, caCert *certs.Certificate) (*AcmeServer, error) {
	root, intermediate, leaf, err := createCertChain(c.Config.DomainName, ourKeys)
	if err != nil {
		return nil, err
	}

	config := &AcmeServerConfig{
		ServerConfig: &config.ServerConfig{
			Key:              ourKeys,
			Certificate:      leaf,
			Intermediate:     intermediate,
			ListenAddress:    listenAddr,
			HandshakeTimeout: 5 * time.Minute,
			DataTimeout:      5 * time.Minute,
			CACerts:          []*certs.Certificate{root, intermediate},
			EnableAuthgrants: true,
		},
		SigningCertificate: nil,
		IsChallengeServer:  true,
		Challenge:          challenge,
		Log:                c.log.WithField("challengeServer", ""),
	}

	server, err := NewAcmeServer(config)
	if err != nil {
		return nil, err
	}

	server.AddAuthGrant(&authgrants.Intent{
		GrantType:      authgrants.Acme,
		StartTime:      time.Now(),
		ExpTime:        time.Now().Add(time.Hour),
		TargetUsername: AcmeUser,
		DelegateCert:   *caCert,
	})

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
		Port:       c.Config.ChallengePort,
		PublicKey:  reqKeyPair.Public,
	}
	_, err = domainAndKey.WriteTo(tube)
	if err != nil {
		return nil, err
	}

	// Step 2: Receive certificate and challenge from server
	c.log.Info("Step 2: Receive certificate and challenge from server")
	challenge := &CertAndChallenge{}
	_, err = challenge.ReadFrom(tube)
	if err != nil {
		return nil, err
	}

	c.log.Infof("client got challenge: %x\n", challenge.Challenge)

	// Step 3: Requester informs CA that challenge is complete
	c.log.Info("Step 3: Requester informs CA that challenge is complete")
	localAddr := "localhost:" + strconv.Itoa(int(c.Config.ChallengePort))
	server, err := c.startChallengeServer(localAddr, challenge.Challenge, reqKeyPair, challenge.Cert)
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
