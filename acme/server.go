package acme

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing/fstest"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/config"
	"hop.computer/hop/hopclient"
	"hop.computer/hop/hopserver"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
	"hop.computer/hop/userauth"
)

type sessID uint32

type AcmeServerConfig struct {
	*config.ServerConfig
	SigningCertificate *certs.Certificate
	IsChallengeServer  bool
	Challenge          []byte
	Log                *logrus.Entry
}

// AcmeServer represents the state of a server engaging in the acme protocol
type AcmeServer struct {
	*hopserver.HopServer
	Config *AcmeServerConfig
	// +checklocks:sessionLock
	sessions      map[sessID]*AcmeSession
	nextSessionID atomic.Uint32
	sessionLock   sync.Mutex
}

type AcmeSession struct {
	transportConn *transport.Handle
	tubeMuxer     *tubes.Muxer
	log           *logrus.Entry

	ID     sessID
	server *AcmeServer
}

func NewAcmeServer(sc *AcmeServerConfig) (*AcmeServer, error) {
	inner, err := hopserver.NewHopServer(sc.ServerConfig)
	if err != nil {
		return nil, err
	}

	return &AcmeServer{
		HopServer: inner,
		Config:    sc,
		sessions:  make(map[sessID]*AcmeSession),
	}, nil
}

// Serve listens for incoming hop connection requests and starts
// corresponding agproxy on unix socket
func (s *AcmeServer) Serve() {
	go s.Server.Serve() // start transport layer server
	logrus.Info("hop server starting")

	for {
		serverConn, err := s.Server.AcceptTimeout(30 * time.Minute)
		// io.EOF indicates the server was closed, which is ok
		if errors.Is(err, io.EOF) {
			return
		} else if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CONNECTION")
		go s.newSession(serverConn)
	}
}

func (s *AcmeServer) newSession(serverConn *transport.Handle) {
	muxerConfig := tubes.Config{
		Timeout: s.Config.DataTimeout,
		Log:     logrus.WithField("muxer", "acme_server"),
	}
	sess := &AcmeSession{
		transportConn: serverConn,
		tubeMuxer:     tubes.Server(serverConn, &muxerConfig),
		server:        s,
		ID:            sessID(s.nextSessionID.Load()),
	}
	sess.log = s.Config.Log.WithField("session", sess.ID)
	sess.log.Debug("created session")
	s.nextSessionID.Add(1)
	s.sessionLock.Lock()
	s.sessions[sess.ID] = sess
	s.sessionLock.Unlock()

	var err error
	if s.Config.IsChallengeServer {
		err = sess.StartChallenge()
	} else {
		err = sess.Start()
	}
	if err != nil {
		sess.log.Warnf("session failed: %v", err)
	}
}

func (s *AcmeSession) StartChallenge() error {
	s.log.Info("checking authgrant")

	t, err := s.tubeMuxer.Accept()
	if err != nil {
		return err
	}
	uaTube, ok := t.(*tubes.Reliable)
	if !ok || uaTube.Type() != common.UserAuthTube {
		return fmt.Errorf("did not get userauth tube")
	}
	defer uaTube.Close()

	username := userauth.GetInitMsg(uaTube) // client sends desired username
	leaf := s.transportConn.FetchClientLeaf()
	k := keys.PublicKey(leaf.PublicKey)
	s.log.Info("got userauth init message: ", k.String())

	ags, err := s.server.AuthorizeKeyAuthGrant(username, k)
	if err != nil {
		return err
	}
	if len(ags) == 1 && ags[0].GrantType == authgrants.Acme && time.Now().Before(ags[0].ExpTime) {
		s.log.Info("client authorized to receive challenge")
		uaTube.Write([]byte{userauth.UserAuthConf})
	} else {
		return fmt.Errorf("client is not authorized to receive challenge")
	}

	s.log.Info("sending challenge")
	tube, err := s.tubeMuxer.Accept()
	if err != nil {
		return err
	}
	_, err = tube.Write(s.server.Config.Challenge)
	if err != nil {
		return err
	}
	return tube.Close()
}

func (s *AcmeSession) Start() error {
	tube, err := s.tubeMuxer.Accept()
	if err != nil {
		s.Close()
		return err
	}
	if tube.Type() != common.ExecTube {
		return fmt.Errorf("acme Session type `%d` instead of ExecTube", tube.Type())
	}

	// Step 1: Read domain to be requested and the public key that it will be advertized with
	s.log.Info("Step 1: read domain and key")
	domainAndKey := DomainNameAndKey{}
	err = domainAndKey.Read(tube)
	if err != nil {
		return err
	}
	domain := domainAndKey.DomainName

	// Step 2: CA sends deployment cert and a random challenge token
	s.log.Info("Step 2. CA sends new deployment cert and random challenge token")

	challenge, err := MakeChallenge()
	if err != nil {
		return err
	}
	_, err = challenge.WriteTo(tube)
	if err != nil {
		return err
	}

	s.log.Infof("challenge: %x\npubkey: %s\n", challenge.Challenge, base64.StdEncoding.EncodeToString(challenge.keyPair.Public[:]))

	// Step 3: Wait for confirmation that challenge is ready
	s.log.Info("Step 3. Wait for confirmation that challenge is ready")
	var ok byte
	err = binary.Read(tube, binary.BigEndian, &ok)
	if err != nil {
		return err
	}
	if ok != 1 {
		return fmt.Errorf("confirmation was %d instead of 1", ok)
	}

	// Step 4: CA checks that client controls identifier
	s.log.Info("Step 4. CA checks that client controls identifier")
	t := true
	username := AcmeUser
	keyPath := "id_hop.pem"
	hc := &config.HostConfigOptional{
		AutoSelfSign:         &t,
		ServerName:           &domain,
		Key:                  &keyPath,
		Port:                 8888,
		User:                 &username,
		InsecureSkipVerify:   &t,
		RequestAuthorization: &t,
	}
	clientConfig := hc.Unwrap()
	client, err := hopclient.NewHopClient(clientConfig)
	if err != nil {
		return err
	}

	keyBytes := challenge.keyPair.Private.String()
	client.Fsystem = fstest.MapFS{
		keyPath: &fstest.MapFile{
			Data: []byte(keyBytes + "\n"),
			Mode: 0600,
		},
	}

	err = client.Dial()
	if err != nil {
		return err
	}

	innerTube, err := client.TubeMuxer.CreateReliableTube(common.ExecTube)
	if err != nil {
		return err
	}

	challengeResponse := make([]byte, ChallengeLen)
	s.log.Info("waiting for client response")
	_, err = io.ReadFull(innerTube, challengeResponse)
	s.log.Infof("expected challenge: %x\n", challenge.Challenge)
	s.log.Infof("finished pipe read: %x\n", challengeResponse)
	if err != nil {
		return err
	}

	if !bytes.Equal(challenge.Challenge, challengeResponse) {
		s.log.Warn("CHALLENGE RESPONSE DID NOT MATCH")
		return fmt.Errorf("challenge response did not match")
	} else {
		s.log.Info("CHALLENGE MATCHED RESPONSE")
	}

	// Send confimation back to requester
	_, err = tube.Write([]byte{1})
	if err != nil {
		return err
	}
	// TODO(hosono) make sure this closes correctly
	go client.Close()

	// Step 5: Requester makes certificate request
	s.log.Info("Step 5. Requester makes certificate request")
	request := CertificateRequest{}
	_, err = request.ReadFrom(tube)
	if err != nil {
		return err
	}

	if request.Name.String() != domainAndKey.DomainName {
		return fmt.Errorf("requested name `%s` did not match verified name `%s`", request.Name.String(), domainAndKey.DomainName)
	}

	// Step 6: CA issues certificate
	s.log.Info("Step 6. CA issues certificate")

	cert, err := certs.IssueLeaf(s.server.Config.SigningCertificate, &certs.Identity{
		PublicKey: request.PubKey,
		Names:     []certs.Name{request.Name},
	})
	if err != nil {
		return err
	}
	_, err = cert.WriteTo(tube)
	if err != nil {
		return err
	}

	return nil
}

func (s *AcmeSession) Close() error {
	panic("todo")
}
