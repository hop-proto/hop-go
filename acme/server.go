package acme

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/config"
	"hop.computer/hop/hopserver"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

type sessID uint32

type AcmeServerConfig struct {
	*config.ServerConfig
}

// AcmeServer represents the state of a server engaging in the acme protocol
type AcmeServer struct {
	*hopserver.HopServer
	Config        *AcmeServerConfig
	sessions      map[sessID]*AcmeSession
	nextSessionID atomic.Uint32
	sessionLock   sync.Mutex
}

type AcmeSession struct {
	transportConn *transport.Handle
	tubeMuxer     *tubes.Muxer

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
		// TODO(hosono) add logging context to server
		tubeMuxer: tubes.Server(serverConn, &muxerConfig),
		server:    s,
		ID:        sessID(s.nextSessionID.Load()),
	}
	s.nextSessionID.Add(1)
	s.sessionLock.Lock()
	s.sessions[sess.ID] = sess
	s.sessionLock.Unlock()

	sess.Start()
}

func (s *AcmeSession) Start() {
	panic("todo")
}
