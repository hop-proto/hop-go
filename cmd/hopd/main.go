package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/flags"
	"hop.computer/hop/hopserver"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	f, err := flags.ParseServerArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}

	if f.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if f.SessionSpecific {
		hopserver.StartSession()
		return
	}

	sc, err := flags.LoadServerConfigFromFlags(f)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}
	sc.HandshakeTimeout = 15 * time.Second

	s, err := hopserver.NewHopServer(sc)
	if err != nil {
		logrus.Fatal(err)
	}
	sch := make(chan os.Signal, 1)
	signal.Notify(sch, os.Interrupt, syscall.SIGTERM) // TODO(dadrian): Does this work on Windows?
	go func() {
		s.Serve()
		sch <- syscall.SIGTERM
	}()
	<-sch
}
