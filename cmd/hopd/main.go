package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/flags"
	"zmap.io/portal/hopserver"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	f, err := flags.ParseServerArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}
	sc, err := flags.LoadServerConfigFromFlags(f)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}

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
